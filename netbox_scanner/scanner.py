from __future__ import annotations

import csv
import ipaddress
import json
import logging
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
import uuid
from pathlib import Path
from typing import Any, Callable, Iterable

if __package__ is None:  # pragma: no cover - allow `python netbox_scanner/scanner.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netbox_scanner.checkpoint import (
    ScanCheckpoint,
    default_checkpoint_path,
    load_checkpoint,
    save_checkpoint,
)
from netbox_scanner.checkmk import CheckMKClient, should_apply_checkmk_tag
from netbox_scanner.checkmk_sync import ip_from_netbox_address_record, resolve_scan_write_hostname
from netbox_scanner.dns_verify import lookup_dns
from netbox_scanner.gap_report import GapReport, build_gap_report
from netbox_scanner.metadata import (
    build_drift_note,
    build_last_verified_custom_fields,
    build_miss_count_fields,
    is_alive_ping_or_ptr,
)
from netbox_scanner.netbox import (
    NetBoxClient,
    NoPtrDiscovery,
    RangeRecord,
    normalize_hostname,
    record_description,
    record_dns_name,
    resolve_write_tag_slugs,
    iter_unique_targets,
    iter_unique_targets_from_prefixes,
)
from netbox_scanner.scan_batch import batch_nmap_scan
from netbox_scanner.stale_policy import increment_miss_count

LOGGER = logging.getLogger(__name__)

SPEED_TO_TIMING = {
    "paranoid": "-T0",
    "sneaky": "-T1",
    "polite": "-T2",
    "normal": "-T3",
    "aggressive": "-T4",
    "insane": "-T5",
}


_PORT_RANGE_RE = re.compile(r"(?<![\d])(\d+)-(\d+)(?![\d])")


def profile_uses_explicit_ports(profile_items: list[str]) -> bool:
    port_items = [item for item in profile_items if not item.startswith("-")]
    if not port_items:
        return False
    combined = ",".join(port_items)
    for match in _PORT_RANGE_RE.finditer(combined):
        start, end = int(match.group(1)), int(match.group(2))
        if end > start:
            return False
    return True


def classify_liveness(
    *,
    ping_ok: bool,
    nmap_status_up: bool,
    profile_items: list[str],
    open_ports: list[int],
) -> str:
    if not ping_ok:
        return "unreachable"
    if profile_uses_explicit_ports(profile_items):
        return "verified" if open_ports else "ping_only"
    if any(item == "-Pn" for item in profile_items):
        return "verified" if open_ports else "ping_only"
    return "verified" if nmap_status_up else "ping_only"


@dataclass(slots=True)
class ScanResult:
    ip: str
    liveness: str = "unreachable"
    excluded: bool = False
    nmap_up: bool = False
    open_ports: list[int] = field(default_factory=list)
    ptr_hostname: str | None = None
    forward_has_a_or_cname: bool = False
    forward_addresses: list[str] = field(default_factory=list)
    reason: str = ""
    netbox_written: bool = False
    netbox_status: str = ""
    netbox_dns_name: str | None = None
    netbox_payload: dict[str, Any] | None = None
    checkmk_monitored: bool | None = None
    checkmk_host_name: str | None = None
    checkmk_tag_applied: bool = False
    checkmk_dns_synced: bool = False
    verified_tag_applied: bool = False
    fast_path: bool = False
    phantom_tag_applied: bool = False


@dataclass(slots=True)
class ScanSummary:
    total_hosts: int = 0
    hosts_completed: int = 0
    verified: int = 0
    ping_only: int = 0
    unreachable: int = 0
    excluded: int = 0
    ptr_found: int = 0
    netbox_created: int = 0
    netbox_updated: int = 0
    netbox_existing: int = 0
    netbox_drift: int = 0
    fast_path_verified: int = 0
    results: list[ScanResult] = field(default_factory=list)
    gap_report: GapReport | None = None


def timing_for_speed(speed: str) -> str:
    try:
        return SPEED_TO_TIMING[speed]
    except KeyError as exc:
        raise ValueError(f"Unsupported speed: {speed}") from exc


def parse_exclusions_file(path: str | None) -> list[ipaddress._BaseNetwork | ipaddress._BaseAddress]:
    if not path:
        return []
    exclusions: list[ipaddress._BaseNetwork | ipaddress._BaseAddress] = []
    with Path(path).expanduser().open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            if "/" in line:
                exclusions.append(ipaddress.ip_network(line, strict=False))
            else:
                exclusions.append(ipaddress.ip_address(line))
    return exclusions


def range_records_to_exclusions(records: Iterable[RangeRecord]) -> list[ipaddress._BaseNetwork | ipaddress._BaseAddress]:
    exclusions: list[ipaddress._BaseNetwork | ipaddress._BaseAddress] = []
    for record in records:
        for network in ipaddress.summarize_address_range(
            ipaddress.ip_address(record.start_address),
            ipaddress.ip_address(record.end_address),
        ):
            exclusions.append(network)
    return exclusions


def is_excluded(ip: str, exclusions: Iterable[ipaddress._BaseNetwork | ipaddress._BaseAddress]) -> bool:
    address = ipaddress.ip_address(ip)
    for exclusion in exclusions:
        if isinstance(exclusion, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            if address == exclusion:
                return True
        elif address in exclusion:
            return True
    return False


def export_results(summary: ScanSummary, output_path: str) -> None:
    path = Path(output_path)
    rows = [asdict(result) for result in summary.results]
    if path.suffix.lower() == ".json":
        path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        return
    if path.suffix.lower() == ".csv":
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=rows[0].keys() if rows else ScanResult.__dataclass_fields__.keys())
            writer.writeheader()
            writer.writerows(rows)
        return
    raise ValueError("Output path must end with .json or .csv")


class NetworkScanner:
    def __init__(
        self,
        config,
        netbox_client: NetBoxClient,
        *,
        checkmk_client: CheckMKClient | None = None,
        dns_resolver=None,
        nmap_scanner=None,
        ping_runner: Callable[[str], bool] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.config = config
        self.netbox_client = netbox_client
        self.checkmk_client = checkmk_client
        self.dns_resolver = dns_resolver
        self._nmap_scanner = nmap_scanner
        self.ping_runner = ping_runner or self._ping_host
        self.logger = logger or LOGGER

    @property
    def nmap_scanner(self):
        if self._nmap_scanner is None:
            try:
                import nmap
            except ImportError as exc:  # pragma: no cover - optional at test time
                raise RuntimeError("python-nmap is required for scanning.") from exc
            self._nmap_scanner = nmap.PortScanner()
        return self._nmap_scanner

    def _ping_host(self, ip: str) -> bool:
        try:
            completed = subprocess.run(
                ["ping", "-c", "1", "-W", str(int(self.config.scanner.ping_timeout)), ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError as exc:
            self.logger.warning("Unable to run ping for %s: %s", ip, exc)
            return False
        return completed.returncode == 0

    def _scan_host(self, ip: str, profile: str, speed: str) -> tuple[bool, list[int]]:
        profile_items = self.config.scanner.profiles[profile]
        ports = ",".join(item for item in profile_items if not item.startswith("-")) or None
        arguments = " ".join([timing_for_speed(speed), *[item for item in profile_items if item.startswith("-")]]).strip()
        if self.config.scanner.scan_rate_limit > 0:
            time.sleep(self.config.scanner.scan_rate_limit)
        scan_result = self.nmap_scanner.scan(hosts=ip, ports=ports, arguments=arguments)
        host_data = scan_result.get("scan", {}).get(ip, {})
        nmap_up = host_data.get("status", {}).get("state") == "up"
        open_ports: list[int] = []
        for proto in ("tcp", "udp"):
            for port, port_data in host_data.get(proto, {}).items():
                if port_data.get("state") == "open":
                    open_ports.append(int(port))
        return nmap_up, sorted(open_ports)

    def _scan_network(
        self,
        cidr: str,
        profile: str,
        speed: str,
        *,
        expected_ips: set[str],
    ) -> dict[str, tuple[bool, list[int]]]:
        profile_items = self.config.scanner.profiles[profile]
        ports = ",".join(item for item in profile_items if not item.startswith("-")) or None
        arguments = " ".join(
            [timing_for_speed(speed), *[item for item in profile_items if item.startswith("-")]]
        ).strip()
        if self.config.scanner.scan_rate_limit > 0:
            time.sleep(self.config.scanner.scan_rate_limit)
        scan_result = self.nmap_scanner.scan(hosts=cidr, ports=ports, arguments=arguments)
        results: dict[str, tuple[bool, list[int]]] = {}
        for ip in expected_ips:
            host_data = scan_result.get("scan", {}).get(ip, {})
            nmap_up = host_data.get("status", {}).get("state") == "up"
            open_ports: list[int] = []
            for proto in ("tcp", "udp"):
                for port, port_data in host_data.get(proto, {}).items():
                    if port_data.get("state") == "open":
                        open_ports.append(int(port))
            results[ip] = (nmap_up, sorted(open_ports))
        return results

    def _build_drift_description(self, existing: Any, result: ScanResult) -> str | None:
        netbox_dns = record_dns_name(existing) or None
        ptr = result.ptr_hostname
        checkmk_name = result.checkmk_host_name
        base = record_description(existing)
        if ptr and normalize_hostname(ptr) != normalize_hostname(netbox_dns):
            return build_drift_note(
                base,
                ptr_hostname=ptr,
                netbox_dns=netbox_dns,
                checkmk_host=checkmk_name,
            )
        if checkmk_name and normalize_hostname(checkmk_name) != normalize_hostname(netbox_dns):
            return build_drift_note(
                base,
                ptr_hostname=ptr,
                netbox_dns=netbox_dns,
                checkmk_host=checkmk_name,
            )
        return None

    def _apply_dns_lookup(self, result: ScanResult, summary: ScanSummary) -> None:
        dns_result = lookup_dns(
            result.ip,
            resolver=self.dns_resolver,
            nameservers=self.config.dns.servers,
            timeout=self.config.dns.timeout,
        )
        result.ptr_hostname = dns_result.ptr_hostname
        result.forward_has_a_or_cname = dns_result.forward_has_a_or_cname
        result.forward_addresses = dns_result.forward_addresses
        if dns_result.ptr_hostname:
            summary.ptr_found += 1

    def _apply_checkmk_lookup(self, result: ScanResult) -> None:
        if not self.config.checkmk.enabled or self.checkmk_client is None:
            return
        lookup = self.checkmk_client.lookup_host_by_ip(result.ip)
        result.checkmk_monitored = lookup.monitored
        result.checkmk_host_name = lookup.host_name

    def _finalize_result(
        self,
        summary: ScanSummary,
        result: ScanResult,
        progress_callback: Callable[[ScanSummary, ScanResult], None] | None,
    ) -> None:
        summary.hosts_completed += 1
        summary.results.append(result)
        if progress_callback:
            progress_callback(summary, result)

    def _handle_fast_path_miss(
        self,
        *,
        ip: str,
        existing: Any,
        result: ScanResult,
        summary: ScanSummary,
        dry_run: bool,
        auto_confirm: bool,
    ) -> None:
        behavior = self.config.scanner.behavior
        slugs = behavior.metadata_fields
        _count, miss_fields, miss_note = increment_miss_count(
            existing,
            slugs,
            threshold=behavior.stale.miss_threshold,
        )
        result.reason = "fast_path_miss"
        if dry_run or not auto_confirm:
            return
        self.netbox_client.apply_supplemental(
            existing,
            custom_fields_patch=miss_fields,
            description=miss_note,
            dry_run=False,
        )

    def _handle_fast_path_verified(
        self,
        *,
        ip: str,
        existing: Any,
        result: ScanResult,
        summary: ScanSummary,
        profile: str,
        dry_run: bool,
        auto_confirm: bool,
        sync_checkmk_dns: bool,
    ) -> None:
        result.fast_path = True
        result.liveness = "verified"
        summary.verified += 1
        summary.fast_path_verified += 1
        self._apply_checkmk_lookup(result)
        behavior = self.config.scanner.behavior
        slugs = behavior.metadata_fields
        tag_slugs = resolve_write_tag_slugs(
            apply_verified_tag=True,
            verified_tag_slug=self.config.scanner.verified_tag_slug,
            apply_checkmk_tag=should_apply_checkmk_tag(
                self.config.checkmk,
                bool(result.checkmk_monitored),
            ),
            checkmk_tag_slug=self.config.checkmk.tag_slug,
        )
        fields = build_last_verified_custom_fields(slugs, profile=f"{profile}-fast", open_ports=None)
        fields.update(build_miss_count_fields(slugs, 0))
        drift_desc = self._build_drift_description(existing, result)
        write_hostname = resolve_scan_write_hostname(
            result.ptr_hostname,
            result.checkmk_host_name,
            record_dns_name(existing),
            sync_checkmk_dns,
        )
        if dry_run or not auto_confirm:
            result.reason = "fast_path_planned"
            return
        if write_hostname:
            self._handle_netbox_write(
                result=result,
                summary=summary,
                hostname=write_hostname,
                profile=profile,
                dry_run=False,
                auto_confirm=True,
                approval_callback=None,
                sync_checkmk_dns=False,
            )
        self.netbox_client.apply_supplemental(
            existing,
            tag_slugs=tag_slugs,
            custom_fields_patch=fields,
            description=drift_desc,
            dry_run=False,
        )
        result.netbox_written = True
        result.reason = "fast_path_ok"

    def _handle_phantom_tag(
        self,
        *,
        result: ScanResult,
        existing: Any | None,
        dry_run: bool,
        auto_confirm: bool,
    ) -> None:
        phantom_slug = self.config.scanner.behavior.stale.phantom_tag_slug
        if not phantom_slug or existing is None:
            return
        if dry_run or not auto_confirm:
            return
        write = self.netbox_client.apply_supplemental(
            existing,
            tag_slugs=[phantom_slug],
            dry_run=False,
        )
        if write.status in ("updated", "tag_update"):
            result.phantom_tag_applied = True

    def _process_ip(
        self,
        *,
        ip: str,
        existing: Any | None,
        exclusions: list,
        profile: str,
        speed: str,
        profile_items: list[str],
        summary: ScanSummary,
        dry_run: bool,
        auto_confirm: bool,
        approval_callback: Callable[[ScanResult], bool] | None,
        sync_checkmk_dns: bool,
        nmap_results: dict[str, tuple[bool, list[int]]] | None,
    ) -> ScanResult:
        if is_excluded(ip, exclusions):
            result = ScanResult(ip=ip, liveness="unreachable", excluded=True, reason="excluded")
            summary.excluded += 1
            return result

        behavior = self.config.scanner.behavior
        use_fast = behavior.fast_path_existing_netbox and existing is not None
        ping_ok = self.ping_runner(ip)
        result = ScanResult(ip=ip, fast_path=use_fast)

        if use_fast:
            self._apply_dns_lookup(result, summary)
            if is_alive_ping_or_ptr(ping_ok=ping_ok, ptr_hostname=result.ptr_hostname):
                self._handle_fast_path_verified(
                    ip=ip,
                    existing=existing,
                    result=result,
                    summary=summary,
                    profile=profile,
                    dry_run=dry_run,
                    auto_confirm=auto_confirm,
                    sync_checkmk_dns=sync_checkmk_dns,
                )
            else:
                result.liveness = "unreachable"
                summary.unreachable += 1
                self._handle_fast_path_miss(
                    ip=ip,
                    existing=existing,
                    result=result,
                    summary=summary,
                    dry_run=dry_run,
                    auto_confirm=auto_confirm,
                )
            return result

        if not ping_ok:
            result.liveness = "unreachable"
            result.reason = "ping_failed"
            summary.unreachable += 1
            return result

        nmap_up = False
        open_ports: list[int] = []
        if nmap_results is not None and ip in nmap_results:
            nmap_up, open_ports = nmap_results[ip]
        else:
            try:
                nmap_up, open_ports = self._scan_host(ip, profile, speed)
            except Exception as exc:
                result.reason = f"nmap_failed:{exc}"
                self.logger.warning("nmap scan failed for %s: %s", ip, exc)
        result.nmap_up = nmap_up
        result.open_ports = open_ports
        result.liveness = classify_liveness(
            ping_ok=True,
            nmap_status_up=nmap_up,
            profile_items=profile_items,
            open_ports=open_ports,
        )
        self._apply_dns_lookup(result, summary)

        if result.liveness == "verified":
            summary.verified += 1
            self._handle_netbox_write(
                result=result,
                summary=summary,
                hostname=result.ptr_hostname,
                profile=profile,
                dry_run=dry_run,
                auto_confirm=auto_confirm,
                approval_callback=approval_callback,
                sync_checkmk_dns=sync_checkmk_dns,
            )
            self._apply_post_write_metadata(result, profile)
        else:
            summary.ping_only += 1
            result.reason = "phantom_suspect"
            if existing is not None:
                self._handle_phantom_tag(
                    result=result,
                    existing=existing,
                    dry_run=dry_run,
                    auto_confirm=auto_confirm,
                )
            self.logger.warning(
                "Phantom suspect for %s: ICMP replied but nmap did not confirm host is up",
                ip,
            )
        return result

    def _apply_post_write_metadata(self, result: ScanResult, profile: str) -> None:
        if not result.netbox_written:
            return
        existing = self.netbox_client._lookup_ip_address(result.ip)
        if existing is None:
            return
        slugs = self.config.scanner.behavior.metadata_fields
        fields = build_last_verified_custom_fields(
            slugs,
            profile=profile,
            open_ports=result.open_ports,
        )
        fields.update(build_miss_count_fields(slugs, 0))
        self.netbox_client.apply_supplemental(
            existing,
            custom_fields_patch=fields,
            dry_run=False,
        )

    def _run_prefix_scan(
        self,
        *,
        prefix_cidr: str,
        targets: list[str],
        exclusions: list,
        profile: str,
        speed: str,
        profile_items: list[str],
        summary: ScanSummary,
        dry_run: bool,
        auto_confirm: bool,
        approval_callback: Callable[[ScanResult], bool] | None,
        sync_checkmk_dns: bool,
        progress_callback: Callable[[ScanSummary, ScanResult], None] | None,
        checkpoint: ScanCheckpoint | None,
        checkpoint_path: Path | None,
        run_id: str,
    ) -> set[str]:
        behavior = self.config.scanner.behavior
        ip_index = (
            self.netbox_client.fetch_ip_index_for_prefix(prefix_cidr)
            if behavior.fast_path_existing_netbox
            else {}
        )
        prefix_state = checkpoint.prefix_state(prefix_cidr) if checkpoint else None

        new_hosts = [
            ip
            for ip in targets
            if ip not in ip_index
            and not (prefix_state and prefix_state.is_ip_done(ip))
        ]
        nmap_results: dict[str, tuple[bool, list[int]]] = {}
        if new_hosts:
            nmap_results = batch_nmap_scan(
                self,
                new_hosts,
                profile,
                speed,
                prefixlen=behavior.nmap_batch_prefixlen,
                parallel_workers=behavior.parallel_workers,
            )

        scanned: set[str] = set()
        for ip in targets:
            if prefix_state and prefix_state.is_ip_done(ip):
                continue
            existing = ip_index.get(ip)
            result = self._process_ip(
                ip=ip,
                existing=existing,
                exclusions=exclusions,
                profile=profile,
                speed=speed,
                profile_items=profile_items,
                summary=summary,
                dry_run=dry_run,
                auto_confirm=auto_confirm,
                approval_callback=approval_callback,
                sync_checkmk_dns=sync_checkmk_dns,
                nmap_results=nmap_results,
            )
            scanned.add(ip)
            self._finalize_result(summary, result, progress_callback)
            if prefix_state:
                prefix_state.mark_ip(ip)
                if checkpoint_path and checkpoint:
                    checkpoint.run_id = run_id
                    save_checkpoint(checkpoint_path, checkpoint)

        if prefix_state:
            prefix_state.mark_complete()
            if checkpoint_path and checkpoint:
                save_checkpoint(checkpoint_path, checkpoint)
        return scanned

    def run(
        self,
        *,
        range_names: list[str] | None = None,
        scan_ranges: list[RangeRecord] | None = None,
        scan_prefixes: list[str] | None = None,
        skip_range_names: list[str] | None = None,
        skip_role_names: list[str] | None = None,
        prefix_exclusion_ranges: list | None = None,
        profile: str,
        speed: str,
        exclude_file: str | None = None,
        dry_run: bool = False,
        auto_confirm: bool = True,
        max_hosts: int | None = None,
        approval_callback: Callable[[ScanResult], bool] | None = None,
        progress_callback: Callable[[ScanSummary, ScanResult], None] | None = None,
        sync_checkmk_dns: bool = False,
        resume: bool = False,
        gap_report_enabled: bool = False,
    ) -> ScanSummary:
        if profile not in self.config.scanner.profiles:
            raise ValueError(f"Unknown scan profile: {profile}")

        profile_items = self.config.scanner.profiles[profile]
        excluded_ranges = self.netbox_client.fetch_excluded_ranges()
        exclusions = range_records_to_exclusions(excluded_ranges) + parse_exclusions_file(exclude_file)

        behavior = self.config.scanner.behavior
        checkpoint_path = default_checkpoint_path(behavior.checkpoint_path)
        checkpoint = load_checkpoint(checkpoint_path) if resume else None
        run_id = checkpoint.run_id if checkpoint else str(uuid.uuid4())
        if checkpoint is None:
            checkpoint = ScanCheckpoint(run_id=run_id)

        all_scanned: set[str] = set()
        netbox_index_all: set[str] = set()

        if scan_prefixes is not None:
            if not scan_prefixes:
                raise ValueError("No scan prefixes resolved from the selection.")
            prefix_exclusions = (
                prefix_exclusion_ranges
                if prefix_exclusion_ranges is not None
                else self.netbox_client.fetch_exclusion_ranges_for_prefixes(
                    scan_prefixes,
                    skip_range_names or [],
                    skip_role_names or [],
                )
            )
            exclusions.extend(range_records_to_exclusions(prefix_exclusions))
            total_targets: list[str] = []
            for prefix_cidr in scan_prefixes:
                if checkpoint and checkpoint.is_prefix_complete(prefix_cidr):
                    continue
                prefix_targets = iter_unique_targets_from_prefixes([prefix_cidr], max_hosts=max_hosts)
                total_targets.extend(prefix_targets)
            if not total_targets and not resume:
                raise ValueError("No scan targets found in the selected prefixes.")
            summary = ScanSummary(total_hosts=len(total_targets))

            for prefix_cidr in scan_prefixes:
                if checkpoint and checkpoint.is_prefix_complete(prefix_cidr):
                    continue
                prefix_targets = iter_unique_targets_from_prefixes([prefix_cidr], max_hosts=max_hosts)
                if not prefix_targets:
                    continue
                scanned = self._run_prefix_scan(
                    prefix_cidr=prefix_cidr,
                    targets=prefix_targets,
                    exclusions=exclusions,
                    profile=profile,
                    speed=speed,
                    profile_items=profile_items,
                    summary=summary,
                    dry_run=dry_run,
                    auto_confirm=auto_confirm,
                    approval_callback=approval_callback,
                    sync_checkmk_dns=sync_checkmk_dns,
                    progress_callback=progress_callback,
                    checkpoint=checkpoint,
                    checkpoint_path=checkpoint_path,
                    run_id=run_id,
                )
                all_scanned.update(scanned)
                netbox_index_all.update(self.netbox_client.fetch_ip_index_for_prefix(prefix_cidr).keys())
        else:
            if scan_ranges is not None:
                resolved_ranges = scan_ranges
            elif range_names:
                resolved_ranges = self.netbox_client.fetch_scan_ranges(range_names)
            else:
                raise ValueError("Provide scan_prefixes, scan_ranges, or range_names.")
            if not resolved_ranges:
                raise ValueError("No NetBox IP ranges matched the selection.")
            targets = iter_unique_targets(resolved_ranges, max_hosts=max_hosts)
            if not targets:
                raise ValueError("No scan targets found in the selected NetBox IP ranges.")
            summary = ScanSummary(total_hosts=len(targets))
            ip_index: dict[str, Any] = {}
            nmap_results = batch_nmap_scan(
                self,
                [ip for ip in targets if ip not in ip_index],
                profile,
                speed,
                prefixlen=behavior.nmap_batch_prefixlen,
                parallel_workers=behavior.parallel_workers,
            )
            for ip in targets:
                result = self._process_ip(
                    ip=ip,
                    existing=ip_index.get(ip),
                    exclusions=exclusions,
                    profile=profile,
                    speed=speed,
                    profile_items=profile_items,
                    summary=summary,
                    dry_run=dry_run,
                    auto_confirm=auto_confirm,
                    approval_callback=approval_callback,
                    sync_checkmk_dns=sync_checkmk_dns,
                    nmap_results=nmap_results,
                )
                all_scanned.add(ip)
                self._finalize_result(summary, result, progress_callback)

        if gap_report_enabled:
            tagged_records = self.netbox_client.fetch_ip_addresses_with_tag(
                self.config.scanner.verified_tag_slug
            )
            tagged_ips = {
                ip_from_netbox_address_record(record)
                for record in tagged_records
                if ip_from_netbox_address_record(record)
            }
            summary.gap_report = build_gap_report(
                summary,
                scanned_ips=all_scanned,
                netbox_index_ips=netbox_index_all,
                tagged_ips=tagged_ips,
                checkmk_enabled=self.config.checkmk.enabled,
            )
        return summary

    def _build_no_ptr_discovery(self, result: ScanResult, profile: str) -> NoPtrDiscovery | None:
        if result.ptr_hostname:
            return None
        return NoPtrDiscovery(
            open_ports=list(result.open_ports),
            profile=profile,
            nmap_up=result.nmap_up,
        )

    def _handle_netbox_write(
        self,
        *,
        result: ScanResult,
        summary: ScanSummary,
        hostname: str | None,
        profile: str,
        dry_run: bool,
        auto_confirm: bool,
        approval_callback: Callable[[ScanResult], bool] | None,
        sync_checkmk_dns: bool = False,
    ) -> None:
        self._apply_checkmk_lookup(result)
        apply_checkmk_tag = should_apply_checkmk_tag(
            self.config.checkmk,
            bool(result.checkmk_monitored),
        )
        checkmk_tag_slug = self.config.checkmk.tag_slug
        apply_verified_tag = True
        verified_tag_slug = self.config.scanner.verified_tag_slug
        discovery = self._build_no_ptr_discovery(result, profile)
        write_hostname = hostname

        if sync_checkmk_dns and not hostname:
            peek = self.netbox_client.evaluate_ip_address(
                result.ip,
                hostname=None,
                apply_checkmk_tag=apply_checkmk_tag,
                checkmk_tag_slug=checkmk_tag_slug,
                apply_verified_tag=apply_verified_tag,
                verified_tag_slug=verified_tag_slug,
                discovery=None,
            )
            write_hostname = resolve_scan_write_hostname(
                None,
                result.checkmk_host_name,
                peek.netbox_dns_name,
                sync_checkmk_dns=True,
            )
            if write_hostname:
                discovery = None
                result.checkmk_dns_synced = write_hostname == result.checkmk_host_name

        evaluation = self.netbox_client.evaluate_ip_address(
            result.ip,
            hostname=write_hostname,
            apply_checkmk_tag=apply_checkmk_tag,
            checkmk_tag_slug=checkmk_tag_slug,
            apply_verified_tag=apply_verified_tag,
            verified_tag_slug=verified_tag_slug,
            discovery=discovery,
        )
        result.netbox_payload = evaluation.payload
        result.netbox_dns_name = evaluation.netbox_dns_name
        result.netbox_status = evaluation.status

        if evaluation.status == "already_exists":
            summary.netbox_existing += 1
            if not result.reason:
                result.reason = "already_exists"
            return

        if dry_run:
            if evaluation.status in ("drift", "tag_update"):
                if evaluation.status == "drift":
                    summary.netbox_drift += 1
                result.netbox_payload = evaluation.update_payload or evaluation.payload
                if not result.reason:
                    result.reason = "dry_run"
                return
            result.netbox_status = "planned"
            result.reason = "dry_run"
            return

        if approval_callback:
            approved = approval_callback(result)
        else:
            approved = auto_confirm
        if not approved:
            result.netbox_status = "planned"
            result.reason = "not_confirmed"
            return

        write_result = self.netbox_client.upsert_ip_address(
            result.ip,
            hostname=write_hostname,
            dry_run=False,
            apply_checkmk_tag=apply_checkmk_tag,
            checkmk_tag_slug=checkmk_tag_slug,
            apply_verified_tag=apply_verified_tag,
            verified_tag_slug=verified_tag_slug,
            discovery=discovery,
        )
        if write_result.status in ("created", "updated"):
            result.netbox_written = True
            if apply_checkmk_tag:
                result.checkmk_tag_applied = True
            if apply_verified_tag:
                result.verified_tag_applied = True
        result.netbox_status = write_result.status
        if write_result.status == "updated" and evaluation.status == "tag_update":
            result.reason = "tag_update"
        else:
            result.reason = write_result.status
        if write_result.status == "created":
            summary.netbox_created += 1
        elif write_result.status == "updated":
            summary.netbox_updated += 1
            if evaluation.status == "tag_update" and apply_checkmk_tag:
                self.logger.info(
                    "Tagged NetBox %s with %r (CheckMK host=%r)",
                    result.ip,
                    checkmk_tag_slug,
                    result.checkmk_host_name,
                )
            elif write_hostname:
                source = "CheckMK" if result.checkmk_dns_synced else "PTR"
                self.logger.info(
                    "Updated NetBox %s dns_name from %r to %r (%s)",
                    result.ip,
                    evaluation.netbox_dns_name,
                    write_hostname,
                    source,
                )
            elif discovery is not None:
                self.logger.info(
                    "Updated NetBox %s discovery note (no PTR, ports=%s)",
                    result.ip,
                    ",".join(str(port) for port in result.open_ports) or "none",
                )
