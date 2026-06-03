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
from pathlib import Path
from typing import Callable, Iterable

if __package__ is None:  # pragma: no cover - allow `python netbox_scanner/scanner.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netbox_scanner.dns_verify import lookup_dns
from netbox_scanner.netbox import (
    NetBoxClient,
    RangeRecord,
    iter_unique_targets,
    iter_unique_targets_from_prefixes,
)

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
    netbox_payload: dict[str, str] | None = None


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
    netbox_existing: int = 0
    netbox_drift: int = 0
    results: list[ScanResult] = field(default_factory=list)


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
        dns_resolver=None,
        nmap_scanner=None,
        ping_runner: Callable[[str], bool] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.config = config
        self.netbox_client = netbox_client
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
        auto_confirm: bool = False,
        max_hosts: int | None = None,
        approval_callback: Callable[[ScanResult], bool] | None = None,
        progress_callback: Callable[[ScanSummary, ScanResult], None] | None = None,
    ) -> ScanSummary:
        if profile not in self.config.scanner.profiles:
            raise ValueError(f"Unknown scan profile: {profile}")

        profile_items = self.config.scanner.profiles[profile]
        excluded_ranges = self.netbox_client.fetch_excluded_ranges()
        exclusions = range_records_to_exclusions(excluded_ranges) + parse_exclusions_file(exclude_file)

        if scan_prefixes is not None:
            if not scan_prefixes:
                raise ValueError("No scan prefixes resolved from the selection.")
            if prefix_exclusion_ranges is not None:
                prefix_exclusions = prefix_exclusion_ranges
            else:
                prefix_exclusions = self.netbox_client.fetch_exclusion_ranges_for_prefixes(
                    scan_prefixes,
                    skip_range_names or [],
                    skip_role_names or [],
                )
            exclusions.extend(range_records_to_exclusions(prefix_exclusions))
            targets = iter_unique_targets_from_prefixes(scan_prefixes, max_hosts=max_hosts)
            if not targets:
                raise ValueError("No scan targets found in the selected prefixes.")
        elif scan_ranges is not None:
            resolved_ranges = scan_ranges
            if not resolved_ranges:
                raise ValueError("No NetBox IP ranges matched the selection.")
            targets = iter_unique_targets(resolved_ranges, max_hosts=max_hosts)
            if not targets:
                raise ValueError("No scan targets found in the selected NetBox IP ranges.")
        elif range_names:
            resolved_ranges = self.netbox_client.fetch_scan_ranges(range_names)
            if not resolved_ranges:
                raise ValueError("No NetBox IP ranges matched the selection.")
            targets = iter_unique_targets(resolved_ranges, max_hosts=max_hosts)
            if not targets:
                raise ValueError("No scan targets found in the selected NetBox IP ranges.")
        else:
            raise ValueError("Provide scan_prefixes, scan_ranges, or range_names.")

        summary = ScanSummary(total_hosts=len(targets))

        for ip in targets:
            if is_excluded(ip, exclusions):
                result = ScanResult(ip=ip, liveness="unreachable", excluded=True, reason="excluded")
                summary.excluded += 1
                summary.hosts_completed += 1
                summary.results.append(result)
                if progress_callback:
                    progress_callback(summary, result)
                continue

            ping_ok = self.ping_runner(ip)
            result = ScanResult(ip=ip)

            if not ping_ok:
                result.liveness = "unreachable"
                result.reason = "ping_failed"
                summary.unreachable += 1
            else:
                nmap_up = False
                open_ports: list[int] = []
                try:
                    nmap_up, open_ports = self._scan_host(ip, profile, speed)
                    result.nmap_up = nmap_up
                    result.open_ports = open_ports
                except Exception as exc:
                    result.reason = f"nmap_failed:{exc}"
                    self.logger.warning("nmap scan failed for %s: %s", ip, exc)

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
                        dry_run=dry_run,
                        auto_confirm=auto_confirm,
                        approval_callback=approval_callback,
                    )
                else:
                    summary.ping_only += 1
                    result.reason = "phantom_suspect"
                    self.logger.warning(
                        "Phantom suspect for %s: ICMP replied but nmap did not confirm host is up",
                        ip,
                    )

            summary.hosts_completed += 1
            summary.results.append(result)
            if progress_callback:
                progress_callback(summary, result)
        return summary

    def _handle_netbox_write(
        self,
        *,
        result: ScanResult,
        summary: ScanSummary,
        hostname: str | None,
        dry_run: bool,
        auto_confirm: bool,
        approval_callback: Callable[[ScanResult], bool] | None,
    ) -> None:
        evaluation = self.netbox_client.evaluate_ip_address(result.ip, hostname=hostname)
        result.netbox_payload = evaluation.payload
        result.netbox_dns_name = evaluation.netbox_dns_name
        result.netbox_status = evaluation.status

        if evaluation.status == "drift":
            summary.netbox_drift += 1
            if not result.reason:
                result.reason = "dns_drift"
            self.logger.warning(
                "DNS drift for %s: NetBox dns_name=%r PTR hostname=%r",
                result.ip,
                evaluation.netbox_dns_name,
                hostname,
            )
            return

        if evaluation.status == "already_exists":
            summary.netbox_existing += 1
            if not result.reason:
                result.reason = "already_exists"
            return

        if dry_run:
            result.netbox_status = "planned"
            result.reason = "dry_run"
            return

        approved = auto_confirm or (approval_callback(result) if approval_callback else False)
        if not approved:
            result.netbox_status = "planned"
            result.reason = "not_confirmed"
            return

        write_result = self.netbox_client.create_ip_address(result.ip, hostname=hostname, dry_run=False)
        result.netbox_written = True
        result.netbox_status = write_result.status
        result.reason = write_result.status
        summary.netbox_created += 1
