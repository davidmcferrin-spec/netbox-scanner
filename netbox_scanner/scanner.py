from __future__ import annotations

import csv
import ipaddress
import json
import logging
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from .dns_verify import DNSVerificationResult, verify_dns
from .netbox import NetBoxClient, RangeRecord, iter_range_ips

LOGGER = logging.getLogger(__name__)

SPEED_TO_TIMING = {
    "paranoid": "-T0",
    "sneaky": "-T1",
    "polite": "-T2",
    "normal": "-T3",
    "aggressive": "-T4",
    "insane": "-T5",
}


@dataclass(slots=True)
class ScanResult:
    ip: str
    alive: bool
    excluded: bool = False
    open_ports: list[int] = field(default_factory=list)
    hostname: str | None = None
    dns_verified: bool = False
    dns_mismatch: bool = False
    reason: str = ""
    netbox_written: bool = False
    netbox_payload: dict[str, str] | None = None


@dataclass(slots=True)
class ScanSummary:
    total_hosts: int = 0
    hosts_completed: int = 0
    discovered: int = 0
    skipped: int = 0
    dns_verified: int = 0
    mismatches: int = 0
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

    def _scan_ports(self, ip: str, profile: str, speed: str) -> list[int]:
        profile_items = self.config.scanner.profiles[profile]
        ports = ",".join(item for item in profile_items if not item.startswith("-")) or None
        arguments = " ".join([timing_for_speed(speed), *[item for item in profile_items if item.startswith("-")]]).strip()
        if self.config.scanner.scan_rate_limit > 0:
            time.sleep(self.config.scanner.scan_rate_limit)
        scan_result = self.nmap_scanner.scan(hosts=ip, ports=ports, arguments=arguments)
        host_data = scan_result.get("scan", {}).get(ip, {})
        open_ports: list[int] = []
        for proto in ("tcp", "udp"):
            for port, port_data in host_data.get(proto, {}).items():
                if port_data.get("state") == "open":
                    open_ports.append(int(port))
        return sorted(open_ports)

    def run(
        self,
        *,
        range_names: list[str],
        profile: str,
        speed: str,
        exclude_file: str | None = None,
        dry_run: bool = False,
        auto_confirm: bool = False,
        approval_callback: Callable[[ScanResult], bool] | None = None,
        progress_callback: Callable[[ScanSummary, ScanResult], None] | None = None,
    ) -> ScanSummary:
        if profile not in self.config.scanner.profiles:
            raise ValueError(f"Unknown scan profile: {profile}")

        scan_ranges = self.netbox_client.fetch_scan_ranges(range_names)
        excluded_ranges = self.netbox_client.fetch_excluded_ranges()
        exclusions = range_records_to_exclusions(excluded_ranges) + parse_exclusions_file(exclude_file)

        targets = [str(ip) for record in scan_ranges for ip in iter_range_ips(record)]
        summary = ScanSummary(total_hosts=len(targets))

        for ip in targets:
            if is_excluded(ip, exclusions):
                result = ScanResult(ip=ip, alive=False, excluded=True, reason="excluded")
                summary.skipped += 1
                summary.hosts_completed += 1
                summary.results.append(result)
                if progress_callback:
                    progress_callback(summary, result)
                continue

            alive = self.ping_runner(ip)
            result = ScanResult(ip=ip, alive=alive, reason="ping_failed" if not alive else "")

            if alive:
                summary.discovered += 1
                try:
                    result.open_ports = self._scan_ports(ip, profile, speed)
                except Exception as exc:
                    result.reason = f"nmap_failed:{exc}"
                    self.logger.warning("nmap scan failed for %s: %s", ip, exc)

                dns_result: DNSVerificationResult = verify_dns(
                    ip,
                    resolver=self.dns_resolver,
                    nameservers=self.config.dns.servers,
                    timeout=self.config.dns.timeout,
                )
                result.hostname = dns_result.hostname
                result.dns_verified = dns_result.verified
                result.dns_mismatch = dns_result.dns_mismatch
                if dns_result.verified:
                    summary.dns_verified += 1
                    result.netbox_payload = self.netbox_client.create_ip_address(
                        ip,
                        hostname=dns_result.hostname,
                        dry_run=True,
                    )

                    approved = dry_run or auto_confirm or (approval_callback(result) if approval_callback else False)
                    if dry_run:
                        result.reason = "dry_run"
                    elif approved:
                        self.netbox_client.create_ip_address(ip, hostname=dns_result.hostname, dry_run=False)
                        result.netbox_written = True
                        result.reason = "written"
                    else:
                        result.reason = "not_confirmed"
                else:
                    summary.mismatches += 1
                    result.reason = dns_result.reason
                    self.logger.warning("DNS mismatch for %s: %s", ip, dns_result.reason)

            summary.hosts_completed += 1
            summary.results.append(result)
            if progress_callback:
                progress_callback(summary, result)
        return summary
