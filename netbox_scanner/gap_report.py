from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scanner import ScanResult, ScanSummary


@dataclass(slots=True)
class GapReport:
    verified_not_in_netbox: list[str] = field(default_factory=list)
    netbox_tagged_not_scanned: list[str] = field(default_factory=list)
    unreachable_tagged: list[str] = field(default_factory=list)
    checkmk_gap_verified: list[str] = field(default_factory=list)
    phantom_hosts: list[str] = field(default_factory=list)


def build_gap_report(
    summary: ScanSummary,
    *,
    scanned_ips: set[str],
    netbox_index_ips: set[str],
    tagged_ips: set[str],
    checkmk_enabled: bool,
) -> GapReport:
    report = GapReport()
    for result in summary.results:
        if result.liveness == "verified" and result.ip not in netbox_index_ips and result.netbox_written:
            report.verified_not_in_netbox.append(result.ip)
        if result.liveness == "ping_only":
            report.phantom_hosts.append(result.ip)
        if (
            checkmk_enabled
            and result.liveness == "verified"
            and result.checkmk_monitored is False
        ):
            report.checkmk_gap_verified.append(result.ip)
        if result.liveness == "unreachable" and result.ip in tagged_ips:
            report.unreachable_tagged.append(result.ip)

    for ip in sorted(tagged_ips):
        if ip not in scanned_ips:
            report.netbox_tagged_not_scanned.append(ip)
    return report
