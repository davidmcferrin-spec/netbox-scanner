from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .checkmk import CheckMKClient, CheckMKConfig
from .netbox import normalize_hostname, record_address

if TYPE_CHECKING:
    from .netbox import NetBoxClient

LOGGER = logging.getLogger(__name__)


def resolve_scan_write_hostname(
    ptr_hostname: str | None,
    checkmk_host_name: str | None,
    netbox_dns_name: str | None,
    sync_checkmk_dns: bool,
) -> str | None:
    """Choose dns_name for a verified scan write. PTR wins; never replace NetBox dns with CheckMK."""
    if ptr_hostname:
        return ptr_hostname
    if normalize_hostname(netbox_dns_name):
        return None
    if sync_checkmk_dns and checkmk_host_name:
        return checkmk_host_name
    return None


def ip_from_netbox_address_record(record: Any) -> str:
    address = record_address(record)
    if not address:
        return ""
    return str(ipaddress.ip_interface(address).ip)


@dataclass(slots=True)
class CheckMKDnsBackfillSummary:
    examined: int = 0
    synced: int = 0
    skipped_no_checkmk_host: int = 0
    skipped_not_in_netbox: int = 0
    dry_run_planned: int = 0
    errors: int = 0


def run_checkmk_dns_backfill(
    netbox_client: NetBoxClient,
    checkmk_client: CheckMKClient,
    checkmk_config: CheckMKConfig,
    *,
    dry_run: bool = False,
) -> CheckMKDnsBackfillSummary:
    summary = CheckMKDnsBackfillSummary()
    records = netbox_client.fetch_ip_addresses_with_tag_missing_dns(checkmk_config.tag_slug)
    summary.examined = len(records)

    for record in records:
        ip = ip_from_netbox_address_record(record)
        if not ip:
            summary.errors += 1
            LOGGER.warning("Skipping NetBox record with no parseable address: %s", record)
            continue

        lookup = checkmk_client.lookup_host_by_ip(ip)
        if not lookup.host_name:
            summary.skipped_no_checkmk_host += 1
            continue

        try:
            result = netbox_client.sync_dns_name_from_checkmk(
                ip,
                lookup.host_name,
                dry_run=dry_run,
            )
        except Exception as exc:
            summary.errors += 1
            LOGGER.warning("CheckMK dns backfill failed for %s: %s", ip, exc)
            continue

        if result.status == "not_found":
            summary.skipped_not_in_netbox += 1
            continue

        if dry_run and result.status == "drift":
            summary.dry_run_planned += 1
            continue

        if result.status == "updated":
            summary.synced += 1
            LOGGER.info("Backfilled NetBox %s dns_name from CheckMK: %r", ip, lookup.host_name)

    return summary
