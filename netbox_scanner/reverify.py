from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .checkmk_sync import ip_from_netbox_address_record
from .metadata import (
    MetadataFieldSlugs,
    ScannerBehaviorConfig,
    StalePolicyConfig,
    build_last_verified_custom_fields,
    build_miss_count_fields,
    is_alive_ping_or_ptr,
)
from .netbox import resolve_write_tag_slugs
from .stale_policy import increment_miss_count

if TYPE_CHECKING:
    from .checkmk import CheckMKClient
    from .netbox import NetBoxClient
    from .scanner import NetworkScanner, ScanSummary

LOGGER = logging.getLogger(__name__)


def run_reverify_tagged(
    scanner: NetworkScanner,
    *,
    dry_run: bool = False,
    auto_confirm: bool = True,
) -> ScanSummary:
    """Ping/PTR-only reverification for all NetBox IPs with the verified tag (global scope)."""
    from .scanner import ScanResult, ScanSummary

    config = scanner.config
    behavior = config.scanner.behavior
    stale = behavior.stale
    slugs = behavior.metadata_fields
    tag_slug = config.scanner.verified_tag_slug

    records = scanner.netbox_client.fetch_ip_addresses_with_tag(tag_slug)
    summary = ScanSummary(total_hosts=len(records))

    for record in records:
        ip = ip_from_netbox_address_record(record)
        if not ip:
            continue

        result = ScanResult(ip=ip, reason="reverify")
        ping_ok = scanner.ping_runner(ip)
        scanner._apply_dns_lookup(result, summary)

        tag_slugs = resolve_write_tag_slugs(
            apply_verified_tag=True,
            verified_tag_slug=tag_slug,
            apply_checkmk_tag=False,
            checkmk_tag_slug=config.checkmk.tag_slug,
        )

        if is_alive_ping_or_ptr(ping_ok=ping_ok, ptr_hostname=result.ptr_hostname):
            result.liveness = "verified"
            summary.verified += 1
            fields = build_last_verified_custom_fields(
                slugs,
                profile="reverify",
                open_ports=None,
            )
            fields.update(build_miss_count_fields(slugs, 0))
            description = scanner._build_drift_description(record, result)
            if not dry_run and auto_confirm:
                scanner.netbox_client.apply_supplemental(
                    record,
                    tag_slugs=tag_slugs,
                    custom_fields_patch=fields,
                    description=description,
                    dry_run=False,
                )
                result.netbox_written = True
                result.reason = "reverify_ok"
            else:
                result.reason = "reverify_planned"
        else:
            result.liveness = "unreachable"
            summary.unreachable += 1
            _new_count, miss_fields, miss_note = increment_miss_count(
                record,
                slugs,
                threshold=stale.miss_threshold,
            )
            if not dry_run and auto_confirm:
                scanner.netbox_client.apply_supplemental(
                    record,
                    custom_fields_patch=miss_fields,
                    description=miss_note,
                    dry_run=False,
                )
            result.reason = "reverify_miss"

        summary.hosts_completed += 1
        summary.results.append(result)

    return summary
