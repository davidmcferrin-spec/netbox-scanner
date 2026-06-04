from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .checkmk import CheckMKClient
from .metadata import (
    MetadataFieldSlugs,
    StalePolicyConfig,
    build_miss_count_fields,
    build_stale_miss_note,
)
from .checkmk_sync import ip_from_netbox_address_record
from .netbox import (
    ip_is_assigned_to_device,
    read_custom_field_int,
    record_description,
)

if TYPE_CHECKING:
    from .netbox import NetBoxClient

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class StaleAction:
    ip: str
    record_id: int
    miss_count: int
    action: str
    reason: str = ""


@dataclass(slots=True)
class StalePolicySummary:
    examined: int = 0
    incremented: int = 0
    reset: int = 0
    would_delete: int = 0
    deleted: int = 0
    skipped_assigned: int = 0
    skipped_checkmk: int = 0
    actions: list[StaleAction] = field(default_factory=list)


def increment_miss_count(
    existing: Any,
    slugs: MetadataFieldSlugs,
    *,
    threshold: int,
) -> tuple[int, dict[str, int], str]:
    current = read_custom_field_int(existing, slugs.scanner_miss_count)
    new_count = current + 1
    note = build_stale_miss_note(record_description(existing), new_count, threshold)
    return new_count, build_miss_count_fields(slugs, new_count), note


def process_global_stale_deletes(
    netbox_client: NetBoxClient,
    checkmk_client: CheckMKClient | None,
    *,
    stale_config: StalePolicyConfig,
    field_slugs: MetadataFieldSlugs,
    apply_deletes: bool,
) -> StalePolicySummary:
    summary = StalePolicySummary()
    records = netbox_client.fetch_ip_addresses_with_tag(stale_config.scope_tag)
    summary.examined = len(records)
    threshold = stale_config.miss_threshold

    for record in records:
        try:
            ip = ip_from_netbox_address_record(record)
        except ValueError:
            continue
        miss_count = read_custom_field_int(record, field_slugs.scanner_miss_count)
        if miss_count < threshold:
            continue

        record_id = int(getattr(record, "id", 0) or record.get("id", 0))
        if stale_config.delete_unassigned_only and ip_is_assigned_to_device(record):
            summary.skipped_assigned += 1
            summary.actions.append(
                StaleAction(
                    ip=ip,
                    record_id=record_id,
                    miss_count=miss_count,
                    action="skipped",
                    reason="assigned to device",
                )
            )
            continue

        if stale_config.exempt_checkmk and checkmk_client is not None:
            lookup = checkmk_client.lookup_host_by_ip(ip)
            if lookup.monitored:
                summary.skipped_checkmk += 1
                summary.actions.append(
                    StaleAction(
                        ip=ip,
                        record_id=record_id,
                        miss_count=miss_count,
                        action="skipped",
                        reason="present in CheckMK",
                    )
                )
                continue

        dry_run = stale_config.dry_run_deletes and not apply_deletes
        if dry_run:
            summary.would_delete += 1
            summary.actions.append(
                StaleAction(
                    ip=ip,
                    record_id=record_id,
                    miss_count=miss_count,
                    action="would_delete",
                )
            )
            LOGGER.info("Would delete stale NetBox IP %s (miss_count=%s)", ip, miss_count)
            continue

        status = netbox_client.delete_ip_address(record, dry_run=False)
        if status == "deleted":
            summary.deleted += 1
            summary.actions.append(
                StaleAction(
                    ip=ip,
                    record_id=record_id,
                    miss_count=miss_count,
                    action="deleted",
                )
            )
            LOGGER.info("Deleted stale NetBox IP %s (miss_count=%s)", ip, miss_count)

    return summary
