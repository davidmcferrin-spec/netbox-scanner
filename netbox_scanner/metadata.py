from __future__ import annotations

from dataclasses import dataclass, field

from .netbox import (
    DEFAULT_VERIFIED_TAG_SLUG,
    NO_PTR_DISCOVERY_MARKER,
    PREVIOUS_DNS_NAME_PREFIX,
    scanner_note_timestamp,
    upsert_scanner_description_line,
)

DRIFT_MARKER_PREFIX = "netbox-scanner: drift:"
STALE_MISS_PREFIX = "netbox-scanner: stale miss:"


@dataclass(slots=True)
class MetadataFieldSlugs:
    last_verified_at: str = "last_verified_at"
    last_verified_profile: str = "last_verified_profile"
    last_open_ports: str = "last_open_ports"
    scanner_miss_count: str = "scanner_miss_count"


@dataclass(slots=True)
class StalePolicyConfig:
    scope_tag: str = DEFAULT_VERIFIED_TAG_SLUG
    miss_threshold: int = 5
    delete_unassigned_only: bool = True
    exempt_checkmk: bool = True
    dry_run_deletes: bool = True
    phantom_tag_slug: str = "netbox-scanner-phantom"


@dataclass(slots=True)
class ScannerBehaviorConfig:
    fast_path_existing_netbox: bool = True
    parallel_workers: int = 4
    nmap_batch_prefixlen: int = 24
    checkpoint_path: str = ""
    metadata_fields: MetadataFieldSlugs = field(default_factory=MetadataFieldSlugs)
    stale: StalePolicyConfig = field(default_factory=StalePolicyConfig)


def build_last_verified_custom_fields(
    slugs: MetadataFieldSlugs,
    *,
    profile: str,
    open_ports: list[int] | None = None,
) -> dict[str, str | int]:
    fields: dict[str, str | int] = {
        slugs.last_verified_at: scanner_note_timestamp(),
        slugs.last_verified_profile: profile,
    }
    if open_ports is not None:
        fields[slugs.last_open_ports] = ",".join(str(port) for port in open_ports) or "none"
    return fields


def build_miss_count_fields(slugs: MetadataFieldSlugs, count: int) -> dict[str, int]:
    return {slugs.scanner_miss_count: count}


def build_drift_note(
    description: str,
    *,
    ptr_hostname: str | None,
    netbox_dns: str | None,
    checkmk_host: str | None = None,
) -> str:
    parts: list[str] = []
    if ptr_hostname:
        parts.append(f"PTR={ptr_hostname}")
    if netbox_dns:
        parts.append(f"NetBox-dns={netbox_dns}")
    if checkmk_host:
        parts.append(f"CheckMK={checkmk_host}")
    body = ", ".join(parts) if parts else "see scan log"
    return upsert_scanner_description_line(description, DRIFT_MARKER_PREFIX, body)


def build_stale_miss_note(description: str, miss_count: int, threshold: int) -> str:
    body = f"count={miss_count}/{threshold} (no ping and no PTR on last check)"
    return upsert_scanner_description_line(description, STALE_MISS_PREFIX, body)


def is_alive_ping_or_ptr(*, ping_ok: bool, ptr_hostname: str | None) -> bool:
    return ping_ok or bool(ptr_hostname and str(ptr_hostname).strip())
