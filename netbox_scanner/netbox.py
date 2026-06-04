from __future__ import annotations

import ipaddress
import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Iterable

from .terminal import format_list_preview

LOGGER = logging.getLogger(__name__)

# NetBox 4.5+ v2 tokens: nbt_<id>.<secret> (Bearer). Legacy v1 tokens use Token scheme.
NETBOX_V2_TOKEN_PREFIX = "nbt_"


def is_netbox_v2_token(token: str) -> bool:
    """True when token matches NetBox v2 format (same rules as pynetbox >= 7.6)."""
    value = token.strip()
    if not value.startswith(NETBOX_V2_TOKEN_PREFIX):
        return False
    return "." in value[len(NETBOX_V2_TOKEN_PREFIX) :]


def netbox_authorization_scheme(token: str) -> str:
    return "Bearer" if is_netbox_v2_token(token) else "Token"


def netbox_authorization_header(token: str) -> str:
    value = token.strip()
    return f"{netbox_authorization_scheme(value)} {value}"


@dataclass(slots=True)
class PrefixRecord:
    id: int
    prefix: str
    description: str
    site: str | None = None
    parent_id: int | None = None
    children_count: int = 0
    depth: int | None = None


@dataclass(slots=True)
class RangeRecord:
    name: str
    start_address: str
    end_address: str
    excluded: bool = False
    id: int = 0
    description: str = ""
    prefix: str | None = None
    role_id: int | None = None
    role_name: str | None = None
    role_slug: str | None = None


@dataclass(slots=True)
class IpAddressWriteResult:
    status: str
    payload: dict[str, Any]
    netbox_dns_name: str | None = None
    previous_dns_name: str | None = None
    record_id: int | None = None
    update_payload: dict[str, Any] | None = None


def _as_mapping(record: Any) -> dict[str, Any]:
    if isinstance(record, dict):
        return record
    return {
        "id": getattr(record, "id", 0),
        "name": getattr(record, "name", ""),
        "start_address": getattr(record, "start_address", ""),
        "end_address": getattr(record, "end_address", ""),
        "description": getattr(record, "description", ""),
        "prefix": getattr(record, "prefix", None),
        "status": getattr(record, "status", None),
        "role": getattr(record, "role", None),
        "role_id": getattr(record, "role_id", None),
        "reserved": getattr(record, "reserved", None),
        "excluded": getattr(record, "excluded", None),
        "custom_fields": getattr(record, "custom_fields", {}) or {},
        "site": getattr(record, "site", None),
        "scope": getattr(record, "scope", None),
        "parent": getattr(record, "parent", None),
        "children": getattr(record, "children", None),
        "_depth": getattr(record, "_depth", getattr(record, "depth", None)),
    }


def _choice_value(choice: Any) -> str:
    if isinstance(choice, dict):
        for key in ("value", "label", "name"):
            value = choice.get(key)
            if value:
                return str(value).lower()
        return ""
    if choice is None:
        return ""
    return str(choice).lower()


def _site_name(site: Any) -> str | None:
    if isinstance(site, dict):
        return site.get("name") or site.get("slug")
    if site is None:
        return None
    return str(site)


def _record_site_name(data: dict[str, Any]) -> str | None:
    """Site label from legacy ``site`` or NetBox 4.x ``scope`` (e.g. dcim.site)."""
    site = _site_name(data.get("site"))
    if site:
        return site
    return _site_name(data.get("scope"))


def _record_depth(data: dict[str, Any]) -> int | None:
    for key in ("_depth", "depth"):
        value = data.get(key)
        if value is not None:
            return int(value)
    return None


def _record_children_count(data: dict[str, Any]) -> int:
    value = data.get("children")
    if value is None:
        return 0
    return int(value)


def _prefix_cidr(prefix: Any) -> str | None:
    if isinstance(prefix, dict):
        return prefix.get("prefix")
    if prefix is None:
        return None
    prefix_value = getattr(prefix, "prefix", None)
    return str(prefix_value) if prefix_value else None


def _parse_range_endpoint(value: str) -> str:
    """NetBox IP ranges return host/mask (e.g. 10.207.2.1/22); keep host for overlap logic."""
    text = str(value).strip()
    if not text:
        return text
    if "/" in text:
        return str(ipaddress.ip_interface(text).ip)
    return str(ipaddress.ip_address(text))


def build_role_catalog(api) -> dict[int, tuple[str | None, str | None]]:
    """Map ipam role id to (name, slug) from /api/ipam/roles/."""
    catalog: dict[int, tuple[str | None, str | None]] = {}
    try:
        for role in api.ipam.roles.all():
            data = role if isinstance(role, dict) else _as_mapping(role)
            role_id = data.get("id")
            if role_id is None:
                continue
            name = data.get("name")
            slug = data.get("slug")
            catalog[int(role_id)] = (
                str(name) if name else None,
                str(slug) if slug else None,
            )
    except Exception as exc:
        LOGGER.debug("Failed to fetch ipam roles catalog: %s", exc)
    return catalog


def parse_role(
    role: Any,
    *,
    role_catalog: dict[int, tuple[str | None, str | None]] | None = None,
) -> tuple[str | None, str | None, int | None]:
    """Return role name, slug, and id when available."""
    role_id: int | None = None
    if role is None:
        return None, None, None
    if isinstance(role, dict):
        role_id_value = role.get("id")
        if role_id_value is not None:
            role_id = int(role_id_value)
        name = role.get("name")
        slug = role.get("slug")
        if not name and not slug:
            for key in ("label", "value"):
                value = role.get(key)
                if value:
                    return str(value), None, role_id
            if role_id is not None and role_catalog:
                name, slug = role_catalog.get(role_id, (None, None))
                return name, slug, role_id
            return None, None, role_id
        return (str(name) if name else None), (str(slug) if slug else None), role_id
    role_id_value = getattr(role, "id", None)
    if role_id_value is not None:
        role_id = int(role_id_value)
    name = getattr(role, "name", None)
    slug = getattr(role, "slug", None)
    if name or slug:
        return (str(name) if name else None), (str(slug) if slug else None), role_id
    if role_id is not None and role_catalog:
        name, slug = role_catalog.get(role_id, (None, None))
        return name, slug, role_id
    return str(role), None, role_id


def range_is_excluded(record: Any) -> bool:
    data = _as_mapping(record)
    custom_fields = data.get("custom_fields") or {}
    return any(
        value is True
        for value in (
            data.get("reserved"),
            data.get("excluded"),
            custom_fields.get("reserved"),
            custom_fields.get("excluded"),
        )
    ) or _choice_value(data.get("status")) == "reserved" or _choice_value(data.get("role")) == "excluded"


def _parent_id(parent: Any) -> int | None:
    if parent is None:
        return None
    if isinstance(parent, dict):
        value = parent.get("id")
        return int(value) if value else None
    value = getattr(parent, "id", None)
    return int(value) if value else None


def normalize_prefix_cidr(cidr: str) -> str:
    return str(ipaddress.ip_network(cidr, strict=False))


def parse_prefix_record(record: Any) -> PrefixRecord:
    data = _as_mapping(record)
    return PrefixRecord(
        id=int(data.get("id") or 0),
        prefix=normalize_prefix_cidr(str(data.get("prefix", ""))),
        description=str(data.get("description") or ""),
        site=_record_site_name(data),
        parent_id=_parent_id(data.get("parent")),
        children_count=_record_children_count(data),
        depth=_record_depth(data),
    )


def build_prefix_index(records: list[PrefixRecord]) -> dict[int, PrefixRecord]:
    return {record.id: record for record in records if record.id}


def children_by_parent(records: list[PrefixRecord]) -> dict[int, list[PrefixRecord]]:
    children: dict[int, list[PrefixRecord]] = {}
    for record in records:
        if record.parent_id is None:
            continue
        children.setdefault(record.parent_id, []).append(record)
    return children


def _prefix_network(record: PrefixRecord) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(record.prefix, strict=False)


def immediate_containing_prefix(
    record: PrefixRecord,
    records: list[PrefixRecord],
) -> PrefixRecord | None:
    """Most specific other prefix in the set that strictly contains this one."""
    network = _prefix_network(record)
    best: PrefixRecord | None = None
    best_prefixlen = -1
    for candidate in records:
        if candidate.id == record.id:
            continue
        try:
            supernet = _prefix_network(candidate)
        except ValueError:
            continue
        if network.subnet_of(supernet) and network != supernet:
            if supernet.prefixlen > best_prefixlen:
                best = candidate
                best_prefixlen = supernet.prefixlen
    return best


def resolve_parent_record(
    record: PrefixRecord,
    records: list[PrefixRecord],
    *,
    index: dict[int, PrefixRecord] | None = None,
) -> PrefixRecord | None:
    prefix_index = index or build_prefix_index(records)
    if record.parent_id is not None and record.parent_id in prefix_index:
        return prefix_index[record.parent_id]
    return immediate_containing_prefix(record, records)


def build_prefix_children_map(records: list[PrefixRecord]) -> dict[int, list[PrefixRecord]]:
    """Direct children: immediate NetBox parent or most specific containing prefix in the set."""
    index = build_prefix_index(records)
    children: dict[int, list[PrefixRecord]] = {}
    for record in records:
        parent = resolve_parent_record(record, records, index=index)
        if parent is None:
            continue
        children.setdefault(parent.id, []).append(record)
    return children


def _records_contained_in(
    parent: PrefixRecord,
    records: list[PrefixRecord],
) -> list[PrefixRecord]:
    parent_net = _prefix_network(parent)
    contained: list[PrefixRecord] = []
    for record in records:
        if record.id == parent.id:
            continue
        try:
            network = _prefix_network(record)
        except ValueError:
            continue
        if network.subnet_of(parent_net) and network != parent_net:
            contained.append(record)
    return contained


def maximal_prefixes_within(
    parent: PrefixRecord,
    records: list[PrefixRecord],
) -> list[str]:
    """Deepest prefixes inside parent among the set (no other listed prefix is a strict subnet)."""
    contained = _records_contained_in(parent, records)
    if not contained:
        return [parent.prefix]

    maximal: list[str] = []
    for record in contained:
        network = _prefix_network(record)
        if any(
            _prefix_network(other).subnet_of(network) and _prefix_network(other) != network
            for other in contained
            if other.id != record.id
        ):
            continue
        maximal.append(record.prefix)
    return sorted(maximal)


def prefix_is_tree_child(record: PrefixRecord) -> bool:
    """True when NetBox reports this prefix below the root of its hierarchy (_depth > 0)."""
    return record.depth is not None and record.depth > 0


def prefixes_for_display(records: list[PrefixRecord]) -> list[PrefixRecord]:
    """Top-level prefixes for the picker: hide tree children and rows with a containing prefix."""
    display: list[PrefixRecord] = []
    for record in records:
        if prefix_is_tree_child(record):
            continue
        if resolve_parent_record(record, records) is not None:
            continue
        display.append(record)
    return sorted(display, key=lambda item: (item.site or "", item.prefix))


def prefix_has_children(
    record: PrefixRecord,
    children: dict[int, list[PrefixRecord]],
) -> bool:
    return record.id in children


def scan_targets_for_prefix(record: PrefixRecord, records: list[PrefixRecord]) -> list[str]:
    return maximal_prefixes_within(record, records)


def scan_preview_for_prefix(record: PrefixRecord, records: list[PrefixRecord]) -> str:
    targets = scan_targets_for_prefix(record, records)
    if targets == [record.prefix]:
        return "(scans this prefix)"
    return format_list_preview(targets)


def _record_by_cidr(records: list[PrefixRecord], cidr: str) -> PrefixRecord | None:
    normalized = normalize_prefix_cidr(cidr)
    for record in records:
        if record.prefix == normalized:
            return record
    return None


def count_scan_targets(record: PrefixRecord, records: list[PrefixRecord]) -> int:
    return len(scan_targets_for_prefix(record, records))


def display_scan_target_count(record: PrefixRecord, records: list[PrefixRecord]) -> int:
    """Count for the prefix picker: NetBox direct child count when set, else leaf CIDRs to scan."""
    if record.children_count > 0:
        return record.children_count
    return count_scan_targets(record, records)


def format_scan_target_label(count: int) -> str:
    return str(count) if count > 1 else "-"


def expand_prefixes_to_scan_cidrs(records: list[PrefixRecord], selected_cidrs: list[str]) -> list[str]:
    expanded: list[str] = []
    seen: set[str] = set()

    for cidr in selected_cidrs:
        record = _record_by_cidr(records, cidr)
        if record is None:
            normalized = normalize_prefix_cidr(cidr)
            if normalized not in seen:
                seen.add(normalized)
                expanded.append(normalized)
            continue

        for scan_cidr in scan_targets_for_prefix(record, records):
            if scan_cidr in seen:
                continue
            seen.add(scan_cidr)
            expanded.append(scan_cidr)

    return expanded


def parse_range_record(
    record: Any,
    *,
    prefix: str | None = None,
    role_catalog: dict[int, tuple[str | None, str | None]] | None = None,
) -> RangeRecord:
    data = _as_mapping(record)
    role_name, role_slug, nested_role_id = parse_role(data.get("role"), role_catalog=role_catalog)
    role_id_value = data.get("role_id")
    role_id = int(role_id_value) if role_id_value is not None else nested_role_id
    if role_id is not None and role_catalog and not role_name and not role_slug:
        role_name, role_slug = role_catalog.get(role_id, (None, None))

    start_raw = str(data.get("start_address", ""))
    end_raw = str(data.get("end_address", ""))
    return RangeRecord(
        id=int(data.get("id") or 0),
        name=str(data.get("name", "")),
        start_address=_parse_range_endpoint(start_raw) if start_raw else "",
        end_address=_parse_range_endpoint(end_raw) if end_raw else "",
        description=str(data.get("description") or ""),
        excluded=range_is_excluded(data),
        prefix=prefix or _prefix_cidr(data.get("prefix")),
        role_id=role_id,
        role_name=role_name,
        role_slug=role_slug,
    )


def range_contained_in_prefix(record: Any, cidr: str) -> bool:
    data = _as_mapping(record)
    try:
        start = ipaddress.ip_address(_parse_range_endpoint(str(data.get("start_address", ""))))
        end = ipaddress.ip_address(_parse_range_endpoint(str(data.get("end_address", ""))))
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return start in network and end in network


def range_overlaps_prefix(record: Any, cidr: str) -> bool:
    """True when any part of the IP range overlaps the prefix (broader than full containment)."""
    data = _as_mapping(record)
    try:
        start = ipaddress.ip_address(_parse_range_endpoint(str(data.get("start_address", ""))))
        end = ipaddress.ip_address(_parse_range_endpoint(str(data.get("end_address", ""))))
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    if start in network or end in network:
        return True
    return int(start) <= int(network.broadcast_address) and int(end) >= int(network.network_address)


def _normalize_role_token(value: str) -> str:
    """Case-insensitive role match; spaces, hyphens, and underscores equivalent."""
    return value.strip().lower().replace("_", "-").replace(" ", "-")


def build_skip_role_match_keys(api, skip_roles: list[str]) -> set[str]:
    keys, _, _ = build_skip_role_matchers(api, skip_roles)
    return keys


def build_skip_role_matchers(
    api,
    skip_roles: list[str],
    *,
    role_catalog: dict[int, tuple[str | None, str | None]] | None = None,
) -> tuple[set[str], set[int], dict[int, tuple[str | None, str | None]]]:
    """Normalized name/slug keys, matching role ids, and full role catalog."""
    keys: set[str] = set()
    role_ids: set[int] = set()
    config_norm: set[str] = set()
    for role in skip_roles:
        value = role.strip()
        if not value:
            continue
        keys.add(value.lower())
        normalized = _normalize_role_token(value)
        keys.add(normalized)
        config_norm.add(normalized)

    catalog = role_catalog if role_catalog is not None else build_role_catalog(api)
    for role_id, (name, slug) in catalog.items():
        name_norm = _normalize_role_token(name) if name else None
        slug_norm = _normalize_role_token(slug) if slug else None
        if (name_norm and name_norm in config_norm) or (slug_norm and slug_norm in config_norm):
            role_ids.add(role_id)
            if name_norm:
                keys.add(name_norm)
            if slug_norm:
                keys.add(slug_norm)
            if name:
                keys.add(str(name).lower())
            if slug:
                keys.add(str(slug).lower())

    return keys, role_ids, catalog


def build_role_slug_index(api) -> dict[str, str]:
    """Map lowercase role name or slug to canonical NetBox role slug."""
    index: dict[str, str] = {}
    try:
        roles = api.ipam.roles.all()
    except Exception as exc:
        LOGGER.debug("Failed to fetch ipam roles: %s", exc)
        return index
    for role in roles:
        data = role if isinstance(role, dict) else _as_mapping(role)
        name = data.get("name")
        slug = data.get("slug")
        if slug:
            slug_str = str(slug)
            index[slug_str.lower()] = slug_str
        if name and slug:
            index[str(name).lower()] = str(slug)
    return index


def _slugify_role_guess(role: str) -> str:
    return role.strip().lower().replace(" ", "-")


def resolve_skip_role_slugs(api, skip_roles: list[str]) -> list[str]:
    if not skip_roles:
        return []
    index = build_role_slug_index(api)
    resolved: list[str] = []
    seen: set[str] = set()
    for role in skip_roles:
        key = role.strip().lower()
        if not key:
            continue
        slug = index.get(key)
        if slug is None:
            slug = _slugify_role_guess(role)
            LOGGER.warning(
                "Skip role %r not found in NetBox ipam/roles; using slug guess %r",
                role,
                slug,
            )
        if slug not in seen:
            seen.add(slug)
            resolved.append(slug)
    return resolved


def _append_unique_range(
    ranges: list[RangeRecord],
    seen_ids: set[int],
    record: RangeRecord,
) -> None:
    if record.id:
        if record.id in seen_ids:
            return
        seen_ids.add(record.id)
    ranges.append(record)


def fetch_prefixes(api) -> list[PrefixRecord]:
    return [parse_prefix_record(record) for record in api.ipam.prefixes.all()]


def collect_ranges_by_name(api, names: list[str]) -> list[RangeRecord]:
    ranges: list[RangeRecord] = []
    for name in names:
        for record in api.ipam.ip_ranges.filter(name=name):
            ranges.append(parse_range_record(record))
    return ranges


def collect_ranges_within_prefixes(
    api,
    prefix_cidrs: list[str],
    *,
    ip_range_records: list[Any] | None = None,
) -> list[RangeRecord]:
    ranges: list[RangeRecord] = []
    seen_ids: set[int] = set()

    if ip_range_records is not None:
        for cidr in prefix_cidrs:
            for record in ip_range_records:
                if not range_contained_in_prefix(record, cidr):
                    continue
                parsed = parse_range_record(record, prefix=cidr)
                _append_unique_range(ranges, seen_ids, parsed)
        return ranges

    for cidr in prefix_cidrs:
        candidates: list[Any] = []
        try:
            candidates = list(api.ipam.ip_ranges.filter(parent=cidr))
        except Exception as exc:
            LOGGER.debug("NetBox parent filter failed for %s: %s", cidr, exc)
            candidates = []

        if not candidates:
            candidates = [
                record
                for record in api.ipam.ip_ranges.all()
                if range_contained_in_prefix(record, cidr)
            ]

        for record in candidates:
            if not range_contained_in_prefix(record, cidr):
                continue
            parsed = parse_range_record(record, prefix=cidr)
            _append_unique_range(ranges, seen_ids, parsed)

    return ranges


def union_prefix_cidrs(*cidr_groups: list[str] | None) -> list[str]:
    """Deduped prefix list (e.g. selected parent /16 plus expanded child /24 scan CIDRs)."""
    seen: set[str] = set()
    merged: list[str] = []
    for group in cidr_groups:
        if not group:
            continue
        for cidr in group:
            try:
                normalized = str(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            merged.append(normalized)
    return merged


def _best_overlap_prefix(record: Any, prefix_cidrs: list[str]) -> str | None:
    """Most specific prefix in the list that overlaps the range (for table display)."""
    best: str | None = None
    best_prefixlen = -1
    for cidr in prefix_cidrs:
        if not range_overlaps_prefix(record, cidr):
            continue
        try:
            prefixlen = ipaddress.ip_network(cidr, strict=False).prefixlen
        except ValueError:
            continue
        if prefixlen > best_prefixlen:
            best = cidr
            best_prefixlen = prefixlen
    return best


def collect_ranges_by_skip_roles_for_prefixes(
    api,
    prefix_cidrs: list[str],
    skip_roles: list[str],
    *,
    ip_range_records: list[Any] | None = None,
    role_catalog: dict[int, tuple[str | None, str | None]] | None = None,
) -> list[RangeRecord]:
    """IP ranges whose assigned role matches skip_roles and overlaps a prefix in scope."""
    if not skip_roles or not prefix_cidrs:
        return []

    if role_catalog is None:
        role_catalog = build_role_catalog(api)
    match_keys, match_role_ids, role_catalog = build_skip_role_matchers(
        api, skip_roles, role_catalog=role_catalog
    )
    if not match_keys and not match_role_ids:
        return []

    ranges: list[RangeRecord] = []
    seen_ids: set[int] = set()

    try:
        all_records = (
            ip_range_records
            if ip_range_records is not None
            else list(api.ipam.ip_ranges.all())
        )
    except Exception as exc:
        LOGGER.debug("Failed to fetch all ip_ranges for skip_roles: %s", exc)
        return []

    matched_roles = 0
    matched_overlap = 0
    for record in all_records:
        parsed = parse_range_record(record, role_catalog=role_catalog)
        if not range_matches_skip_role(
            parsed,
            skip_roles,
            match_keys=match_keys,
            role_ids=match_role_ids,
        ):
            continue
        matched_roles += 1

        overlap_prefix = _best_overlap_prefix(record, prefix_cidrs)
        if overlap_prefix is None:
            continue
        matched_overlap += 1

        parsed_with_prefix = parse_range_record(
            record,
            prefix=overlap_prefix,
            role_catalog=role_catalog,
        )
        _append_unique_range(ranges, seen_ids, parsed_with_prefix)

    if matched_roles and not ranges:
        LOGGER.warning(
            "Found %s IP range(s) with skip role(s) %s but none overlap scan prefixes: %s",
            matched_roles,
            skip_roles,
            ", ".join(prefix_cidrs[:5]),
        )
    elif not matched_roles and skip_roles:
        LOGGER.warning(
            "No IP ranges matched skip_roles %s (check role names in config vs /api/ipam/roles/)",
            skip_roles,
        )

    return ranges


def apply_skip_ranges(records: list[RangeRecord], skip_names: list[str]) -> list[RangeRecord]:
    if not skip_names:
        return records
    skip = set(skip_names)
    return [record for record in records if record.name not in skip]


def range_matches_skip_role(
    record: RangeRecord,
    skip_roles: list[str],
    *,
    match_keys: set[str] | None = None,
    role_ids: set[int] | None = None,
    api: Any | None = None,
) -> bool:
    if not skip_roles:
        return False

    keys = match_keys
    ids = role_ids
    if keys is None or ids is None:
        if api is not None:
            built_keys, built_ids, _ = build_skip_role_matchers(api, skip_roles)
            keys = built_keys if keys is None else keys
            ids = built_ids if ids is None else ids
        else:
            if keys is None:
                keys = set()
                for role in skip_roles:
                    value = role.strip()
                    if not value:
                        continue
                    keys.add(value.lower())
                    keys.add(_normalize_role_token(value))
            if ids is None:
                ids = set()
    if not keys and not ids:
        return False

    if record.role_id is not None and record.role_id in ids:
        return True

    candidates: set[str] = set()
    if record.role_name:
        candidates.add(record.role_name.lower())
        candidates.add(_normalize_role_token(record.role_name))
    if record.role_slug:
        candidates.add(record.role_slug.lower())
        candidates.add(_normalize_role_token(record.role_slug))
    if not candidates:
        return False
    return bool(candidates & keys)


def apply_skip_roles(records: list[RangeRecord], skip_roles: list[str]) -> list[RangeRecord]:
    if not skip_roles:
        return records
    return [record for record in records if not range_matches_skip_role(record, skip_roles)]


def iter_range_ips(record: RangeRecord):
    start = ipaddress.ip_address(record.start_address)
    end = ipaddress.ip_address(record.end_address)
    if start.version != end.version:
        raise ValueError("Range address families must match.")
    for raw_value in range(int(start), int(end) + 1):
        yield ipaddress.ip_address(raw_value)


def range_exclusion_reason(
    record: RangeRecord,
    *,
    skip_names: list[str],
    skip_roles: list[str],
) -> str | None:
    if record.excluded:
        return "reserved/excluded"
    if record.name in skip_names:
        return "skip name"
    if range_matches_skip_role(record, skip_roles):
        return "skip role"
    return None


def collect_exclusion_ranges_for_prefixes(
    api,
    scan_prefix_cidrs: list[str],
    skip_names: list[str],
    skip_roles: list[str],
    *,
    selected_prefix_cidrs: list[str] | None = None,
    ip_range_records: list[Any] | None = None,
    role_catalog: dict[int, tuple[str | None, str | None]] | None = None,
) -> list[RangeRecord]:
    """IP range spans to exclude from prefix host scans (not whole prefixes).

    Uses one ip_ranges payload when ip_range_records is omitted or supplied by the client cache.
    """
    skip_name_set = set(skip_names)
    exclusions: list[RangeRecord] = []
    seen_ids: set[int] = set()
    scope_cidrs = union_prefix_cidrs(selected_prefix_cidrs, scan_prefix_cidrs)
    if not scope_cidrs:
        return []

    if role_catalog is None:
        role_catalog = build_role_catalog(api)

    match_keys: set[str] | None = None
    match_role_ids: set[int] | None = None
    if skip_roles:
        match_keys, match_role_ids, _ = build_skip_role_matchers(
            api, skip_roles, role_catalog=role_catalog
        )

    try:
        all_records = (
            ip_range_records
            if ip_range_records is not None
            else list(api.ipam.ip_ranges.all())
        )
    except Exception as exc:
        LOGGER.debug("Failed to fetch ip_ranges for exclusions: %s", exc)
        return []

    matched_roles = 0
    matched_overlap = 0
    for raw in all_records:
        overlap_prefix = _best_overlap_prefix(raw, scope_cidrs)
        if overlap_prefix is None:
            continue

        parsed = parse_range_record(
            raw,
            prefix=overlap_prefix,
            role_catalog=role_catalog,
        )

        include = False
        if parsed.excluded or parsed.name in skip_name_set:
            include = True
        elif skip_roles and range_matches_skip_role(
            parsed,
            skip_roles,
            match_keys=match_keys,
            role_ids=match_role_ids,
        ):
            matched_roles += 1
            matched_overlap += 1
            include = True

        if include:
            _append_unique_range(exclusions, seen_ids, parsed)

    if skip_roles:
        if matched_roles and not exclusions:
            LOGGER.warning(
                "Found %s IP range(s) with skip role(s) %s but none overlap scan prefixes: %s",
                matched_roles,
                skip_roles,
                ", ".join(scope_cidrs[:5]),
            )
        elif not matched_roles:
            LOGGER.warning(
                "No IP ranges matched skip_roles %s (check role names in config vs /api/ipam/roles/)",
                skip_roles,
            )

    return exclusions


def build_scan_target_counts(
    display_prefixes: list[PrefixRecord],
    all_records: list[PrefixRecord],
) -> dict[int, int]:
    """Precompute picker scan-target counts (one pass per displayed prefix)."""
    return {
        prefix.id: display_scan_target_count(prefix, all_records)
        for prefix in display_prefixes
    }


def iter_prefix_hosts(cidr: str):
    network = ipaddress.ip_network(cidr, strict=False)
    yield from network.hosts()


def iter_unique_targets_from_prefixes(
    prefix_cidrs: list[str],
    *,
    max_hosts: int | None = None,
) -> list[str]:
    seen: set[str] = set()
    targets: list[str] = []
    for cidr in prefix_cidrs:
        for ip in iter_prefix_hosts(cidr):
            ip_str = str(ip)
            if ip_str in seen:
                continue
            seen.add(ip_str)
            targets.append(ip_str)
            if max_hosts is not None and len(targets) > max_hosts:
                raise ValueError(
                    f"Scan target count ({len(targets)}) exceeds --max-hosts limit ({max_hosts})."
                )
    return targets


def iter_unique_targets(
    records: list[RangeRecord],
    *,
    max_hosts: int | None = None,
) -> list[str]:
    seen: set[str] = set()
    targets: list[str] = []
    for record in records:
        for ip in iter_range_ips(record):
            ip_str = str(ip)
            if ip_str in seen:
                continue
            seen.add(ip_str)
            targets.append(ip_str)
            if max_hosts is not None and len(targets) > max_hosts:
                raise ValueError(
                    f"Scan target count ({len(targets)}) exceeds --max-hosts limit ({max_hosts})."
                )
    return targets


def build_ip_address_payload(
    ip: str,
    hostname: str | None = None,
    *,
    tag_slug: str | None = None,
) -> dict[str, Any]:
    address = ipaddress.ip_address(ip)
    cidr = 32 if address.version == 4 else 128
    payload: dict[str, Any] = {"address": f"{address}/{cidr}", "status": "active"}
    if hostname:
        payload["dns_name"] = hostname
    if tag_slug:
        payload["tags"] = [{"slug": tag_slug}]
    return payload


_DUPLICATE_IP_ADDRESS_RE = re.compile(
    r"Duplicate IP address found in global table:\s*([0-9a-fA-F:\.]+/\d+)",
    re.IGNORECASE,
)


def record_address(record: Any) -> str:
    if isinstance(record, dict):
        return str(record.get("address") or "")
    return str(getattr(record, "address", "") or "")


def host_matches_address(ip: str, address_value: str) -> bool:
    if not address_value:
        return False
    try:
        return ipaddress.ip_address(ip) == ipaddress.ip_interface(address_value).ip
    except ValueError:
        return False


def is_no_data_provided_error(exc: Exception) -> bool:
    try:
        import pynetbox
    except ImportError:  # pragma: no cover - optional at test time
        return False
    if not isinstance(exc, pynetbox.RequestError):
        return False
    status_code = getattr(getattr(exc, "req", None), "status_code", None)
    if status_code != 400:
        return False
    blob = str(exc)
    error = getattr(exc, "error", None)
    if error is not None:
        blob = f"{blob} {error!r}"
    return "No data provided" in blob


def is_duplicate_ip_address_error(exc: Exception) -> bool:
    try:
        import pynetbox
    except ImportError:  # pragma: no cover - optional at test time
        return False
    if not isinstance(exc, pynetbox.RequestError):
        return False
    status_code = getattr(getattr(exc, "req", None), "status_code", None)
    if status_code != 400:
        return False
    blob = str(exc)
    error = getattr(exc, "error", None)
    if error is not None:
        blob = f"{blob} {error!r}"
    return "Duplicate IP address" in blob


def duplicate_address_from_error(exc: Exception) -> str | None:
    chunks: list[str] = [str(exc)]
    error = getattr(exc, "error", None)
    if isinstance(error, dict):
        for messages in error.values():
            if isinstance(messages, list):
                chunks.extend(str(message) for message in messages)
            else:
                chunks.append(str(messages))
    elif error is not None:
        chunks.append(str(error))
    for chunk in chunks:
        match = _DUPLICATE_IP_ADDRESS_RE.search(chunk)
        if match:
            return match.group(1)
    return None


def evaluate_existing_ip_address(
    existing: Any,
    *,
    ip: str,
    hostname: str | None,
    payload: dict[str, Any],
    apply_checkmk_tag: bool = False,
    checkmk_tag_slug: str = "checkmk",
) -> IpAddressWriteResult:
    netbox_dns = record_dns_name(existing)
    verified = normalize_hostname(hostname)
    record_id = record_id_value(existing) or None
    tag_slug = checkmk_tag_slug if apply_checkmk_tag else None
    needs_tag = bool(tag_slug and tag_slug.lower() not in record_tag_slugs(existing))
    if netbox_dns == verified:
        if needs_tag:
            return IpAddressWriteResult(
                status="tag_update",
                payload=payload,
                netbox_dns_name=netbox_dns or None,
                previous_dns_name=netbox_dns or None,
                record_id=record_id,
                update_payload=build_tag_only_update(existing, tag_slug),
            )
        return IpAddressWriteResult(
            status="already_exists",
            payload=payload,
            netbox_dns_name=netbox_dns or None,
            previous_dns_name=netbox_dns or None,
            record_id=record_id,
        )
    return IpAddressWriteResult(
        status="drift",
        payload=payload,
        netbox_dns_name=netbox_dns or None,
        previous_dns_name=netbox_dns or None,
        record_id=record_id,
        update_payload=build_ip_address_update(
            existing,
            hostname,
            tag_slug=tag_slug if apply_checkmk_tag else None,
        ),
    )


def record_description(record: Any) -> str:
    if isinstance(record, dict):
        return str(record.get("description") or "")
    return str(getattr(record, "description", "") or "")


def record_id_value(record: Any) -> int:
    if isinstance(record, dict):
        return int(record.get("id") or 0)
    return int(getattr(record, "id", 0) or 0)


def record_tags(record: Any) -> list[Any]:
    if isinstance(record, dict):
        tags = record.get("tags")
    else:
        tags = getattr(record, "tags", None)
    if isinstance(tags, list):
        return tags
    return []


def record_tag_slugs(record: Any) -> set[str]:
    slugs: set[str] = set()
    for tag in record_tags(record):
        if isinstance(tag, dict):
            slug = tag.get("slug") or tag.get("name")
        else:
            slug = getattr(tag, "slug", None) or getattr(tag, "name", None)
        if slug:
            slugs.add(str(slug).lower())
    return slugs


def netbox_tags_payload(tag_slugs: Iterable[str]) -> list[dict[str, str]]:
    return [{"slug": slug} for slug in sorted({slug.lower() for slug in tag_slugs if slug})]


def merge_checkmk_tag(existing: Any, tag_slug: str) -> list[dict[str, str]]:
    slugs = record_tag_slugs(existing)
    slugs.add(tag_slug.lower())
    return netbox_tags_payload(slugs)


def build_tag_only_update(existing: Any, tag_slug: str) -> dict[str, Any]:
    return {
        "id": record_id_value(existing),
        "tags": merge_checkmk_tag(existing, tag_slug),
    }


def format_previous_dns_name_note(previous_dns_name: str | None) -> str:
    previous = previous_dns_name.strip() if previous_dns_name else "(none)"
    return f"Previous dns_name: {previous} (netbox-scanner)"


def append_previous_dns_name_note(description: str, previous_dns_name: str | None) -> str:
    note = format_previous_dns_name_note(previous_dns_name)
    if not description.strip():
        return note
    return f"{description.rstrip()}\n{note}"


def build_ip_address_update(
    existing: Any,
    hostname: str | None,
    *,
    tag_slug: str | None = None,
) -> dict[str, Any]:
    ip = str(record_address(existing)).split("/")[0]
    payload = build_ip_address_payload(ip, hostname)
    old_dns = record_dns_name(existing)
    update: dict[str, Any] = {
        "id": record_id_value(existing),
        "description": append_previous_dns_name_note(record_description(existing), old_dns or None),
    }
    if "dns_name" in payload:
        update["dns_name"] = payload["dns_name"]
    elif old_dns:
        update["dns_name"] = ""
    if tag_slug and tag_slug.lower() not in record_tag_slugs(existing):
        update["tags"] = merge_checkmk_tag(existing, tag_slug)
    return update


def normalize_hostname(hostname: str | None) -> str:
    if not hostname:
        return ""
    return hostname.rstrip(".").lower()


def record_dns_name(record: Any) -> str:
    if record is None:
        return ""
    if isinstance(record, dict):
        return normalize_hostname(record.get("dns_name"))
    return normalize_hostname(getattr(record, "dns_name", None))


def _is_unsupported_filter(exc: Exception) -> bool:
    message = str(exc).lower()
    return "filter" in message and "host" in message


class NetBoxClient:
    def __init__(
        self,
        base_url: str,
        api_token: str,
        *,
        timeout: float = 30.0,
        rate_limit: float = 0.0,
        api=None,
    ) -> None:
        self.base_url = base_url
        self.api_token = api_token.strip()
        self.timeout = timeout
        self.rate_limit = rate_limit
        self._api = api
        self._prefix_cache: list[PrefixRecord] | None = None
        self._ip_range_raw_cache: list[Any] | None = None
        self._role_catalog_cache: dict[int, tuple[str | None, str | None]] | None = None

    @property
    def api(self):
        if self._api is None:
            try:
                import pynetbox
            except ImportError as exc:  # pragma: no cover - optional at test time
                raise RuntimeError("pynetbox is required for NetBox integration.") from exc
            self._api = pynetbox.api(self.base_url, token=self.api_token)
            self._api.http_session.verify = True
            self._api.http_session.timeout = self.timeout
        return self._api

    def _sleep(self) -> None:
        if self.rate_limit > 0:
            time.sleep(self.rate_limit)

    def _handle_request_error(self, exc: Exception) -> None:
        try:
            import pynetbox
        except ImportError:  # pragma: no cover - optional at test time
            raise exc

        if not isinstance(exc, pynetbox.RequestError):
            raise exc

        status_code = getattr(getattr(exc, "req", None), "status_code", None)
        if status_code in (401, 403):
            hint = " Check netbox.base_url and api_token in your config file (or --config path)."
            raise RuntimeError(
                f"NetBox authentication failed (HTTP {status_code}) for {self.base_url}.{hint}"
            ) from exc
        if status_code is not None and status_code >= 500:
            raise RuntimeError(f"NetBox server error (HTTP {status_code}).") from exc
        raise exc

    def verify_authentication(self) -> None:
        """Probe /api/status/ with the same token and base URL the scanner uses."""
        self._sleep()
        url = f"{self.base_url.rstrip('/')}/api/status/"
        try:
            response = self.api.http_session.get(
                url,
                headers={
                    "Authorization": netbox_authorization_header(self.api_token),
                    "Accept": "application/json",
                },
                timeout=self.timeout,
            )
        except Exception as exc:
            raise RuntimeError(f"NetBox connection failed for {self.base_url}: {exc}") from exc

        if response.status_code in (401, 403):
            raise RuntimeError(
                f"NetBox authentication failed (HTTP {response.status_code}) for {self.base_url}. "
                "The API token was rejected (same check as GET /api/status/). "
                "Ensure netbox.api_token and netbox.base_url in your config file match the token and URL used in curl. "
                f"Use Authorization: {netbox_authorization_scheme(self.api_token)} for this token format."
            )
        try:
            response.raise_for_status()
        except Exception as exc:
            raise RuntimeError(
                f"NetBox status check failed for {self.base_url} (HTTP {response.status_code})."
            ) from exc

    def _role_catalog(self) -> dict[int, tuple[str | None, str | None]]:
        if self._role_catalog_cache is None:
            self._sleep()
            self._role_catalog_cache = build_role_catalog(self.api)
        return self._role_catalog_cache

    def _ip_range_raw(self) -> list[Any]:
        if self._ip_range_raw_cache is None:
            self._sleep()
            try:
                self._ip_range_raw_cache = list(self.api.ipam.ip_ranges.all())
            except Exception as exc:
                self._handle_request_error(exc)
        return self._ip_range_raw_cache

    def fetch_prefixes(self) -> list[PrefixRecord]:
        if self._prefix_cache is not None:
            return self._prefix_cache
        self._sleep()
        try:
            self._prefix_cache = fetch_prefixes(self.api)
        except Exception as exc:
            self._handle_request_error(exc)
        return self._prefix_cache

    def fetch_ranges_within_prefixes(self, prefix_cidrs: list[str]) -> list[RangeRecord]:
        self._sleep()
        return collect_ranges_within_prefixes(
            self.api,
            prefix_cidrs,
            ip_range_records=self._ip_range_raw_cache,
        )

    def fetch_exclusion_ranges_for_prefixes(
        self,
        scan_prefix_cidrs: list[str],
        skip_names: list[str],
        skip_roles: list[str],
        *,
        selected_prefix_cidrs: list[str] | None = None,
    ) -> list[RangeRecord]:
        if self._ip_range_raw_cache is None:
            self._sleep()
        return collect_exclusion_ranges_for_prefixes(
            self.api,
            scan_prefix_cidrs,
            skip_names,
            skip_roles,
            selected_prefix_cidrs=selected_prefix_cidrs,
            ip_range_records=self._ip_range_raw(),
            role_catalog=self._role_catalog(),
        )

    def fetch_scan_ranges(self, names: list[str]) -> list[RangeRecord]:
        self._sleep()
        return collect_ranges_by_name(self.api, names)

    def fetch_excluded_ranges(self) -> list[RangeRecord]:
        role_catalog = self._role_catalog()
        return [
            parse_range_record(record, role_catalog=role_catalog)
            for record in self._ip_range_raw()
            if range_is_excluded(record)
        ]

    def _lookup_ip_address(self, ip: str) -> Any | None:
        payload = build_ip_address_payload(ip)
        self._sleep()
        try:
            existing = self.api.ipam.ip_addresses.get(address=payload["address"])
        except Exception as exc:
            self._handle_request_error(exc)
        if existing is not None:
            return existing

        target = str(ipaddress.ip_address(ip))
        matches: list[Any] = []
        try:
            matches = list(self.api.ipam.ip_addresses.filter(host=target))
        except Exception as exc:
            if not _is_unsupported_filter(exc):
                self._handle_request_error(exc)

        for record in matches:
            if host_matches_address(ip, record_address(record)):
                return record
        return None

    def _apply_ip_address_update(
        self,
        evaluation: IpAddressWriteResult,
        *,
        hostname: str | None,
    ) -> IpAddressWriteResult:
        update_payload = evaluation.update_payload
        if update_payload is None:
            raise RuntimeError("Missing NetBox update payload.")
        record_id = evaluation.record_id or int(update_payload["id"])
        patch_body = {key: value for key, value in update_payload.items() if key != "id"}
        if not patch_body:
            LOGGER.warning("Skipping NetBox update for record %s: no writable fields.", record_id)
            return IpAddressWriteResult(
                status="drift",
                payload=evaluation.payload,
                update_payload=update_payload,
                netbox_dns_name=evaluation.netbox_dns_name,
                previous_dns_name=evaluation.previous_dns_name,
                record_id=record_id,
            )
        self._sleep()
        try:
            record = self.api.ipam.ip_addresses.get(record_id)
            if record is None:
                raise RuntimeError(f"NetBox IP address record {record_id} not found.")
            record.update(patch_body)
        except Exception as exc:
            if is_no_data_provided_error(exc):
                LOGGER.warning(
                    "NetBox rejected update for record %s (%s): %s",
                    record_id,
                    evaluation.payload.get("address", ""),
                    exc,
                )
                return IpAddressWriteResult(
                    status="drift",
                    payload=evaluation.payload,
                    update_payload=update_payload,
                    netbox_dns_name=evaluation.netbox_dns_name,
                    previous_dns_name=evaluation.previous_dns_name,
                    record_id=record_id,
                )
            self._handle_request_error(exc)
        return IpAddressWriteResult(
            status="updated",
            payload=evaluation.payload,
            update_payload=update_payload,
            netbox_dns_name=evaluation.netbox_dns_name,
            previous_dns_name=evaluation.previous_dns_name,
            record_id=record_id,
        )

    def _upsert_after_duplicate_create(
        self,
        ip: str,
        *,
        hostname: str | None,
        exc: Exception,
        apply_checkmk_tag: bool = False,
        checkmk_tag_slug: str = "checkmk",
    ) -> IpAddressWriteResult:
        existing = self._lookup_ip_address(ip)
        if existing is None:
            duplicate_cidr = duplicate_address_from_error(exc)
            if duplicate_cidr:
                self._sleep()
                try:
                    existing = self.api.ipam.ip_addresses.get(address=duplicate_cidr)
                except Exception as lookup_exc:
                    self._handle_request_error(lookup_exc)
        if existing is None:
            self._handle_request_error(exc)

        payload = build_ip_address_payload(
            ip,
            hostname,
            tag_slug=checkmk_tag_slug if apply_checkmk_tag else None,
        )
        evaluation = evaluate_existing_ip_address(
            existing,
            ip=ip,
            hostname=hostname,
            payload=payload,
            apply_checkmk_tag=apply_checkmk_tag,
            checkmk_tag_slug=checkmk_tag_slug,
        )
        if evaluation.status == "already_exists":
            return evaluation
        return self._apply_ip_address_update(evaluation, hostname=hostname)

    def evaluate_ip_address(
        self,
        ip: str,
        hostname: str | None = None,
        *,
        apply_checkmk_tag: bool = False,
        checkmk_tag_slug: str = "checkmk",
    ) -> IpAddressWriteResult:
        payload = build_ip_address_payload(
            ip,
            hostname,
            tag_slug=checkmk_tag_slug if apply_checkmk_tag else None,
        )
        existing = self._lookup_ip_address(ip)
        if existing is None:
            return IpAddressWriteResult(status="not_found", payload=payload)
        return evaluate_existing_ip_address(
            existing,
            ip=ip,
            hostname=hostname,
            payload=payload,
            apply_checkmk_tag=apply_checkmk_tag,
            checkmk_tag_slug=checkmk_tag_slug,
        )

    def upsert_ip_address(
        self,
        ip: str,
        hostname: str | None = None,
        *,
        dry_run: bool = False,
        apply_checkmk_tag: bool = False,
        checkmk_tag_slug: str = "checkmk",
    ) -> IpAddressWriteResult:
        evaluation = self.evaluate_ip_address(
            ip,
            hostname,
            apply_checkmk_tag=apply_checkmk_tag,
            checkmk_tag_slug=checkmk_tag_slug,
        )
        if evaluation.status == "already_exists":
            return evaluation

        if dry_run:
            return evaluation

        if evaluation.status == "not_found":
            self._sleep()
            try:
                self.api.ipam.ip_addresses.create(evaluation.payload)
            except Exception as exc:
                if is_duplicate_ip_address_error(exc):
                    return self._upsert_after_duplicate_create(
                        ip,
                        hostname=hostname,
                        exc=exc,
                        apply_checkmk_tag=apply_checkmk_tag,
                        checkmk_tag_slug=checkmk_tag_slug,
                    )
                self._handle_request_error(exc)
            return IpAddressWriteResult(status="created", payload=evaluation.payload)

        if evaluation.status in ("drift", "tag_update"):
            if evaluation.update_payload is None and evaluation.status == "drift":
                existing = self._lookup_ip_address(ip)
                if existing is not None:
                    evaluation = evaluate_existing_ip_address(
                        existing,
                        ip=ip,
                        hostname=hostname,
                        payload=evaluation.payload,
                        apply_checkmk_tag=apply_checkmk_tag,
                        checkmk_tag_slug=checkmk_tag_slug,
                    )
            return self._apply_ip_address_update(evaluation, hostname=hostname)

        return evaluation

    def create_ip_address(self, ip: str, hostname: str | None = None, dry_run: bool = False):
        if dry_run:
            evaluation = self.evaluate_ip_address(ip, hostname)
            if evaluation.status == "drift":
                return evaluation
            if evaluation.status == "already_exists":
                return evaluation
            return build_ip_address_payload(ip, hostname)

        evaluation = self.upsert_ip_address(ip, hostname, dry_run=False)
        if evaluation.status == "already_exists":
            return evaluation
        return evaluation
