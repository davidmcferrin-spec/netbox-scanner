from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import dataclass
from typing import Any

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class PrefixRecord:
    id: int
    prefix: str
    description: str
    site: str | None = None
    parent_id: int | None = None


@dataclass(slots=True)
class RangeRecord:
    name: str
    start_address: str
    end_address: str
    excluded: bool = False
    id: int = 0
    description: str = ""
    prefix: str | None = None
    role_name: str | None = None
    role_slug: str | None = None


@dataclass(slots=True)
class IpAddressWriteResult:
    status: str
    payload: dict[str, str]
    netbox_dns_name: str | None = None


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
        "reserved": getattr(record, "reserved", None),
        "excluded": getattr(record, "excluded", None),
        "custom_fields": getattr(record, "custom_fields", {}) or {},
        "site": getattr(record, "site", None),
        "parent": getattr(record, "parent", None),
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


def _prefix_cidr(prefix: Any) -> str | None:
    if isinstance(prefix, dict):
        return prefix.get("prefix")
    if prefix is None:
        return None
    prefix_value = getattr(prefix, "prefix", None)
    return str(prefix_value) if prefix_value else None


def parse_role(role: Any) -> tuple[str | None, str | None]:
    if role is None:
        return None, None
    if isinstance(role, dict):
        name = role.get("name")
        slug = role.get("slug")
        if not name and not slug:
            for key in ("label", "value"):
                value = role.get(key)
                if value:
                    return str(value), None
        return (str(name) if name else None), (str(slug) if slug else None)
    name = getattr(role, "name", None)
    slug = getattr(role, "slug", None)
    if name or slug:
        return (str(name) if name else None), (str(slug) if slug else None)
    return str(role), None


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
        site=_site_name(data.get("site")),
        parent_id=_parent_id(data.get("parent")),
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


def prefixes_for_display(records: list[PrefixRecord]) -> list[PrefixRecord]:
    """Parents and standalones for the picker: hide rows whose parent exists in NetBox."""
    index = build_prefix_index(records)
    display: list[PrefixRecord] = []
    for record in records:
        if record.parent_id is not None and record.parent_id in index:
            continue
        display.append(record)
    return sorted(display, key=lambda item: (item.site or "", item.prefix))


def prefix_has_children(
    record: PrefixRecord,
    children: dict[int, list[PrefixRecord]],
) -> bool:
    return record.id in children


def leaf_child_prefixes_for_parent(
    record_id: int,
    *,
    children: dict[int, list[PrefixRecord]],
) -> list[str]:
    return sorted(_leaf_descendant_prefixes(record_id, children=children))


def scan_preview_for_prefix(
    record: PrefixRecord,
    *,
    children: dict[int, list[PrefixRecord]],
) -> str:
    leaf_children = leaf_child_prefixes_for_parent(record.id, children=children)
    if leaf_children:
        return ", ".join(leaf_children)
    return "(scans this prefix)"


def _record_by_cidr(records: list[PrefixRecord], cidr: str) -> PrefixRecord | None:
    normalized = normalize_prefix_cidr(cidr)
    for record in records:
        if record.prefix == normalized:
            return record
    return None


def _leaf_descendant_prefixes(
    root_id: int,
    *,
    children: dict[int, list[PrefixRecord]],
) -> list[str]:
    descendants = children.get(root_id, [])
    if not descendants:
        return []

    leaves: list[str] = []
    for child in descendants:
        if child.id in children:
            leaves.extend(_leaf_descendant_prefixes(child.id, children=children))
        else:
            leaves.append(child.prefix)
    return leaves


def count_leaf_descendants(
    record: PrefixRecord,
    *,
    children: dict[int, list[PrefixRecord]],
) -> int:
    return len(leaf_child_prefixes_for_parent(record.id, children=children))


def expand_prefixes_to_scan_cidrs(records: list[PrefixRecord], selected_cidrs: list[str]) -> list[str]:
    children = children_by_parent(records)
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

        scan_cidrs = _leaf_descendant_prefixes(record.id, children=children)
        if not scan_cidrs:
            scan_cidrs = [record.prefix]

        for scan_cidr in scan_cidrs:
            if scan_cidr in seen:
                continue
            seen.add(scan_cidr)
            expanded.append(scan_cidr)

    return expanded


def parse_range_record(record: Any, *, prefix: str | None = None) -> RangeRecord:
    data = _as_mapping(record)
    role_name, role_slug = parse_role(data.get("role"))
    return RangeRecord(
        id=int(data.get("id") or 0),
        name=str(data.get("name", "")),
        start_address=str(data.get("start_address", "")),
        end_address=str(data.get("end_address", "")),
        description=str(data.get("description") or ""),
        excluded=range_is_excluded(data),
        prefix=prefix or _prefix_cidr(data.get("prefix")),
        role_name=role_name,
        role_slug=role_slug,
    )


def range_contained_in_prefix(record: Any, cidr: str) -> bool:
    data = _as_mapping(record)
    try:
        start = ipaddress.ip_address(str(data.get("start_address", "")))
        end = ipaddress.ip_address(str(data.get("end_address", "")))
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return start in network and end in network


def fetch_prefixes(api) -> list[PrefixRecord]:
    return [parse_prefix_record(record) for record in api.ipam.prefixes.all()]


def collect_ranges_by_name(api, names: list[str]) -> list[RangeRecord]:
    ranges: list[RangeRecord] = []
    for name in names:
        for record in api.ipam.ip_ranges.filter(name=name):
            ranges.append(parse_range_record(record))
    return ranges


def collect_ranges_within_prefixes(api, prefix_cidrs: list[str]) -> list[RangeRecord]:
    ranges: list[RangeRecord] = []
    seen_ids: set[int] = set()

    for cidr in prefix_cidrs:
        candidates: list[Any] = []
        try:
            candidates = list(api.ipam.ip_ranges.filter(within=cidr))
        except Exception as exc:
            LOGGER.debug("NetBox within filter failed for %s: %s", cidr, exc)
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
            if parsed.id:
                if parsed.id in seen_ids:
                    continue
                seen_ids.add(parsed.id)
            ranges.append(parsed)

    return ranges


def apply_skip_ranges(records: list[RangeRecord], skip_names: list[str]) -> list[RangeRecord]:
    if not skip_names:
        return records
    skip = set(skip_names)
    return [record for record in records if record.name not in skip]


def range_matches_skip_role(record: RangeRecord, skip_roles: list[str]) -> bool:
    if not skip_roles:
        return False
    candidates: set[str] = set()
    if record.role_name:
        candidates.add(record.role_name.lower())
    if record.role_slug:
        candidates.add(record.role_slug.lower())
    if not candidates:
        return False
    skip_lower = {role.lower() for role in skip_roles}
    return bool(candidates & skip_lower)


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
    prefix_cidrs: list[str],
    skip_names: list[str],
    skip_roles: list[str],
) -> list[RangeRecord]:
    skip_name_set = set(skip_names)
    exclusions: list[RangeRecord] = []
    seen_ids: set[int] = set()

    for record in collect_ranges_within_prefixes(api, prefix_cidrs):
        if range_exclusion_reason(record, skip_names=skip_name_set, skip_roles=skip_roles) is None:
            continue
        if record.id:
            if record.id in seen_ids:
                continue
            seen_ids.add(record.id)
        exclusions.append(record)

    return exclusions


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


def build_ip_address_payload(ip: str, hostname: str | None = None) -> dict[str, str]:
    address = ipaddress.ip_address(ip)
    cidr = 32 if address.version == 4 else 128
    payload = {"address": f"{address}/{cidr}", "status": "active"}
    if hostname:
        payload["dns_name"] = hostname
    return payload


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
        self.api_token = api_token
        self.timeout = timeout
        self.rate_limit = rate_limit
        self._api = api

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
            raise RuntimeError(f"NetBox authentication failed (HTTP {status_code}).") from exc
        if status_code is not None and status_code >= 500:
            raise RuntimeError(f"NetBox server error (HTTP {status_code}).") from exc
        raise exc

    def fetch_prefixes(self) -> list[PrefixRecord]:
        self._sleep()
        return fetch_prefixes(self.api)

    def fetch_ranges_within_prefixes(self, prefix_cidrs: list[str]) -> list[RangeRecord]:
        self._sleep()
        return collect_ranges_within_prefixes(self.api, prefix_cidrs)

    def fetch_exclusion_ranges_for_prefixes(
        self,
        prefix_cidrs: list[str],
        skip_names: list[str],
        skip_roles: list[str],
    ) -> list[RangeRecord]:
        self._sleep()
        return collect_exclusion_ranges_for_prefixes(self.api, prefix_cidrs, skip_names, skip_roles)

    def fetch_scan_ranges(self, names: list[str]) -> list[RangeRecord]:
        self._sleep()
        return collect_ranges_by_name(self.api, names)

    def fetch_excluded_ranges(self) -> list[RangeRecord]:
        self._sleep()
        records = self.api.ipam.ip_ranges.all()
        return [parse_range_record(record) for record in records if range_is_excluded(record)]

    def evaluate_ip_address(self, ip: str, hostname: str | None = None) -> IpAddressWriteResult:
        payload = build_ip_address_payload(ip, hostname)
        self._sleep()
        try:
            existing = self.api.ipam.ip_addresses.get(address=payload["address"])
        except Exception as exc:
            self._handle_request_error(exc)

        if existing is None:
            return IpAddressWriteResult(status="not_found", payload=payload)

        netbox_dns = record_dns_name(existing)
        verified = normalize_hostname(hostname)
        if netbox_dns == verified:
            return IpAddressWriteResult(
                status="already_exists",
                payload=payload,
                netbox_dns_name=netbox_dns or None,
            )

        return IpAddressWriteResult(
            status="drift",
            payload=payload,
            netbox_dns_name=netbox_dns or None,
        )

    def create_ip_address(self, ip: str, hostname: str | None = None, dry_run: bool = False):
        if dry_run:
            return build_ip_address_payload(ip, hostname)

        evaluation = self.evaluate_ip_address(ip, hostname)
        if evaluation.status != "not_found":
            return evaluation

        self._sleep()
        try:
            self.api.ipam.ip_addresses.create(evaluation.payload)
        except Exception as exc:
            self._handle_request_error(exc)

        return IpAddressWriteResult(status="created", payload=evaluation.payload)
