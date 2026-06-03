from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import dataclass
from typing import Any

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
    return ", ".join(targets)


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


def range_overlaps_prefix(record: Any, cidr: str) -> bool:
    """True when any part of the IP range overlaps the prefix (broader than full containment)."""
    data = _as_mapping(record)
    try:
        start = ipaddress.ip_address(str(data.get("start_address", "")))
        end = ipaddress.ip_address(str(data.get("end_address", "")))
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    if start in network or end in network:
        return True
    return int(start) <= int(network.broadcast_address) and int(end) >= int(network.network_address)


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


def collect_ranges_within_prefixes(api, prefix_cidrs: list[str]) -> list[RangeRecord]:
    ranges: list[RangeRecord] = []
    seen_ids: set[int] = set()

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


def collect_ranges_by_skip_roles_for_prefixes(
    api,
    prefix_cidrs: list[str],
    skip_roles: list[str],
) -> list[RangeRecord]:
    """Fetch IP ranges with skip-role slugs inside each scan prefix (child subnet CIDR)."""
    if not skip_roles or not prefix_cidrs:
        return []

    role_slugs = resolve_skip_role_slugs(api, skip_roles)
    if not role_slugs:
        return []

    ranges: list[RangeRecord] = []
    seen_ids: set[int] = set()

    for cidr in prefix_cidrs:
        for slug in role_slugs:
            candidates: list[Any] = []
            try:
                candidates = list(api.ipam.ip_ranges.filter(role=slug, parent=cidr))
            except Exception as exc:
                LOGGER.debug(
                    "NetBox role+parent filter failed for role=%s parent=%s: %s",
                    slug,
                    cidr,
                    exc,
                )
                candidates = []

            if not candidates:
                try:
                    candidates = [
                        record
                        for record in api.ipam.ip_ranges.filter(role=slug)
                        if range_overlaps_prefix(record, cidr)
                    ]
                except Exception as exc:
                    LOGGER.debug("NetBox role filter failed for role=%s: %s", slug, exc)
                    candidates = []

            for record in candidates:
                if not range_overlaps_prefix(record, cidr):
                    continue
                parsed = parse_range_record(record, prefix=cidr)
                _append_unique_range(ranges, seen_ids, parsed)

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
    """IP range spans to exclude from prefix host scans (not whole prefixes)."""
    skip_name_set = set(skip_names)
    exclusions: list[RangeRecord] = []
    seen_ids: set[int] = set()

    for record in collect_ranges_within_prefixes(api, prefix_cidrs):
        if record.excluded or record.name in skip_name_set:
            _append_unique_range(exclusions, seen_ids, record)

    for record in collect_ranges_by_skip_roles_for_prefixes(api, prefix_cidrs, skip_roles):
        _append_unique_range(exclusions, seen_ids, record)

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
        self.api_token = api_token.strip()
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

    def fetch_prefixes(self) -> list[PrefixRecord]:
        self._sleep()
        try:
            return fetch_prefixes(self.api)
        except Exception as exc:
            self._handle_request_error(exc)

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
