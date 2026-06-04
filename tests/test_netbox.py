import ipaddress
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from netbox_scanner.netbox import (
    IpAddressWriteResult,
    NetBoxClient,
    append_previous_dns_name_note,
    apply_skip_ranges,
    build_ip_address_update,
    duplicate_address_from_error,
    evaluate_existing_ip_address,
    merge_checkmk_tag,
    host_matches_address,
    is_duplicate_ip_address_error,
    is_no_data_provided_error,
    apply_skip_roles,
    build_skip_role_match_keys,
    collect_exclusion_ranges_for_prefixes,
    collect_ranges_by_name,
    collect_ranges_by_skip_roles_for_prefixes,
    range_overlaps_prefix,
    collect_ranges_within_prefixes,
    is_netbox_v2_token,
    iter_unique_targets,
    netbox_authorization_header,
    netbox_authorization_scheme,
    normalize_hostname,
    parse_range_record,
    parse_role,
    range_contained_in_prefix,
    range_is_excluded,
    range_matches_skip_role,
    record_dns_name,
    resolve_skip_role_slugs,
)
from netbox_scanner.netbox import RangeRecord
from netbox_scanner.scanner import is_excluded, range_records_to_exclusions


def make_duplicate_ip_request_error(existing_address: str):
    try:
        import json

        import pynetbox
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("pynetbox is required for duplicate IP tests.") from exc

    body = {"address": [f"Duplicate IP address found in global table: {existing_address}"]}
    req = SimpleNamespace(
        status_code=400,
        reason="Bad Request",
        url="https://netbox.example.com/api/ipam/ip-addresses/",
        request=SimpleNamespace(body=None),
        json=lambda: body,
        text=json.dumps(body),
    )
    return pynetbox.RequestError(req)


def make_no_data_provided_error():
    try:
        import json

        import pynetbox
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("pynetbox is required for no-data update tests.") from exc

    body = {"non_field_errors": ["No data provided"]}
    req = SimpleNamespace(
        status_code=400,
        reason="Bad Request",
        url="https://netbox.example.com/api/ipam/ip-addresses/7/",
        request=SimpleNamespace(body=None),
        json=lambda: body,
        text=json.dumps(body),
    )
    return pynetbox.RequestError(req)


class FakeRoles:
    def __init__(self, roles=None):
        self.roles = roles or [{"name": "DHCP Pool", "slug": "dhcp-pool"}]

    def all(self):
        return self.roles


class FakeIPRanges:
    def __init__(
        self,
        responses=None,
        all_ranges=None,
        within_ranges=None,
        parent_ranges=None,
        role_parent_ranges=None,
        role_ranges=None,
    ):
        self.responses = responses or {}
        self.all_ranges = all_ranges or []
        self.parent_ranges = parent_ranges if parent_ranges is not None else (within_ranges or {})
        self.role_parent_ranges = role_parent_ranges or {}
        self.role_ranges = role_ranges or {}

    def filter(self, **kwargs):
        if "name" in kwargs:
            return self.responses.get(kwargs["name"], [])
        role = kwargs.get("role")
        parent = kwargs.get("parent")
        if role is not None and parent is not None:
            return self.role_parent_ranges.get((role, parent), [])
        if parent is not None:
            return self.parent_ranges.get(parent, [])
        if role is not None:
            return self.role_ranges.get(role, [])
        if "within" in kwargs:
            return self.parent_ranges.get(kwargs["within"], [])
        return []

    def all(self):
        return self.all_ranges


class FakePrefixes:
    def __init__(self, prefixes):
        self.prefixes = prefixes

    def all(self):
        return self.prefixes


class FakeIPAddressRecord:
    def __init__(self, parent, record):
        self._parent = parent
        self._record = record

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        if name in self._record:
            return self._record[name]
        if name in ("description", "dns_name"):
            return ""
        if name == "tags":
            return self._record.get("tags", [])
        raise AttributeError(name)

    def update(self, data):
        if self._parent.update_error is not None:
            raise self._parent.update_error
        if "dns_name" in data:
            self._record["dns_name"] = data["dns_name"]
        if "description" in data:
            self._record["description"] = data["description"]
        if "tags" in data:
            self._record["tags"] = data["tags"]
        self._parent.updated.append({"id": self._record["id"], **data})
        return self._record


class FakeIPAddresses:
    def __init__(self, records=None, *, update_error=None):
        self.records = records or {}
        self.created = []
        self.updated = []
        self.update_error = update_error

    def _wrap(self, record):
        if record is None:
            return None
        if isinstance(record, FakeIPAddressRecord):
            return record
        return FakeIPAddressRecord(self, record)

    def get(self, record_id=None, *, address=None):
        if address is not None:
            return self._wrap(self.records.get(address))
        if record_id is not None:
            for record in self.records.values():
                if record.get("id") == record_id or str(record.get("id")) == str(record_id):
                    return self._wrap(record)
            return None
        return None

    def filter(self, **kwargs):
        if "host" in kwargs:
            target = ipaddress.ip_address(kwargs["host"])
            return [
                record
                for address, record in self.records.items()
                if ipaddress.ip_interface(address).ip == target
            ]
        if "address" in kwargs:
            record = self.records.get(kwargs["address"])
            return [record] if record else []
        return []

    def create(self, payload):
        new_address = payload["address"]
        new_host = ipaddress.ip_interface(new_address).ip
        for address in self.records:
            if ipaddress.ip_interface(address).ip == new_host:
                raise make_duplicate_ip_request_error(address)
        record = {
            **payload,
            "id": len(self.records) + 1,
            "address": new_address,
            "description": payload.get("description", ""),
        }
        self.records[new_address] = record
        self.created.append(payload)
        return record

    def update(self, payloads):
        updated = []
        for payload in payloads:
            record_id = payload["id"]
            for record in self.records.values():
                if str(record.get("id")) == str(record_id):
                    if "dns_name" in payload:
                        record["dns_name"] = payload["dns_name"]
                    if "description" in payload:
                        record["description"] = payload["description"]
                    if "tags" in payload:
                        record["tags"] = payload["tags"]
                    self.updated.append(payload)
                    updated.append(record)
                    break
        return updated


class FakeAPI:
    def __init__(
        self,
        responses,
        ip_addresses=None,
        all_ranges=None,
        within_ranges=None,
        parent_ranges=None,
        role_parent_ranges=None,
        role_ranges=None,
        roles=None,
        prefixes=None,
    ):
        self.ipam = SimpleNamespace(
            ip_ranges=FakeIPRanges(
                responses,
                all_ranges=all_ranges,
                within_ranges=within_ranges,
                parent_ranges=parent_ranges,
                role_parent_ranges=role_parent_ranges,
                role_ranges=role_ranges,
            ),
            roles=FakeRoles(roles),
            ip_addresses=ip_addresses or FakeIPAddresses(),
            prefixes=FakePrefixes(prefixes or []),
        )
        self.http_session = SimpleNamespace(verify=True, timeout=None)


class NetBoxAuthTests(unittest.TestCase):
    def test_v1_token_uses_token_scheme(self):
        token = "0123456789abcdef0123456789abcdef01234567"
        self.assertFalse(is_netbox_v2_token(token))
        self.assertEqual("Token", netbox_authorization_scheme(token))
        self.assertEqual(f"Token {token}", netbox_authorization_header(token))

    def test_v2_token_uses_bearer_scheme(self):
        token = "nbt_abc123.def456ghi789"
        self.assertTrue(is_netbox_v2_token(token))
        self.assertEqual("Bearer", netbox_authorization_scheme(token))
        self.assertEqual(f"Bearer {token}", netbox_authorization_header(token))

    def test_v2_prefix_without_dot_is_v1_scheme(self):
        token = "nbt_not-a-v2-token"
        self.assertFalse(is_netbox_v2_token(token))
        self.assertEqual("Token", netbox_authorization_scheme(token))


class NetBoxTests(unittest.TestCase):
    def test_range_name_duplicates_are_preserved(self):
        api = FakeAPI(
            {
                "prod": [
                    {"name": "prod", "start_address": "10.0.0.1", "end_address": "10.0.0.2"},
                    {"name": "prod", "start_address": "10.0.0.5", "end_address": "10.0.0.5"},
                ]
            }
        )

        records = collect_ranges_by_name(api, ["prod", "prod"])

        self.assertEqual(4, len(records))
        self.assertEqual(["prod", "prod", "prod", "prod"], [record.name for record in records])

    def test_reserved_or_excluded_flags_are_parsed(self):
        self.assertTrue(range_is_excluded({"status": {"value": "reserved"}}))
        self.assertTrue(range_is_excluded({"role": {"value": "excluded"}}))
        self.assertTrue(range_is_excluded({"custom_fields": {"excluded": True}}))
        self.assertFalse(range_is_excluded({"status": {"value": "active"}}))

    def test_parse_range_record_sets_excluded_flag(self):
        record = parse_range_record(
            {"name": "lab", "start_address": "10.0.0.1", "end_address": "10.0.0.3", "excluded": True}
        )

        self.assertTrue(record.excluded)
        self.assertEqual("lab", record.name)

    def test_iter_unique_targets_deduplicates_overlapping_ranges(self):
        records = [
            RangeRecord(name="a", start_address="10.0.0.1", end_address="10.0.0.3"),
            RangeRecord(name="b", start_address="10.0.0.2", end_address="10.0.0.4"),
        ]

        targets = iter_unique_targets(records)

        self.assertEqual(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"], targets)

    def test_iter_unique_targets_enforces_max_hosts(self):
        records = [RangeRecord(name="a", start_address="10.0.0.1", end_address="10.0.0.5")]

        with self.assertRaisesRegex(ValueError, "exceeds --max-hosts"):
            iter_unique_targets(records, max_hosts=3)

    def test_range_contained_in_prefix(self):
        record = {"start_address": "10.0.0.10", "end_address": "10.0.0.20"}
        self.assertTrue(range_contained_in_prefix(record, "10.0.0.0/24"))
        self.assertFalse(range_contained_in_prefix(record, "10.0.1.0/24"))

    def test_apply_skip_ranges_filters_by_name(self):
        records = [
            RangeRecord(name="keep", start_address="10.0.0.1", end_address="10.0.0.1"),
            RangeRecord(name="skip-me", start_address="10.0.0.2", end_address="10.0.0.2"),
        ]
        filtered = apply_skip_ranges(records, ["skip-me"])
        self.assertEqual(["keep"], [record.name for record in filtered])

    def test_parse_role_extracts_name_and_slug(self):
        self.assertEqual(
            ("DHCP Pool", "dhcp-pool", None),
            parse_role({"name": "DHCP Pool", "slug": "dhcp-pool"}),
        )
        self.assertEqual(("VIP", None, None), parse_role({"value": "VIP"}))

    def test_parse_role_resolves_id_only_nested_role_from_catalog(self):
        catalog = {7: ("DHCP-Pool", "dhcp-pool")}
        self.assertEqual(
            ("DHCP-Pool", "dhcp-pool", 7),
            parse_role({"id": 7, "url": "http://example/roles/7/"}, role_catalog=catalog),
        )

    def test_range_overlaps_prefix_with_netbox_cidr_endpoints(self):
        record = {"start_address": "10.0.0.10/32", "end_address": "10.0.0.20/32"}
        self.assertTrue(range_overlaps_prefix(record, "10.0.0.0/24"))

    def test_nn_dhcp_pool_range_overlaps_selected_parent_not_only_child_scan(self):
        """NetBox returns start/end with /22; pool sits in /22 under site /16."""
        nn_range = {
            "id": 6,
            "name": "",
            "start_address": "10.207.2.1/22",
            "end_address": "10.207.3.254/22",
            "role": {
                "id": 1,
                "name": "DHCP-Pool",
                "slug": "dhcp-pool",
            },
        }
        api = FakeAPI(
            {},
            all_ranges=[nn_range],
            roles=[{"id": 1, "name": "DHCP-Pool", "slug": "dhcp-pool"}],
        )
        exclusions = collect_exclusion_ranges_for_prefixes(
            api,
            scan_prefix_cidrs=["10.207.10.0/24"],
            skip_names=[],
            skip_roles=["DHCP Pool"],
            selected_prefix_cidrs=["10.207.0.0/16"],
        )
        self.assertEqual(1, len(exclusions))
        self.assertEqual("10.207.2.1", exclusions[0].start_address)
        self.assertEqual("10.207.3.254", exclusions[0].end_address)
        self.assertEqual("DHCP-Pool", exclusions[0].role_name)

    def test_collect_skip_roles_matches_role_id_only_on_range(self):
        all_ranges = [
            {
                "id": 99,
                "name": "dhcp-by-id",
                "start_address": "10.0.0.40/32",
                "end_address": "10.0.0.45/32",
                "role": {"id": 7},
            },
        ]
        api = FakeAPI(
            {},
            all_ranges=all_ranges,
            roles=[{"id": 7, "name": "DHCP-Pool", "slug": "dhcp-pool"}],
        )
        exclusions = collect_ranges_by_skip_roles_for_prefixes(
            api,
            ["10.0.0.0/24"],
            ["DHCP-Pool"],
        )
        self.assertEqual(1, len(exclusions))
        self.assertEqual("dhcp-by-id", exclusions[0].name)
        self.assertEqual("DHCP-Pool", exclusions[0].role_name)

    def test_parse_range_record_extracts_role(self):
        record = parse_range_record(
            {
                "name": "pool",
                "start_address": "10.0.0.1",
                "end_address": "10.0.0.10",
                "role": {"name": "DHCP Pool", "slug": "dhcp-pool"},
            }
        )
        self.assertEqual("DHCP Pool", record.role_name)
        self.assertEqual("dhcp-pool", record.role_slug)

    def test_apply_skip_roles_skips_matching_roles(self):
        records = [
            RangeRecord(name="static", start_address="10.0.0.1", end_address="10.0.0.1"),
            RangeRecord(
                name="dhcp",
                start_address="10.0.0.2",
                end_address="10.0.0.2",
                role_name="DHCP Pool",
                role_slug="dhcp-pool",
            ),
            RangeRecord(
                name="slug-only",
                start_address="10.0.0.3",
                end_address="10.0.0.3",
                role_slug="dhcp-pool",
            ),
        ]
        filtered = apply_skip_roles(records, ["DHCP Pool"])
        self.assertEqual(["static"], [record.name for record in filtered])
        filtered_by_slug = apply_skip_roles(records, ["dhcp-pool"])
        self.assertEqual(["static"], [record.name for record in filtered_by_slug])

    def test_apply_skip_roles_is_case_insensitive(self):
        records = [
            RangeRecord(
                name="dhcp",
                start_address="10.0.0.1",
                end_address="10.0.0.1",
                role_name="dhcp pool",
            )
        ]
        self.assertTrue(range_matches_skip_role(records[0], ["DHCP Pool"]))
        self.assertTrue(range_matches_skip_role(records[0], ["dhcp pool"]))
        self.assertEqual([], apply_skip_roles(records, ["dhcp pool"]))

    def test_range_matches_skip_role_hyphen_and_case_variants(self):
        record = RangeRecord(
            name="pool",
            start_address="10.0.0.1",
            end_address="10.0.0.2",
            role_name="DHCP Pool",
            role_slug="dhcp-pool",
        )
        api = FakeAPI({}, roles=[{"name": "DHCP-Pool", "slug": "dhcp-pool"}])
        self.assertTrue(range_matches_skip_role(record, ["DHCP-Pool"], api=api))
        self.assertTrue(range_matches_skip_role(record, ["dhcp pool"], api=api))
        keys = build_skip_role_match_keys(api, ["DHCP-POOL"])
        self.assertIn("dhcp-pool", keys)

    def test_apply_skip_roles_keeps_ranges_without_role(self):
        records = [RangeRecord(name="lab", start_address="10.0.0.1", end_address="10.0.0.1")]
        self.assertEqual(records, apply_skip_roles(records, ["DHCP Pool"]))

    def test_collect_ranges_within_prefixes_includes_duplicate_names(self):
        api = FakeAPI(
            {},
            within_ranges={
                "10.0.0.0/24": [
                    {"id": 1, "name": "branch", "start_address": "10.0.0.1", "end_address": "10.0.0.5"},
                    {"id": 2, "name": "branch", "start_address": "10.0.0.10", "end_address": "10.0.0.12"},
                ]
            },
        )
        records = collect_ranges_within_prefixes(api, ["10.0.0.0/24"])
        self.assertEqual(2, len(records))
        self.assertEqual(["branch", "branch"], [record.name for record in records])
        self.assertEqual("10.0.0.0/24", records[0].prefix)

    def test_collect_ranges_within_prefixes_falls_back_to_all(self):
        api = FakeAPI(
            {},
            all_ranges=[
                {"id": 3, "name": "lab", "start_address": "10.0.0.50", "end_address": "10.0.0.55"},
                {"id": 4, "name": "other", "start_address": "10.1.0.1", "end_address": "10.1.0.2"},
            ],
            parent_ranges={"10.0.0.0/24": []},
        )
        records = collect_ranges_within_prefixes(api, ["10.0.0.0/24"])
        self.assertEqual(1, len(records))
        self.assertEqual("lab", records[0].name)

    def test_resolve_skip_role_slugs_maps_display_name_to_slug(self):
        api = FakeAPI({})
        slugs = resolve_skip_role_slugs(api, ["DHCP Pool"])
        self.assertEqual(["dhcp-pool"], slugs)

    def test_collect_skip_roles_fetch_all_without_api_role_filter(self):
        all_ranges = [
            {
                "id": 1,
                "name": "dhcp-a",
                "start_address": "10.0.0.10",
                "end_address": "10.0.0.12",
                "role": {"name": "DHCP-Pool", "slug": "dhcp-pool"},
            },
            {
                "id": 2,
                "name": "dhcp-b",
                "start_address": "10.0.0.20",
                "end_address": "10.0.0.22",
                "role": {"name": "DHCP-Pool", "slug": "dhcp-pool"},
            },
            {
                "id": 3,
                "name": "dhcp-c",
                "start_address": "10.0.0.30",
                "end_address": "10.0.0.32",
                "role": {"name": "DHCP-Pool", "slug": "dhcp-pool"},
            },
            {
                "id": 4,
                "name": "usable",
                "start_address": "10.0.0.50",
                "end_address": "10.0.0.55",
            },
        ]
        api = FakeAPI(
            {},
            all_ranges=all_ranges,
            roles=[{"name": "DHCP-Pool", "slug": "dhcp-pool"}],
        )

        exclusions = collect_ranges_by_skip_roles_for_prefixes(
            api,
            ["10.0.0.0/24"],
            ["DHCP Pool"],
        )

        self.assertEqual(3, len(exclusions))
        self.assertEqual(
            ["dhcp-a", "dhcp-b", "dhcp-c"],
            sorted(record.name for record in exclusions),
        )

    def test_collect_exclusion_ranges_fetches_skip_role_from_all_ranges(self):
        dhcp_range = {
            "id": 1,
            "name": "dhcp",
            "start_address": "10.0.0.10",
            "end_address": "10.0.0.20",
            "role": {"name": "DHCP-Pool", "slug": "dhcp-pool"},
        }
        api = FakeAPI(
            {},
            all_ranges=[dhcp_range],
            parent_ranges={"10.0.0.0/24": []},
            roles=[{"name": "DHCP-Pool", "slug": "dhcp-pool"}],
        )

        exclusions = collect_exclusion_ranges_for_prefixes(
            api,
            ["10.0.0.0/24"],
            skip_names=[],
            skip_roles=["DHCP-Pool"],
        )

        self.assertEqual(1, len(exclusions))
        self.assertEqual("dhcp", exclusions[0].name)
        self.assertEqual("10.0.0.10", exclusions[0].start_address)

    def test_skip_role_excludes_only_range_ips_not_whole_prefix(self):
        dhcp_range = RangeRecord(
            id=1,
            name="dhcp",
            start_address="10.0.0.10",
            end_address="10.0.0.12",
            role_name="DHCP Pool",
            role_slug="dhcp-pool",
        )
        exclusions = range_records_to_exclusions([dhcp_range])

        self.assertTrue(is_excluded("10.0.0.10", exclusions))
        self.assertTrue(is_excluded("10.0.0.11", exclusions))
        self.assertFalse(is_excluded("10.0.0.50", exclusions))

    def test_collect_exclusion_ranges_includes_reserved_by_name(self):
        reserved = {
            "id": 10,
            "name": "reserved-block",
            "start_address": "10.0.0.1",
            "end_address": "10.0.0.2",
            "status": {"value": "reserved"},
        }
        api = FakeAPI(
            {},
            all_ranges=[reserved],
            parent_ranges={"10.0.0.0/24": [reserved]},
        )

        exclusions = collect_exclusion_ranges_for_prefixes(
            api,
            ["10.0.0.0/24"],
            skip_names=["skip-by-name"],
            skip_roles=[],
        )

        self.assertEqual(1, len(exclusions))
        self.assertEqual("reserved-block", exclusions[0].name)

    def test_normalize_hostname_strips_trailing_dot_and_lowercases(self):
        self.assertEqual("host.example.com", normalize_hostname("Host.Example.COM."))

    def test_record_dns_name_reads_dict_and_object_records(self):
        self.assertEqual("host.example.com", record_dns_name({"dns_name": "host.example.com."}))
        self.assertEqual("host.example.com", record_dns_name(SimpleNamespace(dns_name="HOST.example.com")))

    def test_evaluate_ip_address_reports_not_found(self):
        ip_addresses = FakeIPAddresses()
        client = NetBoxClient("https://netbox.example.com", "token", api=FakeAPI({}, ip_addresses))

        result = client.evaluate_ip_address("10.0.0.1", hostname="host.example.com")

        self.assertEqual("not_found", result.status)
        self.assertEqual("10.0.0.1/32", result.payload["address"])

    def test_evaluate_ip_address_reports_already_exists(self):
        ip_addresses = FakeIPAddresses(
            {"10.0.0.1/32": {"id": 1, "address": "10.0.0.1/32", "dns_name": "host.example.com"}}
        )
        client = NetBoxClient("https://netbox.example.com", "token", api=FakeAPI({}, ip_addresses))

        result = client.evaluate_ip_address("10.0.0.1", hostname="host.example.com")

        self.assertEqual("already_exists", result.status)

    def test_evaluate_ip_address_finds_existing_host_with_different_prefix_length(self):
        ip_addresses = FakeIPAddresses(
            {
                "10.98.0.10/22": {
                    "id": 9,
                    "address": "10.98.0.10/22",
                    "dns_name": "host.nexstar.tv",
                }
            }
        )
        client = NetBoxClient("https://netbox.example.com", "token", api=FakeAPI({}, ip_addresses))

        result = client.evaluate_ip_address("10.98.0.10", hostname="host.nexstar.tv")

        self.assertEqual("already_exists", result.status)
        self.assertEqual("host.nexstar.tv", result.netbox_dns_name)

    def test_host_matches_address_compares_host_portion_only(self):
        self.assertTrue(host_matches_address("10.98.0.10", "10.98.0.10/22"))
        self.assertFalse(host_matches_address("10.98.0.10", "10.98.0.11/22"))

    def test_duplicate_address_from_error_parses_netbox_message(self):
        exc = make_duplicate_ip_request_error("10.98.0.10/22")
        self.assertTrue(is_duplicate_ip_address_error(exc))
        self.assertEqual("10.98.0.10/22", duplicate_address_from_error(exc))

    def test_upsert_ip_address_recovers_from_duplicate_create_with_other_mask(self):
        ip_addresses = FakeIPAddresses(
            {
                "10.98.0.10/22": {
                    "id": 9,
                    "address": "10.98.0.10/22",
                    "dns_name": "old.nexstar.tv",
                    "description": "keep",
                }
            }
        )
        client = NetBoxClient("https://netbox.example.com", "token", api=FakeAPI({}, ip_addresses))

        result = client.upsert_ip_address("10.98.0.10", hostname="new.nexstar.tv", dry_run=False)

        self.assertEqual("updated", result.status)
        self.assertEqual([], ip_addresses.created)
        self.assertEqual(1, len(ip_addresses.updated))
        record = ip_addresses.records["10.98.0.10/22"]
        self.assertEqual("new.nexstar.tv", record["dns_name"])
        self.assertIn("Previous dns_name: old.nexstar.tv (netbox-scanner)", record["description"])

    def test_evaluate_ip_address_reports_drift(self):
        ip_addresses = FakeIPAddresses(
            {
                "10.0.0.1/32": {
                    "id": 1,
                    "address": "10.0.0.1/32",
                    "dns_name": "old.example.com",
                    "description": "manual note",
                }
            }
        )
        client = NetBoxClient("https://netbox.example.com", "token", api=FakeAPI({}, ip_addresses))

        result = client.evaluate_ip_address("10.0.0.1", hostname="new.example.com")

        self.assertEqual("drift", result.status)
        self.assertEqual("old.example.com", result.netbox_dns_name)
        self.assertIn("Previous dns_name: old.example.com (netbox-scanner)", result.update_payload["description"])
        self.assertIn("manual note", result.update_payload["description"])
        self.assertEqual("new.example.com", result.update_payload["dns_name"])
        self.assertIsInstance(result.update_payload["id"], int)

    def test_build_ip_address_update_clears_dns_name_without_ptr(self):
        existing = {
            "id": 3,
            "address": "10.0.0.9/32",
            "dns_name": "stale.example.com",
            "description": "manual",
        }
        update = build_ip_address_update(existing, None)
        self.assertEqual(3, update["id"])
        self.assertEqual("", update["dns_name"])
        self.assertIn("Previous dns_name: stale.example.com (netbox-scanner)", update["description"])

    def test_is_no_data_provided_error_detects_netbox_message(self):
        exc = make_no_data_provided_error()
        self.assertTrue(is_no_data_provided_error(exc))
        self.assertFalse(is_duplicate_ip_address_error(exc))

    def test_upsert_ip_address_continues_when_netbox_rejects_empty_patch(self):
        ip_addresses = FakeIPAddresses(
            {"10.0.0.9/32": {"id": 7, "address": "10.0.0.9/32", "dns_name": "old.example.com"}},
            update_error=make_no_data_provided_error(),
        )
        client = NetBoxClient("https://netbox.example.com", "token", api=FakeAPI({}, ip_addresses))

        result = client.upsert_ip_address("10.0.0.9", hostname="new.example.com", dry_run=False)

        self.assertEqual("drift", result.status)
        self.assertEqual([], ip_addresses.updated)

    def test_append_previous_dns_name_note_uses_none_placeholder(self):
        self.assertEqual(
            "Previous dns_name: (none) (netbox-scanner)",
            append_previous_dns_name_note("", None),
        )

    def test_upsert_ip_address_updates_drift_and_appends_description(self):
        ip_addresses = FakeIPAddresses(
            {"10.0.0.1/32": {"id": 7, "address": "10.0.0.1/32", "dns_name": "old.example.com", "description": "keep me"}}
        )
        client = NetBoxClient("https://netbox.example.com", "token", api=FakeAPI({}, ip_addresses))

        result = client.upsert_ip_address("10.0.0.1", hostname="new.example.com", dry_run=False)

        self.assertEqual("updated", result.status)
        self.assertEqual(1, len(ip_addresses.updated))
        record = ip_addresses.records["10.0.0.1/32"]
        self.assertEqual("new.example.com", record["dns_name"])
        self.assertIn("keep me", record["description"])
        self.assertIn("Previous dns_name: old.example.com (netbox-scanner)", record["description"])

    def test_upsert_ip_address_skips_unchanged_record(self):
        ip_addresses = FakeIPAddresses(
            {"10.0.0.1/32": {"id": 1, "address": "10.0.0.1/32", "dns_name": "host.example.com"}}
        )
        client = NetBoxClient("https://netbox.example.com", "token", api=FakeAPI({}, ip_addresses))

        result = client.upsert_ip_address("10.0.0.1", hostname="host.example.com", dry_run=False)

        self.assertEqual("already_exists", result.status)
        self.assertEqual([], ip_addresses.updated)
        self.assertEqual([], ip_addresses.created)

    def test_evaluate_ip_address_requests_tag_update_when_dns_matches(self):
        existing = {
            "id": 2,
            "address": "10.0.0.2/32",
            "dns_name": "host.example.com",
            "tags": [],
        }
        evaluation = evaluate_existing_ip_address(
            existing,
            ip="10.0.0.2",
            hostname="host.example.com",
            payload={"address": "10.0.0.2/32", "status": "active", "dns_name": "host.example.com"},
            apply_checkmk_tag=True,
            checkmk_tag_slug="checkmk",
        )
        self.assertEqual("tag_update", evaluation.status)
        self.assertEqual([{"slug": "checkmk"}], evaluation.update_payload["tags"])

    def test_merge_checkmk_tag_preserves_existing_tags(self):
        existing = {"id": 1, "tags": [{"slug": "production"}]}
        self.assertEqual(
            [{"slug": "checkmk"}, {"slug": "production"}],
            merge_checkmk_tag(existing, "checkmk"),
        )

    def test_upsert_ip_address_applies_checkmk_tag_on_create(self):
        ip_addresses = FakeIPAddresses()
        client = NetBoxClient("https://netbox.example.com", "token", api=FakeAPI({}, ip_addresses))

        result = client.upsert_ip_address(
            "10.0.0.3",
            hostname="new.example.com",
            dry_run=False,
            apply_checkmk_tag=True,
            checkmk_tag_slug="checkmk",
        )

        self.assertEqual("created", result.status)
        record = ip_addresses.records["10.0.0.3/32"]
        self.assertEqual([{"slug": "checkmk"}], record["tags"])

    def test_upsert_ip_address_applies_checkmk_tag_when_already_exists(self):
        ip_addresses = FakeIPAddresses(
            {
                "10.0.0.4/32": {
                    "id": 4,
                    "address": "10.0.0.4/32",
                    "dns_name": "host.example.com",
                    "tags": [],
                }
            }
        )
        client = NetBoxClient("https://netbox.example.com", "token", api=FakeAPI({}, ip_addresses))

        result = client.upsert_ip_address(
            "10.0.0.4",
            hostname="host.example.com",
            dry_run=False,
            apply_checkmk_tag=True,
            checkmk_tag_slug="checkmk",
        )

        self.assertEqual("updated", result.status)
        record = ip_addresses.records["10.0.0.4/32"]
        self.assertEqual([{"slug": "checkmk"}], record["tags"])

    def test_create_ip_address_creates_when_not_found(self):
        ip_addresses = FakeIPAddresses()
        client = NetBoxClient("https://netbox.example.com", "token", api=FakeAPI({}, ip_addresses))

        result = client.create_ip_address("10.0.0.1", hostname="host.example.com", dry_run=False)

        self.assertEqual("created", result.status)
        self.assertEqual(1, len(ip_addresses.created))

    def test_create_ip_address_skips_existing_record(self):
        ip_addresses = FakeIPAddresses(
            {"10.0.0.1/32": {"id": 1, "address": "10.0.0.1/32", "dns_name": "host.example.com"}}
        )
        client = NetBoxClient("https://netbox.example.com", "token", api=FakeAPI({}, ip_addresses))

        result = client.create_ip_address("10.0.0.1", hostname="host.example.com", dry_run=False)

        self.assertEqual("already_exists", result.status)
        self.assertEqual([], ip_addresses.created)

    def test_create_ip_address_dry_run_returns_payload(self):
        client = NetBoxClient("https://netbox.example.com", "token", api=FakeAPI({}))

        payload = client.create_ip_address("10.0.0.1", hostname="host.example.com", dry_run=True)

        self.assertEqual("10.0.0.1/32", payload["address"])
        self.assertEqual("host.example.com", payload["dns_name"])

    def test_api_property_applies_http_timeout(self):
        client = NetBoxClient("https://netbox.example.com", "token", timeout=42.0)
        fake_api = FakeAPI({})

        with patch("pynetbox.api", return_value=fake_api):
            api = client.api

        self.assertIs(api, fake_api)
        self.assertEqual(42.0, fake_api.http_session.timeout)

    def test_verify_authentication_rejects_forbidden(self):
        response = SimpleNamespace(status_code=403)

        class FakeSession:
            def get(self, url, headers=None, timeout=None):
                self.url = url
                self.headers = headers
                return response

        fake_api = FakeAPI({})
        fake_api.http_session = FakeSession()
        client = NetBoxClient("http://netbox.example.com", "bad-token", api=fake_api)

        with self.assertRaisesRegex(RuntimeError, "authentication failed"):
            client.verify_authentication()

        self.assertEqual("http://netbox.example.com/api/status/", fake_api.http_session.url)
        self.assertEqual("Token bad-token", fake_api.http_session.headers["Authorization"])

    def test_verify_authentication_uses_bearer_for_v2_token(self):
        response = SimpleNamespace(status_code=200, raise_for_status=lambda: None)

        class FakeSession:
            def get(self, url, headers=None, timeout=None):
                self.headers = headers
                return response

        fake_api = FakeAPI({})
        fake_api.http_session = FakeSession()
        v2_token = "nbt_abc123.def456ghi789"
        client = NetBoxClient("http://netbox.example.com", v2_token, api=fake_api)

        client.verify_authentication()

        self.assertEqual(f"Bearer {v2_token}", fake_api.http_session.headers["Authorization"])

    def test_auth_errors_fail_fast(self):
        request_error = self._make_request_error(401)
        ip_addresses = MagicMock()
        ip_addresses.get.side_effect = request_error
        api = SimpleNamespace(ipam=SimpleNamespace(ip_addresses=ip_addresses))
        client = NetBoxClient("https://netbox.example.com", "token", api=api)

        with patch("pynetbox.RequestError", new=type(request_error)):
            with self.assertRaisesRegex(RuntimeError, "authentication failed"):
                client.evaluate_ip_address("10.0.0.1", hostname="host.example.com")

    def _make_request_error(self, status_code):
        req = SimpleNamespace(status_code=status_code)

        class RequestError(Exception):
            def __init__(self, req):
                self.req = req

        return RequestError(req)
