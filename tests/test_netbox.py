import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from netbox_scanner.netbox import (
    IpAddressWriteResult,
    NetBoxClient,
    apply_skip_ranges,
    apply_skip_roles,
    collect_ranges_by_name,
    collect_ranges_within_prefixes,
    iter_unique_targets,
    normalize_hostname,
    parse_range_record,
    parse_role,
    range_contained_in_prefix,
    range_is_excluded,
    range_matches_skip_role,
    record_dns_name,
)
from netbox_scanner.netbox import RangeRecord


class FakeIPRanges:
    def __init__(self, responses=None, all_ranges=None, within_ranges=None):
        self.responses = responses or {}
        self.all_ranges = all_ranges or []
        self.within_ranges = within_ranges or {}

    def filter(self, **kwargs):
        if "name" in kwargs:
            return self.responses.get(kwargs["name"], [])
        if "within" in kwargs:
            return self.within_ranges.get(kwargs["within"], [])
        return []

    def all(self):
        return self.all_ranges


class FakePrefixes:
    def __init__(self, prefixes):
        self.prefixes = prefixes

    def all(self):
        return self.prefixes


class FakeIPAddresses:
    def __init__(self, records=None):
        self.records = records or {}
        self.created = []

    def get(self, address):
        return self.records.get(address)

    def create(self, payload):
        self.created.append(payload)
        return payload


class FakeAPI:
    def __init__(self, responses, ip_addresses=None, all_ranges=None, within_ranges=None, prefixes=None):
        self.ipam = SimpleNamespace(
            ip_ranges=FakeIPRanges(responses, all_ranges=all_ranges, within_ranges=within_ranges),
            ip_addresses=ip_addresses or FakeIPAddresses(),
            prefixes=FakePrefixes(prefixes or []),
        )
        self.http_session = SimpleNamespace(verify=True, timeout=None)


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
            ("DHCP Pool", "dhcp-pool"),
            parse_role({"name": "DHCP Pool", "slug": "dhcp-pool"}),
        )
        self.assertEqual(("VIP", None), parse_role({"value": "VIP"}))

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
        self.assertEqual(["static", "slug-only"], [record.name for record in filtered])
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
        self.assertEqual([], apply_skip_roles(records, ["dhcp pool"]))

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
            within_ranges={"10.0.0.0/24": []},
        )
        records = collect_ranges_within_prefixes(api, ["10.0.0.0/24"])
        self.assertEqual(1, len(records))
        self.assertEqual("lab", records[0].name)

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
        ip_addresses = FakeIPAddresses({"10.0.0.1/32": {"dns_name": "host.example.com"}})
        client = NetBoxClient("https://netbox.example.com", "token", api=FakeAPI({}, ip_addresses))

        result = client.evaluate_ip_address("10.0.0.1", hostname="host.example.com")

        self.assertEqual("already_exists", result.status)

    def test_evaluate_ip_address_reports_drift(self):
        ip_addresses = FakeIPAddresses({"10.0.0.1/32": {"dns_name": "old.example.com"}})
        client = NetBoxClient("https://netbox.example.com", "token", api=FakeAPI({}, ip_addresses))

        result = client.evaluate_ip_address("10.0.0.1", hostname="new.example.com")

        self.assertEqual("drift", result.status)
        self.assertEqual("old.example.com", result.netbox_dns_name)

    def test_create_ip_address_creates_when_not_found(self):
        ip_addresses = FakeIPAddresses()
        client = NetBoxClient("https://netbox.example.com", "token", api=FakeAPI({}, ip_addresses))

        result = client.create_ip_address("10.0.0.1", hostname="host.example.com", dry_run=False)

        self.assertEqual("created", result.status)
        self.assertEqual(1, len(ip_addresses.created))

    def test_create_ip_address_skips_existing_record(self):
        ip_addresses = FakeIPAddresses({"10.0.0.1/32": {"dns_name": "host.example.com"}})
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
