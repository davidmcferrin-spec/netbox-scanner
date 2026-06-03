import unittest

from netbox_scanner.dns_verify import lookup_dns


class FakeResolver:
    def __init__(self, reverse_records, forward_records):
        self.reverse_records = reverse_records
        self.forward_records = forward_records

    def resolve(self, query, record_type):
        if record_type == "PTR":
            return [self.reverse_records[str(query)]]
        return self.forward_records[(str(query), record_type)]


class DNSLookupTests(unittest.TestCase):
    def test_ptr_and_forward_records_are_collected(self):
        resolver = FakeResolver(
            reverse_records={"1.0.0.10.in-addr.arpa": "host.example.com."},
            forward_records={("host.example.com", "A"): ["10.0.0.1"]},
        )

        result = lookup_dns("10.0.0.1", resolver=resolver)

        self.assertEqual("lookup_ok", result.reason)
        self.assertEqual("host.example.com", result.ptr_hostname)
        self.assertTrue(result.forward_has_a_or_cname)
        self.assertEqual(["10.0.0.1"], result.forward_addresses)

    def test_forward_ip_mismatch_is_not_an_error(self):
        resolver = FakeResolver(
            reverse_records={"2.0.0.10.in-addr.arpa": "host.example.com."},
            forward_records={("host.example.com", "A"): ["10.0.0.99"]},
        )

        result = lookup_dns("10.0.0.2", resolver=resolver)

        self.assertEqual("lookup_ok", result.reason)
        self.assertEqual("host.example.com", result.ptr_hostname)
        self.assertTrue(result.forward_has_a_or_cname)
        self.assertEqual(["10.0.0.99"], result.forward_addresses)

    def test_missing_ptr_is_informational(self):
        resolver = FakeResolver(reverse_records={}, forward_records={})

        def resolve(query, record_type):
            if record_type == "PTR":
                raise RuntimeError("no ptr")
            return []

        resolver.resolve = resolve  # type: ignore[method-assign]

        result = lookup_dns("10.0.0.5", resolver=resolver)

        self.assertEqual("ptr_missing", result.reason)
        self.assertIsNone(result.ptr_hostname)
        self.assertFalse(result.forward_has_a_or_cname)

    def test_cname_counts_as_forward_record(self):
        resolver = FakeResolver(
            reverse_records={"3.0.0.10.in-addr.arpa": "alias.example.com."},
            forward_records={
                ("alias.example.com", "A"): [],
                ("alias.example.com", "CNAME"): ["host.example.com."],
            },
        )

        result = lookup_dns("10.0.0.3", resolver=resolver)

        self.assertEqual("lookup_ok", result.reason)
        self.assertTrue(result.forward_has_a_or_cname)
