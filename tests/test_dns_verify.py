import unittest

from netbox_scanner.dns_verify import verify_dns


class FakeResolver:
    def __init__(self, reverse_records, forward_records):
        self.reverse_records = reverse_records
        self.forward_records = forward_records

    def resolve(self, query, record_type):
        if record_type == "PTR":
            return [self.reverse_records[str(query)]]
        return self.forward_records[(str(query), record_type)]


class DNSVerifyTests(unittest.TestCase):
    def test_forward_and_reverse_lookup_must_match(self):
        resolver = FakeResolver(
            reverse_records={"1.0.0.10.in-addr.arpa": "host.example.com."},
            forward_records={("host.example.com", "A"): ["10.0.0.1"]},
        )

        result = verify_dns("10.0.0.1", resolver=resolver)

        self.assertTrue(result.verified)
        self.assertEqual("host.example.com", result.hostname)

    def test_mismatch_is_reported(self):
        resolver = FakeResolver(
            reverse_records={"2.0.0.10.in-addr.arpa": "host.example.com."},
            forward_records={("host.example.com", "A"): ["10.0.0.99"]},
        )

        result = verify_dns("10.0.0.2", resolver=resolver)

        self.assertFalse(result.verified)
        self.assertTrue(result.dns_mismatch)
        self.assertEqual("forward_mismatch", result.reason)
