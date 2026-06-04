import unittest
from unittest.mock import patch

from netbox_scanner.metadata import (
    is_alive_ping_or_ptr,
    build_last_verified_custom_fields,
    MetadataFieldSlugs,
)
from netbox_scanner.stale_policy import increment_miss_count


class MetadataTests(unittest.TestCase):
    def test_is_alive_ping_or_ptr(self):
        self.assertTrue(is_alive_ping_or_ptr(ping_ok=True, ptr_hostname=None))
        self.assertTrue(is_alive_ping_or_ptr(ping_ok=False, ptr_hostname="host.example.com"))
        self.assertFalse(is_alive_ping_or_ptr(ping_ok=False, ptr_hostname=None))
        self.assertFalse(is_alive_ping_or_ptr(ping_ok=False, ptr_hostname=""))

    def test_increment_miss_count_updates_custom_field(self):
        existing = {"id": 1, "description": "", "custom_fields": {"scanner_miss_count": 2}}
        slugs = MetadataFieldSlugs()
        with patch("netbox_scanner.netbox.scanner_note_timestamp", return_value="2026-06-03 12:00:00 UTC"):
            count, fields, note = increment_miss_count(existing, slugs, threshold=5)
        self.assertEqual(3, count)
        self.assertEqual(3, fields["scanner_miss_count"])
        self.assertIn("count=3/5", note)

    def test_build_last_verified_custom_fields(self):
        with patch("netbox_scanner.metadata.scanner_note_timestamp", return_value="2026-06-03 12:00:00 UTC"):
            fields = build_last_verified_custom_fields(
                MetadataFieldSlugs(),
                profile="services",
                open_ports=[22, 80],
            )
        self.assertEqual("services", fields["last_verified_profile"])
        self.assertEqual("22,80", fields["last_open_ports"])
