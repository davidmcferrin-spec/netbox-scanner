import unittest
from unittest.mock import MagicMock

from netbox_scanner.checkmk import CheckMKConfig, CheckMKLookupResult
from netbox_scanner.checkmk_sync import (
    CheckMKDnsBackfillSummary,
    ip_from_netbox_address_record,
    resolve_scan_write_hostname,
    run_checkmk_dns_backfill,
)
from netbox_scanner.netbox import IpAddressWriteResult


class ResolveScanWriteHostnameTests(unittest.TestCase):
    def test_ptr_wins_over_checkmk(self):
        self.assertEqual(
            "ptr.example.com",
            resolve_scan_write_hostname(
                "ptr.example.com",
                "cmk.example.com",
                None,
                sync_checkmk_dns=True,
            ),
        )

    def test_never_overwrite_existing_netbox_dns(self):
        self.assertIsNone(
            resolve_scan_write_hostname(
                None,
                "cmk.example.com",
                "netbox.example.com",
                sync_checkmk_dns=True,
            ),
        )

    def test_sync_checkmk_when_no_ptr_or_netbox_dns(self):
        self.assertEqual(
            "cmk.example.com",
            resolve_scan_write_hostname(None, "cmk.example.com", None, sync_checkmk_dns=True),
        )

    def test_no_sync_without_flag(self):
        self.assertIsNone(
            resolve_scan_write_hostname(None, "cmk.example.com", None, sync_checkmk_dns=False),
        )


class CheckMKDnsBackfillTests(unittest.TestCase):
    def test_ip_from_netbox_address_record(self):
        self.assertEqual("10.1.2.3", ip_from_netbox_address_record({"address": "10.1.2.3/32"}))

    def test_run_checkmk_dns_backfill(self):
        netbox_client = MagicMock()
        netbox_client.fetch_ip_addresses_with_tag_missing_dns.return_value = [
            {"id": 1, "address": "10.0.0.10/32"},
            {"id": 2, "address": "10.0.0.11/32"},
        ]
        checkmk_client = MagicMock()
        checkmk_client.lookup_host_by_ip.side_effect = [
            CheckMKLookupResult(monitored=True, host_name="host-a.example.com"),
            CheckMKLookupResult(monitored=True, host_name="host-b.example.com"),
        ]
        netbox_client.sync_dns_name_from_checkmk.side_effect = [
            IpAddressWriteResult(status="updated", payload={}),
            IpAddressWriteResult(status="not_found", payload={}),
        ]

        summary = run_checkmk_dns_backfill(
            netbox_client,
            checkmk_client,
            CheckMKConfig(enabled=True, tag_slug="checkmk"),
            dry_run=False,
        )

        self.assertEqual(2, summary.examined)
        self.assertEqual(1, summary.synced)
        self.assertEqual(0, summary.skipped_no_checkmk_host)
        self.assertEqual(1, summary.skipped_not_in_netbox)
        netbox_client.fetch_ip_addresses_with_tag_missing_dns.assert_called_once_with("checkmk")
