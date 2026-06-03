import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from netbox_scanner.config import AppConfig, DNSConfig, NetBoxConfig, ScannerConfig
from netbox_scanner.dns_verify import DNSLookupResult
from netbox_scanner.netbox import IpAddressWriteResult, RangeRecord
from netbox_scanner.scanner import (
    NetworkScanner,
    ScanResult,
    classify_liveness,
    export_results,
    profile_uses_explicit_ports,
)

SERVICES_PROFILE = ["-sS", "-sU", "T:22,23,80,443,445,U:161"]


class LivenessClassificationTests(unittest.TestCase):
    def test_range_profile_allows_nmap_up_without_open_ports(self):
        self.assertEqual(
            "verified",
            classify_liveness(ping_ok=True, nmap_status_up=True, profile_items=["1-65535"], open_ports=[]),
        )

    def test_range_profile_phantom_when_nmap_down(self):
        self.assertEqual(
            "ping_only",
            classify_liveness(ping_ok=True, nmap_status_up=False, profile_items=["1-65535"], open_ports=[]),
        )

    def test_explicit_ports_require_open_port(self):
        self.assertEqual(
            "verified",
            classify_liveness(
                ping_ok=True,
                nmap_status_up=True,
                profile_items=SERVICES_PROFILE,
                open_ports=[22],
            ),
        )
        self.assertEqual(
            "ping_only",
            classify_liveness(
                ping_ok=True,
                nmap_status_up=True,
                profile_items=SERVICES_PROFILE,
                open_ports=[],
            ),
        )

    def test_pn_on_range_profile_requires_open_port(self):
        self.assertEqual(
            "verified",
            classify_liveness(ping_ok=True, nmap_status_up=True, profile_items=["-Pn", "-sS", "443"], open_ports=[443]),
        )
        self.assertEqual(
            "ping_only",
            classify_liveness(ping_ok=True, nmap_status_up=True, profile_items=["-Pn", "-sS", "443"], open_ports=[]),
        )

    def test_profile_uses_explicit_ports(self):
        self.assertTrue(profile_uses_explicit_ports(SERVICES_PROFILE))
        self.assertTrue(profile_uses_explicit_ports(["443", "80"]))
        self.assertFalse(profile_uses_explicit_ports(["1-65535"]))
        self.assertFalse(profile_uses_explicit_ports(["1-1024"]))
        self.assertFalse(profile_uses_explicit_ports(["-sS", "-Pn"]))


class ScannerRunTests(unittest.TestCase):
    def setUp(self):
        self.config = AppConfig(
            netbox=NetBoxConfig(base_url="https://netbox.example.com", api_token="token"),
            dns=DNSConfig(servers=[], timeout=2.0),
            scanner=ScannerConfig(),
        )
        self.netbox_client = MagicMock()
        self.netbox_client.fetch_scan_ranges.return_value = [
            RangeRecord(name="lab", start_address="10.0.0.1", end_address="10.0.0.2")
        ]
        self.netbox_client.fetch_excluded_ranges.return_value = []

    def _make_scanner(self, ping_runner, nmap_scanner):
        return NetworkScanner(
            config=self.config,
            netbox_client=self.netbox_client,
            ping_runner=ping_runner,
            nmap_scanner=nmap_scanner,
        )

    def _verified_nmap_response(self, ip: str, port: int = 22):
        return {
            "scan": {
                ip: {
                    "status": {"state": "up"},
                    "tcp": {port: {"state": "open"}},
                }
            }
        }

    def test_run_raises_when_no_ranges_match(self):
        self.netbox_client.fetch_scan_ranges.return_value = []
        scanner = NetworkScanner(config=self.config, netbox_client=self.netbox_client)

        with self.assertRaisesRegex(ValueError, "No NetBox IP ranges matched"):
            scanner.run(range_names=["missing"], profile="services", speed="polite")

    def test_run_dry_run_reports_planned_write_when_verified(self):
        nmap_scanner = MagicMock()
        nmap_scanner.scan.return_value = self._verified_nmap_response("10.0.0.1")
        scanner = self._make_scanner(lambda ip: ip == "10.0.0.1", nmap_scanner)

        dns_result = DNSLookupResult(ip="10.0.0.1", ptr_hostname="host.example.com", reason="lookup_ok")
        self.netbox_client.evaluate_ip_address.return_value = IpAddressWriteResult(
            status="not_found",
            payload={"address": "10.0.0.1/32", "status": "active", "dns_name": "host.example.com"},
        )

        with patch("netbox_scanner.scanner.lookup_dns", return_value=dns_result):
            summary = scanner.run(range_names=["lab"], profile="services", speed="polite", dry_run=True)

        self.assertEqual(1, summary.verified)
        self.assertEqual(1, summary.unreachable)
        planned = [result for result in summary.results if result.reason == "dry_run"]
        self.assertEqual(1, len(planned))
        self.assertEqual("verified", planned[0].liveness)

    def test_run_phantom_suspect_does_not_write(self):
        nmap_scanner = MagicMock()
        nmap_scanner.scan.return_value = {
            "scan": {"10.0.0.1": {"status": {"state": "up"}, "tcp": {}}}
        }
        scanner = self._make_scanner(lambda ip: ip == "10.0.0.1", nmap_scanner)

        dns_result = DNSLookupResult(ip="10.0.0.1", ptr_hostname=None, reason="ptr_missing")

        with patch("netbox_scanner.scanner.lookup_dns", return_value=dns_result):
            summary = scanner.run(
                range_names=["lab"],
                profile="services",
                speed="polite",
                auto_confirm=True,
            )

        self.assertEqual(1, summary.ping_only)
        self.assertEqual(0, summary.verified)
        phantom = [result for result in summary.results if result.reason == "phantom_suspect"]
        self.assertEqual(1, len(phantom))
        self.netbox_client.create_ip_address.assert_not_called()

    def test_run_creates_when_verified_and_auto_confirm(self):
        nmap_scanner = MagicMock()
        nmap_scanner.scan.return_value = self._verified_nmap_response("10.0.0.1")
        scanner = self._make_scanner(lambda ip: ip == "10.0.0.1", nmap_scanner)

        dns_result = DNSLookupResult(ip="10.0.0.1", ptr_hostname="host.example.com", reason="lookup_ok")
        self.netbox_client.evaluate_ip_address.return_value = IpAddressWriteResult(
            status="not_found",
            payload={"address": "10.0.0.1/32", "status": "active", "dns_name": "host.example.com"},
        )
        self.netbox_client.create_ip_address.return_value = IpAddressWriteResult(
            status="created",
            payload={"address": "10.0.0.1/32", "status": "active", "dns_name": "host.example.com"},
        )

        with patch("netbox_scanner.scanner.lookup_dns", return_value=dns_result):
            summary = scanner.run(
                range_names=["lab"],
                profile="services",
                speed="polite",
                auto_confirm=True,
            )

        self.assertEqual(1, summary.netbox_created)
        created = [result for result in summary.results if result.netbox_written]
        self.assertEqual(1, len(created))
        self.assertEqual("created", created[0].reason)

    def test_services_profile_verified_with_open_port(self):
        nmap_scanner = MagicMock()
        nmap_scanner.scan.return_value = self._verified_nmap_response("10.0.0.1", port=443)
        scanner = self._make_scanner(lambda ip: ip == "10.0.0.1", nmap_scanner)

        dns_result = DNSLookupResult(ip="10.0.0.1", ptr_hostname="host.example.com", reason="lookup_ok")
        self.netbox_client.evaluate_ip_address.return_value = IpAddressWriteResult(
            status="not_found",
            payload={"address": "10.0.0.1/32", "status": "active", "dns_name": "host.example.com"},
        )

        with patch("netbox_scanner.scanner.lookup_dns", return_value=dns_result):
            summary = scanner.run(
                range_names=["lab"],
                profile="services",
                speed="polite",
                dry_run=True,
            )

        verified = [result for result in summary.results if result.liveness == "verified"]
        self.assertEqual(1, len(verified))
        self.assertEqual([443], verified[0].open_ports)

    def test_run_accepts_scan_ranges_directly(self):
        nmap_scanner = MagicMock()
        nmap_scanner.scan.return_value = {
            "scan": {"10.0.0.1": {"status": {"state": "up"}, "tcp": {22: {"state": "open"}}}}
        }
        scanner = self._make_scanner(lambda ip: ip == "10.0.0.1", nmap_scanner)
        scan_ranges = [RangeRecord(name="lab", start_address="10.0.0.1", end_address="10.0.0.1")]

        dns_result = DNSLookupResult(ip="10.0.0.1", ptr_hostname="host.example.com", reason="lookup_ok")
        self.netbox_client.evaluate_ip_address.return_value = IpAddressWriteResult(
            status="not_found",
            payload={"address": "10.0.0.1/32", "status": "active", "dns_name": "host.example.com"},
        )

        with patch("netbox_scanner.scanner.lookup_dns", return_value=dns_result):
            summary = scanner.run(
                scan_ranges=scan_ranges,
                profile="services",
                speed="polite",
                dry_run=True,
            )

        self.assertEqual(1, summary.verified)
        self.netbox_client.fetch_scan_ranges.assert_not_called()

    def test_export_results_writes_json_and_csv(self):
        summary = SimpleNamespace(
            results=[
                ScanResult(
                    ip="10.0.0.1",
                    liveness="verified",
                    nmap_up=True,
                    ptr_hostname="host.example.com",
                    netbox_status="planned",
                )
            ]
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            json_path = Path(tmp_dir) / "results.json"
            csv_path = Path(tmp_dir) / "results.csv"

            export_results(summary, str(json_path))
            export_results(summary, str(csv_path))

            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual("10.0.0.1", payload[0]["ip"])
            self.assertEqual("verified", payload[0]["liveness"])
            self.assertIn("ptr_hostname", payload[0])
            self.assertIn("ptr_hostname", csv_path.read_text(encoding="utf-8"))

    def test_export_results_rejects_unknown_suffix(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            with self.assertRaisesRegex(ValueError, "Output path must end with"):
                export_results(SimpleNamespace(results=[]), str(Path(tmp_dir) / "results.txt"))
