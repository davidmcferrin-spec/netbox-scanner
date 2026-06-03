import unittest
from io import StringIO
from unittest.mock import MagicMock, patch

from click.testing import CliRunner
from rich.console import Console

from netbox_scanner.config import AppConfig, DNSConfig, NetBoxConfig, ScannerConfig
from netbox_scanner.cli import (
    ResolvedScanTargets,
    format_verified_find_line,
    main,
    netbox_outcome_label,
    render_run_configuration,
)
from netbox_scanner.netbox import RangeRecord
from netbox_scanner.scanner import ScanResult


class CliTests(unittest.TestCase):
    def test_confirm_and_auto_confirm_are_mutually_exclusive(self):
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["--ranges", "lab", "--confirm", "--auto-confirm"],
        )

        self.assertNotEqual(0, result.exit_code)
        self.assertIn("not both", result.output)

    def test_schedule_rejects_confirm(self):
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["--ranges", "lab", "--confirm", "--schedule", "0 * * * *"],
        )

        self.assertNotEqual(0, result.exit_code)
        self.assertIn("--confirm is not supported with --schedule", result.output)

    def test_schedule_requires_prefixes_or_ranges(self):
        runner = CliRunner()
        config = AppConfig(netbox=NetBoxConfig(base_url="https://netbox.example.com", api_token="token"))
        config.scanner.prefixes = []

        def run_job_immediately(_cron, job):
            job()

        with patch("netbox_scanner.cli.load_config", return_value=config), patch(
            "netbox_scanner.cli.configure_logging"
        ), patch("netbox_scanner.cli.NetBoxClient.verify_authentication"), patch(
            "netbox_scanner.cli.run_on_schedule", side_effect=run_job_immediately
        ):
            result = runner.invoke(main, ["--schedule", "0 * * * *"])

        self.assertNotEqual(0, result.exit_code)
        self.assertIn("require scanner.prefixes", result.output)

    def test_ranges_no_longer_required(self):
        runner = CliRunner()
        result = runner.invoke(main, [])
        self.assertNotIn("Missing option '--ranges'", result.output)

    def test_netbox_outcome_label_for_created_host(self):
        result = ScanResult(
            ip="10.0.0.1",
            liveness="verified",
            open_ports=[22],
            ptr_hostname="host.example.com",
            netbox_written=True,
            netbox_status="created",
            reason="created",
            netbox_payload={
                "address": "10.0.0.1/32",
                "status": "active",
                "dns_name": "host.example.com",
            },
        )
        self.assertEqual("added to NetBox (dns_name=host.example.com)", netbox_outcome_label(result))
        line = format_verified_find_line(result)
        self.assertIn("FIND 10.0.0.1", line)
        self.assertIn("PTR=host.example.com", line)
        self.assertIn("dns_name=host.example.com", line)
        self.assertIn("added to NetBox (dns_name=host.example.com)", line)

    def test_netbox_outcome_label_for_dry_run(self):
        result = ScanResult(
            ip="10.0.0.2",
            liveness="verified",
            ptr_hostname="dry.example.com",
            netbox_status="planned",
            reason="dry_run",
            netbox_payload={
                "address": "10.0.0.2/32",
                "status": "active",
                "dns_name": "dry.example.com",
            },
        )
        self.assertEqual(
            "would add to NetBox (dry-run, dns_name=dry.example.com)",
            netbox_outcome_label(result),
        )

    def test_render_run_configuration_shows_prefix_mode_and_redacts_token(self):
        config = AppConfig(
            netbox=NetBoxConfig(
                base_url="https://netbox.example.com",
                api_token="super-secret-token-value",
            ),
            dns=DNSConfig(servers=["1.1.1.1"], timeout=2.0),
            scanner=ScannerConfig(default_profile="services", default_speed="polite"),
        )
        resolved = ResolvedScanTargets(
            legacy_ranges=False,
            selection_source="--prefix",
            selected_display_prefixes=["10.114.0.0/16"],
            scan_prefixes=["10.114.50.0/24"],
            scan_ranges=None,
            legacy_plan_ranges=None,
            exclusion_ranges=[],
            skip_name_set=set(),
        )
        buffer = StringIO()
        console = Console(file=buffer, width=120, force_terminal=True)

        render_run_configuration(
            config=config,
            config_path=None,
            resolved=resolved,
            profile="services",
            speed="polite",
            skip_ranges=[],
            skip_roles=["DHCP Pool"],
            dry_run=True,
            confirm=False,
            auto_confirm=False,
            exclude_file=None,
            output=None,
            max_hosts=None,
            interactive=True,
            scheduled=False,
            host_count_label="254",
            console=console,
        )

        output = buffer.getvalue()
        self.assertIn("Run Configuration", output)
        self.assertIn("prefix", output)
        self.assertIn("services", output)
        self.assertIn("polite", output)
        self.assertIn("dry-run", output)
        self.assertIn("configured", output)
        self.assertNotIn("super-secret-token-value", output)

    def test_render_run_configuration_shows_legacy_ranges_mode(self):
        config = AppConfig(
            netbox=NetBoxConfig(base_url="https://netbox.example.com", api_token="token"),
            scanner=ScannerConfig(),
        )
        resolved = ResolvedScanTargets(
            legacy_ranges=True,
            selection_source="--ranges",
            selected_display_prefixes=None,
            scan_prefixes=None,
            scan_ranges=[
                RangeRecord(name="lab", start_address="10.0.0.1", end_address="10.0.0.2"),
            ],
            legacy_plan_ranges=None,
            exclusion_ranges=None,
            skip_name_set=set(),
        )
        buffer = StringIO()
        console = Console(file=buffer, width=120, force_terminal=True)

        render_run_configuration(
            config=config,
            config_path=None,
            resolved=resolved,
            profile="services",
            speed="normal",
            skip_ranges=[],
            skip_roles=[],
            dry_run=False,
            confirm=False,
            auto_confirm=False,
            exclude_file=None,
            output=None,
            max_hosts=100,
            interactive=False,
            scheduled=True,
            host_count_label="2",
            console=console,
        )

        output = buffer.getvalue()
        self.assertIn("legacy IP ranges", output)
        self.assertIn("scheduled", output)
        self.assertIn("lab", output)

    def test_run_scan_prints_configuration_before_scan(self):
        config = AppConfig(
            netbox=NetBoxConfig(base_url="https://netbox.example.com", api_token="token"),
            scanner=ScannerConfig(prefixes=["10.0.0.0/30"]),
        )
        summary = MagicMock()
        summary.total_hosts = 2
        summary.hosts_completed = 2
        summary.verified = 0
        summary.ping_only = 0
        summary.unreachable = 2
        summary.excluded = 0
        summary.ptr_found = 0
        summary.netbox_created = 0
        summary.netbox_existing = 0
        summary.netbox_drift = 0
        summary.results = []

        client = MagicMock()
        client.fetch_prefixes.return_value = []
        client.fetch_exclusion_ranges_for_prefixes.return_value = []

        scanner = MagicMock()
        scanner.run.return_value = summary

        with patch("netbox_scanner.cli.load_config", return_value=config), patch(
            "netbox_scanner.cli.validate_config"
        ), patch("netbox_scanner.cli.configure_logging"), patch(
            "netbox_scanner.cli.NetBoxClient", return_value=client
        ), patch(
            "netbox_scanner.cli.NetworkScanner", return_value=scanner
        ), patch(
            "netbox_scanner.cli.expand_prefixes_to_scan_cidrs", return_value=["10.0.0.0/30"]
        ):
            from netbox_scanner.cli import _run_scan

            _run_scan(
                config_path=None,
                ranges=(),
                prefixes=("10.0.0.0/30",),
                skip_range_flags=(),
                skip_role_flags=(),
                profile=None,
                speed=None,
                dry_run=True,
                exclude_file=None,
                output=None,
                confirm=False,
                auto_confirm=False,
                max_hosts=None,
                interactive=False,
                scheduled=False,
            )

        scanner.run.assert_called_once()
