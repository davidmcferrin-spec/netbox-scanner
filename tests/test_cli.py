import unittest
from unittest.mock import patch

from click.testing import CliRunner

from netbox_scanner.config import AppConfig, NetBoxConfig
from netbox_scanner.cli import main


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
        ), patch("netbox_scanner.cli.run_on_schedule", side_effect=run_job_immediately):
            result = runner.invoke(main, ["--schedule", "0 * * * *"])

        self.assertNotEqual(0, result.exit_code)
        self.assertIn("require scanner.prefixes", result.output)

    def test_ranges_no_longer_required(self):
        runner = CliRunner()
        result = runner.invoke(main, [])
        self.assertNotIn("Missing option '--ranges'", result.output)
