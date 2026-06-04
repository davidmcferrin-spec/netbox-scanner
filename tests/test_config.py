import logging
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from netbox_scanner.config import (
    AppConfig,
    ConsoleLogFormatter,
    KeyValueFormatter,
    LoggingConfig,
    NetBoxConfig,
    PACKAGE_LOGGER_NAME,
    configure_logging,
    load_config,
    validate_config,
)


class ConfigTests(unittest.TestCase):
    def test_validate_config_requires_netbox_credentials(self):
        with self.assertRaisesRegex(ValueError, "base_url is required"):
            validate_config(AppConfig(netbox=NetBoxConfig(base_url="", api_token="token")))

        with self.assertRaisesRegex(ValueError, "api_token is required"):
            validate_config(AppConfig(netbox=NetBoxConfig(base_url="https://netbox.example.com", api_token="")))

    def test_load_config_reads_netbox_credentials_from_file(self):
        yaml_text = """
netbox:
  base_url: "https://file.example.com"
  api_token: "file-token"
"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / "config.yaml"
            config_path.write_text(yaml_text, encoding="utf-8")
            config = load_config(str(config_path))

        self.assertEqual("https://file.example.com", config.netbox.base_url)
        self.assertEqual("file-token", config.netbox.api_token)

    def test_load_config_default_skip_roles(self):
        config = load_config("/nonexistent/config.yaml")
        self.assertEqual(["DHCP Pool"], config.scanner.skip_roles)

    def test_load_config_empty_skip_roles_disables_filter(self):
        yaml_text = """
netbox:
  base_url: "https://file.example.com"
  api_token: "file-token"
scanner:
  skip_roles: []
"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / "config.yaml"
            config_path.write_text(yaml_text, encoding="utf-8")
            config = load_config(str(config_path))
        self.assertEqual([], config.scanner.skip_roles)


class LoggingConfigTests(unittest.TestCase):
    def tearDown(self) -> None:
        self._close_log_handlers()

    @staticmethod
    def _close_log_handlers() -> None:
        for logger_name in ("", PACKAGE_LOGGER_NAME):
            logger = logging.getLogger(logger_name) if logger_name else logging.getLogger()
            for handler in logger.handlers[:]:
                handler.close()
                logger.removeHandler(handler)

    def test_configure_logging_interactive_uses_file_only(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_file = Path(tmp_dir) / "scan.log"
            config = LoggingConfig(level="INFO", file=str(log_file))
            stderr = StringIO()
            with patch("netbox_scanner.config.sys.stderr", stderr):
                configure_logging(config, console=False)
                logging.getLogger("netbox_scanner.cli").info("FIND 10.0.0.1 example")
                self._close_log_handlers()

            self.assertEqual("", stderr.getvalue())
            self.assertIn("FIND 10.0.0.1 example", log_file.read_text(encoding="utf-8"))

    def test_configure_logging_does_not_propagate_to_root_stream_handler(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_file = Path(tmp_dir) / "scan.log"
            config = LoggingConfig(level="INFO", file=str(log_file))
            stdout = StringIO()
            root_stream = logging.StreamHandler(stdout)
            root_stream.setFormatter(KeyValueFormatter())
            root_logger = logging.getLogger()
            root_logger.handlers.clear()
            root_logger.addHandler(root_stream)
            try:
                configure_logging(config, console=False)
                logging.getLogger("netbox_scanner.cli").info("secret scan event")
                self._close_log_handlers()
            finally:
                root_logger.handlers.clear()

            self.assertEqual("", stdout.getvalue())
            self.assertIn("secret scan event", log_file.read_text(encoding="utf-8"))

    def test_package_logger_does_not_propagate(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_file = Path(tmp_dir) / "scan.log"
            configure_logging(LoggingConfig(level="INFO", file=str(log_file)), console=False)
            package_logger = logging.getLogger(PACKAGE_LOGGER_NAME)
            try:
                self.assertFalse(package_logger.propagate)
            finally:
                self._close_log_handlers()

    def test_configure_logging_unattended_writes_compact_stderr(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            log_file = Path(tmp_dir) / "scan.log"
            config = LoggingConfig(level="INFO", file=str(log_file))
            stderr = StringIO()
            with patch("netbox_scanner.config.sys.stderr", stderr):
                configure_logging(config, console=True)
                logging.getLogger("netbox_scanner.cli").info("short message")
                self._close_log_handlers()

            output = stderr.getvalue()
            self.assertIn("INFO: short message", output)
            self.assertNotIn("logger=test.unattended", output)
            self.assertLessEqual(max(len(line) for line in output.splitlines()), 80)

    def test_console_log_formatter_truncates_long_lines(self):
        formatter = ConsoleLogFormatter(max_width=40)
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="x" * 100,
            args=(),
            exc_info=None,
        )
        formatted = formatter.format(record)
        self.assertLessEqual(len(formatted), 40)
        self.assertTrue(formatted.endswith("…"))

    def test_key_value_formatter_keeps_structured_file_records(self):
        formatter = KeyValueFormatter()
        record = logging.LogRecord(
            name="netbox_scanner.cli",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="Run configuration profile=services",
            args=(),
            exc_info=None,
        )
        formatted = formatter.format(record)
        self.assertIn("logger=netbox_scanner.cli", formatted)
        self.assertIn("message=Run configuration profile=services", formatted)
