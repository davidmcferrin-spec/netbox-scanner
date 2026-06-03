import tempfile
import unittest
from pathlib import Path

from netbox_scanner.config import AppConfig, NetBoxConfig, load_config, validate_config


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
