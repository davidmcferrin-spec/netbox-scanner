import json
import unittest

from netbox_scanner.checkmk import (
    CheckMKClient,
    CheckMKConfig,
    authorization_header,
    build_host_lookup_query,
    checkmk_api_root,
    parse_host_lookup_response,
    should_apply_checkmk_tag,
)
from netbox_scanner.config import AppConfig, NetBoxConfig, load_config, validate_config


class CheckMKTests(unittest.TestCase):
    def test_build_host_lookup_query_uses_livestatus_address(self):
        query = json.loads(build_host_lookup_query("192.168.1.100"))
        self.assertEqual("=", query["op"])
        self.assertEqual("address", query["left"])
        self.assertEqual("192.168.1.100", query["right"])

    def test_checkmk_api_root_accepts_site_or_full_api_url(self):
        self.assertEqual(
            "https://nncorpnagios.nexstar.tv/NewsNation/check_mk/api/1.0",
            checkmk_api_root("https://nncorpnagios.nexstar.tv/NewsNation"),
        )
        self.assertEqual(
            "https://nncorpnagios.nexstar.tv/NewsNation/check_mk/api/1.0",
            checkmk_api_root("https://nncorpnagios.nexstar.tv/NewsNation/check_mk/api/1.0"),
        )

    def test_authorization_header_uses_bearer_user_secret(self):
        self.assertEqual(
            "Bearer automation secret-value",
            authorization_header("automation", "secret-value"),
        )

    def test_parse_host_lookup_response_reads_extensions_name(self):
        payload = {
            "value": [
                {
                    "id": "DCWASOF2NAS01",
                    "title": "DCWASOF2NAS01",
                    "extensions": {"name": "DCWASOF2NAS01", "address": "10.98.0.10"},
                }
            ]
        }
        result = parse_host_lookup_response(payload)
        self.assertTrue(result.monitored)
        self.assertEqual("DCWASOF2NAS01", result.host_name)

    def test_parse_host_lookup_response_empty_means_not_monitored(self):
        result = parse_host_lookup_response({"value": []})
        self.assertFalse(result.monitored)
        self.assertIsNone(result.host_name)

    def test_should_apply_checkmk_tag_when_monitored_and_enabled(self):
        config = CheckMKConfig(enabled=True)
        self.assertTrue(should_apply_checkmk_tag(config, True))
        self.assertFalse(should_apply_checkmk_tag(config, False))

    def test_should_apply_checkmk_tag_skips_when_disabled(self):
        config = CheckMKConfig(enabled=False)
        self.assertFalse(should_apply_checkmk_tag(config, True))

    def test_lookup_host_by_ip_uses_host_collection_filter(self):
        captured = {}

        def fake_http_get(url, headers, timeout):
            captured["url"] = url
            captured["headers"] = headers
            captured["timeout"] = timeout
            body = json.dumps(
                {
                    "value": [
                        {
                            "id": "DCWASOF2NAS01",
                            "title": "DCWASOF2NAS01",
                            "extensions": {"name": "DCWASOF2NAS01", "address": "10.98.0.10"},
                        }
                    ]
                }
            )
            return 200, body

        client = CheckMKClient(
            CheckMKConfig(
                enabled=True,
                base_url="https://nncorpnagios.nexstar.tv/NewsNation",
                automation_user="netbox",
                automation_secret="secret",
            ),
            http_get=fake_http_get,
        )
        result = client.lookup_host_by_ip("10.98.0.10")

        self.assertTrue(result.monitored)
        self.assertEqual("DCWASOF2NAS01", result.host_name)
        self.assertIn("domain-types/host/collections/all", captured["url"])
        self.assertNotIn("host_config", captured["url"])
        self.assertIn("query=", captured["url"])
        self.assertIn("%22address%22", captured["url"])
        self.assertIn("10.98.0.10", captured["url"])
        self.assertEqual("Bearer netbox secret", captured["headers"]["Authorization"])

    def test_validate_config_requires_checkmk_credentials_when_enabled(self):
        with self.assertRaisesRegex(ValueError, "checkmk.base_url is required"):
            validate_config(
                AppConfig(
                    netbox=NetBoxConfig(base_url="https://netbox.example.com", api_token="token"),
                    checkmk=CheckMKConfig(enabled=True, automation_user="user", automation_secret="secret"),
                )
            )

    def test_load_config_reads_checkmk_settings(self):
        yaml_text = """
netbox:
  base_url: "https://netbox.example.com"
  api_token: "token"
checkmk:
  enabled: true
  base_url: "https://checkmk.example.com/site"
  automation_user: "automation"
  automation_secret: "secret"
"""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / "config.yaml"
            config_path.write_text(yaml_text, encoding="utf-8")
            config = load_config(str(config_path))

        self.assertTrue(config.checkmk.enabled)
        self.assertEqual("https://checkmk.example.com/site", config.checkmk.base_url)
        self.assertEqual("checkmk", config.checkmk.tag_slug)
