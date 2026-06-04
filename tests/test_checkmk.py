import json
import unittest

from netbox_scanner.checkmk import (
    CheckMKClient,
    CheckMKConfig,
    authorization_header,
    build_host_config_query,
    parse_host_config_response,
    should_apply_checkmk_tag,
)
from netbox_scanner.config import AppConfig, NetBoxConfig, load_config, validate_config


class CheckMKTests(unittest.TestCase):
    def test_build_host_config_query_uses_exact_ip_match(self):
        query = json.loads(build_host_config_query("192.168.1.100"))
        self.assertEqual("=", query["op"])
        self.assertEqual("attributes.ipaddress", query["left"])
        self.assertEqual("192.168.1.100", query["right"])

    def test_authorization_header_uses_bearer_user_secret(self):
        self.assertEqual(
            "Bearer automation secret-value",
            authorization_header("automation", "secret-value"),
        )

    def test_parse_host_config_response_detects_monitored_host(self):
        payload = {"value": [{"id": "host-1", "title": "server01.example.com"}]}
        result = parse_host_config_response(payload)
        self.assertTrue(result.monitored)
        self.assertEqual("server01.example.com", result.host_name)

    def test_parse_host_config_response_empty_means_not_monitored(self):
        result = parse_host_config_response({"value": []})
        self.assertFalse(result.monitored)
        self.assertIsNone(result.host_name)

    def test_should_apply_checkmk_tag_when_monitored_and_enabled(self):
        config = CheckMKConfig(enabled=True)
        self.assertTrue(should_apply_checkmk_tag(config, True))
        self.assertFalse(should_apply_checkmk_tag(config, False))

    def test_should_apply_checkmk_tag_skips_when_disabled(self):
        config = CheckMKConfig(enabled=False)
        self.assertFalse(should_apply_checkmk_tag(config, True))

    def test_lookup_host_by_ip_uses_rest_filter(self):
        captured = {}

        def fake_http_get(url, headers, timeout):
            captured["url"] = url
            captured["headers"] = headers
            captured["timeout"] = timeout
            body = json.dumps({"value": [{"id": "1", "title": "host.example.com"}]})
            return 200, body

        client = CheckMKClient(
            CheckMKConfig(
                enabled=True,
                base_url="https://checkmk.example.com/monitoring",
                automation_user="automation",
                automation_secret="secret",
            ),
            http_get=fake_http_get,
        )
        result = client.lookup_host_by_ip("10.0.0.5")

        self.assertTrue(result.monitored)
        self.assertEqual("host.example.com", result.host_name)
        self.assertIn("host_config/collections/all", captured["url"])
        self.assertIn("query=", captured["url"])
        self.assertIn("attributes.ipaddress", captured["url"])
        self.assertIn("10.0.0.5", captured["url"])
        self.assertEqual("Bearer automation secret", captured["headers"]["Authorization"])

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
