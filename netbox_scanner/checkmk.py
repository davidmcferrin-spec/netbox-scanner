from __future__ import annotations

import ipaddress
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

LOGGER = logging.getLogger(__name__)

HOST_CONFIG_COLLECTION = "domain-types/host_config/collections/all"


@dataclass(slots=True)
class CheckMKConfig:
    enabled: bool = False
    base_url: str = ""
    automation_user: str = ""
    automation_secret: str = ""
    tag_slug: str = "checkmk"
    timeout: float = 10.0
    rate_limit: float = 0.0
    verify_ssl: bool = True


@dataclass(slots=True)
class CheckMKLookupResult:
    monitored: bool
    host_name: str | None = None


def should_apply_checkmk_tag(config: CheckMKConfig, monitored: bool) -> bool:
    return config.enabled and monitored


def normalize_checkmk_ip(ip: str) -> str:
    return str(ipaddress.ip_address(ip))


def build_host_config_query(ip: str) -> str:
    normalized = normalize_checkmk_ip(ip)
    return json.dumps(
        {"op": "=", "left": "attributes.ipaddress", "right": normalized},
        separators=(",", ":"),
    )


def authorization_header(user: str, secret: str) -> str:
    return f"Bearer {user.strip()} {secret.strip()}"


def parse_host_config_response(payload: Any) -> CheckMKLookupResult:
    if not isinstance(payload, dict):
        return CheckMKLookupResult(monitored=False)

    entries = payload.get("value")
    if not isinstance(entries, list) or not entries:
        return CheckMKLookupResult(monitored=False)

    first = entries[0]
    if not isinstance(first, dict):
        return CheckMKLookupResult(monitored=True)

    host_name = first.get("title") or first.get("id")
    if host_name is not None:
        host_name = str(host_name)
    return CheckMKLookupResult(monitored=True, host_name=host_name)


HttpGet = Callable[[str, dict[str, str], float], tuple[int, str]]


class CheckMKClient:
    def __init__(
        self,
        config: CheckMKConfig,
        *,
        http_get: HttpGet | None = None,
    ) -> None:
        self.config = config
        self._http_get = http_get or self._default_http_get
        self._last_request_at: float | None = None

    @property
    def api_root(self) -> str:
        return f"{self.config.base_url.rstrip('/')}/check_mk/api/1.0"

    def lookup_host_by_ip(self, ip: str) -> CheckMKLookupResult:
        if not self.config.enabled:
            return CheckMKLookupResult(monitored=False)

        self._sleep()
        query = build_host_config_query(ip)
        params = urllib.parse.urlencode(
            [
                ("query", query),
                ("columns", "name"),
                ("columns", "attributes.ipaddress"),
            ]
        )
        url = f"{self.api_root}/{HOST_CONFIG_COLLECTION}?{params}"
        headers = {
            "Accept": "application/json",
            "Authorization": authorization_header(
                self.config.automation_user,
                self.config.automation_secret,
            ),
        }
        try:
            status_code, body = self._http_get(url, headers, self.config.timeout)
        except urllib.error.URLError as exc:
            LOGGER.warning("CheckMK lookup failed for %s: %s", ip, exc)
            return CheckMKLookupResult(monitored=False)

        if status_code in (401, 403):
            LOGGER.warning("CheckMK authentication failed for %s (HTTP %s)", ip, status_code)
            return CheckMKLookupResult(monitored=False)
        if status_code >= 400:
            LOGGER.warning("CheckMK lookup failed for %s (HTTP %s): %s", ip, status_code, body[:200])
            return CheckMKLookupResult(monitored=False)

        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            LOGGER.warning("CheckMK returned invalid JSON for %s: %s", ip, exc)
            return CheckMKLookupResult(monitored=False)

        return parse_host_config_response(payload)

    def _sleep(self) -> None:
        if self.config.rate_limit <= 0:
            return
        now = time.monotonic()
        if self._last_request_at is not None:
            elapsed = now - self._last_request_at
            if elapsed < self.config.rate_limit:
                time.sleep(self.config.rate_limit - elapsed)
        self._last_request_at = time.monotonic()

    def _default_http_get(self, url: str, headers: dict[str, str], timeout: float) -> tuple[int, str]:
        request = urllib.request.Request(url, headers=headers, method="GET")
        context = None
        if not self.config.verify_ssl:
            import ssl

            context = ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                body = response.read().decode("utf-8", errors="replace")
                return response.status, body
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            return exc.code, body
