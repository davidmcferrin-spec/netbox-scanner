from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import dataclass
from typing import Any

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class RangeRecord:
    name: str
    start_address: str
    end_address: str
    excluded: bool = False


def _as_mapping(record: Any) -> dict[str, Any]:
    if isinstance(record, dict):
        return record
    return {
        "name": getattr(record, "name", ""),
        "start_address": getattr(record, "start_address", ""),
        "end_address": getattr(record, "end_address", ""),
        "status": getattr(record, "status", None),
        "role": getattr(record, "role", None),
        "reserved": getattr(record, "reserved", None),
        "excluded": getattr(record, "excluded", None),
        "custom_fields": getattr(record, "custom_fields", {}) or {},
    }


def _choice_value(choice: Any) -> str:
    if isinstance(choice, dict):
        for key in ("value", "label", "name"):
            value = choice.get(key)
            if value:
                return str(value).lower()
        return ""
    if choice is None:
        return ""
    return str(choice).lower()


def range_is_excluded(record: Any) -> bool:
    data = _as_mapping(record)
    custom_fields = data.get("custom_fields") or {}
    return any(
        value is True
        for value in (
            data.get("reserved"),
            data.get("excluded"),
            custom_fields.get("reserved"),
            custom_fields.get("excluded"),
        )
    ) or _choice_value(data.get("status")) == "reserved" or _choice_value(data.get("role")) == "excluded"


def parse_range_record(record: Any) -> RangeRecord:
    data = _as_mapping(record)
    return RangeRecord(
        name=str(data.get("name", "")),
        start_address=str(data.get("start_address", "")),
        end_address=str(data.get("end_address", "")),
        excluded=range_is_excluded(data),
    )


def collect_ranges_by_name(api, names: list[str]) -> list[RangeRecord]:
    ranges: list[RangeRecord] = []
    for name in names:
        for record in api.ipam.ip_ranges.filter(name=name):
            ranges.append(parse_range_record(record))
    return ranges


def iter_range_ips(record: RangeRecord):
    start = ipaddress.ip_address(record.start_address)
    end = ipaddress.ip_address(record.end_address)
    if start.version != end.version:
        raise ValueError("Range address families must match.")
    for raw_value in range(int(start), int(end) + 1):
        yield ipaddress.ip_address(raw_value)


def build_ip_address_payload(ip: str, hostname: str | None = None) -> dict[str, str]:
    address = ipaddress.ip_address(ip)
    cidr = 32 if address.version == 4 else 128
    payload = {"address": f"{address}/{cidr}", "status": "active"}
    if hostname:
        payload["dns_name"] = hostname
    return payload


class NetBoxClient:
    def __init__(
        self,
        base_url: str,
        api_token: str,
        *,
        timeout: float = 30.0,
        rate_limit: float = 0.0,
        api=None,
    ) -> None:
        self.base_url = base_url
        self.api_token = api_token
        self.timeout = timeout
        self.rate_limit = rate_limit
        self._api = api

    @property
    def api(self):
        if self._api is None:
            try:
                import pynetbox
            except ImportError as exc:  # pragma: no cover - optional at test time
                raise RuntimeError("pynetbox is required for NetBox integration.") from exc
            self._api = pynetbox.api(self.base_url, token=self.api_token)
            self._api.http_session.verify = True
        return self._api

    def _sleep(self) -> None:
        if self.rate_limit > 0:
            time.sleep(self.rate_limit)

    def fetch_scan_ranges(self, names: list[str]) -> list[RangeRecord]:
        self._sleep()
        return collect_ranges_by_name(self.api, names)

    def fetch_excluded_ranges(self) -> list[RangeRecord]:
        self._sleep()
        records = self.api.ipam.ip_ranges.all()
        return [parse_range_record(record) for record in records if range_is_excluded(record)]

    def create_ip_address(self, ip: str, hostname: str | None = None, dry_run: bool = False):
        payload = build_ip_address_payload(ip, hostname)
        if dry_run:
            return payload

        self._sleep()
        try:
            existing = self.api.ipam.ip_addresses.get(address=payload["address"])
        except Exception as exc:
            LOGGER.warning("Failed to query existing NetBox IP record: %s", exc)
            existing = None

        if existing is not None:
            return existing

        self._sleep()
        return self.api.ipam.ip_addresses.create(payload)
