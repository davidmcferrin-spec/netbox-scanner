from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - optional at test time
    yaml = None


DEFAULT_CONFIG_FILES = (
    Path("~/.netbox-scanner.conf").expanduser(),
    Path.cwd() / "config.yaml",
)


@dataclass(slots=True)
class NetBoxConfig:
    base_url: str = ""
    api_token: str = ""
    timeout: float = 30.0
    rate_limit: float = 0.0


@dataclass(slots=True)
class DNSConfig:
    servers: list[str] = field(default_factory=list)
    timeout: float = 2.0


@dataclass(slots=True)
class LoggingConfig:
    level: str = "INFO"
    file: str = "netbox-scanner.log"


@dataclass(slots=True)
class ScannerConfig:
    default_profile: str = "default"
    default_speed: str = "normal"
    scan_rate_limit: float = 0.0
    ping_timeout: float = 1.0
    profiles: dict[str, list[str]] = field(
        default_factory=lambda: {
            "default": ["1-1024"],
            "full": ["1-65535"],
            "web": ["80", "443", "8080", "8443"],
            "media": ["554", "8554", "1935"],
            "stealth": ["-sS", "-Pn"],
        }
    )


@dataclass(slots=True)
class AppConfig:
    netbox: NetBoxConfig = field(default_factory=NetBoxConfig)
    dns: DNSConfig = field(default_factory=DNSConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    scanner: ScannerConfig = field(default_factory=ScannerConfig)


class KeyValueFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage().replace("\n", "\\n")
        return (
            f"time={self.formatTime(record)} "
            f"level={record.levelname} "
            f"logger={record.name} "
            f"message={message}"
        )


def _load_yaml(path: Path) -> dict[str, Any]:
    if yaml is None:
        raise RuntimeError("PyYAML is required to read configuration files.")
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _select_config_path(explicit_path: str | None = None) -> Path | None:
    if explicit_path:
        return Path(explicit_path).expanduser()
    for candidate in DEFAULT_CONFIG_FILES:
        if candidate.exists():
            return candidate
    return None


def load_config(path: str | None = None) -> AppConfig:
    raw: dict[str, Any] = {}
    config_path = _select_config_path(path)
    if config_path and config_path.exists():
        raw = _load_yaml(config_path)

    netbox = raw.get("netbox", {})
    dns = raw.get("dns", {})
    logging_cfg = raw.get("logging", {})
    scanner = raw.get("scanner", {})

    config = AppConfig(
        netbox=NetBoxConfig(
            base_url=os.getenv("NETBOX_SCANNER_BASE_URL", netbox.get("base_url", "")),
            api_token=os.getenv("NETBOX_SCANNER_API_TOKEN", netbox.get("api_token", "")),
            timeout=float(netbox.get("timeout", 30.0)),
            rate_limit=float(netbox.get("rate_limit", 0.0)),
        ),
        dns=DNSConfig(
            servers=list(dns.get("servers", [])),
            timeout=float(dns.get("timeout", 2.0)),
        ),
        logging=LoggingConfig(
            level=str(logging_cfg.get("level", "INFO")).upper(),
            file=str(logging_cfg.get("file", "netbox-scanner.log")),
        ),
        scanner=ScannerConfig(
            default_profile=str(scanner.get("default_profile", "default")),
            default_speed=str(scanner.get("default_speed", "normal")),
            scan_rate_limit=float(scanner.get("scan_rate_limit", 0.0)),
            ping_timeout=float(scanner.get("ping_timeout", 1.0)),
            profiles={
                key: [str(item) for item in value]
                for key, value in scanner.get("profiles", ScannerConfig().profiles).items()
            },
        ),
    )
    return config


def configure_logging(config: LoggingConfig) -> None:
    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(getattr(logging, config.level, logging.INFO))

    formatter = KeyValueFormatter()
    file_handler = logging.FileHandler(config.file)
    file_handler.setFormatter(formatter)

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)

    root_logger.addHandler(file_handler)
    root_logger.addHandler(stdout_handler)
