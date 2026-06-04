from __future__ import annotations

import logging
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
    default_profile: str = "services"
    default_speed: str = "polite"
    scan_rate_limit: float = 0.5
    ping_timeout: float = 1.0
    prefixes: list[str] = field(default_factory=list)
    skip_ranges: list[str] = field(default_factory=list)
    skip_roles: list[str] = field(default_factory=lambda: ["DHCP Pool"])
    lock_file: str = ""
    profiles: dict[str, list[str]] = field(
        default_factory=lambda: {
            "services": ["-sS", "-sU", "T:22,23,80,443,445,U:161"],
            "web": ["80", "443", "8080", "8443"],
            "media": ["554", "8554", "1935"],
            "full": ["1-65535"],
            "stealth": ["-sS", "T:22,23,80,443,445,U:161"],
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


class ConsoleLogFormatter(logging.Formatter):
    """Short single-line records for stderr; keeps unattended output within ~80 columns."""

    def __init__(self, max_width: int = 80) -> None:
        super().__init__()
        self.max_width = max_width

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage().replace("\n", " ")
        line = f"{record.levelname}: {message}"
        if len(line) <= self.max_width:
            return line
        return line[: self.max_width - 1] + "…"


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
            base_url=str(netbox.get("base_url", "")),
            api_token=str(netbox.get("api_token", "")),
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
            default_profile=str(scanner.get("default_profile", ScannerConfig().default_profile)),
            default_speed=str(scanner.get("default_speed", ScannerConfig().default_speed)),
            scan_rate_limit=float(scanner.get("scan_rate_limit", ScannerConfig().scan_rate_limit)),
            ping_timeout=float(scanner.get("ping_timeout", ScannerConfig().ping_timeout)),
            prefixes=[str(item) for item in scanner.get("prefixes", [])],
            skip_ranges=[str(item) for item in scanner.get("skip_ranges", [])],
            skip_roles=(
                [str(item) for item in scanner["skip_roles"]]
                if "skip_roles" in scanner
                else list(ScannerConfig().skip_roles)
            ),
            profiles={
                key: [str(item) for item in value]
                for key, value in scanner.get("profiles", ScannerConfig().profiles).items()
            },
            lock_file=str(scanner.get("lock_file", "")),
        ),
    )
    return config


def validate_config(config: AppConfig) -> None:
    if not config.netbox.base_url.strip():
        raise ValueError(
            "NetBox base_url is required. Set netbox.base_url in your config file or pass --config."
        )
    if not config.netbox.api_token.strip():
        raise ValueError(
            "NetBox api_token is required. Set netbox.api_token in your config file or pass --config."
        )


PACKAGE_LOGGER_NAME = "netbox_scanner"


def configure_logging(config: LoggingConfig, *, console: bool = True) -> None:
    root_logger = logging.getLogger()
    root_logger.handlers.clear()

    level = getattr(logging, config.level, logging.INFO)
    package_logger = logging.getLogger(PACKAGE_LOGGER_NAME)
    package_logger.handlers.clear()
    package_logger.setLevel(level)
    package_logger.propagate = False

    file_formatter = KeyValueFormatter()
    file_handler = logging.FileHandler(config.file)
    file_handler.setFormatter(file_formatter)
    package_logger.addHandler(file_handler)

    if console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(ConsoleLogFormatter())
        package_logger.addHandler(console_handler)
