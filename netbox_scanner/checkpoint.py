from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class PrefixCheckpoint:
    prefix_cidr: str
    completed_ips: list[str] = field(default_factory=list)

    def is_ip_done(self, ip: str) -> bool:
        return ip in self.completed_ips

    def mark_ip(self, ip: str) -> None:
        if ip not in self.completed_ips:
            self.completed_ips.append(ip)

    @property
    def complete(self) -> bool:
        return bool(self.completed_ips) and getattr(self, "_marked_complete", False)

    def mark_complete(self) -> None:
        self._marked_complete = True


@dataclass
class ScanCheckpoint:
    run_id: str
    prefixes: dict[str, PrefixCheckpoint] = field(default_factory=dict)

    def prefix_state(self, prefix_cidr: str) -> PrefixCheckpoint:
        if prefix_cidr not in self.prefixes:
            self.prefixes[prefix_cidr] = PrefixCheckpoint(prefix_cidr=prefix_cidr)
        return self.prefixes[prefix_cidr]

    def is_prefix_complete(self, prefix_cidr: str) -> bool:
        state = self.prefixes.get(prefix_cidr)
        return bool(state and getattr(state, "_marked_complete", False))

    def mark_prefix_complete(self, prefix_cidr: str) -> None:
        self.prefix_state(prefix_cidr).mark_complete()


def default_checkpoint_path(configured: str) -> Path:
    if configured.strip():
        return Path(configured).expanduser()
    return Path.home() / ".netbox-scanner-checkpoint.json"


def load_checkpoint(path: Path, *, run_id: str | None = None) -> ScanCheckpoint | None:
    if not path.exists():
        return None
    try:
        raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    stored_run_id = str(raw.get("run_id") or "")
    if run_id is not None and stored_run_id and stored_run_id != run_id:
        return None
    state = ScanCheckpoint(run_id=stored_run_id or run_id or "")
    for prefix_cidr, payload in (raw.get("prefixes") or {}).items():
        pc = PrefixCheckpoint(
            prefix_cidr=prefix_cidr,
            completed_ips=list(payload.get("completed_ips") or []),
        )
        if payload.get("complete"):
            pc.mark_complete()
        state.prefixes[prefix_cidr] = pc
    return state


def save_checkpoint(path: Path, state: ScanCheckpoint) -> None:
    payload: dict[str, Any] = {
        "run_id": state.run_id,
        "prefixes": {
            prefix: {
                "completed_ips": pc.completed_ips,
                "complete": getattr(pc, "_marked_complete", False),
            }
            for prefix, pc in state.prefixes.items()
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
