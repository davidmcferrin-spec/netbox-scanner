from __future__ import annotations

import contextlib
import os
import signal
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

DEFAULT_LOCK_NAME = ".netbox-scanner.lock"


class RunLockError(RuntimeError):
    """Another scan is already running or the lock file could not be used."""


def default_lock_path() -> Path:
    return Path.home() / DEFAULT_LOCK_NAME


def resolve_lock_path(path: str | Path | None) -> Path:
    if path is None or not str(path).strip():
        return default_lock_path()
    return Path(path).expanduser()


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    else:
        return True


def _read_lock_pid(path: Path) -> int | None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("pid="):
            try:
                return int(line.split("=", 1)[1].strip())
            except ValueError:
                return None
    return None


class RunLock:
    """Exclusive lock file for a single scanner run."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = resolve_lock_path(path)
        self._held = False
        self._old_handlers: dict[int, Any] = {}

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        while True:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                holder = _read_lock_pid(self.path)
                if holder is not None and pid_alive(holder):
                    raise RunLockError(
                        f"Another netbox-scanner run is in progress (PID {holder}). "
                        f"Lock file: {self.path}"
                    )
                try:
                    self.path.unlink(missing_ok=True)
                except OSError as exc:
                    raise RunLockError(
                        f"Could not replace stale lock file {self.path}: {exc}"
                    ) from exc
                continue

            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(f"pid={os.getpid()}\n")
                handle.write(f"started={datetime.now(timezone.utc).isoformat()}\n")
            self._held = True
            self._install_signal_handlers()
            return

    def release(self) -> None:
        if not self._held:
            return
        self._restore_signal_handlers()
        self._held = False
        try:
            if self.path.exists():
                holder = _read_lock_pid(self.path)
                if holder in (None, os.getpid()):
                    self.path.unlink()
        except OSError:
            pass

    def _install_signal_handlers(self) -> None:
        for sig in (signal.SIGINT, getattr(signal, "SIGTERM", None)):
            if sig is None:
                continue
            try:
                self._old_handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, self._signal_handler)
            except (ValueError, OSError):
                pass

    def _restore_signal_handlers(self) -> None:
        for sig, handler in self._old_handlers.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass
        self._old_handlers.clear()

    def _signal_handler(self, signum: int, frame: Any) -> None:
        self.release()
        handler = self._old_handlers.get(signum, signal.SIG_DFL)
        if callable(handler) and handler not in (signal.SIG_DFL, signal.SIG_IGN):
            handler(signum, frame)
            return
        if signum == signal.SIGINT:
            raise KeyboardInterrupt
        raise SystemExit(128 + signum)

    def __enter__(self) -> RunLock:
        self.acquire()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.release()


@contextlib.contextmanager
def run_lock(path: str | Path | None = None) -> Iterator[RunLock]:
    lock = RunLock(path)
    try:
        lock.acquire()
        yield lock
    finally:
        lock.release()
