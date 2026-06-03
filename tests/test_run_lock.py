import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netbox_scanner.run_lock import RunLock, RunLockError, resolve_lock_path


class RunLockTests(unittest.TestCase):
    def test_acquire_and_release_removes_lock_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.lock"
            lock = RunLock(path)
            lock.acquire()
            self.assertTrue(path.exists())
            lock.release()
            self.assertFalse(path.exists())

    def test_second_acquire_fails_while_holder_alive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.lock"
            first = RunLock(path)
            first.acquire()
            second = RunLock(path)
            with patch("netbox_scanner.run_lock.pid_alive", return_value=True):
                with self.assertRaises(RunLockError) as ctx:
                    second.acquire()
            self.assertIn("in progress", str(ctx.exception))
            first.release()

    def test_stale_lock_removed_when_pid_not_alive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.lock"
            path.write_text("pid=999999\n", encoding="utf-8")
            with patch("netbox_scanner.run_lock.pid_alive", return_value=False):
                lock = RunLock(path)
                lock.acquire()
            self.assertTrue(path.read_text(encoding="utf-8").startswith(f"pid={os.getpid()}\n"))
            lock.release()
            self.assertFalse(path.exists())

    def test_context_manager_releases_on_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.lock"
            with self.assertRaises(ValueError):
                with RunLock(path):
                    self.assertTrue(path.exists())
                    raise ValueError("abort")
            self.assertFalse(path.exists())

    def test_resolve_lock_path_uses_default_when_empty(self):
        self.assertEqual(resolve_lock_path(""), resolve_lock_path(None))
