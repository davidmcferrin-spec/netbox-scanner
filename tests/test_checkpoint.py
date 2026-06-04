import unittest
from pathlib import Path
import tempfile

from netbox_scanner.checkpoint import ScanCheckpoint, load_checkpoint, save_checkpoint


class CheckpointTests(unittest.TestCase):
    def test_save_and_resume_prefix_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "checkpoint.json"
            state = ScanCheckpoint(run_id="run-1")
            pc = state.prefix_state("10.0.0.0/24")
            pc.mark_ip("10.0.0.1")
            save_checkpoint(path, state)

            loaded = load_checkpoint(path)
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual("run-1", loaded.run_id)
            self.assertTrue(loaded.prefix_state("10.0.0.0/24").is_ip_done("10.0.0.1"))
