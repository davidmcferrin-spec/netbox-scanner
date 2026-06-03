import ipaddress
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from netbox_scanner.scanner import (
    SPEED_TO_TIMING,
    is_excluded,
    parse_exclusions_file,
    range_records_to_exclusions,
    timing_for_speed,
)
from netbox_scanner.netbox import RangeRecord


class ScannerTests(unittest.TestCase):
    def test_speed_mapping_matches_expected_nmap_templates(self):
        for speed, timing in SPEED_TO_TIMING.items():
            self.assertEqual(timing, timing_for_speed(speed))

    def test_exclusion_logic_covers_netbox_ranges_and_file_entries(self):
        netbox_exclusions = range_records_to_exclusions(
            [RangeRecord(name="reserved", start_address="10.0.0.10", end_address="10.0.0.12", excluded=True)]
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            exclusions_file = Path(tmp_dir) / "exclude.txt"
            exclusions_file.write_text("10.0.0.20\n10.0.0.30/31\n", encoding="utf-8")
            file_exclusions = parse_exclusions_file(str(exclusions_file))

        combined = [*netbox_exclusions, *file_exclusions]

        self.assertTrue(is_excluded("10.0.0.10", combined))
        self.assertTrue(is_excluded("10.0.0.20", combined))
        self.assertTrue(is_excluded("10.0.0.31", combined))
        self.assertFalse(is_excluded("10.0.0.40", combined))
