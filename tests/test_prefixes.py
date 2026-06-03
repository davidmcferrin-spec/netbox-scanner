import unittest

from netbox_scanner.netbox import (
    PrefixRecord,
    collect_exclusion_ranges_for_prefixes,
    expand_prefixes_to_scan_cidrs,
    iter_unique_targets_from_prefixes,
    prefixes_for_display,
)
from tests.test_netbox import FakeAPI


def _record(
    record_id: int,
    prefix: str,
    *,
    parent_id: int | None = None,
    description: str = "",
) -> PrefixRecord:
    return PrefixRecord(
        id=record_id,
        prefix=prefix,
        description=description,
        parent_id=parent_id,
    )


class PrefixHierarchyTests(unittest.TestCase):
    def test_prefixes_for_display_hides_children_with_known_parent(self):
        records = [
            _record(1, "10.114.0.0/16"),
            _record(2, "10.114.50.0/24", parent_id=1),
            _record(3, "10.200.0.0/24"),
        ]

        display = prefixes_for_display(records)

        self.assertEqual(["10.114.0.0/16", "10.200.0.0/24"], [item.prefix for item in display])

    def test_expand_parent_to_leaf_children(self):
        records = [
            _record(1, "10.114.0.0/16"),
            _record(2, "10.114.50.0/24", parent_id=1),
            _record(3, "10.114.51.0/24", parent_id=1),
        ]

        expanded = expand_prefixes_to_scan_cidrs(records, ["10.114.0.0/16"])

        self.assertEqual(["10.114.50.0/24", "10.114.51.0/24"], expanded)

    def test_expand_parent_without_children_scans_parent(self):
        records = [_record(1, "10.114.0.0/16")]

        expanded = expand_prefixes_to_scan_cidrs(records, ["10.114.0.0/16"])

        self.assertEqual(["10.114.0.0/16"], expanded)

    def test_expand_child_drill_down_scans_only_child(self):
        records = [
            _record(1, "10.114.0.0/16"),
            _record(2, "10.114.50.0/24", parent_id=1),
        ]

        expanded = expand_prefixes_to_scan_cidrs(records, ["10.114.50.0/24"])

        self.assertEqual(["10.114.50.0/24"], expanded)

    def test_expand_nested_hierarchy_uses_leaf_prefixes(self):
        records = [
            _record(1, "10.114.0.0/16"),
            _record(2, "10.114.48.0/20", parent_id=1),
            _record(3, "10.114.50.0/24", parent_id=2),
        ]

        expanded = expand_prefixes_to_scan_cidrs(records, ["10.114.0.0/16"])

        self.assertEqual(["10.114.50.0/24"], expanded)

    def test_iter_unique_targets_from_prefixes_deduplicates(self):
        targets = iter_unique_targets_from_prefixes(["10.0.0.0/30", "10.0.0.0/30"])

        self.assertEqual(["10.0.0.1", "10.0.0.2"], targets)

    def test_collect_exclusion_ranges_for_prefixes(self):
        api = FakeAPI(
            {},
            all_ranges=[
                {
                    "id": 1,
                    "name": "dhcp",
                    "start_address": "10.0.0.10",
                    "end_address": "10.0.0.20",
                    "role": {"name": "DHCP Pool", "slug": "dhcp-pool"},
                },
                {
                    "id": 2,
                    "name": "usable",
                    "start_address": "10.0.0.50",
                    "end_address": "10.0.0.60",
                },
            ],
            within_ranges={
                "10.0.0.0/24": [
                    {
                        "id": 1,
                        "name": "dhcp",
                        "start_address": "10.0.0.10",
                        "end_address": "10.0.0.20",
                        "role": {"name": "DHCP Pool", "slug": "dhcp-pool"},
                    },
                    {
                        "id": 2,
                        "name": "usable",
                        "start_address": "10.0.0.50",
                        "end_address": "10.0.0.60",
                    },
                ]
            },
        )

        exclusions = collect_exclusion_ranges_for_prefixes(
            api,
            ["10.0.0.0/24"],
            skip_names=[],
            skip_roles=["DHCP Pool"],
        )

        self.assertEqual(1, len(exclusions))
        self.assertEqual("dhcp", exclusions[0].name)


if __name__ == "__main__":
    unittest.main()
