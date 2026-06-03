import unittest

from netbox_scanner.netbox import (
    PrefixRecord,
    collect_exclusion_ranges_for_prefixes,
    display_scan_target_count,
    expand_prefixes_to_scan_cidrs,
    format_scan_target_label,
    iter_unique_targets_from_prefixes,
    parse_prefix_record,
    prefixes_for_display,
    scan_preview_for_prefix,
    scan_targets_for_prefix,
)
from tests.test_netbox import FakeAPI


def _record(
    record_id: int,
    prefix: str,
    *,
    parent_id: int | None = None,
    description: str = "",
    site: str | None = None,
    children_count: int = 0,
    depth: int | None = None,
) -> PrefixRecord:
    return PrefixRecord(
        id=record_id,
        prefix=prefix,
        description=description,
        parent_id=parent_id,
        site=site,
        children_count=children_count,
        depth=depth,
    )


class PrefixHierarchyTests(unittest.TestCase):
    def test_parse_prefix_record_reads_scope_children_and_depth(self):
        record = parse_prefix_record(
            {
                "id": 155,
                "prefix": "10.207.10.0/24",
                "description": "",
                "scope": {
                    "name": "NYNYCOF1 - NewNation NY",
                    "slug": "newnation-ny",
                },
                "children": 0,
                "_depth": 1,
            }
        )

        self.assertEqual("10.207.10.0/24", record.prefix)
        self.assertEqual("NYNYCOF1 - NewNation NY", record.site)
        self.assertEqual(0, record.children_count)
        self.assertEqual(1, record.depth)

    def test_prefixes_for_display_hides_children_by_netbox_depth(self):
        records = [
            _record(2, "10.207.0.0/16", depth=0, children_count=28),
            _record(155, "10.207.10.0/24", depth=1),
        ]

        display = prefixes_for_display(records)

        self.assertEqual(["10.207.0.0/16"], [item.prefix for item in display])

    def test_display_scan_target_count_uses_netbox_children(self):
        records = [
            _record(2, "10.207.0.0/16", depth=0, children_count=28),
            _record(155, "10.207.10.0/24", depth=1),
        ]

        self.assertEqual(28, display_scan_target_count(records[0], records))
        self.assertEqual("-", format_scan_target_label(display_scan_target_count(records[1], records)))

    def test_prefixes_for_display_hides_children_by_cidr_containment(self):
        records = [
            _record(5, "10.207.0.0/16"),
            _record(6, "10.207.0.0/22"),
            _record(7, "10.207.10.0/24"),
            _record(34, "10.70.0.0/16"),
            _record(35, "10.70.10.0/24"),
            _record(1, "10.115.16.0/24"),
        ]

        display = prefixes_for_display(records)

        self.assertEqual(
            ["10.115.16.0/24", "10.207.0.0/16", "10.70.0.0/16"],
            [item.prefix for item in display],
        )

    def test_expand_parent_uses_containment_when_parent_id_missing(self):
        records = [
            _record(5, "10.207.0.0/16"),
            _record(6, "10.207.0.0/22"),
            _record(7, "10.207.10.0/24"),
            _record(10, "10.207.11.0/24"),
        ]

        expanded = expand_prefixes_to_scan_cidrs(records, ["10.207.0.0/16"])

        self.assertEqual(
            ["10.207.0.0/22", "10.207.10.0/24", "10.207.11.0/24"],
            expanded,
        )

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

    def test_scan_targets_for_parent_lists_maximal_child_cidrs(self):
        records = [
            _record(1, "10.114.0.0/16"),
            _record(2, "10.114.51.0/24", parent_id=1),
            _record(3, "10.114.50.0/24", parent_id=1),
        ]

        targets = scan_targets_for_prefix(records[0], records)

        self.assertEqual(["10.114.50.0/24", "10.114.51.0/24"], targets)

    def test_scan_preview_for_parent_lists_child_cidrs(self):
        records = [
            _record(1, "10.114.0.0/16"),
            _record(2, "10.114.50.0/24", parent_id=1),
        ]

        preview = scan_preview_for_prefix(records[0], records)

        self.assertEqual("10.114.50.0/24", preview)

    def test_scan_preview_for_standalone(self):
        records = [_record(1, "10.200.0.0/24")]

        preview = scan_preview_for_prefix(records[0], records)

        self.assertEqual("(scans this prefix)", preview)

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
        dhcp_range = {
            "id": 1,
            "name": "dhcp",
            "start_address": "10.0.0.10",
            "end_address": "10.0.0.20",
            "role": {"name": "DHCP-Pool", "slug": "dhcp-pool"},
        }
        api = FakeAPI(
            {},
            all_ranges=[dhcp_range],
            parent_ranges={"10.0.0.0/24": []},
            roles=[{"name": "DHCP-Pool", "slug": "dhcp-pool"}],
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
