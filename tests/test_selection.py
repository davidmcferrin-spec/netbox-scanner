import unittest
from io import StringIO
from unittest.mock import patch

from rich.console import Console

from netbox_scanner.netbox import PrefixRecord
from netbox_scanner.selection import parse_prefix_selection, prompt_prefix_selection


class SelectionTests(unittest.TestCase):
    def test_parse_all_returns_every_index(self):
        self.assertEqual([1, 2, 3], parse_prefix_selection("all", 3))
        self.assertEqual([1, 2, 3], parse_prefix_selection("", 3))

    def test_parse_comma_separated_indices(self):
        self.assertEqual([1, 3], parse_prefix_selection("1, 3", 3))

    def test_parse_rejects_out_of_range(self):
        with self.assertRaisesRegex(ValueError, "out of range"):
            parse_prefix_selection("4", 3)

    def test_parse_rejects_invalid_tokens(self):
        with self.assertRaisesRegex(ValueError, "Invalid selection"):
            parse_prefix_selection("one", 3)

    def test_prompt_prefix_selection_can_show_child_table(self):
        display = [
            PrefixRecord(id=1, prefix="10.114.0.0/16", description="site"),
            PrefixRecord(id=3, prefix="10.200.0.0/24", description="solo"),
        ]
        all_prefixes = [
            *display,
            PrefixRecord(id=2, prefix="10.114.50.0/24", description="", parent_id=1),
        ]
        buffer = StringIO()
        console = Console(file=buffer, width=120, force_terminal=True)

        with patch("netbox_scanner.selection.click.confirm", return_value=True), patch(
            "netbox_scanner.selection.click.prompt", return_value="1"
        ):
            selected = prompt_prefix_selection(
                display,
                all_prefixes=all_prefixes,
                console=console,
            )

        self.assertEqual(["10.114.0.0/16"], selected)
        output = buffer.getvalue()
        self.assertIn("Child Prefixes To Scan", output)
        self.assertIn("10.114.50.0/24", output)
        self.assertIn("(scans this prefix)", output)

    def test_prompt_prefix_selection_skips_child_table_when_declined(self):
        display = [PrefixRecord(id=1, prefix="10.114.0.0/16", description="site")]
        buffer = StringIO()
        console = Console(file=buffer, width=120, force_terminal=True)

        with patch("netbox_scanner.selection.click.confirm", return_value=False), patch(
            "netbox_scanner.selection.click.prompt", return_value="all"
        ):
            selected = prompt_prefix_selection(display, console=console)

        self.assertEqual(["10.114.0.0/16"], selected)
        self.assertNotIn("Child Prefixes To Scan", buffer.getvalue())
