import unittest

from netbox_scanner.selection import parse_prefix_selection


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
