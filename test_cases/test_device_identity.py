"""Direct contract of tools/device_identity.py: short names, MAC spellings and the eth1 hint (v3.1.1 M4, P3b).

Expectations are written from the issue texts, not from the module:
- I-007 rule 6 (short name: trim blanks, drop the trailing ".", ignore case, part before the first ".",
  never split on "-" or "_"), rule 4 (same device = same short name), rule 5 (short names unique,
  several matches are an error, no guessing) and rule 7 (no endswith, no dropping "-"/"_");
- P3b design point (v3.1.1 guide 14.1): the display short name keeps its case, the comparison key is
  casefolded;
- I-018 and O1 points 5-7 (owner 2026-11-07 "同意你的建议。"): the MAC spellings in
  test_cases/fixtures/mac_spellings.tsv;
- I-041 (owner 2026-11-05): eth1_mac should be eth0_mac + 1; only a hint, and only when both are filled.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import device_identity as DI  # noqa: E402

FIXTURE = ROOT / "test_cases/fixtures/mac_spellings.tsv"


def fixture_rows():
    lines = FIXTURE.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "input\texpected", lines[0]
    rows = [tuple(line.split("\t")) for line in lines[1:]]
    assert all(len(row) == 2 for row in rows), rows
    return rows


class ShortNameTests(unittest.TestCase):
    def test_full_name_trailing_dot_and_blanks_give_one_short_name(self):
        # I-007 rule 6; the three spellings of the v3.1.1 guide 14.4.
        for hostname, display in (
            ("ew-leaf001.site.example.test", "ew-leaf001"),
            ("EW-Leaf001.Site.Example.Test.", "EW-Leaf001"),
            (" ew-leaf001 ", "ew-leaf001"),
            ("ew-leaf001.", "ew-leaf001"),
        ):
            with self.subTest(hostname=hostname):
                self.assertEqual(display, DI.short_name(hostname))   # display keeps the case
                self.assertEqual("ew-leaf001", DI.short_key(hostname))  # comparison key is casefolded

    def test_only_the_dot_splits(self):
        # I-007 rule 6: "只按「.」切，不按「-」或「_」切".
        self.assertEqual("ib_pod-a-leaf01", DI.short_name("ib_pod-a-leaf01.site.example.test"))
        self.assertEqual("ib_pod-a-leaf01", DI.short_key("IB_Pod-A-Leaf01"))

    def test_same_device_compares_short_names_without_fuzzy_matching(self):
        # I-007 rule 4: same device by short name; rule 7: no endswith, no dropping "-" or "_".
        self.assertTrue(DI.same_device("ew-leaf001.site.example.test", "EW-LEAF001"))
        self.assertTrue(DI.same_device("ew-leaf001.site.example.test", "ew-leaf001.other.example.test"))
        for a, b in (
            ("ew-leaf001", "ew-leaf0011"),
            ("ew-leaf1", "leaf1"),            # endswith without a boundary
            ("ew-leaf001", "ewleaf001"),      # "-" dropped
            ("ew_leaf001", "ew-leaf001"),     # "_" vs "-"
            ("ufm-02", "ufm02.site.example.test"),  # the I-007 field example needs an explicit alias
        ):
            with self.subTest(a=a, b=b):
                self.assertFalse(DI.same_device(a, b))

    def test_duplicate_short_names_lists_every_clash_ignoring_case(self):
        # I-007 rule 5: short names, case ignored, must be unique.
        hostnames = [
            "ew-leaf001.site.example.test",
            "ew-leaf002",
            "ew-leaf001.other.example.test",
            "ew-leaf003",
            "EW-LEAF002.site.example.test",
        ]
        self.assertEqual(
            {
                "ew-leaf001": ["ew-leaf001.site.example.test", "ew-leaf001.other.example.test"],
                "ew-leaf002": ["ew-leaf002", "EW-LEAF002.site.example.test"],
            },
            DI.duplicate_short_names(hostnames),
        )
        self.assertEqual({}, DI.duplicate_short_names(["ew-leaf001", "ew-leaf002.site.example.test"]))

    def test_resolve_returns_one_host_refuses_two_and_never_guesses(self):
        hostnames = ["ew-leaf001.site.example.test", "ew-leaf001.other.example.test",
                     "ew-leaf002.site.example.test", "ufm02.site.example.test"]
        # rule 5: several matches are an error naming them
        with self.assertRaises(DI.AmbiguousNameError) as caught:
            DI.resolve("ew-leaf001", hostnames)
        self.assertIsInstance(caught.exception, ValueError)
        self.assertIn("ew-leaf001.site.example.test", str(caught.exception))
        self.assertIn("ew-leaf001.other.example.test", str(caught.exception))
        with self.assertRaises(DI.AmbiguousNameError):
            DI.resolve("ew-leaf001.site.example.test", hostnames)   # still two devices with that short name
        # rule 4: one match by short name, full or short, any case
        self.assertEqual("ew-leaf002.site.example.test", DI.resolve("EW-LEAF002", hostnames))
        self.assertEqual("ew-leaf002.site.example.test", DI.resolve("ew-leaf002.other.example.test", hostnames))
        # rule 7: no fuzzy match
        self.assertIsNone(DI.resolve("leaf002", hostnames))
        self.assertIsNone(DI.resolve("ufm-02", hostnames))
        self.assertIsNone(DI.resolve("ew-leaf003", hostnames))


class MacTests(unittest.TestCase):
    def test_fixture_spellings(self):
        rows = fixture_rows()
        kinds = {expected if expected in ("MISSING", "INVALID") else "VALUE" for _, expected in rows}
        self.assertEqual({"VALUE", "MISSING", "INVALID"}, kinds)
        for value, expected in rows:
            with self.subTest(value=value):
                if expected == "INVALID":
                    with self.assertRaises(ValueError):
                        DI.normalize_mac(value)
                elif expected == "MISSING":
                    self.assertEqual("", DI.normalize_mac(value))
                else:
                    self.assertEqual(expected, DI.normalize_mac(value))

    def test_invalid_value_is_named_in_the_error(self):
        with self.assertRaises(ValueError) as caught:
            DI.normalize_mac("02 00 00 00 00 05")
        self.assertIn("02 00 00 00 00 05", str(caught.exception))


class Eth1FollowsEth0Tests(unittest.TestCase):
    def test_adjacent_with_carry(self):
        # I-041: eth1_mac = eth0_mac + 1 as a 48-bit number, carries included.
        for eth0, eth1 in (
            ("02:00:00:00:00:01", "02:00:00:00:00:02"),
            ("02:00:00:00:00:ff", "02:00:00:00:01:00"),
            ("02:00:00:00:ff:ff", "02:00:00:01:00:00"),
        ):
            with self.subTest(eth0=eth0):
                self.assertIs(True, DI.eth1_follows_eth0(eth0, eth1))

    def test_not_adjacent(self):
        for eth0, eth1 in (
            ("02:00:00:00:00:01", "02:00:00:00:00:03"),
            ("02:00:00:00:00:02", "02:00:00:00:00:01"),   # eth0 + 1 is not eth1 - 1
            ("02:00:00:00:00:01", "02:00:00:00:00:01"),
            ("02:00:00:00:00:ff", "02:00:00:00:00:00"),   # the last byte wraps without the carry
            ("02:00:00:00:00:01", "02:00:00:01:00:02"),
        ):
            with self.subTest(eth0=eth0, eth1=eth1):
                self.assertIs(False, DI.eth1_follows_eth0(eth0, eth1))

    def test_only_one_filled_is_not_judged(self):
        # I-041: the hint needs both MACs; with one missing there is nothing to judge.
        for eth0, eth1 in (
            ("02:00:00:00:00:01", "NA"),
            ("", "02:00:00:00:00:02"),
            ("N/A", "-"),
        ):
            with self.subTest(eth0=eth0, eth1=eth1):
                self.assertIsNone(DI.eth1_follows_eth0(eth0, eth1))

    def test_spellings_and_case_do_not_matter(self):
        self.assertIs(True, DI.eth1_follows_eth0("02-00-00-00-00-0A", "0200.0000.000b"))
        self.assertIs(True, DI.eth1_follows_eth0("02:AB:CD:EF:00:FF", "02abcdef0100"))
        self.assertIs(False, DI.eth1_follows_eth0("02-00-00-00-00-0A", "0200.0000.000C"))

    def test_unrecognised_mac_is_an_error(self):
        with self.assertRaises(ValueError):
            DI.eth1_follows_eth0("02:00:00:00:00:01", "02:00:00:00:00:0g")


if __name__ == "__main__":
    unittest.main()
