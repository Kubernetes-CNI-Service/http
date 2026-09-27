"""C-24 local Whitelist snapshot and per-record decision contract."""

import hashlib
import json
import unittest

from monitor.issue_tracker_whitelist import (
    WhitelistHoldError, WhitelistSnapshot, evaluate_whitelist, freeze_whitelist_sheet,
)


HEADER = ["Submit Date", "Submitor", "Datahalll", "Rack", "Device Name", "Comments"]


def sheet(*rules):
    return [HEADER, *[[None, None, None, None, rule, None] for rule in rules]]


class WhitelistTests(unittest.TestCase):
    def test_missing_and_malformed_sheet_hold_not_empty(self):
        for rows in (None, [], [["Device", "Name"]],
                     [HEADER, ["date", None, None, None, None, None]],
                     [HEADER + ["Unexpected"]]):
            with self.subTest(rows=rows), self.assertRaises(WhitelistHoldError):
                freeze_whitelist_sheet(rows)

    def test_legally_empty_sheet_has_canonical_empty_digest(self):
        snapshot = freeze_whitelist_sheet([HEADER, [None] * 6])
        self.assertEqual((), snapshot.rules)
        self.assertEqual(hashlib.sha256(b"[]\n").hexdigest(), snapshot.sha256)

    def test_invalid_regex_holds_at_freeze(self):
        with self.assertRaises(WhitelistHoldError):
            freeze_whitelist_sheet(sheet("re:[invalid"))

    def test_normalized_rule_digest_is_order_and_case_stable(self):
        left = freeze_whitelist_sheet(sheet(" LEAF-01 ", "leaf-*", r"re:^rack-\d+$"))
        right = freeze_whitelist_sheet(sheet(r"re:^rack-\d+$", "LEAF-*", "leaf-01"))
        self.assertEqual(left.rules, right.rules)
        self.assertEqual(left.sha256, right.sha256)
        self.assertEqual(3, len(left.rules))
        self.assertEqual(hashlib.sha256(left.canonical_bytes).hexdigest(), left.sha256)
        self.assertEqual(left.rules, tuple(json.loads(left.canonical_bytes)))

    def test_any_endpoint_exact_glob_regex_with_visible_source_rule_and_counts(self):
        snapshot = freeze_whitelist_sheet(sheet("Leaf-01", "spine-*", r"re:^rack-\d+$"))
        records = [
            {"record_id": "s1", "source": "Switch", "hostname": "LEAF-01"},
            {"record_id": "c1", "source": "Cabling", "a_node": "other", "z_node": "SPINE-02"},
            {"record_id": "c2", "source": "Cabling", "a_node": "RACK-12", "z_node": "other"},
            {"record_id": "s2", "source": "Switch", "hostname": "untouched"},
        ]
        evaluation = evaluate_whitelist(snapshot, records)
        self.assertEqual(3, evaluation.skipped_switches + evaluation.skipped_cabling)
        self.assertEqual(1, evaluation.skipped_switches)
        self.assertEqual(2, evaluation.skipped_cabling)
        self.assertEqual([True, True, True, False], [item.skipped for item in evaluation.decisions])
        self.assertEqual(["Switch", "Cabling", "Cabling", "Switch"],
                         [item.source for item in evaluation.decisions])
        self.assertEqual(["leaf-01", "spine-*", r"re:^rack-\d+$", None],
                         [item.matched_rule for item in evaluation.decisions])
        self.assertTrue(all(item.snapshot_sha256 == snapshot.sha256 for item in evaluation.decisions))

    def test_bad_record_source_or_endpoint_holds(self):
        snapshot = freeze_whitelist_sheet(sheet("leaf*"))
        for record in (
            {"record_id": "x", "source": "IB", "hostname": "leaf01"},
            {"record_id": "x", "source": "Switch"},
            {"record_id": "x", "source": "Cabling", "a_node": None, "z_node": None},
        ):
            with self.subTest(record=record), self.assertRaises(WhitelistHoldError):
                evaluate_whitelist(snapshot, [record])

    def test_forged_snapshot_digest_and_duplicate_record_hold(self):
        snapshot = freeze_whitelist_sheet(sheet("leaf*"))
        forged = WhitelistSnapshot(snapshot.rules, snapshot.canonical_bytes, "0" * 64)
        record = {"record_id": "s1", "source": "Switch", "hostname": "leaf01"}
        with self.assertRaises(WhitelistHoldError):
            evaluate_whitelist(forged, [record])
        with self.assertRaises(WhitelistHoldError):
            evaluate_whitelist(snapshot, [record, record])


if __name__ == "__main__":
    unittest.main()
