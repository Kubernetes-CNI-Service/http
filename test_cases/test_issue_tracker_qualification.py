"""Stage-L-only C-5 qualification seam; no runtime publication authority."""

import hashlib
import json
import unittest
import dataclasses

from tools.project_contract import build_collection_cycle_identity
from monitor.issue_tracker_qualification import qualify_stage_l
from monitor.issue_tracker_whitelist import freeze_whitelist_sheet
from monitor.issue_tracker_whitelist_workbook import WorkbookWhitelistSnapshot


EMPTY_WHITELIST_SHA = hashlib.sha256(b"[]\n").hexdigest()
SWITCH = {"operation_id": "2-switch", "activity_key": ["switch", "leaf01", "fan", "fan1"], "action": "upsert"}
CABLING = {"operation_id": "1-cabling", "activity_key": ["eth_cabling", "leaf01", "swp1", "Link Down"], "action": "upsert"}
TOKEN_1 = "00112233445546778899aabbccddeeff"
TOKEN_2 = "ffeeddccbbaa49888776655443322110"
WHITELIST_HEADER = ("Submit Date", "Submitor", "Datahalll", "Rack", "Device Name", "Comments")


def bound_snapshot(*rules):
    rows = [WHITELIST_HEADER]
    rows.extend((None, None, None, None, rule, None) for rule in rules)
    return WorkbookWhitelistSnapshot(
        freeze_whitelist_sheet(rows), "b" * 64, 100, 1, 1,
    )


def cycle(sequence, token, operations, **changes):
    value = {
        "identity": build_collection_cycle_identity("site-a", "prod", sequence, token),
        "fresh": True,
        "qualifying": True,
        "source_mode": "synthetic-local-fixture",
        "authority_sha256": "a" * 64,
        "observations_sha256": ("d" if sequence == 7 else "e") * 64,
        "active_operations": operations,
    }
    value.update(changes)
    return value


class IssueTrackerQualificationTests(unittest.TestCase):
    def qualify(self, cycles=None, **changes):
        if cycles is None:
            cycles = [cycle(7, TOKEN_1, [SWITCH, CABLING]), cycle(8, TOKEN_2, [CABLING, SWITCH])]
        arguments = {
            "k": 2, "whitelist_rules": [],
            "whitelist_sha256": EMPTY_WHITELIST_SHA,
            "template_sha256": "b" * 64,
        }
        arguments.update(changes)
        return qualify_stage_l(cycles, **arguments)

    def test_two_cycle_qualified_set_retains_both_despite_one_local_change(self):
        local_diff_projection = [CABLING]
        qualified = self.qualify()
        self.assertEqual([CABLING, SWITCH], json.loads(qualified.operations_json))
        self.assertEqual(1, len(local_diff_projection))
        self.assertEqual(2, len(json.loads(qualified.operations_json)))
        self.assertEqual(2, qualified.k)
        self.assertEqual("synthetic-local-fixture", qualified.mode)

    def test_only_latest_active_intersection_qualifies(self):
        qualified = self.qualify([cycle(7, TOKEN_1, [SWITCH, CABLING]), cycle(8, TOKEN_2, [CABLING])])
        self.assertEqual([CABLING], json.loads(qualified.operations_json))

    def test_runtime_nonempty_whitelist_and_ib_authority_fail_closed(self):
        with self.assertRaises(ValueError):
            self.qualify([cycle(7, TOKEN_1, [SWITCH], source_mode="runtime"), cycle(8, TOKEN_2, [SWITCH])])
        with self.assertRaises(ValueError):
            self.qualify(whitelist_rules=["leaf01"])
        ib = dict(CABLING, activity_key=["ib_cabling", "leaf01", "swp1", "Link Down"])
        with self.assertRaises(ValueError):
            self.qualify([cycle(7, TOKEN_1, [ib]), cycle(8, TOKEN_2, [ib])])

    def test_invalid_identity_gap_and_nonqualifying_cycle_fail_closed(self):
        bad = cycle(7, TOKEN_1, [SWITCH])
        bad["identity"]["cycle_id"] = "0" * 64
        with self.assertRaises(ValueError):
            self.qualify([bad, cycle(8, TOKEN_2, [SWITCH])])
        with self.assertRaises(ValueError):
            self.qualify([cycle(7, TOKEN_1, [SWITCH]), cycle(9, TOKEN_2, [SWITCH])])
        with self.assertRaises(ValueError):
            self.qualify([cycle(7, TOKEN_1, [SWITCH], qualifying=False), cycle(8, TOKEN_2, [SWITCH])])

    def test_duplicate_keys_and_malformed_k_fail_closed(self):
        with self.assertRaises(ValueError):
            self.qualify([cycle(7, TOKEN_1, [SWITCH, SWITCH]), cycle(8, TOKEN_2, [SWITCH])])
        with self.assertRaises(ValueError):
            self.qualify(k=True)

    def test_same_activity_cannot_change_operation_identity_within_k(self):
        changed = dict(SWITCH, operation_id="different-switch")
        with self.assertRaises(ValueError):
            self.qualify([cycle(7, TOKEN_1, [SWITCH]), cycle(8, TOKEN_2, [changed])])

    def test_bound_nonempty_snapshot_filters_switch_with_canonical_provenance(self):
        survivor = {"operation_id": "3-spine", "activity_key": ["switch", "spine01", "fan", "fan2"], "action": "upsert"}
        for rule in ("leaf01", "leaf*", "re:^leaf0[0-9]$"):
            with self.subTest(rule=rule):
                snapshot = bound_snapshot(rule)
                qualified = self.qualify(
                    [cycle(7, TOKEN_1, [SWITCH, survivor]), cycle(8, TOKEN_2, [survivor, SWITCH])],
                    whitelist_rules=list(snapshot.whitelist.rules),
                    whitelist_sha256=snapshot.whitelist.sha256,
                    whitelist_snapshot=snapshot,
                )
                self.assertEqual([survivor], json.loads(qualified.operations_json))
                self.assertEqual(
                    [{"operation_id": "2-switch", "activity_key": SWITCH["activity_key"],
                      "matched_rule": snapshot.whitelist.rules[0]}],
                    json.loads(qualified.whitelist_skips_json),
                )

    def test_nonempty_snapshot_requires_source_bound_cabling_endpoints(self):
        snapshot = bound_snapshot("leaf01")
        with self.assertRaisesRegex(ValueError, "A/Z|endpoint"):
            self.qualify(
                whitelist_rules=list(snapshot.whitelist.rules),
                whitelist_sha256=snapshot.whitelist.sha256,
                whitelist_snapshot=snapshot,
            )

    def test_nonempty_snapshot_rejects_forgery_and_duplicates_before_skip(self):
        snapshot = bound_snapshot("leaf01")
        switches = [cycle(7, TOKEN_1, [SWITCH]), cycle(8, TOKEN_2, [SWITCH])]
        valid = dict(whitelist_rules=list(snapshot.whitelist.rules),
                     whitelist_sha256=snapshot.whitelist.sha256,
                     whitelist_snapshot=snapshot)
        for changed in (
            {"whitelist_sha256": "f" * 64},
            {"whitelist_rules": ["other-host"]},
            {"whitelist_snapshot": dataclasses.replace(snapshot, workbook_sha256="f" * 64)},
            {"whitelist_snapshot": dataclasses.replace(
                snapshot, whitelist=dataclasses.replace(snapshot.whitelist, sha256="f" * 64))},
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.qualify(switches, **(valid | changed))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.qualify([cycle(7, TOKEN_1, [SWITCH, SWITCH]), switches[1]], **valid)


if __name__ == "__main__":
    unittest.main()
