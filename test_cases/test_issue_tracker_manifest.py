"""Independent literal canonical-body contract for Stage-L C-5 foundation."""

import dataclasses
import hashlib
import json
import unittest

from monitor.issue_tracker_qualification import QualifiedSet, qualify_stage_l
from monitor.issue_tracker_manifest import freeze_qualified_manifest
from test_cases.test_issue_tracker_qualification import (
    EMPTY_WHITELIST_SHA, SWITCH, TOKEN_1, TOKEN_2, bound_snapshot, cycle,
)


OPS = (
    b'[{"action":"upsert","activity_key":["eth_cabling","leaf01","swp1","Link Down"],'
    b'"operation_id":"1-cabling"},{"action":"upsert","activity_key":'
    b'["switch","leaf01","fan","fan1"],"operation_id":"2-switch"}]'
)
QUALIFIED = QualifiedSet(
    operations_json=OPS,
    cycle_ids=("c" * 64, "e" * 64),
    source_authority_sha256="a" * 64,
    observations_sha256="d" * 64,
    whitelist_sha256=EMPTY_WHITELIST_SHA,
    template_sha256="b" * 64,
    project_key=hashlib.sha256(b"site-a").hexdigest(),
    scope="prod",
    k=2,
    mode="synthetic-local-fixture",
)
METADATA = {
    "project_id": "site-a", "schema_version": 1,
    "producer_version": "1", "template_contract_version": "1",
    "template_sha256": "b" * 64,
}
EXPECTED = (
    '{"operations":[{"action":"upsert","activity_key":["eth_cabling","leaf01","swp1","Link Down"],'
    '"operation_id":"1-cabling"},{"action":"upsert","activity_key":'
    '["switch","leaf01","fan","fan1"],"operation_id":"2-switch"}],'
    '"producer_version":"1","project_id":"site-a","qualified_source":'
    '{"cycle_ids":["' + "c" * 64 + '","' + "e" * 64 + '"],"k":2,'
    '"mode":"synthetic-local-fixture","observations_sha256":"' + "d" * 64 + '",'
    '"project_key":"' + hashlib.sha256(b"site-a").hexdigest() + '","scope":"prod",'
    '"source_authority_sha256":"' + "a" * 64 + '","whitelist_sha256":"' + EMPTY_WHITELIST_SHA + '"},'
    '"schema_version":1,"template_contract_version":"1","template_sha256":"' + "b" * 64 + '"}\n'
).encode("utf-8")


class IssueTrackerManifestTests(unittest.TestCase):
    def freeze(self, qualified=QUALIFIED, metadata=METADATA):
        return freeze_qualified_manifest(
            qualified, metadata=metadata, expected_template_sha256="b" * 64,
        )

    def test_exact_literal_body_and_digest(self):
        body, identity = self.freeze()
        self.assertEqual(EXPECTED, body)
        self.assertEqual(hashlib.sha256(EXPECTED).hexdigest(), identity)
        self.assertEqual(1, body.count(b"\n"))

    def test_outcomes_and_duplicate_operation_identity_are_not_manifest(self):
        for poisoned in (
            OPS.replace(b'"operation_id":"2-switch"', b'"operation_id":"1-cabling"'),
            OPS.replace(b'"action":"upsert"', b'"outcome":"APPLIED","action":"upsert"', 1),
        ):
            with self.subTest(poisoned=poisoned[:70]), self.assertRaises(ValueError):
                self.freeze(dataclasses.replace(QUALIFIED, operations_json=poisoned))

    def test_template_digest_and_nonfinite_scalar_fail_closed(self):
        with self.assertRaises(ValueError):
            self.freeze(metadata=dict(METADATA, template_sha256="0" * 64))
        with self.assertRaises(ValueError):
            self.freeze(dataclasses.replace(QUALIFIED, operations_json=OPS[:-1] + b',NaN]'))
        with self.assertRaises(ValueError):
            self.freeze(dataclasses.replace(QUALIFIED, project_key="9" * 64))
        with self.assertRaises(ValueError):
            self.freeze(dataclasses.replace(QUALIFIED, whitelist_sha256="f" * 64))

    def test_only_qualified_type_not_local_projection(self):
        local_diff_projection = ({"operation_id": "1-cabling"},)
        with self.assertRaises((TypeError, ValueError)):
            self.freeze(local_diff_projection)

    def test_prod_freezer_rejects_synthetic_qualified_set_before_source_access(self):
        from monitor.issue_tracker_manifest import freeze_prod_stage_l_manifest

        class PoisonStore:
            def __getattribute__(self, name):
                raise AssertionError("synthetic input must not read a source")

        with self.assertRaises(ValueError):
            freeze_prod_stage_l_manifest(
                QUALIFIED, PoisonStore(), http_root=object(), settings=object(),
                whitelist_snapshot=object(), whitelist_path=object(),
                metadata=METADATA, expected_template_sha256="b" * 64,
            )

    def test_runtime_skip_uses_real_source_identity_and_matched_rule(self):
        from monitor.issue_tracker_manifest import _runtime_skip
        from monitor.issue_tracker_stage_l_consumer import StageLQualifiedSkip

        cases = (
            (StageLQualifiedSkip("ib_cabling", "ib-rule", activity_key=(
                "ib_cabling", "leaf01", "leaf02", "Link Down")),
             {"source": "ib_cabling", "activity_key": [
                 "ib_cabling", "leaf01", "leaf02", "Link Down"],
              "matched_rule": "ib-rule"}),
            (StageLQualifiedSkip("eth_cabling", "eth-rule", endpoints=(
                "leaf01", "swp1", "leaf02", "swp2")),
             {"source": "eth_cabling", "endpoints": [
                 "leaf01", "swp1", "leaf02", "swp2"],
              "matched_rule": "eth-rule"}),
            (StageLQualifiedSkip("switch", "switch-rule",
                                 record_id="switch:leaf01"),
             {"source": "switch", "record_id": "switch:leaf01",
              "matched_rule": "switch-rule"}),
        )
        for skip, expected in cases:
            with self.subTest(source=skip.source):
                self.assertEqual(expected, _runtime_skip(skip))
        for poisoned in (
            dataclasses.replace(cases[0][0], endpoints=("a", "b", "c", "d")),
            dataclasses.replace(cases[1][0], endpoints=("", "b", "c", "d")),
            dataclasses.replace(cases[2][0], record_id="leaf01"),
            dataclasses.replace(cases[2][0], matched_rule=""),
            dataclasses.replace(cases[2][0], source="other"),
        ):
            with self.subTest(poisoned=poisoned), self.assertRaises(ValueError):
                _runtime_skip(poisoned)

    def test_runtime_source_time_is_exact_calendar_utc(self):
        from monitor.issue_tracker_manifest import _runtime_recorded_at

        self.assertEqual("2026-09-25T08:00:00Z",
                         _runtime_recorded_at("2026-09-25T08:00:00Z"))
        for poisoned in ("2026-9-25T08:00:00Z", "2026-09-31T08:00:00Z",
                         "2026-09-25T08:00:00+00:00", "2026-09-25T08:00:00Z\n",
                         "", None, True):
            with self.subTest(poisoned=poisoned), self.assertRaises(ValueError):
                _runtime_recorded_at(poisoned)

    def test_nonempty_bound_skip_is_canonical_and_cannot_be_forged(self):
        snapshot = bound_snapshot("leaf01")
        qualified = qualify_stage_l(
            [cycle(7, TOKEN_1, [SWITCH]), cycle(8, TOKEN_2, [SWITCH])],
            k=2, whitelist_rules=list(snapshot.whitelist.rules),
            whitelist_sha256=snapshot.whitelist.sha256,
            whitelist_snapshot=snapshot, template_sha256=snapshot.workbook_sha256,
        )
        body, identity = self.freeze(qualified)
        parsed = json.loads(body)
        self.assertEqual([], parsed["operations"])
        self.assertEqual(
            [{"operation_id": "2-switch", "activity_key": SWITCH["activity_key"],
              "matched_rule": "leaf01"}],
            parsed["qualified_source"]["whitelist_skips"],
        )
        self.assertEqual(hashlib.sha256(body).hexdigest(), identity)
        for poisoned in (
            dataclasses.replace(qualified, whitelist_skips_json=b"[]"),
            dataclasses.replace(qualified, whitelist_skips_json=b"not-json"),
            dataclasses.replace(qualified, whitelist_snapshot=dataclasses.replace(
                snapshot, workbook_sha256="f" * 64)),
        ):
            with self.subTest(poisoned=poisoned.whitelist_skips_json), self.assertRaises(ValueError):
                self.freeze(poisoned)


if __name__ == "__main__":
    unittest.main()
