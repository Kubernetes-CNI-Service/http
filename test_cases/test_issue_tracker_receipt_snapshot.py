"""C-25 local published count is a durable, cycle-bound C6 fact."""

import json
import unittest
import importlib.util
from dataclasses import replace

from monitor.issue_tracker_state_owner import tracker_writer
from test_cases.test_issue_tracker_stage_l_consumer import ProdStageLFixture


class CurrentCycleReceiptSnapshotDirectTests(ProdStageLFixture):
    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("monitor.issue_tracker_receipt_snapshot"),
            "cycle-bound local receipt snapshot is not implemented")
        super().setUp()

    def _snapshot(self):
        from monitor.issue_tracker_receipt_snapshot import (
            LocalReceiptSnapshotHold, read_current_cycle_local_receipts,
        )
        with tracker_writer(self.project, self.publication) as token:
            return read_current_cycle_local_receipts(
                token, self.store,
                expected_template_sha256=self.snapshot.workbook_sha256,
                settings=self.settings,
                whitelist_sha256=self.snapshot.whitelist.sha256,
            )

    def test_proved_empty_journal_has_zero_current_cycle_units(self):
        self._cycle(activity=True, derivation=True)
        snapshot = self._snapshot()
        self.assertEqual(0, snapshot.published)
        self.assertEqual((), snapshot.generation_ids)

    def test_c6_receipt_without_shared_admission_is_hold_not_zero(self):
        from monitor.issue_tracker_local_commit import (
            begin_generation, commit, record_intent,
        )
        from monitor.issue_tracker_receipt_snapshot import LocalReceiptSnapshotHold
        self._cycle(activity=True, derivation=True)
        manifest = (
            '{"qualified_source":{"mode":"prod-runtime-protected-v1"},'
            '"template_sha256":"' + self.snapshot.workbook_sha256 + '"}\n'
        ).encode()
        with tracker_writer(self.project, self.publication) as token:
            generation = begin_generation(token, manifest)
            record_intent(token, generation, self.template.read_bytes(), kind="xlsx")
            commit(token, generation)
        with self.assertRaises(LocalReceiptSnapshotHold):
            self._snapshot()

    def test_admitted_receipt_with_wrong_manifest_cycle_is_hold(self):
        from monitor.issue_tracker_admission import record_shared_local_admission
        from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
        from monitor.issue_tracker_local_commit import (
            begin_generation, commit, record_intent,
        )
        from monitor.issue_tracker_receipt_snapshot import LocalReceiptSnapshotHold

        self.two_cycles(activity=True, derivation=True)
        cycles = read_completed_cycle_evidence(self.store)
        cycle = cycles[-1]
        source = {
            "cycle_ids": [cycles[0].cycle_id, "different-cycle"],
            "completion_sha256": [item.completion_sha256 for item in cycles],
            "k": self.settings.k, "mode": "prod-runtime-protected-v1",
            "project_key": self.store.project_key, "scope": "prod",
            "source_authority_sha256": "a" * 64,
            "observations_sha256": "b" * 64,
            "whitelist_sha256": self.snapshot.whitelist.sha256,
            "k_event_sha256": self.settings.event_sha256,
            "recorded_at_utc": "2026-09-25T00:01:00Z",
            "whitelist_skips": [],
        }
        manifest = (json.dumps({
            "qualified_source": source,
            "template_sha256": self.snapshot.workbook_sha256,
        }, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with tracker_writer(self.project, self.publication) as token:
            generation = begin_generation(token, manifest)
            record_intent(token, generation, self.template.read_bytes(), kind="xlsx")
            receipt = commit(token, generation)
            record_shared_local_admission(token, receipt.generation_id,
                receipt.published_sha256, {
                    "sequence": 1, "schema_version": 1, "lane": "manual",
                    "project_key": self.store.project_key, "scope": "prod",
                    "cycle_id": cycle.cycle_id,
                    "cycle_completion_sha256": cycle.completion_sha256,
                    "policy_sha256": "c" * 64, "publish_every_cycles": 1,
                    "boot_id": "fixture", "monotonic_ns": 1,
                })
        with self.assertRaisesRegex(
            LocalReceiptSnapshotHold, "manifest differs from admitted cycle window",
        ):
            self._snapshot()

    def test_historical_receipt_cannot_bridge_a_nonqualifying_cycle(self):
        from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
        from monitor.issue_tracker_receipt_snapshot import (
            LocalReceiptSnapshotHold, _validate_source,
        )
        self.two_cycles(activity=True, derivation=True)
        first, second = read_completed_cycle_evidence(self.store)
        interrupted = replace(second, qualifying=False)
        third = replace(second, sequence=3, cycle_id="d" * 64,
                        completion_sha256="e" * 64)
        fourth = replace(second, sequence=4, cycle_id="f" * 64,
                         completion_sha256="a" * 64)
        cycles = (first, interrupted, third, fourth)
        source = {
            "cycle_ids": [first.cycle_id, third.cycle_id],
            "completion_sha256": [first.completion_sha256, third.completion_sha256],
            "k": 2, "mode": "prod-runtime-protected-v1",
            "project_key": self.store.project_key, "scope": "prod",
            "source_authority_sha256": "a" * 64,
            "observations_sha256": "b" * 64,
            "whitelist_sha256": self.snapshot.whitelist.sha256,
            "k_event_sha256": self.settings.event_sha256,
            "recorded_at_utc": "2026-09-25T00:01:00Z", "whitelist_skips": [],
        }
        event = {"project_key": self.store.project_key, "scope": "prod",
                 "cycle_id": third.cycle_id,
                 "cycle_completion_sha256": third.completion_sha256}
        with self.assertRaisesRegex(LocalReceiptSnapshotHold, "cycle window"):
            _validate_source(
                source, event, cycles, {self.settings.event_sha256: 2},
                template_sha256=self.snapshot.workbook_sha256,
                expected_template_sha256=self.snapshot.workbook_sha256,
                settings=self.settings, whitelist_sha256=self.snapshot.whitelist.sha256,
                qualified_source=None,
            )


if __name__ == "__main__":
    unittest.main()
