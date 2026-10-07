"""REQ7 C-25 RED: worker status must expose source-bound per-key progress.

These assertions do not enable the production HTML, CGI, Unix listener, or
Stage O. The workflow uses real worker/emitter role files, not typed fixtures.
"""

import unittest
import json

from monitor.issue_tracker_publish_runtime import inspect_stage_l
from test_cases.test_issue_tracker_stage_l_consumer import ProdStageLFixture


SWITCH_KEY = ["switch", "leaf-a", "fan", "PSU1/FAN1"]


class StageLPerKeyStatusContractTests(ProdStageLFixture):
    def _status(self):
        return inspect_stage_l(
            self.store, http_root=self.root, project=self.project,
            publication=self.publication, template_path=self.template,
        )

    def test_cold_start_panel_status_shows_zero_of_held_k_not_qualified(self):
        status = self._status()
        self.assertEqual(("pending", 2), (status["state"], status["k"]))
        for panel in ("Switch Status", "Eth Link Validation", "IB Link Validation"):
            self.assertEqual("pending 0/2", status["panels"][panel]["progress_text"])
            self.assertEqual([], status["panels"][panel]["per_key"])
        self.assertEqual(0, status["cycle_summary"]["pending"])
        self.assertFalse(status["cycle_summary"]["pending_count_complete"])
        self.assertEqual("disabled_no_send_authority", status["online"])

    def test_archive_sequence_gap_is_distinct_from_cold_start_and_has_unknown_counts(self):
        self.two_cycles(activity=True, derivation=True)
        for path in (self.store.start_path(1), self.store.launch_path(1),
                     self.store.completion_path(1)):
            path.unlink()  # Only this test's private TemporaryDirectory.
        status = self._status()
        self.assertEqual("hold", status["state"])
        self.assertEqual("archive_sequence_gap", status["reason"])
        for panel in status["panels"].values():
            self.assertEqual("archive_sequence_gap", panel["reason"])
            self.assertEqual("pending ?/2 — archive sequence gap", panel["progress_text"])
            self.assertEqual([], panel["per_key"])
        self.assertEqual({"published": None, "skipped": None, "pending": None,
                          "pending_count_complete": False}, status["cycle_summary"])
        self.assertEqual("disabled_no_send_authority", status["online"])

    def test_cycle_reader_keeps_gap_fail_closed_with_distinct_type(self):
        from monitor import issue_tracker_cycle_source as source
        gap = getattr(source, "CycleSequenceGap", None)
        self.assertIsNotNone(gap, "archive gap classification is missing")
        self.two_cycles(activity=True, derivation=True)
        for path in (self.store.start_path(1), self.store.launch_path(1),
                     self.store.completion_path(1)):
            path.unlink()
        with self.assertRaises(gap):
            source.read_completed_cycle_evidence(self.store)

    def test_c6_receipt_without_shared_admission_never_reports_zero(self):
        from monitor.issue_tracker_local_commit import (
            begin_generation, commit, record_intent,
        )
        from monitor.issue_tracker_publish_runtime import StageLHold
        from monitor.issue_tracker_state_owner import tracker_writer

        self._cycle(activity=True, derivation=True)
        manifest = (json.dumps({
            "qualified_source": {"mode": "prod-runtime-protected-v1"},
            "template_sha256": self.snapshot.workbook_sha256,
        }, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with tracker_writer(self.project, self.publication) as token:
            generation = begin_generation(token, manifest)
            record_intent(token, generation, self.template.read_bytes(), kind="xlsx")
            commit(token, generation)
        with self.assertRaises(StageLHold):
            self._status()

    def test_c6_admission_with_wrong_manifest_cycle_is_hold(self):
        from monitor.issue_tracker_admission import record_shared_local_admission
        from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
        from monitor.issue_tracker_local_commit import (
            begin_generation, commit, record_intent,
        )
        from monitor.issue_tracker_publish_runtime import StageLHold
        from monitor.issue_tracker_state_owner import tracker_writer

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
        with self.assertRaises(StageLHold):
            self._status()


class QualifiedSubsetProgressContractTests(unittest.TestCase):
    """Pure status consistency checks, never a qualification authority."""

    def _checker(self):
        from monitor import issue_tracker_publish_runtime as runtime
        checker = getattr(runtime, "_qualified_key_progress_matches", None)
        self.assertIsNotNone(checker, "qualified-subset progress check is missing")
        return checker

    def _panels(self):
        return {
            "Switch Status": {"state": "pending", "per_key": [
                {"activity_key": SWITCH_KEY, "state": "source_window_complete",
                 "observed": 2, "required": 2, "progress_text": "pending 2/2"},
                {"activity_key": ["switch", "leaf-a", "fan", "PSU2/FAN1"],
                 "state": "pending", "observed": 1, "required": 2,
                 "progress_text": "pending 1/2"},
            ]},
            "Eth Link Validation": {"state": "pending", "per_key": []},
            "IB Link Validation": {"state": "pending", "per_key": []},
        }

    def test_pending_other_key_does_not_block_completed_qualified_subset(self):
        checker = self._checker()
        self.assertTrue(checker(
            (("Switch Status", tuple(SWITCH_KEY)),), self._panels(), 2))

    def test_pending_or_absent_candidate_is_never_qualified(self):
        checker = self._checker()
        for key in (("switch", "leaf-a", "fan", "PSU2/FAN1"),
                    ("switch", "leaf-a", "fan", "not-observed")):
            self.assertFalse(checker((("Switch Status", key),), self._panels(), 2))

    def test_ambiguous_duplicate_key_or_held_panel_refuses(self):
        checker = self._checker()
        panels = self._panels()
        panels["Switch Status"]["per_key"].append(
            dict(panels["Switch Status"]["per_key"][0]))
        self.assertFalse(checker(
            (("Switch Status", tuple(SWITCH_KEY)),), panels, 2))
        panels = self._panels()
        panels["IB Link Validation"]["state"] = "hold"
        self.assertFalse(checker(
            (("Switch Status", tuple(SWITCH_KEY)),), panels, 2))

    def test_qualified_subset_summary_keeps_other_key_pending_visible(self):
        from monitor import issue_tracker_publish_runtime as runtime
        renderer = getattr(runtime, "_qualified_panel_status", None)
        self.assertIsNotNone(renderer, "qualified panel renderer is missing")
        panel = renderer(self._panels()["Switch Status"], 2)
        self.assertEqual("qualified subset; pending 1/2", panel["progress_text"])
        self.assertEqual("source complete 2/2", panel["per_key"][0]["progress_text"])
        self.assertEqual("pending 1/2", panel["per_key"][1]["progress_text"])

    def test_latest_inactive_key_is_not_rendered_as_pending_subset(self):
        from monitor import issue_tracker_publish_runtime as runtime
        renderer = getattr(runtime, "_qualified_panel_status", None)
        self.assertIsNotNone(renderer, "qualified panel renderer is missing")
        panel = self._panels()["Switch Status"]
        panel["per_key"][1].update(reason="latest_absent", observed=0,
                                   progress_text="inactive in latest cycle")
        result = renderer(panel, 2)
        self.assertEqual("qualified 2/2", result["progress_text"])
        self.assertEqual("inactive in latest cycle", result["per_key"][1]["progress_text"])


if __name__ == "__main__":
    unittest.main()
