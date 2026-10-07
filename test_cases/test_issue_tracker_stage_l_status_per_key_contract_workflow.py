"""REQ7 C-25 RED: genuine worker/emitter cycle drives status, not a claim."""

import unittest
import json
from unittest import mock

from monitor.issue_tracker_publish_runtime import inspect_stage_l
from test_cases.test_collection_cycle_persistence import WORKER
from test_cases.test_issue_tracker_stage_l_consumer import ProdStageLFixture
from test_cases.test_issue_tracker_stage_l_status_per_key_contract import SWITCH_KEY


class StageLPerKeyStatusContractWorkflowTests(ProdStageLFixture):
    def _status(self):
        return inspect_stage_l(
            self.store, http_root=self.root, project=self.project,
            publication=self.publication, template_path=self.template,
        )

    def test_real_p2p_authority_switch_is_unknown_not_cold_start_or_missing_source(self):
        import zipfile
        from test_cases.test_issue_tracker_topology_derivation_workflow import (
            _real_chain, P2P,
        )

        paths, _context = _real_chain(self.root)
        self._cycle(activity=True, derivation=True)
        # Change independently selected input bytes, keeping the literal
        # physical edges the same. Rebuild the real producer provenance;
        # neither completed roles nor the reader's return values are patched.
        with zipfile.ZipFile(paths["topology"], "a") as workbook:
            workbook.writestr("req7-authority-change.txt", b"second selected input\n")
        P2P._write_splitter_profiles(
            paths["lldpq"], {}, paths["topology"], paths["inventory"],
            paths["port_mapping"], expected_hashes=P2P._splitter_source_hashes(
                paths["topology"], paths["inventory"], paths["port_mapping"],
            ),
        )
        self._cycle(activity=True, derivation=True)
        status = self._status()
        panel = status["panels"]["Eth Link Validation"]
        self.assertEqual("hold", panel["state"])
        self.assertEqual("source_authority_changed", panel["reason"])
        self.assertEqual("unknown — source authority changed; confirm input change",
                         panel["progress_text"])
        self.assertEqual([], panel["per_key"])
        self.assertEqual("hold", status["state"])
        self.assertEqual(0, status["cycle_summary"]["published"])
        self.assertFalse(status["cycle_summary"]["pending_count_complete"])
        self.assertEqual("disabled_no_send_authority", status["online"])
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_real_worker_status_preserves_archive_gap_reason_without_fake_count(self):
        self.two_cycles(activity=True, derivation=True)
        for path in (self.store.start_path(1), self.store.launch_path(1),
                     self.store.completion_path(1)):
            path.unlink()  # Only this test's private TemporaryDirectory.
        template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
        template.write_bytes(self.template.read_bytes())
        path = self.root / "monitor/status/issue-tracker-stage-l.status.json"
        with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
              mock.patch.object(WORKER, "STATUS_DIR", path.parent),
              mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE", path)):
            WORKER._publish_stage_l_status_after_completion(self.store)
        status = json.loads(path.read_bytes())
        self.assertEqual("hold", status["state"])
        self.assertEqual("archive_sequence_gap", status["reason"])
        self.assertIsNone(status["cycle_summary"]["published"])
        self.assertEqual("disabled_no_send_authority", status["online"])

    def test_real_worker_emitter_cycle_reports_key_one_of_two_and_ib_unknown(self):
        cycle, _artifacts = self._cycle(activity=True, derivation=True)
        status = self._status()
        self.assertEqual(cycle["cycle_id"], status["latest_cycle_id"])
        self.assertEqual("pending", status["state"])
        entries = status["panels"]["Switch Status"]["per_key"]
        switch = next(item for item in entries if item["activity_key"] == SWITCH_KEY)
        self.assertEqual(("pending", 1, 2, "pending 1/2"), (
            switch["state"], switch["observed"], switch["required"],
            switch["progress_text"],
        ))
        self.assertEqual("hold", status["panels"]["IB Link Validation"]["state"])
        self.assertEqual("ib_report_not_bound_to_completed_cycle",
                         status["panels"]["IB Link Validation"]["reason"])
        self.assertEqual(0, status["cycle_summary"]["published"])
        self.assertGreaterEqual(status["cycle_summary"]["pending"], 1)
        self.assertFalse(status["cycle_summary"]["pending_count_complete"])
        self.assertEqual("disabled_no_send_authority", status["online"])

    def test_same_worker_cycle_with_swapped_archive_cannot_keep_per_key_progress(self):
        _cycle, artifacts = self._cycle(activity=True, derivation=True)
        archive = artifacts["ethernet/prod"]["info"]
        archive.write_bytes(archive.read_bytes() + b"post-completion drift")
        status = self._status()
        self.assertNotEqual("qualified", status["state"])
        self.assertEqual("hold", status["panels"]["Switch Status"]["state"])
        self.assertEqual([], status["panels"]["Switch Status"]["per_key"])
        self.assertEqual("disabled_no_send_authority", status["online"])

    def test_key_inactive_in_latest_cycle_is_not_counted_as_pending_issue(self):
        from test_cases.test_issue_tracker_switch_info_source import _info
        original = self._archive

        def archive(area, prefix, host, body, **kwargs):
            if host == "leaf-a" and kwargs.get("sequence") == 2:
                body = _info(host, fan_state="ok")
            return original(area, prefix, host, body, **kwargs)

        self._archive = archive
        self.two_cycles(activity=True, derivation=True)
        status = self._status()
        entries = status["panels"]["Switch Status"]["per_key"]
        prior = next(item for item in entries if item["activity_key"] == SWITCH_KEY)
        self.assertEqual(("latest_absent", 0), (prior["reason"], prior["observed"]))
        self.assertEqual(0, status["cycle_summary"]["pending"])
        self.assertFalse(status["cycle_summary"]["pending_count_complete"])

    def test_real_qualified_panels_show_completed_not_pending_progress(self):
        from monitor import issue_tracker_publish_runtime as runtime
        from test_cases.test_issue_tracker_stage_l_consumer_workflow import (
            ProdStageLConsumerWorkflowTests,
        )

        original = runtime.inspect_stage_l
        witnessed = []

        def inspect_and_check(*args, **kwargs):
            status = original(*args, **kwargs)
            if status["state"] == "qualified":
                witnessed.append(status)
                for panel in status["panels"].values():
                    self.assertEqual("qualified", panel["state"])
                    self.assertEqual("qualified 1/1", panel["progress_text"])
                    for item in panel["per_key"]:
                        self.assertEqual("source_window_complete", item["state"])
                        self.assertEqual((1, 1),
                                         (item["observed"], item["required"]))
                        self.assertEqual("source complete 1/1",
                                         item["progress_text"])
            return status

        with mock.patch.object(runtime, "inspect_stage_l",
                               side_effect=inspect_and_check):
            ProdStageLConsumerWorkflowTests._exercise_real_protected_three_panel_fixture(
                self, skip_history=False)
        self.assertTrue(witnessed, "real worker/emitter/IB source must qualify")

    def test_current_cycle_c6_receipt_counts_local_unit_not_online_send(self):
        from monitor.issue_tracker_local_workbook_commit import CommittedProdWorkbook
        from test_cases.test_issue_tracker_stage_l_consumer_workflow import (
            ProdStageLConsumerWorkflowTests,
        )

        real_publish = WORKER._publish_stage_l_local_after_completion
        observed = []

        def after_publish(store):
            result = real_publish(store)
            if isinstance(result, CommittedProdWorkbook):
                observed.append(self._status())
            return result

        with mock.patch.object(WORKER, "_publish_stage_l_local_after_completion",
                               side_effect=after_publish):
            ProdStageLConsumerWorkflowTests._exercise_real_protected_three_panel_fixture(
                self, skip_history=False, automatic_first=True)
        self.assertEqual(1, len(observed))
        status = observed[0]
        self.assertEqual("qualified", status["state"])
        self.assertEqual("source_set_qualified_local_receipt", status["reason"])
        self.assertEqual({"published": 1, "skipped": 0, "pending": 0},
                         {key: status["cycle_summary"][key]
                          for key in ("published", "skipped", "pending")})
        self.assertTrue(status["cycle_summary"]["pending_count_complete"])
        self.assertEqual("disabled_no_send_authority", status["online"])

    def test_real_worker_persisted_status_counts_committed_current_cycle(self):
        from monitor.issue_tracker_local_workbook_commit import CommittedProdWorkbook
        from test_cases.test_issue_tracker_stage_l_consumer_workflow import (
            ProdStageLConsumerWorkflowTests,
        )

        path = self.root / "monitor/status/issue-tracker-stage-l.status.json"
        real_publish = WORKER._publish_stage_l_local_after_completion
        persisted = []

        def after_publish(store):
            result = real_publish(store)
            if isinstance(result, CommittedProdWorkbook):
                persisted.append(json.loads(path.read_bytes()))
            return result

        with mock.patch.object(WORKER, "_publish_stage_l_local_after_completion",
                               side_effect=after_publish):
            ProdStageLConsumerWorkflowTests._exercise_real_protected_three_panel_fixture(
                self, skip_history=False, automatic_first=True)
        self.assertEqual(1, len(persisted))
        status = persisted[0]
        self.assertEqual("local_applied", status["state"])
        self.assertEqual(1, status["cycle_summary"]["published"])
        self.assertEqual(0, status["cycle_summary"]["pending"])
        self.assertEqual("disabled_no_send_authority", status["online"])

    def test_prior_cycle_c6_receipt_is_not_current_cycle_published(self):
        from test_cases.test_issue_tracker_stage_l_consumer_workflow import (
            ProdStageLConsumerWorkflowTests,
        )

        ProdStageLConsumerWorkflowTests._exercise_real_protected_three_panel_fixture(
            self, skip_history=False, automatic_first=True,
            manual_second_probe=True)
        status = self._status()
        # The second fixture cycle has no current-cycle IB report, so its
        # source state is HOLD. The earlier C6 receipt must still not count.
        self.assertEqual("hold", status["state"])
        self.assertEqual("prod_source_evidence_incomplete", status["reason"])
        self.assertEqual(0, status["cycle_summary"]["published"])
        self.assertEqual("disabled_no_send_authority", status["online"])

    def test_current_cycle_c6_receipt_rejects_changed_k_identity(self):
        from monitor.issue_tracker_local_workbook_commit import CommittedProdWorkbook
        from monitor.issue_tracker_publish_runtime import StageLHold
        from monitor.issue_tracker_state_owner import set_k, tracker_writer
        from test_cases.test_issue_tracker_stage_l_consumer_workflow import (
            ProdStageLConsumerWorkflowTests,
        )

        real_publish = WORKER._publish_stage_l_local_after_completion
        observed = []
        class IdentityProbeComplete(Exception):
            pass

        def after_publish(store):
            result = real_publish(store)
            if isinstance(result, CommittedProdWorkbook):
                with tracker_writer(self.project, self.publication) as token:
                    set_k(token, new_k=2, actor="operator:fixture",
                          recorded_at="2026-09-26T05:00:00Z",
                          request_id="receipt-k-drift", expected_revision=1)
                with self.assertRaises(StageLHold):
                    self._status()
                observed.append(True)
                # Stop before the shared fixture's later qualified-state
                # assertions: this probe deliberately changed K identity.
                raise IdentityProbeComplete
            return result

        with self.assertRaises(IdentityProbeComplete):
            with mock.patch.object(WORKER, "_publish_stage_l_local_after_completion",
                                   side_effect=after_publish):
                ProdStageLConsumerWorkflowTests._exercise_real_protected_three_panel_fixture(
                    self, skip_history=False, automatic_first=True)
        self.assertEqual([True], observed)


if __name__ == "__main__":
    unittest.main()
