"""REQ7 runtime Stage L must not turn a source preview into a local receipt."""

from __future__ import annotations

import json
import unittest
from unittest import mock
from types import SimpleNamespace

from test_cases.test_issue_tracker_switch_runtime import RuntimeWorkerFixture


class StageLRuntimeDirectTests(RuntimeWorkerFixture, unittest.TestCase):
    def test_manual_entry_refuses_prior_auto_admission_before_qualification(self):
        from monitor.issue_tracker_publish_runtime import (
            StageLHold, commit_qualified_prod_local,
        )

        template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
        template.parent.mkdir(parents=True, exist_ok=True)
        template.write_bytes(self.workbook.read_bytes())
        (self.project / ".tracker/admissions").mkdir(mode=0o700)
        with (mock.patch.object(self.store, "scope", "prod"),
              mock.patch("monitor.issue_tracker_publish_runtime.read_auto_local_admission",
                         return_value={"generation_id": "prior"}) as prior,
              mock.patch("monitor.issue_tracker_stage_l_consumer.qualify_prod_stage_l")
              as qualify):
            with self.assertRaisesRegex(StageLHold, "shared admission"):
                commit_qualified_prod_local(
                    self.store, http_root=self.root, project=self.project,
                    publication=self.publication, template_path=template,
                )
        prior.assert_called_once()
        qualify.assert_not_called()

    def test_worker_surfaces_subfloor_admission_as_collector_anomaly(self):
        from monitor.issue_tracker_publish_runtime import AutoLocalCollectorAnomaly
        from test_cases.test_collection_cycle_persistence import WORKER

        source = {"state": "qualified", "completed_cycles": 2}
        store = SimpleNamespace(scope="prod", project_identity=self.project)
        with (mock.patch("monitor.issue_tracker_publish_runtime.local_publish_interval",
                         return_value=(2, "a" * 64)),
              mock.patch("monitor.issue_tracker_publish_runtime.inspect_stage_l",
                         return_value=source),
              mock.patch("monitor.issue_tracker_publish_runtime.commit_qualified_prod_local",
                         side_effect=AutoLocalCollectorAnomaly(
                             "collector_interval_below_minimum")),
              mock.patch.object(WORKER, "_current_boot_identity",
                                return_value="fixture-boot"),
              mock.patch.object(WORKER, "_write_status_file") as status):
            self.assertIsNone(WORKER._publish_stage_l_local_after_completion(store))
        self.assertEqual("hold", status.call_args.args[2])
        self.assertEqual("collector_interval_below_minimum",
                         status.call_args.kwargs["reason"])

    def test_worker_names_terminal_receipt_without_admission(self):
        from monitor.issue_tracker_publish_runtime import TerminalC6AdmissionHold
        from test_cases.test_collection_cycle_persistence import WORKER

        source = {"state": "qualified", "completed_cycles": 2}
        store = SimpleNamespace(scope="prod", project_identity=self.project)
        with (mock.patch("monitor.issue_tracker_publish_runtime.local_publish_interval",
                         return_value=(1, "a" * 64)),
              mock.patch("monitor.issue_tracker_publish_runtime.inspect_stage_l",
                         return_value=source),
              mock.patch("monitor.issue_tracker_publish_runtime.commit_qualified_prod_local",
                         side_effect=TerminalC6AdmissionHold(
                             "C6 RECEIPT has no admission evidence")),
              mock.patch.object(WORKER, "_current_boot_identity",
                                return_value="fixture-boot"),
              mock.patch.object(WORKER, "_write_status_file") as status):
            self.assertIsNone(WORKER._publish_stage_l_local_after_completion(store))
        self.assertEqual("hold", status.call_args.args[2])
        self.assertEqual("local_c6_terminal_admission_state",
                         status.call_args.kwargs["reason"])
        self.assertEqual("C6 RECEIPT has no admission evidence",
                         status.call_args.kwargs["terminal_detail"])
        self.assertEqual("disabled_no_send_authority",
                         status.call_args.kwargs["online"])

    def test_first_admission_clock_is_taken_after_c6_receipt(self):
        from monitor.issue_tracker_admission import (
            AdmissionHold, read_shared_local_admission,
            record_shared_local_admission,
        )
        from monitor.issue_tracker_local_commit import (
            begin_generation, commit, record_intent,
        )
        from monitor.issue_tracker_state_owner import tracker_writer

        prepared = {
            "schema_version": 1, "lane": "automatic",
            "project_key": self.store.project_key,
            "scope": "prod", "cycle_id": "completed-cycle-1",
            "cycle_completion_sha256": "b" * 64,
            "policy_sha256": "c" * 64, "publish_every_cycles": 1,
            "boot_id": "fixture-boot", "monotonic_ns": 10,
            "sequence": 1,
        }
        with tracker_writer(self.project, self.publication) as token:
            generation = begin_generation(token, b'{"operations":[],"schema_version":1}\n')
            record_intent(token, generation, self.workbook.read_bytes(), kind="xlsx")
            receipt = commit(token, generation)
            with self.assertRaisesRegex(AdmissionHold,
                                        "C6 RECEIPT has no admission evidence"):
                read_shared_local_admission(
                    token, self.store, self.workbook.read_bytes(),
                )
            self.assertFalse((self.project / ".tracker/admissions").exists())
            with self.assertRaisesRegex(AdmissionHold, "differs from C6 RECEIPT"):
                record_shared_local_admission(
                    token, receipt.generation_id, "a" * 64, prepared,
                )
            self.assertFalse((self.project / ".tracker/admissions").exists())
            with mock.patch("monitor.issue_tracker_admission.time.monotonic_ns",
                            return_value=9):
                with self.assertRaises(AdmissionHold):
                    record_shared_local_admission(
                        token, receipt.generation_id,
                        receipt.published_sha256, prepared,
                    )
            self.assertFalse((self.project / ".tracker/admissions").exists())
            with mock.patch("monitor.issue_tracker_admission.time.monotonic_ns",
                            return_value=1234):
                record_shared_local_admission(
                    token, receipt.generation_id,
                    receipt.published_sha256, prepared,
                )
        record = json.loads((self.project / ".tracker/admissions/"
                             "admission-00000000000000000001.json").read_bytes())
        self.assertEqual(1234, record["monotonic_ns"])

    def test_worker_first_backlog_uses_relative_count_not_total_modulo(self):
        from monitor.issue_tracker_publish_runtime import StageLHold
        from test_cases.test_collection_cycle_persistence import WORKER

        source = {"state": "qualified", "completed_cycles": 3}
        store = SimpleNamespace(scope="prod", project_identity=self.project)
        with (mock.patch("monitor.issue_tracker_publish_runtime.local_publish_interval",
                         return_value=(2, "a" * 64)),
              mock.patch("monitor.issue_tracker_publish_runtime.inspect_stage_l",
                         return_value=source),
              mock.patch("monitor.issue_tracker_publish_runtime.commit_qualified_prod_local",
                         side_effect=StageLHold("admission reached")) as commit,
              mock.patch.object(WORKER, "_current_boot_identity",
                                return_value="fixture-boot"),
              mock.patch.object(WORKER, "_write_status_file")):
            self.assertIsNone(WORKER._publish_stage_l_local_after_completion(store))
        commit.assert_called_once()

    def test_auto_admission_reader_refuses_unexplained_directory(self):
        from monitor.issue_tracker_publish_runtime import (
            StageLHold, read_auto_local_admission,
        )
        from monitor.issue_tracker_state_owner import tracker_writer

        with tracker_writer(self.project, self.publication) as token:
            self.assertIsNone(read_auto_local_admission(
                token, self.store, self.whitelist_snapshot.workbook_sha256,
            ))
        (self.project / ".tracker/admissions").mkdir(mode=0o700)
        with tracker_writer(self.project, self.publication) as token:
            with self.assertRaises(StageLHold):
                read_auto_local_admission(
                    token, self.store, self.whitelist_snapshot.workbook_sha256,
                )

    def test_automatic_cadence_counts_since_last_admission_and_shared_floor(self):
        from monitor.issue_tracker_publish_runtime import (
            StageLHold, assess_auto_local_due,
        )

        ids = ("cycle-1", "cycle-2", "cycle-3", "cycle-4")
        self.assertFalse(assess_auto_local_due(
            ids, interval=2, last_admitted_cycle_id="cycle-3",
            elapsed_seconds=600, minimum_seconds=600,
        ))
        # Enough distinct completed cycles in less than the collector's
        # admitted-publication floor are an anomaly, not an ordinary wait.
        with self.assertRaisesRegex(StageLHold, "collector.*below.*minimum"):
            assess_auto_local_due(
                (*ids, "cycle-5"), interval=2,
                last_admitted_cycle_id="cycle-3",
                elapsed_seconds=599, minimum_seconds=600,
            )
        self.assertTrue(assess_auto_local_due(
            (*ids, "cycle-5"), interval=2,
            last_admitted_cycle_id="cycle-3",
            elapsed_seconds=600, minimum_seconds=600,
        ))
        with self.assertRaises(StageLHold):
            assess_auto_local_due(
                ids, interval=2, last_admitted_cycle_id="unknown",
                elapsed_seconds=600, minimum_seconds=600,
            )
        for elapsed in (True, float("inf"), float("nan"), -1, 10 ** 1000):
            with self.subTest(elapsed=elapsed), self.assertRaises(StageLHold):
                assess_auto_local_due(
                    ids, interval=1, last_admitted_cycle_id="cycle-3",
                    elapsed_seconds=elapsed, minimum_seconds=600,
                )

    def test_local_interval_defaults_to_one_and_rejects_unsafe_policy(self):
        from monitor.issue_tracker_publish_runtime import StageLHold, local_publish_interval

        global_path = self.project / "01-global.yaml"
        body = ("schema_version: 2\ncommon:\n  mgmt:\n"
                "    issue-tracker:\n      status: disabled\n")
        global_path.write_text(body, encoding="utf-8")
        self.assertEqual(1, local_publish_interval(self.project)[0])
        global_path.write_text(body + "      status: enabled\n", encoding="utf-8")
        with self.assertRaises(StageLHold):
            local_publish_interval(self.project)
        global_path.unlink()
        target = self.project / "other-global.yaml"
        target.write_text(body, encoding="utf-8")
        global_path.symlink_to(target)
        with self.assertRaises(StageLHold):
            local_publish_interval(self.project)

    def test_air_preview_is_visible_hold_without_local_receipt(self):
        from monitor.issue_tracker_publish_runtime import inspect_stage_l

        first = self.cycle(activity=True)
        second = self.cycle(activity=True)
        before = tuple(self.publication.iterdir())
        status = inspect_stage_l(
            self.store, http_root=self.root, project=self.project,
            publication=self.publication, template_path=self.workbook,
        )
        self.assertEqual("hold", status["state"])
        self.assertEqual([first["cycle_id"], second["cycle_id"]],
                         status["window_cycle_ids"])
        self.assertEqual("preview_is_not_qualification",
                         status["panels"]["Switch Status"]["reason"])
        self.assertEqual("disabled_no_send_authority", status["online"])
        self.assertEqual(before, tuple(self.publication.iterdir()))

    def test_cold_window_is_pending_not_applied(self):
        from monitor.issue_tracker_publish_runtime import inspect_stage_l

        self.cycle()
        status = inspect_stage_l(
            self.store, http_root=self.root, project=self.project,
            publication=self.publication, template_path=self.workbook,
        )
        self.assertEqual("pending", status["state"])
        self.assertEqual(1, status["completed_cycles"])
        self.assertEqual(2, status["k"])
        self.assertTrue(all(panel["state"] != "applied"
                            for panel in status["panels"].values()))


if __name__ == "__main__":
    unittest.main()
