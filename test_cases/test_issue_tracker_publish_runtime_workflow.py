"""Worker completion and Stage L status remain separate from C5/C6 authority."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
from test_cases.test_issue_tracker_switch_runtime import RuntimeWorkerFixture, WORKER


class StageLRuntimeWorkflowTests(RuntimeWorkerFixture, unittest.TestCase):
    def test_replayed_worker_completion_cannot_become_local_applied(self):
        from monitor.issue_tracker_publish_runtime import StageLHold, inspect_stage_l

        self.cycle(activity=True)
        self.cycle(activity=True)
        self.assertEqual(2, len(read_completed_cycle_evidence(self.store)))
        completion = self.store.completion_path(2)
        completion.write_bytes(self.store.completion_path(1).read_bytes())
        with self.assertRaises(StageLHold):
            inspect_stage_l(
                self.store, http_root=self.root, project=self.project,
                publication=self.publication, template_path=self.workbook,
            )
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_root_entrypoint_refuses_unbound_template_before_local_generation(self):
        from monitor.issue_tracker_publish_runtime import (
            StageLHold, commit_qualified_prod_local,
        )

        self.cycle(activity=True)
        self.cycle(activity=True)
        with self.assertRaises(StageLHold):
            commit_qualified_prod_local(
                self.store, http_root=self.root, project=self.project,
                publication=self.publication,
                template_path=self.project / "unbound-template.xlsx",
            )
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_worker_completed_cycle_exposes_hold_but_no_receipt(self):
        self.cycle(activity=True)
        self.cycle(activity=True)
        template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
        template.parent.mkdir(parents=True, exist_ok=True)
        template.write_bytes(self.workbook.read_bytes())
        status_path = self.root / "monitor/status/issue-tracker-stage-l.status.json"
        with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
              mock.patch.object(WORKER, "STATUS_DIR", status_path.parent),
              mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE", status_path)):
            WORKER._publish_stage_l_status_after_completion(self.store)
        status = json.loads(status_path.read_bytes())
        self.assertEqual("hold", status["state"])
        self.assertEqual("disabled_no_send_authority", status["online"])
        self.assertEqual("preview_is_not_qualification",
                         status["panels"]["Switch Status"]["reason"])
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_local_auto_lane_missing_policy_holds_without_generation(self):
        self.cycle(activity=True)
        self.cycle(activity=True)
        status_path = self.root / "monitor/status/issue-tracker-stage-l.status.json"
        prod_store = mock.Mock(
            scope="prod", project_identity=str(self.project),
        )
        with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
              mock.patch.object(WORKER, "STATUS_DIR", status_path.parent),
              mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE", status_path)):
            self.assertIsNone(WORKER._publish_stage_l_local_after_completion(prod_store))
        status = json.loads(status_path.read_bytes())
        self.assertEqual("hold", status["state"])
        self.assertEqual("local_c6_admission_refused", status["reason"])
        self.assertEqual("disabled_no_send_authority", status["online"])
        self.assertEqual((), tuple(self.publication.iterdir()))


if __name__ == "__main__":
    unittest.main()
