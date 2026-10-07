"""Real worker/emitter -> protected Stage L -> C6 local receipt snapshot."""

import unittest
import importlib.util
from unittest import mock

from monitor.issue_tracker_state_owner import current_k, tracker_writer
from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
from test_cases.test_collection_cycle_persistence import WORKER
from test_cases.test_issue_tracker_stage_l_consumer import ProdStageLFixture
import test_cases.test_issue_tracker_stage_l_consumer_workflow as source_workflow


class CurrentCycleReceiptSnapshotWorkflowTests(ProdStageLFixture):
    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("monitor.issue_tracker_receipt_snapshot"),
            "cycle-bound local receipt snapshot is not implemented")
        super().setUp()

    _exercise_real_protected_three_panel_fixture = (
        source_workflow.ProdStageLConsumerWorkflowTests
        ._exercise_real_protected_three_panel_fixture
    )

    def test_real_worker_emitter_c6_receipt_is_current_cycle_only(self):
        from monitor.issue_tracker_local_workbook_commit import CommittedProdWorkbook
        from monitor.issue_tracker_receipt_snapshot import read_current_cycle_local_receipts
        from monitor.issue_tracker_stage_l_consumer import qualify_prod_stage_l

        real_publish = WORKER._publish_stage_l_local_after_completion
        observed = []

        def after_publish(store):
            result = real_publish(store)
            if isinstance(result, CommittedProdWorkbook):
                template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
                whitelist = read_whitelist_workbook(template)
                with tracker_writer(self.project, self.publication) as token:
                    settings = current_k(token)
                    qualified = qualify_prod_stage_l(
                        store, http_root=self.root, settings=settings,
                        whitelist_snapshot=whitelist, whitelist_path=template,
                        writer_token=token,
                    )
                    snap = read_current_cycle_local_receipts(
                        token, store,
                        expected_template_sha256=whitelist.workbook_sha256,
                        settings=settings,
                        whitelist_sha256=whitelist.whitelist.sha256,
                        qualified_source=qualified,
                    )
                observed.append((snap.published, snap.generation_ids))
            return result

        with mock.patch.object(WORKER, "_publish_stage_l_local_after_completion",
                               side_effect=after_publish):
            self._exercise_real_protected_three_panel_fixture(
                skip_history=False, automatic_first=True,
            )
        self.assertEqual(1, len(observed))
        self.assertEqual(1, observed[0][0])
        self.assertEqual(1, len(observed[0][1]))

    def test_prior_cycle_receipt_is_not_current_cycle_publication(self):
        from monitor.issue_tracker_receipt_snapshot import read_current_cycle_local_receipts

        real_cycle = self._cycle
        after_second_cycle = []

        def observed_cycle(*args, **kwargs):
            result = real_cycle(*args, **kwargs)
            if (self.project / ".tracker/admissions").exists():
                with tracker_writer(self.project, self.publication) as token:
                    snap = read_current_cycle_local_receipts(
                        token, self.store,
                        expected_template_sha256=self.snapshot.workbook_sha256,
                        settings=current_k(token),
                        whitelist_sha256=self.snapshot.whitelist.sha256,
                    )
                after_second_cycle.append((result[0]["cycle_id"], snap))
            return result

        self._cycle = observed_cycle
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, automatic_first=True,
            manual_second_probe=True,
        )
        self.assertEqual(1, len(after_second_cycle))
        cycle_id, snapshot = after_second_cycle[0]
        self.assertEqual(cycle_id, snapshot.cycle_id)
        self.assertEqual(0, snapshot.published)
        self.assertEqual((), snapshot.generation_ids)


if __name__ == "__main__":
    unittest.main()

