"""REQ7 manual preview cannot mint authority from the real Stage L HOLD path."""

import unittest
from types import SimpleNamespace
from unittest import mock

from monitor.issue_tracker_manual_preview import ManualPreviewBroker, ManualPreviewHold
from monitor.issue_tracker_publish_runtime import StageLHold, commit_qualified_prod_local, inspect_stage_l
from test_cases.test_issue_tracker_switch_runtime import RuntimeWorkerFixture


class ManualPreviewWorkflowTests(RuntimeWorkerFixture, unittest.TestCase):
    def test_real_completed_cycles_and_template_still_hold_without_three_sources(self):
        self.cycle(activity=True)
        self.cycle(activity=True)
        broker = ManualPreviewBroker(
            lambda: inspect_stage_l(
                self.store, http_root=self.root, project=self.project,
                publication=self.publication, template_path=self.workbook,
            ),
            lambda *_: self.fail("HOLD must never call C6"),
        )
        with self.assertRaises(ManualPreviewHold):
            broker.preview("nvis", "Switch Status")
        self.assertEqual(0, broker.pending_count)
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_c6_writer_requalifies_preview_identity_under_publication_lock(self):
        template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
        template.parent.mkdir(parents=True, exist_ok=True)
        template.write_bytes(self.workbook.read_bytes())
        qualified = SimpleNamespace(
            project_key=self.store.project_key, scope="prod", k=2,
            cycle_ids=("cycle-a", "cycle-b"),
            whitelist_sha256="a" * 64,
            template_sha256=self.whitelist_snapshot.workbook_sha256,
            source_authority_sha256="c" * 64,
            observations_sha256="d" * 64,
        )
        expected = {
            "project_key": self.store.project_key, "scope": "prod",
            "k": 2, "k_revision": self.settings.revision,
            "latest_cycle_id": "cycle-b",
            "window_cycle_ids": ("cycle-a", "cycle-b"),
            "whitelist_sha256": "a" * 64,
            "template_sha256": self.whitelist_snapshot.workbook_sha256,
            "source_authority_sha256": "e" * 64,
            "observations_sha256": "d" * 64,
        }
        with (mock.patch.object(self.store, "scope", "prod"),
              mock.patch("monitor.issue_tracker_stage_l_consumer.qualify_prod_stage_l",
                         return_value=qualified),
              mock.patch("monitor.issue_tracker_local_workbook_commit.commit_prod_stage_l_workbook")
              as commit):
            with self.assertRaises(StageLHold):
                commit_qualified_prod_local(
                    self.store, http_root=self.root, project=self.project,
                    publication=self.publication, template_path=template,
                    expected_manual_preview=expected,
                    manual_admission=("f" * 64, 1, "fixture-boot", 1000),
                )
        commit.assert_not_called()
        self.assertEqual((), tuple(self.publication.iterdir()))
        expected["source_authority_sha256"] = "c" * 64
        marker = object()
        with (mock.patch.object(self.store, "scope", "prod"),
              mock.patch("monitor.issue_tracker_stage_l_consumer.qualify_prod_stage_l",
                         return_value=qualified),
              mock.patch("monitor.issue_tracker_local_workbook_commit.commit_prod_stage_l_workbook",
                         return_value=marker) as commit):
            result = commit_qualified_prod_local(
                self.store, http_root=self.root, project=self.project,
                publication=self.publication, template_path=template,
                expected_manual_preview=expected,
                manual_admission=("f" * 64, 1, "fixture-boot", 1000),
            )
        self.assertIs(marker, result)
        commit.assert_called_once()


if __name__ == "__main__":
    unittest.main()
