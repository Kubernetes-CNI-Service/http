"""Workflow: after a real worker cycle no old Issue Tracker status exists, is served or is polled.

Codex REQ7 retirement, batch 1 (2026-10-23). Real scripts: monitor/switch-collection-worker.py (its
dedicated cycle coordinator), monitor/switch_collection_gate.py, monitor/collection_v2_emitter.py and the
managed cron.sh collectors, run by the test_collection_cycle_handoff_workflow harness for one completed
prod cycle; then monitor/switch-collection-control.cgi answering from that cycle's status directory, and
monitor/generate-monitor-html.py, whose control script must poll only views the CGI serves.

Before the retirement the worker ran three Issue Tracker lanes after every completion (Stage L status,
Stage L local C6, online dispatch) and wrote issue-tracker-stage-l.status.json and
issue-tracker-online.status.json, which the CGI served to the page. The direct counterpart is
test_monitor_legacy_tracker_retirement.
"""

from __future__ import annotations

import tempfile
import unittest

import test_cases.test_collection_cycle_handoff_workflow as handoff
from test_cases.module_loader import load_script
from test_cases.test_monitor_legacy_tracker_retirement import (
    CGI_PATH, PAGE_PATH, RETIRED_VIEWS, get_view, page_html, polled_views,
)


class LegacyTrackerRetirementWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cgi = load_script("legacy_tracker_retirement_workflow_cgi", CGI_PATH)
        cls.page = load_script("legacy_tracker_retirement_workflow_page", PAGE_PATH)

    def test_a_completed_prod_cycle_leaves_no_tracker_status_and_the_page_polls_only_served_views(self):
        harness = handoff.CollectionCycleHandoffWorkflowTests(
            "test_dedicated_coordinator_persists_launch_and_completion_before_return")
        with tempfile.TemporaryDirectory() as directory:
            root = harness.make_layout(directory)
            completed, payload, _traces = harness.run_workflow(root, "prod", action="persisted")
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertTrue(payload and payload["returned"], completed.stderr)
            records = payload["persisted"]["records"]
            self.assertEqual("cycle_completed",
                             records["00000000000000000001.completion.json"]["outcome"],
                             "the worker completed and persisted the cycle")

            status = root / "monitor/status"
            leftovers = sorted(str(path.relative_to(status)) for path in status.rglob("*")
                               if "issue-tracker" in path.name or "issue_tracker" in path.name)
            self.assertEqual([], leftovers, "no Issue Tracker lane wrote a status file after completion")
            self.assertNotIn("Issue Tracker", completed.stderr, "no Issue Tracker lane ran after completion")

            for view in RETIRED_VIEWS:
                with self.subTest(view=view):
                    respond = get_view(self.cgi, status, f"view={view}")
                    respond.assert_called_once_with({"error": "invalid status view"}, "400 Bad Request")

            views = polled_views(page_html(self.page))
            self.assertIn("yaml_backup", views)
            for view in sorted(views):
                with self.subTest(polled=view):
                    respond = get_view(self.cgi, status, f"view={view}")
                    respond.assert_called_once()
                    self.assertEqual(1, len(respond.call_args[0]), f"the page polls view={view}; the CGI must serve it")


if __name__ == "__main__":
    unittest.main()
