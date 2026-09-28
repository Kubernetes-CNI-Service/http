"""REQ7 manual controls are local-only and never enabled by production HTML."""

import ast
import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
for import_root in (ROOT, ROOT / "tools", ROOT / "monitor"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))
SPEC = importlib.util.spec_from_file_location(
    "req7_manual_ui_html", ROOT / "monitor/generate-monitor-html.py"
)
HTML = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HTML
SPEC.loader.exec_module(HTML)


def page(*, local_ui=False):
    stats = {"changed": 0, "new": 0, "removed": 0, "same": 0}
    return HTML.build_html(
        {}, "", 0, "", "", 0, {}, "",
        "", "", stats, None, 0,
        "", "", stats, None, 0,
        "", "", 0, "",
        "", "", stats, None, 0,
        {}, {}, {}, {},
        {"available": False, "counts": {}, "environment_updates": {},
         "devices": []},
        issue_tracker_local_ui=local_ui,
    )


class ManualUiTests(unittest.TestCase):
    def test_production_entrypoint_cannot_opt_in_or_expose_a_cli_flag(self):
        tree = ast.parse((ROOT / "monitor/generate-monitor-html.py").read_text(
            encoding="utf-8"))
        generator = next(node for node in tree.body if isinstance(
            node, ast.FunctionDef) and node.name == "_generate_monitor_html")
        calls = [node for node in ast.walk(generator) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name)
                 and node.func.id == "build_html"]
        self.assertEqual(1, len(calls))
        self.assertNotIn("issue_tracker_local_ui",
                         [keyword.arg for keyword in calls[0].keywords])
        parser = next(node for node in tree.body if isinstance(
            node, ast.FunctionDef) and node.name == "parse_args")
        self.assertNotIn("issue_tracker_local_ui", ast.unparse(parser))

    def test_default_page_contains_no_manual_ui_or_manual_route(self):
        rendered = page()
        self.assertNotIn('data-issue-tracker-panel=', rendered)
        self.assertNotIn('id="issue-tracker-manual-dialog"', rendered)
        self.assertNotIn('/monitor/control/issue-tracker', rendered)
        self.assertNotIn('issueTrackerManualPreview(', rendered)

    def test_only_three_exact_panels_have_local_controls(self):
        rendered = page(local_ui=True)
        for panel_id, panel in (
            ("eth", "Switch Status"),
            ("etop", "Eth Link Validation"),
            ("itop", "IB Link Validation"),
        ):
            self.assertIn(f'data-issue-tracker-panel="{panel}"', rendered)
            self.assertIn(f'id="issue-tracker-{panel_id}-preview"', rendered)
            self.assertIn(f'id="issue-tracker-{panel_id}-k"', rendered)
        self.assertEqual(3, rendered.count('>发布到 Issue Tracker</button>'))
        self.assertEqual(3, rendered.count('合格窗口 K'))
        self.assertEqual(1, rendered.count('id="issue-tracker-manual-dialog"'))
        self.assertIn('id="issue-tracker-confirm"', rendered)
        self.assertIn('id="issue-tracker-cancel"', rendered)
        self.assertIn('Stage O 在线发布未启用', rendered)

    def test_incomplete_preview_and_wrong_panel_cannot_enable_confirmation(self):
        rendered = page(local_ui=True)
        self.assertIn('function validIssueTrackerPreview(payload, panel)', rendered)
        self.assertIn('payload.panel !== panel', rendered)
        self.assertIn('payload.online !== "disabled_no_send_authority"', rendered)
        self.assertIn('Array.isArray(payload.source_files)', rendered)
        self.assertIn('Array.isArray(payload.row_digests)', rendered)
        self.assertIn('Number.isInteger(payload.new_count)', rendered)
        self.assertIn('Number.isInteger(payload.update_count)', rendered)
        self.assertIn('Number.isInteger(payload.skip_count)', rendered)
        self.assertIn('if (!validIssueTrackerPreview(payload, panel))', rendered)
        self.assertIn('confirmation: "publish_local"', rendered)
        self.assertIn('pendingIssueTrackerPreview = null;', rendered)
        self.assertIn('textContent =', rendered)
        self.assertNotIn('innerHTML = payload', rendered)


if __name__ == "__main__":
    unittest.main()
