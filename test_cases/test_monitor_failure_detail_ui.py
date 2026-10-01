#!/usr/bin/env python3
"""Direct contracts for bounded switch collection failure presentation."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "monitor/generate-monitor-html.py"


class MonitorFailureDetailUiTests(unittest.TestCase):
    def test_large_failure_summary_is_bounded_but_exact_count_remains_visible(self):
        source = SOURCE.read_text(encoding="utf-8")
        helper = source.split("function failedDeviceSummary(payload) {{", 1)[1].split(
            "\n}}\n\nfunction", 1,
        )[0]
        self.assertIn("const FAILURE_SUMMARY_LIMIT = 3;", source)
        self.assertIn("const FAILURE_SUMMARY_NAME_LIMIT = 40;", source)
        self.assertIn("names.slice(0, FAILURE_SUMMARY_LIMIT)", helper)
        self.assertIn("name.slice(0, FAILURE_SUMMARY_NAME_LIMIT - 1)", helper)
        self.assertIn("count", helper)
        self.assertIn("remaining", helper)
        self.assertNotIn("names.join('、')", helper)

    def test_complete_failure_evidence_uses_text_nodes_in_a_bounded_dialog(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('id="switch-failure-detail-dialog"', source)
        self.assertIn('id="switch-failure-detail-list"', source)
        self.assertIn('id="switch-failure-detail-button"', source)
        self.assertIn("failure?.hostname", source)
        self.assertIn("failure?.operation", source)
        self.assertIn("failure?.reason", source)
        self.assertIn("row.textContent =", source)
        self.assertNotIn("row.innerHTML", source)
        self.assertIn("if (failures.length === 0 && dialog?.open)", source)
        self.assertIn("dialog.close();", source)
        self.assertNotIn("成功设备的结果仍然保留", source)
        self.assertIn(".collection-failure-list", source)
        self.assertRegex(
            source,
            r"\.collection-failure-list\s*\{\{[^}}]*max-height:[^}}]*overflow-y:\s*auto",
        )

    def test_dialog_close_restores_focus_to_the_details_button(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("switchFailureDetailReturnFocus", source)
        self.assertIn("dialog.showModal();", source)
        self.assertIn("switchFailureDetailReturnFocus.focus();", source)


if __name__ == "__main__":
    unittest.main()
