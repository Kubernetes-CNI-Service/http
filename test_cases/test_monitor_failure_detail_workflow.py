#!/usr/bin/env python3
"""Generated-page workflow contract for very large collection failures."""

from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "monitor/generate-monitor-html.py"


def load_module():
    monitor_dir = str(SCRIPT.parent)
    if monitor_dir not in sys.path:
        sys.path.insert(0, monitor_dir)
    loader = SourceFileLoader("monitor_failure_detail_html", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class MonitorFailureDetailWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.monitor = load_module()

    def test_generated_page_keeps_large_failure_details_out_of_toolbar_flow(self):
        stats = {"changed": 0, "new": 0, "removed": 0, "same": 0}
        html = self.monitor.build_html(
            {}, "", 0, "", "", 0, {}, "",
            "", "", stats, None, 0,
            "", "", stats, None, 0,
            "", "", 0, "",
            "", "", stats, None, 0,
            {}, {}, {}, {},
            {
                "available": False, "counts": {},
                "environment_updates": {}, "devices": [],
            },
        )
        toolbar_start = html.index('<div id="eth-toolbar">')
        detail_dialog = html.index('<dialog id="switch-failure-detail-dialog"')
        yaml_dialog = html.index('<dialog id="yaml-backup-dialog"', toolbar_start)
        card_grid = html.index('<div id="card-grid">')
        self.assertIn("</div>", html[detail_dialog - 40:detail_dialog])
        self.assertLess(detail_dialog, yaml_dialog)
        self.assertLess(detail_dialog, card_grid)
        self.assertIn('aria-haspopup="dialog"', html[toolbar_start:detail_dialog])
        self.assertIn('hidden>查看失败明细</button>', html[toolbar_start:detail_dialog])
        self.assertIn("dialog.showModal();", html)
        self.assertIn("failures.forEach((failure, index) =>", html)
        self.assertIn("list.replaceChildren(fragment);", html)
        self.assertIn("button.hidden = failures.length === 0;", html)


if __name__ == "__main__":
    unittest.main()
