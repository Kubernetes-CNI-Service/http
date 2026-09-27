"""C-24 workbook reader and pure Whitelist qualification share one digest."""

from pathlib import Path
import tempfile
import unittest

from monitor.issue_tracker_whitelist import evaluate_whitelist, freeze_whitelist_sheet
from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
from test_cases.test_issue_tracker_whitelist_workbook import HEADER, literal_xlsx


class WhitelistWorkbookWorkflowTests(unittest.TestCase):
    def test_real_workbook_reader_and_pure_decision_use_same_frozen_rules(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "local.xlsx"
            path.write_bytes(literal_xlsx(rules=("leaf-*",)))
            from_workbook = read_whitelist_workbook(path)
            from_values = freeze_whitelist_sheet([
                HEADER, [None, None, None, None, "leaf-*", None],
            ])
            self.assertEqual(from_values.sha256, from_workbook.whitelist.sha256)
            evaluation = evaluate_whitelist(from_workbook.whitelist, [
                {"record_id": "s1", "source": "Switch", "hostname": "LEAF-01"},
            ])
            self.assertEqual(from_workbook.whitelist.sha256, evaluation.snapshot_sha256)
            self.assertEqual(("s1",), evaluation.skipped_keys)


if __name__ == "__main__":
    unittest.main()
