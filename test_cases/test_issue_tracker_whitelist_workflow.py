"""Two-production-module C-24 local empty-sheet snapshot qualification workflow."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from monitor.issue_tracker_manifest import freeze_qualified_manifest
from monitor.issue_tracker_qualification import qualify_stage_l
from monitor.issue_tracker_whitelist import evaluate_whitelist, freeze_whitelist_sheet
from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
from test_cases.test_issue_tracker_qualification import SWITCH, TOKEN_1, TOKEN_2, cycle
from test_cases.test_issue_tracker_whitelist import HEADER, sheet
from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx


class WhitelistWorkflowTests(unittest.TestCase):
    def test_one_frozen_empty_snapshot_flows_to_local_qualified_manifest(self):
        snapshot = freeze_whitelist_sheet([HEADER])
        evaluation = evaluate_whitelist(snapshot, [{"record_id": "s1", "source": "Switch", "hostname": "leaf01"}])
        self.assertEqual(0, evaluation.skipped_switches)
        qualified = qualify_stage_l(
            [cycle(7, TOKEN_1, [SWITCH]), cycle(8, TOKEN_2, [SWITCH])],
            k=2, whitelist_rules=list(snapshot.rules), whitelist_sha256=snapshot.sha256,
            template_sha256="b" * 64,
        )
        body, manifest_id = freeze_qualified_manifest(
            qualified,
            metadata={"project_id": "site-a", "schema_version": 1,
                      "producer_version": "1", "template_contract_version": "1",
                      "template_sha256": "b" * 64},
            expected_template_sha256="b" * 64,
        )
        self.assertEqual(snapshot.sha256, qualified.whitelist_sha256)
        self.assertEqual(snapshot.sha256, json.loads(body)["qualified_source"]["whitelist_sha256"])
        self.assertEqual(hashlib.sha256(body).hexdigest(), manifest_id)

    def test_nonempty_snapshot_cannot_be_misrepresented_as_empty_qualification(self):
        snapshot = freeze_whitelist_sheet(sheet("leaf01"))
        with self.assertRaises(ValueError):
            qualify_stage_l(
                [cycle(7, TOKEN_1, [SWITCH]), cycle(8, TOKEN_2, [SWITCH])],
                k=2, whitelist_rules=list(snapshot.rules), whitelist_sha256=snapshot.sha256,
                template_sha256="b" * 64,
            )

    def test_real_c24_reader_to_c5_freezer_filters_fake_nonempty_workbook(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fake-template.xlsx"
            path.write_bytes(literal_xlsx(rules=("re:^LEAF0[0-9]$",)))
            snapshot = read_whitelist_workbook(path)
            qualified = qualify_stage_l(
                [cycle(7, TOKEN_1, [SWITCH]), cycle(8, TOKEN_2, [SWITCH])],
                k=2, whitelist_rules=list(snapshot.whitelist.rules),
                whitelist_sha256=snapshot.whitelist.sha256,
                whitelist_snapshot=snapshot,
                template_sha256=snapshot.workbook_sha256,
            )
            body, manifest_id = freeze_qualified_manifest(
                qualified,
                metadata={"project_id": "site-a", "schema_version": 1,
                          "producer_version": "1", "template_contract_version": "1",
                          "template_sha256": snapshot.workbook_sha256},
                expected_template_sha256=snapshot.workbook_sha256,
            )
            parsed = json.loads(body)
            self.assertEqual([], parsed["operations"])
            self.assertEqual("re:^LEAF0[0-9]$", parsed["qualified_source"]["whitelist_skips"][0]["matched_rule"])
            self.assertEqual(snapshot.whitelist.sha256, parsed["qualified_source"]["whitelist_sha256"])
            self.assertEqual(hashlib.sha256(body).hexdigest(), manifest_id)


if __name__ == "__main__":
    unittest.main()
