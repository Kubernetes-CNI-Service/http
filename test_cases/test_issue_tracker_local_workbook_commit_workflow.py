"""Real C24/C5/W0/C6 fake-only local XLSX transaction workflow."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path
import hashlib
import json
import tempfile
import unittest
from unittest import mock
import zipfile
import xml.etree.ElementTree as ET

from monitor.issue_tracker_manifest import freeze_qualified_manifest
from monitor.issue_tracker_qualification import qualify_stage_l
from monitor.issue_tracker_state_owner import initialize_tracker_state, tracker_writer
from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
from monitor.issue_tracker_local_commit import LocalCommitHold, inspect_local_generation
from monitor.issue_tracker_local_workbook import (
    LocalWorkbookHold, SwitchDescriptionEdit, SwitchRowInsert, HistoryAppend,
)
from monitor.issue_tracker_local_workbook_commit import commit_fake_workbook
from test_cases.test_issue_tracker_local_workbook import KEY, fake_workbook
from test_cases.test_issue_tracker_local_workbook_commit import large_fake_workbook
from test_cases.test_issue_tracker_qualification import SWITCH, TOKEN_1, TOKEN_2, cycle


SHEET_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"


def _has_formula(cell_xml: bytes) -> bool:
    """Check the SpreadsheetML element, not ElementTree's global prefix choice."""
    return ET.fromstring(cell_xml).find(f"{{{SHEET_NS}}}f") is not None


class LocalWorkbookCommitWorkflowTests(unittest.TestCase):
    def test_formula_probe_is_independent_of_xml_namespace_prefix(self):
        for prefix in ("ns0", "s"):
            cell = (f'<{prefix}:c xmlns:{prefix}="{SHEET_NS}">'
                    f'<{prefix}:f>SUM(A1:A2)</{prefix}:f>'
                    f'</{prefix}:c>').encode("utf-8")
            self.assertTrue(_has_formula(cell))
        no_formula = (f'<s:c xmlns:s="{SHEET_NS}"><s:v>3</s:v></s:c>')
        self.assertFalse(_has_formula(no_formula.encode("utf-8")))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="tracker-w1a-workflow-")
        self.addCleanup(self.tmp.cleanup)
        self.project = Path(self.tmp.name).resolve(strict=True) / "project"
        self.project.mkdir(mode=0o755)
        self.publication = self.project / "99-output-monitor"
        self.publication.mkdir(mode=0o755)
        initialize_tracker_state(
            self.project, self.publication, initialized_at="2026-09-25T00:00:00Z",
            acquisition_id="acquisition-w1a",
        )
        self.template = Path(self.tmp.name) / "fake-template.xlsx"
        self.source = large_fake_workbook()
        self.template.write_bytes(self.source)
        snapshot = read_whitelist_workbook(self.template)
        self.source_sha = snapshot.workbook_sha256
        qualified = qualify_stage_l(
            [cycle(7, TOKEN_1, [SWITCH]), cycle(8, TOKEN_2, [SWITCH])],
            k=2, whitelist_rules=[], whitelist_sha256=snapshot.whitelist.sha256,
            template_sha256=snapshot.workbook_sha256,
        )
        self.body, self.manifest_id = freeze_qualified_manifest(
            qualified,
            metadata={
                "project_id": "site-a", "schema_version": 1,
                "producer_version": "1", "template_contract_version": "1",
                "template_sha256": snapshot.workbook_sha256,
            },
            expected_template_sha256=snapshot.workbook_sha256,
        )
        self.edit = SwitchDescriptionEdit(
            "2-switch", KEY, "[MONITOR][fan][fan1] old", "[MONITOR][fan][fan1] new",
        )

    def test_shared_owner_real_freeze_to_durable_xlsx_preserves_source_and_members(self):
        with tracker_writer(self.project, self.publication) as token:
            result = commit_fake_workbook(
                token, self.template, self.body, [self.edit],
                expected_template_sha256=self.source_sha,
            )
            self.assertEqual(self.manifest_id, result.generation.manifest_id)
            self.assertEqual(self.manifest_id, result.receipt.manifest_id)
            self.assertEqual(self.source_sha, result.prepared.source_sha256)
            self.assertEqual(result.prepared.sha256, result.receipt.published_sha256)
            self.assertEqual((("ETH&IB Switch", "L3"),), result.prepared.changed_cells)
        self.assertEqual(self.source, self.template.read_bytes())
        published = self.publication / (result.generation.generation_id + ".xlsx")
        self.assertEqual(result.prepared.xlsx_bytes, published.read_bytes())
        self.assertEqual(hashlib.sha256(published.read_bytes()).hexdigest(), result.receipt.published_sha256)
        with zipfile.ZipFile(BytesIO(self.source)) as before, zipfile.ZipFile(published) as after:
            self.assertEqual(before.namelist(), after.namelist())
            for member in before.namelist():
                if member != "xl/worksheets/sheet2.xml":
                    self.assertEqual(before.read(member), after.read(member), member)
            changed = after.read("xl/worksheets/sheet2.xml")
            self.assertIn(b"human-owner", changed)
            self.assertIn(b"human-comment", changed)
            self.assertIn(b"[MONITOR][fan][fan1] new", changed)
        self.assertEqual("RECEIPT-PRESENT-NOT-ELIGIBILITY",
                         inspect_local_generation(self.project, self.publication,
                                                  result.generation).status)

    def test_template_drift_stops_before_generation_or_receipt(self):
        self.template.write_bytes(self.source + b"changed")
        with tracker_writer(self.project, self.publication) as token:
            with self.assertRaises((LocalWorkbookHold, LocalCommitHold)):
                commit_fake_workbook(
                    token, self.template, self.body, [self.edit],
                    expected_template_sha256=self.source_sha,
                )
        self.assertEqual([], list((self.project / ".tracker" / "generations").iterdir()))

    def _nonempty_w1_fixture(self):
        small = fake_workbook(reserved_switch_rows=1, decorated=True,
                              whitelist_rules=("leaf01",))
        output = BytesIO()
        with zipfile.ZipFile(BytesIO(small)) as original, zipfile.ZipFile(output, "w") as padded:
            for member in original.infolist():
                padded.writestr(member, original.read(member.filename))
            for index in range(50 - len(original.namelist())):
                padded.writestr(f"fixture/opaque-{index:02d}.bin", bytes((index,)))
        source = output.getvalue()
        self.template.write_bytes(source)
        snapshot = read_whitelist_workbook(self.template)
        self.assertEqual(50, len(zipfile.ZipFile(BytesIO(source)).namelist()))
        key = ("switch", "leaf02", "fan", "fan2")
        kept = {"operation_id": "3-switch", "activity_key": list(key), "action": "upsert"}
        skipped = {"operation_id": "2-switch", "activity_key": list(KEY), "action": "upsert"}
        qualified = qualify_stage_l(
            [cycle(7, TOKEN_1, [skipped, kept]), cycle(8, TOKEN_2, [kept, skipped])],
            k=2, whitelist_rules=list(snapshot.whitelist.rules),
            whitelist_sha256=snapshot.whitelist.sha256,
            template_sha256=snapshot.workbook_sha256, whitelist_snapshot=snapshot,
        )
        self.assertEqual([kept], json.loads(qualified.operations_json))
        body, manifest_id = freeze_qualified_manifest(
            qualified,
            metadata={"project_id": "site-a", "schema_version": 1,
                      "producer_version": "1", "template_contract_version": "1",
                      "template_sha256": snapshot.workbook_sha256},
            expected_template_sha256=snapshot.workbook_sha256,
        )
        insert = SwitchRowInsert(
            "3-switch", key, "2026-09-25", "fixture-monitor", "Compute", "Critical",
            "[MONITOR][fan][fan2] observed",
        )
        history = HistoryAppend("3-switch", key, "2026-09-25T08:00:00Z", "fixture insert")
        return source, snapshot, qualified, body, manifest_id, insert, history

    def test_nonempty_w1_switch_insert_and_history_durably_bind_one_receipt(self):
        source, snapshot, qualified, body, manifest_id, insert, history = self._nonempty_w1_fixture()
        with tracker_writer(self.project, self.publication) as token:
            result = commit_fake_workbook(
                token, self.template, body, [insert, history],
                expected_template_sha256=snapshot.workbook_sha256,
                qualified_set=qualified, expected_manifest_id=manifest_id,
            )
        expected_cells = tuple(("ETH&IB Switch", f"{column}4") for column in "BCFJKLN") + tuple(
            ("Update_History", f"{column}3") for column in "ABCDE"
        )
        self.assertEqual(expected_cells, result.prepared.changed_cells)
        self.assertEqual(source, self.template.read_bytes())
        published = self.publication / (result.generation.generation_id + ".xlsx")
        self.assertEqual(result.prepared.xlsx_bytes, published.read_bytes())
        self.assertEqual(manifest_id, result.receipt.manifest_id)
        self.assertEqual(hashlib.sha256(published.read_bytes()).hexdigest(),
                         result.receipt.published_sha256)
        with zipfile.ZipFile(BytesIO(source)) as before, zipfile.ZipFile(published) as after:
            self.assertEqual(before.namelist(), after.namelist())
            unchanged = [member for member in before.namelist() if member not in (
                "xl/worksheets/sheet2.xml", "xl/worksheets/sheet6.xml",
            )]
            self.assertEqual(48, len(unchanged))
            for member in unchanged:
                self.assertEqual(before.read(member), after.read(member), member)
            namespace = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
            for member, changed in (
                ("xl/worksheets/sheet2.xml", {f"{column}4" for column in "BCFJKLN"}),
                ("xl/worksheets/sheet6.xml", {f"{column}3" for column in "ABCDE"}),
            ):
                before_cells = {cell.attrib["r"]: ET.tostring(cell) for cell in
                                ET.fromstring(before.read(member)).findall(".//m:c", namespace)}
                after_cells = {cell.attrib["r"]: ET.tostring(cell) for cell in
                               ET.fromstring(after.read(member)).findall(".//m:c", namespace)}
                self.assertEqual(changed, {address for address in before_cells.keys() | after_cells.keys()
                                           if before_cells.get(address) != after_cells.get(address)})
                if member.endswith("sheet2.xml"):
                    self.assertTrue(all(_has_formula(after_cells[f"{column}4"]) and
                                        before_cells[f"{column}4"] == after_cells[f"{column}4"]
                                        for column in "DEGH"))
                    self.assertEqual(before_cells.get("I4"), after_cells.get("I4"))
                    self.assertTrue(all(before_cells.get(f"{column}4") == after_cells.get(f"{column}4")
                                        for column in "MOPQRSTU"))
        self.assertEqual("RECEIPT-PRESENT-NOT-ELIGIBILITY",
                         inspect_local_generation(self.project, self.publication,
                                                  result.generation).status)

    def test_nonempty_w1_forged_manifest_and_skipped_switch_hold_before_generation(self):
        source, snapshot, qualified, body, manifest_id, insert, history = self._nonempty_w1_fixture()
        skipped = SwitchRowInsert(
            "2-switch", KEY, "2026-09-25", "fixture-monitor", "Compute", "Critical",
            "[MONITOR][fan][fan1] observed",
        )
        forged_body = body.replace(b'"operation_id":"3-switch"', b'"operation_id":"forged"')
        self.assertNotEqual(body, forged_body)
        rejected = (
            (body, [skipped, HistoryAppend("2-switch", KEY, "2026-09-25T08:00:00Z", "skip")],
             manifest_id, "skipped by the frozen Whitelist"),
            (body, [insert, history], "0" * 64, "frozen manifest drifted"),
            (forged_body, [insert, history], manifest_id, "frozen manifest drifted"),
        )
        with tracker_writer(self.project, self.publication) as token:
            for attempted_body, edits, expected_id, reason in rejected:
                with self.assertRaisesRegex(LocalWorkbookHold, reason):
                    commit_fake_workbook(
                        token, self.template, attempted_body, edits,
                        expected_template_sha256=snapshot.workbook_sha256,
                        qualified_set=qualified, expected_manifest_id=expected_id,
                    )
                self.assertEqual([], list((self.project / ".tracker" / "generations").iterdir()))
        self.assertEqual(source, self.template.read_bytes())

    def test_nonempty_w1_failure_after_intent_preserves_evidence_without_receipt(self):
        source, snapshot, qualified, body, manifest_id, insert, history = self._nonempty_w1_fixture()
        with tracker_writer(self.project, self.publication) as token:
            with mock.patch(
                "monitor.issue_tracker_local_workbook_commit.commit",
                side_effect=LocalCommitHold("injected after INTENT"),
            ):
                with self.assertRaisesRegex(LocalCommitHold, "injected after INTENT"):
                    commit_fake_workbook(
                        token, self.template, body, [insert, history],
                        expected_template_sha256=snapshot.workbook_sha256,
                        qualified_set=qualified, expected_manifest_id=manifest_id,
                    )
        generations = list((self.project / ".tracker" / "generations").iterdir())
        self.assertEqual(1, len(generations))
        self.assertTrue((generations[0] / "INTENT").is_file())
        self.assertFalse((generations[0] / "RECEIPT").exists())
        self.assertEqual(source, self.template.read_bytes())


if __name__ == "__main__":
    unittest.main()
