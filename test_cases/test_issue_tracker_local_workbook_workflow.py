"""Real C24 read + C5 qualification/manifest + W0 fake local preparation."""

from __future__ import annotations

from io import BytesIO
import hashlib
import json
import tempfile
from pathlib import Path
import unittest
import zipfile

from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
from monitor.issue_tracker_qualification import qualify_stage_l
from monitor.issue_tracker_manifest import freeze_qualified_manifest
from monitor.issue_tracker_local_workbook import (
    LocalWorkbookHold, SwitchDescriptionEdit, prepare_fake_local_workbook,
)
from monitor import issue_tracker_local_workbook as writer
from test_cases.test_issue_tracker_local_workbook import KEY, fake_workbook
from test_cases.test_issue_tracker_qualification import SWITCH, TOKEN_1, TOKEN_2, cycle


class LocalWorkbookWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "fake.xlsx"
        self.source = fake_workbook()
        self.path.write_bytes(self.source)
        snapshot = read_whitelist_workbook(self.path)
        self.assertEqual((), snapshot.whitelist.rules)
        self.snapshot = snapshot
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

    def test_real_read_and_manifest_bind_one_fake_edit_without_persistence(self):
        prepared = prepare_fake_local_workbook(
            self.path, self.body, [self.edit],
            expected_template_sha256=self.snapshot.workbook_sha256,
        )
        self.assertEqual(self.source, self.path.read_bytes())
        self.assertEqual(self.snapshot.workbook_sha256, prepared.source_sha256)
        self.assertEqual(self.manifest_id, prepared.manifest_id)
        self.assertEqual(hashlib.sha256(prepared.xlsx_bytes).hexdigest(), prepared.sha256)
        self.assertEqual((("ETH&IB Switch", "L3"),), prepared.changed_cells)
        with zipfile.ZipFile(BytesIO(prepared.xlsx_bytes)) as archive:
            self.assertEqual(self.source_member("xl/drawings/drawing1.xml"), archive.read("xl/drawings/drawing1.xml"))

    def source_member(self, member):
        with zipfile.ZipFile(BytesIO(self.source)) as archive:
            return archive.read(member)

    def test_preparation_refuses_manifest_or_whitelist_drift(self):
        with self.assertRaises(LocalWorkbookHold):
            prepare_fake_local_workbook(
                self.path, self.body.replace(b"synthetic-local-fixture", b"runtime-collector"),
                [self.edit], expected_template_sha256=self.snapshot.workbook_sha256,
            )
        changed = fake_workbook(whitelist_rules=("leaf01",))
        self.path.write_bytes(changed)
        with self.assertRaises(LocalWorkbookHold):
            prepare_fake_local_workbook(
                self.path, self.body, [self.edit],
                expected_template_sha256=self.snapshot.workbook_sha256,
            )

    def test_real_c5_frozen_operation_id_key_and_action_are_exactly_bound(self):
        for change in ("operation_id", "activity_key", "action"):
            with self.subTest(change=change):
                parsed = json.loads(self.body)
                operation = parsed["operations"][0]
                operation[change] = {
                    "operation_id": "different-switch",
                    "activity_key": ["switch", "different-host", "fan", "fan1"],
                    "action": "delete",
                }[change]
                forged = json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode() + b"\n"
                with self.assertRaises(LocalWorkbookHold):
                    prepare_fake_local_workbook(
                        self.path, forged, [self.edit],
                        expected_template_sha256=self.snapshot.workbook_sha256,
                    )

    def test_real_c24_c5_switch_insert_and_history_remain_one_in_memory_change(self):
        source = fake_workbook(reserved_switch_rows=1, decorated=True)
        self.path.write_bytes(source)
        snapshot = read_whitelist_workbook(self.path)
        key = ("switch", "leaf02", "fan", "fan2")
        operation = {"operation_id": "3-switch", "activity_key": list(key), "action": "upsert"}
        qualified = qualify_stage_l(
            [cycle(7, TOKEN_1, [operation]), cycle(8, TOKEN_2, [operation])],
            k=2, whitelist_rules=[], whitelist_sha256=snapshot.whitelist.sha256,
            template_sha256=snapshot.workbook_sha256,
        )
        body, manifest_id = freeze_qualified_manifest(
            qualified,
            metadata={"project_id": "site-a", "schema_version": 1,
                      "producer_version": "1", "template_contract_version": "1",
                      "template_sha256": snapshot.workbook_sha256},
            expected_template_sha256=snapshot.workbook_sha256,
        )
        insert = writer.SwitchRowInsert(
            "3-switch", key, "2026-09-25", "fixture-monitor", "Compute", "Critical",
            "[MONITOR][fan][fan2] observed",
        )
        history = writer.HistoryAppend("3-switch", key, "2026-09-25T08:00:00Z", "fixture insert")
        prepared = prepare_fake_local_workbook(
            self.path, body, [insert, history],
            expected_template_sha256=snapshot.workbook_sha256,
        )
        self.assertEqual(manifest_id, prepared.manifest_id)
        self.assertEqual(source, self.path.read_bytes())
        self.assertIn(("ETH&IB Switch", "F4"), prepared.changed_cells)
        self.assertIn(("Update_History", "D3"), prepared.changed_cells)
        for forged in (
            dict(operation, operation_id="wrong"),
            dict(operation, activity_key=["switch", "leaf03", "fan", "fan2"]),
            dict(operation, action="delete"),
        ):
            with self.subTest(forged=forged):
                parsed = json.loads(body)
                parsed["operations"] = [forged]
                forged_body = json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode() + b"\n"
                with self.assertRaises(LocalWorkbookHold):
                    prepare_fake_local_workbook(
                        self.path, forged_body, [insert, history],
                        expected_template_sha256=snapshot.workbook_sha256,
                    )
                self.assertEqual(source, self.path.read_bytes())

    def test_nonempty_real_c24_c5_kept_switch_insert_cannot_resurrect_skip(self):
        source = fake_workbook(reserved_switch_rows=1, whitelist_rules=("leaf01",))
        self.path.write_bytes(source)
        snapshot = read_whitelist_workbook(self.path)
        kept_key = ("switch", "leaf02", "fan", "fan2")
        kept = {"operation_id": "3-switch", "activity_key": list(kept_key), "action": "upsert"}
        qualified = qualify_stage_l(
            [cycle(7, TOKEN_1, [SWITCH, kept]), cycle(8, TOKEN_2, [kept, SWITCH])],
            k=2, whitelist_rules=list(snapshot.whitelist.rules),
            whitelist_sha256=snapshot.whitelist.sha256,
            template_sha256=snapshot.workbook_sha256, whitelist_snapshot=snapshot,
        )
        self.assertIn(b"2-switch", qualified.whitelist_skips_json)
        self.assertEqual([kept], json.loads(qualified.operations_json))
        body, manifest_id = freeze_qualified_manifest(
            qualified,
            metadata={"project_id": "site-a", "schema_version": 1,
                      "producer_version": "1", "template_contract_version": "1",
                      "template_sha256": snapshot.workbook_sha256},
            expected_template_sha256=snapshot.workbook_sha256,
        )
        insert = writer.SwitchRowInsert(
            "3-switch", kept_key, "2026-09-25", "fixture-monitor", "Compute", "Critical",
            "[MONITOR][fan][fan2] observed",
        )
        history = writer.HistoryAppend("3-switch", kept_key, "2026-09-25T08:00:00Z", "fixture insert")
        prepared = prepare_fake_local_workbook(
            self.path, body, [insert, history],
            expected_template_sha256=snapshot.workbook_sha256,
            qualified_set=qualified, expected_manifest_id=manifest_id,
        )
        self.assertEqual(source, self.path.read_bytes())
        self.assertIn(("ETH&IB Switch", "F4"), prepared.changed_cells)
        self.assertIn(("Update_History", "D3"), prepared.changed_cells)
        with self.assertRaises(LocalWorkbookHold):
            prepare_fake_local_workbook(
                self.path, body, [self.edit],
                expected_template_sha256=snapshot.workbook_sha256,
                qualified_set=qualified, expected_manifest_id=manifest_id,
            )


if __name__ == "__main__":
    unittest.main()
