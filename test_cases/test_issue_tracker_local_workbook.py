"""Independent fake OOXML contract for a local, nonpersistent W0 preparation."""

from __future__ import annotations

from dataclasses import replace
from html import escape
from io import BytesIO
from pathlib import Path
import hashlib
import json
import os
import tempfile
import unittest
from unittest import mock
import zipfile
import xml.etree.ElementTree as ET

from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
from monitor.issue_tracker_local_workbook import (
    LocalWorkbookHold, SwitchDescriptionEdit, prepare_fake_local_workbook,
)
from monitor import issue_tracker_local_workbook as writer
from monitor.issue_tracker_manifest import freeze_qualified_manifest
from monitor.issue_tracker_qualification import qualify_stage_l
from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
from test_cases.test_issue_tracker_qualification import SWITCH, TOKEN_1, TOKEN_2, cycle


SWITCH_HEADERS = (
    "Issue#", "Submit Date", "Submitor", "Rack", "RU", "Host Name",
    "OOB IP", "SN", "Model", "Fabric", "Priority", "Issue Description",
    "NVEX Case ID", "Status", "Owner", "Action Description", "P-Status",
    "Replacement SN", "Replacement ETH0 MAC", "Remark \n(Partner)", "Remark\n(NV)",
)
CABLING_HEADERS = (
    "Fault ID", "Source", "Requested by", "Date opened", "Link Type",
    "Issue Type", "Issue Desc", "A-SU", "A-Rack", "A-RU", "A-Node",
    "A-Port", "A Actual Node", "A Actual Port", "Z-Rack", "Z-RU",
    "Z-Node", "Z-Port", "Z Actual Node", "Z Actual Port", "Status",
    "Notes", "AI Recommendation (Refer only)", "NV Comments",
    "Assigned to", "Engineer Assigned", "Action Description", "P-status", "CVT",
)
HISTORY_HEADERS = ("Timestamp (UTC)", "Sheet", "Action", "Key", "Details")
KEY = ("switch", "leaf01", "fan", "fan1")
OP = {"operation_id": "2-switch", "activity_key": list(KEY), "action": "upsert"}


def _column(index):
    result = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        result = chr(65 + remainder) + result
    return result


def _text_cell(address, value):
    return f'<c r="{address}" t="inlineStr"><is><t>{escape(value)}</t></is></c>'


def _sheet(headers, *, switch_rows=1, switch_status="Open", reserved_switch_rows=0,
           busy_reserved_rows=(), decorated=False, missing_headroom_formula=None,
           existing_switch_id=None):
    ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    row2 = ''.join(_text_cell(f"{_column(i)}2", value) for i, value in enumerate(headers, 1))
    rows = ['<row r="2">' + row2 + '</row>']
    if headers == SWITCH_HEADERS:
        for n in range(3, 3 + switch_rows):
            # Formula, operator and target cells deliberately share one row.
            cells = ''.join(f'<c r="{col}{n}"><f>{n}+1</f></c>' for col in "DEGHI")
            if n == 3 and existing_switch_id is not None:
                cells += _text_cell("A3", existing_switch_id)
            cells += _text_cell(f"F{n}", "leaf01")
            cells += _text_cell(f"L{n}", "[MONITOR][fan][fan1] old")
            cells += _text_cell(f"N{n}", switch_status)
            cells += _text_cell(f"O{n}", "human-owner")
            cells += _text_cell(f"U{n}", "human-comment")
            rows.append(f'<row r="{n}">{cells}</row>')
        for n in range(4, 4 + reserved_switch_rows):
            cells = _text_cell(f"A{n}", f"NV{9998 + n}")
            cells += ''.join(f'<c r="{col}{n}" s="2"><f>{n}+1</f></c>'
                             for col in "DEGH" if col != missing_headroom_formula)
            cells += '<c r="I%d" s="5"/>' % n
            cells += '<c r="M%d" s="6"/><c r="O%d" s="6"/><c r="U%d" s="6"/>' % (n, n, n)
            if n in busy_reserved_rows:
                cells += _text_cell(f"J{n}", "occupied")
            rows.append(f'<row r="{n}" s="1">{cells}</row>')
    decorations = (
        '<mergeCells count="1"><mergeCell ref="A1:B1"/></mergeCells>'
        '<dataValidations count="1"><dataValidation type="list" sqref="N4:N5"/>'
        '</dataValidations><drawing r:id="rId1"/>' if decorated else ""
    )
    return (f'<worksheet xmlns="{ns}" xmlns:r="http://schemas.openxmlformats.org/'
            f'officeDocument/2006/relationships"><sheetData>{"".join(rows)}'
            f'</sheetData>{decorations}</worksheet>').encode()


def fake_workbook(*, switch_rows=1, switch_status="Open", bad_header=None,
                  whitelist_rules=(), reserved_switch_rows=0,
                  busy_reserved_rows=(), decorated=False, missing_headroom_formula=None,
                  existing_switch_id=None):
    source = literal_xlsx(rules=whitelist_rules)
    source_zip = zipfile.ZipFile(BytesIO(source))
    result = BytesIO()
    overrides = {
        "xl/worksheets/sheet2.xml": _sheet(SWITCH_HEADERS, switch_rows=switch_rows,
                                            switch_status=switch_status,
                                            reserved_switch_rows=reserved_switch_rows,
                                            busy_reserved_rows=busy_reserved_rows,
                                            decorated=decorated,
                                            missing_headroom_formula=missing_headroom_formula,
                                            existing_switch_id=existing_switch_id),
        "xl/worksheets/sheet3.xml": _sheet(CABLING_HEADERS),
        "xl/worksheets/sheet4.xml": _sheet(CABLING_HEADERS),
        "xl/worksheets/sheet6.xml": _sheet(HISTORY_HEADERS),
    }
    if bad_header is not None:
        member = {"switch": 2, "eth": 3, "ib": 4, "history": 6}[bad_header]
        headers = {2: SWITCH_HEADERS, 3: CABLING_HEADERS,
                   4: CABLING_HEADERS, 6: HISTORY_HEADERS}[member]
        overrides[f"xl/worksheets/sheet{member}.xml"] = _sheet(
            ("Wrong", *headers[1:]), switch_rows=switch_rows,
        )
    with zipfile.ZipFile(result, "w", zipfile.ZIP_DEFLATED) as output:
        for info in source_zip.infolist():
            output.writestr(info, overrides.get(info.filename, source_zip.read(info.filename)))
        output.writestr("xl/drawings/drawing1.xml", b"<drawing>unchanged</drawing>")
    return result.getvalue()


def fixture_manifest(workbook_sha, operations=(OP,)):
    import json
    value = {
        "project_id": "site-a", "schema_version": 1, "producer_version": "1",
        "template_contract_version": "1", "template_sha256": workbook_sha,
        "operations": list(operations),
        "qualified_source": {
            "mode": "synthetic-local-fixture", "k": 1,
            "whitelist_sha256": hashlib.sha256(b"[]\n").hexdigest(),
        },
    }
    return (json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n")


class LocalWorkbookTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "fake.xlsx"
        self.raw = fake_workbook()
        self.path.write_bytes(self.raw)
        self.digest = hashlib.sha256(self.raw).hexdigest()
        self.manifest = fixture_manifest(self.digest)
        self.edit = SwitchDescriptionEdit("2-switch", KEY, "[MONITOR][fan][fan1] old", "[MONITOR][fan][fan1] new")

    def prepare(self, **changes):
        options = {"expected_template_sha256": self.digest}
        options.update(changes)
        return prepare_fake_local_workbook(self.path, self.manifest, [self.edit], **options)

    def nonempty_frozen(self, raw, operations=(SWITCH,)):
        self.path.write_bytes(raw)
        snapshot = read_whitelist_workbook(self.path)
        qualified = qualify_stage_l(
            [cycle(7, TOKEN_1, list(operations)), cycle(8, TOKEN_2, list(operations))],
            k=2, whitelist_rules=list(snapshot.whitelist.rules),
            whitelist_sha256=snapshot.whitelist.sha256,
            template_sha256=snapshot.workbook_sha256,
            whitelist_snapshot=snapshot,
        )
        body, manifest_id = freeze_qualified_manifest(
            qualified,
            metadata={"project_id": "site-a", "schema_version": 1,
                      "producer_version": "1", "template_contract_version": "1",
                      "template_sha256": snapshot.workbook_sha256},
            expected_template_sha256=snapshot.workbook_sha256,
        )
        return snapshot, qualified, body, manifest_id

    def test_switch_l_only_and_all_other_members_and_source_are_preserved(self):
        result = self.prepare()
        self.assertEqual(self.digest, result.source_sha256)
        self.assertEqual(self.raw, self.path.read_bytes())
        self.assertEqual(hashlib.sha256(result.xlsx_bytes).hexdigest(), result.sha256)
        self.assertEqual((("ETH&IB Switch", "L3"),), result.changed_cells)
        with zipfile.ZipFile(BytesIO(self.raw)) as before, zipfile.ZipFile(BytesIO(result.xlsx_bytes)) as after:
            self.assertEqual(before.namelist(), after.namelist())
            for name in before.namelist():
                if name != "xl/worksheets/sheet2.xml":
                    self.assertEqual(before.read(name), after.read(name), name)
            changed = after.read("xl/worksheets/sheet2.xml")
            self.assertIn(b"[MONITOR][fan][fan1] new", changed)
            self.assertNotIn(b"[MONITOR][fan][fan1] old", changed)
            self.assertIn(b"human-owner", changed)
            self.assertIn(b"human-comment", changed)
            formulas = [node.text for node in ET.fromstring(changed).iter()
                        if node.tag.endswith("}f")]
            self.assertEqual(["3+1"] * 5, formulas)
            old_cells = {node.attrib["r"]: ET.tostring(node) for node in
                         ET.fromstring(before.read("xl/worksheets/sheet2.xml")).iter()
                         if node.tag.endswith("}c")}
            new_cells = {node.attrib["r"]: ET.tostring(node) for node in
                         ET.fromstring(changed).iter() if node.tag.endswith("}c")}
            self.assertEqual(old_cells.keys(), new_cells.keys())
            self.assertEqual({key: value for key, value in old_cells.items() if key != "L3"},
                             {key: value for key, value in new_cells.items() if key != "L3"})

    def test_protected_w1_skip_history_records_real_identity_and_rule_only(self):
        from monitor.issue_tracker_stage_l_consumer import StageLQualifiedSkip

        skips = (
            StageLQualifiedSkip("eth_cabling", "leaf*", endpoints=(
                "leaf01", "swp1", "leaf02", "swp2")),
            StageLQualifiedSkip("switch", "leaf01", record_id="switch:leaf01"),
        )
        manifest_id = "a" * 64
        result = writer.project_whitelist_skip_history_image(
            self.raw, skips, recorded_at_utc="2026-09-25T08:00:00Z",
            manifest_id=manifest_id,
        )
        self.assertEqual(self.raw, self.path.read_bytes())
        with zipfile.ZipFile(BytesIO(self.raw)) as before, zipfile.ZipFile(BytesIO(result)) as after:
            self.assertEqual(before.namelist(), after.namelist())
            for name in before.namelist():
                if name != "xl/worksheets/sheet6.xml":
                    self.assertEqual(before.read(name), after.read(name), name)
            history = after.read("xl/worksheets/sheet6.xml")
            self.assertEqual(4, history.count(b"Whitelist Skip"))  # Action and details per row.
            for literal in (b"leaf*", b"leaf01", b"swp1", b"swp2",
                            b"switch:leaf01", manifest_id.encode()):
                self.assertIn(literal, history)
        self.assertEqual(result, writer.project_whitelist_skip_history_image(
            result, skips, recorded_at_utc="2026-09-25T08:00:00Z",
            manifest_id=manifest_id,
        ))
        with self.assertRaises(LocalWorkbookHold):
            writer.project_whitelist_skip_history_image(
                result, (replace(skips[0], matched_rule="another-rule"), skips[1]),
                recorded_at_utc="2026-09-25T08:00:00Z",
                manifest_id=manifest_id,
            )
        with self.assertRaises(LocalWorkbookHold):
            writer.project_whitelist_skip_history_image(
                self.raw, (skips[0], skips[0]),
                recorded_at_utc="2026-09-25T08:00:00Z",
                manifest_id=manifest_id,
            )
        with self.assertRaises(LocalWorkbookHold):
            writer.project_whitelist_skip_history_image(
                self.raw, skips, recorded_at_utc="not a timestamp",
                manifest_id=manifest_id,
            )

    def test_stale_digest_bad_header_and_nonempty_whitelist_hold(self):
        with self.assertRaises(LocalWorkbookHold):
            self.prepare(expected_template_sha256="0" * 64)
        for raw in (*(fake_workbook(bad_header=sheet) for sheet in
                      ("switch", "eth", "ib", "history")),
                    fake_workbook(whitelist_rules=("leaf01",))):
            self.path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            with self.assertRaises(LocalWorkbookHold):
                prepare_fake_local_workbook(self.path, fixture_manifest(digest), [self.edit], expected_template_sha256=digest)

    def test_duplicate_row_and_missing_or_unsupported_edit_hold(self):
        raw = fake_workbook(switch_rows=2)
        self.path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        with self.assertRaises(LocalWorkbookHold):
            prepare_fake_local_workbook(self.path, fixture_manifest(digest), [self.edit], expected_template_sha256=digest)
        with self.assertRaises(LocalWorkbookHold):
            prepare_fake_local_workbook(
                self.path, self.manifest,
                [SwitchDescriptionEdit("wrong", KEY, self.edit.expected_description, self.edit.new_description)],
                expected_template_sha256=self.digest,
            )

    def test_closed_existing_row_is_not_reopened_by_fake_update(self):
        raw = fake_workbook(switch_status="Closed")
        self.path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        with self.assertRaises(LocalWorkbookHold):
            prepare_fake_local_workbook(
                self.path, fixture_manifest(digest), [self.edit],
                expected_template_sha256=digest,
            )
        self.assertEqual(raw, self.path.read_bytes())

    def test_symlink_and_source_change_hold(self):
        link = Path(self.tmp.name) / "link.xlsx"
        link.symlink_to(self.path)
        with self.assertRaises(LocalWorkbookHold):
            prepare_fake_local_workbook(link, self.manifest, [self.edit], expected_template_sha256=self.digest)
        self.path.write_bytes(self.raw + b"x")
        with self.assertRaises(LocalWorkbookHold):
            self.prepare()

    def test_no_template_write_flags_or_publish_call_even_on_output_failure(self):
        real_open = os.open
        seen_flags = []

        def readonly_open(path, flags, *args, **kwargs):
            seen_flags.append(flags)
            if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC):
                self.fail("W0 attempted a filesystem write")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(writer.os, "open", side_effect=readonly_open):
            self.prepare()
        self.assertTrue(seen_flags)
        self.assertEqual(self.raw, self.path.read_bytes())
        with mock.patch.object(writer.zipfile.ZipFile, "writestr", side_effect=OSError("injected")):
            with self.assertRaises(LocalWorkbookHold):
                self.prepare()
        self.assertEqual(self.raw, self.path.read_bytes())

    def test_switch_reserved_insert_and_bound_history_preserve_unedited_package(self):
        key = ("switch", "leaf02", "fan", "fan2")
        operation = {"operation_id": "3-switch", "activity_key": list(key), "action": "upsert"}
        source = fake_workbook(reserved_switch_rows=2, decorated=True)
        self.path.write_bytes(source)
        digest = hashlib.sha256(source).hexdigest()
        insert = writer.SwitchRowInsert(
            "3-switch", key, "2026-09-25", "fixture-monitor", "Compute", "Critical",
            "[MONITOR][fan][fan2] observed",
        )
        history = writer.HistoryAppend(
            "3-switch", key, "2026-09-25T08:00:00Z", "fixture insert",
        )
        prepared = prepare_fake_local_workbook(
            self.path, fixture_manifest(digest, (operation,)), [insert, history],
            expected_template_sha256=digest,
        )
        self.assertEqual(source, self.path.read_bytes())
        self.assertEqual(digest, prepared.source_sha256)
        expected = {("ETH&IB Switch", f"{column}4") for column in "BCFJKLN"}
        expected.update(("Update_History", f"{column}3") for column in "ABCDE")
        self.assertEqual(expected, set(prepared.changed_cells))
        with zipfile.ZipFile(BytesIO(source)) as before, zipfile.ZipFile(BytesIO(prepared.xlsx_bytes)) as after:
            self.assertEqual(before.namelist(), after.namelist())
            changed_members = {"xl/worksheets/sheet2.xml", "xl/worksheets/sheet6.xml"}
            for member in before.namelist():
                if member not in changed_members:
                    self.assertEqual(before.read(member), after.read(member), member)
            def cells(archive, member):
                root = ET.fromstring(archive.read(member))
                return root, {node.attrib["r"]: ET.tostring(node) for node in root.iter()
                              if node.tag.endswith("}c")}
            old_switch, old_cells = cells(before, "xl/worksheets/sheet2.xml")
            new_switch, new_cells = cells(after, "xl/worksheets/sheet2.xml")
            self.assertEqual(
                {k: v for k, v in old_cells.items() if k not in {f"{c}4" for c in "BCFJKLN"}},
                {k: v for k, v in new_cells.items() if k not in {f"{c}4" for c in "BCFJKLN"}},
            )
            for name in ("mergeCells", "dataValidations", "drawing"):
                old = next(node for node in old_switch if node.tag.endswith("}" + name))
                new = next(node for node in new_switch if node.tag.endswith("}" + name))
                self.assertEqual(ET.tostring(old), ET.tostring(new))
            switch_xml = after.read("xl/worksheets/sheet2.xml")
            for text in (b"leaf02", b"fixture-monitor", b"Critical", b"[MONITOR][fan][fan2] observed"):
                self.assertIn(text, switch_xml)
            self.assertEqual(4, sum(1 for node in new_switch.iter() if node.tag.endswith("}f")
                                    and node.attrib == {} and node.text == "5+1"))
            _, old_history = cells(before, "xl/worksheets/sheet6.xml")
            _, new_history = cells(after, "xl/worksheets/sheet6.xml")
            self.assertEqual(old_history, {k: v for k, v in new_history.items() if k not in
                                           {f"{c}3" for c in "ABCDE"}})
            history_xml = after.read("xl/worksheets/sheet6.xml")
            for text in (b"2026-09-25T08:00:00Z", b"ETH&amp;IB Switch", b"Insert",
                         b"NV10002", b"fixture insert"):
                self.assertIn(text, history_xml)

    def test_switch_insert_exhaustion_duplicate_and_unbound_history_hold(self):
        key = ("switch", "leaf02", "fan", "fan2")
        operation = {"operation_id": "3-switch", "activity_key": list(key), "action": "upsert"}
        insert = writer.SwitchRowInsert(
            "3-switch", key, "2026-09-25", "fixture-monitor", "Compute", "Critical",
            "[MONITOR][fan][fan2] observed",
        )
        history = writer.HistoryAppend("3-switch", key, "2026-09-25T08:00:00Z", "fixture insert")
        for raw, history_edit in (
            (fake_workbook(reserved_switch_rows=2, busy_reserved_rows=(4, 5)), history),
            (fake_workbook(reserved_switch_rows=2),
             writer.HistoryAppend("wrong", key, "2026-09-25T08:00:00Z", "fixture insert")),
            (fake_workbook(reserved_switch_rows=2),
             writer.HistoryAppend("3-switch", key, "not UTC", "fixture insert")),
        ):
            with self.subTest(raw_sha=hashlib.sha256(raw).hexdigest(), history=history_edit):
                self.path.write_bytes(raw)
                digest = hashlib.sha256(raw).hexdigest()
                with self.assertRaises(LocalWorkbookHold):
                    prepare_fake_local_workbook(
                        self.path, fixture_manifest(digest, (operation,)), [insert, history_edit],
                        expected_template_sha256=digest,
                    )
                self.assertEqual(raw, self.path.read_bytes())

    def test_switch_insert_does_not_use_row_with_missing_formula_headroom(self):
        key = ("switch", "leaf02", "fan", "fan2")
        operation = {"operation_id": "3-switch", "activity_key": list(key), "action": "upsert"}
        raw = fake_workbook(reserved_switch_rows=1, missing_headroom_formula="D")
        self.path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        insert = writer.SwitchRowInsert(
            "3-switch", key, "2026-09-25", "fixture-monitor", "Compute", "Critical",
            "[MONITOR][fan][fan2] observed",
        )
        history = writer.HistoryAppend("3-switch", key, "2026-09-25T08:00:00Z", "fixture insert")
        with self.assertRaisesRegex(LocalWorkbookHold, "formula|headroom"):
            prepare_fake_local_workbook(
                self.path, fixture_manifest(digest, (operation,)), [insert, history],
                expected_template_sha256=digest,
            )
        self.assertEqual(raw, self.path.read_bytes())

    def test_switch_insert_rejects_reserved_id_reuse_with_existing_row(self):
        key = ("switch", "leaf02", "fan", "fan2")
        operation = {"operation_id": "3-switch", "activity_key": list(key), "action": "upsert"}
        raw = fake_workbook(reserved_switch_rows=1, existing_switch_id="NV10002")
        self.path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        insert = writer.SwitchRowInsert(
            "3-switch", key, "2026-09-25", "fixture-monitor", "Compute", "Critical",
            "[MONITOR][fan][fan2] observed",
        )
        history = writer.HistoryAppend("3-switch", key, "2026-09-25T08:00:00Z", "fixture insert")
        with self.assertRaisesRegex(LocalWorkbookHold, "duplicate|ID"):
            prepare_fake_local_workbook(
                self.path, fixture_manifest(digest, (operation,)), [insert, history],
                expected_template_sha256=digest,
            )
        self.assertEqual(raw, self.path.read_bytes())

    def test_switch_insert_skips_a_business_occupied_reserved_row(self):
        key = ("switch", "leaf02", "fan", "fan2")
        operation = {"operation_id": "3-switch", "activity_key": list(key), "action": "upsert"}
        raw = fake_workbook(reserved_switch_rows=2, busy_reserved_rows=(4,))
        self.path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        insert = writer.SwitchRowInsert(
            "3-switch", key, "2026-09-25", "fixture-monitor", "Compute", "Critical",
            "[MONITOR][fan][fan2] observed",
        )
        history = writer.HistoryAppend("3-switch", key, "2026-09-25T08:00:00Z", "fixture insert")
        prepared = prepare_fake_local_workbook(
            self.path, fixture_manifest(digest, (operation,)), [insert, history],
            expected_template_sha256=digest,
        )
        self.assertIn(("ETH&IB Switch", "F5"), prepared.changed_cells)
        self.assertNotIn(("ETH&IB Switch", "F4"), prepared.changed_cells)
        with zipfile.ZipFile(BytesIO(prepared.xlsx_bytes)) as output:
            self.assertIn(b"NV10003", output.read("xl/worksheets/sheet6.xml"))
            self.assertIn(b"occupied", output.read("xl/worksheets/sheet2.xml"))
        self.assertEqual(raw, self.path.read_bytes())

    def test_switch_insert_conflicts_with_existing_active_activity_key(self):
        raw = fake_workbook(reserved_switch_rows=1)
        self.path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        insert = writer.SwitchRowInsert(
            "2-switch", KEY, "2026-09-25", "fixture-monitor", "Compute", "Critical",
            "[MONITOR][fan][fan1] observed",
        )
        history = writer.HistoryAppend("2-switch", KEY, "2026-09-25T08:00:00Z", "fixture insert")
        with self.assertRaisesRegex(LocalWorkbookHold, "duplicate active"):
            prepare_fake_local_workbook(
                self.path, fixture_manifest(digest), [insert, history],
                expected_template_sha256=digest,
            )
        self.assertEqual(raw, self.path.read_bytes())

    def test_eth_ib_cabling_edits_without_bound_az_or_ib_authority_hold(self):
        for sheet, key in (
            ("ETH Cabling", ("eth_cabling", "leaf01", "swp1", "Link Down")),
            ("IB Cabling", ("ib_cabling", "leaf01", "swp1", "Link Down")),
        ):
            with self.subTest(sheet=sheet):
                edit = writer.CablingRowEdit("1-cabling", key, sheet, "append")
                with self.assertRaisesRegex(LocalWorkbookHold, "endpoint|IB authority"):
                    prepare_fake_local_workbook(
                        self.path, self.manifest, [edit], expected_template_sha256=self.digest,
                    )
                self.assertEqual(self.raw, self.path.read_bytes())

    def test_nonempty_held_whitelist_allows_only_unmatched_frozen_switch_update(self):
        raw = fake_workbook(whitelist_rules=("spine*",))
        snapshot, qualified, body, manifest_id = self.nonempty_frozen(raw)
        result = prepare_fake_local_workbook(
            self.path, body, [self.edit], expected_template_sha256=snapshot.workbook_sha256,
            qualified_set=qualified, expected_manifest_id=manifest_id,
        )
        self.assertEqual(raw, self.path.read_bytes())
        self.assertEqual(manifest_id, result.manifest_id)
        self.assertEqual((("ETH&IB Switch", "L3"),), result.changed_cells)
        with zipfile.ZipFile(BytesIO(raw)) as before, zipfile.ZipFile(BytesIO(result.xlsx_bytes)) as after:
            for name in before.namelist():
                if name != "xl/worksheets/sheet2.xml":
                    self.assertEqual(before.read(name), after.read(name), name)

    def test_nonempty_matching_skip_and_forged_body_id_cannot_restore_operation(self):
        raw = fake_workbook(whitelist_rules=("leaf*",))
        snapshot, qualified, body, manifest_id = self.nonempty_frozen(raw)
        self.assertEqual(b"[]", qualified.operations_json)
        self.assertIn(b"2-switch", qualified.whitelist_skips_json)
        with self.assertRaisesRegex(LocalWorkbookHold, "Whitelist|skip"):
            prepare_fake_local_workbook(
                self.path, body, [self.edit], expected_template_sha256=snapshot.workbook_sha256,
                qualified_set=qualified, expected_manifest_id=manifest_id,
            )
        parsed = json.loads(body)
        parsed["operations"] = [SWITCH]
        forged = json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        with self.assertRaises(LocalWorkbookHold):
            prepare_fake_local_workbook(
                self.path, forged, [self.edit], expected_template_sha256=snapshot.workbook_sha256,
                qualified_set=qualified, expected_manifest_id=hashlib.sha256(forged).hexdigest(),
            )
        self.assertEqual(raw, self.path.read_bytes())

    def test_nonempty_missing_or_drifted_held_authority_and_invalid_rule_hold(self):
        raw = fake_workbook(whitelist_rules=("spine*",))
        snapshot, qualified, body, manifest_id = self.nonempty_frozen(raw)
        for changes in (
            {},
            {"qualified_set": qualified, "expected_manifest_id": "0" * 64},
            {"qualified_set": qualified, "expected_manifest_id": manifest_id,
             "expected_template_sha256": "0" * 64},
            {"qualified_set": replace(qualified, pre_filter_operations_json=b"[]"),
             "expected_manifest_id": manifest_id},
            {"qualified_set": replace(qualified, whitelist_snapshot=replace(
                snapshot, inode=snapshot.inode + 1)),
             "expected_manifest_id": manifest_id},
        ):
            with self.subTest(changes=changes), self.assertRaises(LocalWorkbookHold):
                expected = changes.get("expected_template_sha256", snapshot.workbook_sha256)
                prepare_fake_local_workbook(
                    self.path, body, [self.edit],
                    expected_template_sha256=expected,
                    **{key: value for key, value in changes.items() if key != "expected_template_sha256"},
                )
        drifted = fake_workbook(whitelist_rules=("leaf*",))
        self.path.write_bytes(drifted)
        with self.assertRaises(LocalWorkbookHold):
            prepare_fake_local_workbook(
                self.path, body, [self.edit],
                expected_template_sha256=hashlib.sha256(drifted).hexdigest(),
                qualified_set=qualified, expected_manifest_id=manifest_id,
            )
        self.assertEqual(drifted, self.path.read_bytes())
        self.path.write_bytes(fake_workbook(whitelist_rules=("re:[",)))
        corrupt_digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        with self.assertRaises(LocalWorkbookHold):
            prepare_fake_local_workbook(
                self.path, body, [self.edit], expected_template_sha256=corrupt_digest,
                qualified_set=qualified, expected_manifest_id=manifest_id,
            )


if __name__ == "__main__":
    unittest.main()
