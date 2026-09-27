"""REQ7 C6 Switch workbook-image and operator/formula preservation contracts."""

from dataclasses import replace
from io import BytesIO
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import zipfile

from monitor.issue_tracker_local_workbook import (
    LocalWorkbookHold, SwitchSourceWorkbookRow, project_switch_workbook_image,
    validate_operator_edited_workbook,
)
from monitor import issue_tracker_local_workbook as workbook
from test_cases.test_issue_tracker_cabling_projection import _cell, _repack, _set, _sheet, _value
from test_cases.test_issue_tracker_local_workbook import fake_workbook


MAIN = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"


class SwitchProjectionTests(unittest.TestCase):
    def setUp(self):
        self.base = fake_workbook(reserved_switch_rows=2, existing_switch_id="NV10001")
        self.new = SwitchSourceWorkbookRow(
            activity_key=("switch", "leaf02", "fan", "PSU1/FAN"),
            evidence_description="PSU1/FAN state=fail", fabric="Inband",
            fabric_source="template", priority="P2",
            recorded_at_utc="2026-09-26T03:00:00Z",
        )

    def test_insert_uses_reserved_id_keeps_formulas_and_operator_columns(self):
        projected = project_switch_workbook_image(self.base, (self.new,))
        sheet, history = _sheet(projected, 2), _sheet(projected, 6)
        self.assertEqual(tuple(_value(sheet, col + "4") for col in ("A", "F", "J", "K", "N")),
                         ("NV10002", "leaf02", "Inband", "P2", "New"))
        self.assertIn("[MONITOR][fan][PSU1/FAN]", _value(sheet, "L4"))
        self.assertIn("fabric_source=template", _value(sheet, "L4"))
        for column in "DEGH":
            self.assertIsNotNone(_cell(sheet, column + "4").find(MAIN + "f"))
        self.assertIsNone(_cell(sheet, "I4").find(MAIN + "f"))
        self.assertIsNone(_value(sheet, "I4"))
        self.assertEqual((_value(sheet, "M4"), _value(sheet, "O4"), _value(sheet, "U4")),
                         (None, None, None))
        self.assertEqual((_value(history, "B3"), _value(history, "C3"), _value(history, "D3")),
                         ("ETH&IB Switch", "Insert", "NV10002"))
        self.assertEqual(project_switch_workbook_image(projected, (self.new,)), projected)

    def test_existing_row_updates_only_description_and_retains_operator_edits(self):
        source = self.base
        sheet = _sheet(source, 2)
        _set(sheet, 3, "O3", "new human owner")
        edited = _repack(source, {"xl/worksheets/sheet2.xml": ET.tostring(sheet)})
        self.assertEqual(validate_operator_edited_workbook(source, edited), edited)
        update = replace(self.new,
                         activity_key=("switch", "leaf01", "fan", "fan1"),
                         fabric="Compute", fabric_source="hostname-fallback",
                         evidence_description="fan1 state=fail")
        output = project_switch_workbook_image(edited, (update,))
        sheet = _sheet(output, 2)
        self.assertEqual(_value(sheet, "O3"), "new human owner")
        self.assertEqual(_value(sheet, "U3"), "human-comment")
        self.assertIn("fabric_source=hostname-fallback", _value(sheet, "L3"))
        self.assertIsNotNone(_cell(sheet, "D3").find(MAIN + "f"))
        self.assertEqual(_value(sheet, "F4"), None)

    def test_source_or_structure_forgery_is_not_an_operator_edit(self):
        source = self.base
        sheet = _sheet(source, 2)
        _set(sheet, 3, "L3", "forged source")
        forged = _repack(source, {"xl/worksheets/sheet2.xml": ET.tostring(sheet)})
        with self.assertRaises(LocalWorkbookHold):
            validate_operator_edited_workbook(source, forged)
        with self.assertRaises(LocalWorkbookHold):
            project_switch_workbook_image(self.base, (replace(self.new, fabric_source="guess"),))
        with self.assertRaises(LocalWorkbookHold):
            project_switch_workbook_image(self.base, (self.new, self.new))

    def test_two_insertions_have_stable_reserved_assignment(self):
        other = replace(self.new, activity_key=("switch", "leaf03", "fan", "fan3"),
                        evidence_description="fan3 state=fail")
        self.assertEqual(project_switch_workbook_image(self.base, (self.new, other)),
                         project_switch_workbook_image(self.base, (other, self.new)))
        first = project_switch_workbook_image(self.base, (self.new, other))
        sheet = _sheet(first, 2)
        self.assertEqual((_value(sheet, "A4"), _value(sheet, "A5")),
                         ("NV10002", "NV10003"))

    def test_postimage_formula_readback_rejects_corrupted_repack(self):
        original = workbook._repack_projected

        def corrupt(*args):
            result = original(*args)
            switch = _sheet(result, 2)
            _set(switch, 4, "D4", "not a formula")
            return _repack(result, {"xl/worksheets/sheet2.xml": ET.tostring(switch)})

        with mock.patch.object(workbook, "_repack_projected", side_effect=corrupt):
            with self.assertRaises(LocalWorkbookHold):
                project_switch_workbook_image(self.base, (self.new,))


if __name__ == "__main__":
    unittest.main()
