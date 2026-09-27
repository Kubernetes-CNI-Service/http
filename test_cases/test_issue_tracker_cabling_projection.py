"""REQ7 C6 workbook-image contracts; typed rows are not source authority."""

from dataclasses import replace
from io import BytesIO
from pathlib import Path
import tempfile
import unittest
import warnings
import xml.etree.ElementTree as ET
import zipfile

from monitor.issue_tracker_local_workbook import (
    CablingSourceRow, LocalWorkbookHold, project_cabling_workbook_image,
    validate_operator_edited_workbook,
)
from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
from test_cases.test_issue_tracker_local_workbook import fake_workbook


MAIN = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
ETH = ("eth_cabling", "leaf01", "swp1", "Link Down")
IB = ("ib_cabling", "ib-leaf01", "1/1", "Link Down")


def _repack(raw, overrides):
    output = BytesIO()
    with zipfile.ZipFile(BytesIO(raw)) as source, zipfile.ZipFile(output, "w") as target:
        for member in source.infolist():
            target.writestr(member, overrides.get(member.filename, source.read(member.filename)))
    return output.getvalue()


def _sheet(raw, number):
    with zipfile.ZipFile(BytesIO(raw)) as archive:
        return ET.fromstring(archive.read(f"xl/worksheets/sheet{number}.xml"))


def _cell(root, address):
    return root.find(".//" + MAIN + "c[@r='" + address + "']")


def _value(root, address):
    cell = _cell(root, address)
    if cell is None:
        return None
    inline = cell.find(MAIN + "is")
    return "".join(inline.itertext()) if inline is not None else None


def _set(root, row_number, address, value):
    row = root.find(".//" + MAIN + f"row[@r='{row_number}']")
    if row is None:
        row = ET.SubElement(root.find(MAIN + "sheetData"), MAIN + "row", {"r": str(row_number)})
    cell = _cell(row, address)
    if cell is None:
        cell = ET.SubElement(row, MAIN + "c", {"r": address})
    for child in list(cell):
        cell.remove(child)
    cell.set("t", "inlineStr")
    ET.SubElement(ET.SubElement(cell, MAIN + "is"), MAIN + "t").text = value


class CablingProjectionTests(unittest.TestCase):
    def setUp(self):
        self.base = fake_workbook()
        self.eth = CablingSourceRow(
            sheet="ETH Cabling", activity_key=ETH,
            expected_endpoints=("leaf01", "swp1", "spine01", "swp9"),
            actual_endpoints=("spine02", "swp8", "leaf01", "swp1"),
            source_status="DOWN", evidence_description="observed peer down",
            recorded_at_utc="2026-09-26T03:00:00Z",
        )
        self.ib = CablingSourceRow(
            sheet="IB Cabling", activity_key=IB,
            expected_endpoints=("ib-leaf01", "1/1", "ib-spine01", "2/1"),
            actual_endpoints=(), source_status="MISSING_DEVICE",
            evidence_description="expected peer absent",
            recorded_at_utc="2026-09-26T03:00:00Z",
        )

    def test_shared_sequence_and_exact_business_columns(self):
        projected = project_cabling_workbook_image(self.base, (self.eth, self.ib))
        eth, ib, history = (_sheet(projected, n) for n in (3, 4, 6))
        self.assertEqual(_value(eth, "A3"), "NV30001")
        self.assertEqual(_value(ib, "A3"), "NV30002")
        self.assertEqual(tuple(_value(eth, col + "3") for col in ("F", "K", "L", "Q", "R", "M", "N", "S", "T", "U")),
                         ("Link Down", "leaf01", "swp1", "spine01", "swp9", "spine02", "swp8", "leaf01", "swp1", "New"))
        self.assertEqual(tuple(_value(ib, col + "3") for col in ("M", "N", "S", "T")),
                         (None, None, None, None))
        self.assertEqual((_value(history, "B3"), _value(history, "C3"), _value(history, "D3")),
                         ("ETH Cabling", "Insert", "NV30001"))
        self.assertEqual((_value(history, "B4"), _value(history, "C4"), _value(history, "D4")),
                         ("IB Cabling", "Insert", "NV30002"))
        self.assertEqual(project_cabling_workbook_image(self.base, (self.ib, self.eth)), projected)
        self.assertEqual(project_cabling_workbook_image(projected, (self.eth, self.ib)), projected)
        with zipfile.ZipFile(BytesIO(self.base)) as before, zipfile.ZipFile(BytesIO(projected)) as after:
            self.assertEqual(before.namelist(), after.namelist())
            for name in before.namelist():
                if name not in {"xl/worksheets/sheet3.xml", "xl/worksheets/sheet4.xml", "xl/worksheets/sheet6.xml"}:
                    self.assertEqual(before.read(name), after.read(name), name)

    def test_upsert_retains_operator_cells_and_closed_recurrence_allocates_new_id(self):
        first = project_cabling_workbook_image(self.base, (self.eth,))
        sheet = _sheet(first, 3)
        _set(sheet, 3, "X3", "owner note")
        _set(sheet, 3, "Y3", "assigned engineer")
        edited = _repack(first, {"xl/worksheets/sheet3.xml": ET.tostring(sheet)})
        accepted = validate_operator_edited_workbook(first, edited)
        second = project_cabling_workbook_image(
            accepted, (replace(self.eth, evidence_description="new observation"),))
        sheet = _sheet(second, 3)
        self.assertEqual(_value(sheet, "A3"), "NV30001")
        self.assertIn("new observation", _value(sheet, "G3"))
        self.assertEqual((_value(sheet, "X3"), _value(sheet, "Y3")),
                         ("owner note", "assigned engineer"))
        _set(sheet, 3, "U3", "Closed")
        closed = _repack(second, {"xl/worksheets/sheet3.xml": ET.tostring(sheet)})
        self.assertEqual(validate_operator_edited_workbook(second, closed), closed)
        with self.assertRaises(LocalWorkbookHold):
            validate_operator_edited_workbook(second, closed, disallow_unproved_closure=True)
        recurrent = project_cabling_workbook_image(closed, (self.eth,))
        self.assertEqual(_value(_sheet(recurrent, 3), "A4"), "NV30002")

    def test_invalid_source_duplicate_key_and_duplicate_workbook_member_hold(self):
        with self.assertRaises(LocalWorkbookHold):
            project_cabling_workbook_image(self.base, (replace(self.ib, actual_endpoints=("invented", "1", "invented", "2")),))
        with self.assertRaises(LocalWorkbookHold):
            project_cabling_workbook_image(self.base, (self.eth, self.eth))
        output = BytesIO(self.base)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(output, "a") as archive:
                archive.writestr("xl/workbook.xml", archive.read("xl/workbook.xml"))
        with self.assertRaises(LocalWorkbookHold):
            project_cabling_workbook_image(output.getvalue(), (self.eth,))
        with self.assertRaises(LocalWorkbookHold):
            validate_operator_edited_workbook(output.getvalue(), output.getvalue())

    def test_duplicate_existing_ids_and_active_keys_fail_closed(self):
        first = project_cabling_workbook_image(self.base, (self.eth,))
        ib = _sheet(first, 4)
        _set(ib, 3, "A3", "NV30001")
        duplicate_id = _repack(first, {"xl/worksheets/sheet4.xml": ET.tostring(ib)})
        with self.assertRaises(LocalWorkbookHold):
            project_cabling_workbook_image(duplicate_id, (self.ib,))

        eth = _sheet(first, 3)
        for column in ("A", "F", "G", "K", "L", "U"):
            _set(eth, 4, column + "4", _value(eth, column + "3") if column != "A" else "NV30002")
        duplicate_key = _repack(first, {"xl/worksheets/sheet3.xml": ET.tostring(eth)})
        with self.assertRaises(LocalWorkbookHold):
            project_cabling_workbook_image(duplicate_key, (self.eth,))

    def test_changed_header_and_formula_as_operator_cell_hold(self):
        with self.assertRaises(LocalWorkbookHold):
            project_cabling_workbook_image(fake_workbook(bad_header="eth"), (self.eth,))
        first = project_cabling_workbook_image(self.base, (self.eth,))
        eth = _sheet(first, 3)
        row = eth.find(".//" + MAIN + "row[@r='3']")
        ET.SubElement(ET.SubElement(row, MAIN + "c", {"r": "X3"}), MAIN + "f").text = "1+1"
        forged = _repack(first, {"xl/worksheets/sheet3.xml": ET.tostring(eth)})
        with self.assertRaises(LocalWorkbookHold):
            validate_operator_edited_workbook(first, forged)

    def test_real_whitelist_reader_then_projection_does_not_change_template_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authority.xlsx"
            path.write_bytes(self.base)
            snapshot = read_whitelist_workbook(path)
            self.assertEqual(snapshot.workbook_sha256,
                             __import__("hashlib").sha256(self.base).hexdigest())
            projected = project_cabling_workbook_image(path.read_bytes(), (self.eth,))
            self.assertEqual(path.read_bytes(), self.base)
            self.assertEqual(_value(_sheet(projected, 3), "A3"), "NV30001")


if __name__ == "__main__":
    unittest.main()
