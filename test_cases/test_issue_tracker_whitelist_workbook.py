"""Independent OOXML fixtures for the C-24 local workbook read boundary."""

from __future__ import annotations

from html import escape
from io import BytesIO
from pathlib import Path
import hashlib
import tempfile
import unittest
from unittest import mock
import zipfile

from monitor.issue_tracker_whitelist import WhitelistHoldError
from monitor import issue_tracker_whitelist_workbook as reader


SHEETS = (
    "GPU Server", "ETH&IB Switch", "ETH Cabling", "IB Cabling", "Dashboard",
    "Update_History", "Inventory", "ServerProfile", "PortProfile", "CVT_SUM",
    "CVT_Import", "Agent_status", "Whitelist", "BasicData",
)
HEADER = (
    "Submit Date", "Submitor", "Datahalll", "Rack", "Device Name", "Comments",
)


def literal_xlsx(*, names=SHEETS, header=HEADER, rules=(), shared=False,
                 whitelist_target=None, extra_members=0, extra_header_cell=None):
    """Make a small literal ZIP/XML workbook, independent of product parsing."""
    sheets_xml = "".join(
        f'<sheet name="{escape(name)}" sheetId="{n}" r:id="rId{n}"/>'
        for n, name in enumerate(names, 1)
    )
    relationships = "".join(
        '<Relationship Id="rId{n}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="{target}"/>'.format(
            n=n, target=(whitelist_target if name == "Whitelist" and whitelist_target
                         else f"worksheets/sheet{n}.xml"),
        ) for n, name in enumerate(names, 1)
    )
    workbook = (
        '<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org/'
        'spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/'
        'officeDocument/2006/relationships"><sheets>' + sheets_xml +
        '</sheets></workbook>'
    )
    rels = (
        '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/'
        'package/2006/relationships">' + relationships + '</Relationships>'
    )
    strings = (*header, *rules)

    def cell(col, row, value):
        if shared:
            return f'<c r="{col}{row}" t="s"><v>{strings.index(value)}</v></c>'
        return f'<c r="{col}{row}" t="inlineStr"><is><t>{escape(value)}</t></is></c>'

    header_xml = ''.join(cell(chr(65 + i), 1, text) for i, text in enumerate(header))
    if extra_header_cell is not None:
        header_xml += cell(extra_header_cell, 1, "unexpected")
    rows = ['<row r="1">' + header_xml + '</row>']
    rows.extend(f'<row r="{n}">{cell("E", n, rule)}</row>'
                for n, rule in enumerate(rules, 2))
    whitelist_xml = (
        '<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/'
        'spreadsheetml/2006/main"><sheetData>' + ''.join(rows) +
        '</sheetData></worksheet>'
    )
    empty_xml = ('<?xml version="1.0"?><worksheet '
                 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                 '<sheetData/></worksheet>')
    result = BytesIO()
    with zipfile.ZipFile(result, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", rels)
        if shared:
            shared_xml = ('<?xml version="1.0"?><sst xmlns="http://schemas.openxmlformats.org/'
                          'spreadsheetml/2006/main">' + ''.join(
                              f'<si><t>{escape(text)}</t></si>' for text in strings
                          ) + '</sst>')
            archive.writestr("xl/sharedStrings.xml", shared_xml)
        for n, name in enumerate(names, 1):
            archive.writestr(f"xl/worksheets/sheet{n}.xml",
                             whitelist_xml if name == "Whitelist" else empty_xml)
        for n in range(extra_members):
            archive.writestr(f"unrelated/{n}.txt", "x")
    return result.getvalue()


class WhitelistWorkbookTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "tracker.xlsx"

    def write(self, **options):
        self.path.write_bytes(literal_xlsx(**options))
        return self.path

    def test_actual_inline_rule_values_are_frozen_with_workbook_identity(self):
        path = self.write(rules=(" Leaf-01 ", "spine-*"))
        result = reader.read_whitelist_workbook(path)
        self.assertEqual(("leaf-01", "spine-*"), result.whitelist.rules)
        self.assertEqual(len(path.read_bytes()), result.workbook_size)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                         result.workbook_sha256)

    def test_shared_strings_and_legally_empty_sheet(self):
        result = reader.read_whitelist_workbook(self.write(shared=True))
        self.assertEqual((), result.whitelist.rules)
        self.assertEqual(hashlib.sha256(b"[]\n").hexdigest(),
                         result.whitelist.sha256)

    def test_missing_sheet_or_bad_header_holds(self):
        for options in ({"names": tuple(name for name in SHEETS if name != "Whitelist")},
                        {"header": (*HEADER[:4], "Wrong", HEADER[5])}):
            with self.subTest(options=options):
                with self.assertRaises(WhitelistHoldError):
                    reader.read_whitelist_workbook(self.write(**options))

    def test_multiletter_column_is_rejected_as_a_typed_hold(self):
        # AB is a valid OOXML column address, but outside the six-column
        # whitelist schema.  It must not leak a parser TypeError.
        with self.assertRaises(WhitelistHoldError):
            reader.read_whitelist_workbook(self.write(extra_header_cell="AB"))

    def test_invalid_regex_and_corrupt_zip_hold(self):
        with self.assertRaises(WhitelistHoldError):
            reader.read_whitelist_workbook(self.write(rules=("re:[bad",)))
        self.path.write_bytes(b"not a workbook")
        with self.assertRaises(WhitelistHoldError):
            reader.read_whitelist_workbook(self.path)

    def test_unsafe_relationship_oversized_source_and_member_count_hold(self):
        with self.assertRaises(WhitelistHoldError):
            reader.read_whitelist_workbook(
                self.write(whitelist_target="../foreign.xml"),
            )
        path = self.write()
        with mock.patch.object(reader, "_MAX_FILE_BYTES", path.stat().st_size - 1):
            with self.assertRaises(WhitelistHoldError):
                reader.read_whitelist_workbook(path)
        with self.assertRaises(WhitelistHoldError):
            reader.read_whitelist_workbook(self.write(extra_members=250))

    def test_symlink_and_nonregular_source_hold(self):
        real = self.write()
        link = Path(self.tmp.name) / "alias.xlsx"
        link.symlink_to(real)
        for path in (link, Path(self.tmp.name)):
            with self.subTest(path=path), self.assertRaises(WhitelistHoldError):
                reader.read_whitelist_workbook(path)

    def test_same_inode_byte_change_during_parse_holds(self):
        path = self.write()
        original = reader._parse_xlsx_bytes

        def mutate_after_parse(data):
            parsed = original(data)
            with path.open("r+b") as stream:
                stream.seek(10)
                byte = stream.read(1)
                stream.seek(10)
                stream.write(bytes([byte[0] ^ 1]))
            return parsed

        with mock.patch.object(reader, "_parse_xlsx_bytes", side_effect=mutate_after_parse):
            with self.assertRaises(WhitelistHoldError):
                reader.read_whitelist_workbook(path)


if __name__ == "__main__":
    unittest.main()
