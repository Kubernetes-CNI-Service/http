"""Independent C-24 read-only online Whitelist, never refiltering or admission."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_req7_sheets_read_plan as plan_fixture

MODULE = Path(__file__).resolve().parents[1] / "monitor/issue_tracker_online_whitelist_read.py"
HEADER = ("Submit Date", "Submitor", "Datahalll", "Rack", "Device Name", "Comments")


def load():
    if not MODULE.is_file(): raise AssertionError("REQ7 online Whitelist read comparison missing")
    # Bind the actual isolated dependency under its production import name;
    # never stub decoding or place unreviewed candidates in the main tree.
    from test_req7_sheets_read_decode import load as load_decoder
    load_decoder()
    spec = importlib.util.spec_from_file_location("req7_online_whitelist_read_candidate", MODULE)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module); return module


def document(rules=(" Leaf-01 ", "SPINE-*")):
    rows = [{"values": [{"userEnteredValue": {"stringValue": value}} for value in HEADER]}]
    rows.extend({"values": [{}, {}, {}, {}, {"userEnteredValue": {"stringValue": rule}}]} for rule in rules)
    return {"spreadsheetId": "synthetic_spreadsheet_id_0001", "sheets": [{
        "properties": {"sheetId": 12, "title": "Whitelist", "gridProperties": {"rowCount": 100, "columnCount": 6}},
        "data": [{"rowData": rows}],
    }]}


def response(value):
    return SimpleNamespace(status=200, complete=True, data=json.dumps(value, allow_nan=False).encode())


class Req7OnlineWhitelistReadDirectTests(unittest.TestCase):
    def setUp(self):
        plan_fixture.Req7SheetsReadPlanDirectTests.setUp(self)
        self.planner = self.module; self.module = load()
        from monitor.issue_tracker_whitelist import freeze_whitelist_sheet
        self.local = freeze_whitelist_sheet([HEADER, (None, None, None, None, "leaf-01", None),
                                             (None, None, None, None, "spine-*", None)])

    def plan(self):
        return self.planner.prepare_online_whitelist_read(self.binding, self.token)

    def test_read_shape_has_one_fixed_bounded_range_and_required_grid_capacity(self):
        with mock.patch("socket.socket", side_effect=AssertionError("no network in plan")):
            plan = self.plan()
        query = parse_qs(urlsplit(plan.path).query, strict_parsing=True)
        self.assertEqual(["'Whitelist'!A1:F10000"], query["ranges"])
        self.assertEqual(["spreadsheetId,sheets(properties(sheetId,title,gridProperties(rowCount,columnCount)),data(startRow,startColumn,rowData(values(userEnteredValue))))"], query["fields"])
        self.assertEqual("GET", plan.method); self.assertEqual(b"", plan.body)
        self.assertFalse(hasattr(plan, "mutation_permit")); self.assertNotIn(self.token.value, repr(plan))

    def test_normalized_rules_must_match_frozen_local_input_without_refiltering(self):
        value = self.module.compare_online_whitelist_read(self.plan(), response(document()), self.local)
        self.assertEqual(self.local.sha256, value.rules_sha256)
        self.assertEqual(12, value.sheet_id); self.assertEqual(100, value.row_count)
        self.assertFalse(hasattr(value, "admitted")); self.assertFalse(hasattr(value, "mutation_permit"))
        self.assertNotIn("leaf-01", repr(value))
        for rules in (("leaf-02", "spine-*"), ("re:[bad",), ()):
            with self.subTest(rules=rules), self.assertRaises(self.module.OnlineWhitelistReadHold) as caught:
                self.module.compare_online_whitelist_read(self.plan(), response(document(rules)), self.local)
            self.assertEqual("req7_online_whitelist_unproved", str(caught.exception))
            self.assertIsNone(caught.exception.__context__)

    def test_legally_empty_complete_sheet_matches_only_empty_frozen_local_snapshot(self):
        from monitor.issue_tracker_whitelist import freeze_whitelist_sheet
        empty = freeze_whitelist_sheet([HEADER])
        value = self.module.compare_online_whitelist_read(self.plan(), response(document(())), empty)
        self.assertEqual(empty.sha256, value.rules_sha256)
        missing = document(()); missing["sheets"][0]["data"] = []
        with self.assertRaises(self.module.OnlineWhitelistReadHold):
            self.module.compare_online_whitelist_read(self.plan(), response(missing), empty)

    def test_capacity_missing_identity_extra_rows_and_wrong_grid_cannot_be_called_complete(self):
        variants = []
        for key, value in (("rowCount", True), ("rowCount", 0), ("rowCount", 10001), ("columnCount", 5), ("columnCount", True)):
            raw = document(); raw["sheets"][0]["properties"]["gridProperties"][key] = value; variants.append(raw)
        for key, value in (("startRow", 1), ("startColumn", 1), ("startRow", True)):
            raw = document(); raw["sheets"][0]["data"][0][key] = value; variants.append(raw)
        raw = document(); raw["sheets"][0]["properties"]["gridProperties"]["rowCount"] = 1; variants.append(raw)
        raw = document(); del raw["sheets"][0]["properties"]["gridProperties"]; variants.append(raw)
        raw = document(); raw["spreadsheetId"] = "foreign_spreadsheet_id_0002"; variants.append(raw)
        raw = document(); raw["sheets"][0]["properties"]["title"] = "ETH Cabling"; variants.append(raw)
        raw = document(); raw["sheets"][0]["properties"]["sheetId"] = True; variants.append(raw)
        raw = document(); raw["sheets"] *= 2; variants.append(raw)
        for raw in variants:
            with self.subTest(index=variants.index(raw)), self.assertRaises(self.module.OnlineWhitelistReadHold) as caught:
                self.module.compare_online_whitelist_read(self.plan(), response(raw), self.local)
            self.assertIsNone(caught.exception.__context__)

    def test_formulas_numbers_nonliteral_headers_or_populated_row_without_device_refuse(self):
        variants = []
        for entered in ({"formulaValue": '="leaf-01"'}, {"numberValue": 0}, {"boolValue": False}, {"stringValue": ""}):
            raw = document(); raw["sheets"][0]["data"][0]["rowData"][1]["values"][4] = {"userEnteredValue": entered}
            if entered == {"stringValue": ""}:
                raw["sheets"][0]["data"][0]["rowData"][1]["values"][0] = {"userEnteredValue": {"stringValue": "orphan"}}
            variants.append(raw)
        raw = document(); raw["sheets"][0]["data"][0]["rowData"][0]["values"][4] = {"userEnteredValue": {"stringValue": "device name"}}; variants.append(raw)
        raw = document(); raw["sheets"][0]["data"][0]["rowData"][1]["values"].append({}); raw["sheets"][0]["data"][0]["rowData"][1]["values"].append({"userEnteredValue": {"stringValue": "hidden"}}); variants.append(raw)
        for raw in variants:
            with self.subTest(index=variants.index(raw)), self.assertRaises(self.module.OnlineWhitelistReadHold):
                self.module.compare_online_whitelist_read(self.plan(), response(raw), self.local)

    def test_duplicate_json_non200_incomplete_and_forged_local_digest_are_sanitized(self):
        from dataclasses import replace
        bad = (SimpleNamespace(status=200, complete=True, data=b'{"sheets":[],"sheets":[]}'),
               SimpleNamespace(status=503, complete=True, data=b"sentinel private"),
               SimpleNamespace(status=200, complete=False, data=b"sentinel private"))
        for raw in bad:
            with self.assertRaises(self.module.OnlineWhitelistReadHold) as caught:
                self.module.compare_online_whitelist_read(self.plan(), raw, self.local)
            self.assertIsNone(caught.exception.__context__)
        with self.assertRaises(self.module.OnlineWhitelistReadHold):
            self.module.compare_online_whitelist_read(self.plan(), response(document()), replace(self.local, sha256="0" * 64))


class Req7OnlineWhitelistReadWorkflowTests(unittest.TestCase):
    setUp = plan_fixture.Req7SheetsNativeReadWorkflowTests.setUp
    fixture = plan_fixture.Req7SheetsNativeReadWorkflowTests.fixture
    certificates = plan_fixture.Req7SheetsNativeReadWorkflowTests.certificates
    server = plan_fixture.Req7SheetsNativeReadWorkflowTests.server

    def test_actual_native_get_compares_real_local_workbook_snapshot_without_changing_it(self):
        from test_req7_sdk_authentication import load as load_auth
        from monitor.issue_tracker_online_target import OnlineTargetBinding
        from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
        from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
        import tempfile, time
        auth = load_auth(); planner = plan_fixture.load(); compare = load()
        binding = OnlineTargetBinding("synthetic_spreadsheet_id_0001", "a" * 64, "b" * 64)
        token = auth.AuthenticatedToken("sentinel.private-token", time.time() + 3600)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owned.xlsx"; raw = literal_xlsx(rules=("leaf-01", "spine-*")); path.write_bytes(raw)
            local = read_whitelist_workbook(path).whitelist
            payload = json.dumps(document()).encode()
            reply = ("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(payload)).encode() + payload
            unit = self.module.NativeOnlineWhitelistReadUnit(binding, token)
            with self.server(reply, hostname="sheets.googleapis.com", destination="sheets.googleapis.com") as (records, errors):
                with self.fixture(): observed = compare.compare_online_whitelist_read(planner.prepare_online_whitelist_read(binding, token), unit.send_once(), local)
            self.assertEqual([], errors); self.assertEqual(1, len(records)); self.assertEqual(raw, path.read_bytes())
            self.assertEqual(local.sha256, observed.rules_sha256)
            self.assertEqual(["'Whitelist'!A1:F10000"], parse_qs(urlsplit(records[0][0].decode().split(" ")[1]).query)["ranges"])
            self.assertFalse(hasattr(observed, "mutation_permit"))


if __name__ == "__main__": unittest.main()
