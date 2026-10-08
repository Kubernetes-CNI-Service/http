"""Independent exact-grid response checks; a read image grants no write permit."""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from dataclasses import replace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_req7_sheets_read_plan as plan_fixture

MODULE = Path(__file__).resolve().parents[1] / "monitor/issue_tracker_sheets_read_decode.py"


def load():
    if not MODULE.is_file(): raise AssertionError("REQ7 complete bound Sheets read decoder missing")
    from test_cases.test_req7_history_read import load as canonical_loader
    return canonical_loader('issue_tracker_sheets_read_decode',path=MODULE)


def row_response():
    cells = [{} for _ in range(21)]
    cells[0] = {"userEnteredValue": {"stringValue": "NV30017"}}
    for index in (3, 4, 6, 7, 8): cells[index] = {"userEnteredValue": {"formulaValue": "=synthetic_lookup()"}}
    return {"spreadsheetId": "synthetic_spreadsheet_id_0001", "sheets": [{
        "properties": {"sheetId": 17, "title": "ETH&IB Switch"},
        "data": [{"startRow": 2, "startColumn": 0, "rowData": [{"values": cells}]}],
    }]}


def response(value):
    return SimpleNamespace(status=200, complete=True, data=json.dumps(value, allow_nan=False).encode())


# Independent literal format expectations, not imported from product constants.
TEMPLATE_SHEETS = ("GPU Server", "ETH&IB Switch", "ETH Cabling", "IB Cabling", "Dashboard", "Update_History",
                   "Inventory", "ServerProfile", "PortProfile", "CVT_SUM", "CVT_Import", "Agent_status", "Whitelist", "BasicData")
SWITCH_HEADER = ("Issue#", "Submit Date", "Submitor", "Rack", "RU", "Host Name", "OOB IP", "SN", "Model", "Fabric",
                 "Priority", "Issue Description", "NVEX Case ID", "Status", "Owner", "Action Description", "P-Status",
                 "Replacement SN", "Replacement ETH0 MAC", "Remark \n(Partner)", "Remark\n(NV)")
CABLING_HEADER = ("Fault ID", "Source", "Requested by", "Date opened", "Link Type", "Issue Type", "Issue Desc", "A-SU",
                  "A-Rack", "A-RU", "A-Node", "A-Port", "A Actual Node", "A Actual Port", "Z-Rack", "Z-RU", "Z-Node", "Z-Port",
                  "Z Actual Node", "Z Actual Port", "Status", "Notes", "AI Recommendation (Refer only)", "NV Comments", "Assigned to",
                  "Engineer Assigned", "Action Description", "P-status", "CVT")
HISTORY_HEADER = ("Timestamp (UTC)", "Sheet", "Action", "Key", "Details")
HEADERS = {"ETH&IB Switch": SWITCH_HEADER, "ETH Cabling": CABLING_HEADER, "IB Cabling": CABLING_HEADER, "Update_History": HISTORY_HEADER}


def identity_response():
    return {"spreadsheetId": "synthetic_spreadsheet_id_0001", "sheets": [
        {"properties": {"sheetId": 100 + i, "title": title}} for i, title in enumerate(TEMPLATE_SHEETS)]}


def header_response():
    return {"spreadsheetId": "synthetic_spreadsheet_id_0001", "sheets": [
        {"properties": {"sheetId": 100 + TEMPLATE_SHEETS.index(title), "title": title},
         "data": [{"startRow": 1, "rowData": [{"values": [
             {"userEnteredValue": {"stringValue": text}} for text in header]}]}]}
        for title, header in HEADERS.items()]}


class Req7TemplateReadDirectTests(unittest.TestCase):
    def setUp(self):
        plan_fixture.Req7SheetsReadPlanDirectTests.setUp(self)
        self.planner = self.module; self.module = load()

    def shapes(self):
        self.assertTrue(hasattr(self.planner, "prepare_template_identity_read"), "template identity plan absent")
        self.assertTrue(hasattr(self.module, "decode_template_identity"), "complete fourteen-sheet identity decoder absent")
        return (self.planner.prepare_template_identity_read(self.binding, self.token),
                self.planner.prepare_template_header_read(self.binding, self.token))

    def test_fourteen_identity_and_four_exact_multiline_headers_are_immutable_necessary_observations(self):
        identity_plan, header_plan = self.shapes()
        raw_identity = response(identity_response()); raw_header = response(header_response())
        observed = self.module.decode_template_identity(identity_plan, raw_identity)
        checked = self.module.decode_template_headers(header_plan, raw_header, observed)
        self.assertEqual(tuple((title, 100 + i) for i, title in enumerate(TEMPLATE_SHEETS)), observed.sheet_ids)
        self.assertEqual(tuple((title, len(header)) for title, header in HEADERS.items()), checked.checked_headers)
        self.assertEqual(hashlib.sha256(raw_identity.data).hexdigest(), checked.identity_sha256)
        self.assertEqual(hashlib.sha256(raw_header.data).hexdigest(), checked.headers_sha256)
        self.assertFalse(hasattr(checked, "mutation_permit")); self.assertFalse(hasattr(checked, "applied"))
        with self.assertRaises(AttributeError): observed.sheet_ids = ()
        with self.assertRaises(AttributeError): checked.checked_headers = ()

    def test_missing_extra_duplicate_and_reused_numeric_sheet_identity_all_hold(self):
        plan, _ = self.shapes(); variants = []
        missing = identity_response(); missing["sheets"].pop(); variants.append(missing)
        extra = identity_response(); extra["sheets"].append({"properties": {"sheetId": 999, "title": "Foreign"}}); variants.append(extra)
        for field, value in (("title", "Whitelist "), ("title", "ETH&IB Switch"), ("sheetId", True), ("sheetId", -1), ("sheetId", 101)):
            item = identity_response(); item["sheets"][0]["properties"][field] = value; variants.append(item)
        extra_data = identity_response(); extra_data["sheets"][0]["data"] = []; variants.append(extra_data)
        for item in variants:
            with self.subTest(case=variants.index(item)), self.assertRaises(self.module.SheetsDecodeHold) as caught:
                self.module.decode_template_identity(plan, response(item))
            self.assertIsNone(caught.exception.__context__)
        reordered = identity_response(); reordered["sheets"].reverse()
        self.assertEqual(tuple((title, 100 + i) for i, title in enumerate(TEMPLATE_SHEETS)),
                         self.module.decode_template_identity(plan, response(reordered)).sheet_ids)

    def test_every_header_cell_requires_exact_original_literal_not_trimmed_formula_or_formatted_text(self):
        identity_plan, header_plan = self.shapes()
        observed = self.module.decode_template_identity(identity_plan, response(identity_response()))
        # Every literal cell is independently changed; no implementation-derived expected value.
        for sheet_index, (title, header) in enumerate(HEADERS.items()):
            for column, original in enumerate(header):
                item = header_response(); item["sheets"][sheet_index]["data"][0]["rowData"][0]["values"][column] = {
                    "userEnteredValue": {"stringValue": original + " "}}
                with self.subTest(sheet=title, column=column), self.assertRaises(self.module.SheetsDecodeHold):
                    self.module.decode_template_headers(header_plan, response(item), observed)
        for value in ({"userEnteredValue": {"formulaValue": '="Issue#"'}}, {"formattedValue": "Issue#"},
                      {"userEnteredValue": {"numberValue": 1}}, {}, {"userEnteredValue": {"stringValue": "Remark (Partner)"}}):
            item = header_response(); item["sheets"][0]["data"][0]["rowData"][0]["values"][0] = value
            with self.subTest(fields=tuple(value)), self.assertRaises(self.module.SheetsDecodeHold):
                self.module.decode_template_headers(header_plan, response(item), observed)

    def test_header_grid_and_prior_sheet_binding_are_not_replaceable_by_row_or_foreign_ids(self):
        identity_plan, header_plan = self.shapes()
        observed = self.module.decode_template_identity(identity_plan, response(identity_response()))
        variants = []
        for field, value in (("startRow", 2), ("startRow", True), ("startColumn", 1)):
            item = header_response(); item["sheets"][0]["data"][0][field] = value; variants.append(item)
        for field, value in (("sheetId", 999), ("title", "GPU Server")):
            item = header_response(); item["sheets"][0]["properties"][field] = value; variants.append(item)
        item = header_response(); item["sheets"].pop(); variants.append(item)
        item = header_response(); item["sheets"].append(deepcopy(item["sheets"][0])); variants.append(item)
        for operation in (lambda grid: grid["rowData"].append({}), lambda grid: grid["rowData"][0]["values"].append({}),
                          lambda grid: grid["rowData"][0]["values"].pop()):
            item = header_response(); operation(item["sheets"][0]["data"][0]); variants.append(item)
        for item in variants:
            with self.subTest(case=variants.index(item)), self.assertRaises(self.module.SheetsDecodeHold):
                self.module.decode_template_headers(header_plan, response(item), observed)
        with self.assertRaises(self.module.SheetsDecodeHold):
            self.module.decode_template_headers(header_plan, response(header_response()), SimpleNamespace(**observed.__dict__))
        with self.assertRaises(self.module.SheetsDecodeHold):
            self.module.decode_template_headers(header_plan, response(header_response()), replace(observed, spreadsheet_id="foreign_spreadsheet_0002"))

    def test_partial_non200_duplicate_json_and_modified_query_never_form_template_evidence(self):
        identity_plan, header_plan = self.shapes()
        observed = self.module.decode_template_identity(identity_plan, response(identity_response()))
        for raw in (SimpleNamespace(status=200, complete=False, data=b"private incomplete"),
                    SimpleNamespace(status=401, complete=True, data=b"private failure"),
                    SimpleNamespace(status=200, complete=True, data=b'{"sheets":[],"sheets":[]}')):
            for decode, plan, args in ((self.module.decode_template_identity, identity_plan, ()),
                                       (self.module.decode_template_headers, header_plan, (observed,))):
                with self.subTest(decoder=decode.__name__), self.assertRaises(self.module.SheetsDecodeHold) as caught:
                    decode(plan, raw, *args)
                self.assertIsNone(caught.exception.__context__); self.assertNotIn("private", str(caught.exception))
        for changed in (replace(header_plan, path=header_plan.path + "&ranges=A%3AZZ"),
                        replace(header_plan, method="POST"), replace(header_plan, budget_seconds=60.0)):
            with self.assertRaises(self.module.SheetsDecodeHold):
                self.module.decode_template_headers(changed, response(header_response()), observed)


class Req7SheetsReadDecodeDirectTests(unittest.TestCase):
    def setUp(self):
        plan_fixture.Req7SheetsReadPlanDirectTests.setUp(self)
        self.plan = self.module.prepare_sheets_read(self.binding, self.token, mode="row_rectangle", sheet="ETH&IB Switch", first_row=3)
        self.module = load()

    def test_complete_exact_rectangle_preserves_formula_numeric_bool_and_literal_identity(self):
        document = row_response()
        document["sheets"][0]["data"][0]["rowData"][0]["values"][12] = {"userEnteredValue": {"boolValue": False}}
        document["sheets"][0]["data"][0]["rowData"][0]["values"][13] = {"userEnteredValue": {"numberValue": 0}}
        document["sheets"][0]["data"][0]["rowData"][0]["values"][14] = {"userEnteredValue": {"stringValue": "0"}}
        raw = response(document); observed = self.module.decode_sheets_read(self.plan, raw)
        self.assertEqual(17, observed.sheet_id); self.assertEqual("ETH&IB Switch", observed.sheet_title)
        self.assertEqual(hashlib.sha256(raw.data).hexdigest(), observed.source_sha256)
        cells = {(row, column): dict(pairs) for row, column, pairs in observed.cells}
        self.assertEqual(21, len(cells)); self.assertEqual({"stringValue": "NV30017"}, cells[(2, "A")])
        self.assertEqual({"formulaValue": "=synthetic_lookup()"}, cells[(2, "I")])
        self.assertIs(False, cells[(2, "M")]["boolValue"])
        self.assertEqual({"numberValue": 0}, cells[(2, "N")]); self.assertEqual({"stringValue": "0"}, cells[(2, "O")])
        self.assertNotIn("NV30017", repr(observed)); self.assertFalse(hasattr(observed, "mutation_permit"))
        with self.assertRaises(AttributeError): observed.sheet_id = 18
        with self.assertRaises(TypeError): observed.cells[0][2][0] = ("stringValue", "foreign")

    def test_missing_conflicting_or_unbounded_grid_identity_is_never_a_complete_observation(self):
        variants = []
        for field, value in (("sheetId", True), ("sheetId", -1), ("title", "IB Cabling")):
            document = row_response(); document["sheets"][0]["properties"][field] = value; variants.append(document)
        for field, value in (("startRow", True), ("startRow", 3), ("startColumn", 1),
                             ("rowData", [{"values": []}, {"values": []}])):
            document = row_response(); document["sheets"][0]["data"][0][field] = value; variants.append(document)
        document = row_response(); document["spreadsheetId"] = "foreign_spreadsheet_id_0002"; variants.append(document)
        document = row_response(); document["sheets"][0]["data"] = []; variants.append(document)
        document = row_response(); document["sheets"] *= 2; variants.append(document)
        document = row_response(); del document["sheets"][0]["properties"]["sheetId"]; variants.append(document)
        for document in variants:
            with self.subTest(case=variants.index(document)), self.assertRaises(self.module.SheetsDecodeHold) as caught:
                self.module.decode_sheets_read(self.plan, response(document))
            self.assertEqual("req7_sheets_read_unproved", str(caught.exception)); self.assertIsNone(caught.exception.__context__)

    def test_duplicate_json_keys_non200_partial_and_raw_size_overflow_are_sanitized_without_payload(self):
        bad = (SimpleNamespace(status=200, complete=False, data=b"sentinel private incomplete"),
               SimpleNamespace(status=True, complete=True, data=b"{}"),
               SimpleNamespace(status=401, complete=True, data=b"sentinel private failure"),
               SimpleNamespace(status=200, complete=1, data=b"{}"),
               SimpleNamespace(status=200, complete=True, data=bytearray(b"{}")),
               SimpleNamespace(status=200, complete=True, data=b'{"spreadsheetId":"one","spreadsheetId":"two"}'),
               SimpleNamespace(status=200, complete=True, data=b'{"secret":NaN}'),
               SimpleNamespace(status=200, complete=True, data=b"\xff"),
               SimpleNamespace(status=200, complete=True, data=b" " * (2 * 1024 * 1024 + 1)))
        for value in bad:
            with self.subTest(status=value.status, complete=value.complete), self.assertRaises(self.module.SheetsDecodeHold) as caught:
                self.module.decode_sheets_read(self.plan, value)
            self.assertEqual("req7_sheets_read_unproved", str(caught.exception))
            self.assertIsNone(caught.exception.__cause__); self.assertIsNone(caught.exception.__context__)

    def test_formatted_effective_unknown_or_multiple_value_union_never_replaces_original_type(self):
        values = ({"formattedValue": "sentinel"}, {"effectiveValue": {"stringValue": "sentinel"}},
                  {"userEnteredValue": {"numberValue": True}},
                  {"userEnteredValue": {"stringValue": "x", "formulaValue": "=x"}},
                  {"userEnteredValue": {"formulaValue": ""}}, {"userEnteredValue": {"stringValue": "x\x00y"}},
                  {"userEnteredValue": {"errorValue": {}}}, {"userEnteredValue": {"stringValue": "x" * 32769}})
        for value in values:
            document = row_response(); document["sheets"][0]["data"][0]["rowData"][0]["values"][12] = value
            with self.subTest(fields=tuple(value)), self.assertRaises(self.module.SheetsDecodeHold) as caught:
                self.module.decode_sheets_read(self.plan, response(document))
            self.assertIsNone(caught.exception.__context__)

    def test_discovery_range_coordinates_must_cover_exactly_requested_columns_even_when_grids_reorder(self):
        plan = plan_fixture.load().prepare_sheets_read(self.binding, self.token, mode="discovery", sheet="ETH&IB Switch", first_row=3, last_row=4)
        document = {"spreadsheetId": "synthetic_spreadsheet_id_0001", "sheets": [{
            "properties": {"sheetId": 17, "title": "ETH&IB Switch"}, "data": [
                {"startRow": 2, "startColumn": 11, "rowData": [{"values": [{"userEnteredValue": {"stringValue": "description"}}]}]},
                {"startRow": 2, "startColumn": 0, "rowData": [{"values": [{"userEnteredValue": {"stringValue": "NV30017"}}]}]},
                {"startRow": 2, "startColumn": 5, "rowData": [{"values": [{"userEnteredValue": {"stringValue": "host-1"}}]}]},
                {"startRow": 2, "startColumn": 13, "rowData": [{"values": [{"userEnteredValue": {"stringValue": "New"}}]}]},
            ],
        }]}
        observed = self.module.decode_sheets_read(plan, response(document))
        self.assertEqual(8, len(observed.cells))
        self.assertEqual({(3, "A"), (3, "F"), (3, "L"), (3, "N")}, {(row, column) for row, column, pairs in observed.cells if not pairs})
        bad = deepcopy(document); bad["sheets"][0]["data"][2]["startColumn"] = 0
        with self.assertRaises(self.module.SheetsDecodeHold): self.module.decode_sheets_read(plan, response(bad))


class Req7SheetsReadDecodeWorkflowTests(unittest.TestCase):
    setUp = plan_fixture.Req7SheetsNativeReadWorkflowTests.setUp
    fixture = plan_fixture.Req7SheetsNativeReadWorkflowTests.fixture
    certificates = plan_fixture.Req7SheetsNativeReadWorkflowTests.certificates
    server = plan_fixture.Req7SheetsNativeReadWorkflowTests.server

    def test_native_metadata_then_exact_headers_share_bound_ids_but_grant_no_send_authority(self):
        from test_req7_sdk_authentication import load as load_auth
        from monitor.issue_tracker_online_target import OnlineTargetBinding
        import time
        self.assertTrue(hasattr(self.module, "NativeTemplateIdentityReadUnit"), "native template identity unit missing")
        self.assertTrue(hasattr(self.module, "NativeTemplateHeaderReadUnit"), "native template header unit missing")
        auth = load_auth(); planner = plan_fixture.load(); decoder = load()
        binding = OnlineTargetBinding("synthetic_spreadsheet_id_0001", "a" * 64, "b" * 64)
        token = auth.AuthenticatedToken("sentinel.private-token", time.time() + 3600)
        observed = None
        for constructor, prepare, document, decode in (
            (self.module.NativeTemplateIdentityReadUnit, planner.prepare_template_identity_read, identity_response(), decoder.decode_template_identity),
            (self.module.NativeTemplateHeaderReadUnit, planner.prepare_template_header_read, header_response(), decoder.decode_template_headers),
        ):
            plan = prepare(binding, token); unit = constructor(binding, token)
            payload = json.dumps(document).encode()
            reply = ("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(payload)).encode() + payload
            with self.server(reply, hostname="sheets.googleapis.com", destination="sheets.googleapis.com") as (records, errors):
                with self.fixture(), mock.patch.dict("os.environ", {"HTTPS_PROXY": "http://foreign.invalid:9"}):
                    raw = unit.send_once()
                    result = decode(plan, raw) if observed is None else decode(plan, raw, observed)
                    with self.assertRaises(self.module.TlsInputHold): unit.send_once()
            self.assertEqual([], errors); self.assertEqual(1, len(records))
            self.assertEqual(plan.path, records[0][0].decode().strip().split(" ")[1])
            self.assertEqual(b"", records[0][2]); self.assertEqual(200, raw.status)
            if observed is None: observed = result
            self.assertFalse(hasattr(result, "mutation_permit")); self.assertFalse(hasattr(result, "applied"))
        self.assertEqual((("ETH&IB Switch",21),("ETH Cabling",29),("IB Cabling",29),("Update_History",5)), result.checked_headers)

    def test_actual_native_read_decodes_into_real_switch_row_checks_without_relabeling_read_as_applied(self):
        from test_req7_sdk_authentication import load as load_auth
        from monitor.issue_tracker_online_target import OnlineTargetBinding
        from monitor.issue_tracker_online_rows import select_switch_free_row
        import time
        auth = load_auth(); planner = plan_fixture.load(); decoder = load()
        binding = OnlineTargetBinding("synthetic_spreadsheet_id_0001", "a" * 64, "b" * 64)
        token = auth.AuthenticatedToken("sentinel.private-token", time.time() + 3600)
        plan = planner.prepare_sheets_read(binding, token, mode="row_rectangle", sheet="ETH&IB Switch", first_row=3)
        unit = self.module.NativeSheetsReadUnit(binding, token, mode="row_rectangle", sheet="ETH&IB Switch", first_row=3)
        payload = json.dumps(row_response()).encode()
        raw_reply = ("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(payload)).encode() + payload
        with self.server(raw_reply, hostname="sheets.googleapis.com", destination="sheets.googleapis.com") as (records, errors):
            with self.fixture(): observed = decoder.decode_sheets_read(plan, unit.send_once())
        self.assertEqual([], errors); self.assertEqual(1, len(records))
        cells = {column: dict(pairs) for row, column, pairs in observed.cells if row == 2}
        selected = select_switch_free_row(((2, cells),))
        self.assertEqual(2, selected.row_index); self.assertEqual("NV30017", selected.issue_id)
        self.assertFalse(hasattr(observed, "outcome")); self.assertFalse(hasattr(observed, "mutation_permit"))


if __name__ == "__main__": unittest.main()
