"""Independent bounded-read shapes; no online service or send authority."""
from dataclasses import replace
import importlib.util
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit
import test_cases

ROOT = Path(test_cases.__file__).resolve().parents[1]
CANDIDATE = Path(__file__).resolve().parents[1]
MODULE = CANDIDATE / "monitor/issue_tracker_sheets_read_plan.py"
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))


def load():
    if not MODULE.is_file(): raise AssertionError("REQ7 fixed Sheets read-plan helper missing")
    from test_cases.test_req7_history_read import load as canonical_loader
    return canonical_loader('issue_tracker_sheets_read_plan',path=MODULE)


class Req7SheetsReadPlanDirectTests(unittest.TestCase):
    def setUp(self):
        from test_req7_sdk_authentication import load as load_auth
        from monitor.issue_tracker_online_target import OnlineTargetBinding
        self.auth = load_auth(); self.module = load()
        self.binding = OnlineTargetBinding("synthetic_spreadsheet_id_0001", "a" * 64, "b" * 64)
        self.token = self.auth.AuthenticatedToken("sentinel.private-token", time.time() + 3600)

    def prepare(self, **options):
        return self.module.prepare_sheets_read(self.binding, self.token, **options)

    def test_template_identity_and_headers_are_separate_fixed_bounded_reads(self):
        self.assertTrue(hasattr(self.module, "prepare_template_identity_read"), "fixed template identity read missing")
        self.assertTrue(hasattr(self.module, "prepare_template_header_read"), "fixed template header read missing")
        expected = (
            (self.module.prepare_template_identity_read, {
                "includeGridData": ["false"], "fields": ["spreadsheetId,sheets(properties(sheetId,title))"]}),
            (self.module.prepare_template_header_read, {
                "includeGridData": ["true"],
                "fields": ["spreadsheetId,sheets(properties(sheetId,title),data(startRow,startColumn,rowData(values(userEnteredValue))))"],
                "ranges": ["'ETH&IB Switch'!A2:U2", "'ETH Cabling'!A2:AC2", "'IB Cabling'!A2:AC2", "'Update_History'!A2:E2"]}),
        )
        for prepare, query in expected:
            with self.subTest(read=prepare.__name__), mock.patch("socket.socket") as networking:
                plan = prepare(self.binding, self.token)
            self.assertEqual(query, parse_qs(urlsplit(plan.path).query, strict_parsing=True))
            self.assertEqual("/v4/spreadsheets/synthetic_spreadsheet_id_0001", urlsplit(plan.path).path)
            self.assertEqual(("sheets.googleapis.com", "GET", b"", 30.0), (plan.host, plan.method, plan.body, plan.budget_seconds))
            self.assertNotIn("sentinel.private-token", repr(plan)); networking.assert_not_called()
            with self.assertRaises(TypeError): prepare(self.binding, self.token, ranges="A:ZZ")

    def test_template_reads_keep_exact_target_and_token_validation(self):
        self.assertTrue(hasattr(self.module, "prepare_template_identity_read"))
        self.assertTrue(hasattr(self.module, "prepare_template_header_read"))
        for prepare in (self.module.prepare_template_identity_read, self.module.prepare_template_header_read):
            for binding, token in ((replace(self.binding, spreadsheet_id="foreign/path"), self.token),
                                   (self.binding, replace(self.token, value="private\r\nHeader: x")),
                                   (self.binding, replace(self.token, expires_at=True))):
                with self.subTest(read=prepare.__name__), mock.patch("socket.socket") as networking, self.assertRaises(self.module.SheetsReadHold) as caught:
                    prepare(binding, token)
                self.assertIsNone(caught.exception.__context__); networking.assert_not_called()

    def test_switch_discovery_reads_only_explicit_identity_columns_and_user_entered_values(self):
        with mock.patch("socket.socket", side_effect=AssertionError("network forbidden")):
            plan = self.prepare(mode="discovery", sheet="ETH&IB Switch", first_row=3, last_row=5002)
        url = urlsplit(plan.path)
        self.assertEqual("/v4/spreadsheets/synthetic_spreadsheet_id_0001", url.path)
        self.assertEqual({"ranges": ["'ETH&IB Switch'!A3:A5002", "'ETH&IB Switch'!F3:F5002", "'ETH&IB Switch'!L3:L5002", "'ETH&IB Switch'!N3:N5002"],
                          "includeGridData": ["true"],
                          "fields": ["spreadsheetId,sheets(properties(sheetId,title),data(startRow,startColumn,rowData(values(userEnteredValue))))"]},
                         parse_qs(url.query, strict_parsing=True))
        self.assertEqual("sheets.googleapis.com", plan.host); self.assertEqual("GET", plan.method)
        self.assertEqual(b"", plan.body); self.assertEqual(30.0, plan.budget_seconds)
        self.assertEqual((("Accept", "application/json"), ("Authorization", "Bearer sentinel.private-token")), plan.headers)
        self.assertNotIn("sentinel.private-token", repr(plan))
        self.assertNotIn("synthetic_spreadsheet_id_0001", repr(plan))
        with self.assertRaises(AttributeError): plan.path = "/foreign"

    def test_cabling_discovery_is_eight_explicit_columns_including_status_not_a_wide_sheet_read(self):
        for sheet in ("ETH Cabling", "IB Cabling"):
            with self.subTest(sheet=sheet):
                plan = self.prepare(mode="discovery", sheet=sheet, first_row=3, last_row=9)
                query = parse_qs(urlsplit(plan.path).query, strict_parsing=True)
                self.assertEqual(["'%s'!%s3:%s9" % (sheet, column, column) for column in ("A", "F", "G", "K", "L", "Q", "R", "U")], query["ranges"])
                self.assertNotIn("effectiveValue", query["fields"][0]); self.assertNotIn("formattedValue", query["fields"][0])
                self.assertNotIn("A:ZZ", plan.path)

    def test_occupancy_and_formula_prepost_reads_are_exact_single_row_rectangles(self):
        for sheet, expected in (("ETH&IB Switch", "'ETH&IB Switch'!A5002:U5002"),
                                ("ETH Cabling", "'ETH Cabling'!A7:AC7"), ("IB Cabling", "'IB Cabling'!A7:AC7")):
            row = 5002 if sheet == "ETH&IB Switch" else 7
            with self.subTest(sheet=sheet):
                plan = self.prepare(mode="row_rectangle", sheet=sheet, first_row=row)
                self.assertEqual([expected], parse_qs(urlsplit(plan.path).query)["ranges"])

    def test_foreign_sheet_path_unbounded_grid_and_bool_indices_are_denied_without_network(self):
        cases = ({"sheet": "Whitelist"}, {"sheet": "ETH&IB Switch'!A:ZZ"}, {"sheet": True},
                 {"mode": "metadata"}, {"mode": "batchUpdate"}, {"first_row": True}, {"first_row": 2},
                 {"last_row": True}, {"last_row": 5003}, {"last_row": 2},
                 {"sheet": "ETH Cabling", "last_row": 5003}, {"last_row": 10 ** 1000},
                 {"mode": "row_rectangle", "first_row": 7, "last_row": 8})
        for changes in cases:
            options = {"mode": "discovery", "sheet": "ETH&IB Switch", "first_row": 3, "last_row": 5002}
            options.update(changes)
            with self.subTest(fields=tuple(changes)), mock.patch("socket.socket") as socket_constructor, self.assertRaises(
                self.module.SheetsReadHold,
            ) as caught:
                self.prepare(**options)
            self.assertEqual("req7_sheets_read_denied", str(caught.exception))
            self.assertIsNone(caught.exception.__context__); socket_constructor.assert_not_called()

    def test_binding_and_private_token_require_native_finite_safe_identity_without_string_coercion(self):
        invalid_bindings = (SimpleNamespace(**self.binding.__dict__), replace(self.binding, spreadsheet_id="https://foreign.invalid"),
                            replace(self.binding, spreadsheet_id="x" * 4097), replace(self.binding, policy_sha256="B" * 64),
                            replace(self.binding, allowlist_sha256="missing"))
        invalid_tokens = (SimpleNamespace(**self.token.__dict__), replace(self.token, value="sentinel\r\nLeak: x"),
                          replace(self.token, value="x" * 8193), replace(self.token, expires_at=True),
                          replace(self.token, expires_at=time.time() - 1), replace(self.token, expires_at=float("nan")),
                          replace(self.token, expires_at=float("inf")), replace(self.token, expires_at=10 ** 1000))
        for binding, token in ([(value, self.token) for value in invalid_bindings] + [(self.binding, value) for value in invalid_tokens]):
            with self.subTest(binding_type=type(binding).__name__, token_type=type(token).__name__), self.assertRaises(self.module.SheetsReadHold) as caught:
                self.module.prepare_sheets_read(binding, token, mode="row_rectangle", sheet="ETH Cabling", first_row=3)
            self.assertIsNone(caught.exception.__context__)


class Req7SheetsReadPlanWorkflowTests(unittest.TestCase):
    def test_real_public_refresh_and_policy_allowlist_binding_build_one_private_read_without_granting_a_mutation(self):
        from test_req7_sdk_authentication import load as load_auth, fresh_info, parsed_info, FakeTokenUnit
        from monitor.issue_tracker_online_target import bind_online_target, freeze_target_allowlist
        auth = load_auth(); module = load(); unit = FakeTokenUnit()
        import json
        document = {"schema_version": 2, "common": {"mgmt": {"issue-tracker": {
            "status": "enabled", "spreadsheet_id": "synthetic_spreadsheet_id_0001"}}}}
        binding = bind_online_target(document, freeze_target_allowlist(b'["synthetic_spreadsheet_id_0001"]'))
        with mock.patch("socket.socket", side_effect=AssertionError("real network forbidden")):
            token = auth.refresh_validated_service_account(parsed_info(fresh_info()), unit)
            plan = module.prepare_sheets_read(binding, token, mode="row_rectangle", sheet="ETH Cabling", first_row=3)
        self.assertEqual(1, len(unit.calls)); self.assertEqual("sheets.googleapis.com", plan.host)
        self.assertEqual("GET", plan.method); self.assertEqual("Bearer sentinel", dict(plan.headers)["Authorization"])
        self.assertNotIn(":batchUpdate", plan.path)
        self.assertFalse(hasattr(plan, "mutation_permit")); self.assertFalse(hasattr(plan, "send_once"))


class Req7SheetsNativeReadWorkflowTests(unittest.TestCase):
    import test_req7_tls_inputs as _tls_fixture
    import test_req7_native_tls_wire as _wire_fixture
    setUp = _tls_fixture.Req7TlsInputsDirectTests.setUp
    fixture = _tls_fixture.Req7TlsInputsDirectTests.fixture
    certificates = _wire_fixture.Req7NativeTlsWireTests.certificates
    server = _wire_fixture.Req7NativeTlsWireTests.server

    def read_unit(self):
        from test_req7_sdk_authentication import load as load_auth
        from monitor.issue_tracker_online_target import OnlineTargetBinding
        auth = load_auth(); load()
        return self.module.NativeSheetsReadUnit(
            OnlineTargetBinding("synthetic_spreadsheet_id_0001", "a" * 64, "b" * 64),
            auth.AuthenticatedToken("sentinel.private-token", time.time() + 3600),
            mode="row_rectangle", sheet="ETH Cabling", first_row=7,
        )

    def test_native_sheets_read_is_one_verified_get_with_private_bearer_and_exact_rectangle(self):
        unit = self.read_unit()
        with self.server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                         hostname="sheets.googleapis.com", destination="sheets.googleapis.com") as (records, errors):
            with self.fixture(), mock.patch.dict("os.environ", {"HTTPS_PROXY": "http://foreign.invalid:9"}):
                result = unit.send_once()
                with self.assertRaises(self.module.TlsInputHold): unit.send_once()
        self.assertEqual([], errors); self.assertEqual(1, len(records))
        method, path, version = records[0][0].decode().strip().split(" ")
        self.assertEqual("GET", method); self.assertEqual("HTTP/1.1", version)
        self.assertEqual("/v4/spreadsheets/synthetic_spreadsheet_id_0001", urlsplit(path).path)
        self.assertEqual(["'ETH Cabling'!A7:AC7"], parse_qs(urlsplit(path).query)["ranges"])
        self.assertIn(b"Host: sheets.googleapis.com\r\n", records[0][1])
        self.assertIn(b"Authorization: Bearer sentinel.private-token\r\n", records[0][1])
        self.assertEqual(b"", records[0][2]); self.assertEqual(200, result.status)
        self.assertEqual(b"{}", result.data); self.assertIs(True, result.complete)
        self.assertNotIn("sentinel", repr(result))

    def test_native_read_401_and_redirect_never_refresh_token_or_open_second_connection(self):
        for status in (401, 302, 503):
            unit = self.read_unit()
            response = ("HTTP/1.1 %d Denied\r\nContent-Length: 2\r\nLocation: https://foreign.invalid/\r\n"
                        "Connection: close\r\n\r\n{}" % status).encode()
            with self.subTest(status=status):
                with self.server(response, hostname="sheets.googleapis.com", destination="sheets.googleapis.com") as (records, errors):
                    with self.fixture(), self.assertRaises(self.module.TlsInputHold) as caught: unit.send_once()
                    with self.assertRaises(self.module.TlsInputHold): unit.send_once()
                self.assertEqual([], errors); self.assertEqual(1, len(records))
                self.assertIsNone(caught.exception.__context__)


if __name__ == "__main__": unittest.main()
