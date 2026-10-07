"""Independent bounded active/Closed observations; never absence or write authority."""
from copy import deepcopy
import hashlib
import json
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from test_cases import test_req7_sheets_read_plan as plans
from test_cases import test_req7_sheets_read_decode as grids


def document(sheet, rows):
    columns = (("A", 0), ("F", 5), ("L", 11), ("N", 13)) if sheet == "ETH&IB Switch" else (
        ("A", 0), ("F", 5), ("G", 6), ("K", 10), ("L", 11), ("Q", 16), ("R", 17), ("U", 20))
    return {"spreadsheetId": "synthetic_spreadsheet_id_0001", "sheets": [{
        "properties": {"sheetId": 17, "title": sheet}, "data": [
            {"startRow": 2, "startColumn": index, "rowData": [{"values": [
                {"userEnteredValue": row[column]} if column in row else {}]} for row in rows]}
            for column, index in reversed(columns)]}]}


def literal(value): return {"stringValue": value}


def switch_row(identifier="NV30017", status="New", description="[MONITOR][down][fabric] evidence"):
    return {"A": literal(identifier), "F": literal("switch-1"), "L": literal(description), "N": literal(status)}


def cabling_row(identifier="NV30017", status="New"):
    return {"A": literal(identifier), "F": literal("Link Down"), "G": literal("synthetic evidence"),
            "K": literal("switch-1"), "L": literal("swp1"), "Q": literal("switch-2"),
            "R": literal("swp2"), "U": literal(status)}


class Req7ActivityDiscoveryDirectTests(unittest.TestCase):
    def setUp(self):
        plans.Req7SheetsReadPlanDirectTests.setUp(self)
        self.planner = self.module; self.module = grids.load()

    def plan(self, sheet="ETH&IB Switch", first=3, last=5):
        return self.planner.prepare_sheets_read(self.binding, self.token, mode="discovery", sheet=sheet,
                                               first_row=first, last_row=last)

    def discover(self, value, key=("switch", "switch-1", "down", "fabric"), plan=None):
        self.assertTrue(hasattr(self.module, "discover_activity_rows"), "REQ7 active/Closed discovery missing")
        return self.module.discover_activity_rows(plan or self.plan(), grids.response(value), activity_key=key)

    def test_discovery_requests_original_status_alongside_full_identity_without_wide_reads(self):
        for sheet, columns in (("ETH&IB Switch", ("A", "F", "L", "N")),
                               ("ETH Cabling", ("A", "F", "G", "K", "L", "Q", "R", "U")),
                               ("IB Cabling", ("A", "F", "G", "K", "L", "Q", "R", "U"))):
            plan = self.plan(sheet)
            self.assertEqual(["'%s'!%s3:%s5" % (sheet, c, c) for c in columns],
                             parse_qs(urlsplit(plan.path).query)["ranges"])
            self.assertNotIn("effectiveValue", plan.path); self.assertNotIn("formattedValue", plan.path)

    def test_exact_switch_key_classifies_closed_and_retains_actual_online_ids_without_local_rewrite(self):
        rows = [switch_row("NV00008", "Closed"), switch_row("NV30091"),
                switch_row("NV30092", description="[MONITOR][down][other] unrelated")]
        source = document("ETH&IB Switch", rows); raw = grids.response(source)
        result = self.discover(source)
        self.assertEqual(((3, "NV30091"),), result.active_rows)
        self.assertEqual(((2, "NV00008"),), result.closed_rows)
        self.assertEqual((2, 4), (result.first_row_index, result.last_row_index))
        self.assertEqual(hashlib.sha256(raw.data).hexdigest(), result.source_sha256)
        self.assertEqual(("switch", "switch-1", "down", "fabric"), result.activity_key)
        self.assertNotIn("switch-1", repr(result)); self.assertNotIn("NV30091", repr(result))
        for name in ("absent", "insert_allowed", "mutation_permit", "complete", "applied"):
            self.assertFalse(hasattr(result, name))
        with self.assertRaises(AttributeError): result.active_rows = ()
        self.assertEqual(rows, [switch_row("NV00008", "Closed"), switch_row("NV30091"),
                                switch_row("NV30092", description="[MONITOR][down][other] unrelated")])

    def test_cabling_family_a_side_and_issue_type_define_key_peer_and_description_do_not(self):
        for sheet, family in (("ETH Cabling", "eth_cabling"), ("IB Cabling", "ib_cabling")):
            rows = [cabling_row("NV30014", "Closed"), cabling_row("NV30041"), cabling_row("NV30042")]
            rows[1]["Q"] = literal("changed-peer"); rows[1]["G"] = literal("human description")
            rows[2]["L"] = literal("swp10")
            result = self.discover(document(sheet, rows), (family, "switch-1", "swp1", "Link Down"), self.plan(sheet))
            self.assertEqual(((3, "NV30041"),), result.active_rows)
            self.assertEqual(((2, "NV30014"),), result.closed_rows)
            with self.assertRaises(self.module.SheetsDecodeHold):
                self.discover(document(sheet, rows), ("switch", "switch-1", "down", "fabric"), self.plan(sheet))

    def test_duplicate_active_key_is_conflict_even_with_different_ids_but_closed_duplicates_are_not_active(self):
        self.assertTrue(hasattr(self.module, "OnlineActivityConflict"), "duplicate-key conflict missing")
        for sheet, key, row in (("ETH&IB Switch", ("switch", "switch-1", "down", "fabric"), switch_row),
                               ("ETH Cabling", ("eth_cabling", "switch-1", "swp1", "Link Down"), cabling_row)):
            with self.assertRaises(self.module.OnlineActivityConflict):
                self.discover(document(sheet, [row("NV30017"), row("NV30018")]), key, self.plan(sheet))
            result = self.discover(document(sheet, [row("NV30017", "Closed"), row("NV30018", "Closed")]), key, self.plan(sheet))
            self.assertEqual((), result.active_rows); self.assertEqual(((2,"NV30017"),(3,"NV30018")), result.closed_rows)

    def test_closed_is_exact_literal_not_trimmed_casefolded_formula_numeric_or_bool(self):
        for value in ("closed", "Closed ", " CLOSED", "", "In Progress"):
            result = self.discover(document("ETH&IB Switch", [switch_row(status=value)]))
            self.assertEqual(((2, "NV30017"),), result.active_rows); self.assertEqual((), result.closed_rows)
        for value in ({"formulaValue": '="Closed"'}, {"numberValue": 0}, {"boolValue": False}):
            row = switch_row(); row["N"] = value
            with self.assertRaises(self.module.SheetsDecodeHold) as caught:
                self.discover(document("ETH&IB Switch", [row]))
            self.assertIsNone(caught.exception.__context__)
        row = switch_row(); del row["N"]
        self.assertEqual(((2,"NV30017"),), self.discover(document("ETH&IB Switch", [row])).active_rows)

    def test_missing_formula_invalid_or_duplicate_identity_holds_instead_of_inventing_id(self):
        self.assertTrue(hasattr(self.module, "discover_activity_rows"), "REQ7 active/Closed discovery missing")
        variants = []
        for column in ("A", "F", "L"):
            item = switch_row(); item[column] = {"formulaValue": '=private_sentinel()'}; variants.append([item])
        for identifier in ("", "NV1", "NV30017 ", "private_sentinel"):
            variants.append([switch_row(identifier)])
        variants.append([switch_row("NV30017", "Closed"), switch_row("NV30017")])
        for rows in variants:
            with self.subTest(rows=len(rows)), self.assertRaises(self.module.SheetsDecodeHold) as caught:
                self.discover(document("ETH&IB Switch", rows))
            self.assertNotIn("private_sentinel", str(caught.exception)); self.assertIsNone(caught.exception.__context__)

    def test_partial_window_no_match_is_only_observation_not_absence_or_allocation_authority(self):
        result = self.discover(document("ETH&IB Switch", [{}]))
        self.assertEqual((), result.active_rows); self.assertEqual((), result.closed_rows)
        self.assertEqual((2,4), (result.first_row_index,result.last_row_index))
        for key in (True, ["switch", "switch-1", "down", "fabric"], ("switch", "switch-1", "", "fabric"),
                    ("switch", "switch-1", "down", "fabric]injection"), ("eth_cabling", "switch-1", "swp1", "Link Down")):
            with self.assertRaises(self.module.SheetsDecodeHold): self.discover(document("ETH&IB Switch", []), key)

    def test_cabling_unsupported_issue_types_and_oversized_normalized_key_are_not_discovery_inputs(self):
        for key in (("eth_cabling","switch-1","swp1","unsupported"),
                    ("eth_cabling","x"*256,"swp1","Link Down")):
            with self.assertRaises(self.module.SheetsDecodeHold):
                self.discover(document("ETH Cabling",[]),key,self.plan("ETH Cabling"))

    def test_incomplete_status_grid_or_rectangle_shape_never_manufactures_active_or_closed_image(self):
        source = document("ETH&IB Switch", [switch_row()]); variants = []
        missing = deepcopy(source); missing["sheets"][0]["data"].pop(0); variants.append(missing)
        duplicate = deepcopy(source); duplicate["sheets"][0]["data"].append(duplicate["sheets"][0]["data"][0]); variants.append(duplicate)
        for value in variants:
            with self.assertRaises(self.module.SheetsDecodeHold): self.discover(value)
        rectangle = self.planner.prepare_sheets_read(self.binding,self.token,mode="row_rectangle",sheet="ETH&IB Switch",first_row=3)
        with self.assertRaises(self.module.SheetsDecodeHold): self.discover(grids.row_response(),plan=rectangle)
        self.assertTrue(hasattr(self.module,"discover_activity_rows"))
        for raw in (replace_mock(200,False,b"private_sentinel"),replace_mock(401,True,b"private_sentinel")):
            with self.assertRaises(self.module.SheetsDecodeHold):
                self.module.discover_activity_rows(self.plan(),raw,activity_key=("switch","switch-1","down","fabric"))


def replace_mock(status, complete, data):
    from types import SimpleNamespace
    return SimpleNamespace(status=status, complete=complete, data=data)


class Req7ActivityDiscoveryNativeWorkflowTests(unittest.TestCase):
    setUp = plans.Req7SheetsNativeReadWorkflowTests.setUp
    fixture = plans.Req7SheetsNativeReadWorkflowTests.fixture
    certificates = plans.Req7SheetsNativeReadWorkflowTests.certificates
    server = plans.Req7SheetsNativeReadWorkflowTests.server

    def test_real_native_one_get_planner_decoder_and_classifier_preserve_closed_id_and_active_key(self):
        from test_cases.test_req7_sdk_authentication import load as load_auth
        from monitor.issue_tracker_online_target import OnlineTargetBinding
        import time
        auth = load_auth(); planner = plans.load(); decoder = grids.load()
        binding = OnlineTargetBinding("synthetic_spreadsheet_id_0001","a"*64,"b"*64)
        token = auth.AuthenticatedToken("sentinel.private-token",time.time()+3600)
        options = dict(mode="discovery",sheet="ETH&IB Switch",first_row=3,last_row=5)
        plan = planner.prepare_sheets_read(binding,token,**options)
        unit = self.module.NativeSheetsReadUnit(binding,token,**options)
        payload = json.dumps(document("ETH&IB Switch",[switch_row("NV30000","Closed"),switch_row("NV30019")])).encode()
        reply = ("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"%len(payload)).encode()+payload
        self.assertTrue(hasattr(decoder,"discover_activity_rows"))
        with self.server(reply,hostname="sheets.googleapis.com",destination="sheets.googleapis.com") as (records,errors):
            with self.fixture(),mock.patch.dict("os.environ",{"HTTPS_PROXY":"http://foreign.invalid:9"}):
                result = decoder.discover_activity_rows(plan,unit.send_once(),activity_key=("switch","switch-1","down","fabric"))
                with self.assertRaises(self.module.TlsInputHold): unit.send_once()
        self.assertEqual([],errors); self.assertEqual(1,len(records)); self.assertEqual(b"",records[0][2])
        self.assertEqual(plan.path,records[0][0].decode().strip().split(" ")[1])
        self.assertEqual(((3,"NV30019"),),result.active_rows); self.assertEqual(((2,"NV30000"),),result.closed_rows)

    def test_governed_manifest_binds_real_discovery_flow_and_not_run_card(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root/"test_cases/script_test_manifest.json").read_text())
        self.assertTrue(any(rule["id"]=="req7_native_active_closed_discovery"
                            and {"monitor/issue_tracker_sheets_read_plan.py","monitor/issue_tracker_sheets_read_decode.py",
                                 "monitor/issue_tracker_tls_inputs.py"}<=set(rule["members"])
                            and "test_cases.test_req7_activity_discovery" in rule["tests"] for rule in manifest["workflows"]))
        for script in ("monitor/issue_tracker_sheets_read_plan.py","monitor/issue_tracker_sheets_read_decode.py"):
            self.assertTrue(any(script in rule["paths"] and "test_cases.test_req7_activity_discovery" in rule["tests"]
                                for rule in manifest["test_rules"]))
        self.assertIn("TC-REAL-REQ7-ACTIVE-CLOSED-DISCOVERY-001",(root/"test_cases/REAL_ENVIRONMENT.md").read_text())


if __name__ == "__main__": unittest.main()
