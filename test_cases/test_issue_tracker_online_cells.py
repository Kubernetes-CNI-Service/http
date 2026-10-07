"""Independent C-8 cell runs/C-26 typed comparison; no send eligibility."""

import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


def load():
    path = Path(__file__).resolve().parents[1] / "monitor/issue_tracker_online_cells.py"
    if not path.is_file(): raise AssertionError("online cell encoder is missing")
    spec = importlib.util.spec_from_file_location("isolated_online_cells", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class OnlineCellsDirectTests(unittest.TestCase):
    def setUp(self): self.module = load()

    def test_switch_insert_exact_runs_never_touch_id_formula_or_operator_columns(self):
        values = {"B": "2026-10-07", "C": "ZTP Monitor", "F": "node01",
                  "J": "Compute", "K": "High", "L": '=literal("down")', "N": "New"}
        result = self.module.encode_tool_cells("ETH&IB Switch", 17, "insert", values, row_index=2)
        requests = json.loads(result.requests_json)
        expected = []
        for column, letters in ((1, ("B", "C")), (5, ("F",)), (9, ("J", "K", "L")), (13, ("N",))):
            expected.append({"updateCells": {
                "start": {"sheetId": 17, "rowIndex": 2, "columnIndex": column},
                "rows": [{"values": [{"userEnteredValue": {"stringValue": values[letter]}}
                                     for letter in letters]}], "fields": "userEnteredValue"}})
        self.assertEqual(expected, requests)
        self.assertEqual("WIRE-CANDIDATE", result.outcome)
        self.assertFalse(hasattr(result, "permit"))
        self.assertNotIn("formulaValue", result.requests_json.decode())
        self.assertNotIn('"range"', result.requests_json.decode())

    def test_switch_update_is_l_only_and_formula_or_number_equality_is_not_noop(self):
        for observed, outcome in (({"L": {"stringValue": "down"}}, "OBSERVED-SATISFIED-AT-READ"),
                                  ({"L": {"formulaValue": '="down"'}}, "WIRE-CANDIDATE"),
                                  ({"L": {"numberValue": 123}}, "WIRE-CANDIDATE"),
                                  ({"L": {}}, "WIRE-CANDIDATE")):
            with self.subTest(observed=observed):
                result = self.module.encode_tool_cells("ETH&IB Switch", 17, "update", {"L": "down"},
                                                        row_index=31, observed_values=observed)
                self.assertEqual(outcome, result.outcome)
                requests = json.loads(result.requests_json)
                if outcome == "OBSERVED-SATISFIED-AT-READ": self.assertEqual([], requests)
                else:
                    self.assertEqual(1, len(requests))
                    self.assertEqual({"sheetId": 17, "rowIndex": 31, "columnIndex": 11},
                                     requests[0]["updateCells"]["start"])
        self.assertEqual("WIRE-CANDIDATE", self.module.encode_tool_cells(
            "ETH&IB Switch", 17, "update", {"L": "123"}, row_index=31,
            observed_values={"L": {"numberValue": 123}}).outcome)

    def test_cabling_insert_appends_literal_row_and_update_writes_only_observed_sides(self):
        values = {"A": "NV30017", "B": "ZTP Monitor", "C": "ZTP Monitor", "D": "2026-10-07",
                  "E": "ETH", "F": "Mis-wiring", "G": "bad endpoint", "K": "a", "L": "p1",
                  "M": "observed-a", "N": "p7", "Q": "z", "R": "p2", "S": "observed-z",
                  "T": "p8", "U": "New"}
        for sheet in ("ETH Cabling", "IB Cabling"):
            values["E"] = "ETH" if sheet == "ETH Cabling" else "IB"
            result = self.module.encode_tool_cells(sheet, 8, "insert", values)
            request = json.loads(result.requests_json)[0]["appendCells"]
            self.assertEqual({"sheetId", "rows", "fields"}, set(request))
            self.assertEqual(8, request["sheetId"])
            self.assertEqual("userEnteredValue", request["fields"])
            cells = request["rows"][0]["values"]
            self.assertEqual(21, len(cells))
            self.assertEqual({}, cells[7])  # H is not tool-owned by this insert.
            self.assertEqual({"userEnteredValue": {"stringValue": "NV30017"}}, cells[0])
            update = {"G": "new evidence", "M": "a", "N": "p3", "S": "z", "T": "p4"}
            requests = json.loads(self.module.encode_tool_cells(sheet, 8, "update", update,
                                                               row_index=12).requests_json)
            self.assertEqual([6, 12, 18], [item["updateCells"]["start"]["columnIndex"] for item in requests])
            self.assertEqual([1, 2, 2], [len(item["updateCells"]["rows"][0]["values"]) for item in requests])

    def test_malformed_shapes_owned_matrix_and_partial_observations_fail_closed(self):
        invalid = [
            ("ETH&IB Switch", True, "update", {"L": "x"}, 2, None),
            ("ETH&IB Switch", -1, "update", {"L": "x"}, 2, None),
            ("ETH&IB Switch", 17, "update", {"L": 123}, 2, None),
            ("ETH&IB Switch", 17, "update", {"L": "x", "N": "New"}, 2, None),
            ("ETH&IB Switch", 17, "insert", {"L": "x"}, 2, None),
            ("ETH&IB Switch", 17, "update", {"L": "x"}, True, None),
            ("ETH&IB Switch", 17, "update", {"L": "x"}, 1, None),
            ("ETH&IB Switch", 17, "update", {"L": "x"}, 5002, None),
            ("Unknown", 17, "update", {"L": "x"}, 2, None),
            ("ETH Cabling", 8, "update", {"G": "x", "U": "New"}, 2, None),
            ("ETH&IB Switch", 17, "update", {"L": "x"}, 2, {}),
            ("ETH&IB Switch", 17, "update", {"L": "x"}, 2, {"L": {"stringValue": "x", "formulaValue": "=1"}}),
            ("ETH&IB Switch", 17, "update", {"L": "x"}, 2, {"L": {"boolValue": 1}}),
            ("ETH&IB Switch", 17, "update", {"L": "x"}, 2, {"L": {"numberValue": float("nan")}}),
        ]
        for sheet, sheet_id, action, values, row, observed in invalid:
            with self.subTest(sheet=sheet, action=action, row=row, values=values), self.assertRaises(self.module.OnlineCellsHold):
                self.module.encode_tool_cells(sheet, sheet_id, action, values,
                                              row_index=row, observed_values=observed)

    def test_every_intended_insert_cell_participates_in_noop_and_result_is_frozen(self):
        values = {"B": "2026-10-07", "C": "ZTP Monitor", "F": "node01",
                  "J": "Compute", "K": "High", "L": "down", "N": "New"}
        observed = {key: {"stringValue": value} for key, value in values.items()}
        original = self.module.encode_tool_cells("ETH&IB Switch", 17, "insert", values, row_index=2)
        body = original.requests_json
        noop = self.module.encode_tool_cells("ETH&IB Switch", 17, "insert", values,
                                            row_index=2, observed_values=observed)
        self.assertEqual("OBSERVED-SATISFIED-AT-READ", noop.outcome)
        for letter in values:
            changed = {key: dict(value) for key, value in observed.items()}
            changed[letter] = {"stringValue": "different"}
            with self.subTest(letter=letter):
                self.assertEqual("WIRE-CANDIDATE", self.module.encode_tool_cells(
                    "ETH&IB Switch", 17, "insert", values, row_index=2,
                    observed_values=changed).outcome)
                changed.pop(letter)
                with self.assertRaises(self.module.OnlineCellsHold):
                    self.module.encode_tool_cells("ETH&IB Switch", 17, "insert", values,
                                                  row_index=2, observed_values=changed)
        values["L"] = "caller changed after freeze"
        self.assertEqual(body, original.requests_json)
        with self.assertRaises(AttributeError): original.outcome = "APPLIED"

    def test_cabling_ac_is_literal_but_operator_columns_and_blank_or_nonliteral_inputs_refuse(self):
        values = {"G": "down", "M": "a", "N": "p1", "S": "z", "T": "p2", "AC": "CVT evidence"}
        requests = json.loads(self.module.encode_tool_cells("ETH Cabling", 8, "update", values,
                                                          row_index=2).requests_json)
        self.assertEqual(28, requests[-1]["updateCells"]["start"]["columnIndex"])
        for column in ("A", "B", "C", "D", "E", "F", "H", "I", "J", "K", "L", "O", "P", "Q", "R", "U", "V", "W", "X", "Y", "Z", "AA", "AB"):
            changed = dict(values); changed[column] = "forbidden"
            with self.subTest(column=column), self.assertRaises(self.module.OnlineCellsHold):
                self.module.encode_tool_cells("ETH Cabling", 8, "update", changed, row_index=2)
        for bad in (True, 1, None, {"formulaValue": "=1"}, "\x00", "\ud800", "x" * 32769):
            with self.subTest(bad_type=type(bad).__name__), self.assertRaises(self.module.OnlineCellsHold):
                self.module.encode_tool_cells("ETH&IB Switch", 17, "update", {"L": bad}, row_index=2)


class OnlineCellsSourceWorkflowTests(unittest.TestCase):
    def test_actual_local_noop_does_not_delete_full_qualified_online_business_intent(self):
        from monitor.issue_tracker_local_workbook import SwitchSourceWorkbookRow, project_switch_workbook_image
        from test_cases.test_issue_tracker_local_workbook import fake_workbook
        from test_cases.test_issue_tracker_cabling_projection import _sheet, _value, _cell
        module = load()
        raw = fake_workbook(reserved_switch_rows=2, existing_switch_id="NV10001")
        row = SwitchSourceWorkbookRow(("switch", "leaf02", "fan", "fan1"), "state=fail", "Compute",
                                       "type", "P2", "2026-10-07T01:00:00Z")
        expected = "[MONITOR][fan][fan1] [fabric_source=type] state=fail"
        with mock.patch("socket.socket", side_effect=AssertionError("network forbidden")):
            projected = project_switch_workbook_image(raw, (row,))
            sheet = _sheet(projected, 2)
            self.assertEqual("NV10002", _value(sheet, "A4"))
            self.assertEqual(expected, _value(sheet, "L4"))
            self.assertEqual("leaf02", _value(sheet, "F4"))
            self.assertIsNotNone(_cell(sheet, "D4").find("{http://schemas.openxmlformats.org/spreadsheetml/2006/main}f"))
            self.assertIsNone(_value(sheet, "O4"))
            self.assertEqual(projected, project_switch_workbook_image(projected, (row,)))
            values = module.source_tool_values(row, "update")
            self.assertEqual({"L": expected}, values)
            pending = module.encode_tool_cells("ETH&IB Switch", 17, "update", values, row_index=31,
                                               observed_values={"L": {"stringValue": "old remote evidence"}})
            self.assertEqual("WIRE-CANDIDATE", pending.outcome)
            self.assertEqual({"userEnteredValue": {"stringValue": expected}},
                             json.loads(pending.requests_json)[0]["updateCells"]["rows"][0]["values"][0])
            observed = module.encode_tool_cells("ETH&IB Switch", 17, "update", values, row_index=31,
                                                observed_values={"L": {"stringValue": expected}})
            self.assertEqual("OBSERVED-SATISFIED-AT-READ", observed.outcome)
            self.assertEqual([], json.loads(observed.requests_json))
        self.assertFalse(hasattr(observed, "receipt"))
        self.assertFalse(hasattr(observed, "permit"))

    def test_real_local_source_validation_to_literal_online_intent_no_refresh_timestamp(self):
        from monitor.issue_tracker_local_workbook import SwitchSourceWorkbookRow, CablingSourceRow
        module = load()
        first = SwitchSourceWorkbookRow(("switch", "node01", "fan", "fan1"), "down", "Compute",
                                         "type", "High", "2026-10-07T01:00:00Z")
        second = SwitchSourceWorkbookRow(first.activity_key, "down", "Compute", "type", "High",
                                          "2026-10-07T02:00:00Z")
        with mock.patch("socket.socket", side_effect=AssertionError("network forbidden")):
            values = module.source_tool_values(first, "update")
            self.assertEqual({"L": "[MONITOR][fan][fan1] [fabric_source=type] down"}, values)
            self.assertEqual(values, module.source_tool_values(second, "update"))
            result = module.encode_tool_cells("ETH&IB Switch", 17, "update", values, row_index=2,
                                              observed_values={"L": {"stringValue": values["L"]}})
            self.assertEqual("OBSERVED-SATISFIED-AT-READ", result.outcome)
            cabling = CablingSourceRow("IB Cabling", ("ib_cabling", "a", "p1", "Link Down"),
                                      ("a", "p1", "z", "p2"), (), "Missing", "absent", "2026-10-07T01:00:00Z")
            update = module.source_tool_values(cabling, "update")
            self.assertEqual("", update["M"])
            self.assertEqual("", update["T"])
            self.assertNotIn("A", update)
            self.assertNotIn("U", update)
            with self.assertRaises(module.OnlineCellsHold): module.source_tool_values(cabling, "insert")
            inserted = module.source_tool_values(cabling, "insert", reserved_id="NV30017")
            self.assertEqual("NV30017", inserted["A"])
            self.assertEqual("New", inserted["U"])
        self.assertFalse(hasattr(result, "permit"))


if __name__ == "__main__": unittest.main()
