"""Independent finite Switch occupancy and displacement checks, fake-only."""

import copy
import importlib.util
from pathlib import Path
import sys
import unittest


def load():
    path = Path(__file__).resolve().parents[1] / "monitor/issue_tracker_online_rows.py"
    if not path.is_file(): raise AssertionError("finite Switch row planner is missing")
    spec = importlib.util.spec_from_file_location("isolated_online_rows", path)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def row(index=3):
    values = {chr(65 + i): {} for i in range(21)}
    values["A"] = {"stringValue": f"NV{10000 + index:05d}"}
    for column in ("D", "E", "G", "H"):
        values[column] = {"formulaValue": f"=LOOKUP(F{index + 1})"}
    if index == 2: values["I"] = {"formulaValue": "=LOOKUP(F3)"}
    return (index, values)


class OnlineRowsDirectTests(unittest.TestCase):
    def setUp(self): self.module = load()

    def test_free_row_checks_every_tool_and_operator_occupancy_cell_and_reservations(self):
        baseline = row()
        for column in ("B", "C", "F", *tuple("JKLMNOPQRSTU")):
            for occupied in ({"stringValue": "operator value"}, {"formulaValue": '=IF(TRUE,"","")'},
                             {"numberValue": 0}, {"boolValue": False}):
                busy = copy.deepcopy(baseline); busy[1][column] = occupied
                with self.subTest(column=column, occupied=occupied), self.assertRaises(self.module.OnlineRowsHold):
                    self.module.select_switch_free_row((busy,))
        first, second = row(2), row(3)
        selected = self.module.select_switch_free_row((second, first), reserved_rows=(2,))
        self.assertEqual(3, selected.row_index)
        self.assertEqual("NV10003", selected.issue_id)
        self.assertFalse(hasattr(selected, "permit"))
        with self.assertRaises(self.module.OnlineRowsHold):
            self.module.select_switch_free_row((first, second), reserved_rows=(2, 3))
        self.assertEqual(baseline, row())

    def test_formula_headroom_reserved_ids_and_bounds_fail_closed_without_fabricating_rows(self):
        invalid = []
        for column in ("A", "D", "E", "G", "H"):
            value = row(); value[1][column] = {}; invalid.append((value,))
        value = row(); value[1]["I"] = {"formulaValue": "=1"}; invalid.append((value,))
        value = row(2); value[1]["I"] = {}; invalid.append((value,))
        value = row(); del value[1]["U"]; invalid.append((value,))
        value = row(); value[1]["A"] = {"numberValue": 10003}; invalid.append((value,))
        invalid.extend(((), (row(1),), (row(5002),), (row(True),), (row(), row()),
                        ((3, {"A": {"stringValue": "NV10003"}}),)))
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(self.module.OnlineRowsHold):
                self.module.select_switch_free_row(values)
        for reserved in ((True,), (1,), (5002,), (3, 3), [3]):
            with self.assertRaises(self.module.OnlineRowsHold):
                self.module.select_switch_free_row((row(),), reserved_rows=reserved)

    def test_held_row_digest_detects_displacement_and_any_prewrite_change(self):
        observed = row()
        selected = self.module.select_switch_free_row((observed,))
        self.assertIsNone(self.module.require_switch_row_unchanged(selected, observed))
        changes = []
        for column in tuple("ABCDEFGHIJKLMNOPQRSTU"):
            changed = copy.deepcopy(observed)
            changed[1][column] = {"stringValue": "changed"}
            changes.append(changed)
        changes.append((4, observed[1]))
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaises(self.module.OnlineRowsHold):
                self.module.require_switch_row_unchanged(selected, changed)
        observed[1]["F"] = {"stringValue": "newly occupied"}
        with self.assertRaises(self.module.OnlineRowsHold):
            self.module.require_switch_row_unchanged(selected, observed)


class OnlineRowsWorkbookWorkflowTests(unittest.TestCase):
    def test_real_cell_requests_and_postread_detect_operator_formula_and_row_displacement(self):
        from test_cases.test_issue_tracker_online_cells import load as load_cells
        import json
        module = load()
        before = row(3)
        frozen = module.select_switch_free_row((before,))
        intended = {"B": "2026-10-07", "C": "ZTP Monitor", "F": "leaf01", "J": "ETH",
                    "K": "P2", "L": "[MONITOR][fan][fan1] degraded", "N": "New"}
        requests = json.loads(load_cells().encode_tool_cells(
            "ETH&IB Switch", 6, "insert", intended, row_index=3).requests_json)
        # Fake applies the documented index-addressed updateCells requests,
        # never CAS, row-key lookup or rollback.
        after = copy.deepcopy(before)
        for item in requests:
            change = item["updateCells"]
            self.assertEqual(3, change["start"]["rowIndex"])
            for offset, cell in enumerate(change["rows"][0]["values"]):
                letter = chr(65 + change["start"]["columnIndex"] + offset)
                after[1][letter] = cell["userEnteredValue"]
        self.assertIsNone(module.require_switch_insert_postimage(frozen, before, after, intended))
        self.assertEqual({}, before[1]["F"])
        self.assertEqual({"stringValue": "leaf01"}, after[1]["F"])
        for column in tuple("ABCDEFGHIJKLMNOPQRSTU"):
            displaced = copy.deepcopy(after)
            displaced[1][column] = {"stringValue": "concurrent human edit"}
            with self.subTest(column=column), self.assertRaises(module.OnlineRowConflict):
                module.require_switch_insert_postimage(frozen, before, displaced, intended)
        with self.assertRaises(module.OnlineRowConflict):
            module.require_switch_insert_postimage(frozen, before, (4, after[1]), intended)
        self.assertEqual({"stringValue": "leaf01"}, after[1]["F"])
        # Detection is not rollback: original fake-applied image stays changed.

    def test_actual_template_reserved_rows_and_formula_cells_drive_literal_insert_candidate(self):
        from test_cases.test_issue_tracker_local_workbook import fake_workbook
        from test_cases.test_issue_tracker_cabling_projection import _sheet, _value
        from monitor.issue_tracker_local_workbook import _MAIN
        from test_cases.test_issue_tracker_online_cells import load as load_cells
        import hashlib
        import json
        raw = fake_workbook(existing_switch_id="NV10001", reserved_switch_rows=2)
        before = hashlib.sha256(raw).hexdigest()
        sheet = _sheet(raw, 2)
        observations = []
        for number in (3, 4):
            cells = {cell.get("r"): cell for cell in sheet.iter(f"{{{_MAIN}}}c")}
            values = {}
            for column in tuple("ABCDEFGHIJKLMNOPQRSTU"):
                cell = cells.get(f"{column}{number}")
                formula = cell.find(f"{{{_MAIN}}}f") if cell is not None else None
                if formula is not None: values[column] = {"formulaValue": formula.text}
                else:
                    value = _value(sheet, f"{column}{number}")
                    values[column] = {"stringValue": value} if value else {}
            observations.append((number - 1, values))
        selected = load().select_switch_free_row(tuple(observations), reserved_rows=(2,))
        self.assertEqual(3, selected.row_index)
        self.assertEqual("NV10002", selected.issue_id)
        values = {"B": "2026-10-07", "C": "ZTP Monitor", "F": "leaf01", "J": "ETH",
                  "K": "P2", "L": "[MONITOR][fan][fan1] degraded", "N": "New"}
        encoded = load_cells().encode_tool_cells("ETH&IB Switch", 6, "insert", values,
                                                 row_index=selected.row_index)
        requests = json.loads(encoded.requests_json)
        self.assertTrue(all(item["updateCells"]["start"]["rowIndex"] == 3 for item in requests))
        touched = {item["updateCells"]["start"]["columnIndex"] + offset
                   for item in requests for offset in range(len(item["updateCells"]["rows"][0]["values"]))}
        self.assertEqual({1, 2, 5, 9, 10, 11, 13}, touched)
        self.assertEqual(before, hashlib.sha256(raw).hexdigest())


if __name__ == "__main__": unittest.main()
