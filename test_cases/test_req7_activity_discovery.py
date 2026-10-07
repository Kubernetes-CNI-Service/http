"""Independent bounded active/Closed observations; never absence or write authority."""
from copy import deepcopy
from dataclasses import replace
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


def sheet_document(sheet, rows, row_count=7):
    source = document(sheet, rows)
    source['sheets'][0]['properties'].update(sheetType='GRID', gridProperties={
        'rowCount': row_count, 'columnCount': 21 if sheet == 'ETH&IB Switch' else 29})
    return source


CAPACITY_FIELDS = 'spreadsheetId,sheets(properties(sheetId,title,sheetType,gridProperties(rowCount,columnCount)),data(startRow,startColumn,rowData(values(userEnteredValue))))'


def exact_row_document(sheet, row, index=6):
    width = 21 if sheet == 'ETH&IB Switch' else 29
    cells = [{} for _ in range(width)]
    def column(letter):
        result = 0
        for char in letter: result = result * 26 + ord(char) - 64
        return result - 1
    for letter, value in row.items(): cells[column(letter)] = {'userEnteredValue': value}
    return {'spreadsheetId': 'synthetic_spreadsheet_id_0001', 'sheets': [{
        'properties': {'sheetId': 17, 'title': sheet}, 'data': [{'startRow': index,
        'startColumn': 0, 'rowData': [{'values': cells}]}]}]}


class Req7ActiveRowBindingDirectTests(unittest.TestCase):
    setUp = Req7ActivityDiscoveryDirectTests.setUp

    def inputs(self, sheet='ETH&IB Switch'):
        row = switch_row('NV40017') if sheet == 'ETH&IB Switch' else cabling_row('NV40017')
        key = ('switch', 'switch-1', 'down', 'fabric') if sheet == 'ETH&IB Switch' else (
            'eth_cabling' if sheet == 'ETH Cabling' else 'ib_cabling', 'switch-1', 'swp1', 'Link Down')
        source = sheet_document(sheet, [{}, {}, {}, {}, row])
        exact = exact_row_document(sheet, row)
        return key, source, exact

    def observe(self, key, source, exact, *, sheet='ETH&IB Switch', discovery=None, rectangle=None):
        self.assertTrue(hasattr(self.module, 'observe_active_row'), 'original full discovery/exact-row binding missing')
        return self.module.observe_active_row(
            discovery or self.planner.prepare_activity_sheet_read(self.binding, self.token, sheet=sheet), grids.response(source),
            rectangle or self.planner.prepare_sheets_read(self.binding, self.token, mode='row_rectangle', sheet=sheet, first_row=7),
            grids.response(exact), sheet_id=17, activity_key=key)

    def test_row_coordinate_and_original_id_derive_from_full_key_then_exact_rectangle_for_every_family(self):
        for sheet in ('ETH&IB Switch', 'ETH Cabling', 'IB Cabling'):
            key, source, exact = self.inputs(sheet)
            result = self.observe(key, source, exact, sheet=sheet)
            self.assertEqual((17, sheet, key, 6, 'NV40017'),
                (result.sheet_id, result.sheet_title, result.activity_key, result.row_index, result.nv_id))
            cells = {column: dict(value) for index, column, value in result.cells}
            self.assertEqual({'stringValue': 'NV40017'}, cells['A'])
            self.assertEqual(21 if sheet == 'ETH&IB Switch' else 29, len(cells))
            self.assertEqual(hashlib.sha256(grids.response(source).data).hexdigest(), result.discovery_sha256)
            self.assertEqual(hashlib.sha256(grids.response(exact).data).hexdigest(), result.row_sha256)
            with self.assertRaises(AttributeError): result.row_index = 2
            for name in ('mutation_permit', 'complete', 'insert_allowed', 'applied'): self.assertFalse(hasattr(result, name))
            self.assertNotIn('switch-1', repr(result)); self.assertNotIn('NV40017', repr(result))

    def test_any_discovery_column_drift_including_peer_description_status_or_id_holds_without_retargeting(self):
        for sheet, columns in (('ETH&IB Switch', ('A', 'F', 'L', 'N')),
                               ('ETH Cabling', ('A', 'F', 'G', 'K', 'L', 'Q', 'R', 'U')),
                               ('IB Cabling', ('A', 'F', 'G', 'K', 'L', 'Q', 'R', 'U'))):
            key, source, exact = self.inputs(sheet)
            for letter in columns:
                index = ord(letter) - 65
                for replacement in ({'stringValue': 'different'}, {'formulaValue': '=private_sentinel()'}, {}):
                    changed = deepcopy(exact)
                    changed['sheets'][0]['data'][0]['rowData'][0]['values'][index] = {'userEnteredValue': replacement}
                    with self.subTest(sheet=sheet, column=letter):
                        with self.assertRaises(self.module.SheetsDecodeHold) as caught:
                            self.observe(key, source, changed, sheet=sheet)
                        self.assertIsNone(caught.exception.__context__)
                        self.assertNotIn('private_sentinel', str(caught.exception))

    def test_wrong_row_wrong_target_wrong_sheet_and_partial_discovery_cannot_be_active_row_binding(self):
        key, source, exact = self.inputs()
        variants = []
        changed = deepcopy(exact); changed['sheets'][0]['data'][0]['startRow'] = 2; variants.append(changed)
        changed = deepcopy(exact); changed['sheets'][0]['properties']['sheetId'] = 18; variants.append(changed)
        changed = deepcopy(exact); changed['spreadsheetId'] = 'foreign_spreadsheet_id_0002'; variants.append(changed)
        for changed in variants:
            with self.assertRaises(self.module.SheetsDecodeHold): self.observe(key, source, changed)
        for first, last in ((3, 7), (3, 5002)):
            plan = self.planner.prepare_sheets_read(self.binding, self.token, mode='discovery', sheet='ETH&IB Switch', first_row=first, last_row=last)
            with self.assertRaises(self.module.SheetsDecodeHold): self.observe(key, source, exact, discovery=plan)
        for row in ({}, switch_row('NV40017', 'Closed')):
            with self.assertRaises(self.module.SheetsDecodeHold): self.observe(key, sheet_document('ETH&IB Switch', [row]), exact)
        with self.assertRaises(self.module.OnlineActivityConflict):
            self.observe(key, sheet_document('ETH&IB Switch', [switch_row('NV40016'), {}, {}, {}, switch_row('NV40017')]), exact)

    def test_exact_row_keeps_formula_numeric_bool_and_operator_cells_without_treating_them_as_tool_values(self):
        key, source, exact = self.inputs()
        cells = exact['sheets'][0]['data'][0]['rowData'][0]['values']
        for index in (3, 4, 6, 7): cells[index] = {'userEnteredValue': {'formulaValue': '=original_lookup()'}}
        cells[8] = {}; cells[12] = {'userEnteredValue': {'numberValue': 0}}
        cells[14] = {'userEnteredValue': {'boolValue': False}}
        observed = self.observe(key, source, exact)
        values = {column: dict(value) for _index, column, value in observed.cells}
        self.assertEqual({'formulaValue': '=original_lookup()'}, values['D'])
        self.assertEqual({}, values['I']); self.assertEqual({'numberValue': 0}, values['M'])
        self.assertEqual({'boolValue': False}, values['O'])


def insertion_document(sheet, rows, row_count=7):
    # Independent explicit-column contract: every Cabling column contributes
    # to its append tail; Switch ignores lookup-only columns when selecting.
    columns = ('A', 'B', 'C', 'F', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U') if sheet == 'ETH&IB Switch' else (
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'AA', 'AB', 'AC')
    def number(letter):
        result = 0
        for char in letter: result = result * 26 + ord(char) - 64
        return result - 1
    value = sheet_document(sheet, [], row_count)
    value['sheets'][0]['data'] = [{'startRow': 2, 'startColumn': number(letter), 'rowData': [
        {'values': [{'userEnteredValue': row[letter]} if letter in row else {}]} for row in rows]}
        for letter in reversed(columns)]
    return value


def reserved_switch_row(index):
    row = {'A': literal('NV%05d' % (10001 + index - 2))}
    for letter in ('D', 'E', 'G', 'H'): row[letter] = {'formulaValue': '=IFNA(VLOOKUP(F%d,Inventory!C:K,2,False),"")' % (index + 1)}
    if index == 2: row['I'] = {'formulaValue': '=IFNA(VLOOKUP(F3,Inventory!C:K,7,False),"")'}
    return row


class Req7InsertionPositionDirectTests(unittest.TestCase):
    setUp = Req7ActivityDiscoveryDirectTests.setUp

    def observe(self, sheet, rows, *, exact=None, reserved=(), append_rows=1, capacity=7, occupancy=None, discovery=None, plan=None):
        key = ('switch', 'switch-1', 'down', 'fabric') if sheet == 'ETH&IB Switch' else (
            'eth_cabling' if sheet == 'ETH Cabling' else 'ib_cabling', 'switch-1', 'swp1', 'Link Down')
        self.assertTrue(hasattr(self.planner, 'prepare_insertion_sheet_read'), 'original insertion occupancy plan missing')
        self.assertTrue(hasattr(self.module, 'observe_insertion_position'), 'original insertion position proof missing')
        options = {}
        if exact is not None:
            index = exact['sheets'][0]['data'][0]['startRow']
            options = {'row_plan': self.planner.prepare_sheets_read(self.binding, self.token,
                mode='row_rectangle', sheet=sheet, first_row=index + 1), 'row_response': grids.response(exact)}
        return self.module.observe_insertion_position(
            self.planner.prepare_activity_sheet_read(self.binding, self.token, sheet=sheet), grids.response(discovery or sheet_document(sheet, rows, capacity)),
            plan or self.planner.prepare_insertion_sheet_read(self.binding, self.token, sheet=sheet),
            grids.response(occupancy or insertion_document(sheet, rows, capacity)), sheet_id=17, activity_key=key,
            reserved_row_indexes=reserved, append_rows=append_rows, **options)

    def test_fixed_original_columns_and_capacity_no_arbitrary_window_or_wide_range(self):
        self.assertTrue(hasattr(self.planner, 'prepare_insertion_sheet_read'), 'original insertion occupancy plan missing')
        for sheet, columns in (('ETH&IB Switch', ('A','B','C','F','J','K','L','M','N','O','P','Q','R','S','T','U')),
                               ('ETH Cabling', ('A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','AA','AB','AC')),
                               ('IB Cabling', ('A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','AA','AB','AC'))):
            plan = self.planner.prepare_insertion_sheet_read(self.binding, self.token, sheet=sheet)
            self.assertEqual({'includeGridData': ['true'], 'fields': [CAPACITY_FIELDS],
                'ranges': ["'%s'!%s3:%s5002" % (sheet, c, c) for c in columns]}, parse_qs(urlsplit(plan.path).query))
            self.assertEqual(('GET', b'', 30.0), (plan.method, plan.body, plan.budget_seconds))
            with self.assertRaises(TypeError): self.planner.prepare_insertion_sheet_read(self.binding, self.token, sheet=sheet, last_row=5)

    def test_switch_selects_first_original_free_unreserved_row_and_keeps_formula_and_preset_id(self):
        rows = [reserved_switch_row(i) for i in range(2, 7)]
        rows[0]['M'] = {'numberValue': 0}; rows[1]['O'] = {'boolValue': False}
        result = self.observe('ETH&IB Switch', rows, reserved=(4,), exact=exact_row_document('ETH&IB Switch', rows[3], 5))
        self.assertEqual((5, 'NV10004', 7), (result.row_index, result.nv_id, result.row_count))
        cells = {column: dict(value) for _index, column, value in result.cells}
        self.assertEqual(rows[3]['D'], cells['D']); self.assertEqual({}, cells['I'])
        first = self.observe('ETH&IB Switch', [reserved_switch_row(2)], capacity=3,
            exact=exact_row_document('ETH&IB Switch', reserved_switch_row(2), 2))
        self.assertEqual((2, 'NV10001'), (first.row_index, first.nv_id))
        self.assertEqual({'formulaValue': '=IFNA(VLOOKUP(F3,Inventory!C:K,7,False),"")'},
            {col: dict(value) for _, col, value in first.cells}['I'])
        for name in ('complete', 'applied', 'mutation_permit', 'insert_allowed'): self.assertFalse(hasattr(result, name))

    def test_every_switch_business_or_operator_column_occupies_row_even_explicit_empty_formula_zero_false(self):
        for column in ('B','C','F','J','K','L','M','N','O','P','Q','R','S','T','U'):
            for value in (literal(''), {'formulaValue': '=""'}, {'numberValue': 0}, {'boolValue': False}):
                rows = [reserved_switch_row(2), reserved_switch_row(3)]
                rows[0][column] = value
                # F/L/N are key columns: non-literal values fail strict activity
                # classification rather than being reinterpreted as empty.
                with self.subTest(column=column, value=value):
                    if column in ('F', 'L', 'N') and set(value) != {'stringValue'}:
                        with self.assertRaises(self.module.SheetsDecodeHold): self.observe('ETH&IB Switch', rows,
                            exact=exact_row_document('ETH&IB Switch', rows[1], 3))
                    else:
                        self.assertEqual(3, self.observe('ETH&IB Switch', rows,
                            exact=exact_row_document('ETH&IB Switch', rows[1], 3)).row_index)

    def test_switch_no_free_row_wrong_exact_row_lookup_or_id_drift_and_bad_reservation_fail_closed(self):
        row = reserved_switch_row(3); rows = [reserved_switch_row(2), row]
        for reserved in ((2,3), (True,), (2,2), (1,), (7,), [2]):
            with self.subTest(reserved=reserved):
                with self.assertRaises(self.module.SheetsDecodeHold): self.observe('ETH&IB Switch', rows, reserved=reserved,
                    exact=exact_row_document('ETH&IB Switch', row, 3))
        for column, value in (('A', literal('NV99999')), ('D', literal('lookup text')), ('E', {}), ('G', {'numberValue': 0}),
                              ('H', {'boolValue': False}), ('I', {'formulaValue': '=not_original()'}), ('M', literal('operator'))):
            exact_row = deepcopy(row); exact_row[column] = value
            with self.subTest(column=column):
                with self.assertRaises(self.module.SheetsDecodeHold) as caught: self.observe('ETH&IB Switch', rows,
                    reserved=(2,), exact=exact_row_document('ETH&IB Switch', exact_row, 3))
                self.assertIsNone(caught.exception.__context__)
        with self.assertRaises(self.module.SheetsDecodeHold): self.observe('ETH&IB Switch', rows,
            exact=exact_row_document('ETH&IB Switch', row, 3))
        with self.assertRaises(self.module.SheetsDecodeHold): self.observe('ETH&IB Switch', rows)

    def test_cabling_tail_includes_all_original_operator_tool_cells_gaps_and_exact_capacity(self):
        for sheet in ('ETH Cabling', 'IB Cabling'):
            for column in ('B','D','H','I','J','M','N','O','P','S','T','V','W','X','Y','Z','AA','AB','AC'):
                for value in (literal(''), {'formulaValue': '=""'}, {'numberValue': 0}, {'boolValue': False}):
                    rows = [{}, {}, {}, {}, {column: value}]
                    with self.subTest(sheet=sheet, column=column, value=value):
                        observed = self.observe(sheet, rows, capacity=8)
                        self.assertEqual((6, 7, 8, None), (observed.last_data_row_index, observed.row_index, observed.row_count, observed.nv_id))
                        with self.assertRaises(self.module.SheetsDecodeHold): self.observe(sheet, rows, capacity=7)
            empty = self.observe(sheet, [], capacity=4, append_rows=2)
            self.assertEqual((1, 2), (empty.last_data_row_index, empty.row_index))
            with self.assertRaises(self.module.SheetsDecodeHold): self.observe(sheet, [], capacity=4, append_rows=3)
            closed = cabling_row('NV40000', 'Closed')
            self.assertEqual(3, self.observe(sheet, [closed], capacity=4).row_index)
            with self.assertRaises(self.module.SheetsDecodeHold): self.observe(sheet, [cabling_row()], capacity=4)

    def test_cross_read_drift_partial_duplicate_foreign_capacity_and_invalid_counts_cannot_select_insert(self):
        rows = [reserved_switch_row(2)]
        original = insertion_document('ETH&IB Switch', rows, 3)
        mutations = []
        for key, value in (('rowCount', 5003), ('rowCount', True), ('columnCount', 20)):
            changed = deepcopy(original); changed['sheets'][0]['properties']['gridProperties'][key] = value; mutations.append(changed)
        changed = deepcopy(original); changed['sheets'][0]['data'].pop(); mutations.append(changed)
        changed = deepcopy(original); changed['sheets'][0]['data'].append(deepcopy(changed['sheets'][0]['data'][0])); mutations.append(changed)
        changed = deepcopy(original); changed['spreadsheetId'] = 'foreign_spreadsheet_id_0002'; mutations.append(changed)
        changed = deepcopy(original); changed['sheets'][0]['properties']['sheetId'] = 18; mutations.append(changed)
        changed = deepcopy(original); changed['sheets'][0]['data'][-1]['rowData'][0]['values'][0] = {'userEnteredValue': literal('NV99999')}; mutations.append(changed)
        for changed in mutations:
            with self.assertRaises(self.module.SheetsDecodeHold): self.observe('ETH&IB Switch', rows, capacity=3,
                occupancy=changed, exact=exact_row_document('ETH&IB Switch', rows[0], 2))
        for count in (True, 0, -1, 1001, 1.0, '1'):
            with self.assertRaises(self.module.SheetsDecodeHold): self.observe('ETH Cabling', [], append_rows=count)
        plan = self.planner.prepare_insertion_sheet_read(self.binding, self.token, sheet='ETH Cabling')
        for invalid in (replace(plan, path=plan.path.replace('5002','7')), replace(plan, host='foreign.invalid'),
                        replace(plan, budget_seconds=60.0), replace(plan, method='POST')):
            with self.assertRaises(self.module.SheetsDecodeHold): self.observe('ETH Cabling', [], plan=invalid)
        for discovery in (sheet_document('ETH Cabling', [], 6), sheet_document('ETH Cabling', [cabling_row('NV40000'),cabling_row('NV40001')])):
            with self.assertRaises(self.module.SheetsDecodeHold): self.observe('ETH Cabling', [], discovery=discovery)
        for capacity in (3, 5002):
            self.assertEqual(2, self.observe('ETH Cabling', [], capacity=capacity).row_index)
        for sheet in ('ETH Cabling', 'IB Cabling'):
            with self.assertRaises(self.module.SheetsDecodeHold): self.observe(sheet, [], reserved=(2,))

    def test_governance_covers_each_real_insertion_script_direct_and_multiscript_workflow(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root/'test_cases/script_test_manifest.json').read_text())
        paths = {'monitor/issue_tracker_sheets_read_plan.py','monitor/issue_tracker_sheets_read_decode.py',
                 'monitor/issue_tracker_tls_inputs.py','monitor/issue_tracker_online_cells.py'}
        self.assertTrue(any(rule['id'] == 'req7_native_original_insertion_position' and paths <= set(rule['members'])
            and 'test_cases.test_req7_activity_discovery' in rule['tests'] for rule in manifest['workflows']))
        for path in paths - {'monitor/issue_tracker_online_cells.py'}:
            self.assertTrue(any(path in rule['paths'] and 'test_cases.test_req7_activity_discovery' in rule['tests']
                for rule in manifest['test_rules']))
        self.assertIn('TC-REAL-REQ7-ACTIVE-CLOSED-DISCOVERY-001',(root/'test_cases/REAL_ENVIRONMENT.md').read_text())


class Req7ActivitySheetDirectTests(unittest.TestCase):
    # Existing finite-window tests remain a separate contract. Only new cases
    # use the same-response capacity-clipped full-body plan below.
    setUp = Req7ActivityDiscoveryDirectTests.setUp
    plan = Req7ActivityDiscoveryDirectTests.plan
    def full_plan(self, sheet='ETH&IB Switch'):
        self.assertTrue(hasattr(self.planner, 'prepare_activity_sheet_read'), 'capacity-clipped full activity read missing')
        return self.planner.prepare_activity_sheet_read(self.binding, self.token, sheet=sheet)

    def full_read(self, value, *, sheet='ETH&IB Switch', key=('switch', 'switch-1', 'down', 'fabric'), plan=None, raw=None):
        self.assertTrue(hasattr(self.module, 'discover_activity_sheet'), 'same-response full activity classifier missing')
        return self.module.discover_activity_sheet(plan or self.full_plan(sheet), raw or grids.response(value),
                                                   sheet_id=17, activity_key=key)

    def test_full_capacity_and_original_explicit_columns_are_requested_in_one_fixed_get(self):
        for sheet, columns in (('ETH&IB Switch', 'AFLN'), ('ETH Cabling', ('A', 'F', 'G', 'K', 'L', 'Q', 'R', 'U')),
                               ('IB Cabling', ('A', 'F', 'G', 'K', 'L', 'Q', 'R', 'U'))):
            with mock.patch('socket.socket') as networking: plan = self.full_plan(sheet)
            networking.assert_not_called()
            self.assertEqual({'includeGridData': ['true'], 'fields': [CAPACITY_FIELDS],
                              'ranges': ["'%s'!%s3:%s5002" % (sheet, c, c) for c in columns]}, parse_qs(urlsplit(plan.path).query))
            self.assertEqual(('GET', b'', 30.0), (plan.method, plan.body, plan.budget_seconds))
            with self.assertRaises(TypeError): self.planner.prepare_activity_sheet_read(self.binding, self.token, sheet=sheet, last_row=7)

    def test_last_capacity_row_is_not_truncated_and_nv_max_includes_closed_and_unrelated_rows(self):
        rows = [cabling_row('NV30017', 'Closed'), cabling_row('NV50000', 'Closed'), {}, {}, cabling_row('NV40000')]
        rows[1]['K'] = literal('unrelated')
        seen = self.full_read(sheet_document('ETH Cabling', rows), sheet='ETH Cabling', key=('eth_cabling', 'switch-1', 'swp1', 'Link Down'))
        self.assertEqual((7, 2, 6, 50000), (seen.row_count, seen.first_row_index, seen.last_row_index, seen.maximum_nv_id))
        self.assertEqual(((6, 'NV40000'),), seen.active_rows); self.assertEqual(((2, 'NV30017'),), seen.closed_rows)
        self.assertEqual(hashlib.sha256(grids.response(sheet_document('ETH Cabling', rows)).data).hexdigest(), seen.source_sha256)
        for field in ('permit', 'complete', 'allocation', 'applied'): self.assertFalse(hasattr(seen, field))

    def test_entire_empty_capacity_is_only_absence_observation_no_nonce_reservation_or_permission(self):
        for size in (3, 5002):
            seen = self.full_read(sheet_document('ETH&IB Switch', [], size))
            self.assertEqual((size, 2, size - 1, None), (seen.row_count, seen.first_row_index, seen.last_row_index, seen.maximum_nv_id))
            self.assertEqual((), seen.active_rows); self.assertEqual((), seen.closed_rows)
            with self.assertRaises(AttributeError): seen.row_count = 8

    def test_bad_capacity_non_grid_extra_properties_missing_or_over_capacity_column_holds(self):
        cases = []
        for value in (True, 2, 5003, '7', 7.0):
            item = sheet_document('ETH&IB Switch', []); item['sheets'][0]['properties']['gridProperties']['rowCount'] = value; cases.append(item)
        for value in (True, 20, '21', 21.0, 2147483648):
            item = sheet_document('ETH&IB Switch', []); item['sheets'][0]['properties']['gridProperties']['columnCount'] = value; cases.append(item)
        item = sheet_document('ETH&IB Switch', []); item['sheets'][0]['properties']['sheetType'] = 'DATA_SOURCE'; cases.append(item)
        item = sheet_document('ETH&IB Switch', []); item['sheets'][0]['properties'].pop('gridProperties'); cases.append(item)
        item = sheet_document('ETH&IB Switch', []); item['sheets'][0]['properties']['extra'] = 1; cases.append(item)
        item = sheet_document('ETH&IB Switch', []); item['sheets'][0]['data'].pop(); cases.append(item)
        item = sheet_document('ETH&IB Switch', [switch_row()], 3); item['sheets'][0]['data'][0]['rowData'].append({}); cases.append(item)
        for item in cases:
            with self.subTest(item=item), self.assertRaises(self.module.SheetsDecodeHold): self.full_read(item)

    def test_duplicate_active_key_beyond_old_window_is_conflict_and_bad_last_id_holds(self):
        rows = [switch_row('NV30017'), {}, {}, {}, switch_row('NV30019')]
        with self.assertRaises(self.module.OnlineActivityConflict): self.full_read(sheet_document('ETH&IB Switch', rows))
        rows[-1] = switch_row('NV1')
        with self.assertRaises(self.module.SheetsDecodeHold): self.full_read(sheet_document('ETH&IB Switch', rows))
        rows[-1] = switch_row('NV30017', 'Closed')
        with self.assertRaises(self.module.SheetsDecodeHold): self.full_read(sheet_document('ETH&IB Switch', rows))

    def test_finite_discovery_wrong_sheet_target_or_forged_capacity_plan_is_not_full_discovery(self):
        source = sheet_document('ETH&IB Switch', []); full = self.full_plan()
        for plan in (self.plan(), replace(full, path=full.path.replace('5002', '7')),
                     replace(full, host='foreign.invalid'), replace(full, budget_seconds=60.0)):
            with self.assertRaises(self.module.SheetsDecodeHold): self.full_read(source, plan=plan)
        source['sheets'][0]['properties']['sheetId'] = 18
        with self.assertRaises(self.module.SheetsDecodeHold): self.full_read(source)
        source = sheet_document('ETH&IB Switch', []); source['spreadsheetId'] = 'foreign_spreadsheet_0002'
        with self.assertRaises(self.module.SheetsDecodeHold): self.full_read(source)
        raw = grids.response(sheet_document('ETH&IB Switch', []))
        for response in (replace_mock(200, False, raw.data), replace_mock(503, True, raw.data),
                         replace_mock(200, True, b'{"sheets":[],"sheets":[]}')):
            with self.assertRaises(self.module.SheetsDecodeHold): self.full_read({}, raw=response)


class Req7ActivityDiscoveryNativeWorkflowTests(unittest.TestCase):
    setUp = plans.Req7SheetsNativeReadWorkflowTests.setUp
    fixture = plans.Req7SheetsNativeReadWorkflowTests.fixture
    certificates = plans.Req7SheetsNativeReadWorkflowTests.certificates
    server = plans.Req7SheetsNativeReadWorkflowTests.server

    def native_inputs(self):
        from test_cases.test_req7_sdk_authentication import load as load_auth
        from monitor.issue_tracker_online_target import OnlineTargetBinding
        import time
        auth = load_auth()
        return (plans.load(), grids.load(), OnlineTargetBinding('synthetic_spreadsheet_id_0001', 'a' * 64, 'b' * 64),
                auth.AuthenticatedToken('sentinel.private-token', time.time() + 3600))

    def native_read(self, unit, value):
        payload = json.dumps(value).encode()
        reply = ('HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(payload)).encode() + payload
        with self.server(reply, hostname='sheets.googleapis.com', destination='sheets.googleapis.com') as (records, errors), self.fixture():
            result = unit.send_once()
            with self.assertRaises(self.module.TlsInputHold): unit.send_once()
        self.assertEqual([], errors); self.assertEqual(1, len(records)); self.assertEqual(b'', records[0][2])
        return result, records[0]

    def test_full_capacity_discovery_then_exact_key_row_rectangle_and_literal_update_preserve_id(self):
        planner, decoder, binding, token = self.native_inputs()
        source = sheet_document('ETH&IB Switch', [switch_row('NV30000', 'Closed'), {}, {}, {}, switch_row('NV30019')])
        plan = planner.prepare_activity_sheet_read(binding, token, sheet='ETH&IB Switch')
        raw, request = self.native_read(self.module.NativeActivitySheetReadUnit(binding, token, sheet='ETH&IB Switch'), source)
        observed = decoder.discover_activity_sheet(plan, raw, sheet_id=17, activity_key=('switch', 'switch-1', 'down', 'fabric'))
        self.assertEqual(((6, 'NV30019'),), observed.active_rows); self.assertEqual(((2, 'NV30000'),), observed.closed_rows)
        self.assertEqual(plan.path, request[0].decode().strip().split(' ')[1])
        rectangle = grids.row_response(); grid = rectangle['sheets'][0]['data'][0]
        grid['startRow'] = 6; values = grid['rowData'][0]['values']; values[8] = {}
        for column, value in switch_row('NV30019').items(): values[ord(column) - 65] = {'userEnteredValue': value}
        row_plan = planner.prepare_sheets_read(binding, token, mode='row_rectangle', sheet='ETH&IB Switch', first_row=7)
        row_raw, request = self.native_read(self.module.NativeSheetsReadUnit(binding, token, mode='row_rectangle', sheet='ETH&IB Switch', first_row=7), rectangle)
        row = decoder.decode_sheets_read(row_plan, row_raw)
        original = {column: dict(value) for _index, column, value in row.cells}
        self.assertEqual({'stringValue': 'NV30019'}, original['A']); self.assertEqual({'stringValue': 'switch-1'}, original['F'])
        from monitor.issue_tracker_online_cells import encode_tool_cells
        encoded = encode_tool_cells('ETH&IB Switch', 17, 'update', {'L': 'new literal evidence'}, row_index=6, observed_values={'L': original['L']})
        self.assertEqual([{'updateCells': {'start': {'sheetId': 17, 'rowIndex': 6, 'columnIndex': 11},
            'rows': [{'values': [{'userEnteredValue': {'stringValue': 'new literal evidence'}}]}], 'fields': 'userEnteredValue'}}], json.loads(encoded.requests_json))
        self.assertEqual(row_plan.path, request[0].decode().strip().split(' ')[1])

    def test_both_cabling_full_column_a_maxima_include_closed_rows_without_allocating_or_writing(self):
        planner, decoder, binding, token = self.native_inputs(); maxima = []
        for sheet, sid, identifier, key in (('ETH Cabling', 17, 'NV30017', ('eth_cabling', 'switch-1', 'swp1', 'Link Down')),
                                             ('IB Cabling', 18, 'NV60000', ('ib_cabling', 'switch-1', 'swp1', 'Link Down'))):
            source = sheet_document(sheet, [cabling_row(identifier, 'Closed')]); source['sheets'][0]['properties']['sheetId'] = sid
            raw, request = self.native_read(self.module.NativeActivitySheetReadUnit(binding, token, sheet=sheet), source)
            seen = decoder.discover_activity_sheet(planner.prepare_activity_sheet_read(binding, token, sheet=sheet), raw,
                                                   sheet_id=sid, activity_key=key)
            self.assertEqual((), seen.active_rows); maxima.append(seen.maximum_nv_id)
        self.assertEqual([30017, 60000], maxima)

    def test_original_full_discovery_and_exact_native_row_bind_actual_literal_update_for_all_families(self):
        from monitor.issue_tracker_online_cells import encode_tool_cells
        planner, decoder, binding, token = self.native_inputs()
        for sheet in ('ETH&IB Switch', 'ETH Cabling', 'IB Cabling'):
            row = switch_row('NV40017') if sheet == 'ETH&IB Switch' else cabling_row('NV40017')
            key = ('switch', 'switch-1', 'down', 'fabric') if sheet == 'ETH&IB Switch' else (
                'eth_cabling' if sheet == 'ETH Cabling' else 'ib_cabling', 'switch-1', 'swp1', 'Link Down')
            source = sheet_document(sheet, [{}, {}, {}, {}, row])
            exact = exact_row_document(sheet, row)
            discovery_plan = planner.prepare_activity_sheet_read(binding, token, sheet=sheet)
            row_plan = planner.prepare_sheets_read(binding, token, mode='row_rectangle', sheet=sheet, first_row=7)
            raw_discovery, _ = self.native_read(self.module.NativeActivitySheetReadUnit(binding, token, sheet=sheet), source)
            raw_row, _ = self.native_read(self.module.NativeSheetsReadUnit(binding, token, mode='row_rectangle', sheet=sheet, first_row=7), exact)
            self.assertTrue(hasattr(decoder, 'observe_active_row'), 'native original-image active-row binding missing')
            observed = decoder.observe_active_row(discovery_plan, raw_discovery, row_plan, raw_row, sheet_id=17, activity_key=key)
            self.assertEqual((6, 'NV40017'), (observed.row_index, observed.nv_id))
            original = {column: dict(value) for _index, column, value in observed.cells}
            intended = {'L': 'new literal evidence'} if sheet == 'ETH&IB Switch' else {
                'G': 'new literal evidence', 'M': 'actual-a', 'N': 'actual-port', 'S': 'actual-z', 'T': 'z-port'}
            encoded = encode_tool_cells(observed.sheet_title, observed.sheet_id, 'update', intended,
                row_index=observed.row_index, observed_values={column: original[column] for column in intended})
            requests = json.loads(encoded.requests_json)
            self.assertEqual([11] if sheet == 'ETH&IB Switch' else [6, 12, 18],
                [request['updateCells']['start']['columnIndex'] for request in requests])
            for request in requests:
                update = request['updateCells']
                self.assertEqual({'sheetId': 17, 'rowIndex': 6, 'columnIndex': update['start']['columnIndex']}, update['start'])
                self.assertEqual('userEnteredValue', update['fields'])
                for value in update['rows'][0]['values']: self.assertEqual({'stringValue'}, set(value['userEnteredValue']))
            # Encoder creates bytes only; the original ID and every source image remain unchanged.
            self.assertEqual({'stringValue': 'NV40017'}, original['A'])
            self.assertEqual(exact_row_document(sheet, row), exact)

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

    def test_native_original_discovery_occupancy_and_switch_rectangle_bind_literal_insert_candidates(self):
        from monitor.issue_tracker_online_cells import encode_tool_cells
        planner, decoder, binding, token = self.native_inputs()
        self.assertTrue(hasattr(self.module, 'NativeInsertionSheetReadUnit'), 'native insertion read unit missing')
        for sheet in ('ETH&IB Switch', 'ETH Cabling', 'IB Cabling'):
            rows = [reserved_switch_row(2), reserved_switch_row(3)] if sheet == 'ETH&IB Switch' else [cabling_row('NV40000', 'Closed'), {}, {'AB': {'boolValue': False}}]
            key = ('switch','switch-1','down','fabric') if sheet == 'ETH&IB Switch' else (
                'eth_cabling' if sheet == 'ETH Cabling' else 'ib_cabling','switch-1','swp1','Link Down')
            discovery, _ = self.native_read(self.module.NativeActivitySheetReadUnit(binding, token, sheet=sheet), sheet_document(sheet, rows))
            occupancy, request = self.native_read(self.module.NativeInsertionSheetReadUnit(binding, token, sheet=sheet), insertion_document(sheet, rows))
            occupancy_plan = planner.prepare_insertion_sheet_read(binding, token, sheet=sheet)
            self.assertEqual(occupancy_plan.path, request[0].decode().strip().split(' ')[1])
            options = {}
            if sheet == 'ETH&IB Switch':
                exact, _ = self.native_read(self.module.NativeSheetsReadUnit(binding, token, mode='row_rectangle', sheet=sheet, first_row=4), exact_row_document(sheet, rows[1], 3))
                options = {'row_plan': planner.prepare_sheets_read(binding, token, mode='row_rectangle', sheet=sheet, first_row=4), 'row_response': exact}
            position = decoder.observe_insertion_position(planner.prepare_activity_sheet_read(binding, token, sheet=sheet), discovery,
                occupancy_plan, occupancy, sheet_id=17, activity_key=key, reserved_row_indexes=(2,) if sheet == 'ETH&IB Switch' else (), append_rows=1, **options)
            self.assertEqual(3 if sheet == 'ETH&IB Switch' else 5, position.row_index)
            if sheet == 'ETH&IB Switch':
                values = {'B':'ZTP Monitor','C':'ZTP Monitor','F':'switch-1','J':'2026-10-08T01:00:00Z','K':'High','L':'[MONITOR][down][fabric] literal','N':'New'}
                candidate = encode_tool_cells(sheet, 17, 'insert', values, row_index=position.row_index)
                requests = json.loads(candidate.requests_json)
                self.assertEqual([1,5,9,13], [item['updateCells']['start']['columnIndex'] for item in requests])
                self.assertEqual({3}, {item['updateCells']['start']['rowIndex'] for item in requests})
                self.assertEqual(rows[1]['D'], {col:dict(value) for _,col,value in position.cells}['D'])
                self.assertEqual('NV10002', position.nv_id)
            else:
                values = {'A':'NV40001','B':'ZTP Monitor','C':'ZTP Monitor','D':'2026-10-08T01:00:00Z','E':'ETH' if sheet == 'ETH Cabling' else 'IB',
                    'F':'Link Down','G':'literal','K':'switch-1','L':'swp1','M':'','N':'',
                    'Q':'switch-2','R':'swp2','S':'','T':'','U':'New'}
                candidate = encode_tool_cells(sheet,17,'insert',values)
                requests = json.loads(candidate.requests_json)
                self.assertEqual({'appendCells'},set(requests[0])); self.assertEqual({'sheetId','rows','fields'},set(requests[0]['appendCells']))
                self.assertEqual(17, requests[0]['appendCells']['sheetId'])
                values = requests[0]['appendCells']['rows'][0]['values']
                for index in (7,8,9,14,15): self.assertEqual({}, values[index])
            for item in requests:
                for cell in next(iter(item.values()))['rows'][0]['values']:
                    if cell: self.assertEqual({'stringValue'},set(cell['userEnteredValue']))

    def test_governed_manifest_binds_real_discovery_flow_and_not_run_card(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root/"test_cases/script_test_manifest.json").read_text())
        self.assertTrue(any(rule["id"]=="req7_native_active_closed_discovery"
                            and {"monitor/issue_tracker_sheets_read_plan.py","monitor/issue_tracker_sheets_read_decode.py",
                                 "monitor/issue_tracker_tls_inputs.py"}<=set(rule["members"])
                            and "test_cases.test_req7_activity_discovery" in rule["tests"] for rule in manifest["workflows"]))
        for script in ("monitor/issue_tracker_sheets_read_plan.py","monitor/issue_tracker_sheets_read_decode.py","monitor/issue_tracker_tls_inputs.py"):
            self.assertTrue(any(script in rule["paths"] and "test_cases.test_req7_activity_discovery" in rule["tests"]
                                for rule in manifest["test_rules"]))
        self.assertIn("TC-REAL-REQ7-ACTIVE-CLOSED-DISCOVERY-001",(root/"test_cases/REAL_ENVIRONMENT.md").read_text())


if __name__ == "__main__": unittest.main()
