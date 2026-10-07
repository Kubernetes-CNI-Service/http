"""Independent bounded History observations; never COMPLETE or send authority."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import test_cases
MAIN = Path(test_cases.__file__).resolve().parents[1]
ROOT = Path(__file__).resolve().parents[1]
TARGET = 'synthetic_spreadsheet_id_0001'
FIELDS = 'spreadsheetId,sheets(properties(sheetId,title),data(startRow,startColumn,rowData(values(userEnteredValue))))'


def load(name):
    path = ROOT / 'monitor' / (name + '.py')
    spec = importlib.util.spec_from_file_location('monitor.' + name, path)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module); return module


def inputs():
    from monitor.issue_tracker_online_target import OnlineTargetBinding
    from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
    return OnlineTargetBinding(TARGET, 'a' * 64, 'b' * 64), AuthenticatedToken('sentinel.private-token', time.time() + 3600)


def document():
    return {'spreadsheetId': TARGET, 'sheets': [{'properties': {'sheetId': 99, 'title': 'Update_History'},
        'data': [{'startRow': 8, 'rowData': [{'values': [
            {'userEnteredValue': {'stringValue': value}} for value in
            ('2026-10-08T10:00:00Z', 'ETH&IB Switch', 'update', 'switch:0001', '{"literal":"=no evaluation"}')]}]}]}]}


def response(value):
    return SimpleNamespace(status=200, complete=True, data=json.dumps(value, ensure_ascii=True).encode())


class Req7HistoryReadDirectTests(unittest.TestCase):
    def setUp(self):
        self.planner = load('issue_tracker_sheets_read_plan'); self.decoder = load('issue_tracker_sheets_read_decode')
        self.binding, self.token = inputs()

    def plan(self, first=9, last=11):
        self.assertTrue(hasattr(self.planner, 'prepare_history_read'), 'fixed finite History read absent')
        return self.planner.prepare_history_read(self.binding, self.token, first_row=first, last_row=last)

    def observe(self, value=None, plan=None, sheet_id=99):
        self.assertTrue(hasattr(self.decoder, 'decode_history_read'), 'typed History rectangle decoder absent')
        return self.decoder.decode_history_read(plan or self.plan(), response(document() if value is None else value), sheet_id=sheet_id)

    def test_exact_five_column_rectangle_has_no_arbitrary_sheet_fields_url_or_unbounded_tail(self):
        with mock.patch('socket.socket') as network: plan = self.plan()
        network.assert_not_called()
        self.assertEqual({'includeGridData': ['true'], 'fields': [FIELDS], 'ranges': ["'Update_History'!A9:E11"]}, parse_qs(urlsplit(plan.path).query))
        self.assertEqual('/v4/spreadsheets/' + TARGET, urlsplit(plan.path).path)
        self.assertEqual(('sheets.googleapis.com', 'GET', b'', 30.0), (plan.host, plan.method, plan.body, plan.budget_seconds))
        self.assertNotIn('sentinel.private-token', repr(plan)); self.assertFalse(hasattr(plan, 'permit'))
        with self.assertRaises(TypeError): self.planner.prepare_history_read(self.binding, self.token, first_row=9, last_row=11, sheet='foreign')

    def test_limits_refuse_truncation_boolean_and_invalid_token_or_target(self):
        self.plan(3, 5002)
        for first, last in ((2, 3), (True, 3), (3, True), (10, 9), (3, 5003), (2147483647, 2147483648)):
            with self.subTest(first=first, last=last), self.assertRaises(self.planner.SheetsReadHold): self.plan(first, last)
        for binding, token in ((replace(self.binding, spreadsheet_id='foreign/path'), self.token),
                               (self.binding, replace(self.token, value='token\r\nInjected: x')),
                               (self.binding, replace(self.token, expires_at=True))):
            with self.assertRaises(self.planner.SheetsReadHold): self.planner.prepare_history_read(binding, token, first_row=9, last_row=11)

    def test_complete_typed_rectangle_preserves_formula_number_bool_and_omitted_empty_rows(self):
        item = document(); item['sheets'][0]['data'][0]['rowData'].append({'values': [
            {'userEnteredValue': {'formulaValue': '=literal(1, 2)\n'}}, {'userEnteredValue': {'numberValue': 3}},
            {'userEnteredValue': {'boolValue': True}}, {}, {'userEnteredValue': {'stringValue': ' trailing '}}]})
        observed = self.observe(item)
        self.assertEqual((99, 'Update_History'), (observed.sheet_id, observed.sheet_title))
        self.assertEqual(15, len(observed.cells))
        self.assertEqual((8, 'D', (('stringValue', 'switch:0001'),)), observed.cells[3])
        self.assertEqual((9, 'A', (('formulaValue', '=literal(1, 2)\n'),)), observed.cells[5])
        self.assertEqual((9, 'B', (('numberValue', 3),)), observed.cells[6])
        self.assertEqual((9, 'C', (('boolValue', True),)), observed.cells[7])
        self.assertEqual(tuple((10, letter, ()) for letter in 'ABCDE'), observed.cells[10:])
        self.assertEqual(hashlib.sha256(response(item).data).hexdigest(), observed.source_sha256)
        self.assertFalse(hasattr(observed, 'complete')); self.assertFalse(hasattr(observed, 'permit'))
        with self.assertRaises(AttributeError): observed.cells = ()

    def test_foreign_grid_missing_duplicate_shift_extra_column_and_wrong_identity_hold(self):
        self.assertTrue(hasattr(self.decoder, 'decode_history_read'), 'typed History rectangle decoder absent')
        cases = []
        for field, value in (('startRow', 9), ('startRow', True), ('startColumn', 1), ('startColumn', True)):
            item = document(); item['sheets'][0]['data'][0][field] = value; cases.append(item)
        for field, value in (('sheetId', True), ('sheetId', 17), ('title', 'Update_History ')):
            item = document(); item['sheets'][0]['properties'][field] = value; cases.append(item)
        for mutate in (lambda item: item['sheets'].clear(), lambda item: item['sheets'].append(deepcopy(item['sheets'][0])),
                       lambda item: item['sheets'][0]['data'].clear(),
                       lambda item: item['sheets'][0]['data'].append(deepcopy(item['sheets'][0]['data'][0])),
                       lambda item: item['sheets'][0]['data'][0]['rowData'][0]['values'].append({}),
                       lambda item: item['sheets'][0]['data'][0]['rowData'].extend([{}, {}, {}])):
            item = document(); mutate(item); cases.append(item)
        item = document(); item['spreadsheetId'] = 'foreign_spreadsheet_0002'; cases.append(item)
        for item in cases:
            with self.subTest(case=cases.index(item)), self.assertRaises(self.decoder.SheetsDecodeHold) as caught: self.observe(item)
            self.assertIsNone(caught.exception.__context__)
        for identifier in (True, -1, 2147483648, '99'):
            with self.assertRaises(self.decoder.SheetsDecodeHold): self.observe(sheet_id=identifier)

    def test_partial_non200_duplicate_json_forged_plan_and_invalid_literal_never_complete(self):
        plan = self.plan(); raw = response(document())
        cases = (SimpleNamespace(status=200, complete=False, data=raw.data), SimpleNamespace(status=True, complete=True, data=raw.data),
                 SimpleNamespace(status=503, complete=True, data=raw.data), SimpleNamespace(status=200, complete=True, data=b' ' * (2 * 1024 * 1024 + 1)),
                 SimpleNamespace(status=200, complete=True, data=b'{"spreadsheetId":"x","spreadsheetId":"x","sheets":[]}'))
        self.assertTrue(hasattr(self.decoder, 'decode_history_read'))
        for case in cases:
            with self.assertRaises(self.decoder.SheetsDecodeHold): self.decoder.decode_history_read(plan, case, sheet_id=99)
        for forged in (replace(plan, host='foreign.invalid'), replace(plan, method='POST'), replace(plan, body=b'{}'),
                       replace(plan, path=plan.path + '&ranges=A:ZZ'), replace(plan, budget_seconds=60.0), SimpleNamespace(**plan.__dict__)):
            with self.assertRaises(self.decoder.SheetsDecodeHold): self.decoder.decode_history_read(forged, raw, sheet_id=99)
        for cell in ({'formattedValue': 'text'}, {'userEnteredValue': {'numberValue': True}},
                     {'userEnteredValue': {'stringValue': '\ud800'}}, {'userEnteredValue': {'stringValue': 'x', 'formulaValue': '=x'}}):
            item = document(); item['sheets'][0]['data'][0]['rowData'][0]['values'][0] = cell
            with self.assertRaises(self.decoder.SheetsDecodeHold): self.observe(item)


class Req7HistoryReadNativeWorkflowTests(unittest.TestCase):
    def setUp(self):
        from test_cases.test_req7_sheets_read_plan import Req7SheetsNativeReadWorkflowTests
        Req7SheetsNativeReadWorkflowTests.setUp(self)
        self.tls = load('issue_tracker_tls_inputs'); self.module = self.tls
        self.planner = load('issue_tracker_sheets_read_plan'); self.decoder = load('issue_tracker_sheets_read_decode')
        self.binding, self.token = inputs()

    from test_cases.test_req7_sheets_read_plan import Req7SheetsNativeReadWorkflowTests as _Fixture
    fixture = _Fixture.fixture; certificates = _Fixture.certificates; server = _Fixture.server

    def test_actual_tls_read_bound_history_rectangle_once_preserves_typed_original_bytes(self):
        self.assertTrue(hasattr(self.tls, 'NativeHistoryReadUnit'), 'one-shot native History read missing')
        payload = response(document()).data
        wire = ('HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(payload)).encode() + payload
        unit = self.tls.NativeHistoryReadUnit(self.binding, self.token, first_row=9, last_row=11)
        plan = self.planner.prepare_history_read(self.binding, self.token, first_row=9, last_row=11)
        with self.server(wire, hostname='sheets.googleapis.com', destination='sheets.googleapis.com') as (records, errors), self.fixture():
            observed = self.decoder.decode_history_read(plan, unit.send_once(), sheet_id=99)
            with self.assertRaises(self.tls.TlsInputHold): unit.send_once()
        self.assertEqual([], errors); self.assertEqual(1, len(records)); self.assertEqual(b'', records[0][2])
        self.assertEqual(('GET ' + plan.path + ' HTTP/1.1\r\n').encode(), records[0][0])
        self.assertEqual((8, 'E', (('stringValue', '{"literal":"=no evaluation"}'),)), observed.cells[4])

    def test_non200_native_read_has_one_wire_no_replay_and_no_history_observation(self):
        self.assertTrue(hasattr(self.tls, 'NativeHistoryReadUnit'))
        for code in (302, 401, 503):
            wire = ('HTTP/1.1 %d Synthetic\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}' % code).encode()
            unit = self.tls.NativeHistoryReadUnit(self.binding, self.token, first_row=9, last_row=11)
            with self.server(wire, hostname='sheets.googleapis.com', destination='sheets.googleapis.com') as (records, errors), self.fixture():
                with self.assertRaises(self.tls.TlsInputHold): unit.send_once()
                with self.assertRaises(self.tls.TlsInputHold): unit.send_once()
            self.assertEqual([], errors); self.assertEqual(1, len(records))


class Req7HistoryReadManifestTests(unittest.TestCase):
    def test_all_three_real_scripts_have_direct_workflow_suite_and_not_run_documentation(self):
        registry = json.loads((ROOT / 'test_cases/script_test_manifest.json').read_text())
        name = 'test_cases.test_req7_history_read'
        scripts = {'monitor/issue_tracker_sheets_read_plan.py', 'monitor/issue_tracker_sheets_read_decode.py',
                   'monitor/issue_tracker_tls_inputs.py'}
        for script in scripts:
            self.assertEqual(script, registry['scripts'].get(script))
            self.assertTrue(any(script in rule['paths'] and name in rule['tests'] for rule in registry['test_rules']))
        self.assertTrue(any(scripts <= set(rule['members']) and name in rule['tests'] for rule in registry['workflows']))
        self.assertEqual(['issue-tracker-local'], [suite['id'] for suite in registry['test_suites'] if name in suite['tests']])
        readme = (ROOT / 'test_cases/README.md').read_text(); self.assertIn(name, readme)
        card = (ROOT / 'test_cases/REAL_ENVIRONMENT.md').read_text()
        start = card.index('## TC-REAL-REQ7-BOUNDED-HISTORY-READ-001')
        end = card.find('\n## ', start + 1); card = card[start:] if end == -1 else card[start:end]
        for term in ('NOT RUN / REAL_ENV REQUIRED', '5000', 'userEnteredValue', '不是 COMPLETE', '前置条件', 'stat/inode', '清理'):
            self.assertIn(term, card)


if __name__ == '__main__': unittest.main()
