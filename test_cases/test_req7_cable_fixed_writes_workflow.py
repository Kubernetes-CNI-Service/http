"""Real merge -> actual SDK AuthorizedHttp/HttpRequest -> owned TLS, NOT RUN."""
import json
import unittest
from datetime import datetime, timedelta

from test_cases import fixed_https_peer_fixture as fixture
from test_cases import test_req7_cable_fixed_writes as literal


class FixedWriteSdkWorkflowTests(unittest.TestCase):
    def test_actual_merge_sdk_business_then_raw_history_preserves_operator_cells_once(self):
        transport = literal.entry(self)
        business = literal.unit(self, transport, 'sheets-business')
        history = literal.unit(self, transport, 'sheets-history')
        from googleapiclient.discovery import build
        from googleapiclient.http import HttpRequest
        from google_auth_httplib2 import AuthorizedHttp
        from google.oauth2.credentials import Credentials
        from monitor.issue_tracker_cable_merge import SheetImage, plan_current_online
        from monitor.issue_tracker_source_model import TrackerChanges, SwitchSourceWorkbookRow
        from test_cases.test_issue_tracker_local_workbook import SWITCH_HEADERS, CABLING_HEADERS
        cells = [{} for _ in range(21)]
        for index, value in {
                0: {'stringValue': 'NV10001'}, 1: {'stringValue': '2025-01-01'},
                2: {'stringValue': 'human submitter'}, 3: {'formulaValue': '=1'},
                4: {'formulaValue': '=2'}, 5: {'stringValue': 'leaf01'},
                6: {'formulaValue': '=3'}, 7: {'formulaValue': '=4'},
                8: {'formulaValue': '=5'}, 9: {'stringValue': 'Inband'},
                10: {'stringValue': 'P1'},
                11: {'stringValue': '[MONITOR][fan][PSU1/FAN] old evidence'},
                13: {'stringValue': 'In Progress'}, 14: {'stringValue': 'human-owner'},
                20: {'stringValue': 'human-remark'},
        }.items():
            cells[index] = value
        images = (
            SheetImage('ETH&IB Switch', 12, SWITCH_HEADERS, ((2, tuple(cells)),)),
            SheetImage('ETH Cabling', 13, CABLING_HEADERS, ()),
            SheetImage('IB Cabling', 14, CABLING_HEADERS, ()),
        )
        before = json.dumps([list(image.rows) for image in images], sort_keys=True)
        source = SwitchSourceWorkbookRow(('switch', 'leaf01', 'fan', 'PSU1/FAN'),
            'new evidence', 'Inband', 'template', 'P2', '2026-10-22T01:02:03Z')
        plan = plan_current_online(TrackerChanges((), (source,)), images)  # Real planner, never fakeplan.
        self.assertEqual(literal.REQUESTS, json.loads(plan.requests_json))
        self.assertEqual((('ETH&IB Switch', 'Update', source.activity_key),), plan.actions)
        self.assertEqual(literal.HISTORY, [list(row) for row in plan.history_rows])
        frozen = Credentials(token='owned-write-token', expiry=datetime.utcnow() + timedelta(minutes=5))
        first_states, requests, results = [], [], []
        with fixture.peer(self, [
                fixture.response(200, b'{"spreadsheetId":"synthetic_spreadsheet_id_0001","replies":[{}]}'),
                fixture.response(200, b'{"spreadsheetId":"synthetic_spreadsheet_id_0001","updates":{"updatedRows":1}}'),
                ]) as peer:
            with peer.client(transport) as sockets:
                for role, owned in (('business', business), ('history', history)):
                    service = build('sheets', 'v4',
                        http=AuthorizedHttp(frozen, http=owned, max_refresh_attempts=0),
                        static_discovery=True, cache_discovery=False)
                    if role == 'business':
                        request = service.spreadsheets().batchUpdate(
                            spreadsheetId=literal.TARGET,
                            body={'requests': json.loads(plan.requests_json)})
                    else:
                        request = service.spreadsheets().values().append(
                            spreadsheetId=literal.TARGET, range='History!A3',
                            valueInputOption='RAW', insertDataOption='INSERT_ROWS',
                            body={'values': [list(row) for row in plan.history_rows]})
                    self.assertIs(type(request), HttpRequest)
                    self.assertIs(type(request.body), str, 'REAL_SDK_JSONMODEL_BODY_IS_STR')
                    requests.append((request.uri, request.method, request.body))
                    results.append(request.execute(num_retries=0))
                    first = literal.counters(peer, sockets)  # Before reuse and all owner teardown.
                    _, repeated = literal.capture(lambda: request.execute(num_retries=0))
                    first_states.append((first, literal.counters(peer, sockets), repeated))
                    service.close()
        records, errors = tuple(peer.records), tuple(peer.errors)
        lookups, sni, accepts = tuple(sockets.lookups), tuple(peer.sni), len(peer.accepts)
        self.assertEqual((), errors)
        self.assertEqual(2, accepts); self.assertEqual(2, len(records))
        self.assertEqual((('sheets.googleapis.com', 443),) * 2, lookups)
        self.assertEqual(('sheets.googleapis.com',) * 2, sni)
        for index, (first, after, repeated) in enumerate(first_states, 1):
            self.assertEqual(first, after)
            self.assertEqual(3 * index, len(first[3]))
            self.assertTrue(all(closed for name, closed in first[3]))
            self.assertIs(type(repeated), transport.FixedHttpsHold)
        self.assertEqual((literal.BUSINESS_URL, 'POST'), requests[0][:2])
        self.assertEqual({'requests': literal.REQUESTS}, json.loads(requests[0][2]))
        self.assertEqual((literal.HISTORY_URL, 'POST', json.dumps({'values': literal.HISTORY})), requests[1])
        self.assertEqual(b'POST /v4/spreadsheets/synthetic_spreadsheet_id_0001:batchUpdate?alt=json HTTP/1.1\r\n', records[0][0])
        self.assertEqual(b'POST /v4/spreadsheets/synthetic_spreadsheet_id_0001/values/History%21A3:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS&alt=json HTTP/1.1\r\n', records[1][0])
        for line, headers, body in records:
            self.assertIn(b'Host: sheets.googleapis.com\r\n', headers)
            self.assertIn(b'Authorization: Bearer owned-write-token\r\n', headers)
            self.assertIn(b'Content-Type: application/json\r\n', headers)
            self.assertIn(('Content-Length: %d\r\n' % len(body)).encode('ascii'), headers)
        self.assertEqual({'requests': literal.REQUESTS}, json.loads(records[0][2]))
        self.assertEqual({'values': literal.HISTORY}, json.loads(records[1][2]))
        self.assertEqual(requests[0][2].encode('utf-8'), records[0][2])
        self.assertEqual(requests[1][2].encode('utf-8'), records[1][2])
        self.assertNotIn(b'human-owner', records[0][2]); self.assertNotIn(b'formulaValue', records[0][2])
        self.assertEqual(before, json.dumps([list(image.rows) for image in images], sort_keys=True))
        self.assertEqual({'stringValue': 'human-owner'}, images[0].rows[0][1][14])
        self.assertEqual({'formulaValue': '=1'}, images[0].rows[0][1][3])
        self.assertEqual({'stringValue': 'In Progress'}, images[0].rows[0][1][13])
        self.assertEqual(literal.TARGET, results[0]['spreadsheetId'])
        self.assertEqual(1, results[1]['updates']['updatedRows'])
