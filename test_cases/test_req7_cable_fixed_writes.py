"""Fixed write roles protocol DATA; independent direct oracle, SOURCE NOT RUN."""
import errno
import importlib.util
import json
import ssl
import unittest
from unittest import mock

from test_cases import fixed_https_peer_fixture as fixture

TARGET = 'synthetic_spreadsheet_id_0001'
BUSINESS_URL = 'https://sheets.googleapis.com/v4/spreadsheets/' + TARGET + ':batchUpdate?alt=json'
HISTORY_URL = ('https://sheets.googleapis.com/v4/spreadsheets/' + TARGET
               + '/values/History%21A3:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS&alt=json')
REQUESTS = [{
    'updateCells': {
        'start': {'sheetId': 12, 'rowIndex': 2, 'columnIndex': 11},
        'rows': [{'values': [{'userEnteredValue': {'stringValue':
            '[MONITOR][fan][PSU1/FAN] [fabric_source=template] new evidence'}}]}],
        'fields': 'userEnteredValue',
    },
}]
HISTORY = [['2026-10-22T01:02:03Z', 'ETH&IB Switch', 'Update',
            '["switch","leaf01","fan","PSU1/FAN"]', 'Monitor source merge']]
HEADERS = {'content-type': 'application/json', 'authorization': 'Bearer owned-write-token'}


def entry(case):
    case.assertIsNotNone(importlib.util.find_spec('monitor.issue_tracker_cable_fixed_https'),
                         'MISSING_FIXED_WRITE_PROTOCOL_MODULE')
    from monitor import issue_tracker_cable_fixed_https as transport
    return transport


def unit(case, transport, kind):
    try:
        return transport._protocol_only_http(kind, target=TARGET)
    except transport.FixedHttpsHold:
        case.fail('MISSING_FIXED_BUSINESS_OR_HISTORY_WRITE_ROLE')


def capture(action):
    try:
        return action(), None
    except BaseException as error:
        return None, error


def counters(peer, sockets):
    return (len(sockets.lookups), len(sockets.created), len(peer.records), tuple(peer.closed))


class FixedWriteRoleDirectTests(unittest.TestCase):
    def test_fixed_json_utf8_roles_and_one_emission_failures_preserve_first_cleanup(self):
        transport = entry(self)
        # Capability presence only; neither object is a source/send permission.
        business = unit(self, transport, 'sheets-business')
        unit(self, transport, 'sheets-history')
        wire_body = json.dumps({'requests': REQUESTS})
        large_request = {'updateCells': {
            'start': {'sheetId': 12, 'rowIndex': 2, 'columnIndex': 11},
            'rows': [{'values': [{'userEnteredValue': {'stringValue': '雪' * 10922}}]}],
            'fields': 'userEnteredValue'}}
        large = json.dumps({'requests': [large_request] * 31}, ensure_ascii=False)
        encoded = large.encode('utf-8')
        self.assertGreater(len(encoded), 65536)
        self.assertLessEqual(len(encoded), 1048576)
        host, method, wire = business._wire(BUSINESS_URL, 'POST', large, HEADERS, 0, None, {})
        self.assertEqual(('sheets.googleapis.com', 'POST'), (host, method))
        self.assertTrue(wire.endswith(encoded))
        self.assertIn(('Content-Length: %d\r\n' % len(encoded)).encode('ascii'), wire)
        too_large = json.dumps({'requests': [large_request] * 32}, ensure_ascii=False)
        self.assertGreater(len(too_large.encode('utf-8')), 1048576)
        # This >64KiB acceptance is direct wire DATA, not a bulk TLS proof;
        # the unchanged G9 peer deliberately has its old64KiB request limit.
        with self.assertRaises(transport.FixedHttpsHold):
            business._wire(BUSINESS_URL, 'POST', too_large, HEADERS, 0, None, {})
        token = transport._protocol_only_http('token')
        self.assertEqual('POST', token._wire(fixture.TOKEN_URL, 'POST', b'grant_type=x',
            {'content-type': 'application/x-www-form-urlencoded'}, 0, None, {})[1])
        with self.assertRaises(transport.FixedHttpsHold):
            token._wire(fixture.TOKEN_URL, 'POST', 'grant_type=x',
                {'content-type': 'application/x-www-form-urlencoded'}, 0, None, {})

        invalid = [
            (BUSINESS_URL, 'GET', wire_body, HEADERS),
            (BUSINESS_URL.replace(TARGET, 'different_target_spreadsheet_0001'), 'POST', wire_body, HEADERS),
            (BUSINESS_URL + '&key=not_allowed', 'POST', wire_body, HEADERS),
            (HISTORY_URL.replace('History%21A3', 'Update_History%21A3'), 'POST',
             json.dumps({'values': HISTORY}), HEADERS),
            (BUSINESS_URL, 'POST', None, HEADERS),
            (BUSINESS_URL, 'POST', wire_body.encode('utf-8'), HEADERS),
            (BUSINESS_URL, 'POST', {'requests': REQUESTS}, HEADERS),
            (BUSINESS_URL, 'POST', True, HEADERS),
            (BUSINESS_URL, 'POST', '{"requests":[],"requests":[]}', HEADERS),
            (BUSINESS_URL, 'POST', json.dumps({'requests': [], 'includeSpreadsheetInResponse': True}), HEADERS),
            (BUSINESS_URL, 'POST', json.dumps({'requests': [{'deleteSheet': {'sheetId': 12}}]}), HEADERS),
            (BUSINESS_URL, 'POST', json.dumps({'requests': [{'repeatCell': {'fields': '*'}}]}), HEADERS),
            (HISTORY_URL, 'POST', json.dumps({'values': HISTORY, 'range': 'Elsewhere!A1'}), HEADERS),
            (HISTORY_URL, 'POST', json.dumps({'values': [[1, 'sheet', 'Update', 'key', 'details']]}), HEADERS),
            (HISTORY_URL, 'POST', json.dumps({'values': []}), HEADERS),
            (BUSINESS_URL, 'POST', wire_body, {'content-type': 'application/json'}),
            (BUSINESS_URL, 'POST', wire_body,
             dict(HEADERS, **{'content-length': '1'})),
        ]
        bad_results = []
        with fixture.peer(self, []) as peer:
            with peer.client(transport) as sockets:
                for uri, method, body, headers in invalid:
                    role = 'sheets-history' if '/values/' in uri else 'sheets-business'
                    owned = unit(self, transport, role)
                    before = counters(peer, sockets)
                    _, error = capture(lambda: owned.request(uri, method, body=body, headers=headers,
                                                              redirections=0))
                    _, repeated = capture(lambda: owned.request(
                        HISTORY_URL if role == 'sheets-history' else BUSINESS_URL,
                        'POST', body=json.dumps({'values': HISTORY}) if role == 'sheets-history' else wire_body,
                        headers=HEADERS, redirections=0))
                    bad_results.append((error, repeated, before, counters(peer, sockets)))
        bad_errors = tuple(peer.errors)
        self.assertEqual((), bad_errors)
        for error, repeated, before, after in bad_results:
            self.assertIs(type(error), transport.FixedHttpsHold)
            self.assertEqual('fixed_https_denied', str(error))
            self.assertIsNone(error.__cause__); self.assertIsNone(error.__context__)
            self.assertIs(type(repeated), transport.FixedHttpsHold)
            self.assertEqual(before, after, 'INVALID_OR_REUSED_ROLE_MUST_HAVE_ZERO_IO')

        for role, uri, body in (
                ('sheets-business', BUSINESS_URL, wire_body),
                ('sheets-history', HISTORY_URL, json.dumps({'values': HISTORY}))):
            with self.subTest(role=role):
                replies = [fixture.response(200, b'{}')]
                replies += [fixture.response(status, b'{"private":"SECRET"}', location=status == 302)
                            for status in (302, 401, 429, 500)]
                replies += [fixture.response(200, b'{}', length=3),
                            fixture.response(200, b'{}'), fixture.response(200, b'{}')]
                phases = []
                with fixture.peer(self, replies) as peer:
                    with peer.client(transport) as sockets:
                        for mode in ('healthy', 302, 401, 429, 500, 'short', 'close', 'ni-close'):
                            owned = unit(self, transport, role)
                            primary = KeyboardInterrupt('OWNED_PRIVATE_BODY')
                            cause = ValueError('OWNED_PRIVATE_CAUSE'); primary.__cause__ = cause
                            close_facts = []
                            original_close, original_response = transport._close_resource, transport._WireResponse

                            def close(resource):
                                result = original_close(resource)  # Genuine native close first.
                                if isinstance(resource, ssl.SSLSocket):
                                    close_facts.append(resource.fileno() == -1)
                                    if mode in ('close', 'ni-close'):
                                        raise OSError(errno.EIO, 'OWNED_PRIVATE_CLOSE')
                                return result

                            class ReadNI(original_response):
                                def read(self, *args, **kwargs):
                                    data = super().read(*args, **kwargs)
                                    if mode == 'ni-close':
                                        close_facts.append(data == b'{}')
                                        raise primary  # Same object/cause, after actual complete body.
                                    return data

                            with mock.patch.object(transport, '_close_resource', close), \
                                 mock.patch.object(transport, '_WireResponse', ReadNI):
                                value, error = capture(lambda: owned.request(
                                    uri, 'POST', body=body, headers=HEADERS, redirections=0))
                            first = counters(peer, sockets)  # FIRST return facts, before reuse/owner exit.
                            _, repeated = capture(lambda: owned.request(
                                uri, 'POST', body=body, headers=HEADERS, redirections=0))
                            phases.append((mode, value, error, primary, cause, first,
                                           counters(peer, sockets), repeated, tuple(close_facts)))
                records, peer_errors = tuple(peer.records), tuple(peer.errors)
                lookups, sni, accepts = tuple(sockets.lookups), tuple(peer.sni), len(peer.accepts)
                self.assertEqual((), peer_errors)
                self.assertEqual(8, len(records)); self.assertEqual(8, accepts)
                self.assertEqual((('sheets.googleapis.com', 443),) * 8, lookups)
                self.assertEqual(('sheets.googleapis.com',) * 8, sni)
                for index, (mode, value, error, primary, cause, first, after, repeated, close_facts) in enumerate(phases, 1):
                    self.assertEqual(first, after, 'REUSE_CANNOT_EMIT_OR_FINISH_OLD_CLEANUP')
                    self.assertEqual(3 * index, len(first[3]))
                    self.assertTrue(all(closed for name, closed in first[3]),
                                    'FIRST_RETURN_MUST_ALREADY_HAVE_CLOSED_ALL_THREE')
                    self.assertIs(type(repeated), transport.FixedHttpsHold)
                    self.assertTrue(all(close_facts))
                    if mode == 'healthy':
                        self.assertIsNone(error); self.assertEqual(b'{}', value[1])
                    elif mode == 'ni-close':
                        self.assertIs(error, primary); self.assertIs(error.__cause__, cause)
                        self.assertEqual(2, len(close_facts))
                    else:
                        self.assertIs(type(error), transport.FixedHttpsHold)
                        self.assertEqual('fixed_https_denied', str(error))
                        self.assertIsNone(error.__cause__); self.assertIsNone(error.__context__)
