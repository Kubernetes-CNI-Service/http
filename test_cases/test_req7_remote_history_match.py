"""Independent all-business/all-audit reconciliation, not sending or APPLIED."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

import test_cases
ROOT = Path(test_cases.__file__).resolve().parents[1]
from test_cases.test_req7_spreadsheet_owner import load as load_owner, fixture, binding, TARGET
from test_cases.test_req7_global_attempt_journal import load as load_global
from test_cases.test_req7_history_preread_journal import load as load_before
from test_cases.test_req7_enrollment_journal import load as load_enrollment
from test_cases.test_req7_history_read import load as load_read, inputs as read_inputs, response, tail_document
from test_cases.test_req7_send_unit import inputs as send_inputs
from test_cases.test_req7_sheets_read_decode import identity_response


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()


def load():
    path = ROOT / 'monitor/issue_tracker_remote_history_match.py'
    if not path.is_file(): raise AssertionError('journal/nonce/fence/all-History matcher missing')
    spec = importlib.util.spec_from_file_location('monitor.issue_tracker_remote_history_match', path)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    import monitor
    monitor.issue_tracker_remote_history_match = module
    return module


class Req7RemoteHistoryMatchDirectTests(unittest.TestCase):
    def setUp(self):
        self.owner = load_owner(); self.global_journal = load_global()
        self.planner = load_read('issue_tracker_sheets_read_plan'); self.decoder = load_read('issue_tracker_sheets_read_decode')
        self.enrollment = load_enrollment(); self.before = load_before()
        self.capacity = load_read('issue_tracker_metadata_capacity'); self.decoder = sys.modules['monitor.issue_tracker_sheets_read_decode']
        self.binding, self.token_value = read_inputs()
        self.identity = self.decoder.decode_template_identity(self.planner.prepare_template_identity_read(self.binding, self.token_value), response(identity_response()))
        self.meta_plan = self.capacity.prepare_metadata_capacity_read(self.binding, self.token_value)
        self.plan = self.planner.prepare_history_tail_read(self.binding, self.token_value)
        self.temp = tempfile.TemporaryDirectory(prefix='req7-remote-match-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.state = self.root / 'var/lib/http-ztp-container/issue-tracker'
        self.state.mkdir(parents=True, mode=0o700)
        args = send_inputs(); args.update(sheet_id=101, history_sheet_id=105, target_nonce='a' * 64, history_nonce='d' * 64)
        # First business op is NOOP; only op 1 and ALL assigned audits travel.
        args['business'][0]['observed_values'] = {'L': {'stringValue': 'down'}}
        args['audits'] = ({'event_id': 'settings:001', 'recorded_at_utc': '2026-10-08T10:00:00Z', 'details': 'K=3'},)
        from monitor.issue_tracker_send_unit import freeze_send_unit
        self.unit = freeze_send_unit(**args)
        self.empty = tail_document(12); self.empty['sheets'][0]['properties']['sheetId'] = 105
        self.empty['sheets'][0]['data'][0]['rowData'] = []
        common = {'schema_version': 1, 'unit_id': self.unit.unit_id, 'manifest_id': args['manifest_id'],
                  'generation_id': 'a' * 64, 'publish_id': 'b' * 64, 'action_digest': self.unit.action_digest,
                  'outcome_mapping_sha256': self.unit.outcome_mapping_sha256, 'target_nonce': 'a' * 64,
                  'history_nonce': 'd' * 64, 'preread_sha256': 'e' * 64}
        intended = hashlib.sha256(canonical({'sheet': 'ETH&IB Switch', 'sheet_id': 101, 'action': 'update',
                                            'row_index': 3, 'values': {'L': {'stringValue': 'down'}}})).hexdigest()
        self.rows = [('2026-10-08T10:00:00Z', 'ETH&IB Switch', 'update', 'switch:0001',
                      canonical({**common, 'operation_id': 'switch:0001', 'intended_sha256': intended}).decode().rstrip('\n')),
                     ('2026-10-08T10:00:00Z', 'ETH&IB Switch', 'settings-audit', 'settings:001',
                      canonical({**common, 'event_id': 'settings:001', 'event_details': 'K=3'}).decode().rstrip('\n'))]
        self.post = deepcopy(self.empty)
        self.post['sheets'][0]['data'][0]['rowData'] = [{'values': [{'userEnteredValue': {'stringValue': text}} for text in row]} for row in self.rows]
        self.metadata = {'matchedDeveloperMetadata': [
            {'developerMetadata': {'metadataId': 1, 'metadataKey': 'http-ztp-enrollment-v1', 'metadataValue': 'a' * 64,
                                   'visibility': 'DOCUMENT', 'location': {'locationType': 'SHEET', 'sheetId': 101}}},
            {'developerMetadata': {'metadataId': 2, 'metadataKey': 'http-ztp-enrollment-v1', 'metadataValue': 'd' * 64,
                                   'visibility': 'DOCUMENT', 'location': {'locationType': 'SHEET', 'sheetId': 105}}},
            {'developerMetadata': {'metadataId': self.unit.fence_metadata_id, 'metadataKey': 'z', 'metadataValue': '1',
                                   'visibility': 'DOCUMENT', 'location': {'locationType': 'SHEET', 'sheetId': 101}}}]}

    def prepare(self, token, *, attempt=True, before=None):
        with mock.patch('secrets.token_hex', side_effect=['a' * 64, 'b' * 64, 'c' * 64, 'd' * 64]):
            self.enrollment.prepare_enrollment_journal(token, binding(), self.identity)
        self.global_journal.prepare_global_unit(token, binding(), self.unit)
        self.before.prepare_history_preread(token, binding(), self.unit, self.plan, response(self.empty if before is None else before))
        if attempt: self.global_journal.record_global_attempt_intent(token, binding(), self.unit)

    def observe(self, module, token, *, post=None, metadata=None):
        return module.observe_remote_history_unit(token, binding(), self.unit, self.identity,
            self.meta_plan, response(self.metadata if metadata is None else metadata),
            self.plan, response(self.post if post is None else post))

    def test_actual_journals_and_both_nonces_fence_all_sent_and_audit_match_without_clearing_unknown(self):
        module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            seen = self.observe(module, token)
            self.assertEqual(('MATCHED_OBSERVATION', 2, 2, 1), (seen.state, seen.history_rows_expected, seen.history_rows_matched, seen.attempt_count))
            self.assertTrue(seen.fence_present); self.assertTrue(seen.target_nonce_valid); self.assertTrue(seen.history_nonce_valid)
            self.assertFalse(hasattr(seen, 'permit')); self.assertFalse(hasattr(seen, 'applied'))
            self.assertEqual((1, 'UNKNOWN'), (self.global_journal.inspect_global_unit(token, binding(), self.unit).attempt_count,
                                             self.global_journal.inspect_global_unit(token, binding(), self.unit).outcome))

    def test_fence_alone_missing_audit_duplicate_wrong_digest_or_typed_formula_conflict(self):
        module = load()
        cases = []
        item = deepcopy(self.empty); cases.append(item)
        item = deepcopy(self.post); item['sheets'][0]['data'][0]['rowData'].pop(); cases.append(item)
        item = deepcopy(self.post); item['sheets'][0]['data'][0]['rowData'].append(deepcopy(item['sheets'][0]['data'][0]['rowData'][0])); cases.append(item)
        for column, value in ((3, 'switch:0000'), (4, 'wrong digest')):
            item = deepcopy(self.post); item['sheets'][0]['data'][0]['rowData'][0]['values'][column]['userEnteredValue']['stringValue'] = value; cases.append(item)
        item = deepcopy(self.post); item['sheets'][0]['data'][0]['rowData'][0]['values'][0]['userEnteredValue'] = {'formulaValue': '=literal'}; cases.append(item)
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            for item in cases: self.assertEqual('CONFLICT', self.observe(module, token, post=item).state)
            self.assertEqual(1, self.global_journal.inspect_global_unit(token, binding(), self.unit).attempt_count)

    def test_absent_fence_is_unknown_foreign_fence_or_bad_nonce_cannot_match(self):
        module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            item = deepcopy(self.metadata); item['matchedDeveloperMetadata'].pop()
            self.assertEqual('UNKNOWN', self.observe(module, token, metadata=item).state)
            for field, value in (('metadataKey', 'foreign'), ('metadataValue', '2'), ('visibility', 'PROJECT')):
                item = deepcopy(self.metadata); item['matchedDeveloperMetadata'][-1]['developerMetadata'][field] = value
                self.assertEqual('CONFLICT', self.observe(module, token, metadata=item).state)
            item = deepcopy(self.metadata); item['matchedDeveloperMetadata'][0]['developerMetadata']['metadataValue'] = 'f' * 64
            with self.assertRaises(module.RemoteHistoryHold): self.observe(module, token, metadata=item)

    def test_unattempted_unit_never_matches(self):
        module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token, attempt=False)
            with self.assertRaises(module.RemoteHistoryHold): self.observe(module, token)

    def test_unissued_response_objects_cannot_write_durable_completion_evidence(self):
        module=load()
        self.assertTrue(hasattr(module,'record_owned_completion_evidence'),
                        'C19 needs retained evidence from the actual owned read bridge, not a caller MATCHED flag')
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            retained={str(p.relative_to(self.state)):p.read_bytes() for p in self.state.rglob('*') if p.is_file()}
            with self.assertRaises(module.RemoteHistoryHold) as caught:
                module.record_owned_completion_evidence(object(),token,binding(),self.unit,
                    identity_response=response(identity_response()),headers_response=response({}),
                    metadata_response=response(self.metadata),history_response=response(self.post))
            self.assertIsNone(caught.exception.__context__)
            self.assertEqual(retained,{str(p.relative_to(self.state)):p.read_bytes() for p in self.state.rglob('*') if p.is_file()})

    def test_original_count_changed_during_post_read_cannot_escape_as_matched_observation(self):
        module=load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            decode_tail=module.decode.decode_history_tail; changed=[]
            def decoding(plan,raw,**options):
                result=decode_tail(plan,raw,**options)
                if raw.data==response(self.post).data and not changed:
                    self.global_journal.record_global_attempt_intent(token,binding(),self.unit)
                    changed.append(True)
                return result
            with mock.patch.object(module.decode,'decode_history_tail',side_effect=decoding):
                with self.assertRaises(module.RemoteHistoryHold): self.observe(module,token)
            self.assertEqual([True],changed)
            self.assertEqual((2,'UNKNOWN'),(self.global_journal.inspect_global_unit(token,binding(),self.unit).attempt_count,
                                           self.global_journal.inspect_global_unit(token,binding(),self.unit).outcome))

    def test_byte_identical_original_wire_replacement_during_match_is_not_adopted(self):
        self._identical_original_replacement('.journal','WIRE')

    def test_byte_identical_original_history_replacement_during_match_is_not_adopted(self):
        self._identical_original_replacement('.history','HISTORY-RAW')

    def test_byte_identical_original_nonce_replacement_during_match_is_not_adopted(self):
        self._identical_original_replacement('.enrollment','NONCES')

    def test_original_wire_replaced_during_initial_pin_read_is_not_adopted(self):
        module=load()
        from monitor import issue_tracker_attempt_journal as original_io
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            path=self.state/(hashlib.sha256(TARGET.encode()).hexdigest()+'.journal')/'WIRE'
            raw=path.read_bytes(); preserved=self.root/'preserved-wire-at-initial-pin'
            reading=original_io._read; changed=[]
            def read_then_replace(folder,name,limit):
                result=reading(folder,name,limit)
                if name=='WIRE' and not changed:
                    path.rename(preserved); path.write_bytes(raw); path.chmod(0o600)
                    changed.append(True)
                return result
            with mock.patch.object(original_io,'_read',side_effect=read_then_replace):
                with self.assertRaises(module.RemoteHistoryHold): self.observe(module,token)
            self.assertEqual([True],changed)
            self.assertEqual(raw,path.read_bytes()); self.assertEqual(raw,preserved.read_bytes())
            self.assertEqual(1,self.global_journal.inspect_global_unit(token,binding(),self.unit).attempt_count)

    def test_original_wire_same_inode_rewrite_during_initial_pin_read_is_not_adopted(self):
        module=load()
        from monitor import issue_tracker_attempt_journal as original_io
        import os
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            path=self.state/(hashlib.sha256(TARGET.encode()).hexdigest()+'.journal')/'WIRE'
            raw=path.read_bytes(); original=path.stat()
            reading=original_io._read; changed=[]
            def read_then_rewrite(folder,name,limit):
                result=reading(folder,name,limit)
                if name=='WIRE' and not changed:
                    with path.open('r+b') as held:
                        held.write(raw); held.flush(); os.fsync(held.fileno())
                    os.utime(path,ns=(original.st_atime_ns,original.st_mtime_ns+1_000_000))
                    changed.append(True)
                return result
            with mock.patch.object(original_io,'_read',side_effect=read_then_rewrite):
                with self.assertRaises(module.RemoteHistoryHold): self.observe(module,token)
            self.assertEqual([True],changed)
            self.assertEqual((raw,original.st_ino),(path.read_bytes(),path.stat().st_ino))
            self.assertEqual(1,self.global_journal.inspect_global_unit(token,binding(),self.unit).attempt_count)

    def _identical_original_replacement(self,suffix,name):
        module=load()
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            path=self.state/(hashlib.sha256(TARGET.encode()).hexdigest()+suffix)/name
            original=path.read_bytes(); preserved=self.root/('preserved-original-'+name)
            decode_tail=module.decode.decode_history_tail; changed=[]
            def decoding(plan,raw,**options):
                result=decode_tail(plan,raw,**options)
                if raw.data==response(self.post).data and not changed:
                    path.rename(preserved); path.write_bytes(original); path.chmod(0o600)
                    changed.append(True)
                return result
            with mock.patch.object(module.decode,'decode_history_tail',side_effect=decoding):
                with self.assertRaises(module.RemoteHistoryHold): self.observe(module,token)
            self.assertEqual([True],changed)
            self.assertEqual(original,preserved.read_bytes()); self.assertEqual(original,path.read_bytes())
            self.assertEqual((1,'UNKNOWN'),(self.global_journal.inspect_global_unit(token,binding(),self.unit).attempt_count,
                                           self.global_journal.inspect_global_unit(token,binding(),self.unit).outcome))

    def test_counted_unit_without_original_preread_cannot_match_or_create_preread(self):
        module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            with mock.patch('secrets.token_hex', side_effect=['a' * 64, 'b' * 64, 'c' * 64, 'd' * 64]):
                self.enrollment.prepare_enrollment_journal(token, binding(), self.identity)
            self.global_journal.prepare_global_unit(token, binding(), self.unit)
            self.global_journal.record_global_attempt_intent(token, binding(), self.unit)
            with self.assertRaises(module.RemoteHistoryHold): self.observe(module, token)
            self.assertFalse((self.state / (hashlib.sha256(TARGET.encode()).hexdigest() + '.history')).exists())
            self.assertEqual('UNKNOWN', self.global_journal.inspect_global_unit(token, binding(), self.unit).outcome)

    def test_original_typed_prefix_gaps_and_capacity_must_be_preserved_before_exact_append(self):
        module = load()
        original = deepcopy(self.empty)
        old_rows = [{'values': [{'userEnteredValue': {'boolValue': False}}]}, {},
                    {'values': [{}, {}, {}, {}, {'userEnteredValue': {'stringValue': ' old '}}]}]
        original['sheets'][0]['data'][0]['rowData'] = old_rows
        post = deepcopy(self.post)
        post['sheets'][0]['data'][0]['rowData'] = deepcopy(old_rows) + post['sheets'][0]['data'][0]['rowData']
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token, before=original)
            seen = self.observe(module, token, post=post)
            self.assertEqual(('MATCHED_OBSERVATION', 4, 6), (seen.state, seen.history_last_row_before_send, seen.history_last_row_after_read))
            cases = []
            changed = deepcopy(post); changed['sheets'][0]['data'][0]['rowData'][0]['values'][0]['userEnteredValue'] = {'numberValue': 0}; cases.append(changed)
            changed = deepcopy(post); changed['sheets'][0]['data'][0]['rowData'][1] = {'values': [{'userEnteredValue': {'stringValue': ''}}]}; cases.append(changed)
            changed = deepcopy(post); changed['sheets'][0]['data'][0]['rowData'][2]['values'][4]['userEnteredValue']['stringValue'] = 'old'; cases.append(changed)
            changed = deepcopy(post); changed['sheets'][0]['properties']['gridProperties']['rowCount'] = 8; cases.append(changed)
            for changed in cases:
                with self.subTest(changed=changed): self.assertEqual('CONFLICT', self.observe(module, token, post=changed).state)

    def test_new_row_order_gap_extra_foreign_append_and_alternate_fence_id_never_match(self):
        module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            cases = []
            changed = deepcopy(self.post); changed['sheets'][0]['data'][0]['rowData'].reverse(); cases.append(changed)
            changed = deepcopy(self.post); changed['sheets'][0]['data'][0]['rowData'].insert(0, {}); cases.append(changed)
            changed = deepcopy(self.post); changed['sheets'][0]['data'][0]['rowData'].append({'values': [{'userEnteredValue': {'stringValue': 'foreign append'}}]}); cases.append(changed)
            for changed in cases: self.assertEqual('CONFLICT', self.observe(module, token, post=changed).state)
            changed = deepcopy(self.metadata); changed['matchedDeveloperMetadata'][-1]['developerMetadata']['metadataId'] += 1
            self.assertEqual('UNKNOWN', self.observe(module, token, metadata=changed).state)

    def test_malformed_duplicate_partial_foreign_or_forged_reads_hold_sanitized_without_settlement(self):
        module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.prepare(token)
            raw = response(self.post)
            duplicate = deepcopy(self.metadata); duplicate['matchedDeveloperMetadata'].append(deepcopy(duplicate['matchedDeveloperMetadata'][-1]))
            cases = [dict(metadata_response=response(duplicate)),
                     dict(metadata_response=SimpleNamespace(status=200, complete=False, data=response(self.metadata).data)),
                     dict(history_response=SimpleNamespace(status=200, complete=False, data=raw.data)),
                     dict(history_response=SimpleNamespace(status=503, complete=True, data=raw.data)),
                     dict(history_response=SimpleNamespace(status=200, complete=True, data=b'{"sheets":[],"sheets":[]}')),
                     dict(history_plan=replace(self.plan, path=self.plan.path.replace(TARGET, 'foreign_spreadsheet_0002'))),
                     dict(history_plan=replace(self.plan, path=self.plan.path.replace('E5002', 'E7')))]
            args = dict(token=token, binding=binding(), unit=self.unit, identity=self.identity,
                        metadata_plan=self.meta_plan, metadata_response=response(self.metadata),
                        history_plan=self.plan, history_response=raw)
            for changes in cases:
                with self.subTest(changes=changes), self.assertRaises(module.RemoteHistoryHold) as caught:
                    module.observe_remote_history_unit(**{**args, **changes})
                self.assertIsNone(caught.exception.__context__)
                self.assertEqual('req7_remote_history_unproved', str(caught.exception))
            self.assertEqual('UNKNOWN', self.global_journal.inspect_global_unit(token, binding(), self.unit).outcome)

    def test_full_bounded_rectangle_is_grouped_in_one_pass_without_quadratic_rescanning(self):
        module = load()
        class CountedCells:
            iterations = 0
            def __iter__(self):
                self.iterations += 1
                for row in range(2, 5002):
                    for column in 'ABCDE': yield (row, column, ())
        cells = CountedCells()
        rows = module._rows(cells, 2, 5001)
        self.assertEqual(((),) * 5, rows[0]); self.assertEqual(5000, len(rows))
        self.assertEqual(1, cells.iterations, 'fixed 25000-cell input must not be rescanned once per row')


class Req7RemoteHistoryNativeWorkflowTests(unittest.TestCase):
    from test_cases.test_req7_history_read import Req7HistoryReadNativeWorkflowTests as _Fixture
    fixture = _Fixture.fixture; certificates = _Fixture.certificates; server = _Fixture.server

    def setUp(self):
        self.setup = Req7RemoteHistoryMatchDirectTests('test_actual_journals_and_both_nonces_fence_all_sent_and_audit_match_without_clearing_unknown')
        self.setup.setUp(); self.addCleanup(self.setup.doCleanups)
        self._Fixture.setUp(self)

    def read_once(self, unit, payload):
        wire = ('HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(payload)).encode() + payload
        with self.server(wire, hostname='sheets.googleapis.com', destination='sheets.googleapis.com') as (records, errors), self.fixture():
            raw = unit.send_once()
            with self.assertRaises(ValueError): unit.send_once()
        self.assertEqual([], errors); self.assertEqual(1, len(records))
        return raw, records[0]

    def test_actual_three_native_reads_then_original_journals_and_whole_history_match_without_settlement(self):
        setup = self.setup
        setup.planner = sys.modules['monitor.issue_tracker_sheets_read_plan']
        setup.plan = setup.planner.prepare_history_tail_read(setup.binding, setup.token_value)
        # Separate actual CA/UID validation from the synthetic global-root
        # directory fixture; no arbitrary source path or mocked decoder result.
        before_raw, first = self.read_once(self.tls.NativeHistoryTailReadUnit(setup.binding, setup.token_value), response(setup.empty).data)
        capacity = load_read('issue_tracker_metadata_capacity')
        setup.decoder = sys.modules['monitor.issue_tracker_sheets_read_decode']
        setup.identity = setup.decoder.decode_template_identity(
            setup.planner.prepare_template_identity_read(setup.binding, setup.token_value), response(identity_response()))
        setup.meta_plan = capacity.prepare_metadata_capacity_read(setup.binding, setup.token_value)
        setup.before = load_before()
        with mock.patch.dict(sys.modules, {'monitor.issue_tracker_tls_inputs': self.tls}):
            meta_raw, second = self.read_once(capacity.NativeMetadataCapacityReadUnit(setup.binding, setup.token_value), response(setup.metadata).data)
        after_raw, third = self.read_once(self.tls.NativeHistoryTailReadUnit(setup.binding, setup.token_value), response(setup.post).data)
        module = load()
        with fixture(setup.root), setup.owner.spreadsheet_owner(binding()) as token:
            with mock.patch('secrets.token_hex', side_effect=['a' * 64, 'b' * 64, 'c' * 64, 'd' * 64]):
                setup.enrollment.prepare_enrollment_journal(token, binding(), setup.identity)
            setup.global_journal.prepare_global_unit(token, binding(), setup.unit)
            setup.before.prepare_history_preread(token, binding(), setup.unit, setup.plan, before_raw)
            setup.global_journal.record_global_attempt_intent(token, binding(), setup.unit)
            seen = module.observe_remote_history_unit(token, binding(), setup.unit, setup.identity,
                setup.meta_plan, meta_raw, setup.plan, after_raw)
            self.assertEqual(('MATCHED_OBSERVATION', 2, 2), (seen.state, seen.history_rows_expected, seen.history_rows_matched))
            self.assertEqual('UNKNOWN', setup.global_journal.inspect_global_unit(token, binding(), setup.unit).outcome)
        self.assertEqual(('GET ' + setup.plan.path + ' HTTP/1.1\r\n').encode(), first[0])
        self.assertEqual(first[0], third[0]); self.assertEqual(b'', first[2]); self.assertEqual(b'', third[2])
        self.assertEqual(('POST ' + setup.meta_plan.path + ' HTTP/1.1\r\n').encode(), second[0])
        self.assertEqual(setup.meta_plan.body, second[2])


class Req7OwnedHistoryMatchWorkflowTests(unittest.TestCase):
    # Reuse owned native fixtures, not inherited test methods/discovery.
    from test_cases.test_req7_history_read_launcher import Req7HistoryReadLauncherWorkflowTests as _Fixture
    setUp = _Fixture.setUp; certificates = _Fixture.certificates; server = _Fixture.server
    owners = _Fixture.owners; intercept = _Fixture.intercept; child_fixture = _Fixture.child_fixture

    def read_owned(self, stack, writer, owner, binding, token, kind, value, *, raw_body=None, sheet=None, row=None):
        from monitor import issue_tracker_history_read_launcher as reads
        import socket
        body = json.dumps(value, separators=(',', ':')).encode() if raw_body is None else raw_body
        self.assertIs(type(body),bytes)
        reply = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body
        records=errors=children=None
        try:
            with self.server(reply, hostname='sheets.googleapis.com', destination='sheets.googleapis.com') as (records, errors):
                port = socket.getaddrinfo('sheets.googleapis.com', 443)[0][4][1]
                from contextlib import ExitStack
                with ExitStack() as launched:
                    calls, children = self.intercept(launched, self.child_fixture(port), writer, owner, binding)
                    result = reads.OwnedSheetsReadUnit(writer, owner, binding, token, read_kind=kind, sheet=sheet, row=row).read_once()
                    self.assertEqual((1, 0, body), (len(calls), children[0].returncode, result.data))
                self.assertEqual([], errors); self.assertEqual(1, len(records))
                method = b'POST ' if kind == 'metadata' else b'GET '
                self.assertTrue(records[0][0].startswith(method + b'/v4/spreadsheets/' + binding.spreadsheet_id.encode()))
        except reads.HistoryReadLauncherHold:
            # Preserve the original ERROR and all strict timing/behavioral
            # checks. Only non-secret phase facts survive owned-fixture cleanup;
            # never print the token, argv, HTTP headers or response body.
            print('OWNED_READ_FAILURE_PHASE',kind,
                  'server_records',None if records is None else len(records),
                  'server_errors',None if errors is None else [type(error).__name__ for error in errors],
                  'child_returncodes',None if children is None else [child.returncode for child in children],flush=True)
            raise
        return result

    def prepare_owned(self, stack):
        from monitor import issue_tracker_history_read_launcher as reads
        from monitor import issue_tracker_global_attempt_journal as journal, issue_tracker_enrollment_journal as enroll
        from monitor import issue_tracker_history_preread_journal as preread, issue_tracker_sheets_read_decode as decode
        from monitor.issue_tracker_send_unit import freeze_send_unit
        from test_cases.test_req7_sheets_read_decode import header_response
        _local, _ownership, writer, owner, bound, auth, config = self.owners(stack)
        identity_doc = identity_response(); identity_doc['spreadsheetId'] = bound.spreadsheet_id
        headers_doc = header_response(); headers_doc['spreadsheetId'] = bound.spreadsheet_id
        arguments = send_inputs()
        arguments.update(spreadsheet_id=bound.spreadsheet_id, sheet_id=101, history_sheet_id=105,
                         target_nonce='a'*64, history_nonce='d'*64)
        arguments['business'][0]['observed_values'] = {'L': {'stringValue': 'down'}}
        arguments['audits'] = ({'event_id': 'settings:001', 'recorded_at_utc': '2026-10-08T10:00:00Z', 'details': 'K=3'},)
        unit = freeze_send_unit(**arguments)
        empty = tail_document(12); empty['spreadsheetId'] = bound.spreadsheet_id
        empty['sheets'][0]['properties']['sheetId'] = 105; empty['sheets'][0]['data'][0]['rowData'] = []
        original_read = self.read_owned(stack, writer, owner, bound, auth, 'history_tail', empty)
        original_plan = reads.require_current_owned_read(writer, owner, bound, original_read, read_kind='history_tail')
        identity_plan = reads._prepare(bound, auth, 'template_identity', None, None)
        identity = decode.decode_template_identity(identity_plan, response(identity_doc))
        with mock.patch('secrets.token_hex', side_effect=['a'*64, 'b'*64, 'c'*64, 'd'*64]):
            enroll.prepare_enrollment_journal(owner, bound, identity)
        journal.prepare_global_unit(owner, bound, unit)
        preread.prepare_history_preread(owner, bound, unit, original_plan, original_read)
        journal.record_global_attempt_intent(owner, bound, unit)
        common = {'schema_version': 1, 'unit_id': unit.unit_id, 'manifest_id': arguments['manifest_id'],
                  'generation_id': 'a'*64, 'publish_id': 'b'*64, 'action_digest': unit.action_digest,
                  'outcome_mapping_sha256': unit.outcome_mapping_sha256, 'target_nonce': 'a'*64,
                  'history_nonce': 'd'*64, 'preread_sha256': 'e'*64}
        intended = hashlib.sha256(canonical({'sheet':'ETH&IB Switch','sheet_id':101,'action':'update',
                                             'row_index':3,'values':{'L':{'stringValue':'down'}}})).hexdigest()
        expected_rows = [('2026-10-08T10:00:00Z', 'ETH&IB Switch', 'update', 'switch:0001',
                          canonical({**common, 'operation_id':'switch:0001', 'intended_sha256':intended}).decode().rstrip('\n')),
                         ('2026-10-08T10:00:00Z', 'ETH&IB Switch', 'settings-audit', 'settings:001',
                          canonical({**common, 'event_id':'settings:001', 'event_details':'K=3'}).decode().rstrip('\n'))]
        post = deepcopy(empty)
        post['sheets'][0]['data'][0]['rowData'] = [{'values':[{'userEnteredValue':{'stringValue':text}} for text in row]} for row in expected_rows]
        meta = {'matchedDeveloperMetadata':[
            {'developerMetadata':{'metadataId':1,'metadataKey':'http-ztp-enrollment-v1','metadataValue':'a'*64,
                                  'visibility':'DOCUMENT','location':{'locationType':'SHEET','sheetId':101}}},
            {'developerMetadata':{'metadataId':2,'metadataKey':'http-ztp-enrollment-v1','metadataValue':'d'*64,
                                  'visibility':'DOCUMENT','location':{'locationType':'SHEET','sheetId':105}}},
            {'developerMetadata':{'metadataId':unit.fence_metadata_id,'metadataKey':'z','metadataValue':'1',
                                  'visibility':'DOCUMENT','location':{'locationType':'SHEET','sheetId':101}}}]}
        docs = {'identity_response':('template_identity',identity_doc),'headers_response':('template_headers',headers_doc),
                'metadata_response':('metadata',meta),'history_response':('history_tail',post)}
        return writer, owner, bound, auth, config, unit, docs

    def test_actual_owned_all_business_and_history_continuity_includes_noop_and_preserves_unknown(self):
        from monitor import issue_tracker_history_preread_journal as before
        self.assertTrue(hasattr(before, 'observe_owned_business_continuity'),
                        'fresh ALL business including NOOP and original History must be checked under actual owners')
        from contextlib import ExitStack
        from test_cases.test_req7_history_preread_journal import Req7BusinessPrereadJournalDirectTests
        from monitor.issue_tracker_send_unit import freeze_send_unit
        prototype = Req7BusinessPrereadJournalDirectTests()
        prototype.setUp(); self.addCleanup(prototype.doCleanups)
        before = prototype.module
        from monitor import issue_tracker_global_attempt_journal as journal, issue_tracker_enrollment_journal as enroll
        with ExitStack() as stack:
            _local, _ownership, writer, owner, bound, auth, _config = self.owners(stack,target_id=TARGET)
            original = enroll.prepare_enrollment_journal(owner, bound, prototype.identity)
            nonces = {title: nonce for title, _sid, nonce in original.nonces}
            business = [dict(item) for item in prototype.args['business']]
            business[0]['values'] = {'L': '[MONITOR][down][fabric] old'}
            business[1]['values'] = {'L': '[MONITOR][down][fabric] new'}
            for item in business: item['observed_values'] = {'L': {'stringValue': '[MONITOR][down][fabric] old'}}
            unit = freeze_send_unit(**{**prototype.args, 'business': tuple(business), 'sheet_id': 101, 'history_sheet_id': 105,
                'target_nonce': nonces['ETH&IB Switch'], 'history_nonce': nonces['Update_History'], 'preread_sha256': prototype.digest})
            journal.prepare_global_unit(owner,bound,unit)
            before.prepare_history_preread(owner,bound,unit,prototype.plan,prototype.raw)
            before.prepare_business_preread(owner,bound,prototype.identity,unit,
                manifest=prototype.manifest,business_reads=tuple(prototype.reads))
            journal.record_global_attempt_intent(owner,bound,unit)
            state = self.root/'var/lib/http-ztp-container/issue-tracker'
            retained = {str(path.relative_to(state)):path.read_bytes() for path in state.rglob('*') if path.is_file()}
            identity_read = self.read_owned(stack,writer,owner,bound,auth,'template_identity',identity_response())
            history_read = self.read_owned(stack,writer,owner,bound,auth,'history_tail',json.loads(prototype.raw.data))
            common = {}
            for role,kind in (('discovery','activity'),('occupancy','insertion')):
                common[role+'_response'] = self.read_owned(stack,writer,owner,bound,auth,kind,
                    json.loads(prototype.reads[0][role+'_response'].data),sheet='ETH&IB Switch')
            current = tuple({'operation_id':reading['operation_id'],**common,
                'row_response':self.read_owned(stack,writer,owner,bound,auth,'row',json.loads(reading['row_response'].data),
                    sheet='ETH&IB Switch',row=index+3)} for index,reading in enumerate(prototype.reads))
            options = dict(identity_response=identity_read,history_response=history_read,business_reads=current)
            observed = before.observe_owned_business_continuity(writer,owner,bound,unit,**options)
            self.assertEqual((2,1,prototype.digest),(observed.operations_retained,observed.noop_operations,observed.preread_sha256))
            self.assertFalse(hasattr(observed,'permit')); self.assertFalse(hasattr(observed,'complete'))
            variants = [dict(identity_response=replace(identity_read)),dict(history_response=replace(history_read)),
                        dict(business_reads=current[1:]),dict(business_reads=tuple(reversed(current)))]
            for index in range(2):
                for name in common.keys() | {'row_response'}:
                    changed = [dict(item) for item in current]; changed[index][name] = replace(current[index][name])
                    variants.append(dict(business_reads=tuple(changed)))
            # Operator edit on the NOOP row cannot silently remove its original decision.
            noop = deepcopy(json.loads(prototype.reads[0]['row_response'].data))
            noop['sheets'][0]['data'][0]['rowData'][0]['values'][11]['userEnteredValue'] = {'stringValue':'operator changed NOOP'}
            read = self.read_owned(stack,writer,owner,bound,auth,'row',noop,sheet='ETH&IB Switch',row=3)
            changed = [dict(item) for item in current]; changed[0]['row_response'] = read
            variants.append(dict(business_reads=tuple(changed)))
            history = deepcopy(json.loads(prototype.raw.data))
            history['sheets'][0]['properties']['gridProperties']['rowCount'] += 1
            variants.append(dict(history_response=self.read_owned(stack,writer,owner,bound,auth,'history_tail',history)))
            for changes in variants:
                with self.subTest(changes=tuple(changes)), self.assertRaises(before.HistoryPrereadHold) as caught:
                    before.observe_owned_business_continuity(writer,owner,bound,unit,**{**options,**changes})
                self.assertIsNone(caught.exception.__context__)
            # Same-byte new inode is not the retained original image. Cover
            # replacement just after initial decoding, not only later reads.
            import os
            business_path = state/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.business')/'BUSINESS-RAW'
            preserved = self.root/'preserved-owned-business-original'
            original_raw = business_path.read_bytes(); original_inspect = before._inspect_business
            rebound = [False]
            def replace_after_original_decode(*args,**kwargs):
                result = original_inspect(*args,**kwargs)
                if not rebound[0]:
                    business_path.rename(preserved); business_path.write_bytes(original_raw); business_path.chmod(0o600)
                    rebound[0] = True
                return result
            try:
                with mock.patch.object(before,'_inspect_business',side_effect=replace_after_original_decode):
                    with self.assertRaises(before.HistoryPrereadHold):
                        before.observe_owned_business_continuity(writer,owner,bound,unit,**options)
            finally:
                if rebound[0]: os.replace(preserved,business_path)  # restore only this owned synthetic original
            from monitor import issue_tracker_history_read_launcher as fixed_reads
            with mock.patch.object(fixed_reads,'_monotonic',return_value=__import__('time').monotonic()+31):
                with self.assertRaises(before.HistoryPrereadHold):
                    before.observe_owned_business_continuity(writer,owner,bound,unit,**options)
            self.assertEqual((1,'UNKNOWN'),(journal.inspect_global_unit(owner,bound,unit).attempt_count,
                                          journal.inspect_global_unit(owner,bound,unit).outcome))
            self.assertEqual(retained,{str(path.relative_to(state)):path.read_bytes() for path in state.rglob('*') if path.is_file()})

    def test_actual_issued_match_rejects_original_count_and_history_namespace_drift(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_global_attempt_journal as journal
        module=load()
        for fault in ('count','history-directory'):
            with self.subTest(fault=fault),ExitStack() as stack:
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
                responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                           for name,(kind,value) in docs.items()}
                current=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.history')
                preserved=self.root/'preserved-issued-match-history'
                original={p.name:p.read_bytes() for p in current.iterdir()}
                decoding=module.decode.decode_history_tail; changed=[]
                def decode_then_change(plan,raw,**options):
                    result=decoding(plan,raw,**options)
                    if raw is responses['history_response'] and not changed:
                        if fault=='count': journal.record_global_attempt_intent(owner,bound,unit)
                        else:
                            current.rename(preserved); current.mkdir(mode=0o700)
                            for name,image in original.items():
                                path=current/name; path.write_bytes(image); path.chmod(0o600)
                        changed.append(True)
                    return result
                with mock.patch.object(module.decode,'decode_history_tail',side_effect=decode_then_change):
                    with self.assertRaises(module.RemoteHistoryHold):
                        module.observe_owned_remote_history_unit(writer,owner,bound,unit,**responses)
                self.assertEqual([True],changed)
                seen=journal.inspect_global_unit(owner,bound,unit)
                self.assertEqual((2 if fault=='count' else 1,'UNKNOWN'),(seen.attempt_count,seen.outcome))
                if fault=='history-directory':
                    self.assertEqual(original,{p.name:p.read_bytes() for p in preserved.iterdir()})
                    self.assertEqual(original,{p.name:p.read_bytes() for p in current.iterdir()})
            # Each subcase needs a genuinely new owned state, never an adopted
            # UNKNOWN or a hand-reset original counter.
            if fault=='count': self.doCleanups(); self.setUp()

    def test_actual_owned_complete_proof_is_durable_but_never_applied_or_barrier_release(self):
        module=load()
        self.assertTrue(hasattr(module,'record_owned_completion_evidence'),
                        'fixed issued reads must persist ALL proof rows and original journal identities')
        from contextlib import ExitStack
        from monitor import issue_tracker_global_attempt_journal as journal
        with ExitStack() as stack:
            writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
            responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                       for name,(kind,value) in docs.items()}
            state=self.root/'var/lib/http-ztp-container/issue-tracker'
            retained={p:p.read_bytes() for p in state.rglob('*') if p.is_file()}
            seen=module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
            self.assertEqual(('COMPLETE-PRESENT-NOT-APPLIED',1,2),(seen.state,seen.attempt_count,seen.history_rows_matched))
            self.assertFalse(hasattr(seen,'permit')); self.assertFalse(hasattr(seen,'applied'))
            proof=state/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.completion')
            self.assertEqual({'IDENTITY-RAW','HEADERS-RAW','METADATA-RAW','HISTORY-RAW','HEADER','COMPLETE'},
                             {p.name for p in proof.iterdir()})
            for name,file in (('identity_response','IDENTITY-RAW'),('headers_response','HEADERS-RAW'),
                              ('metadata_response','METADATA-RAW'),('history_response','HISTORY-RAW')):
                self.assertEqual(responses[name].data,(proof/file).read_bytes())
            self.assertEqual(retained,{p:p.read_bytes() for p in retained})
            self.assertEqual(seen,module.inspect_completion_evidence(owner,bound,unit))
            with self.assertRaises(module.RemoteHistoryHold):
                module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
            self.assertEqual((1,'UNKNOWN'),(journal.inspect_global_unit(owner,bound,unit).attempt_count,
                                           journal.inspect_global_unit(owner,bound,unit).outcome))
            with self.assertRaises(journal.GlobalAttemptHold): journal.prepare_global_unit(owner,bound,unit)
        # No live read registry, shared Python object, old token or inherited
        # lock FD survives. The child reads the actual retained original store.
        import subprocess
        program='''import sys,json,hashlib
from pathlib import Path
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
from monitor import issue_tracker_spreadsheet_owner as owner, issue_tracker_remote_history_match as match
from monitor.issue_tracker_online_target import OnlineTargetBinding
from monitor.issue_tracker_send_unit import _original_unit
root=Path(sys.argv[2]); bound=OnlineTargetBinding(**json.loads(sys.stdin.buffer.read()))
path=root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.journal')
unit=_original_unit((path/'ACTION-PREIMAGE').read_bytes(),(path/'WIRE').read_bytes())
with scoped_fixture(root,owner),owner.spreadsheet_owner(bound) as token:
 seen=match.inspect_completion_evidence(token,bound,unit)
 print(seen.state,seen.attempt_count,seen.history_rows_matched)
'''
        from dataclasses import asdict
        cold=subprocess.run([sys.executable,'-B','-c',program,str(ROOT),str(self.root)],
            input=json.dumps(asdict(bound)).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(0,cold.returncode,cold.stderr)
        self.assertEqual(b'COMPLETE-PRESENT-NOT-APPLIED 1 2\n',cold.stdout)

    def test_completion_header_original_identity_and_history_extent_cannot_be_substituted(self):
        module=load()
        from contextlib import ExitStack
        from monitor import issue_tracker_local_commit as local
        for fault in ('same-byte-header','history-extent'):
            with self.subTest(fault=fault),ExitStack() as stack:
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
                responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                           for name,(kind,value) in docs.items()}
                module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                proof=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.completion')
                path=proof/'HEADER'; original=path.read_bytes()
                if fault=='same-byte-header':
                    path.rename(self.root/'preserved-completion-header'); path.write_bytes(original); path.chmod(0o600)
                else:
                    doc=json.loads(original); doc['matched']['history_last_row_after_read']+=1
                    raw=local._canonical(doc); path.write_bytes(raw)
                    marker=json.loads((proof/'COMPLETE').read_bytes()); marker['header_sha256']=hashlib.sha256(raw).hexdigest()
                    if 'header_identity' in marker:
                        from monitor import issue_tracker_attempt_journal as original_io
                        marker['header_identity']=list(original_io._identity(path.stat()))
                    (proof/'COMPLETE').write_bytes(local._canonical(marker))
                retained={p:p.read_bytes() for p in proof.iterdir()}
                with self.assertRaises(module.RemoteHistoryHold): module.inspect_completion_evidence(owner,bound,unit)
                self.assertEqual(retained,{p:p.read_bytes() for p in proof.iterdir()})
            if fault=='same-byte-header': self.doCleanups(); self.setUp()

    def test_cold_completion_replays_raw_semantics_not_a_self_consistent_matched_summary(self):
        """Raw hashes/stat and COMPLETE can agree while the proof rows do not."""
        module=load()
        from contextlib import ExitStack
        from monitor import issue_tracker_local_commit as local, issue_tracker_attempt_journal as original_io
        faults=('fence','nonce','identity','headers','history','request-path')
        for number,fault in enumerate(faults):
            with self.subTest(fault=fault),ExitStack() as stack:
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
                responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                           for name,(kind,value) in docs.items()}
                module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                proof=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.completion')
                header=json.loads((proof/'HEADER').read_bytes())
                if fault=='request-path':
                    header['responses']['HISTORY-RAW']['request_path_sha256']='0'*64
                else:
                    file={'fence':'METADATA-RAW','nonce':'METADATA-RAW','identity':'IDENTITY-RAW',
                          'headers':'HEADERS-RAW','history':'HISTORY-RAW'}[fault]
                    raw=json.loads((proof/file).read_bytes())
                    if fault in ('fence','nonce'):
                        entries=raw['matchedDeveloperMetadata']
                        chosen=next(entry['developerMetadata'] for entry in entries
                                    if (entry['developerMetadata']['metadataKey']=='z')==(fault=='fence'))
                        chosen['metadataValue']='different-original-value'
                    elif fault=='identity':
                        raw['sheets'][0]['properties']['title']='different-template-title'
                    elif fault=='headers':
                        raw['sheets'][0]['data'][0]['rowData'][0]['values'][0]['userEnteredValue']={'stringValue':'different header'}
                    else:
                        raw['sheets'][0]['data'][0]['rowData'].pop()
                    image=local._canonical(raw); (proof/file).write_bytes(image)
                    header['responses'][file]['sha256']=hashlib.sha256(image).hexdigest()
                    header['responses'][file]['identity']=list(original_io._identity((proof/file).stat()))
                    if file=='METADATA-RAW': header['matched']['metadata_sha256']=hashlib.sha256(image).hexdigest()
                    if file=='HISTORY-RAW': header['matched']['history_sha256']=hashlib.sha256(image).hexdigest()
                image=local._canonical(header); (proof/'HEADER').write_bytes(image)
                marker=json.loads((proof/'COMPLETE').read_bytes())
                marker['header_sha256']=hashlib.sha256(image).hexdigest()
                marker['header_identity']=list(original_io._identity((proof/'HEADER').stat()))
                (proof/'COMPLETE').write_bytes(local._canonical(marker))
                retained={path.name:path.read_bytes() for path in proof.iterdir()}
                with self.assertRaises(module.RemoteHistoryHold):
                    module.inspect_completion_evidence(owner,bound,unit)
                self.assertEqual(retained,{path.name:path.read_bytes() for path in proof.iterdir()})
            if number<len(faults)-1: self.doCleanups(); self.setUp()

    def test_owned_completion_missing_audit_forged_read_and_failed_barrier_never_install_marker(self):
        module=load()
        self.assertTrue(hasattr(module,'record_owned_completion_evidence'),'durable C19 writer missing')
        from contextlib import ExitStack
        from monitor import issue_tracker_local_commit as local
        with ExitStack() as stack:
            writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
            responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                       for name,(kind,value) in docs.items()}
            proof=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.completion')
            missing=deepcopy(docs['history_response'][1]); missing['sheets'][0]['data'][0]['rowData'].pop()
            changed=self.read_owned(stack,writer,owner,bound,auth,'history_tail',missing)
            for options in ({**responses,'history_response':changed},
                            {**responses,'metadata_response':replace(responses['metadata_response'])}):
                with self.assertRaises(module.RemoteHistoryHold):
                    module.record_owned_completion_evidence(writer,owner,bound,unit,**options)
                self.assertFalse(proof.exists())
            actual=local._write_new
            def failed_header_barrier(folder,name,raw):
                actual(folder,name,raw)
                if name=='HEADER': raise OSError('owned fixture failed HEADER directory barrier')
            with mock.patch.object(local,'_write_new',side_effect=failed_header_barrier):
                with self.assertRaises(module.RemoteHistoryHold):
                    module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
            self.assertTrue((proof/'HEADER').is_file()); self.assertFalse((proof/'COMPLETE').exists())
            before={p:p.read_bytes() for p in proof.iterdir()}
            with self.assertRaises(module.RemoteHistoryHold): module.inspect_completion_evidence(owner,bound,unit)
            with self.assertRaises(module.RemoteHistoryHold):
                module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
            self.assertEqual(before,{p:p.read_bytes() for p in proof.iterdir()})

    def test_completion_marker_never_precedes_any_required_raw_header_or_directory_barrier(self):
        module=load()
        from contextlib import ExitStack
        import os
        # New-folder parent+folder, all four raw file+folder barriers,
        # HEADER file+folder, then explicit folder+parent synchronization.
        for boundary in range(1,15):
            with self.subTest(boundary=boundary),ExitStack() as stack:
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
                responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                           for name,(kind,value) in docs.items()}
                proof=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.completion')
                actual=os.fsync; calls=[]
                def fail_at(fd):
                    # Matching first synchronizes the pre-existing preread
                    # and nonce stores (nine barriers). A failure there has
                    # created NO partial completion to forbid on the next
                    # read-only retry. Count only this NEW store's barriers,
                    # from its actual mkdir, not global fsync ordinals.
                    if proof.exists():
                        calls.append(fd)
                        if len(calls)==boundary: raise OSError('owned fixture interruption')
                    return actual(fd)
                with mock.patch('os.fsync',side_effect=fail_at),self.assertRaises(module.RemoteHistoryHold):
                    module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                self.assertEqual(boundary,len(calls)); self.assertFalse((proof/'COMPLETE').exists())
                original={str(p.relative_to(proof)):p.read_bytes() for p in proof.rglob('*') if p.is_file()}
                with self.assertRaises(module.RemoteHistoryHold): module.inspect_completion_evidence(owner,bound,unit)
                with self.assertRaises(module.RemoteHistoryHold):
                    module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                self.assertEqual(original,{str(p.relative_to(proof)):p.read_bytes() for p in proof.rglob('*') if p.is_file()})
            if boundary!=14: self.doCleanups(); self.setUp()

    def test_completion_keeps_original_count_through_header_barrier_and_final_owned_deadline(self):
        module=load()
        from contextlib import ExitStack
        from monitor import issue_tracker_local_commit as local, issue_tracker_global_attempt_journal as journal
        from monitor import issue_tracker_history_read_launcher as reads
        import time
        for fault in ('count-after-header','deadline-after-header'):
            with self.subTest(fault=fault),ExitStack() as stack:
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
                responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                           for name,(kind,value) in docs.items()}
                actual=local._write_new; changed=[]
                def after_header(folder,name,raw):
                    actual(folder,name,raw)
                    if name=='HEADER' and not changed:
                        changed.append(True)
                        if fault=='count-after-header': journal.record_global_attempt_intent(owner,bound,unit)
                with mock.patch.object(local,'_write_new',side_effect=after_header), \
                        mock.patch.object(reads,'_monotonic',side_effect=lambda:time.monotonic()+(31 if changed and fault=='deadline-after-header' else 0)):
                    with self.assertRaises(module.RemoteHistoryHold):
                        module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                self.assertEqual([True],changed)
                proof=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.completion')
                self.assertFalse((proof/'COMPLETE').exists())
                self.assertEqual((2 if fault=='count-after-header' else 1,'UNKNOWN'),
                    (journal.inspect_global_unit(owner,bound,unit).attempt_count,journal.inspect_global_unit(owner,bound,unit).outcome))
            if fault=='count-after-header': self.doCleanups(); self.setUp()

    def test_completion_writer_cannot_return_after_final_inspection_deadline_or_namespace_drift(self):
        module=load()
        from contextlib import ExitStack
        from monitor import issue_tracker_history_read_launcher as reads
        import time
        for fault in ('deadline','completion-directory'):
            with self.subTest(fault=fault),ExitStack() as stack:
                writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
                responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                           for name,(kind,value) in docs.items()}
                actual=module.inspect_completion_evidence; changed=[]
                proof=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.completion')
                def finish_then_change(*args,**options):
                    seen=actual(*args,**options); changed.append(True)
                    if fault=='completion-directory':
                        originals={p.name:p.read_bytes() for p in proof.iterdir()}
                        proof.rename(self.root/'preserved-completion-original'); proof.mkdir(mode=0o700)
                        for name,raw in originals.items():
                            path=proof/name; path.write_bytes(raw); path.chmod(0o600)
                    return seen
                with mock.patch.object(module,'inspect_completion_evidence',side_effect=finish_then_change), \
                        mock.patch.object(reads,'_monotonic',side_effect=lambda:time.monotonic()+(31 if changed and fault=='deadline' else 0)):
                    with self.assertRaises(module.RemoteHistoryHold):
                        module.record_owned_completion_evidence(writer,owner,bound,unit,**responses)
                self.assertEqual([True],changed)
                self.assertTrue((proof/'COMPLETE').is_file(),'retained historical evidence is never deleted on late failure')
            if fault=='deadline': self.doCleanups(); self.setUp()

    def test_actual_issued_match_cannot_escape_after_matching_original_count_changes(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_global_attempt_journal as journal
        module=load()
        with ExitStack() as stack:
            writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
            responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value)
                       for name,(kind,value) in docs.items()}
            matching=module.observe_remote_history_unit; changed=[]
            def matched_then_changed(*args,**options):
                result=matching(*args,**options)
                self.assertEqual('MATCHED_OBSERVATION',result.state)
                journal.record_global_attempt_intent(owner,bound,unit); changed.append(True)
                return result
            with mock.patch.object(module,'observe_remote_history_unit',side_effect=matched_then_changed):
                with self.assertRaises(module.RemoteHistoryHold):
                    module.observe_owned_remote_history_unit(writer,owner,bound,unit,**responses)
            self.assertEqual([True],changed)
            self.assertEqual((2,'UNKNOWN'),(journal.inspect_global_unit(owner,bound,unit).attempt_count,
                                           journal.inspect_global_unit(owner,bound,unit).outcome))

    def test_actual_fixed_dual_owner_native_reads_feed_original_whole_match_without_settlement(self):
        module = load()
        self.assertTrue(hasattr(module,'observe_owned_remote_history_unit'),'actual issued-read matcher bridge missing')
        from contextlib import ExitStack
        from monitor import issue_tracker_global_attempt_journal as journal
        with ExitStack() as stack:
            writer, owner, bound, auth, _config, unit, docs = self.prepare_owned(stack)
            original = {p:p.read_bytes() for p in (self.root/'var/lib/http-ztp-container/issue-tracker').rglob('*') if p.is_file()}
            responses = {name:self.read_owned(stack,writer,owner,bound,auth,kind,value) for name,(kind,value) in docs.items()}
            seen = module.observe_owned_remote_history_unit(writer,owner,bound,unit,**responses)
            self.assertEqual(('MATCHED_OBSERVATION',2,2,1),(seen.state,seen.history_rows_expected,seen.history_rows_matched,seen.attempt_count))
            self.assertEqual((1,'UNKNOWN'),(journal.inspect_global_unit(owner,bound,unit).attempt_count,journal.inspect_global_unit(owner,bound,unit).outcome))
            self.assertFalse(hasattr(seen,'permit')); self.assertFalse(hasattr(seen,'applied'))
            self.assertEqual(original,{p:p.read_bytes() for p in (self.root/'var/lib/http-ztp-container/issue-tracker').rglob('*') if p.is_file()})
            for name in responses:
                forged = {**responses,name:replace(responses[name])}
                with self.subTest(copy=name),mock.patch.object(module,'observe_remote_history_unit') as matcher:
                    with self.assertRaises(module.RemoteHistoryHold): module.observe_owned_remote_history_unit(writer,owner,bound,unit,**forged)
                    matcher.assert_not_called()
            from test_cases.test_issue_tracker_online_target import document
            _config.write_text(json.dumps(document(status='disabled')))
            with self.assertRaises(module.RemoteHistoryHold): module.observe_owned_remote_history_unit(writer,owner,bound,unit,**responses)

    def test_actual_issued_bad_header_missing_audit_and_final_policy_revocation_are_not_completion(self):
        module=load()
        self.assertTrue(hasattr(module,'observe_owned_remote_history_unit'),'actual issued-read matcher bridge missing')
        from contextlib import ExitStack
        with ExitStack() as stack:
            writer,owner,bound,auth,config,unit,docs=self.prepare_owned(stack)
            responses={name:self.read_owned(stack,writer,owner,bound,auth,kind,value) for name,(kind,value) in docs.items()}
            bad_header=deepcopy(docs['headers_response'][1]); bad_header['sheets'][0]['data'][0]['rowData'][0]['values'][0]['userEnteredValue']['stringValue']='foreign header'
            changed=self.read_owned(stack,writer,owner,bound,auth,'template_headers',bad_header)
            with mock.patch.object(module,'observe_remote_history_unit') as matcher:
                with self.assertRaises(module.RemoteHistoryHold): module.observe_owned_remote_history_unit(writer,owner,bound,unit,**{**responses,'headers_response':changed})
                matcher.assert_not_called()
            missing=deepcopy(docs['history_response'][1]); missing['sheets'][0]['data'][0]['rowData'].pop()
            changed=self.read_owned(stack,writer,owner,bound,auth,'history_tail',missing)
            seen=module.observe_owned_remote_history_unit(writer,owner,bound,unit,**{**responses,'history_response':changed})
            self.assertEqual(('CONFLICT',2,1),(seen.state,seen.history_rows_expected,seen.history_rows_matched))
            from monitor import issue_tracker_history_read_launcher as reads
            import time
            actual=module.observe_remote_history_unit; expired=[False]
            def finish_after_deadline(*args,**kwargs):
                seen=actual(*args,**kwargs); expired[0]=True; return seen
            with mock.patch.object(module,'observe_remote_history_unit',side_effect=finish_after_deadline), \
                    mock.patch.object(reads,'_monotonic',side_effect=lambda:time.monotonic()+(31 if expired[0] else 0)):
                with self.assertRaises(module.RemoteHistoryHold): module.observe_owned_remote_history_unit(writer,owner,bound,unit,**responses)
            from test_cases.test_issue_tracker_online_target import document
            actual=module.observe_remote_history_unit
            def revoke(*args,**kwargs):
                seen=actual(*args,**kwargs); config.write_text(json.dumps(document(status='disabled'))); return seen
            with mock.patch.object(module,'observe_remote_history_unit',side_effect=revoke):
                with self.assertRaises(module.RemoteHistoryHold): module.observe_owned_remote_history_unit(writer,owner,bound,unit,**responses)

    def test_owned_whitelist_template_nonce_and_visible_capacity_read_gates_are_not_a_permit(self):
        module=load()
        self.assertTrue(hasattr(module,'observe_owned_unit_read_gates'),'original W1/template/enrollment read gate bridge missing')
        from contextlib import ExitStack
        from monitor.issue_tracker_whitelist import freeze_whitelist_sheet
        from test_cases.test_req7_online_whitelist_read import document as whitelist_document, HEADER
        from monitor import issue_tracker_global_attempt_journal as journal
        snapshot=freeze_whitelist_sheet([HEADER,(None,None,None,None,'leaf-01',None),
                                        (None,None,None,None,'spine-*',None)])
        with ExitStack() as stack:
            writer,owner,bound,auth,_config,unit,docs=self.prepare_owned(stack)
            meta=deepcopy(docs['metadata_response'][1]); meta['matchedDeveloperMetadata'].pop()
            whitelist_doc=whitelist_document(); whitelist_doc['spreadsheetId']=bound.spreadsheet_id
            whitelist_doc['sheets'][0]['properties']['sheetId']=112
            images={name:self.read_owned(stack,writer,owner,bound,auth,kind,value) for name,(kind,value) in
                    {'identity_response':docs['identity_response'],'headers_response':docs['headers_response'],
                     'metadata_response':('metadata',meta),'whitelist_response':('whitelist',whitelist_doc)}.items()}
            observed=module.observe_owned_unit_read_gates(writer,owner,bound,unit,whitelist_snapshot=snapshot,**images)
            self.assertEqual(snapshot.sha256,observed.whitelist_sha256)
            self.assertEqual('VISIBLE_ONLY_UNPROVED',observed.capacity_outcome)
            self.assertFalse(hasattr(observed,'permit')); self.assertFalse(hasattr(observed,'applied'))
            self.assertEqual(1,journal.inspect_global_unit(owner,bound,unit).attempt_count)
            wrong_sheet=deepcopy(whitelist_doc); wrong_sheet['sheets'][0]['properties']['sheetId']=113
            read=self.read_owned(stack,writer,owner,bound,auth,'whitelist',wrong_sheet)
            with self.assertRaises(module.RemoteHistoryHold):
                module.observe_owned_unit_read_gates(writer,owner,bound,unit,whitelist_snapshot=snapshot,**{**images,'whitelist_response':read})
            for name in images:
                with self.subTest(copy=name),self.assertRaises(module.RemoteHistoryHold):
                    module.observe_owned_unit_read_gates(writer,owner,bound,unit,whitelist_snapshot=snapshot,**{**images,name:replace(images[name])})
            changed=deepcopy(whitelist_doc); changed['sheets'][0]['data'][0]['rowData'][1]['values'][4]['userEnteredValue']['stringValue']='new-unapproved-device-rule'
            read=self.read_owned(stack,writer,owner,bound,auth,'whitelist',changed)
            with self.assertRaises(module.RemoteHistoryHold):
                module.observe_owned_unit_read_gates(writer,owner,bound,unit,whitelist_snapshot=snapshot,**{**images,'whitelist_response':read})
            read=self.read_owned(stack,writer,owner,bound,auth,'metadata',docs['metadata_response'][1])
            with self.assertRaises(module.RemoteHistoryHold):
                module.observe_owned_unit_read_gates(writer,owner,bound,unit,whitelist_snapshot=snapshot,**{**images,'metadata_response':read})
            bad=deepcopy(meta); bad['matchedDeveloperMetadata'][0]['developerMetadata']['metadataValue']='f'*64
            read=self.read_owned(stack,writer,owner,bound,auth,'metadata',bad)
            with self.assertRaises(module.RemoteHistoryHold):
                module.observe_owned_unit_read_gates(writer,owner,bound,unit,whitelist_snapshot=snapshot,**{**images,'metadata_response':read})
            overflow=deepcopy(meta); overflow['matchedDeveloperMetadata'].append({'developerMetadata': {
                'metadataId':9000,'metadataKey':'x','metadataValue':'a'*30000,'visibility':'DOCUMENT',
                'location':{'locationType':'SHEET','sheetId':101}}})
            read=self.read_owned(stack,writer,owner,bound,auth,'metadata',overflow)
            with self.assertRaises(module.RemoteHistoryHold):
                module.observe_owned_unit_read_gates(writer,owner,bound,unit,whitelist_snapshot=snapshot,**{**images,'metadata_response':read})
            self.assertEqual((1,'UNKNOWN'),(journal.inspect_global_unit(owner,bound,unit).attempt_count,journal.inspect_global_unit(owner,bound,unit).outcome))


class Req7RemoteHistoryManifestTests(unittest.TestCase):
    def test_direct_native_workflow_primary_suite_and_not_run_card_bind_real_dependencies(self):
        registry = json.loads((ROOT / 'test_cases/script_test_manifest.json').read_text())
        script = 'monitor/issue_tracker_remote_history_match.py'; test = 'test_cases.test_req7_remote_history_match'
        self.assertEqual(script, registry['scripts'].get(script))
        self.assertTrue(any(script in rule['paths'] and test in rule['tests'] for rule in registry['test_rules']))
        dependencies = {script, 'monitor/issue_tracker_history_preread_journal.py', 'monitor/issue_tracker_global_attempt_journal.py',
            'monitor/issue_tracker_enrollment_journal.py', 'monitor/issue_tracker_spreadsheet_owner.py',
            'monitor/issue_tracker_history_read_launcher.py', 'monitor/issue_tracker_local_commit.py',
            'monitor/issue_tracker_online_target.py', 'monitor/issue_tracker_attempt_supervision.py',
            'monitor/issue_tracker_metadata_capacity.py', 'monitor/issue_tracker_sheets_read_decode.py', 'monitor/issue_tracker_tls_inputs.py'}
        self.assertTrue(any(dependencies <= set(rule['members']) and test in rule['tests'] for rule in registry['workflows']))
        self.assertEqual(['issue-tracker-local'], [suite['id'] for suite in registry['test_suites'] if test in suite['tests']])
        self.assertIn(test, (ROOT / 'test_cases/README.md').read_text())
        cards = (ROOT / 'test_cases/REAL_ENVIRONMENT.md').read_text(); start = cards.index('## TC-REAL-REQ7-REMOTE-HISTORY-MATCH-001')
        end = cards.find('\n## ', start + 1); card = cards[start:] if end == -1 else cards[start:end]
        for term in ('NOT RUN / REAL_ENV REQUIRED', '前置条件', 'Stage O', '证据', 'stat/inode', '清理', '不是 COMPLETE'):
            self.assertIn(term, card)


if __name__ == '__main__': unittest.main()
