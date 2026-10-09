"""Independent immutable pre-send History boundary, never COMPLETE or permission."""
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

if len(sys.argv) > 1 and sys.argv[1] == '--owned-inspect':
    sys.path.insert(0, sys.argv[3]); sys.path.insert(0, str(Path(sys.argv[3]) / 'tools'))
import test_cases
ROOT = Path(test_cases.__file__).resolve().parents[1]
from test_cases.test_req7_spreadsheet_owner import fixture, binding, TARGET, load as load_owner
from test_cases.test_req7_global_attempt_journal import load as load_global, unit
from test_cases.test_req7_history_read import inputs, load as load_read, response, tail_document
SOURCE = ROOT / 'monitor/issue_tracker_history_preread_journal.py'


def load():
    if not SOURCE.is_file(): raise AssertionError('immutable History pre-send journal missing')
    spec = importlib.util.spec_from_file_location('monitor.issue_tracker_history_preread_journal', SOURCE)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    import monitor
    monitor.issue_tracker_history_preread_journal = module
    return module


class Req7HistoryPrereadJournalDirectTests(unittest.TestCase):
    def setUp(self):
        self.owner = load_owner(); self.global_journal = load_global()
        self.planner = load_read('issue_tracker_sheets_read_plan'); load_read('issue_tracker_sheets_read_decode')
        self.temp = tempfile.TemporaryDirectory(prefix='req7-history-preread-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.locks = self.root / 'var/lib/http-ztp-container/issue-tracker'
        self.locks.mkdir(parents=True, mode=0o700); self.value = unit()
        self.store = self.locks / (hashlib.sha256(TARGET.encode()).hexdigest() + '.history')
        target, token = inputs(); self.plan = self.planner.prepare_history_tail_read(target, token)
        self.raw = response(tail_document())

    def test_original_raw_and_boundary_bind_existing_global_unit_before_any_attempt(self):
        module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            with self.assertRaises(module.HistoryPrereadHold): module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
            self.assertFalse(self.store.exists())
            self.global_journal.prepare_global_unit(token, binding(), self.value)
            module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
            seen = module.inspect_history_preread(token, binding(), self.value)
            self.assertEqual((3, 7, 99), (seen.history_last_row_before_send, seen.row_count, seen.history_sheet_id))
            self.assertEqual(self.raw.data, (self.store / 'HISTORY-RAW').read_bytes())
            self.assertEqual(hashlib.sha256(self.raw.data).hexdigest(), seen.source_sha256)
            self.assertEqual(self.value.action_digest, seen.action_digest)
            self.assertFalse(hasattr(seen, 'complete')); self.assertFalse(hasattr(seen, 'permit'))
            for count in range(1, 7):
                self.global_journal.record_global_attempt_intent(token, binding(), self.value)
                self.assertEqual(3, module.inspect_history_preread(token, binding(), self.value).history_last_row_before_send)
            with self.assertRaises(module.HistoryPrereadHold): module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
            self.assertEqual(self.raw.data, (self.store / 'HISTORY-RAW').read_bytes())

    def test_original_capacity_reserves_all_actual_history_rows_and_survives_unknown_without_reallocation(self):
        module = load()
        self.assertTrue(hasattr(module, 'require_history_append_capacity'), 'actual History row reservation missing')
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.global_journal.prepare_global_unit(token, binding(), self.value)
            module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
            seen = module.require_history_append_capacity(token, binding(), self.value)
            self.assertEqual((4, 5, 2, 1, 7), (seen.first_row_index, seen.last_row_index, seen.rows_reserved, seen.remaining_rows, seen.row_count))
            self.assertEqual(self.value.action_digest, seen.action_digest)
            for count in range(1, 7):
                self.global_journal.record_global_attempt_intent(token, binding(), self.value)
                self.assertEqual(seen, module.require_history_append_capacity(token, binding(), self.value))
            self.assertFalse(hasattr(seen, 'permit')); self.assertFalse(hasattr(seen, 'complete'))

    def test_history_capacity_full_typed_gap_and_exact_boundary_use_original_not_caller_counter(self):
        module = load()
        self.assertTrue(hasattr(module, 'require_history_append_capacity'), 'actual History row reservation missing')
        for row_count, row_data, expected in ((3, [], None), (4, [], (2, 3, 0)),
                (5, [{'values': [{'userEnteredValue': {'boolValue': False}}]}], (3, 4, 0)),
                (5, [{}, {'values': [{}, {}, {}, {}, {'userEnteredValue': {'stringValue': ''}}]}], None)):
            with self.subTest(row_count=row_count, tail=len(row_data)), tempfile.TemporaryDirectory(prefix='req7-history-capacity-') as directory:
                root = Path(directory).resolve(); locks = root / 'var/lib/http-ztp-container/issue-tracker'; locks.mkdir(parents=True, mode=0o700)
                value = tail_document(row_count); value['sheets'][0]['data'][0]['rowData'] = row_data
                with fixture(root), self.owner.spreadsheet_owner(binding()) as token:
                    self.global_journal.prepare_global_unit(token, binding(), self.value)
                    module.prepare_history_preread(token, binding(), self.value, self.plan, response(value))
                    before = {p.name: p.read_bytes() for p in (locks / self.store.name).iterdir()}
                    if expected is None:
                        with self.assertRaises(module.HistoryPrereadHold): module.require_history_append_capacity(token, binding(), self.value)
                    else:
                        seen = module.require_history_append_capacity(token, binding(), self.value)
                        self.assertEqual(expected, (seen.first_row_index, seen.last_row_index, seen.remaining_rows))
                    self.assertEqual(before, {p.name: p.read_bytes() for p in (locks / self.store.name).iterdir()})
                    with self.assertRaises(TypeError): module.require_history_append_capacity(token, binding(), self.value, rows=1)
    def test_after_first_intent_no_creation_and_revocation_or_changed_binding_no_adoption(self):
        module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.global_journal.prepare_global_unit(token, binding(), self.value)
            self.global_journal.record_global_attempt_intent(token, binding(), self.value)
            with self.assertRaises(module.HistoryPrereadHold): module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
            self.assertFalse(self.store.exists())
        with fixture(self.root), self.assertRaises(module.HistoryPrereadHold): module.inspect_history_preread(token, binding(), self.value)
        for changed in (replace(binding(), policy_sha256='f' * 64), replace(binding(), allowlist_sha256='f' * 64)):
            with fixture(self.root), self.owner.spreadsheet_owner(changed) as fresh:
                with self.assertRaises(module.HistoryPrereadHold): module.prepare_history_preread(fresh, changed, self.value, self.plan, self.raw)
        self.assertFalse(self.store.exists())

    def test_fixed_full_response_retains_all_two_mib_without_manifest_limit_or_truncation(self):
        from types import SimpleNamespace
        module = load(); raw = self.raw.data + b' ' * (2 * 1024 * 1024 - len(self.raw.data))
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.global_journal.prepare_global_unit(token, binding(), self.value)
            with self.assertRaises(module.HistoryPrereadHold):
                module.prepare_history_preread(token, binding(), self.value, self.plan,
                    SimpleNamespace(status=200, complete=True, data=raw + b' '))
            self.assertFalse(self.store.exists())
            module.prepare_history_preread(token, binding(), self.value, self.plan,
                SimpleNamespace(status=200, complete=True, data=raw))
            seen = module.inspect_history_preread(token, binding(), self.value)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), seen.source_sha256)
            self.assertEqual((4, 5), (module.require_history_append_capacity(token, binding(), self.value).first_row_index,
                                     module.require_history_append_capacity(token, binding(), self.value).last_row_index))
        self.assertEqual(raw, (self.store / 'HISTORY-RAW').read_bytes())

    def test_partial_window_wrong_history_identity_and_partial_response_never_create_image(self):
        module = load()
        item = tail_document(); item['sheets'][0]['properties']['sheetId'] = 98
        from types import SimpleNamespace
        cases = ((replace(self.plan, path=self.plan.path.replace('E5002', 'E7')), self.raw),
                 (self.plan, response(item)), (self.plan, SimpleNamespace(status=200, complete=False, data=self.raw.data)))
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.global_journal.prepare_global_unit(token, binding(), self.value)
            for plan, raw in cases:
                with self.assertRaises(module.HistoryPrereadHold) as caught: module.prepare_history_preread(token, binding(), self.value, plan, raw)
                self.assertIsNone(caught.exception.__context__); self.assertFalse(self.store.exists())

    def test_all_six_image_barriers_precede_marker_and_partial_never_backfilled(self):
        module = load(); real_fsync = os.fsync
        for boundary in range(1, 7):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory(prefix='req7-before-barrier-') as directory:
                root = Path(directory).resolve(); locks = root / 'var/lib/http-ztp-container/issue-tracker'; locks.mkdir(parents=True, mode=0o700)
                store = locks / self.store.name
                with fixture(root), self.owner.spreadsheet_owner(binding()) as token:
                    self.global_journal.prepare_global_unit(token, binding(), self.value)
                    calls = []
                    def failing(fd):
                        # Target the six HISTORY image barriers, excluding
                        # upstream retained GLOBAL recovery/read barriers.
                        if store.exists():
                            calls.append(fd)
                            if len(calls) == boundary: raise OSError('private synthetic barrier failure')
                        real_fsync(fd)
                    with mock.patch('os.fsync', side_effect=failing), self.assertRaises(module.HistoryPrereadHold):
                        module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
                    self.assertEqual(boundary, len(calls))
                    self.assertTrue(store.is_dir()); self.assertFalse((store / 'INITIALIZED').exists())
                    with self.assertRaises(module.HistoryPrereadHold): module.inspect_history_preread(token, binding(), self.value)
                    with self.assertRaises(module.HistoryPrereadHold): module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
                    self.assertFalse((store / 'INITIALIZED').exists())

    def test_marker_header_raw_alias_extra_namespace_or_global_chain_tamper_hold(self):
        module = load()
        for fault in ('raw', 'header', 'marker', 'mode', 'symlink', 'hardlink', 'extra', 'global'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix='req7-before-tamper-') as directory:
                root = Path(directory).resolve(); locks = root / 'var/lib/http-ztp-container/issue-tracker'; locks.mkdir(parents=True, mode=0o700)
                store = locks / self.store.name
                with fixture(root), self.owner.spreadsheet_owner(binding()) as token:
                    self.global_journal.prepare_global_unit(token, binding(), self.value)
                    module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
                    if fault == 'mode': (store / 'HISTORY-RAW').chmod(0o644)
                    elif fault == 'extra': (store / 'foreign').write_bytes(b'foreign')
                    elif fault == 'global': (locks / (hashlib.sha256(TARGET.encode()).hexdigest() + '.journal') / 'WIRE').write_bytes(b'foreign')
                    elif fault in ('symlink', 'hardlink'):
                        (store / 'HISTORY-RAW').rename(root / 'preserved')
                        if fault == 'symlink': (store / 'HISTORY-RAW').symlink_to(root / 'preserved')
                        else: os.link(root / 'preserved', store / 'HISTORY-RAW')
                    else: (store / {'raw': 'HISTORY-RAW', 'header': 'HEADER', 'marker': 'INITIALIZED'}[fault]).write_bytes(b'foreign')
                    before = {p.name: p.read_bytes() for p in store.iterdir()}
                    with self.assertRaises(module.HistoryPrereadHold): module.inspect_history_preread(token, binding(), self.value)
                    self.assertEqual(before, {p.name: p.read_bytes() for p in store.iterdir()})

    def test_coherent_foreign_target_rehash_does_not_retarget_original_global_journal(self):
        module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.global_journal.prepare_global_unit(token, binding(), self.value)
            module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
            other = 'foreign_spreadsheet_0002'; item = tail_document(); item['spreadsheetId'] = other
            raw = response(item).data; (self.store / 'HISTORY-RAW').write_bytes(raw)
            header = json.loads((self.store / 'HEADER').read_bytes())
            header['read_path'] = header['read_path'].replace(TARGET, other)
            header['source_sha256'] = hashlib.sha256(raw).hexdigest()
            canonical = lambda value: (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()
            (self.store / 'HEADER').write_bytes(canonical(header))
            (self.store / 'INITIALIZED').write_bytes(canonical({'schema_version': 1, 'state': 'INITIALIZED',
                'header_sha256': hashlib.sha256(canonical(header)).hexdigest()}))
            with self.assertRaises(module.HistoryPrereadHold): module.inspect_history_preread(token, binding(), self.value)


class Req7BusinessPrereadJournalDirectTests(unittest.TestCase):
    def test_owned_continuity_refuses_forged_response_before_reading_originals(self):
        from types import SimpleNamespace
        self.assertTrue(hasattr(self.module, 'observe_owned_business_continuity'),
                        'issued current ALL-business gate missing')
        forged = SimpleNamespace(status=200,complete=True,data=b'{}')
        with mock.patch.object(self.module,'_business_inputs') as originals:
            with self.assertRaises(self.module.HistoryPrereadHold) as caught:
                self.module.observe_owned_business_continuity(None,None,self.target,object(),
                    identity_response=forged,history_response=forged,business_reads=())
            originals.assert_not_called()
        self.assertIsNone(caught.exception.__context__)

    def setUp(self):
        from test_cases.test_req7_enrollment_journal import load as load_enrollment
        from test_cases.test_req7_send_unit import inputs as unit_inputs
        from test_cases.test_req7_sheets_read_decode import response as grid_response, identity_response
        from test_cases.test_req7_activity_discovery import sheet_document, insertion_document, exact_row_document, switch_row, literal
        self.owner = load_owner(); self.enrollment = load_enrollment(); self.global_journal = load_global()
        self.planner = load_read('issue_tracker_sheets_read_plan')
        decoder = load_read('issue_tracker_sheets_read_decode')
        import monitor
        monitor.issue_tracker_sheets_read_plan = self.planner
        monitor.issue_tracker_sheets_read_decode = decoder
        self.module = load(); self.target, credential = inputs()
        self.identity = decoder.decode_template_identity(self.planner.prepare_template_identity_read(self.target, credential), grid_response(identity_response()))
        self.temp = tempfile.TemporaryDirectory(prefix='req7-business-preread-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.locks = self.root/'var/lib/http-ztp-container/issue-tracker'
        self.locks.mkdir(parents=True, mode=0o700)
        self.store = self.locks/(hashlib.sha256(TARGET.encode()).hexdigest()+'.business')
        self.args = unit_inputs(); self.manifest = self.args['manifest']; rows = []
        for i in range(2):
            row = switch_row('NV%05d' % (10001+i)); row['F'] = literal('node%04d' % i)
            row['L'] = literal('[MONITOR][down][fabric] old'); rows.append(row)
        discovered = sheet_document('ETH&IB Switch', rows); occupied = insertion_document('ETH&IB Switch', rows)
        for item in (discovered, occupied): item['sheets'][0]['properties']['sheetId'] = 101
        discovery_plan = self.planner.prepare_activity_sheet_read(self.target, credential, sheet='ETH&IB Switch')
        occupancy_plan = self.planner.prepare_insertion_sheet_read(self.target, credential, sheet='ETH&IB Switch')
        self.reads = []
        for i in range(2):
            exact = exact_row_document('ETH&IB Switch', rows[i], i+2); exact['sheets'][0]['properties']['sheetId'] = 101
            self.reads.append(dict(operation_id='switch:%04d' % i, discovery_plan=discovery_plan, discovery_response=grid_response(discovered),
                occupancy_plan=occupancy_plan, occupancy_response=grid_response(occupied),
                row_plan=self.planner.prepare_sheets_read(self.target, credential, mode='row_rectangle', sheet='ETH&IB Switch', first_row=i+3), row_response=grid_response(exact)))
        self.plan = self.planner.prepare_history_tail_read(self.target, credential)
        history = tail_document(); history['sheets'][0]['properties']['sheetId'] = 105; self.raw = grid_response(history)
        image = {'schema_version': 1, 'spreadsheet_id': TARGET, 'sheet': 'ETH&IB Switch', 'sheet_id': 101, 'history_sheet_id': 105,
            'history_path': self.plan.path, 'history_sha256': hashlib.sha256(self.raw.data).hexdigest(),
            'business': [{'operation_id': reading['operation_id'], 'discovery_path': discovery_plan.path,
                'discovery_sha256': hashlib.sha256(reading['discovery_response'].data).hexdigest(), 'occupancy_path': occupancy_plan.path,
                'occupancy_sha256': hashlib.sha256(reading['occupancy_response'].data).hexdigest(),
                'row_path': reading['row_plan'].path, 'row_sha256': hashlib.sha256(reading['row_response'].data).hexdigest()} for reading in self.reads]}
        self.digest = hashlib.sha256((json.dumps(image, ensure_ascii=False, sort_keys=True, separators=(',', ':'))+'\n').encode()).hexdigest()

    def initialize(self, token):
        from monitor.issue_tracker_send_unit import freeze_send_unit
        original = self.enrollment.prepare_enrollment_journal(token, binding(), self.identity)
        nonces = {title: nonce for title, _sid, nonce in original.nonces}
        business = [dict(item) for item in self.args['business']]
        business[0]['values'] = {'L': '[MONITOR][down][fabric] old'}
        business[1]['values'] = {'L': '[MONITOR][down][fabric] new'}
        for item in business: item['observed_values'] = {'L': {'stringValue': '[MONITOR][down][fabric] old'}}
        self.value = freeze_send_unit(**{**self.args, 'business': tuple(business), 'sheet_id': 101, 'history_sheet_id': 105,
            'target_nonce': nonces['ETH&IB Switch'], 'history_nonce': nonces['Update_History'], 'preread_sha256': self.digest})
        self.global_journal.prepare_global_unit(token, binding(), self.value)
        self.module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)

    def prepare(self, token, **changes):
        options = dict(manifest=self.manifest, business_reads=tuple(self.reads)); options.update(changes)
        return self.module.prepare_business_preread(token, binding(), self.identity, self.value, **options)

    def test_full_original_including_noop_survives_unknown_without_credentials_or_reconstruction(self):
        self.assertTrue(hasattr(self.module, 'prepare_business_preread'), 'durable original business images missing')
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); self.prepare(token)
            seen = self.module.inspect_business_preread(token, binding(), self.identity, self.value)
            self.assertEqual((2, 1, self.digest), (seen.operations_retained, seen.noop_operations, seen.preread_sha256))
            self.assertEqual(self.value.action_digest, seen.action_digest); self.assertEqual(self.value.wire_sha256, seen.wire_sha256)
            self.assertEqual({'MANIFEST', 'BUSINESS-RAW', 'HEADER', 'INITIALIZED'}, set(os.listdir(self.store)))
            self.assertEqual(self.manifest, (self.store/'MANIFEST').read_bytes())
            before = {path.name: path.read_bytes() for path in self.store.iterdir()}
            for data in before.values():
                self.assertNotIn(b'Bearer', data); self.assertNotIn(b'synthetic.private', data)
            for count in range(1, 7):
                self.global_journal.record_global_attempt_intent(token, binding(), self.value)
                self.assertEqual(seen, self.module.inspect_business_preread(token, binding(), self.identity, self.value))
            with self.assertRaises(self.module.HistoryPrereadHold): self.prepare(token)
            self.assertEqual(before, {path.name: path.read_bytes() for path in self.store.iterdir()})
            for name in ('permit', 'complete', 'applied', 'send_once'): self.assertFalse(hasattr(seen, name))

    def test_mismatched_original_digest_missing_noop_reordered_or_credential_claims_never_create(self):
        self.assertTrue(hasattr(self.module, 'prepare_business_preread'), 'durable original business images missing')
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token)
            for changed in ({'manifest': self.manifest+b' '}, {'business_reads': tuple(self.reads[1:])},
                            {'business_reads': tuple(reversed(self.reads))}, {'row_reservations': (2, 3)}):
                with self.subTest(fields=tuple(changed)), self.assertRaises(self.module.HistoryPrereadHold): self.prepare(token, **changed)
                self.assertFalse(self.store.exists())
            original = self.reads[0]['row_response']
            self.reads[0]['row_response'] = type(original)(status=200, complete=True, data=original.data+b' ')
            try:
                with self.assertRaises(self.module.HistoryPrereadHold): self.prepare(token)
            finally: self.reads[0]['row_response'] = original
            self.assertFalse(self.store.exists())

    def test_eight_business_image_barriers_precede_marker_and_partial_store_never_adopted(self):
        real_fsync = os.fsync
        for boundary in range(1, 9):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory(prefix='req7-business-barrier-') as directory:
                self.root = Path(directory).resolve(); self.locks = self.root/'var/lib/http-ztp-container/issue-tracker'
                self.locks.mkdir(parents=True, mode=0o700); self.store = self.locks/(hashlib.sha256(TARGET.encode()).hexdigest()+'.business')
                with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
                    self.initialize(token); calls = []
                    def failing(fd):
                        if self.store.exists():
                            calls.append(fd)
                            if len(calls) == boundary: raise OSError('private original image barrier fault')
                        return real_fsync(fd)
                    with mock.patch('os.fsync', side_effect=failing), self.assertRaises(self.module.HistoryPrereadHold): self.prepare(token)
                    self.assertTrue(self.store.is_dir()); self.assertFalse((self.store/'INITIALIZED').exists())
                    before = {path.name: path.read_bytes() for path in self.store.iterdir()}
                    with self.assertRaises(self.module.HistoryPrereadHold): self.module.inspect_business_preread(token, binding(), self.identity, self.value)
                    with self.assertRaises(self.module.HistoryPrereadHold): self.prepare(token)
                    self.assertEqual(before, {path.name: path.read_bytes() for path in self.store.iterdir()})

    def test_original_aliases_mode_bytes_marker_global_history_nonce_or_extra_names_hold_without_repair(self):
        for fault in ('raw', 'manifest', 'header', 'marker', 'mode', 'symlink', 'hardlink', 'extra', 'global', 'history', 'nonces'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix='req7-business-tamper-') as directory:
                self.root = Path(directory).resolve(); self.locks = self.root/'var/lib/http-ztp-container/issue-tracker'
                self.locks.mkdir(parents=True, mode=0o700); stem = hashlib.sha256(TARGET.encode()).hexdigest(); self.store = self.locks/(stem+'.business')
                with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
                    self.initialize(token); self.prepare(token)
                    if fault == 'mode': (self.store/'BUSINESS-RAW').chmod(0o644)
                    elif fault in ('symlink', 'hardlink'):
                        (self.store/'BUSINESS-RAW').rename(self.root/'preserved')
                        if fault == 'symlink': (self.store/'BUSINESS-RAW').symlink_to(self.root/'preserved')
                        else: os.link(self.root/'preserved', self.store/'BUSINESS-RAW')
                    elif fault == 'extra': (self.store/'foreign').write_bytes(b'foreign')
                    elif fault in ('global', 'history', 'nonces'):
                        folder, name = {'global': ('.journal', 'WIRE'), 'history': ('.history', 'HISTORY-RAW'), 'nonces': ('.enrollment', 'NONCES')}[fault]
                        (self.locks/(stem+folder)/name).write_bytes(b'foreign')
                    else: (self.store/{'raw': 'BUSINESS-RAW', 'manifest': 'MANIFEST', 'header': 'HEADER', 'marker': 'INITIALIZED'}[fault]).write_bytes(b'foreign')
                    before = {path.name: path.read_bytes() for path in self.store.iterdir()}
                    with self.assertRaises(self.module.HistoryPrereadHold) as caught: self.module.inspect_business_preread(token, binding(), self.identity, self.value)
                    self.assertIsNone(caught.exception.__context__)
                    self.assertEqual(before, {path.name: path.read_bytes() for path in self.store.iterdir()})

    def test_creation_after_unknown_or_revoked_owner_never_backfills_or_changes_bindings(self):
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); self.global_journal.record_global_attempt_intent(token, binding(), self.value)
            with self.assertRaises(self.module.HistoryPrereadHold): self.prepare(token)
            self.assertFalse(self.store.exists())
        with fixture(self.root), self.assertRaises(self.module.HistoryPrereadHold): self.prepare(token)
        with fixture(self.root), self.owner.spreadsheet_owner(replace(binding(), policy_sha256='f'*64)) as fresh:
            with self.assertRaises(self.module.HistoryPrereadHold): self.module.inspect_business_preread(fresh, replace(binding(), policy_sha256='f'*64), self.identity, self.value)
        self.assertFalse(self.store.exists())

    def test_raw_change_during_final_marker_barrier_cannot_return_an_original_observation(self):
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); self.prepare(token)
            real_sync = self.global_journal._sync_initialization
            def change_after_image_decode(parent, folder, header):
                real_sync(parent, folder, header)
                (self.store/'BUSINESS-RAW').write_bytes(b'changed during original observation')
            with mock.patch.object(self.global_journal, '_sync_initialization', side_effect=change_after_image_decode):
                with self.assertRaises(self.module.HistoryPrereadHold):
                    self.module.inspect_business_preread(token, binding(), self.identity, self.value)
            self.assertEqual(b'changed during original observation', (self.store/'BUSINESS-RAW').read_bytes())

    def test_same_bytes_new_inode_during_marker_barrier_is_not_the_original_read_image(self):
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); self.prepare(token)
            original = (self.store/'BUSINESS-RAW').read_bytes(); original_inode = (self.store/'BUSINESS-RAW').stat().st_ino
            real_sync = self.global_journal._sync_initialization
            def replace_after_image_decode(parent, folder, header):
                real_sync(parent, folder, header)
                (self.store/'BUSINESS-RAW').rename(self.root/'preserved-original')
                (self.store/'BUSINESS-RAW').write_bytes(original); (self.store/'BUSINESS-RAW').chmod(0o600)
            with mock.patch.object(self.global_journal, '_sync_initialization', side_effect=replace_after_image_decode):
                with self.assertRaises(self.module.HistoryPrereadHold):
                    self.module.inspect_business_preread(token, binding(), self.identity, self.value)
            self.assertNotEqual(original_inode, (self.store/'BUSINESS-RAW').stat().st_ino)
            self.assertEqual(original, (self.store/'BUSINESS-RAW').read_bytes())

    def test_shared_originals_deduplicate_whole_bytes_but_each_raw_and_aggregate_bounds_fail_closed(self):
        from copy import deepcopy
        self.assertTrue(hasattr(self.module, '_pack_business'), 'bounded original envelope missing')
        packed = self.module._pack_business(tuple(self.reads)); image = json.loads(packed)
        self.assertEqual(4, len(image['images']))
        self.assertEqual(image['operations'][0]['discovery'], image['operations'][1]['discovery'])
        self.assertEqual(image['operations'][0]['occupancy'], image['operations'][1]['occupancy'])
        mutated = deepcopy(self.reads)
        for i, reading in enumerate(mutated):
            for j, role in enumerate(('discovery', 'occupancy', 'row')):
                original = reading[role+'_response']; raw = original.data+b' '*(2*1024*1024-len(original.data)-i*3-j)+b' '*(i*3+j)
                # A different valid-whitespace suffix preserves JSON while
                # making every image distinct; no implementation-derived bound.
                raw = raw[:-1]+(b'\t' if (i*3+j)%2 else b'\n')
                reading[role+'_response'] = type(original)(status=200, complete=True, data=raw)
        # Distinct bodies for shared paths as well, to exercise whole envelope.
        mutated[1]['discovery_response'].data = mutated[1]['discovery_response'].data[:-2]+b'\t\t'
        mutated[1]['occupancy_response'].data = mutated[1]['occupancy_response'].data[:-2]+b'\n\n'
        with self.assertRaises(self.module.HistoryPrereadHold): self.module._pack_business(tuple(mutated))
        oversized = dict(self.reads[0]); original = oversized['row_response']
        oversized['row_response'] = type(original)(status=200, complete=True, data=b' '*(2*1024*1024+1))
        with self.assertRaises(self.module.HistoryPrereadHold): self.module._pack_business((oversized,))


class Req7OriginalBusinessReservedIntentDirectTests(unittest.TestCase):
    setUp = Req7BusinessPrereadJournalDirectTests.setUp
    initialize = Req7BusinessPrereadJournalDirectTests.initialize
    prepare = Req7BusinessPrereadJournalDirectTests.prepare

    def quota(self, token):
        from test_cases.test_req7_metadata_reservation import load as load_quota
        capacity = load_read('issue_tracker_metadata_capacity')
        self.quota_module = load_quota()
        original = self.enrollment.inspect_enrollment_journal(token, binding(), self.identity)
        raw = response({'matchedDeveloperMetadata': [
            {'developerMetadata': {'metadataId': index+1, 'metadataKey': 'http-ztp-enrollment-v1',
                'metadataValue': nonce, 'visibility': 'DOCUMENT',
                'location': {'locationType': 'SHEET', 'sheetId': sid}}}
            for index, (_title, sid, nonce) in enumerate(original.nonces)]})
        target, credential = inputs()
        return self.quota_module.prepare_metadata_reservation(token, binding(), self.identity, self.value,
            capacity.prepare_metadata_capacity_read(target, credential), raw)

    def record(self, token):
        self.assertTrue(hasattr(self.global_journal, 'record_original_business_reserved_attempt_intent'),
            'original complete business images must dominate every counted attempt')
        return self.global_journal.record_original_business_reserved_attempt_intent(token, binding(), self.identity, self.value)

    def test_missing_original_business_holds_before_count_and_all_six_keep_originals(self):
        self.assertTrue(hasattr(self.global_journal, 'record_original_business_reserved_attempt_intent'),
            'original complete business images must dominate every counted attempt')
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); quota = self.quota(token)
            with self.assertRaises(self.global_journal.GlobalAttemptHold): self.record(token)
            self.assertEqual(0, self.global_journal.inspect_global_unit(token, binding(), self.value).attempt_count)
            self.prepare(token); original = {path.name: path.read_bytes() for path in self.store.iterdir()}
            for count in range(1, 7):
                seen = self.record(token)
                self.assertEqual((count, 'UNKNOWN'), (seen.attempt_count, seen.outcome))
                self.assertEqual((2, 1, self.digest), tuple(getattr(self.module.inspect_business_preread(
                    token, binding(), self.identity, self.value), field)
                    for field in ('operations_retained', 'noop_operations', 'preread_sha256')))
                self.assertEqual(quota, self.quota_module.inspect_metadata_reservation(token, binding(), self.identity, self.value))
                self.assertEqual(original, {path.name: path.read_bytes() for path in self.store.iterdir()})
                for name in ('permit', 'send_once', 'complete'): self.assertFalse(hasattr(seen, name))
            with self.assertRaises(self.global_journal.GlobalAttemptHold): self.record(token)
            self.assertEqual(6, self.global_journal.inspect_global_unit(token, binding(), self.value).attempt_count)

    def test_each_business_original_or_partial_marker_holds_without_count_or_repair(self):
        self.assertTrue(hasattr(self.global_journal, 'record_original_business_reserved_attempt_intent'),
            'original complete business images must dominate every counted attempt')
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); self.quota(token); self.prepare(token)
            for name in ('MANIFEST', 'BUSINESS-RAW', 'HEADER', 'INITIALIZED'):
                with self.subTest(name=name):
                    path = self.store/name; saved = path.read_bytes(); path.write_bytes(b'foreign original')
                    try:
                        with self.assertRaises(self.global_journal.GlobalAttemptHold): self.record(token)
                        self.assertEqual(b'foreign original', path.read_bytes())
                        self.assertEqual(0, self.global_journal.inspect_global_unit(token, binding(), self.value).attempt_count)
                    finally: path.write_bytes(saved)

    def test_post_count_business_drift_keeps_unknown_and_never_authorizes_or_repairs(self):
        self.assertTrue(hasattr(self.global_journal, 'record_original_business_reserved_attempt_intent'),
            'original complete business images must dominate every counted attempt')
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); self.quota(token); self.prepare(token)
            original = self.global_journal._observe
            def drift(*args, **kwargs):
                result = original(*args, **kwargs)
                if args[3]: (self.store/'BUSINESS-RAW').write_bytes(b'changed after durable count')
                return result
            with mock.patch.object(self.global_journal, '_observe', side_effect=drift):
                with self.assertRaises(self.global_journal.GlobalAttemptHold): self.record(token)
            self.assertEqual((1, 'UNKNOWN'), tuple(getattr(self.global_journal.inspect_global_unit(
                token, binding(), self.value), field) for field in ('attempt_count', 'outcome')))
            self.assertEqual(b'changed after durable count', (self.store/'BUSINESS-RAW').read_bytes())
            with self.assertRaises(self.global_journal.GlobalAttemptHold): self.record(token)
            self.assertEqual(1, self.global_journal.inspect_global_unit(token, binding(), self.value).attempt_count)


class Req7BusinessSourceProjectionDirectTests(unittest.TestCase):
    setUp = Req7BusinessPrereadJournalDirectTests.setUp
    initialize = Req7BusinessPrereadJournalDirectTests.initialize
    prepare = Req7BusinessPrereadJournalDirectTests.prepare

    def matching_originals(self, token):
        from monitor.issue_tracker_local_workbook import SwitchSourceWorkbookRow
        from monitor.issue_tracker_send_unit import freeze_send_unit
        # Independent literal oracle, not source_tool_values or copied encoder
        # output. Both original NOOP and transmitted L are governed by C8.
        old = '[MONITOR][down][fabric] [fabric_source=type] old'
        new = '[MONITOR][down][fabric] [fabric_source=type] new'
        for reading in self.reads:
            for role in ('discovery', 'occupancy', 'row'):
                original = reading[role+'_response']
                reading[role+'_response'] = type(original)(status=200, complete=True,
                    data=original.data.replace(b'[MONITOR][down][fabric] old', old.encode()))
        image = {'schema_version': 1, 'spreadsheet_id': TARGET, 'sheet': 'ETH&IB Switch',
            'sheet_id': 101, 'history_sheet_id': 105, 'history_path': self.plan.path,
            'history_sha256': hashlib.sha256(self.raw.data).hexdigest(),
            'business': [{'operation_id': reading['operation_id'],
                **{role+'_path': reading[role+'_plan'].path for role in ('discovery', 'occupancy', 'row')},
                **{role+'_sha256': hashlib.sha256(reading[role+'_response'].data).hexdigest()
                   for role in ('discovery', 'occupancy', 'row')}} for reading in self.reads]}
        self.digest = hashlib.sha256((json.dumps(image, ensure_ascii=False, sort_keys=True,
            separators=(',', ':'))+'\n').encode()).hexdigest()
        original = self.enrollment.prepare_enrollment_journal(token, binding(), self.identity)
        nonces = {title: nonce for title, _sid, nonce in original.nonces}
        business = tuple({**item, 'values': {'L': value},
            'observed_values': {'L': {'stringValue': old}}}
            for item, value in zip(self.args['business'], (old, new)))
        self.value = freeze_send_unit(**{**self.args, 'business': business,
            'sheet_id': 101, 'history_sheet_id': 105, 'target_nonce': nonces['ETH&IB Switch'],
            'history_nonce': nonces['Update_History'], 'preread_sha256': self.digest})
        self.global_journal.prepare_global_unit(token, binding(), self.value)
        self.module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
        self.prepare(token)
        return tuple(SwitchSourceWorkbookRow(activity_key=('switch', 'node%04d'%i, 'down', 'fabric'),
            evidence_description=description, fabric='Compute', fabric_source='type', priority='P2',
            recorded_at_utc='2026-10-08T10:00:00Z') for i, description in enumerate(('old', 'new')))

    def test_all_source_values_noop_and_timestamp_match_without_recompiling_unknown(self):
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            rows = self.matching_originals(token)
            originals = {path.name: path.read_bytes() for path in self.store.iterdir()}
            observed = self.module.inspect_business_preread(token, binding(), self.identity, self.value)
            for count in range(7):
                self.assertEqual(observed, self.module.inspect_business_source_projection(
                    token, binding(), self.identity, self.value, rows))
                self.assertEqual((2, 1, self.digest), (observed.operations_retained,
                    observed.noop_operations, observed.preread_sha256))
                self.assertEqual(originals, {path.name: path.read_bytes() for path in self.store.iterdir()})
                if count < 6: self.global_journal.record_global_attempt_intent(token, binding(), self.value)
            self.assertEqual((6, 'UNKNOWN'), tuple(getattr(self.global_journal.inspect_global_unit(
                token, binding(), self.value), field) for field in ('attempt_count', 'outcome')))
            for name in ('permit', 'complete', 'applied'): self.assertFalse(hasattr(observed, name))

    def test_missing_duplicate_untyped_noop_sent_value_or_sent_time_holds_without_count(self):
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            rows = self.matching_originals(token)
            originals = {path.name: path.read_bytes() for path in self.store.iterdir()}
            changed = (None, (), list(rows), rows[:1], rows+(rows[0],), (object(), rows[1]),
                (replace(rows[0], evidence_description='changed NOOP'), rows[1]),
                (rows[0], replace(rows[1], evidence_description='changed transmitted L')),
                (rows[0], replace(rows[1], recorded_at_utc='2026-10-08T10:01:00Z')),
                (rows[0], replace(rows[1], activity_key=('switch', 'foreign', 'down', 'fabric'))))
            for index, candidate in enumerate(changed):
                with self.subTest(case=index), self.assertRaises(self.module.HistoryPrereadHold) as caught:
                    self.module.inspect_business_source_projection(token, binding(), self.identity, self.value, candidate)
                self.assertIsNone(caught.exception.__context__)
                self.assertEqual(0, self.global_journal.inspect_global_unit(token, binding(), self.value).attempt_count)
                self.assertEqual(originals, {path.name: path.read_bytes() for path in self.store.iterdir()})

    def test_structurally_coherent_original_wire_cannot_substitute_for_required_source_values(self):
        from monitor.issue_tracker_local_workbook import SwitchSourceWorkbookRow
        self.assertTrue(hasattr(self.module, 'inspect_business_source_projection'),
            'ALL original decisions must match actual requalified source values')
        source_rows = tuple(SwitchSourceWorkbookRow(activity_key=('switch', 'node%04d'%index, 'down', 'fabric'),
            evidence_description='independently required source', fabric='Compute', fabric_source='type',
            priority='P2', recorded_at_utc='2026-10-08T10:00:00Z') for index in range(2))
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); self.prepare(token)
            # Existing fixture contains one coherent NOOP and one coherent wire
            # but neither literal L matches the independently required source.
            self.assertEqual((2, 1), tuple(getattr(self.module.inspect_business_preread(
                token, binding(), self.identity, self.value), key) for key in ('operations_retained', 'noop_operations')))
            original = {path.name: path.read_bytes() for path in self.store.iterdir()}
            with self.assertRaises(self.module.HistoryPrereadHold):
                self.module.inspect_business_source_projection(token, binding(), self.identity, self.value, source_rows)
            self.assertEqual(0, self.global_journal.inspect_global_unit(token, binding(), self.value).attempt_count)
            self.assertEqual(original, {path.name: path.read_bytes() for path in self.store.iterdir()})


class Req7ReceiptedOriginalIntentDirectTests(unittest.TestCase):
    setUp = Req7BusinessPrereadJournalDirectTests.setUp
    initialize = Req7BusinessPrereadJournalDirectTests.initialize
    prepare = Req7BusinessPrereadJournalDirectTests.prepare
    quota = Req7OriginalBusinessReservedIntentDirectTests.quota

    def test_structural_caller_receipt_or_unheld_writer_never_counts_complete_business(self):
        from types import SimpleNamespace
        self.assertTrue(hasattr(self.global_journal, 'record_receipted_original_attempt_intent'),
            'original protected C6 receipt must dominate counted business intent')
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); self.quota(token); self.prepare(token)
            originals = {path.name: path.read_bytes() for path in self.store.iterdir()}
            for writer in (None, object(), SimpleNamespace(project=self.root, held=True)):
                with self.subTest(writer=type(writer).__name__):
                    with self.assertRaises(self.global_journal.GlobalAttemptHold):
                        self.global_journal.record_receipted_original_attempt_intent(
                            token, binding(), self.identity, self.value,
                            qualified_source=SimpleNamespace(qualified=True, mode='prod-runtime-protected-v1'),
                            store=SimpleNamespace(project_identity=self.root, scope='prod'),
                            writer_token=writer, settings=SimpleNamespace(k=1),
                            whitelist_snapshot=SimpleNamespace(whitelist=SimpleNamespace(sha256='a'*64)),
                            expected_template_sha256='a'*64, http_root=self.root,
                            whitelist_path=self.root/'owned-template.xlsx')
                    self.assertEqual(0, self.global_journal.inspect_global_unit(token, binding(), self.value).attempt_count)
                    self.assertEqual(originals, {path.name: path.read_bytes() for path in self.store.iterdir()})
            self.assertFalse((self.root/'.tracker/generations').exists())


class Req7BusinessPrereadJournalWorkflowTests(unittest.TestCase):
    setUp = Req7BusinessPrereadJournalDirectTests.setUp
    initialize = Req7BusinessPrereadJournalDirectTests.initialize
    prepare = Req7BusinessPrereadJournalDirectTests.prepare
    quota = Req7OriginalBusinessReservedIntentDirectTests.quota

    def test_six_native_cold_processes_count_only_complete_original_business_and_reservations(self):
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); self.quota(token); self.prepare(token)
        original = {path.name: path.read_bytes() for path in self.store.iterdir()}
        code = '''import sys,json,pathlib,hashlib,os
sys.path.insert(0,sys.argv[2]); sys.path.insert(0,str(pathlib.Path(sys.argv[2])/'tools'))
from test_cases.test_req7_spreadsheet_owner import load as load_owner,fixture,binding
from test_cases.test_req7_global_attempt_journal import load as load_global
from test_cases.test_req7_history_preread_journal import load
from test_cases.test_req7_enrollment_journal import load as load_enrollment
from test_cases.test_req7_metadata_reservation import load as load_quota
from monitor.issue_tracker_send_unit import FrozenSendUnit
from monitor.issue_tracker_sheets_read_decode import ObservedTemplateIdentity
owner=load_owner(); global_journal=load_global(); load_enrollment(); load(); load_quota()
root=pathlib.Path(sys.argv[1]); stem=hashlib.sha256(binding().spreadsheet_id.encode()).hexdigest()
parent=root/'var/lib/http-ztp-container/issue-tracker'; folder=parent/(stem+'.journal')
raw=(folder/'ACTION-PREIMAGE').read_bytes(); wire=(folder/'WIRE').read_bytes()
action=json.loads(raw); header=json.loads((folder/'HEADER').read_bytes()); outcomes=tuple(tuple(x) for x in action['outcomes'])
canonical=lambda value:(json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\\n').encode()
unit=FrozenSendUnit(header['unit_id'],wire,header['wire_sha256'],raw,header['action_digest'],outcomes,hashlib.sha256(canonical(action['outcomes'])).hexdigest(),(int(header['unit_id'][:8],16)&0x7fffffff) or 1,len(action['business'])+len(action['audits']),(),'WIRE-CANDIDATE')
quota=json.loads((parent/(stem+'.metadata')/'HEADER').read_bytes())
identity=ObservedTemplateIdentity(binding().spreadsheet_id,tuple(tuple(x) for x in quota['sheet_ids']),quota['identity_sha256'])
with fixture(root),owner.spreadsheet_owner(binding()) as token:
 try: seen=global_journal.record_original_business_reserved_attempt_intent(token,binding(),identity,unit)
 except global_journal.GlobalAttemptHold:
  if global_journal.inspect_global_unit(token,binding(),unit).attempt_count!=6: raise
  os.write(1,b'EXHAUSTED UNKNOWN\\n')
 else: os.write(1,('%d UNKNOWN\\n'%seen.attempt_count).encode())
'''
        for count in range(1, 8):
            result = subprocess.run([sys.executable, '-B', '-c', code, str(self.root), str(ROOT)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(('%d UNKNOWN\n' % count).encode() if count <= 6 else b'EXHAUSTED UNKNOWN\n', result.stdout)
            self.assertEqual(original, {path.name: path.read_bytes() for path in self.store.iterdir()})
        self.assertEqual({'ACTION-PREIMAGE', 'WIRE', 'HEADER', 'INITIALIZED',
            *(f'ATTEMPT-{count}' for count in range(1, 7))}, set(os.listdir(self.locks/(hashlib.sha256(TARGET.encode()).hexdigest()+'.journal'))))

    def test_manifest_maps_original_source_global_nonce_nv_and_business_workflow(self):
        manifest = json.loads((ROOT/'test_cases/script_test_manifest.json').read_text())
        required = {'monitor/issue_tracker_history_preread_journal.py', 'monitor/issue_tracker_send_unit.py',
            'monitor/issue_tracker_global_attempt_journal.py', 'monitor/issue_tracker_enrollment_journal.py',
            'monitor/issue_tracker_nv_reservation.py', 'monitor/issue_tracker_local_workbook_commit.py',
            'monitor/issue_tracker_manifest.py', 'monitor/issue_tracker_receipt_snapshot.py'}
        self.assertTrue(any(required <= set(workflow['members']) and
            {'test_cases.test_req7_history_preread_journal', 'test_cases.test_issue_tracker_stage_l_consumer_workflow'} <= set(workflow['tests'])
            for workflow in manifest['workflows']))
        self.assertIn('prepare_business_preread', (ROOT/'test_cases/README.md').read_text())
        self.assertTrue(any(required | {'monitor/issue_tracker_metadata_reservation.py',
            'monitor/issue_tracker_metadata_capacity.py'} <= set(workflow['members']) and
            workflow['id'] == 'req7_original_business_source_reservations_count'
            for workflow in manifest['workflows']))
        self.assertIn('record_original_business_reserved_attempt_intent', (ROOT/'test_cases/README.md').read_text())
        self.assertTrue(any(workflow['id'] == 'req7_protected_original_receipt_business_count' and
            required | {'monitor/issue_tracker_admission.py', 'monitor/issue_tracker_cycle_source.py',
                        'monitor/issue_tracker_stage_l_consumer.py', 'monitor/issue_tracker_state_owner.py',
                        'monitor/issue_tracker_local_workbook.py', 'monitor/issue_tracker_online_cells.py'} <= set(workflow['members'])
            for workflow in manifest['workflows']))
        self.assertIn('record_receipted_original_attempt_intent', (ROOT/'test_cases/README.md').read_text())
        self.assertIn('inspect_business_source_projection', (ROOT/'test_cases/README.md').read_text())

    def test_native_cold_process_reopens_exact_original_all_operations_after_unknown(self):
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); self.prepare(token); self.global_journal.record_global_attempt_intent(token, binding(), self.value)
        code = '''import sys,json,pathlib,hashlib,os
sys.path.insert(0,sys.argv[2]); sys.path.insert(0,str(pathlib.Path(sys.argv[2])/'tools'))
from test_cases.test_req7_spreadsheet_owner import load as load_owner,fixture,binding
from test_cases.test_req7_history_preread_journal import load
from monitor.issue_tracker_send_unit import FrozenSendUnit
from monitor.issue_tracker_sheets_read_decode import ObservedTemplateIdentity
owner=load_owner(); module=load(); root=pathlib.Path(sys.argv[1]); stem=hashlib.sha256(binding().spreadsheet_id.encode()).hexdigest()
folder=root/'var/lib/http-ztp-container/issue-tracker'/(stem+'.journal'); raw=(folder/'ACTION-PREIMAGE').read_bytes(); wire=(folder/'WIRE').read_bytes()
action=json.loads(raw); header=json.loads((folder/'HEADER').read_bytes()); outcomes=tuple(tuple(x) for x in action['outcomes'])
canonical=lambda value:(json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\\n').encode()
unit=FrozenSendUnit(header['unit_id'],wire,header['wire_sha256'],raw,header['action_digest'],outcomes,hashlib.sha256(canonical(action['outcomes'])).hexdigest(),(int(header['unit_id'][:8],16)&0x7fffffff) or 1,len(action['business'])+len(action['audits']),(),'WIRE-CANDIDATE')
identity=ObservedTemplateIdentity(binding().spreadsheet_id,tuple(tuple(x) for x in json.loads(sys.argv[3])),'a'*64)
with fixture(root),owner.spreadsheet_owner(binding()) as token:
 seen=module.inspect_business_preread(token,binding(),identity,unit)
 os.write(1,('%d %d %s\\n'%(seen.operations_retained,seen.noop_operations,seen.preread_sha256)).encode())
'''
        result = subprocess.run([sys.executable, '-B', '-c', code, str(self.root), str(ROOT), json.dumps(self.identity.sheet_ids)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(('2 1 '+self.digest+'\n').encode(), result.stdout)


class Req7HistoryPrereadJournalWorkflowTests(unittest.TestCase):
    setUp = Req7HistoryPrereadJournalDirectTests.setUp

    def test_actual_native_cold_process_redecodes_immutable_before_tail_after_unknown_intent(self):
        module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.global_journal.prepare_global_unit(token, binding(), self.value)
            module.prepare_history_preread(token, binding(), self.value, self.plan, self.raw)
            self.global_journal.record_global_attempt_intent(token, binding(), self.value)
        command = [sys.executable, '-B', str(Path(__file__).resolve()), '--owned-inspect', str(self.root), str(ROOT)]
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr); self.assertEqual(b'3 7\n', result.stdout)
        self.assertEqual(self.raw.data, (self.store / 'HISTORY-RAW').read_bytes())

    def test_manifest_binds_actual_native_and_durable_dependencies_and_not_run_card(self):
        manifest = json.loads((ROOT / 'test_cases/script_test_manifest.json').read_text())
        source = 'monitor/issue_tracker_history_preread_journal.py'; test = 'test_cases.test_req7_history_preread_journal'
        self.assertEqual(source, manifest['scripts'].get(source))
        self.assertTrue(any(source in rule['paths'] and test in rule['tests'] for rule in manifest['test_rules']))
        dependencies = {source, 'monitor/issue_tracker_global_attempt_journal.py', 'monitor/issue_tracker_spreadsheet_owner.py',
                        'monitor/issue_tracker_sheets_read_plan.py', 'monitor/issue_tracker_sheets_read_decode.py', 'monitor/issue_tracker_tls_inputs.py'}
        self.assertTrue(any(dependencies <= set(rule['members']) and test in rule['tests'] for rule in manifest['workflows']))
        self.assertEqual(['issue-tracker-local'], [suite['id'] for suite in manifest['test_suites'] if test in suite['tests']])
        self.assertIn(test, (ROOT / 'test_cases/README.md').read_text())
        cards = (ROOT / 'test_cases/REAL_ENVIRONMENT.md').read_text(); start = cards.index('## TC-REAL-REQ7-HISTORY-PREREAD-JOURNAL-001')
        end = cards.find('\n## ', start + 1); card = cards[start:] if end == -1 else cards[start:end]
        for term in ('NOT RUN / REAL_ENV REQUIRED', '前置条件', 'Stage O', '证据', 'stat/inode', '清理', '不是 COMPLETE'):
            self.assertIn(term, card)


class Req7HistoryPrereadNativeWorkflowTests(unittest.TestCase):
    from test_cases.test_req7_history_read import Req7HistoryReadNativeWorkflowTests as _Fixture
    fixture = _Fixture.fixture; certificates = _Fixture.certificates; server = _Fixture.server

    def setUp(self):
        Req7HistoryPrereadJournalDirectTests.setUp(self)
        self.journal_root = self.root
        self._Fixture.setUp(self)
        target, token = inputs(); self.plan = self.planner.prepare_history_tail_read(target, token)

    def test_native_complete_tail_then_actual_owner_durable_image_then_unknown_does_not_replace_before(self):
        module = load(); target, token_value = inputs()
        payload = self.raw.data
        wire = ('HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(payload)).encode() + payload
        unit_read = self.tls.NativeHistoryTailReadUnit(target, token_value)
        self.assertEqual(self.root, self.path.parents[3], 'CA fixture must retain its own actual root')
        # Native network fixture and synthetic global-root fixture deliberately
        # do not overlap: TLS/CA file validation retains real UID/path semantics.
        with self.server(wire, hostname='sheets.googleapis.com', destination='sheets.googleapis.com') as (records, errors), self.fixture():
            raw = unit_read.send_once()
        self.assertEqual([], errors); self.assertEqual(1, len(records))
        with fixture(self.journal_root), self.owner.spreadsheet_owner(binding()) as token:
            self.global_journal.prepare_global_unit(token, binding(), self.value)
            module.prepare_history_preread(token, binding(), self.value, self.plan, raw)
            reserved = module.require_history_append_capacity(token, binding(), self.value)
            self.assertEqual((4, 5, 2, 1), (reserved.first_row_index, reserved.last_row_index, reserved.rows_reserved, reserved.remaining_rows))
            self.global_journal.record_global_attempt_intent(token, binding(), self.value)
            seen = module.inspect_history_preread(token, binding(), self.value)
            self.assertEqual((3, 7), (seen.history_last_row_before_send, seen.row_count))
            self.assertEqual(reserved, module.require_history_append_capacity(token, binding(), self.value))
            later = tail_document(); later['sheets'][0]['data'][0]['rowData'].append({'values': [{'userEnteredValue': {'stringValue': 'later'}}]})
            with self.assertRaises(module.HistoryPrereadHold): module.prepare_history_preread(token, binding(), self.value, self.plan, response(later))
            self.assertEqual(payload, (self.store / 'HISTORY-RAW').read_bytes())


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--owned-inspect':
        owner = load_owner(); module = load()
        with fixture(Path(sys.argv[2])), owner.spreadsheet_owner(binding()) as token:
            seen = module.inspect_history_preread(token, binding(), unit())
            reserved = module.require_history_append_capacity(token, binding(), unit())
            if (reserved.first_row_index, reserved.last_row_index, reserved.rows_reserved, reserved.remaining_rows) != (4, 5, 2, 1):
                raise AssertionError('original cold-process append reservation changed')
            os.write(1, ('%d %d\n' % (seen.history_last_row_before_send, seen.row_count)).encode())
    else: unittest.main()
