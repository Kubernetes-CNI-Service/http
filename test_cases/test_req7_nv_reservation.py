"""Independent C17 durable shared sequence, not an online mutation permit."""
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
from types import SimpleNamespace

if len(sys.argv) > 1 and sys.argv[1] == '--owned-inspect':
    sys.path.insert(0, sys.argv[3]); sys.path.insert(0, str(Path(sys.argv[3]) / 'tools'))
from test_cases import test_req7_enrollment_journal as enrollment_tests
from test_cases.test_req7_spreadsheet_owner import fixture, binding, TARGET
from test_cases.test_req7_activity_discovery import sheet_document, cabling_row, literal
from test_cases import test_req7_sheets_read_decode as grids

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'monitor/issue_tracker_nv_reservation.py'
KEYS = (('eth_cabling', 'switch-1', 'swp3', 'Link Down'), ('eth_cabling', 'switch-1', 'swp4', 'Mis-wiring'))


def load():
    if not SOURCE.is_file(): raise AssertionError('C17 durable two-Cabling NV reservation missing')
    spec = importlib.util.spec_from_file_location('monitor.issue_tracker_nv_reservation', SOURCE)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module); return module


def source(sheet, identifiers):
    rows = []
    for index, identifier in enumerate(identifiers):
        row = cabling_row(identifier, 'Closed'); row['K'] = literal('unrelated-%d' % index); rows.append(row)
    item = sheet_document(sheet, rows)
    item['spreadsheetId'] = TARGET
    item['sheets'][0]['properties']['sheetId'] = 102 if sheet == 'ETH Cabling' else 103
    return grids.response(item)


def cabling_inputs(nonces, *, identifiers=('NV30102', 'NV30103')):
    from test_cases.test_req7_send_unit import inputs
    args = inputs(); operations = []; business = []
    for index, (key, identifier) in enumerate(zip(KEYS, identifiers)):
        operation_id = 'eth_cabling:%04d' % index
        operations.append({'operation_id': operation_id, 'activity_key': list(key), 'action': 'upsert'})
        values = {letter: '' for letter in ('A', 'B', 'C', 'D', 'E', 'F', 'G', 'K', 'L', 'M', 'N', 'Q', 'R', 'S', 'T', 'U')}
        values.update(A=identifier, E='ETH', F=key[3], G='literal evidence', K=key[1], L=key[2], U='New')
        business.append({'operation_id': operation_id, 'action': 'insert', 'row_index': None, 'values': values,
            'observed_values': None, 'recorded_at_utc': '2026-10-08T10:00:00Z'})
    manifest = (json.dumps({'schema_version': 1, 'operations': operations}, sort_keys=True, separators=(',', ':')) + '\n').encode()
    original = {title: (sid, nonce) for title, sid, nonce in nonces}
    args.update(manifest=manifest, manifest_id=hashlib.sha256(manifest).hexdigest(), generation_id='c' * 64,
        publish_id='d' * 64, sheet='ETH Cabling', sheet_id=102, history_sheet_id=105,
        target_nonce=original['ETH Cabling'][1], history_nonce=original['Update_History'][1], business=tuple(business))
    return args


class Req7NvReservationDirectTests(unittest.TestCase):
    def setUp(self):
        enrollment_tests.Req7EnrollmentJournalDirectTests.setUp(self)
        self.enrollment = self.module; self.module = None
        self.store = self.state / (hashlib.sha256(TARGET.encode()).hexdigest() + '.nv')
        read_binding = replace(self.binding, spreadsheet_id=TARGET)
        self.eth_plan = self.planner.prepare_activity_sheet_read(read_binding, self.token, sheet='ETH Cabling')
        self.ib_plan = self.planner.prepare_activity_sheet_read(read_binding, self.token, sheet='IB Cabling')
        self.eth = source('ETH Cabling', ('NV30016',))
        self.ib = source('IB Cabling', ('NV30101',))
        self.identity = self.decoder.decode_template_identity(
            self.planner.prepare_template_identity_read(read_binding, self.token),
            grids.response({**grids.identity_response(), 'spreadsheetId': TARGET}))
        self.kw = dict(generation_id='c' * 64, publish_id='d' * 64, sheet='ETH Cabling', requested_keys=KEYS)

    def initialize(self, token): return self.enrollment.prepare_enrollment_journal(token, binding(), self.identity)
    def reserve(self, token, **changes):
        args = dict(self.kw); args.update(changes)
        return self.module.prepare_nv_reservation(token, binding(), self.identity,
            self.eth_plan, self.eth, self.ib_plan, self.ib, **args)
    def inspect(self, token, **changes):
        args = dict(self.kw); args.update(changes)
        return self.module.inspect_nv_reservation(token, binding(), self.identity, **args)

    def test_two_original_columns_closed_and_unrelated_seed_next_ids_without_rewriting_rows(self):
        self.module = load()
        before = (self.eth.data, self.ib.data)
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); seen = self.reserve(token)
            self.assertEqual(((KEYS[0], 'NV30102'), (KEYS[1], 'NV30103')), seen.reservations)
            self.assertEqual(seen, self.inspect(token))
            with self.assertRaises(self.module.NvReservationHold): self.reserve(token)
        self.assertEqual(before, (self.eth.data, self.ib.data))
        self.assertEqual({'ETH-RAW', 'IB-RAW', 'HEADER', 'RESERVATIONS', 'INITIALIZED'}, set(os.listdir(self.store)))
        for private in ('switch-1', 'NV30102'): self.assertNotIn(private, repr(seen))
        for authority in ('permit', 'complete', 'applied', 'send_once'): self.assertFalse(hasattr(seen, authority))

    def test_both_fixed_capacity_responses_retain_full_two_mib_and_reject_overflow_before_store(self):
        self.module = load()
        eth = self.eth.data + b' ' * (2 * 1024 * 1024 - len(self.eth.data))
        ib = self.ib.data + b' ' * (2 * 1024 * 1024 - len(self.ib.data))
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token)
            self.eth = SimpleNamespace(status=200, complete=True, data=eth + b' ')
            with self.assertRaises(self.module.NvReservationHold): self.reserve(token)
            self.assertFalse(self.store.exists())
            self.eth = SimpleNamespace(status=200, complete=True, data=eth)
            self.ib = SimpleNamespace(status=200, complete=True, data=ib)
            seen = self.reserve(token); self.assertEqual(seen, self.inspect(token))
            self.assertEqual(((KEYS[0], 'NV30102'), (KEYS[1], 'NV30103')), seen.reservations)
        self.assertEqual(eth, (self.store / 'ETH-RAW').read_bytes()); self.assertEqual(ib, (self.store / 'IB-RAW').read_bytes())

    def test_seed_is_observed_not_hardcoded_and_cross_family_max_never_reused(self):
        self.module = load(); self.eth = source('ETH Cabling', ('NV00008',)); self.ib = source('IB Cabling', ())
        self.kw.update(sheet='IB Cabling', requested_keys=(('ib_cabling', 'switch-2', 'p1', 'Link Down'),))
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); seen = self.reserve(token)
            self.assertEqual(((('ib_cabling', 'switch-2', 'p1', 'Link Down'), 'NV00009'),), seen.reservations)

    def test_unknown_global_unit_blocks_new_allocation_but_existing_reservation_survives_unchanged(self):
        self.module = load()
        from test_cases.test_req7_global_attempt_journal import load as global_load, unit
        global_journal = global_load(); value = unit()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); first = self.reserve(token)
            global_journal.prepare_global_unit(token, binding(), value)
            global_journal.record_global_attempt_intent(token, binding(), value)
            self.assertEqual(first, self.inspect(token))
            image = {p.name: p.read_bytes() for p in self.store.iterdir()}
            for changed in ({'publish_id': 'f' * 64}, {'generation_id': 'f' * 64},
                            {'sheet': 'IB Cabling', 'requested_keys': (('ib_cabling', 'other', 'p1', 'Link Down'),)}):
                with self.assertRaises(self.module.NvReservationHold): self.inspect(token, **changed)
            self.assertEqual(image, {p.name: p.read_bytes() for p in self.store.iterdir()})
        with tempfile.TemporaryDirectory(prefix='req7-nv-global-block-') as directory:
            root = Path(directory).resolve(); state = root / 'var/lib/http-ztp-container/issue-tracker'; state.mkdir(parents=True, mode=0o700)
            with fixture(root), self.owner.spreadsheet_owner(binding()) as token:
                self.initialize(token); global_journal.prepare_global_unit(token, binding(), value)
                with self.assertRaises(self.module.NvReservationHold): self.reserve(token)
                self.assertFalse((state / self.store.name).exists())

    def test_no_enrollment_partial_reads_cross_duplicate_ids_and_exhaustion_do_not_create_store(self):
        self.module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            with self.assertRaises(self.module.NvReservationHold): self.reserve(token)
            self.initialize(token)
            variants = ((source('ETH Cabling', ()), source('IB Cabling', ())),
                        (source('ETH Cabling', ('NV99999',)), self.ib),
                        (source('ETH Cabling', ('NV99998',)), self.ib),
                        (source('ETH Cabling', ('NV30101',)), self.ib),
                        (SimpleNamespace(status=200, complete=False, data=self.eth.data), self.ib))
            for eth, ib in variants:
                self.eth, self.ib = eth, ib
                with self.assertRaises(self.module.NvReservationHold) as caught: self.reserve(token)
                self.assertIsNone(caught.exception.__context__); self.assertFalse(self.store.exists())

    def test_fixed_original_targets_keys_and_unit_encoding_not_caller_sequence_or_identity_alias(self):
        self.module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token)
            for options in ({'generation_id': True}, {'publish_id': 'bad'}, {'sheet': 'ETH&IB Switch'},
                            {'requested_keys': ()}, {'requested_keys': (KEYS[0], KEYS[0])},
                            {'requested_keys': (('ib_cabling', 'switch-1', 'p1', 'Link Down'),)}):
                with self.assertRaises(self.module.NvReservationHold): self.reserve(token, **options)
                self.assertFalse(self.store.exists())
            old = self.eth_plan
            for plan in (self.ib_plan, replace(old, path=old.path.replace('5002', '7')),
                         replace(old, path=old.path.replace(TARGET, 'foreign_spreadsheet_0002'))):
                self.eth_plan = plan
                with self.assertRaises(self.module.NvReservationHold): self.reserve(token)
                self.assertFalse(self.store.exists())
            self.eth_plan = old; seen = self.reserve(token)
            canonical_identity = {'schema_version': 1, 'generation_id': 'c' * 64, 'publish_id': 'd' * 64,
                'spreadsheet_id': TARGET, 'sheet': 'ETH Cabling', 'sheet_id': 102}
            raw = (json.dumps(canonical_identity, sort_keys=True, separators=(',', ':')) + '\n').encode()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), seen.unit_id)
            self.assertEqual(seen, self.inspect(token, requested_keys=tuple(reversed(KEYS))))
            self.assertNotIn(b'sentinel.private-token', (self.store / 'HEADER').read_bytes())

    def test_all_ten_image_barriers_precede_marker_partial_store_never_adopted(self):
        self.module = load(); real = os.fsync
        for boundary in range(1, 11):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory(prefix='req7-nv-barrier-') as directory:
                root = Path(directory).resolve(); state = root / 'var/lib/http-ztp-container/issue-tracker'; state.mkdir(parents=True, mode=0o700)
                store = state / self.store.name
                with fixture(root), self.owner.spreadsheet_owner(binding()) as token:
                    self.initialize(token); calls = []
                    def failing(fd):
                        if store.exists():
                            calls.append(fd)
                            if len(calls) == boundary: raise OSError('private barrier sentinel')
                        return real(fd)
                    with mock.patch('os.fsync', side_effect=failing), self.assertRaises(self.module.NvReservationHold): self.reserve(token)
                    self.assertTrue(store.is_dir()); self.assertFalse((store / 'INITIALIZED').exists())
                    with self.assertRaises(self.module.NvReservationHold): self.inspect(token)
                    with self.assertRaises(self.module.NvReservationHold): self.reserve(token)
                    self.assertFalse((store / 'INITIALIZED').exists())

    def test_original_binding_identity_raw_and_private_names_must_still_match(self):
        self.module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); self.reserve(token)
            image = {p.name: p.read_bytes() for p in self.store.iterdir()}
            for name in ('ETH-RAW', 'IB-RAW', 'HEADER', 'RESERVATIONS', 'INITIALIZED'):
                (self.store / name).write_bytes(b'private tamper')
                with self.assertRaises(self.module.NvReservationHold): self.inspect(token)
                (self.store / name).write_bytes(image[name])
            changed = replace(self.identity, sheet_ids=tuple((title, 999 if title == 'ETH Cabling' else sid) for title, sid in self.identity.sheet_ids))
            with self.assertRaises(self.module.NvReservationHold):
                self.module.inspect_nv_reservation(token, binding(), changed, **self.kw)
            (self.store / 'RESERVATIONS').chmod(0o644)
            with self.assertRaises(self.module.NvReservationHold): self.inspect(token)
            (self.store / 'RESERVATIONS').chmod(0o600)
        with fixture(self.root), self.assertRaises(self.module.NvReservationHold): self.inspect(token)

    def test_actual_compiled_insert_unit_must_use_every_original_reserved_id_and_nonce(self):
        self.module = load()
        self.assertTrue(hasattr(self.module, 'require_unit_nv_reservation'), 'durable NV-to-actual-batch binding missing')
        from monitor.issue_tracker_send_unit import freeze_send_unit
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            original = self.initialize(token); expected = self.reserve(token)
            args = cabling_inputs(original.nonces); unit = freeze_send_unit(**args)
            observed = self.module.require_unit_nv_reservation(token, binding(), self.identity, unit)
            self.assertEqual(expected, observed); self.assertEqual(unit.unit_id, observed.unit_id)
            for identifiers in (('NV30104', 'NV30103'), ('NV30102', 'NV30102'), ('NV30016', 'NV30103')):
                with self.assertRaises(self.module.NvReservationHold):
                    self.module.require_unit_nv_reservation(token, binding(), self.identity,
                        freeze_send_unit(**cabling_inputs(original.nonces, identifiers=identifiers)))
            for changes in ({'publish_id': 'f' * 64}, {'generation_id': 'f' * 64}, {'target_nonce': 'f' * 64},
                            {'history_nonce': 'f' * 64}, {'sheet_id': 103}, {'history_sheet_id': 104}):
                altered = dict(args); altered.update(changes)
                with self.assertRaises(self.module.NvReservationHold):
                    self.module.require_unit_nv_reservation(token, binding(), self.identity, freeze_send_unit(**altered))
            before = {path.name: path.read_bytes() for path in self.store.iterdir()}
            altered = dict(args); altered['business'] = args['business'][:1]
            document = json.loads(args['manifest']); document['operations'] = document['operations'][:1]
            altered['manifest'] = (json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n').encode()
            altered['manifest_id'] = hashlib.sha256(altered['manifest']).hexdigest()
            with self.assertRaises(self.module.NvReservationHold):
                self.module.require_unit_nv_reservation(token, binding(), self.identity, freeze_send_unit(**altered))
            self.assertEqual(before, {path.name: path.read_bytes() for path in self.store.iterdir()})

    def test_coherent_compiler_cannot_attach_foreign_activity_key_to_reserved_literal_id(self):
        self.module = load()
        self.assertTrue(hasattr(self.module, 'require_unit_nv_reservation'), 'durable NV-to-actual-batch binding missing')
        from monitor.issue_tracker_send_unit import freeze_send_unit
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            original = self.initialize(token); self.reserve(token); args = cabling_inputs(original.nonces)
            args['business'][0]['values']['K'] = 'foreign-node'
            with self.assertRaises(self.module.NvReservationHold):
                self.module.require_unit_nv_reservation(token, binding(), self.identity, freeze_send_unit(**args))
        with fixture(self.root), self.assertRaises(self.module.NvReservationHold):
            self.module.require_unit_nv_reservation(token, binding(), self.identity, freeze_send_unit(**args))

    def test_mixed_literal_updates_do_not_consume_ids_or_write_existing_a_column(self):
        self.module = load()
        from monitor.issue_tracker_send_unit import freeze_send_unit
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            original = self.initialize(token); expected = self.reserve(token); args = cabling_inputs(original.nonces)
            document = json.loads(args['manifest'])
            document['operations'].append({'operation_id': 'eth_cabling:existing',
                'activity_key': ['eth_cabling', 'switch-1', 'swp9', 'Link Down'], 'action': 'upsert'})
            args['manifest'] = (json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n').encode()
            args['manifest_id'] = hashlib.sha256(args['manifest']).hexdigest()
            update = {'operation_id': 'eth_cabling:existing', 'action': 'update', 'row_index': 3,
                'values': {'G': 'new evidence', 'M': 'a', 'N': 'b', 'S': 'c', 'T': 'd'},
                'observed_values': {column: {} for column in ('G', 'M', 'N', 'S', 'T')},
                'recorded_at_utc': '2026-10-08T10:00:00Z'}
            args['business'] += (update,); unit = freeze_send_unit(**args)
            self.assertEqual(expected, self.module.require_unit_nv_reservation(token, binding(), self.identity, unit))
            image = json.loads(unit.action_preimage)['business'][-1]['requests']
            self.assertEqual([6, 12, 18], [item['updateCells']['start']['columnIndex'] for item in image])
            self.assertEqual(((KEYS[0], 'NV30102'), (KEYS[1], 'NV30103')), expected.reservations)


class Req7NvReservationWorkflowTests(unittest.TestCase):
    setUp = Req7NvReservationDirectTests.setUp
    initialize = Req7NvReservationDirectTests.initialize
    reserve = Req7NvReservationDirectTests.reserve
    inspect = Req7NvReservationDirectTests.inspect

    def test_actual_reserved_unit_global_journal_and_unknown_retry_use_identical_original_ids(self):
        from test_cases.test_req7_global_attempt_journal import load as global_load
        from monitor.issue_tracker_send_unit import freeze_send_unit
        global_journal = global_load()
        self.module = load()
        self.assertTrue(hasattr(self.module, 'require_unit_nv_reservation'), 'durable NV-to-actual-batch binding missing')
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            original = self.initialize(token); first = self.reserve(token)
            unit = freeze_send_unit(**cabling_inputs(original.nonces))
            self.assertEqual(first, self.module.require_unit_nv_reservation(token, binding(), self.identity, unit))
            global_journal.prepare_global_unit(token, binding(), unit)
            global_journal.record_global_attempt_intent(token, binding(), unit)
            self.assertEqual(first, self.module.require_unit_nv_reservation(token, binding(), self.identity, unit))
            altered = cabling_inputs(original.nonces); altered['business'][0]['values']['G'] = 'changed frozen evidence'
            with self.assertRaises(self.module.NvReservationHold):
                self.module.require_unit_nv_reservation(token, binding(), self.identity, freeze_send_unit(**altered))
            self.assertEqual(1, global_journal.inspect_global_unit(token, binding(), unit).attempt_count)
            self.assertEqual(unit.wire_bytes, (self.state / (hashlib.sha256(TARGET.encode()).hexdigest() + '.journal') / 'WIRE').read_bytes())

    def test_native_cold_process_redecodes_both_original_columns_and_keeps_ids_after_unknown(self):
        self.module = load()
        from test_cases.test_req7_global_attempt_journal import load as global_load, unit
        global_journal = global_load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); seen = self.reserve(token)
            value = unit(); global_journal.prepare_global_unit(token, binding(), value)
            global_journal.record_global_attempt_intent(token, binding(), value)
        command = [sys.executable, '-B', str(Path(__file__).resolve()), '--owned-inspect', str(self.root), str(ROOT)]
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr); self.assertEqual(b'NV30102 NV30103\n', result.stdout)
        self.assertEqual(self.eth.data, (self.store / 'ETH-RAW').read_bytes())
        self.assertEqual(self.ib.data, (self.store / 'IB-RAW').read_bytes())

    def test_manifest_real_multi_script_workflow_primary_suite_and_not_run_card(self):
        manifest = json.loads((ROOT / 'test_cases/script_test_manifest.json').read_text())
        script = 'monitor/issue_tracker_nv_reservation.py'; test = 'test_cases.test_req7_nv_reservation'
        self.assertEqual(script, manifest['scripts'].get(script))
        self.assertTrue(any(script in item['paths'] and test in item['tests'] for item in manifest['test_rules']))
        members = {script, 'monitor/issue_tracker_online_nv_ids.py', 'monitor/issue_tracker_enrollment_journal.py',
            'monitor/issue_tracker_global_attempt_journal.py', 'monitor/issue_tracker_spreadsheet_owner.py',
            'monitor/issue_tracker_sheets_read_decode.py', 'monitor/issue_tracker_sheets_read_plan.py', 'monitor/issue_tracker_tls_inputs.py',
            'monitor/issue_tracker_send_unit.py', 'monitor/issue_tracker_send_intent.py', 'monitor/issue_tracker_online_cells.py'}
        self.assertTrue(any(members <= set(item['members']) and test in item['tests'] for item in manifest['workflows']))
        self.assertEqual(['issue-tracker-local'], [item['id'] for item in manifest['test_suites'] if test in item['tests']])
        self.assertIn(test, (ROOT / 'test_cases/README.md').read_text())
        cards = (ROOT / 'test_cases/REAL_ENVIRONMENT.md').read_text(); start = cards.index('## TC-REAL-REQ7-NV-RESERVATION-001')
        end = cards.find('\n## ', start + 1); card = cards[start:] if end == -1 else cards[start:end]
        for term in ('NOT RUN / REAL_ENV REQUIRED', script, '前置条件', 'stat/inode', '证据', '清理', '不是 COMPLETE'):
            self.assertIn(term, card)


class Req7NvReservationNativeWorkflowTests(unittest.TestCase):
    from test_cases.test_req7_sheets_read_plan import Req7SheetsNativeReadWorkflowTests as _Fixture
    fixture = _Fixture.fixture; certificates = _Fixture.certificates; server = _Fixture.server
    initialize = Req7NvReservationDirectTests.initialize
    reserve = Req7NvReservationDirectTests.reserve
    inspect = Req7NvReservationDirectTests.inspect

    def setUp(self):
        Req7NvReservationDirectTests.setUp(self); self.journal_root = self.root
        self._Fixture.setUp(self); self.tls = self.module

    def test_two_actual_native_fixed_reads_then_owner_enrollment_and_immutable_reservation(self):
        self.module = load()
        target = replace(self.binding, spreadsheet_id=TARGET)
        originals = (self.eth, self.ib); replies = []
        for sheet, original in zip(('ETH Cabling', 'IB Cabling'), originals):
            unit = self.tls.NativeActivitySheetReadUnit(target, self.token, sheet=sheet)
            payload = original.data
            wire = ('HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(payload)).encode() + payload
            with self.server(wire, hostname='sheets.googleapis.com', destination='sheets.googleapis.com') as (records, errors), self.fixture():
                replies.append(unit.send_once())
                with self.assertRaises(self.tls.TlsInputHold): unit.send_once()
            self.assertEqual([], errors); self.assertEqual(1, len(records)); self.assertEqual(b'', records[0][2])
            self.assertIn(('GET ' + (self.eth_plan if sheet == 'ETH Cabling' else self.ib_plan).path + ' HTTP/1.1').encode(), records[0][0])
        self.eth, self.ib = replies
        with fixture(self.journal_root), self.owner.spreadsheet_owner(binding()) as token:
            original = self.initialize(token); seen = self.reserve(token)
            self.assertEqual(((KEYS[0], 'NV30102'), (KEYS[1], 'NV30103')), seen.reservations)
            self.assertEqual(seen, self.inspect(token))
            from monitor.issue_tracker_send_unit import freeze_send_unit
            compiled = freeze_send_unit(**cabling_inputs(original.nonces))
            self.assertEqual(seen, self.module.require_unit_nv_reservation(token, binding(), self.identity, compiled))
        self.assertEqual(tuple(raw.data for raw in originals), tuple(raw.data for raw in replies))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--owned-inspect':
        case = Req7NvReservationDirectTests(); case.setUp(); case.module = load()
        with fixture(Path(sys.argv[2])), case.owner.spreadsheet_owner(binding()) as token:
            seen = case.inspect(token)
        print(' '.join(value for key, value in seen.reservations)); case.doCleanups()
    else: unittest.main()
