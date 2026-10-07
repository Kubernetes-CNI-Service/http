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


class Req7NvReservationWorkflowTests(unittest.TestCase):
    setUp = Req7NvReservationDirectTests.setUp
    initialize = Req7NvReservationDirectTests.initialize
    reserve = Req7NvReservationDirectTests.reserve
    inspect = Req7NvReservationDirectTests.inspect

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
            'monitor/issue_tracker_sheets_read_decode.py', 'monitor/issue_tracker_sheets_read_plan.py', 'monitor/issue_tracker_tls_inputs.py'}
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
            self.initialize(token); seen = self.reserve(token)
            self.assertEqual(((KEYS[0], 'NV30102'), (KEYS[1], 'NV30103')), seen.reservations)
            self.assertEqual(seen, self.inspect(token))
        self.assertEqual(tuple(raw.data for raw in originals), tuple(raw.data for raw in replies))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--owned-inspect':
        case = Req7NvReservationDirectTests(); case.setUp(); case.module = load()
        with fixture(Path(sys.argv[2])), case.owner.spreadsheet_owner(binding()) as token:
            seen = case.inspect(token)
        print(' '.join(value for key, value in seen.reservations)); case.doCleanups()
    else: unittest.main()
