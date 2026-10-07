"""Actual original nonces/global unit plus durable G1 budget, not admission."""
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
from test_cases import test_req7_remote_history_match as matching
from test_cases.test_req7_spreadsheet_owner import fixture, binding, TARGET
from test_cases.test_req7_history_read import response

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'monitor/issue_tracker_metadata_reservation.py'


def load():
    if not SOURCE.is_file(): raise AssertionError('durable actual-unit G1 metadata reservation missing')
    spec = importlib.util.spec_from_file_location('monitor.issue_tracker_metadata_reservation', SOURCE)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module); return module


class Req7MetadataReservationDirectTests(unittest.TestCase):
    def setUp(self):
        matching.Req7RemoteHistoryMatchDirectTests.setUp(self)
        self.store = self.state / (hashlib.sha256(TARGET.encode()).hexdigest() + '.metadata')
        self.raw = response({'matchedDeveloperMetadata': self.metadata['matchedDeveloperMetadata'][:2]})

    def initialize(self, token): matching.Req7RemoteHistoryMatchDirectTests.prepare(self, token, attempt=False)
    def reserve(self, token, *, plan=None, raw=None, unit=None):
        return self.module.prepare_metadata_reservation(token, binding(), self.identity, unit or self.unit,
            plan or self.meta_plan, raw or self.raw)
    def inspect(self, token, **changes):
        return self.module.inspect_metadata_reservation(token, binding(), self.identity, changes.get('unit', self.unit))

    def test_real_nonce_pools_and_actual_permanent_fence_use_exact_budget_not_caller_reservation(self):
        self.module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); seen = self.reserve(token)
            self.assertEqual('VISIBLE_ONLY_UNPROVED', seen.outcome); self.assertIs(False, seen.inventory_complete)
            self.assertEqual(1, seen.outstanding_reservations)
            self.assertEqual((101, 86, 2, 29912), next(row for row in seen.pools if row[0] == 101))
            self.assertEqual((105, 86, 0, 29914), next(row for row in seen.pools if row[0] == 105))
            self.assertEqual((None, 0, 0, 30000), seen.pools[0])
            self.assertEqual(self.unit.fence_metadata_id, seen.fence_metadata_id)
            self.assertEqual(seen, self.inspect(token))
            with self.assertRaises(self.module.MetadataReservationHold): self.reserve(token)
            with self.assertRaises(TypeError): self.module.prepare_metadata_reservation(token, binding(), self.identity,
                self.unit, self.meta_plan, self.raw, reservations=())
        self.assertEqual({'METADATA-RAW', 'HEADER', 'RESERVATION', 'INITIALIZED'}, set(os.listdir(self.store)))
        for name in ('permit', 'complete', 'applied', 'send_once'): self.assertFalse(hasattr(seen, name))
        self.assertNotIn('sentinel.private-token', repr(seen)); self.assertNotIn(b'sentinel.private-token', (self.store / 'HEADER').read_bytes())

    def test_overflow_existing_fence_bad_nonce_partial_or_foreign_read_never_creates_store(self):
        self.module = load()
        payload = json.loads(self.raw.data)
        overflow = json.loads(self.raw.data); overflow['matchedDeveloperMetadata'].append({'developerMetadata': {
            'metadataId': 400, 'metadataKey': 'x', 'metadataValue': 'a' * 29912, 'visibility': 'DOCUMENT',
            'location': {'locationType': 'SHEET', 'sheetId': 101}}})
        bad_nonce = json.loads(self.raw.data); bad_nonce['matchedDeveloperMetadata'][0]['developerMetadata']['metadataValue'] = 'f' * 64
        from types import SimpleNamespace
        variants = ((self.meta_plan, response(overflow)), (self.meta_plan, response(self.metadata)),
                    (self.meta_plan, response(bad_nonce)), (self.meta_plan, response({'matchedDeveloperMetadata': payload['matchedDeveloperMetadata'][:1]})),
                    (replace(self.meta_plan, path=self.meta_plan.path.replace(TARGET, 'foreign_spreadsheet_0002')), self.raw),
                    (self.meta_plan, SimpleNamespace(status=200, complete=False, data=self.raw.data)))
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token)
            for plan, raw in variants:
                with self.assertRaises(self.module.MetadataReservationHold) as caught: self.reserve(token, plan=plan, raw=raw)
                self.assertIsNone(caught.exception.__context__); self.assertFalse(self.store.exists())

    def test_unattempted_global_is_required_and_unknown_cannot_create_or_replace_quota(self):
        self.module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            with self.assertRaises(self.module.MetadataReservationHold): self.reserve(token)
            self.initialize(token); first = self.reserve(token)
            self.global_journal.record_global_attempt_intent(token, binding(), self.unit)
            self.assertEqual(first, self.inspect(token))
            image = {p.name: p.read_bytes() for p in self.store.iterdir()}
            with self.assertRaises(self.module.MetadataReservationHold): self.reserve(token)
            self.assertEqual(image, {p.name: p.read_bytes() for p in self.store.iterdir()})
        with tempfile.TemporaryDirectory(prefix='req7-quota-after-intent-') as directory:
            root = Path(directory).resolve(); state = root / 'var/lib/http-ztp-container/issue-tracker'; state.mkdir(parents=True, mode=0o700)
            with fixture(root), self.owner.spreadsheet_owner(binding()) as token:
                self.initialize(token); self.global_journal.record_global_attempt_intent(token, binding(), self.unit)
                with self.assertRaises(self.module.MetadataReservationHold): self.reserve(token)
                self.assertFalse((state / self.store.name).exists())

    def test_entire_two_mib_fixed_response_is_retained_and_over_limit_rejected_before_creation(self):
        self.module = load()
        raw = self.raw.data + b' ' * (2 * 1024 * 1024 - len(self.raw.data))
        from types import SimpleNamespace
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token)
            with self.assertRaises(self.module.MetadataReservationHold):
                self.reserve(token, raw=SimpleNamespace(status=200, complete=True, data=raw + b' '))
            self.assertFalse(self.store.exists())
            seen = self.reserve(token, raw=SimpleNamespace(status=200, complete=True, data=raw))
            self.assertEqual(seen, self.inspect(token))
        self.assertEqual(raw, (self.store / 'METADATA-RAW').read_bytes())

    def test_all_eight_image_barriers_precede_marker_and_partial_quota_never_adopted(self):
        self.module = load(); real = os.fsync
        for boundary in range(1, 9):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory(prefix='req7-quota-barrier-') as directory:
                root = Path(directory).resolve(); state = root / 'var/lib/http-ztp-container/issue-tracker'; state.mkdir(parents=True, mode=0o700)
                store = state / self.store.name
                with fixture(root), self.owner.spreadsheet_owner(binding()) as token:
                    self.initialize(token); calls = []
                    def failing(fd):
                        if store.exists():
                            calls.append(fd)
                            if len(calls) == boundary: raise OSError('private quota barrier')
                        return real(fd)
                    with mock.patch('os.fsync', side_effect=failing), self.assertRaises(self.module.MetadataReservationHold): self.reserve(token)
                    self.assertTrue(store.is_dir()); self.assertFalse((store / 'INITIALIZED').exists())
                    with self.assertRaises(self.module.MetadataReservationHold): self.inspect(token)
                    with self.assertRaises(self.module.MetadataReservationHold): self.reserve(token)

    def test_original_images_unit_binding_links_and_foreign_names_never_repair_or_clear_unknown(self):
        self.module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); self.reserve(token)
            image = {p.name: p.read_bytes() for p in self.store.iterdir()}
            for name in ('METADATA-RAW', 'RESERVATION', 'HEADER', 'INITIALIZED'):
                (self.store / name).write_bytes(b'private tamper')
                with self.assertRaises(self.module.MetadataReservationHold): self.inspect(token)
                (self.store / name).write_bytes(image[name])
            for name in ('METADATA-RAW', 'RESERVATION', 'HEADER', 'INITIALIZED'):
                with self.subTest(linked=name):
                    anchor = self.state / ('private-' + name)
                    (self.store / name).rename(anchor); os.link(anchor, self.store / name)
                    with self.assertRaises(self.module.MetadataReservationHold): self.inspect(token)
                    (self.store / name).unlink(); anchor.rename(self.store / name)
            value = json.loads(image['RESERVATION']); value['metadataValue'] = '2'
            wrong = matching.canonical(value); header = json.loads(image['HEADER'])
            header['reservation_sha256'] = hashlib.sha256(wrong).hexdigest()
            (self.store / 'RESERVATION').write_bytes(wrong); (self.store / 'HEADER').write_bytes(matching.canonical(header))
            (self.store / 'INITIALIZED').write_bytes(matching.canonical({'schema_version': 1, 'state': 'INITIALIZED',
                'header_sha256': hashlib.sha256(matching.canonical(header)).hexdigest()}))
            with self.assertRaises(self.module.MetadataReservationHold): self.inspect(token)
            for name, raw in image.items(): (self.store / name).write_bytes(raw)
            (self.store / 'foreign').write_bytes(b'private foreign')
            with self.assertRaises(self.module.MetadataReservationHold): self.inspect(token)
        with fixture(self.root), self.assertRaises(self.module.MetadataReservationHold): self.inspect(token)


class Req7MetadataReservationWorkflowTests(unittest.TestCase):
    setUp = Req7MetadataReservationDirectTests.setUp
    initialize = Req7MetadataReservationDirectTests.initialize
    reserve = Req7MetadataReservationDirectTests.reserve
    inspect = Req7MetadataReservationDirectTests.inspect

    def test_actual_cold_process_keeps_quota_unknown_and_original_fence_without_reclamation(self):
        self.module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); seen = self.reserve(token)
            self.global_journal.record_global_attempt_intent(token, binding(), self.unit)
        result = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), '--owned-inspect', str(self.root), str(ROOT)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(b'VISIBLE_ONLY_UNPROVED 1 29912\n', result.stdout)
        self.assertEqual(self.raw.data, (self.store / 'METADATA-RAW').read_bytes())

    def test_manifest_primary_suite_actual_multiscript_dependencies_and_not_run_card(self):
        manifest = json.loads((ROOT / 'test_cases/script_test_manifest.json').read_text())
        script = 'monitor/issue_tracker_metadata_reservation.py'; test = 'test_cases.test_req7_metadata_reservation'
        self.assertEqual(script, manifest['scripts'].get(script))
        self.assertTrue(any(script in rule['paths'] and test in rule['tests'] for rule in manifest['test_rules']))
        members = {script, 'monitor/issue_tracker_metadata_capacity.py', 'monitor/issue_tracker_global_attempt_journal.py',
            'monitor/issue_tracker_enrollment_journal.py', 'monitor/issue_tracker_spreadsheet_owner.py', 'monitor/issue_tracker_send_intent.py',
            'monitor/issue_tracker_sheets_read_decode.py', 'monitor/issue_tracker_tls_inputs.py'}
        self.assertTrue(any(members <= set(rule['members']) and test in rule['tests'] for rule in manifest['workflows']))
        self.assertEqual(['issue-tracker-local'], [suite['id'] for suite in manifest['test_suites'] if test in suite['tests']])
        self.assertIn(test, (ROOT / 'test_cases/README.md').read_text())
        cards = (ROOT / 'test_cases/REAL_ENVIRONMENT.md').read_text(); start = cards.index('## TC-REAL-REQ7-METADATA-RESERVATION-001')
        end = cards.find('\n## ', start + 1); card = cards[start:] if end == -1 else cards[start:end]
        for term in ('NOT RUN / REAL_ENV REQUIRED', script, '前置条件', '证据', 'stat/inode', '清理', '不是 COMPLETE'):
            self.assertIn(term, card)


class Req7MetadataReservationNativeWorkflowTests(unittest.TestCase):
    _Fixture = matching.Req7RemoteHistoryNativeWorkflowTests
    fixture = _Fixture.fixture; certificates = _Fixture.certificates; server = _Fixture.server
    read_once = _Fixture.read_once

    def setUp(self):
        self.setup = Req7MetadataReservationDirectTests(); self.setup.setUp()
        self.addCleanup(self.setup.doCleanups)
        self._Fixture._Fixture.setUp(self)

    def test_actual_fixed_metadata_tls_read_original_nonces_global_unit_and_durable_budget_unknown(self):
        setup = self.setup
        # CA fixture validates the actual UID; do not overlap it with the
        # synthetic private-global-root ownership fixture below.
        capacity = matching.load_read('issue_tracker_metadata_capacity')
        setup.decoder = sys.modules['monitor.issue_tracker_sheets_read_decode']
        setup.planner = sys.modules['monitor.issue_tracker_sheets_read_plan']
        setup.identity = setup.decoder.decode_template_identity(
            setup.planner.prepare_template_identity_read(setup.binding, setup.token_value), response(matching.identity_response()))
        setup.meta_plan = capacity.prepare_metadata_capacity_read(setup.binding, setup.token_value)
        setup.plan = setup.planner.prepare_history_tail_read(setup.binding, setup.token_value)
        setup.before = matching.load_before()
        with mock.patch.dict(sys.modules, {'monitor.issue_tracker_tls_inputs': self.tls}):
            raw, record = self.read_once(capacity.NativeMetadataCapacityReadUnit(setup.binding, setup.token_value), setup.raw.data)
        setup.module = load()
        with fixture(setup.root), setup.owner.spreadsheet_owner(binding()) as token:
            setup.initialize(token)
            seen = setup.module.prepare_metadata_reservation(token, binding(), setup.identity, setup.unit, setup.meta_plan, raw)
            setup.global_journal.record_global_attempt_intent(token, binding(), setup.unit)
            self.assertEqual(seen, setup.inspect(token)); self.assertEqual(29912, next(row[3] for row in seen.pools if row[0] == 101))
            self.assertEqual('UNKNOWN', setup.global_journal.inspect_global_unit(token, binding(), setup.unit).outcome)
        self.assertEqual(('POST ' + setup.meta_plan.path + ' HTTP/1.1\r\n').encode(), record[0])
        self.assertEqual(setup.meta_plan.body, record[2]); self.assertFalse(seen.inventory_complete)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--owned-inspect':
        case = Req7MetadataReservationDirectTests(); case.setUp(); case.module = load()
        with fixture(Path(sys.argv[2])), case.owner.spreadsheet_owner(binding()) as token:
            seen = case.inspect(token)
        print(seen.outcome, seen.outstanding_reservations, next(row[3] for row in seen.pools if row[0] == 101)); case.doCleanups()
    else: unittest.main()
