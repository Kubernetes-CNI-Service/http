"""Actual original nonces/global unit plus durable G1 budget, not admission."""
from dataclasses import replace
from contextlib import redirect_stderr
import hashlib
import importlib.util
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


def _cold_phase(phase,**values):
    print('REQ7_METADATA_CHILD_PHASE '+json.dumps({'phase':phase,
        'monotonic':time.monotonic(),'wall_ns':time.time_ns(),**values},sort_keys=True),
        file=sys.stderr,flush=True)


if len(sys.argv) > 1 and sys.argv[1] in ('--owned-inspect', '--owned-count'):
    _cold_phase('before_fixture_imports')
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
    spec.loader.exec_module(module)
    # Match normal canonical imports after the owned fixture reloads owner /
    # global journal. Never weaken production token or class identity checks.
    import monitor
    monitor.issue_tracker_metadata_reservation = module
    return module


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

    def test_cold_timeout_preserves_original_error_budget_and_partial_phase_evidence(self):
        self.assertTrue('_run_owned_count_child' in globals(),'cold count timeout evidence wrapper missing')
        command=['fixed-test-python','-B','fixed-test-entry','--owned-count','owned-root',str(ROOT)]
        partial=b'REQ7_METADATA_CHILD_PHASE {"phase":"before_count"}\n'
        failure=subprocess.TimeoutExpired(command,5,output=b'partial count',stderr=partial)
        evidence=StringIO()
        with mock.patch.object(subprocess,'run',side_effect=failure) as run,redirect_stderr(evidence):
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                _run_owned_count_child(command,4)
        self.assertIs(failure,caught.exception)
        run.assert_called_once_with(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,timeout=5)
        entries=[json.loads(line.split(' ',1)[1]) for line in evidence.getvalue().splitlines()]
        self.assertEqual(['spawn_begin','timeout'],[entry['phase'] for entry in entries])
        self.assertEqual([4,4],[entry['count'] for entry in entries])
        self.assertEqual('partial count',entries[-1]['stdout'])
        self.assertEqual(partial.decode(),entries[-1]['stderr'])

    def test_owned_cold_entry_cleans_fixture_after_the_original_counter_error(self):
        self.assertTrue('_owned_metadata_child' in globals(),'cold entry lacks guaranteed fixture cleanup')
        failure=RuntimeError('independent cold count fault')
        case=mock.MagicMock(); case.owner.spreadsheet_owner.return_value.__enter__=mock.Mock(return_value=object())
        case.owner.spreadsheet_owner.return_value.__exit__=mock.Mock(return_value=False)
        case.global_journal.record_reserved_attempt_intent.side_effect=failure
        with mock.patch(__name__+'.Req7MetadataReservationDirectTests',return_value=case), \
                mock.patch(__name__+'.load',return_value=object()),mock.patch(__name__+'.fixture') as scoped:
            scoped.return_value.__enter__=mock.Mock(return_value=None)
            scoped.return_value.__exit__=mock.Mock(return_value=False)
            with self.assertRaises(RuntimeError) as caught:
                _owned_metadata_child('--owned-count',self.root)
        self.assertIs(failure,caught.exception)
        case.doCleanups.assert_called_once_with()

    def test_project_reservation_requires_live_original_reads_before_any_durable_write(self):
        self.module=load()
        self.assertTrue(hasattr(self.module,'prepare_owned_project_metadata_reservation'),
                        'G1 budget must derive its fence from an actual unit and original project reads')
        with mock.patch.object(self.module,'_prepare_metadata_reservation') as writing:
            with self.assertRaises(self.module.MetadataReservationHold) as caught:
                self.module.prepare_owned_project_metadata_reservation(object(),object(),binding(),object(),self.unit,
                    identity_response=object(),metadata_response=self.raw)
            self.assertIsNone(caught.exception.__context__); writing.assert_not_called()
        self.assertFalse(self.store.exists())

    def test_fixture_canonical_metadata_alias_and_original_owner_dependencies_match_current_imports(self):
        import monitor
        module = load()
        self.assertIs(module, monitor.issue_tracker_metadata_reservation)
        self.assertIs(module.global_journal, self.global_journal)
        self.assertIs(module.ownership, self.owner)
        self.assertIs(module.enrollment, self.enrollment)

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

    def test_original_quota_directory_or_image_rebinding_after_inspection_cannot_return_success(self):
        self.module=load()
        for fault in ('directory','HEADER','RESERVATION','METADATA-RAW','INITIALIZED'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory(prefix='req7-quota-original-return-') as directory:
                root=Path(directory).resolve(); state=root/'var/lib/http-ztp-container/issue-tracker'
                state.mkdir(parents=True,mode=0o700); store=state/self.store.name
                with fixture(root),self.owner.spreadsheet_owner(binding()) as token:
                    self.initialize(token); inspect=self.module._inspect; changed=[]
                    def inspected_then_rebind(*args,**kwargs):
                        result=inspect(*args,**kwargs)
                        if not changed:
                            changed.append(True)
                            if fault=='directory':
                                original={p.name:p.read_bytes() for p in store.iterdir()}
                                store.rename(root/'preserved-quota'); store.mkdir(mode=0o700)
                                for name,raw in original.items():
                                    path=store/name; path.write_bytes(raw); path.chmod(0o600)
                            else:
                                path=store/fault; raw=path.read_bytes()
                                path.rename(root/('preserved-'+fault)); path.write_bytes(raw); path.chmod(0o600)
                        return result
                    with mock.patch.object(self.module,'_inspect',side_effect=inspected_then_rebind),self.assertRaises(self.module.MetadataReservationHold):
                        self.module.prepare_metadata_reservation(token,binding(),self.identity,self.unit,self.meta_plan,self.raw)
                    self.assertEqual([True],changed)
                    self.assertTrue((store/'INITIALIZED').exists(),'late failure retains original and replacement evidence')
                    self.assertEqual(0,self.global_journal.inspect_global_unit(token,binding(),self.unit).attempt_count)

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

    def test_reserved_intent_requires_original_quota_before_count_and_keeps_all_six_identical(self):
        self.module = load()
        self.assertTrue(hasattr(self.global_journal, 'record_reserved_attempt_intent'),
                        'actual reservation chain must dominate counted intent')
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token)
            with self.assertRaises(self.global_journal.GlobalAttemptHold):
                self.global_journal.record_reserved_attempt_intent(token, binding(), self.identity, self.unit)
            self.assertEqual(0, self.global_journal.inspect_global_unit(token, binding(), self.unit).attempt_count)
            quota = self.reserve(token); image = {p.name: p.read_bytes() for p in self.store.iterdir()}
            for count in range(1, 7):
                seen = self.global_journal.record_reserved_attempt_intent(token, binding(), self.identity, self.unit)
                self.assertEqual((count, 'UNKNOWN', self.unit.action_digest, self.unit.wire_sha256),
                                 (seen.attempt_count, seen.outcome, seen.action_digest, seen.wire_sha256))
                self.assertEqual(quota, self.inspect(token))
                self.assertEqual(image, {p.name: p.read_bytes() for p in self.store.iterdir()})
                self.assertFalse(hasattr(seen, 'permit')); self.assertFalse(hasattr(seen, 'send_once'))
            with self.assertRaises(self.global_journal.GlobalAttemptHold):
                self.global_journal.record_reserved_attempt_intent(token, binding(), self.identity, self.unit)
            self.assertEqual(6, self.global_journal.inspect_global_unit(token, binding(), self.unit).attempt_count)

    def test_reserved_count_cannot_adopt_same_byte_quota_replacement_after_count(self):
        self.module=load()
        for fault in ('directory','HEADER'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory(prefix='req7-count-quota-original-') as directory:
                root=Path(directory).resolve(); state=root/'var/lib/http-ztp-container/issue-tracker'
                state.mkdir(parents=True,mode=0o700); store=state/self.store.name
                with fixture(root),self.owner.spreadsheet_owner(binding()) as token:
                    self.initialize(token); quota=self.reserve(token)
                    image={p.name:p.read_bytes() for p in store.iterdir()}
                    original=self.global_journal._observe; injected=[]
                    def replaced_after_count(*args,**kwargs):
                        result=original(*args,**kwargs)
                        if args[3]:
                            if fault=='directory':
                                store.rename(root/'preserved-quota'); store.mkdir(mode=0o700)
                                for name,raw in image.items():
                                    path=store/name; path.write_bytes(raw); path.chmod(0o600)
                            else:
                                path=store/'HEADER'; path.rename(root/'preserved-HEADER')
                                path.write_bytes(image['HEADER']); path.chmod(0o600)
                            injected.append(result.attempt_count)
                        return result
                    with mock.patch.object(self.global_journal,'_observe',side_effect=replaced_after_count), \
                            self.assertRaises(self.global_journal.GlobalAttemptHold):
                        self.global_journal.record_reserved_attempt_intent(token,binding(),self.identity,self.unit)
                    self.assertEqual([1],injected)
                    self.assertEqual((1,'UNKNOWN'),tuple(getattr(self.global_journal.inspect_global_unit(
                        token,binding(),self.unit),name) for name in ('attempt_count','outcome')))
                    self.assertEqual(image,{p.name:p.read_bytes() for p in store.iterdir()})
                    self.assertEqual(quota,self.inspect(token))

    def test_shared_retry_count_cannot_adopt_same_byte_quota_header_after_count(self):
        # Isolate the quota/count boundary with real owner, journal and quota.
        # Protected C5/live-read/cadence integration is asserted separately by
        # the actual Stage-L multi-script workflow, not by these stubs.
        from contextlib import nullcontext
        from types import SimpleNamespace
        from monitor import issue_tracker_admission as admission
        from monitor import issue_tracker_history_preread_journal as continuity
        from monitor import issue_tracker_remote_history_match as gates
        from monitor import issue_tracker_local_workbook_commit as publications
        from monitor import issue_tracker_stage_l_consumer as consumer
        from monitor import issue_tracker_cycle_source as cycles
        from monitor import issue_tracker_receipt_snapshot as receipts
        from monitor import issue_tracker_send_unit as units
        self.module=load()
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); self.reserve(token)
            self.assertEqual(1,self.global_journal.record_reserved_attempt_intent(
                token,binding(),self.identity,self.unit).attempt_count)
            path=self.store/'HEADER'; raw=path.read_bytes(); inode=path.stat().st_ino
            preserved=self.root/'owned-original-retry-quota-header'; injected=[]
            original_receipt=('owned-generation','owned-publication','owned-manifest')
            original_facts=(original_receipt,'owned-qualified',
                            'owned-reservations','owned-business','owned-audits')
            store=SimpleNamespace(project_identity=self.root)
            cycle_checks=[]
            original=self.global_journal._observe
            def replace_after_retry(*values,**options):
                result=original(*values,**options)
                if values[3]:
                    path.rename(preserved); path.write_bytes(raw); path.chmod(0o600)
                    injected.append(result.attempt_count)
                return result
            with mock.patch.object(consumer,'_hold_original_replay_inputs',
                        return_value=nullcontext(lambda:None)) as inputs_guard, \
                    mock.patch.object(cycles,'_hold_completed_cycle_replay',
                        return_value=nullcontext(lambda:cycle_checks.append('cycle'))) as cycles_guard, \
                    mock.patch.object(receipts,'_hold_history_originals',
                        return_value=nullcontext(lambda:None)) as receipts_guard, \
                    mock.patch.object(units,'_read_original_generation_identity',
                        return_value=original_receipt) as original_generation, \
                    mock.patch.object(self.global_journal,'_hold_receipted_audit_originals',
                        return_value=nullcontext(lambda:None)), \
                    mock.patch.object(continuity,'observe_owned_business_continuity',return_value=('owned-continuity',)), \
                    mock.patch.object(gates,'observe_owned_unit_read_gates',return_value=SimpleNamespace(identity=self.identity)), \
                    mock.patch.object(self.global_journal,'_receipted_original_facts',return_value=original_facts), \
                    mock.patch.object(publications,'_latest_receipted_prod_xlsx',return_value=b'owned-publication'), \
                    mock.patch.object(admission,'_hold_shared_retry_opportunity',return_value=nullcontext()), \
                    mock.patch.object(self.global_journal,'_observe',side_effect=replace_after_retry), \
                    self.assertRaises(self.global_journal.GlobalAttemptHold):
                self.global_journal.record_shared_retry_continuous_owned_attempt_intent(token,binding(),self.unit,
                    writer_token=None,identity_response=None,history_response=None,business_reads=(),
                    qualified_source=None,store=store,settings=None,whitelist_snapshot=SimpleNamespace(whitelist=None),
                    expected_template_sha256='a'*64,http_root=self.root,whitelist_path=self.root/'not-used',
                    headers_response=None,whitelist_response=None,metadata_response=None,
                    boot_id='owned-boot',monotonic_ns=1)
            inputs_guard.assert_called_once_with(store,self.root,self.root/'not-used')
            cycles_guard.assert_called_once_with(store)
            self.assertEqual(['cycle','cycle'],cycle_checks)
            receipts_guard.assert_called_once_with(None)
            original_generation.assert_called_once_with('owned-generation',None)
            self.assertEqual([2],injected); self.assertNotEqual(inode,path.stat().st_ino)
            seen=self.global_journal.inspect_global_unit(token,binding(),self.unit)
            self.assertEqual((2,'UNKNOWN'),(seen.attempt_count,seen.outcome))
            self.assertEqual(raw,path.read_bytes()); self.assertEqual(raw,preserved.read_bytes())

    def test_reserved_intent_refuses_each_drifted_original_image_without_increment_or_repair(self):
        self.module = load()
        self.assertTrue(hasattr(self.global_journal, 'record_reserved_attempt_intent'),
                        'actual reservation chain must dominate counted intent')
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); self.reserve(token)
            parent = self.state
            stores = {suffix: parent / (hashlib.sha256(TARGET.encode()).hexdigest() + suffix)
                      for suffix in ('.enrollment', '.history', '.metadata')}
            for suffix, name in (('.enrollment', 'NONCES'), ('.history', 'HISTORY-RAW'),
                                 ('.metadata', 'RESERVATION'), ('.metadata', 'INITIALIZED')):
                with self.subTest(suffix=suffix, image=name):
                    path = stores[suffix] / name; raw = path.read_bytes(); path.write_bytes(b'private damaged image')
                    with self.assertRaises(self.global_journal.GlobalAttemptHold) as caught:
                        self.global_journal.record_reserved_attempt_intent(token, binding(), self.identity, self.unit)
                    self.assertIsNone(caught.exception.__context__)
                    self.assertEqual(b'private damaged image', path.read_bytes())
                    self.assertEqual(0, self.global_journal.inspect_global_unit(token, binding(), self.unit).attempt_count)
                    path.write_bytes(raw)
            changed = replace(self.identity, sheet_ids=tuple((title, 999 if title == 'Update_History' else sid)
                                                             for title, sid in self.identity.sheet_ids))
            with self.assertRaises(self.global_journal.GlobalAttemptHold):
                self.global_journal.record_reserved_attempt_intent(token, binding(), changed, self.unit)
            self.assertEqual(0, self.global_journal.inspect_global_unit(token, binding(), self.unit).attempt_count)
        with fixture(self.root), self.assertRaises(self.global_journal.GlobalAttemptHold):
            self.global_journal.record_reserved_attempt_intent(token, binding(), self.identity, self.unit)

    def test_reserved_intent_post_barrier_failure_keeps_counted_unknown_and_never_returns_permission(self):
        self.module = load()
        self.assertTrue(hasattr(self.global_journal, 'record_reserved_attempt_intent'),
                        'actual reservation chain must dominate counted intent')
        real = os.fsync
        journal_store = self.state / (hashlib.sha256(TARGET.encode()).hexdigest() + '.journal')
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); self.reserve(token)
            def failing(fd):
                if (journal_store / 'ATTEMPT-1').exists(): raise OSError('private post-intent barrier failure')
                return real(fd)
            with mock.patch('os.fsync', side_effect=failing), self.assertRaises(self.global_journal.GlobalAttemptHold):
                self.global_journal.record_reserved_attempt_intent(token, binding(), self.identity, self.unit)
            self.assertTrue((journal_store / 'ATTEMPT-1').exists())
            self.assertEqual((1, 'UNKNOWN'), (self.global_journal.inspect_global_unit(token, binding(), self.unit).attempt_count,
                                             self.global_journal.inspect_global_unit(token, binding(), self.unit).outcome))
            self.assertEqual(1, self.inspect(token).outstanding_reservations)

    def test_history_capacity_must_fit_all_sent_business_and_all_audits_before_fence_reservation(self):
        self.module = load()
        # One NOOP contributes no History row; one actual update PLUS one
        # settings audit need two rows. Only one row remains in a 3-row sheet.
        self.empty['sheets'][0]['properties']['gridProperties']['rowCount'] = 3
        self.assertEqual(2, self.unit.history_rows_expected)
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token)
            with self.assertRaises(self.module.MetadataReservationHold): self.reserve(token)
            self.assertFalse(self.store.exists()); self.assertEqual(0, self.global_journal.inspect_global_unit(token, binding(), self.unit).attempt_count)

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

    def test_six_real_cold_processes_reopen_original_reservations_and_seventh_cannot_count(self):
        self.module = load()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.initialize(token); self.reserve(token)
        image = {p.name: p.read_bytes() for p in self.store.iterdir()}
        command = [sys.executable, '-B', str(Path(__file__).resolve()), '--owned-count', str(self.root), str(ROOT)]
        for count in range(1, 7):
            result = _run_owned_count_child(command,count)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(('%d UNKNOWN\n' % count).encode(), result.stdout)
            self.assertEqual(image, {p.name: p.read_bytes() for p in self.store.iterdir()})
        result = _run_owned_count_child(command,7)
        self.assertNotEqual(0, result.returncode); self.assertEqual(b'', result.stdout)
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.assertEqual(6, self.global_journal.inspect_global_unit(token, binding(), self.unit).attempt_count)
            self.assertEqual(1, self.inspect(token).outstanding_reservations)

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
            'monitor/issue_tracker_history_preread_journal.py', 'monitor/issue_tracker_sheets_read_decode.py', 'monitor/issue_tracker_tls_inputs.py'}
        self.assertTrue(any(members <= set(rule['members']) and test in rule['tests'] for rule in manifest['workflows']))
        self.assertEqual(['issue-tracker-local'], [suite['id'] for suite in manifest['test_suites'] if test in suite['tests']])
        self.assertIn(test, (ROOT / 'test_cases/README.md').read_text())
        cards = (ROOT / 'test_cases/REAL_ENVIRONMENT.md').read_text(); start = cards.index('## TC-REAL-REQ7-METADATA-RESERVATION-001')
        end = cards.find('\n## ', start + 1); card = cards[start:] if end == -1 else cards[start:end]
        for term in ('NOT RUN / REAL_ENV REQUIRED', script, '前置条件', '证据', 'stat/inode', '清理', '不是 COMPLETE'):
            self.assertIn(term, card)


class Req7MetadataReservationProjectWorkflowTests(unittest.TestCase):
    from test_cases.test_req7_history_read_launcher import Req7HistoryReadLauncherWorkflowTests as _Fixture
    setUp=_Fixture.setUp; certificates=_Fixture.certificates; server=_Fixture.server
    owners=_Fixture.owners; intercept=_Fixture.intercept; child_fixture=_Fixture.child_fixture
    project_auth=_Fixture.project_auth

    def read_project(self,stack,writer,owner,bound,authentication,kind,value):
        from contextlib import ExitStack
        import socket
        from monitor import issue_tracker_history_read_launcher as reads
        body=json.dumps(value,separators=(',',':')).encode()
        reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
        with self.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors),ExitStack() as launched:
            port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
            calls,children=self.intercept(launched,self.child_fixture(port),writer,owner,bound)
            result=reads.OwnedProjectSheetsReadUnit(writer,owner,bound,authentication,read_kind=kind).read_once()
            self.assertEqual(1,len(calls)); self.assertEqual(0,children[0].returncode)
        self.assertEqual([],errors); self.assertEqual(1,len(records)); self.assertEqual(body,result.data)
        self.assertIn(b'Authorization: Bearer owned-project-token\r\n',records[0][1])
        return result

    def prepare_original(self,stack):
        from monitor import issue_tracker_global_attempt_journal as journal, issue_tracker_enrollment_journal as enrollment
        from monitor import issue_tracker_history_preread_journal as preread, issue_tracker_sheets_read_decode as decode
        from monitor import issue_tracker_history_read_launcher as reads
        from test_cases.test_req7_send_unit import inputs
        from monitor.issue_tracker_send_unit import freeze_send_unit
        _local,ownership,writer,owner,bound,_token,config=self.owners(stack)
        authentication,credential,original=self.project_auth(stack,ownership,owner,bound)
        document=matching.identity_response(); document['spreadsheetId']=bound.spreadsheet_id
        identity_read=self.read_project(stack,writer,owner,bound,authentication,'template_identity',document)
        identity_plan,_project,_digest=reads.require_current_owned_project_read(writer,owner,bound,identity_read,authentication,read_kind='template_identity')
        identity=decode.decode_template_identity(identity_plan,identity_read)
        with mock.patch('secrets.token_hex',side_effect=['a'*64,'b'*64,'c'*64,'d'*64]):
            enrollment.prepare_enrollment_journal(owner,bound,identity)
        arguments=inputs(); arguments.update(spreadsheet_id=bound.spreadsheet_id,sheet_id=101,history_sheet_id=105,
            target_nonce='a'*64,history_nonce='d'*64)
        unit=freeze_send_unit(**arguments); journal.prepare_global_unit(owner,bound,unit)
        history=matching.tail_document(12); history['spreadsheetId']=bound.spreadsheet_id
        history['sheets'][0]['properties']['sheetId']=105; history['sheets'][0]['data'][0]['rowData']=[]
        history_read=self.read_project(stack,writer,owner,bound,authentication,'history_tail',history)
        history_plan,_project,_digest=reads.require_current_owned_project_read(writer,owner,bound,history_read,authentication,read_kind='history_tail')
        preread.prepare_history_preread(owner,bound,unit,history_plan,history_read)
        metadata={'matchedDeveloperMetadata':[
            {'developerMetadata':{'metadataId':1,'metadataKey':'http-ztp-enrollment-v1','metadataValue':'a'*64,
                'visibility':'DOCUMENT','location':{'locationType':'SHEET','sheetId':101}}},
            {'developerMetadata':{'metadataId':2,'metadataKey':'http-ztp-enrollment-v1','metadataValue':'d'*64,
                'visibility':'DOCUMENT','location':{'locationType':'SHEET','sheetId':105}}}]}
        return writer,owner,bound,authentication,identity_read,identity,unit,metadata,credential,original

    def test_real_project_reads_original_unit_fence_reservation_never_infer_hidden_inventory_or_clear_unknown(self):
        from contextlib import ExitStack
        module=load()
        self.assertTrue(hasattr(module,'prepare_owned_project_metadata_reservation'))
        with ExitStack() as stack:
            writer,owner,bound,auth,identity_read,identity,unit,metadata,credential,original=self.prepare_original(stack)
            metadata_read=self.read_project(stack,writer,owner,bound,auth,'metadata',metadata)
            store=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.metadata')
            for images in ((replace(identity_read),metadata_read),(identity_read,replace(metadata_read))):
                with self.assertRaises(module.MetadataReservationHold):
                    module.prepare_owned_project_metadata_reservation(writer,owner,bound,auth,unit,
                        identity_response=images[0],metadata_response=images[1])
                self.assertFalse(store.exists())
            seen=module.prepare_owned_project_metadata_reservation(writer,owner,bound,auth,unit,
                identity_response=identity_read,metadata_response=metadata_read)
            self.assertEqual('VISIBLE_ONLY_UNPROVED',seen.outcome); self.assertIs(False,seen.inventory_complete)
            self.assertEqual((101,86,2,29912),next(row for row in seen.pools if row[0]==101))
            self.assertEqual(1,seen.outstanding_reservations); self.assertEqual(unit.fence_metadata_id,seen.fence_metadata_id)
            self.assertFalse(hasattr(seen,'permit')); self.assertFalse(hasattr(seen,'send_once'))
            retained={path.name:path.read_bytes() for path in store.iterdir()}
            self.assertNotIn(b'owned-project-token',retained['HEADER'])
            module.global_journal.record_reserved_attempt_intent(owner,bound,identity,unit)
            self.assertEqual((1,'UNKNOWN'),(module.global_journal.inspect_global_unit(owner,bound,unit).attempt_count,
                                          module.global_journal.inspect_global_unit(owner,bound,unit).outcome))
            self.assertEqual(seen,module.inspect_metadata_reservation(owner,bound,identity,unit))
            with self.assertRaises(module.MetadataReservationHold):
                module.prepare_owned_project_metadata_reservation(writer,owner,bound,auth,unit,
                    identity_response=identity_read,metadata_response=metadata_read)
            self.assertEqual(retained,{path.name:path.read_bytes() for path in store.iterdir()})
            self.assertEqual(original,credential.read_bytes())

    def test_project_read_expiry_after_quota_barrier_keeps_reservation_without_permission_or_reset(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_history_read_launcher as reads
        import time
        module=load()
        self.assertTrue(hasattr(module,'prepare_owned_project_metadata_reservation'))
        with ExitStack() as stack:
            writer,owner,bound,auth,identity_read,identity,unit,metadata,_credential,_original=self.prepare_original(stack)
            metadata_read=self.read_project(stack,writer,owner,bound,auth,'metadata',metadata)
            native=module._inspect; finished=[]
            def inspect_then_expire(*args,**kwargs):
                result=native(*args,**kwargs); finished.append(True); return result
            with mock.patch.object(module,'_inspect',side_effect=inspect_then_expire), \
                    mock.patch.object(reads,'_monotonic',side_effect=lambda:time.monotonic()+(31 if finished else 0)):
                with self.assertRaises(module.MetadataReservationHold):
                    module.prepare_owned_project_metadata_reservation(writer,owner,bound,auth,unit,
                        identity_response=identity_read,metadata_response=metadata_read)
            self.assertEqual([True],finished)
            store=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.metadata')
            self.assertEqual({'METADATA-RAW','HEADER','RESERVATION','INITIALIZED'},set(os.listdir(store)))
            self.assertIs(False,module.inspect_metadata_reservation(owner,bound,identity,unit).inventory_complete)
            self.assertEqual(0,module.global_journal.inspect_global_unit(owner,bound,unit).attempt_count)
            retained={path.name:path.read_bytes() for path in store.iterdir()}
            with self.assertRaises(module.MetadataReservationHold):
                module.prepare_owned_project_metadata_reservation(writer,owner,bound,auth,unit,
                    identity_response=identity_read,metadata_response=metadata_read)
            self.assertEqual(retained,{path.name:path.read_bytes() for path in store.iterdir()})

    def test_project_final_source_revalidation_cannot_adopt_identical_replaced_quota_namespace(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_history_read_launcher as reads
        module=load()
        with ExitStack() as stack:
            writer,owner,bound,auth,identity_read,_identity,unit,metadata,_credential,_original=self.prepare_original(stack)
            metadata_read=self.read_project(stack,writer,owner,bound,auth,'metadata',metadata)
            store=self.root/'var/lib/http-ztp-container/issue-tracker'/(hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.metadata')
            current=reads.require_current_owned_project_read; changed=[]
            def fresh_read_then_replace(*args,**kwargs):
                result=current(*args,**kwargs)
                if (store/'INITIALIZED').exists() and not changed:
                    changed.append(True); originals={p.name:p.read_bytes() for p in store.iterdir()}
                    store.rename(self.root/'preserved-original-quota'); store.mkdir(mode=0o700)
                    for name,raw in originals.items():
                        path=store/name; path.write_bytes(raw); path.chmod(0o600)
                return result
            with mock.patch.object(reads,'require_current_owned_project_read',side_effect=fresh_read_then_replace),self.assertRaises(module.MetadataReservationHold):
                module.prepare_owned_project_metadata_reservation(writer,owner,bound,auth,unit,
                    identity_response=identity_read,metadata_response=metadata_read)
            self.assertEqual([True],changed)
            self.assertEqual({p.name:p.read_bytes() for p in (self.root/'preserved-original-quota').iterdir()},
                             {p.name:p.read_bytes() for p in store.iterdir()})
            self.assertEqual(0,module.global_journal.inspect_global_unit(owner,bound,unit).attempt_count)


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
            setup.global_journal.record_reserved_attempt_intent(token, binding(), setup.identity, setup.unit)
            self.assertEqual(seen, setup.inspect(token)); self.assertEqual(29912, next(row[3] for row in seen.pools if row[0] == 101))
            self.assertEqual('UNKNOWN', setup.global_journal.inspect_global_unit(token, binding(), setup.unit).outcome)
        self.assertEqual(('POST ' + setup.meta_plan.path + ' HTTP/1.1\r\n').encode(), record[0])
        self.assertEqual(setup.meta_plan.body, record[2]); self.assertFalse(seen.inventory_complete)


def _run_owned_count_child(command,count):
    """Keep the original command, 5s budget and error; retain native phases."""
    started=time.monotonic()
    def phase(name,**fields):
        print('REQ7_METADATA_PARENT_PHASE '+json.dumps({'phase':name,'count':count,
            'monotonic':time.monotonic(),'wall_ns':time.time_ns(),
            'elapsed':time.monotonic()-started,**fields},sort_keys=True),file=sys.stderr,flush=True)
    def text(value):
        return value.decode('utf-8','backslashreplace') if isinstance(value,bytes) else (value or '')
    phase('spawn_begin')
    try:
        result=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,timeout=5)
    except subprocess.TimeoutExpired as exc:
        phase('timeout',stdout=text(exc.output),stderr=text(exc.stderr))
        raise
    phase('return',exit=result.returncode,stdout=text(result.stdout),stderr=text(result.stderr))
    return result


def _owned_metadata_child(mode,root):
    case=Req7MetadataReservationDirectTests()
    try:
        _cold_phase('fixture_setup_begin'); case.setUp(); _cold_phase('fixture_setup_end')
        case.module=load(); _cold_phase('source_loaded')
        with fixture(root),case.owner.spreadsheet_owner(binding()) as token:
            _cold_phase('owner_entered')
            if mode=='--owned-count':
                _cold_phase('before_count')
                seen = case.global_journal.record_reserved_attempt_intent(token, binding(), case.identity, case.unit)
                _cold_phase('after_count',count=seen.attempt_count,outcome=seen.outcome)
                print(seen.attempt_count, seen.outcome)
            else:
                seen = case.inspect(token)
                print(seen.outcome, seen.outstanding_reservations, next(row[3] for row in seen.pools if row[0] == 101))
    finally:
        case.doCleanups()
        _cold_phase('fixture_cleanup_end')


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] in ('--owned-inspect', '--owned-count'):
        _owned_metadata_child(sys.argv[1],Path(sys.argv[2]))
    else: unittest.main()
