"""Independent global UNKNOWN barriers and native cold-process intent limits."""
from contextlib import contextmanager, ExitStack
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

if len(sys.argv) > 1 and sys.argv[1] in ('--owned-retry','--owned-wire-claim'):
    sys.path.insert(0, sys.argv[3]); sys.path.insert(0, str(Path(sys.argv[3]) / 'tools'))
import test_cases
ROOT = Path(test_cases.__file__).resolve().parents[1]
from test_cases.test_req7_spreadsheet_owner import fixture, binding, TARGET, load as load_owner
from test_cases.test_req7_send_unit import inputs
SOURCE = Path(__file__).resolve().parents[1] / 'monitor/issue_tracker_global_attempt_journal.py'


def load():
    if not SOURCE.is_file(): raise AssertionError('spreadsheet-wide durable UNKNOWN/attempt journal missing')
    spec = importlib.util.spec_from_file_location('monitor.issue_tracker_global_attempt_journal', SOURCE)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    # Match Python's normal canonical import: dependent journals must not
    # retain a package alias pointing at an older owner/token registry.
    import monitor
    monitor.issue_tracker_global_attempt_journal = module
    return module


def unit(**changes):
    from monitor.issue_tracker_send_unit import freeze_send_unit
    args = inputs(); args.update(changes); return freeze_send_unit(**args)


class Req7GlobalAttemptJournalTests(unittest.TestCase):
    def test_original_wire_claim_requires_actual_both_owners_before_any_dispatch_store(self):
        self.assertTrue(hasattr(self.module,'_hold_counted_original_wire'),'durable single-use original WIRE handoff missing')
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.module.prepare_global_unit(token,binding(),self.value)
            self.module.record_global_attempt_intent(token,binding(),self.value)
            retained = {p.name:p.read_bytes() for p in self.store.iterdir()}
            with mock.patch.object(self.module,'_create_folder') as creating:
                with self.assertRaises(self.module.GlobalAttemptHold) as caught:
                    with self.module._hold_counted_original_wire(None,token,binding(),self.value): self.fail('no writer')
                creating.assert_not_called()
            self.assertIsNone(caught.exception.__context__)
            self.assertEqual(retained,{p.name:p.read_bytes() for p in self.store.iterdir()})

    def setUp(self):
        self.owner = load_owner(); self.module = load()
        self.temp = tempfile.TemporaryDirectory(prefix='req7-global-unknown-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.locks = self.root / 'var/lib/http-ztp-container/issue-tracker'
        self.locks.mkdir(parents=True, mode=0o700); self.value = unit()
        self.store = self.locks / (hashlib.sha256(TARGET.encode()).hexdigest() + '.journal')

    def test_owned_counter_rejects_unissued_reads_before_protected_chain(self):
        from types import SimpleNamespace
        self.assertTrue(hasattr(self.module, 'record_owned_receipted_attempt_intent'),
                        'fresh original read gates must precede protected C6 count')
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.module.prepare_global_unit(token,binding(),self.value)
            forged = SimpleNamespace(status=200,complete=True,data=b'{}')
            options = dict(qualified_source=None,store=None,writer_token=None,settings=None,
                           whitelist_snapshot=SimpleNamespace(whitelist=None),expected_template_sha256='a'*64,
                           http_root=self.root,whitelist_path=self.root/'not-a-template',
                           identity_response=forged,headers_response=forged,
                           whitelist_response=forged,metadata_response=forged)
            with mock.patch.object(self.module,'record_receipted_original_attempt_intent') as protected:
                with self.assertRaises(self.module.GlobalAttemptHold) as caught:
                    self.module.record_owned_receipted_attempt_intent(token,binding(),self.value,**options)
                protected.assert_not_called()
            self.assertIsNone(caught.exception.__context__)
            self.assertEqual(0,self.module.inspect_global_unit(token,binding(),self.value).attempt_count)

    def test_continuous_counter_refuses_unissued_history_before_any_intent(self):
        from types import SimpleNamespace
        self.assertTrue(hasattr(self.module,'record_continuous_owned_attempt_intent'),
                        'ALL live business/History continuity must dominate original count')
        forged = SimpleNamespace(status=200,complete=True,data=b'{}')
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.module.prepare_global_unit(token,binding(),self.value)
            with mock.patch.object(self.module,'record_owned_receipted_attempt_intent') as counting:
                with self.assertRaises(self.module.GlobalAttemptHold) as caught:
                    self.module.record_continuous_owned_attempt_intent(token,binding(),self.value,
                        writer_token=None,identity_response=forged,history_response=forged,business_reads=(),
                        qualified_source=None,store=None,settings=None,whitelist_snapshot=None,
                        expected_template_sha256='a'*64,http_root=self.root,whitelist_path=self.root/'absent',
                        headers_response=forged,whitelist_response=forged,metadata_response=forged)
                counting.assert_not_called()
            self.assertIsNone(caught.exception.__context__)
            self.assertEqual(0,self.module.inspect_global_unit(token,binding(),self.value).attempt_count)

    def test_action_wire_and_header_are_immutable_before_six_global_unknown_intents(self):
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.module.prepare_global_unit(token, binding(), self.value)
            first = self.module.inspect_global_unit(token, binding(), self.value)
            self.assertEqual((0, 'UNATTEMPTED_OBSERVATION'), (first.attempt_count, first.outcome))
            self.assertEqual(self.value.action_preimage, (self.store / 'ACTION-PREIMAGE').read_bytes())
            self.assertEqual(self.value.wire_bytes, (self.store / 'WIRE').read_bytes())
            header = json.loads((self.store / 'HEADER').read_bytes())
            self.assertEqual({'schema_version': 1, 'spreadsheet_id': TARGET, 'allowlist_sha256': 'a' * 64,
                              'policy_sha256': 'b' * 64, 'unit_id': self.value.unit_id,
                              'action_digest': self.value.action_digest, 'wire_sha256': self.value.wire_sha256}, header)
            for count in range(1, 7):
                record = self.module.record_global_attempt_intent(token, binding(), self.value)
                self.assertEqual((count, 'UNKNOWN'), (record.attempt_count, record.outcome))
                self.assertFalse(hasattr(record, 'permit')); self.assertFalse(hasattr(record, 'send_once'))
            with self.assertRaises(self.module.GlobalAttemptHold): self.module.record_global_attempt_intent(token, binding(), self.value)
            self.assertEqual(6, self.module.inspect_global_unit(token, binding(), self.value).attempt_count)

    def test_unknown_blocks_every_new_generation_publish_and_sheet_not_only_same_project(self):
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.module.prepare_global_unit(token, binding(), self.value)
            self.module.record_global_attempt_intent(token, binding(), self.value)
        for changes in ({'generation_id': 'f' * 64}, {'publish_id': 'f' * 64}, {'sheet_id': 18}):
            with self.subTest(changes=tuple(changes)), fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
                before = {p.name: p.read_bytes() for p in self.store.iterdir()}
                with self.assertRaises(self.module.GlobalAttemptHold): self.module.prepare_global_unit(token, binding(), unit(**changes))
                with self.assertRaises(self.module.GlobalAttemptHold): self.module.record_global_attempt_intent(token, binding(), unit(**changes))
                self.assertEqual(before, {p.name: p.read_bytes() for p in self.store.iterdir()})

    def test_initialization_marker_never_precedes_all_eight_image_barriers(self):
        real_fsync = os.fsync; observed = []
        def syncing(fd):
            observed.append(set(os.listdir(self.store)) if self.store.exists() else set())
            real_fsync(fd)
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            with mock.patch('os.fsync', side_effect=syncing): self.module.prepare_global_unit(token, binding(), self.value)
            self.assertEqual(10, len(observed))
            self.assertTrue(all('INITIALIZED' not in names for names in observed[:9]))
            self.assertEqual({'ACTION-PREIMAGE', 'WIRE', 'HEADER'}, observed[7])
            self.assertEqual({'ACTION-PREIMAGE', 'WIRE', 'HEADER', 'INITIALIZED'}, observed[9])
            marker = json.loads((self.store / 'INITIALIZED').read_bytes())
            self.assertEqual({'schema_version': 1, 'state': 'INITIALIZED',
                'header_sha256': hashlib.sha256((self.store / 'HEADER').read_bytes()).hexdigest()}, marker)
            (self.store / 'INITIALIZED').rename(self.root / 'preserved-marker')
            with self.assertRaises(self.module.GlobalAttemptHold): self.module.record_global_attempt_intent(token, binding(), self.value)
            self.assertFalse((self.store / 'ATTEMPT-1').exists())

    def test_revoked_owner_target_or_binding_change_cannot_reset_retarget_or_increment(self):
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.module.prepare_global_unit(token, binding(), self.value)
        with fixture(self.root), self.assertRaises(self.module.GlobalAttemptHold): self.module.record_global_attempt_intent(token, binding(), self.value)
        for changed in (replace(binding(), policy_sha256='f' * 64), replace(binding(), allowlist_sha256='f' * 64)):
            with fixture(self.root), self.owner.spreadsheet_owner(changed) as fresh:
                with self.assertRaises(self.module.GlobalAttemptHold): self.module.record_global_attempt_intent(fresh, changed, self.value)
        with fixture(self.root), self.owner.spreadsheet_owner(binding(TARGET + '_other')) as other:
            with self.assertRaises(self.module.GlobalAttemptHold): self.module.prepare_global_unit(other, binding(TARGET + '_other'), self.value)
        self.assertFalse((self.store / 'ATTEMPT-1').exists())

    def test_changed_bytes_missing_chain_or_extra_record_never_repair_unknown(self):
        for fault in ('action', 'wire', 'header', 'attempt', 'hole', 'foreign'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix='req7-global-tamper-') as directory:
                root = Path(directory).resolve(); locks = root / 'var/lib/http-ztp-container/issue-tracker'; locks.mkdir(parents=True, mode=0o700)
                store = locks / self.store.name
                with fixture(root), self.owner.spreadsheet_owner(binding()) as token:
                    self.module.prepare_global_unit(token, binding(), self.value)
                    self.module.record_global_attempt_intent(token, binding(), self.value)
                    self.module.record_global_attempt_intent(token, binding(), self.value)
                    if fault == 'hole': (store / 'ATTEMPT-1').rename(root / 'preserved')
                    elif fault == 'foreign': (store / 'foreign').write_bytes(b'unknown')
                    else:
                        name = {'action': 'ACTION-PREIMAGE', 'wire': 'WIRE', 'header': 'HEADER', 'attempt': 'ATTEMPT-2'}[fault]
                        (store / name).write_bytes(b'foreign')
                    before = {p.name: p.read_bytes() for p in store.iterdir()}
                    with self.assertRaises(self.module.GlobalAttemptHold): self.module.record_global_attempt_intent(token, binding(), self.value)
                    self.assertEqual(before, {p.name: p.read_bytes() for p in store.iterdir()})

    def test_partial_creation_barriers_preserve_store_and_never_adopt_it(self):
        real_fsync = os.fsync
        # Folder parent+folder (2), then file+folder for each of the three
        # immutable images (6): eight independently required barriers.
        for boundary in range(1, 9):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory(prefix='req7-global-barrier-') as directory:
                root = Path(directory).resolve(); locks = root / 'var/lib/http-ztp-container/issue-tracker'; locks.mkdir(parents=True, mode=0o700)
                store = locks / self.store.name
                with fixture(root), self.owner.spreadsheet_owner(binding()) as token:
                    calls = []
                    def failing(fd):
                        calls.append(fd)
                        if len(calls) == boundary: raise OSError('synthetic private fault')
                        return real_fsync(fd)
                    with mock.patch('os.fsync', side_effect=failing), self.assertRaises(self.module.GlobalAttemptHold):
                        self.module.prepare_global_unit(token, binding(), self.value)
                    self.assertTrue(store.is_dir()); self.assertFalse((store / 'ATTEMPT-1').exists())
                    with self.assertRaises(self.module.GlobalAttemptHold): self.module.prepare_global_unit(token, binding(), self.value)
                    with self.assertRaises(self.module.GlobalAttemptHold): self.module.record_global_attempt_intent(token, binding(), self.value)
                    self.assertFalse((store / 'ATTEMPT-1').exists())
                    self.assertNotIn('synthetic private fault', str(self.module.GlobalAttemptHold()))

    def test_symlink_hardlink_and_directory_displacement_are_not_adopted(self):
        for fault in ('symlink', 'hardlink', 'directory', 'mode'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix='req7-global-alias-') as directory:
                root = Path(directory).resolve(); locks = root / 'var/lib/http-ztp-container/issue-tracker'; locks.mkdir(parents=True, mode=0o700)
                store = locks / self.store.name
                with fixture(root), self.owner.spreadsheet_owner(binding()) as token:
                    self.module.prepare_global_unit(token, binding(), self.value)
                    if fault == 'directory': store.rename(locks / 'preserved'); store.mkdir(mode=0o700)
                    elif fault == 'mode': (store / 'WIRE').chmod(0o644)
                    else:
                        (store / 'WIRE').rename(root / 'preserved')
                        if fault == 'symlink': (store / 'WIRE').symlink_to(root / 'preserved')
                        else: os.link(root / 'preserved', store / 'WIRE')
                    with self.assertRaises(self.module.GlobalAttemptHold): self.module.record_global_attempt_intent(token, binding(), self.value)
                    self.assertFalse((store / 'ATTEMPT-1').exists())

    def test_forged_incoherent_unit_cannot_create_store_and_errors_remain_sanitized(self):
        for bad in (None, replace(self.value, action_digest='f' * 64), replace(self.value, wire_bytes=b'foreign')):
            with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
                with self.assertRaises(self.module.GlobalAttemptHold) as caught: self.module.prepare_global_unit(token, binding(), bad)
                self.assertEqual('req7_global_attempt_unproved', str(caught.exception)); self.assertIsNone(caught.exception.__context__)
            self.assertFalse(self.store.exists())

    def test_manifest_real_multiscript_workflow_and_real_env_card_are_registered(self):
        manifest = json.loads((ROOT / 'test_cases/script_test_manifest.json').read_text())
        source = 'monitor/issue_tracker_global_attempt_journal.py'; test = 'test_cases.test_req7_global_attempt_journal'
        self.assertEqual(source, manifest['scripts'].get(source))
        self.assertTrue(any(source in rule['paths'] and test in rule['tests'] for rule in manifest['test_rules']))
        self.assertTrue(any({source, 'monitor/issue_tracker_spreadsheet_owner.py', 'monitor/issue_tracker_send_intent.py',
                             'monitor/issue_tracker_local_commit.py'} <= set(rule['members']) and test in rule['tests']
                            for rule in manifest['workflows']))
        card = (ROOT / 'test_cases/REAL_ENVIRONMENT.md').read_text(); start = card.index('## TC-REAL-REQ7-GLOBAL-ATTEMPT-001')
        end = card.find('\n## ', start + 1); card = card[start:] if end < 0 else card[start:end]
        for value in ('NOT RUN / REAL_ENV REQUIRED', '前置条件', '证据', '清理', 'UNKNOWN', '六次意图', '真实尝试'):
            self.assertIn(value, card)


class Req7GlobalAttemptJournalWorkflowTests(unittest.TestCase):
    setUp = Req7GlobalAttemptJournalTests.setUp

    @contextmanager
    def counted_wire_owners(self):
        from test_cases.test_req7_history_read_launcher import Req7HistoryReadLauncherWorkflowTests as native
        self.root = self.root/'owned-claim-boundary'; self.root.mkdir()
        self.locks = self.root/'var/lib/http-ztp-container/issue-tracker'
        self.store = self.locks/(hashlib.sha256(TARGET.encode()).hexdigest()+'.journal')
        with ExitStack() as stack:
            _local,_owner,writer,sheet_token,target,_credential,_config = native.owners(self,stack,target_id=TARGET)
            self.module.prepare_global_unit(sheet_token,target,self.value)
            self.module.record_global_attempt_intent(sheet_token,target,self.value)
            yield writer,sheet_token,target

    def test_wire_metadata_drift_holds_but_closes_its_original_owned_descriptor(self):
        with self.counted_wire_owners() as (writer,token,target):
            with self.assertRaises(self.module.GlobalAttemptHold):
                with self.module._hold_counted_original_wire(writer,token,target,self.value) as image:
                    os.chmod(self.store/'WIRE',0o400)
            # Rejecting mutable metadata must not leak the still-owned inode FD.
            try:
                with self.assertRaises(OSError): os.fstat(image.fd)
            finally:
                try: os.close(image.fd)
                except OSError: pass
            dispatch = self.locks/(hashlib.sha256(TARGET.encode()).hexdigest()+'.dispatch')
            self.assertEqual('CONSUMED_UNKNOWN_NOT_SEND_PROOF',json.loads((dispatch/'CLAIM-1').read_bytes())['outcome'])
            self.assertTrue((self.store/'ATTEMPT-1').is_file())
            self.assertFalse((self.store/'ATTEMPT-2').exists())

    def test_violated_wire_borrow_never_closes_a_foreign_reused_descriptor(self):
        foreign = os.open(self.root/'foreign-owned',os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
        self.addCleanup(os.close,foreign)
        with self.counted_wire_owners() as (writer,token,target):
            with self.assertRaises(self.module.GlobalAttemptHold):
                with self.module._hold_counted_original_wire(writer,token,target,self.value) as image:
                    os.close(image.fd); os.dup2(foreign,image.fd)
            try:
                self.assertEqual(os.fstat(foreign).st_ino,os.fstat(image.fd).st_ino)
            finally: os.close(image.fd)
            self.assertEqual(1,self.module.inspect_global_unit(token,target,self.value).attempt_count)
            with self.assertRaises(self.module.GlobalAttemptHold):
                with self.module._hold_counted_original_wire(writer,token,target,self.value): self.fail('violated borrow resurrected')

    def test_claim_barrier_failure_cannot_yield_or_resurrect_a_consumed_original_count(self):
        from monitor import issue_tracker_local_commit as local
        with self.counted_wire_owners() as (writer,token,target):
            original = {p.name:p.read_bytes() for p in self.store.iterdir()}
            writing = local._write_new
            def failed_barrier(folder,name,data):
                writing(folder,name,data)
                if name == 'CLAIM-1': raise OSError('owned interruption after durable claim')
            with mock.patch.object(local,'_write_new',side_effect=failed_barrier):
                with self.assertRaises(self.module.GlobalAttemptHold) as caught:
                    with self.module._hold_counted_original_wire(writer,token,target,self.value): self.fail('unconfirmed claim yielded')
            self.assertIsNone(caught.exception.__context__)
            self.assertEqual(original,{p.name:p.read_bytes() for p in self.store.iterdir()})
            with self.assertRaises(self.module.GlobalAttemptHold):
                with self.module._hold_counted_original_wire(writer,token,target,self.value): self.fail('consumed interrupted claim retried')

    def test_counted_handoff_borrows_original_action_fd_not_a_rebuilt_or_current_source_image(self):
        with self.counted_wire_owners() as (writer,token,target):
            with self.module._hold_counted_original_wire(writer,token,target,self.value) as image:
                self.assertTrue(hasattr(image,'action_fd'),'isolated handoff needs held original ACTION, not recompilation')
                self.assertEqual((self.store/'ACTION-PREIMAGE').stat().st_ino,os.fstat(image.action_fd).st_ino)
                self.assertEqual(self.value.action_preimage,os.pread(image.action_fd,1024*1024+1,0))
                self.assertFalse(os.get_inheritable(image.action_fd))
            with self.assertRaises(OSError): os.fstat(image.action_fd)

    def test_cold_process_claim_consumes_original_once_and_never_rebuilds_or_recounts(self):
        with self.counted_wire_owners() as (_writer,_token,target):
            original = {p.name:p.read_bytes() for p in self.store.iterdir()}
        command = [sys.executable,'-B',str(Path(__file__).resolve()),'--owned-wire-claim',str(self.root),str(ROOT)]
        raw = json.dumps(vars(target),sort_keys=True,separators=(',',':')).encode()
        first = subprocess.run(command,input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(0,first.returncode,first.stderr)
        self.assertEqual(b'1 '+self.value.wire_sha256.encode()+b'\n',first.stdout)
        second = subprocess.run(command,input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(3,second.returncode,second.stderr); self.assertEqual(b'held\n',second.stdout)
        self.assertEqual(original,{p.name:p.read_bytes() for p in self.store.iterdir()})

    def test_actual_dual_owner_original_wire_claim_is_once_per_durable_count_and_survives_cold_owner(self):
        self.assertTrue(hasattr(self.module,'_hold_counted_original_wire'),'durable original WIRE claim missing')
        from contextlib import ExitStack
        from test_cases.test_req7_history_read_launcher import Req7HistoryReadLauncherWorkflowTests as native
        from test_cases.test_req7_spreadsheet_owner import scoped_fixture
        from monitor import issue_tracker_local_commit as local
        # The native dual-owner fixture provisions its own fixed state root.
        self.root = self.root/'owned-wire-workflow'; self.root.mkdir()
        self.locks = self.root/'var/lib/http-ztp-container/issue-tracker'
        self.store = self.locks/(hashlib.sha256(TARGET.encode()).hexdigest()+'.journal')
        with ExitStack() as stack:
            _local,owner,writer,sheet_token,target,_credential,_config = native.owners(self,stack,target_id=TARGET)
            # Use this test's matching literal binding in both original stores;
            # target's actual policy hash differs from binding()'s fixture hash.
            self.module.prepare_global_unit(sheet_token,target,self.value)
            before = {p.name:p.read_bytes() for p in self.store.iterdir()}
            with self.assertRaises(self.module.GlobalAttemptHold):
                with self.module._hold_counted_original_wire(writer,sheet_token,target,self.value): self.fail('unattempted')
            self.assertEqual(before,{p.name:p.read_bytes() for p in self.store.iterdir()})
            for count in range(1,7):
                self.module.record_global_attempt_intent(sheet_token,target,self.value)
                with self.module._hold_counted_original_wire(writer,sheet_token,target,self.value) as image:
                    self.assertEqual((count,self.value.wire_sha256),(image.attempt_count,image.wire_sha256))
                    self.assertEqual(self.value.wire_bytes,os.pread(image.fd,1024*1024+1,0))
                    self.assertFalse(os.get_inheritable(image.fd)); self.assertFalse(hasattr(image,'permit'))
                    with self.assertRaises(self.module.GlobalAttemptHold):
                        with self.module._hold_counted_original_wire(writer,sheet_token,target,self.value): self.fail('duplicate claim')
                with self.assertRaises(OSError): os.fstat(image.fd)
            self.assertEqual((6,'UNKNOWN'),(self.module.inspect_global_unit(sheet_token,target,self.value).attempt_count,
                                           self.module.inspect_global_unit(sheet_token,target,self.value).outcome))
            saved_target = target
        # A fresh ownership acquisition cannot resurrect consumed count 6.
        project = self.root/'project'; publication = project/'publication'
        with local.writer_owner(project,publication) as writer:
            with scoped_fixture(self.root,self.owner),self.owner.spreadsheet_owner(saved_target) as sheet_token:
                with self.assertRaises(self.module.GlobalAttemptHold):
                    with self.module._hold_counted_original_wire(writer,sheet_token,saved_target,self.value): self.fail('cold reuse')


    def test_six_native_cold_process_intents_share_one_global_count_and_new_unit_is_blocked(self):
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.module.prepare_global_unit(token, binding(), self.value)
        # A cold owner/count test, not isolated-interpreter transport proof.
        # Inherit the runner's dependency environment; -I discards both its
        # authenticated PYTHONPATH and ordinary local PyYAML installation.
        command = [sys.executable, '-B', str(Path(__file__).resolve()), '--owned-retry', str(self.root), str(ROOT)]
        for count in range(1, 7):
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            self.assertEqual(0, result.returncode, result.stderr); self.assertEqual(('%d UNKNOWN\n' % count).encode(), result.stdout)
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(3, result.returncode, result.stderr); self.assertEqual(b'held\n', result.stdout)
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.assertEqual(6, self.module.inspect_global_unit(token, binding(), self.value).attempt_count)
            with self.assertRaises(self.module.GlobalAttemptHold): self.module.prepare_global_unit(token, binding(), unit(publish_id='f' * 64))

    def test_actual_c6_action_journal_and_global_count_match_without_send_or_completion(self):
        from monitor.issue_tracker_local_commit import create_local_commit_store, writer_owner
        from monitor.issue_tracker_send_intent import prepare_send_intent, record_compiled_attempt_intent, inspect_send_intent
        project = self.root / 'project'; project.mkdir(mode=0o700); pub = project / 'publication'; pub.mkdir(mode=0o700)
        create_local_commit_store(project, pub)
        with writer_owner(project, pub) as local_token:
            prepare_send_intent(local_token, self.value)
            with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
                self.module.prepare_global_unit(token, binding(), self.value)
                global_record = self.module.record_global_attempt_intent(token, binding(), self.value)
            local_record = record_compiled_attempt_intent(local_token, self.value)
            self.assertEqual((1, 'UNKNOWN'), (global_record.attempt_count, global_record.outcome))
            self.assertEqual(local_record.wire_sha256, global_record.wire_sha256)
            self.assertEqual(1, inspect_send_intent(local_token, self.value).attempt_count)
        # Two records alone are NOT one atomic transition or an actual send.
        self.assertTrue((project / '.tracker/remote-attempts' / self.value.unit_id / 'ATTEMPT-1').exists())


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--owned-wire-claim':
        from monitor import issue_tracker_local_commit as local
        from monitor.issue_tracker_online_target import OnlineTargetBinding
        from test_cases.test_req7_spreadsheet_owner import scoped_fixture
        owner = load_owner(); module = load(); root = Path(sys.argv[2]); value = unit()
        target = OnlineTargetBinding(**json.loads(sys.stdin.buffer.read(16385)))
        try:
            with local.writer_owner(root/'project',root/'project/publication') as writer:
                with scoped_fixture(root,owner),owner.spreadsheet_owner(target) as token:
                    with module._hold_counted_original_wire(writer,token,target,value) as image:
                        if os.pread(image.fd,1024*1024+1,0) != value.wire_bytes: raise AssertionError('original differs')
                        os.write(1,('%d %s\n'%(image.attempt_count,image.wire_sha256)).encode())
        except module.GlobalAttemptHold:
            os.write(1,b'held\n'); raise SystemExit(3)
    elif len(sys.argv) > 1 and sys.argv[1] == '--owned-retry':
        owner = load_owner(); module = load()
        try:
            with fixture(Path(sys.argv[2])), owner.spreadsheet_owner(binding()) as token:
                record = module.record_global_attempt_intent(token, binding(), unit())
                os.write(1, ('%d UNKNOWN\n' % record.attempt_count).encode())
        except module.GlobalAttemptHold:
            os.write(1, b'held\n'); raise SystemExit(3)
    else: unittest.main()
