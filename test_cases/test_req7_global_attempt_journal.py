"""Independent global UNKNOWN barriers and native cold-process intent limits."""
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

if len(sys.argv) > 1 and sys.argv[1] == '--owned-retry':
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
    if len(sys.argv) > 1 and sys.argv[1] == '--owned-retry':
        owner = load_owner(); module = load()
        try:
            with fixture(Path(sys.argv[2])), owner.spreadsheet_owner(binding()) as token:
                record = module.record_global_attempt_intent(token, binding(), unit())
                os.write(1, ('%d UNKNOWN\n' % record.attempt_count).encode())
        except module.GlobalAttemptHold:
            os.write(1, b'held\n'); raise SystemExit(3)
    else: unittest.main()
