"""Independent durable nonrecursive action/wire binding; no send authority."""
import hashlib
from dataclasses import replace
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import test_cases
MAIN = Path(test_cases.__file__).resolve().parents[1]
from monitor.issue_tracker_local_commit import create_local_commit_store, writer_owner
from test_cases.test_req7_send_unit import inputs


def freeze_send_unit(**kwargs):
    # Existing isolated contract loaders reload this canonical module between
    # cases; bind the owning module at the call, not a stale constructor class.
    from monitor.issue_tracker_send_unit import freeze_send_unit as compile_unit
    return compile_unit(**kwargs)

SOURCE = Path(__file__).resolve().parents[1] / 'monitor/issue_tracker_send_intent.py'


def load():
    if not SOURCE.is_file(): raise AssertionError('durable compiled action/wire binding missing')
    spec = importlib.util.spec_from_file_location('monitor.issue_tracker_send_intent', SOURCE)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module); return module


class Req7SendIntentDirectTests(unittest.TestCase):
    def setUp(self):
        self.module = load(); self.temp = tempfile.TemporaryDirectory(prefix='req7-private-action-')
        self.addCleanup(self.temp.cleanup); self.project = Path(self.temp.name).resolve()
        self.pub = self.project / 'publication'; self.pub.mkdir(mode=0o700)
        create_local_commit_store(self.project, self.pub); self.unit = freeze_send_unit(**inputs())

    def test_actual_local_generation_and_receipt_identity_survive_composer_and_intent(self):
        from monitor.issue_tracker_local_commit import begin_generation, record_intent, commit
        args = inputs()
        with writer_owner(self.project, self.pub) as token:
            generation = begin_generation(token, args['manifest'])
            record_intent(token, generation, b'private fixture publication, not online authority')
            receipt = commit(token, generation)
            args.update(generation_id=generation.generation_id, publish_id=receipt.published_sha256)
            unit = freeze_send_unit(**args)
            actual = self.module.prepare_send_intent(token, unit)
            self.assertEqual(0, actual.attempt_count)
            action = json.loads((self.project / '.tracker/remote-actions' / unit.unit_id / 'ACTION-PREIMAGE').read_bytes())
            self.assertEqual(generation.generation_id, action['identity']['generation_id'])
            self.assertEqual(receipt.published_sha256, action['identity']['publish_id'])
            self.assertEqual(1, self.module.record_compiled_attempt_intent(token, unit).attempt_count)
            self.assertFalse(hasattr(actual, 'permit'))
        program = '''import sys
from pathlib import Path
from test_cases.test_req7_send_unit import inputs
from monitor.issue_tracker_send_unit import freeze_send_unit
from monitor.issue_tracker_local_commit import writer_owner
from monitor.issue_tracker_send_intent import record_compiled_attempt_intent
args = inputs(); args.update(generation_id=sys.argv[3], publish_id=sys.argv[4])
unit = freeze_send_unit(**args)
with writer_owner(Path(sys.argv[1]), Path(sys.argv[2])) as owner:
    observed = record_compiled_attempt_intent(owner, unit)
    print(observed.attempt_count, observed.outcome)
'''
        child = subprocess.run([sys.executable, '-B', '-c', program, str(self.project), str(self.pub),
            generation.generation_id, receipt.published_sha256], cwd=MAIN,
            env={**os.environ, 'PYTHONPYCACHEPREFIX': '/tmp/http-test-pyc'}, capture_output=True, text=True, timeout=15)
        self.assertEqual(0, child.returncode, child.stderr)
        self.assertEqual('2 UNKNOWN\n', child.stdout)
        self.assertEqual(unit.wire_bytes, (self.project / '.tracker/remote-attempts' / unit.unit_id / 'WIRE').read_bytes())

    def test_action_preimage_and_explicit_digest_are_durable_before_first_attempt(self):
        with writer_owner(self.project, self.pub) as token:
            observation = self.module.prepare_send_intent(token, self.unit)
            self.assertEqual(0, observation.attempt_count); self.assertEqual('UNATTEMPTED_OBSERVATION', observation.outcome)
            self.assertEqual(self.unit.action_digest, observation.action_digest)
            action = self.project / '.tracker/remote-actions' / self.unit.unit_id
            self.assertEqual(self.unit.action_preimage, (action / 'ACTION-PREIMAGE').read_bytes())
            header = json.loads((action / 'HEADER').read_bytes())
            self.assertEqual({'schema_version': 1, 'unit_id': self.unit.unit_id,
                              'action_digest': self.unit.action_digest, 'wire_sha256': self.unit.wire_sha256}, header)
            self.assertEqual(0o600, (action / 'ACTION-PREIMAGE').stat().st_mode & 0o777)
            for count in range(1, 7):
                result = self.module.record_compiled_attempt_intent(token, self.unit)
                self.assertEqual(count, result.attempt_count); self.assertEqual('UNKNOWN', result.outcome)
                self.assertEqual(self.unit.action_digest, result.action_digest)
                self.assertFalse(hasattr(result, 'permit'))
            with self.assertRaises(self.module.SendIntentHold): self.module.record_compiled_attempt_intent(token, self.unit)

    def test_changed_action_header_or_wire_keeps_evidence_and_never_increments(self):
        for fault in ('action', 'header', 'wire'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix='req7-action-tamper-') as directory:
                project = Path(directory).resolve(); pub = project / 'publication'; pub.mkdir(mode=0o700)
                create_local_commit_store(project, pub)
                with writer_owner(project, pub) as token:
                    self.module.prepare_send_intent(token, self.unit)
                    folder = project / '.tracker/remote-actions' / self.unit.unit_id
                    if fault == 'wire': path = project / '.tracker/remote-attempts' / self.unit.unit_id / 'WIRE'
                    else: path = folder / ('HEADER' if fault == 'header' else 'ACTION-PREIMAGE')
                    path.write_bytes(b'foreign'); before = path.read_bytes()
                    with self.assertRaises(self.module.SendIntentHold): self.module.record_compiled_attempt_intent(token, self.unit)
                    self.assertEqual(before, path.read_bytes())
                    self.assertFalse((project / '.tracker/remote-attempts' / self.unit.unit_id / 'ATTEMPT-1').exists())

    def test_symlink_hardlink_nonprivate_or_foreign_namespace_cannot_be_adopted(self):
        for fault in ('symlink', 'hardlink', 'mode', 'extra'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix='req7-action-namespace-') as directory:
                project = Path(directory).resolve(); pub = project / 'publication'; pub.mkdir(mode=0o700)
                create_local_commit_store(project, pub)
                with writer_owner(project, pub) as token:
                    self.module.prepare_send_intent(token, self.unit)
                    folder = project / '.tracker/remote-actions' / self.unit.unit_id; path = folder / 'ACTION-PREIMAGE'
                    if fault == 'hardlink': os.link(path, project / 'foreign-alias')
                    elif fault == 'mode': path.chmod(0o644)
                    elif fault == 'extra': (folder / 'foreign').write_bytes(b'unknown')
                    else:
                        saved = project / 'preserved'; path.rename(saved); path.symlink_to(saved)
                    with self.assertRaises(self.module.SendIntentHold): self.module.record_compiled_attempt_intent(token, self.unit)
                    self.assertFalse((project / '.tracker/remote-attempts' / self.unit.unit_id / 'ATTEMPT-1').exists())

    def test_noop_inactive_owner_or_foreign_unit_cannot_create_intent_or_clear_unknown(self):
        args = inputs()
        for item in args['business']: item['observed_values'] = {'L': {'stringValue': 'down'}}
        noop = freeze_send_unit(**args)
        with writer_owner(self.project, self.pub) as token:
            with self.assertRaises(self.module.SendIntentHold): self.module.prepare_send_intent(token, noop)
            self.assertFalse((self.project / '.tracker/remote-actions').exists())
            self.module.prepare_send_intent(token, self.unit)
            with self.assertRaises(self.module.SendIntentHold): self.module.prepare_send_intent(token, self.unit)
            args = inputs(); args['publish_id'] = 'f' * 64; other = freeze_send_unit(**args)
            with self.assertRaises(self.module.SendIntentHold): self.module.prepare_send_intent(token, other)
        with self.assertRaises(self.module.SendIntentHold): self.module.record_compiled_attempt_intent(token, self.unit)

    def test_preexisting_legacy_wire_store_cannot_be_retroactively_given_action_authority(self):
        from monitor.issue_tracker_attempt_journal import prepare_unit, inspect_unit
        with writer_owner(self.project, self.pub) as token:
            prepare_unit(token, self.unit.unit_id, self.unit.wire_bytes)
            with self.assertRaises(self.module.SendIntentHold): self.module.prepare_send_intent(token, self.unit)
            self.assertFalse((self.project / '.tracker/remote-actions').exists())
            with self.assertRaises(self.module.SendIntentHold): self.module.record_compiled_attempt_intent(token, self.unit)
            self.assertEqual(0, inspect_unit(token, self.unit.unit_id, self.unit.wire_bytes).attempt_count)

    def test_failed_action_barrier_leaves_partial_evidence_without_wire_or_count(self):
        actual = self.module.local._write_new
        def fail_after_action(fd, name, raw):
            actual(fd, name, raw)
            if name == 'ACTION-PREIMAGE': raise OSError('injected action barrier failure')
        with writer_owner(self.project, self.pub) as token:
            with mock.patch.object(self.module.local, '_write_new', side_effect=fail_after_action), self.assertRaises(self.module.SendIntentHold) as caught:
                self.module.prepare_send_intent(token, self.unit)
            self.assertIsNone(caught.exception.__context__)
            path = self.project / '.tracker/remote-actions' / self.unit.unit_id / 'ACTION-PREIMAGE'
            self.assertEqual(self.unit.action_preimage, path.read_bytes())
            self.assertFalse((self.project / '.tracker/remote-attempts').exists())
            with self.assertRaises(self.module.SendIntentHold): self.module.prepare_send_intent(token, self.unit)
            with self.assertRaises(self.module.SendIntentHold): self.module.record_compiled_attempt_intent(token, self.unit)

    def test_namespace_displacement_after_intent_keeps_count_unknown_without_repair(self):
        with writer_owner(self.project, self.pub) as token:
            self.module.prepare_send_intent(token, self.unit)
            folder = self.project / '.tracker/remote-actions' / self.unit.unit_id
            preserved = folder.with_name('preserved-action')
            actual = self.module.journal.record_attempt_intent
            def displace(*args):
                result = actual(*args); folder.rename(preserved); folder.mkdir(mode=0o700)
                return result
            with mock.patch.object(self.module.journal, 'record_attempt_intent', side_effect=displace), self.assertRaises(self.module.SendIntentHold):
                self.module.record_compiled_attempt_intent(token, self.unit)
            self.assertEqual([], list(folder.iterdir()))
            self.assertEqual(self.unit.action_preimage, (preserved / 'ACTION-PREIMAGE').read_bytes())
            attempt = self.project / '.tracker/remote-attempts' / self.unit.unit_id / 'ATTEMPT-1'
            self.assertEqual('UNKNOWN', json.loads(attempt.read_bytes())['outcome'])

    def test_real_barriers_put_action_then_wire_then_count_in_physical_order(self):
        actual = self.module.local._write_new; written = []
        def observed_write(fd, name, raw):
            actual(fd, name, raw)
            written.append(name)
        with writer_owner(self.project, self.pub) as token, mock.patch.object(self.module.local, '_write_new', side_effect=observed_write):
            self.module.prepare_send_intent(token, self.unit)
            self.assertEqual(['ACTION-PREIMAGE', 'HEADER', 'WIRE', 'HEADER'], written)
            self.module.record_compiled_attempt_intent(token, self.unit)
            self.assertEqual(['ACTION-PREIMAGE', 'HEADER', 'WIRE', 'HEADER', 'ATTEMPT-1'], written)

    def test_wire_barrier_failure_preserves_action_and_cannot_manufacture_a_count(self):
        actual = self.module.local._write_new
        def fail_after_wire(fd, name, raw):
            actual(fd, name, raw)
            if name == 'WIRE': raise OSError('injected wire barrier failure')
        with writer_owner(self.project, self.pub) as token:
            with mock.patch.object(self.module.local, '_write_new', side_effect=fail_after_wire), self.assertRaises(self.module.SendIntentHold):
                self.module.prepare_send_intent(token, self.unit)
            action = self.project / '.tracker/remote-actions' / self.unit.unit_id
            wire = self.project / '.tracker/remote-attempts' / self.unit.unit_id
            self.assertEqual(self.unit.action_preimage, (action / 'ACTION-PREIMAGE').read_bytes())
            self.assertEqual(self.unit.wire_bytes, (wire / 'WIRE').read_bytes())
            self.assertFalse((wire / 'HEADER').exists())
            for method in (self.module.prepare_send_intent, self.module.inspect_send_intent, self.module.record_compiled_attempt_intent):
                with self.assertRaises(self.module.SendIntentHold): method(token, self.unit)
            self.assertFalse((wire / 'ATTEMPT-1').exists())

    def test_contradictory_frozen_projection_cannot_create_action_or_wire(self):
        variants = (replace(self.unit, outcomes=()), replace(self.unit, outcome_mapping_sha256='0' * 64),
                    replace(self.unit, fence_metadata_id=self.unit.fence_metadata_id + 1),
                    replace(self.unit, history_rows_expected=1), replace(self.unit, pending_audit_ids=('foreign',)))
        bad_history = json.loads(self.unit.wire_bytes)
        bad_history['requests'][-2]['appendCells']['rows'][0]['values'][3]['userEnteredValue']['stringValue'] = 'foreign'
        wrong_business = json.loads(self.unit.wire_bytes)
        wrong_business['requests'][0]['updateCells']['rows'][0]['values'][0]['userEnteredValue']['stringValue'] = 'different'
        for value in (bad_history, wrong_business):
            raw = (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode()
            variants += (replace(self.unit, wire_bytes=raw, wire_sha256=hashlib.sha256(raw).hexdigest()),)
        for unit in variants:
            with self.subTest(fault=variants.index(unit)), tempfile.TemporaryDirectory(prefix='req7-bad-projection-') as directory:
                project = Path(directory).resolve(); pub = project / 'publication'; pub.mkdir(mode=0o700)
                create_local_commit_store(project, pub)
                with writer_owner(project, pub) as token:
                    with self.assertRaises(self.module.SendIntentHold): self.module.prepare_send_intent(token, unit)
                    self.assertFalse((project / '.tracker/remote-actions').exists())
                    self.assertFalse((project / '.tracker/remote-attempts').exists())


class Req7SendIntentColdWorkflowTests(unittest.TestCase):
    def test_real_composer_keeps_noop_mapping_and_all_audits_in_persisted_action_and_history(self):
        module = load(); args = inputs()
        args['business'][0]['observed_values'] = {'L': {'stringValue': 'down'}}
        args['audits'] = ({'event_id': 'settings:1', 'recorded_at_utc': '2026-10-08T10:00:00Z', 'details': 'K=2'},
                          {'event_id': 'settings:2', 'recorded_at_utc': '2026-10-08T10:00:00Z', 'details': 'K=3'})
        unit = freeze_send_unit(**args)
        with tempfile.TemporaryDirectory(prefix='req7-action-audit-') as directory:
            project = Path(directory).resolve(); pub = project / 'publication'; pub.mkdir(mode=0o700)
            create_local_commit_store(project, pub)
            with writer_owner(project, pub) as token:
                module.prepare_send_intent(token, unit)
                observation = module.record_compiled_attempt_intent(token, unit)
                self.assertEqual('UNKNOWN', observation.outcome)
                self.assertEqual(1, observation.attempt_count)
                action = json.loads((project / '.tracker/remote-actions' / unit.unit_id / 'ACTION-PREIMAGE').read_bytes())
                self.assertEqual([['switch:0000', 'OBSERVED-SATISFIED-AT-READ'], ['switch:0001', 'WIRE-CANDIDATE']], action['outcomes'])
                self.assertEqual(['switch:0001'], [item['operation_id'] for item in action['business']])
                self.assertEqual(['settings:1', 'settings:2'], [item['event_id'] for item in action['audits']])
                wire = json.loads((project / '.tracker/remote-attempts' / unit.unit_id / 'WIRE').read_bytes())
                rows = wire['requests'][-2]['appendCells']['rows']
                self.assertEqual(['switch:0001', 'settings:1', 'settings:2'],
                                 [row['values'][3]['userEnteredValue']['stringValue'] for row in rows])
                self.assertEqual(3, unit.history_rows_expected)

    def test_real_composer_action_store_and_journal_cold_processes_never_reset_six(self):
        module = load(); unit = freeze_send_unit(**inputs())
        with tempfile.TemporaryDirectory(prefix='req7-action-cold-') as directory:
            project = Path(directory).resolve(); pub = project / 'publication'; pub.mkdir(mode=0o700)
            create_local_commit_store(project, pub)
            with writer_owner(project, pub) as token: module.prepare_send_intent(token, unit)
            code = """import importlib.util,pathlib,sys
sys.path.insert(0,sys.argv[1])
from monitor.issue_tracker_local_commit import writer_owner
from monitor.issue_tracker_send_unit import freeze_send_unit
from test_cases.test_req7_send_unit import inputs
spec=importlib.util.spec_from_file_location('monitor.issue_tracker_send_intent',sys.argv[2])
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
with writer_owner(pathlib.Path(sys.argv[3]),pathlib.Path(sys.argv[4])) as token:
    r=m.record_compiled_attempt_intent(token,freeze_send_unit(**inputs()))
    print(r.attempt_count,r.action_digest,r.outcome)
"""
            for expected in range(1, 7):
                # Inherit the runner's dependency environment: -I discards its
                # authenticated PYTHONPATH (and ordinary local user packages).
                # This fixture tests a cold owner/count, not Python -I isolation.
                result = subprocess.run([sys.executable, '-B', '-c', code, str(MAIN), str(SOURCE), str(project), str(pub)],
                                        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(f'{expected} {unit.action_digest} UNKNOWN\n', result.stdout)
            with writer_owner(project, pub) as token, self.assertRaises(module.SendIntentHold): module.record_compiled_attempt_intent(token, unit)


class Req7SendIntentManifestTests(unittest.TestCase):
    def test_compiled_intent_has_direct_multiscript_primary_suite_and_real_env_registration(self):
        registry = Path(__file__).resolve().parents[1]
        manifest = json.loads((registry / 'test_cases/script_test_manifest.json').read_text())
        source = 'monitor/issue_tracker_send_intent.py'; tests = 'test_cases.test_req7_send_intent'
        self.assertEqual(source, manifest['scripts'].get(source))
        self.assertTrue(any(source in rule['paths'] and tests in rule['tests'] for rule in manifest['test_rules']))
        self.assertTrue(any({source, 'monitor/issue_tracker_send_unit.py', 'monitor/issue_tracker_attempt_journal.py',
                             'monitor/issue_tracker_local_commit.py'} <= set(rule['members']) and tests in rule['tests']
                            for rule in manifest['workflows']))
        self.assertEqual(['issue-tracker-local'], [suite['id'] for suite in manifest['test_suites'] if tests in suite['tests']])
        card = (registry / 'test_cases/REAL_ENVIRONMENT.md').read_text()
        for required in ('TC-REAL-REQ7-COMPILED-SEND-INTENT-001', source, 'NOT RUN / REAL_ENV REQUIRED'):
            self.assertIn(required, card)
        self.assertIn(tests, (registry / 'test_cases/README.md').read_text())
        spec = importlib.util.spec_from_file_location('req7_action_manual', registry / 'tools/update-user-manual.py')
        manual = importlib.util.module_from_spec(spec); spec.loader.exec_module(manual)
        profile = manual.script_profile(registry, source)
        self.assertTrue(profile['direct'].startswith('否'))
        for field, required in (('environment', '未安装'), ('scenario', '非递归'), ('success', '整个 REQ7'),
                                ('success', '不授予'), ('recovery', 'HOLD'), ('example', tests)):
            self.assertIn(required, profile[field])


if __name__ == '__main__': unittest.main()
