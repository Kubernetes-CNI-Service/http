"""Actual locked C25 event -> immutable C19 unit, never remote delivery."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import importlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from monitor import issue_tracker_k_store as settings
from monitor import issue_tracker_local_commit as local
from test_cases.test_req7_send_unit import inputs, canonical, load as load_composer
from test_cases.test_req7_spreadsheet_owner import scoped_fixture, binding

ROOT = Path(__file__).resolve().parents[1]
MODULE = 'monitor.issue_tracker_settings_audit_allocation'


def load():
    if not (ROOT / 'monitor/issue_tracker_settings_audit_allocation.py').is_file():
        raise AssertionError('actual settings audit allocation missing')
    module = importlib.import_module(MODULE)
    # Other native workflow fixtures deliberately reload canonical registries.
    # Match current package identity; never relax production owner checks.
    from monitor import issue_tracker_global_attempt_journal, issue_tracker_spreadsheet_owner
    module.global_journal = issue_tracker_global_attempt_journal
    module.ownership = issue_tracker_spreadsheet_owner
    return module


class Req7SettingsAuditAllocationTests(unittest.TestCase):
    def setUp(self):
        self.module = load()
        self.composer = load_composer()
        from monitor import issue_tracker_spreadsheet_owner as owner
        from monitor import issue_tracker_global_attempt_journal as global_journal
        self.owner, self.global_journal = owner, global_journal
        self.temp = tempfile.TemporaryDirectory(prefix='req7-settings-allocate-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.project = self.root / 'project'; self.project.mkdir(mode=0o700)
        self.publication = self.project / '99-output-monitor'; self.publication.mkdir(mode=0o700)
        local.create_local_commit_store(self.project, self.publication)
        self.locks = self.root / 'var/lib/http-ztp-container/issue-tracker'
        self.locks.mkdir(parents=True, mode=0o700)
        self.allocation = self.project / '.tracker/settings-audit-allocation'
        with local.writer_owner(self.project, self.publication) as token:
            settings.initialize_local_k_store(self.project / '.tracker', token=token,
                initialized_at='2026-10-08T10:00:00Z', acquisition_id='first-use')
        # Independently authored revision-zero oracle, not implementation output.
        payload = {'new_k': 3, 'actor': 'system:default', 'expected_revision': None, 'request_id': 'first-use'}
        self.event0 = canonical({'schema_version': 1, 'revision': 0, 'type': 'init', 'old_k': None,
            'new_k': 3, 'actor': 'system:default', 'recorded_at': '2026-10-08T10:00:00Z',
            'request_id': 'first-use', 'payload_sha256': hashlib.sha256(canonical(payload)).hexdigest(),
            'predecessor_sha256': None})
        self.audit0 = {'event_id': 'settings:0:' + hashlib.sha256(self.event0).hexdigest(),
            'recorded_at_utc': '2026-10-08T10:00:00Z', 'details': self.event0.decode().rstrip('\n')}

    @contextmanager
    def owners(self):
        with local.writer_owner(self.project, self.publication) as writer, scoped_fixture(self.root, self.owner), self.owner.spreadsheet_owner(binding()) as sheet:
            yield writer, sheet

    def unit(self, audits=None, **changes):
        args = inputs(); args.update(audits=(deepcopy(self.audit0),) if audits is None else audits)
        args.update(changes)
        return self.composer.freeze_send_unit(**args)

    def prepare(self, writer, sheet, value):
        self.global_journal.prepare_global_unit(sheet, binding(), value)
        return self.module.prepare_settings_audit_allocation(writer, sheet, binding(), value)

    def image(self):
        return {str(p.relative_to(self.project)): p.read_bytes()
                for p in (self.project / '.tracker').rglob('*') if p.is_file()}

    def test_pending_projection_comes_from_exact_actual_event_and_retains_outbox(self):
        before = self.image()
        with local.writer_owner(self.project, self.publication) as writer:
            actual = self.module.pending_settings_audits(writer)
            self.assertEqual((self.audit0,), actual)
            actual[0]['details'] = 'caller-mutated-return'
            self.assertEqual((self.audit0,), self.module.pending_settings_audits(writer))
        self.assertEqual(before, self.image()); self.assertFalse(self.allocation.exists())

    def test_real_settings_composer_global_intents_keep_allocation_and_new_event_pending(self):
        value = self.unit()
        with self.owners() as (writer, sheet):
            self.prepare(writer, sheet, value)
            assignments = (self.allocation / 'ASSIGNMENTS').read_bytes()
            self.assertEqual([{'revision': 0, 'event_sha256': hashlib.sha256(self.event0).hexdigest(),
                'audit': self.audit0}], json.loads(assignments))
            original = self.image()
            for count in range(1, 7):
                self.assertEqual(assignments, self.module.inspect_settings_audit_allocation(writer, sheet, binding(), value))
                result = self.global_journal.record_global_attempt_intent(sheet, binding(), value)
                self.assertEqual((count, 'UNKNOWN'), (result.attempt_count, result.outcome))
                self.assertEqual(original, self.image())
            settings.apply_local_k_change(self.project / '.tracker', token=writer, new_k=4,
                actor='operator:fixture', recorded_at='2026-10-08T10:01:00Z', request_id='change-1', expected_revision=0)
            self.assertEqual(assignments, self.module.inspect_settings_audit_allocation(writer, sheet, binding(), value))
            pending = self.module.pending_settings_audits(writer)
            self.assertEqual(2, len(pending)); self.assertEqual(self.audit0, pending[0])
            self.assertEqual('2026-10-08T10:01:00Z', pending[1]['recorded_at_utc'])
            self.assertEqual(6, self.global_journal.inspect_global_unit(sheet, binding(), value).attempt_count)
            self.assertEqual(['0.json', '1.json'], sorted(p.name for p in (self.project / '.tracker/settings/outbox').iterdir()))
        # Fresh lock period must inspect originals, not an in-memory allocation.
        with self.owners() as (writer, sheet):
            self.assertEqual(assignments, self.module.inspect_settings_audit_allocation(writer, sheet, binding(), value))
            with self.assertRaises(self.module.SettingsAuditHold):
                self.module.prepare_settings_audit_allocation(writer, sheet, binding(), value)
            with self.assertRaises(self.module.SettingsAuditHold):
                self.module.inspect_settings_audit_allocation(writer, sheet, binding(), self.unit(publish_id='f'*64))

    def test_unassigned_or_forged_audit_rows_cannot_allocate(self):
        for field, bad in (('event_id', 'invented-event'), ('details', '{}'),
                           ('recorded_at_utc', '2026-10-08T10:00:01Z')):
            with self.subTest(field=field):
                audit = {**self.audit0, field: bad}; value = self.unit((audit,))
                case = type(self)('test_pending_projection_comes_from_exact_actual_event_and_retains_outbox'); case.setUp()
                try:
                    with case.owners() as (writer, sheet):
                        # Coherent caller-frozen rows DO have a global original;
                        # reject actual event mismatch, not merely missing WIRE.
                        case.global_journal.prepare_global_unit(sheet, binding(), value)
                        before = case.image()
                        with self.assertRaises(case.module.SettingsAuditHold):
                            case.module.prepare_settings_audit_allocation(writer, sheet, binding(), value)
                        self.assertEqual(before, case.image()); self.assertFalse(case.allocation.exists())
                finally: case.doCleanups()
        self.assertFalse(self.allocation.exists())

    def test_noop_and_audit_only_never_allocate_or_consume_pending(self):
        args = inputs()
        noop_business = tuple({**item, 'observed_values': {'L': {'stringValue': 'down'}}} for item in args['business'])
        for value in (self.unit(business=noop_business), self.unit(audits=()),
                      self.composer.freeze_send_unit(**{**inputs(0), 'audits': (self.audit0,)})):
            with self.owners() as (writer, sheet):
                if value.outcome == 'WIRE-CANDIDATE': self.global_journal.prepare_global_unit(sheet, binding(), value)
                else: self.assertEqual('NO_SEND', value.outcome)
                before = self.image()
                with self.assertRaises(self.module.SettingsAuditHold):
                    self.module.prepare_settings_audit_allocation(writer, sheet, binding(), value)
                self.assertEqual(before, self.image())
        self.assertFalse(self.allocation.exists())

    def test_attempted_unit_cannot_create_late_allocation(self):
        value = self.unit()
        with self.owners() as (writer, sheet):
            self.global_journal.prepare_global_unit(sheet, binding(), value)
            self.global_journal.record_global_attempt_intent(sheet, binding(), value)
            before = self.image()
            with self.assertRaises(self.module.SettingsAuditHold):
                self.module.prepare_settings_audit_allocation(writer, sheet, binding(), value)
            self.assertEqual(before, self.image()); self.assertFalse(self.allocation.exists())

    def test_revoked_project_and_spreadsheet_owners_do_not_create_or_repair(self):
        value = self.unit()
        with self.owners() as (writer, sheet):
            self.prepare(writer, sheet, value)
        before = self.image()
        for operation in (self.module.prepare_settings_audit_allocation, self.module.inspect_settings_audit_allocation):
            with self.assertRaises(self.module.SettingsAuditHold) as caught:
                operation(writer, sheet, binding(), value)
            self.assertEqual('req7_settings_audit_unproved', str(caught.exception))
            self.assertIsNone(caught.exception.__context__)
        with self.assertRaises(self.module.SettingsAuditHold): self.module.pending_settings_audits(writer)
        self.assertEqual(before, self.image())

    def test_missing_outbox_allocation_and_corrupt_original_stop_without_repair(self):
        for fault in ('outbox', 'event', 'assignments', 'marker', 'foreign', 'alias'):
            with self.subTest(fault=fault):
                # Use separate native stores for every destructive fixture fault.
                case = type(self)('test_pending_projection_comes_from_exact_actual_event_and_retains_outbox'); case.setUp()
                try:
                    value = case.unit()
                    with case.owners() as (writer, sheet):
                        case.prepare(writer, sheet, value)
                        if fault == 'foreign': (case.allocation / 'foreign').write_bytes(b'foreign')
                        else:
                            path = {'outbox': case.project / '.tracker/settings/outbox/0.json',
                                'event': case.project / '.tracker/settings/events/0.json',
                                'assignments': case.allocation / 'ASSIGNMENTS',
                                'marker': case.allocation / 'INITIALIZED', 'alias': case.allocation / 'HEADER'}[fault]
                            path.rename(case.root / 'preserved')
                            if fault == 'event': path.write_bytes(b'foreign'); path.chmod(0o600)
                            if fault == 'alias': path.symlink_to(case.root / 'preserved')
                        before = case.image()
                        with self.assertRaises(case.module.SettingsAuditHold):
                            case.module.inspect_settings_audit_allocation(writer, sheet, binding(), value)
                        self.assertEqual(before, case.image())
                        self.assertEqual(0, case.global_journal.inspect_global_unit(sheet, binding(), value).attempt_count)
                finally: case.doCleanups()

    def test_all_six_pre_marker_barrier_failures_leave_unadoptable_evidence(self):
        native_fsync = os.fsync
        for boundary in range(1, 7):
            with self.subTest(boundary=boundary):
                case = type(self)('test_pending_projection_comes_from_exact_actual_event_and_retains_outbox'); case.setUp()
                try:
                    value = case.unit()
                    with case.owners() as (writer, sheet):
                        case.global_journal.prepare_global_unit(sheet, binding(), value)
                        calls = []
                        def fsync(fd):
                            calls.append(fd)
                            if len(calls) == boundary: raise OSError('owned allocation barrier fault')
                            return native_fsync(fd)
                        with mock.patch.object(case.module.os, 'fsync', side_effect=fsync), self.assertRaises(case.module.SettingsAuditHold):
                            case.module.prepare_settings_audit_allocation(writer, sheet, binding(), value)
                        self.assertTrue(case.allocation.is_dir()); self.assertFalse((case.allocation/'INITIALIZED').exists())
                        before = case.image()
                        with self.assertRaises(case.module.SettingsAuditHold): case.module.inspect_settings_audit_allocation(writer, sheet, binding(), value)
                        with self.assertRaises(case.module.SettingsAuditHold): case.module.prepare_settings_audit_allocation(writer, sheet, binding(), value)
                        self.assertEqual(before, case.image())
                        self.assertEqual(0, case.global_journal.inspect_global_unit(sheet, binding(), value).attempt_count)
                finally: case.doCleanups()

    def test_attempt_drift_before_marker_never_promotes_partial_allocation(self):
        value = self.unit(); native_write = local._write_new
        with self.owners() as (writer, sheet):
            self.global_journal.prepare_global_unit(sheet, binding(), value)
            def write(parent, name, raw):
                native_write(parent, name, raw)
                if name == 'ASSIGNMENTS': self.global_journal.record_global_attempt_intent(sheet, binding(), value)
            with mock.patch.object(local, '_write_new', side_effect=write), self.assertRaises(self.module.SettingsAuditHold):
                self.module.prepare_settings_audit_allocation(writer, sheet, binding(), value)
            self.assertFalse((self.allocation/'INITIALIZED').exists())
            self.assertEqual((1, 'UNKNOWN'), (self.global_journal.inspect_global_unit(sheet, binding(), value).attempt_count,
                self.global_journal.inspect_global_unit(sheet, binding(), value).outcome))

    def test_manifest_has_actual_multiscript_workflow_and_real_env_not_run(self):
        manifest = json.loads((ROOT / 'test_cases/script_test_manifest.json').read_text())
        source = 'monitor/issue_tracker_settings_audit_allocation.py'; test = 'test_cases.test_req7_settings_audit_allocation'
        self.assertEqual(source, manifest['scripts'].get(source))
        self.assertTrue(any(source in row['paths'] and test in row['tests'] for row in manifest['test_rules']))
        required = {source, 'monitor/issue_tracker_k_store.py', 'monitor/issue_tracker_k_chain.py',
            'monitor/issue_tracker_local_commit.py', 'monitor/issue_tracker_send_unit.py',
            'monitor/issue_tracker_global_attempt_journal.py', 'monitor/issue_tracker_spreadsheet_owner.py'}
        self.assertTrue(any(required <= set(row['members']) and test in row['tests'] for row in manifest['workflows']))
        self.assertIn('settings-audit-allocation', (ROOT / 'test_cases/REAL_ENVIRONMENT.md').read_text())

    def test_marker_follows_six_image_barriers_and_inspection_sync_failure_holds(self):
        value = self.unit(); native_fsync = os.fsync; observed = []
        with self.owners() as (writer, sheet):
            self.global_journal.prepare_global_unit(sheet, binding(), value)
            def fsync(fd):
                observed.append(set(os.listdir(self.allocation)) if self.allocation.exists() else set())
                return native_fsync(fd)
            with mock.patch.object(self.module.os, 'fsync', side_effect=fsync):
                self.module.prepare_settings_audit_allocation(writer, sheet, binding(), value)
            self.assertEqual(11, len(observed))
            self.assertTrue(all('INITIALIZED' not in row for row in observed[:6]))
            self.assertEqual({'HEADER', 'ASSIGNMENTS'}, observed[5])
            before = self.image()
            with mock.patch.object(self.module.os, 'fsync', side_effect=OSError('owned re-sync failure')):
                with self.assertRaises(self.module.SettingsAuditHold):
                    self.module.inspect_settings_audit_allocation(writer, sheet, binding(), value)
            self.assertEqual(before, self.image())


if __name__ == '__main__': unittest.main()
