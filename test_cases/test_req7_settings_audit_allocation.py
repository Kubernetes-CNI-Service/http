"""Actual locked C25 event -> immutable C19 unit, never remote delivery."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import importlib
from importlib import metadata as distribution_metadata
import json
import os
from pathlib import Path
import subprocess
import sys
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

    def test_pending_never_adopts_same_byte_replaced_original_settings_files(self):
        for relative in ('settings/events/0.json','settings/outbox/0.json','settings/current','INITIALIZED',
                         'settings/events','settings/outbox','settings'):
            with self.subTest(original=relative):
                case=type(self)('test_pending_projection_comes_from_exact_actual_event_and_retains_outbox'); case.setUp()
                try:
                    path=case.project/'.tracker'/relative; preserved=case.root/'preserved-settings-original'
                    validate=case.module.chain.validate_k_chain_snapshot; changed=[]
                    def validated_then_replaced(*args,**kwargs):
                        result=validate(*args,**kwargs)
                        if not changed:
                            if path.is_dir():
                                import shutil
                                path.rename(preserved); shutil.copytree(preserved,path)
                            else:
                                image=path.read_bytes(); path.rename(preserved); path.write_bytes(image); path.chmod(0o600)
                            changed.append(True)
                        return result
                    with local.writer_owner(case.project,case.publication) as writer, \
                            mock.patch.object(case.module.chain,'validate_k_chain_snapshot',side_effect=validated_then_replaced):
                        with self.assertRaises(case.module.SettingsAuditHold): case.module.pending_settings_audits(writer)
                    self.assertEqual([True],changed)
                    self.assertFalse(case.allocation.exists())
                    if path.is_dir():
                        self.assertEqual({str(p.relative_to(preserved)):p.read_bytes() for p in preserved.rglob('*') if p.is_file()},
                                         {str(p.relative_to(path)):p.read_bytes() for p in path.rglob('*') if p.is_file()})
                    else: self.assertEqual(preserved.read_bytes(),path.read_bytes())
                finally: case.doCleanups()

    def test_actual_allocation_pins_original_event_before_final_marker(self):
        value=self.unit(); native_write=local._write_new
        with self.owners() as (writer,sheet):
            self.global_journal.prepare_global_unit(sheet,binding(),value)
            path=self.project/'.tracker/settings/events/0.json'; preserved=self.root/'preserved-allocation-event'
            changed=[]
            def write_then_replace(parent,name,raw):
                result=native_write(parent,name,raw)
                if name=='ASSIGNMENTS' and not changed:
                    image=path.read_bytes(); path.rename(preserved); path.write_bytes(image); path.chmod(0o600)
                    changed.append(True)
                return result
            with mock.patch.object(local,'_write_new',side_effect=write_then_replace):
                with self.assertRaises(self.module.SettingsAuditHold):
                    self.module.prepare_settings_audit_allocation(writer,sheet,binding(),value)
            self.assertEqual([True],changed)
            self.assertFalse((self.allocation/'INITIALIZED').exists())
            # Existing independent global journal contract: no attempted wire
            # is not UNKNOWN. Rejection must leave this original zero count.
            self.assertEqual((0,'UNATTEMPTED_OBSERVATION'),(self.global_journal.inspect_global_unit(sheet,binding(),value).attempt_count,
                                            self.global_journal.inspect_global_unit(sheet,binding(),value).outcome))
            self.assertEqual(self.event0,(self.project/'.tracker/settings/events/0.json').read_bytes())

    def test_allocation_call_never_adopts_same_byte_replaced_assignment_originals(self):
        for mode in ('create','inspect'):
            for name in ('HEADER','ASSIGNMENTS','INITIALIZED','SETTINGS-AUDIT-ALLOCATED'):
                with self.subTest(mode=mode,original=name):
                    case=type(self)('test_pending_projection_comes_from_exact_actual_event_and_retains_outbox'); case.setUp()
                    try:
                        value=case.unit()
                        with case.owners() as (writer,sheet):
                            case.global_journal.prepare_global_unit(sheet,binding(),value)
                            if mode=='inspect':
                                case.module.prepare_settings_audit_allocation(writer,sheet,binding(),value)
                            path=(case.project/'.tracker'/name if name=='SETTINGS-AUDIT-ALLOCATED'
                                  else case.allocation/name)
                            preserved=case.root/'preserved-assignment-original'
                            synchronize=case.module._sync_marker; changed=[]; retained=[]
                            def synchronize_then_replace(*args,**kwargs):
                                result=synchronize(*args,**kwargs)
                                if not changed:
                                    retained.append(case.image())
                                    image=path.read_bytes(); before=path.stat().st_ino
                                    path.rename(preserved); path.write_bytes(image); path.chmod(0o600)
                                    self.assertNotEqual(before,path.stat().st_ino)
                                    changed.append(True)
                                return result
                            operation=(case.module.prepare_settings_audit_allocation if mode=='create'
                                       else case.module.inspect_settings_audit_allocation)
                            with mock.patch.object(case.module,'_sync_marker',side_effect=synchronize_then_replace):
                                with self.assertRaises(case.module.SettingsAuditHold):
                                    operation(writer,sheet,binding(),value)
                            self.assertEqual([True],changed)
                            self.assertEqual(preserved.read_bytes(),path.read_bytes())
                            self.assertEqual(retained,[case.image()],'HOLD must not repair or remove retained evidence')
                            self.assertEqual((0,'UNATTEMPTED_OBSERVATION'),
                                (case.global_journal.inspect_global_unit(sheet,binding(),value).attempt_count,
                                 case.global_journal.inspect_global_unit(sheet,binding(),value).outcome))
                            self.assertEqual(['0.json'],sorted(p.name for p in (case.project/'.tracker/settings/outbox').iterdir()))
                    finally: case.doCleanups()

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

    def test_count_scope_pins_all_originals_and_preserves_zero_or_durable_unknown(self):
        self.assertTrue(hasattr(self.module, '_hold_counted_audit_originals'),
                        'original C25 identity must remain held across the durable counter')
        for counted in (False, True):
            for relative in ('settings/events/0.json','settings/outbox/0.json','settings/current','INITIALIZED',
                             'settings-audit-allocation/HEADER','settings-audit-allocation/ASSIGNMENTS',
                             'settings-audit-allocation/INITIALIZED','SETTINGS-AUDIT-ALLOCATED'):
                with self.subTest(counted=counted,original=relative):
                    case=type(self)('test_pending_projection_comes_from_exact_actual_event_and_retains_outbox'); case.setUp()
                    try:
                        value=case.unit()
                        with case.owners() as (writer,sheet):
                            case.prepare(writer,sheet,value)
                            before=case.image(); path=case.project/'.tracker'/relative
                            raw=path.read_bytes(); inode=path.stat().st_ino
                            preserved=case.root/'owned-original-count-scope'
                            with self.assertRaises(case.module.SettingsAuditHold):
                                with case.module._hold_counted_audit_originals(writer,sheet,binding(),value) as verify:
                                    verify()
                                    if counted: case.global_journal.record_global_attempt_intent(sheet,binding(),value)
                                    path.rename(preserved); path.write_bytes(raw); path.chmod(0o600)
                                    verify()
                            self.assertNotEqual(inode,path.stat().st_ino)
                            self.assertEqual(raw,preserved.read_bytes()); self.assertEqual(raw,path.read_bytes())
                            self.assertEqual(before,case.image(),'rejection must not repair retained originals')
                            actual=case.global_journal.inspect_global_unit(sheet,binding(),value)
                            self.assertEqual((1,'UNKNOWN') if counted else (0,'UNATTEMPTED_OBSERVATION'),
                                             (actual.attempt_count,actual.outcome))
                            self.assertEqual(['0.json'],sorted(p.name for p in (case.project/'.tracker/settings/outbox').iterdir()))
                    finally: case.doCleanups()

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

    def test_disappeared_entire_allocation_folder_cannot_be_recreated_at_count_zero(self):
        value = self.unit()
        with self.owners() as (writer, sheet):
            self.prepare(writer, sheet, value)
            self.allocation.rename(self.root/'preserved-original-allocation')
            before = self.image()
            with self.assertRaises(self.module.SettingsAuditHold):
                self.module.prepare_settings_audit_allocation(writer, sheet, binding(), value)
            self.assertEqual(before, self.image()); self.assertFalse(self.allocation.exists())
            self.assertEqual(0, self.global_journal.inspect_global_unit(sheet, binding(), value).attempt_count)

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

    def test_all_eight_witness_and_pre_marker_barrier_failures_leave_unadoptable_evidence(self):
        native_fsync = os.fsync
        for boundary in range(1, 9):
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
                        # Independent physical order: two witness barriers,
                        # then mkdir parent/folder, then both evidence files.
                        self.assertEqual(boundary >= 3, case.allocation.is_dir())
                        self.assertFalse((case.allocation/'INITIALIZED').exists())
                        self.assertTrue((case.project/'.tracker/SETTINGS-AUDIT-ALLOCATED').exists()
                            or any(p.name.startswith('.pending-') for p in (case.project/'.tracker').iterdir()))
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

    def test_marker_follows_eight_witness_image_barriers_and_inspection_sync_failure_holds(self):
        value = self.unit(); native_fsync = os.fsync; observed = []
        with self.owners() as (writer, sheet):
            self.global_journal.prepare_global_unit(sheet, binding(), value)
            def fsync(fd):
                observed.append(set(os.listdir(self.allocation)) if self.allocation.exists() else set())
                return native_fsync(fd)
            with mock.patch.object(self.module.os, 'fsync', side_effect=fsync):
                self.module.prepare_settings_audit_allocation(writer, sheet, binding(), value)
            self.assertEqual(13, len(observed))
            self.assertTrue(all('INITIALIZED' not in row for row in observed[:8]))
            self.assertEqual({'HEADER', 'ASSIGNMENTS'}, observed[7])
            before = self.image()
            with mock.patch.object(self.module.os, 'fsync', side_effect=OSError('owned re-sync failure')):
                with self.assertRaises(self.module.SettingsAuditHold):
                    self.module.inspect_settings_audit_allocation(writer, sheet, binding(), value)
            self.assertEqual(before, self.image())

    def test_missing_corrupt_or_linked_external_witness_never_authorizes_or_repairs(self):
        for fault in ('missing', 'corrupt', 'alias'):
            with self.subTest(fault=fault):
                case = type(self)('test_pending_projection_comes_from_exact_actual_event_and_retains_outbox'); case.setUp()
                try:
                    value = case.unit()
                    with case.owners() as (writer, sheet):
                        case.prepare(writer, sheet, value)
                        witness = case.project/'.tracker/SETTINGS-AUDIT-ALLOCATED'
                        witness.rename(case.root/'preserved-witness')
                        if fault == 'corrupt': witness.write_bytes(b'foreign'); witness.chmod(0o600)
                        elif fault == 'alias': witness.symlink_to(case.root/'preserved-witness')
                        before = case.image()
                        with self.assertRaises(case.module.SettingsAuditHold):
                            case.module.inspect_settings_audit_allocation(writer, sheet, binding(), value)
                        with self.assertRaises(case.module.SettingsAuditHold):
                            case.module.prepare_settings_audit_allocation(writer, sheet, binding(), value)
                        self.assertEqual(before, case.image())
                finally: case.doCleanups()

    def test_real_cold_process_reopens_original_allocated_audit_and_unknown_count(self):
        value = self.unit()
        with self.owners() as (writer, sheet):
            self.prepare(writer, sheet, value)
            self.global_journal.record_global_attempt_intent(sheet, binding(), value)
            expected = hashlib.sha256((self.allocation/'ASSIGNMENTS').read_bytes()).hexdigest()
        before = self.image()
        # -I must remain isolated. Add ONLY the measured installed PyYAML
        # distribution root at this owned fixture boundary, not user-site or
        # a production fallback/installation/interpreter identity assertion.
        yaml_root = Path(distribution_metadata.distribution('PyYAML').locate_file('')).resolve(strict=True)
        child = '''import sys, pathlib, hashlib
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools",sys.argv[3]]
from monitor import issue_tracker_local_commit as local, issue_tracker_settings_audit_allocation as audit
from monitor import issue_tracker_spreadsheet_owner as owner, issue_tracker_global_attempt_journal as journal
from test_cases.test_req7_spreadsheet_owner import scoped_fixture, binding
from test_cases.test_req7_send_unit import inputs, load
root=pathlib.Path(sys.argv[2]); project=root/"project"
with local.writer_owner(project, project/"99-output-monitor") as writer, scoped_fixture(root,owner), owner.spreadsheet_owner(binding()) as sheet:
    args=inputs(); args["audits"]=audit.pending_settings_audits(writer)
    unit=load().freeze_send_unit(**args)
    original=audit.inspect_settings_audit_allocation(writer,sheet,binding(),unit)
    state=journal.inspect_global_unit(sheet,binding(),unit)
    assert (state.attempt_count,state.outcome)==(1,"UNKNOWN")
    print(hashlib.sha256(original).hexdigest())
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', child, str(ROOT), str(self.root), str(yaml_root)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=ROOT, timeout=10, env={'LC_ALL': 'C', 'PYTHONPYCACHEPREFIX': '/tmp/http-test-pyc'})
        self.assertEqual(0, result.returncode, result.stderr.decode('utf-8', 'replace'))
        self.assertEqual((expected+'\n').encode(), result.stdout); self.assertEqual(before, self.image())


if __name__ == '__main__': unittest.main()
