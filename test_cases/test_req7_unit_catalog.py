"""Durable multiple pending originals under ONE real shared OS owner.

This is not complete inventory, original C6, APPLIED, admission or sending.
"""
from contextlib import ExitStack, contextmanager
from dataclasses import replace, asdict
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.test_req7_spreadsheet_owner import load as load_owner, scoped_fixture, binding, TARGET
from test_cases.test_req7_global_attempt_journal import unit, original_read_files
from test_cases.test_req7_send_unit import inputs as send_inputs
from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx

SOURCE = Path(__file__).resolve().parents[1] / 'monitor/issue_tracker_unit_catalog.py'
STEM = hashlib.sha256(TARGET.encode()).hexdigest()


def load(*, reset_dependencies=True):
    if not SOURCE.is_file():
        raise AssertionError('original multi-unit pending catalog is absent')
    if reset_dependencies:
        load_owner()
    # Keep the actual canonical local registry shared by preimported C6/K/
    # send-intent consumers. Reloading it splits ordinary full-discovery
    # function imports from new opaque owners, rather than isolating a test.
    # Each test still creates its own project, original owners and cleanup.
    global_source = SOURCE.with_name('issue_tracker_global_attempt_journal.py')
    if reset_dependencies and global_source.exists():
        spec = importlib.util.spec_from_file_location('monitor.issue_tracker_global_attempt_journal', global_source)
        global_module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = global_module
        spec.loader.exec_module(global_module)
        import monitor
        monitor.issue_tracker_global_attempt_journal = global_module
    spec = importlib.util.spec_from_file_location('monitor.issue_tracker_unit_catalog', SOURCE)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    import monitor
    monitor.issue_tracker_unit_catalog = module
    return module


def load_component(name):
    """Canonical source selection only, never substitute an owner or proof."""
    spec = importlib.util.spec_from_file_location('monitor.' + name, SOURCE.with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    import monitor
    setattr(monitor, name, module)
    return module


class CatalogNativeAuditAssignmentTests(unittest.TestCase):
    def test_same_literal_event_in_two_original_projects_is_not_a_duplicate(self):
        module=load(reset_dependencies=False);seen=set()
        unit=SimpleNamespace(unit_id='a'*64,action_preimage=module.local._canonical({'audits':[{'event_id':'literal-event-0'}]}))
        module._check_native_audit_assignments(seen,unit,{'unit_id':unit.unit_id,'project_identity':[7,101]})
        module._check_native_audit_assignments(seen,unit,{'unit_id':unit.unit_id,'project_identity':[7,102]})
        self.assertEqual({(7,101,'literal-event-0'),(7,102,'literal-event-0')},seen)

    def test_same_original_project_event_in_second_unit_refuses_without_mutating_seen(self):
        module=load(reset_dependencies=False);seen=set()
        first=SimpleNamespace(unit_id='a'*64,action_preimage=module.local._canonical({'audits':[{'event_id':'literal-event-0'}]}))
        second=SimpleNamespace(unit_id='b'*64,action_preimage=module.local._canonical({'audits':[{'event_id':'literal-event-0'}]}))
        module._check_native_audit_assignments(seen,first,{'unit_id':first.unit_id,'project_identity':[7,101]})
        with self.assertRaises(module.UnitCatalogHold):
            module._check_native_audit_assignments(seen,second,{'unit_id':second.unit_id,'project_identity':[7,101]})
        self.assertEqual({(7,101,'literal-event-0')},seen)


class CatalogOriginalFirstStatCleanupTests(unittest.TestCase):
    def test_written_image_handoff_uses_first_identity_without_reopening_or_adopting(self):
        module=load(reset_dependencies=False)
        self.assertTrue(callable(getattr(module._Originals,'_written_file',None)),
            'first writer identity must be handed to the original graph')
        with tempfile.TemporaryDirectory(prefix='req7-first-written-graph-') as temporary:
            root=Path(temporary); parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            held=module._Originals(); raw=b'independent first-written bytes\n'
            try:
                written=module.local._write_new(parent,'HEADER',raw,_return_original=True)
                (root/'HEADER').rename(root/'preserved'); (root/'HEADER').write_bytes(raw); (root/'HEADER').chmod(0o600)
                with mock.patch.object(module.os,'open',side_effect=AssertionError('must not reopen replacement')):
                    with self.assertRaises((module.UnitCatalogHold,module.journal.AttemptJournalHold)):
                        held._written_file(parent,'HEADER',written,raw,16384)
                self.assertEqual(written[0],held.files[0][2])
                self.assertEqual(written[1],held.files[0][3])
                self.assertEqual(raw,(root/'preserved').read_bytes())
                self.assertNotEqual((root/'HEADER').stat().st_ino,written[1][1])
            finally:
                held.close(); os.close(parent)

    def test_graph_finalizer_interrupt_closes_all_other_owned_originals(self):
        module=load(reset_dependencies=False)
        with tempfile.TemporaryDirectory(prefix='req7-original-graph-interrupt-') as temporary:
            root=Path(temporary);(root/'folder').mkdir(mode=0o700)
            for name in ('first','second'):
                (root/name).write_bytes((name+' original\n').encode());(root/name).chmod(0o600)
            parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY);held=module._Originals();owned=[]
            native_close=module._close_original;primary=KeyboardInterrupt('actual original graph finalizer')
            reached=[]
            def close(descriptor,identity):
                native_close(descriptor,identity)
                if not reached:reached.append(descriptor);raise primary
            try:
                owned.append(held.directory(parent,'folder'))
                for name in ('first','second'):
                    held.file(parent,name,64);owned.append(held.files[-1][2])
                with mock.patch.object(module,'_close_original',side_effect=close):
                    with self.assertRaises(KeyboardInterrupt) as caught:held.close()
                self.assertIs(primary,caught.exception);self.assertEqual(1,len(reached))
                for descriptor in owned:
                    closed=False
                    try:os.fstat(descriptor)
                    except OSError as exc:closed=exc.errno==9
                    self.assertTrue(closed,'one interrupt bypassed another owned graph original')
            finally:
                for descriptor in owned+[parent]:
                    try:os.close(descriptor)
                    except OSError:pass

    def exercise(self, *, directory):
        module = load(reset_dependencies=False)
        with tempfile.TemporaryDirectory(prefix='req7-original-first-stat-') as temporary:
            root = Path(temporary)
            (root/'folder').mkdir(mode=0o700)
            (root/'file').write_bytes(b'independent original image')
            (root/'file').chmod(0o600)
            parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            held = module._Originals(); opened = []; fired = []; native_stat = os.fstat
            native_open = os.open; native_directory = module.local._directory
            failure = OSError('owned original first stat fault')
            def open_file(name, *args, **kwargs):
                fd = native_open(name, *args, **kwargs)
                if name == 'file': opened.append(fd)
                return fd
            def open_directory(*args, **kwargs):
                fd = native_directory(*args, **kwargs); opened.append(fd); return fd
            def first_stat(fd):
                if opened and fd == opened[0] and not fired:
                    fired.append(True); raise failure
                return native_stat(fd)
            try:
                with mock.patch.object(module.os, 'open', side_effect=open_file), \
                        mock.patch.object(module.local, '_directory', side_effect=open_directory), \
                        mock.patch.object(module.os, 'fstat', side_effect=first_stat):
                    with self.assertRaises(OSError) as caught:
                        if directory: held.directory(parent, 'folder')
                        else: held.file(parent, 'file', 64)
                    self.assertIs(failure, caught.exception)
                    held.close()
                self.assertEqual([True], fired); self.assertEqual(1, len(opened))
                closed = False
                try: native_stat(opened[0])
                except OSError as exc: closed = exc.errno == 9
                self.assertTrue(closed, 'just-opened original FD leaked on its first fstat failure')
                self.assertEqual(b'independent original image', (root/'file').read_bytes())
            finally:
                for fd in opened:
                    try: os.close(fd)
                    except OSError: pass
                os.close(parent)

    def test_real_file_open_first_stat_failure_closes_owned_fd(self):
        self.exercise(directory=False)

    def test_real_directory_open_first_stat_failure_closes_owned_fd(self):
        self.exercise(directory=True)

    def exercise_reused_fd(self, *, directory):
        module = load(reset_dependencies=False)
        with tempfile.TemporaryDirectory(prefix='req7-original-reused-fd-') as temporary:
            root = Path(temporary)
            for name in ('folder', 'foreign-folder'):
                (root/name).mkdir(mode=0o700)
            (root/'file').write_bytes(b'independent original image')
            (root/'foreign-file').write_bytes(b'independent foreign image')
            for name in ('file', 'foreign-file'): (root/name).chmod(0o600)
            parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            foreign = os.open(root/('foreign-folder' if directory else 'foreign-file'),
                              os.O_RDONLY | (os.O_DIRECTORY if directory else 0))
            native_stat = os.fstat; native_open = os.open; native_list = os.listdir
            native_directory = module.local._directory
            expected = native_stat(foreign)
            held = module._Originals(); opened = []; fired = []
            failure = OSError('original acquisition slot replaced by foreign inode')
            def open_file(name, *args, **kwargs):
                fd = native_open(name, *args, **kwargs)
                if name == 'file': opened.append(fd)
                return fd
            def open_directory(*args, **kwargs):
                fd = native_directory(*args, **kwargs); opened.append(fd); return fd
            def replace_slot(fd):
                fired.append(True)
                os.dup2(foreign, fd)
                raise failure
            def first_stat(fd):
                if not directory and opened and fd == opened[0] and not fired:
                    replace_slot(fd)
                return native_stat(fd)
            def first_list(fd):
                if directory and opened and fd == opened[0] and not fired:
                    replace_slot(fd)
                return native_list(fd)
            try:
                with mock.patch.object(module.os, 'open', side_effect=open_file), \
                        mock.patch.object(module.local, '_directory', side_effect=open_directory), \
                        mock.patch.object(module.os, 'fstat', side_effect=first_stat), \
                        mock.patch.object(module.os, 'listdir', side_effect=first_list):
                    with self.assertRaises(OSError) as caught:
                        if directory: held.directory(parent, 'folder')
                        else: held.file(parent, 'file', 64)
                    self.assertIs(failure, caught.exception)
                    held.close()
                self.assertEqual([True], fired); self.assertEqual(1, len(opened))
                preserved = False
                try:
                    actual = native_stat(opened[0])
                    preserved = (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino)
                except OSError: pass
                self.assertTrue(preserved, 'cleanup closed a numeric FD reused for a foreign inode')
                self.assertEqual(b'independent original image', (root/'file').read_bytes())
                self.assertEqual(b'independent foreign image', (root/'foreign-file').read_bytes())
            finally:
                # Every descriptor here was opened/duplicated by this fixture.
                for fd in opened + [foreign, parent]:
                    try: os.close(fd)
                    except OSError: pass

    def test_real_file_first_stat_failure_preserves_reused_foreign_fd(self):
        self.exercise_reused_fd(directory=False)

    def test_real_directory_list_failure_preserves_reused_foreign_fd(self):
        self.exercise_reused_fd(directory=True)


class CatalogAppliedNativeWorkflowTests(unittest.TestCase):
    """Actual C6, owned TLS reads, COMPLETE/APPLIED/key pair and pending unit.

    No caller MATCHED/APPLIED label, synthetic receipt or cleared UNKNOWN.
    Native heavy tests run in an exclusive local window; normal discovery
    includes the class, with every original native timing/behavior assertion.
    """
    def all_project_applied_api(self):
        inventory = load_component('issue_tracker_retained_inventory')
        api = getattr(inventory, '_hold_all_project_applied_keys', None)
        self.assertTrue(callable(api), 'ALL real project C6 origins and counted COMPLETE/APPLIED key pairs must stay held together')
        return api

    def test_actual_all_project_applied_keys_join_distinct_c6_roots_without_comparing_local_sequences(self):
        self.all_project_applied_api()
        with self.completed_and_pending(cross_project=True) as (case, catalog, _remote, inventory, _old_api,
                writer, owner, bound, originals):
            api = inventory._hold_all_project_applied_keys
            before = original_read_files(case.root)
            handles = {token: dict(active.handles) for token, active in catalog.local._ACTIVE.items()}
            with api(owner, bound) as (observed, verify):
                self.assertEqual(originals, tuple(row.unit for row in observed))
                self.assertEqual((1, 0), tuple(row.attempt_count for row in observed))
                self.assertNotEqual(observed[0].project_identity, observed[1].project_identity)
                self.assertEqual(1, case.native_generation.sequence)
                self.assertTrue(observed[0].key_watermarks)
                self.assertEqual({1}, {sequence for _key, sequence in observed[0].key_watermarks})
                self.assertEqual((), observed[1].key_watermarks)
                self.assertFalse(any(hasattr(row, name) for row in observed for name in ('permit', 'settled', 'global_sequence')))
                verify()
            self.assertEqual(handles, {token: dict(active.handles) for token, active in catalog.local._ACTIVE.items()})
            self.assertEqual(before, original_read_files(case.root))

    def test_actual_all_project_applied_keys_foreign_pending_receipt_rebind_revokes_complete_handoff(self):
        self.all_project_applied_api()
        with self.completed_and_pending(cross_project=True) as (case, catalog, _remote, inventory, _old_api,
                writer, owner, bound, originals):
            action = json.loads(originals[1].action_preimage)
            receipt = case.root / 'other-project/.tracker/generations' / action['identity']['generation_id'] / 'RECEIPT'
            with self.assertRaises(inventory.RetainedInventoryHold):
                with inventory._hold_all_project_applied_keys(owner, bound) as (observed, verify):
                    self.assertEqual((1, 0), tuple(row.attempt_count for row in observed))
                    raw = receipt.read_bytes(); old = receipt.stat().st_ino
                    preserved = case.root / 'preserved-other-project-receipt'
                    receipt.rename(preserved); receipt.write_bytes(raw); receipt.chmod(0o600)
                    self.assertNotEqual(old, receipt.stat().st_ino)
                    verify()
            self.assertEqual(raw, receipt.read_bytes()); self.assertEqual(raw, preserved.read_bytes())

    def test_actual_all_project_applied_keys_cold_independent_process_keeps_counts_and_uses_original_proofs(self):
        self.all_project_applied_api()
        with self.completed_and_pending(cross_project=True, cold_handoff=True) as (case, catalog, _remote,
                _inventory, _old_api, _writer, _owner, bound, originals):
            before = original_read_files(case.root)
            program = '''import importlib.util,json,sys
from pathlib import Path
sys.path[:0]=[sys.argv[1],str(Path(sys.argv[1])/'tools')]
spec=importlib.util.spec_from_file_location('cold_applied_projects_test_contract',sys.argv[3])
tests=importlib.util.module_from_spec(spec);spec.loader.exec_module(tests)
catalog=tests.load();inventory=tests.load_component('issue_tracker_retained_inventory')
tests.load_component('issue_tracker_remote_history_match')
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
from monitor.issue_tracker_online_target import OnlineTargetBinding
bound=OnlineTargetBinding(**json.loads(sys.stdin.buffer.read()))
assert catalog.local._ACTIVE=={}
with scoped_fixture(Path(sys.argv[2]),catalog.ownership),catalog.ownership.spreadsheet_owner(bound) as owner:
 with inventory._hold_all_project_applied_keys(owner,bound) as (observed,verify):
  assert tuple(row.unit.unit_id for row in observed)==tuple(sys.argv[4:])
  assert tuple(row.attempt_count for row in observed)==(1,0)
  assert observed[0].project_identity!=observed[1].project_identity
  assert observed[0].key_watermarks and observed[1].key_watermarks==()
  assert all(sequence==1 for key,sequence in observed[0].key_watermarks)
  assert len(catalog.local._ACTIVE)==2 and all(active.handles=={} for active in catalog.local._ACTIVE.values())
  assert not any(hasattr(row,'permit') or hasattr(row,'settled') for row in observed)
  verify()
 assert catalog.local._ACTIVE=={}
print('COLD_DISTINCT_PROJECT_APPLIED_ORIGINALS_UNKNOWN_COUNTS_UNCHANGED')
'''
            result = subprocess.run([sys.executable, '-B', '-c', program,
                str(Path(__import__('test_cases').__file__).resolve().parents[1]), str(case.root), __file__,
                originals[0].unit_id, originals[1].unit_id], input=json.dumps(asdict(bound)).encode(),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual(b'COLD_DISTINCT_PROJECT_APPLIED_ORIGINALS_UNKNOWN_COUNTS_UNCHANGED\n', result.stdout)
            self.assertEqual(before, original_read_files(case.root))

    @contextmanager
    def completed_and_pending(self, *, reverse_catalog=False, cold_handoff=False, older_unsent=False, cross_project=False, project_origins=False):
        from test_cases import test_req7_remote_history_match as native
        catalog = load()
        case = native.Req7OwnedHistoryMatchWorkflowTests()
        case.setUp()
        try:
            remote = load_component('issue_tracker_remote_history_match')
            inventory = load_component('issue_tracker_retained_inventory')
            api = getattr(inventory, '_hold_catalog_applied_keys', None)
            self.assertTrue(callable(api), 'catalog APPLIED original join missing')
            from monitor import issue_tracker_global_attempt_journal as globals_
            original_prepare = globals_.prepare_global_unit
            actual_owners = case.owners; genuine = []; originals = []; earlier = []; bound_inputs = []
            original_begin = catalog.local.begin_generation
            def capture_owners(scope, **kwargs):
                values = actual_owners(scope, **kwargs)
                genuine.append(values[2]); bound_inputs.append(values[4]); return values
            def allocate_native(writer, manifest):
                if older_unsent:
                    # Real local generation 1 existed without an online
                    # attempt. The admitted native generation 2 is registered
                    # FIRST, before this retained old unit is indexed. This
                    # never sends generation 1 behind a later APPLIED value.
                    self.assertEqual([], earlier)
                    args = send_inputs(); bound = bound_inputs[0]
                    self.assertEqual(args['manifest'], manifest)
                    args.update(spreadsheet_id=bound.spreadsheet_id, sheet_id=101, history_sheet_id=105,
                                target_nonce='a' * 64, history_nonce='d' * 64)
                    args['business'][0]['observed_values'] = {'L': {'stringValue': 'down'}}
                    args['audits'] = ({'event_id': 'settings:001', 'recorded_at_utc': '2026-10-08T10:00:00Z', 'details': 'K=3'},)
                    old = original_begin(writer, manifest)
                    catalog.local.record_intent(writer, old, literal_xlsx(), kind='xlsx')
                    receipt = catalog.local.commit(writer, old)
                    args.update(generation_id=old.generation_id, publish_id=receipt.published_sha256)
                    earlier.append(catalog.composer.freeze_send_unit(**args))
                    self.assertEqual(1, old.sequence)
                return original_begin(writer, manifest)
            def prepare_both(token, bound, first):
                self.assertEqual([], originals)
                writer = genuine[0]
                arguments = send_inputs()
                arguments.update(spreadsheet_id=bound.spreadsheet_id, sheet_id=101, history_sheet_id=105,
                                 target_nonce='a' * 64, history_nonce='d' * 64)
                arguments['business'][0]['observed_values'] = {'L': {'stringValue': 'down'}}
                arguments['audits'] = ({'event_id': 'settings:001', 'recorded_at_utc': '2026-10-08T10:00:00Z', 'details': 'K=3'},)
                if older_unsent:
                    self.assertEqual(1, len(earlier)); second = earlier[0]
                    self.assertEqual(2, case.native_generation.sequence)
                else:
                    source = writer
                    if cross_project:
                        project = case.root / 'other-project'; project.mkdir(mode=0o700)
                        publication = project / 'publication'; publication.mkdir(mode=0o700)
                        catalog.local.create_local_commit_store(project, publication)
                        source = scope.enter_context(catalog.local.writer_owner(project, publication))
                    generation = original_begin(source, arguments['manifest'])
                    catalog.local.record_intent(source, generation, literal_xlsx(), kind='xlsx')
                    receipt = catalog.local.commit(source, generation)
                    arguments.update(generation_id=generation.generation_id, publish_id=receipt.published_sha256)
                    second = catalog.composer.freeze_send_unit(**arguments)
                    self.assertEqual(1 if cross_project else 2, generation.sequence)
                for unit_ in ((second, first) if reverse_catalog else (first, second)):
                    if cross_project or project_origins:
                        origin_writer = writer if not cross_project or unit_ == first else source
                        catalog.register_pending_c6_unit(origin_writer, token, bound, unit_)
                    else:
                        catalog.register_pending_unit(token, bound, unit_)
                for unit_ in (first, second):
                    original_prepare(token, bound, unit_)
                originals.extend((first, second))
            with ExitStack() as scope:
                # Adapt original fixture orchestration to register both actual
                # pending units BEFORE its first native attempt. All production
                # operations, genuine owner tokens and TLS assertions execute.
                with mock.patch.object(case, 'owners', side_effect=capture_owners), \
                        mock.patch.object(globals_, 'prepare_global_unit', side_effect=prepare_both), \
                        mock.patch.object(catalog.local, 'begin_generation', side_effect=allocate_native):
                    writer, owner, bound, first = case.prepare_native_completed(scope, remote)
                self.assertEqual(first, originals[0]); self.assertEqual(2, len(originals))
                remote.record_owned_applied_evidence(writer, owner, bound, first, generation=case.native_generation)
                remote.record_owned_applied_key_watermarks(writer, owner, bound, first, generation=case.native_generation)
                if cold_handoff:
                    # Finish every original context and release both real
                    # owners BEFORE an independent process acquires them.
                    scope.close()
                case.catalog_release_owners = scope.close
                yield case, catalog, remote, inventory, api, writer, owner, bound, tuple(originals)
        finally:
            case.doCleanups()

    def test_actual_applied_key_maximum_pending_sequence_and_reversed_catalog_fifo_hold(self):
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                inventory = load_component('issue_tracker_retained_inventory')
                self.assertTrue(callable(getattr(inventory, '_hold_catalog_key_order', None)),
                                'actual APPLIED keys must feed the held per-key order consumer')
                if reverse:
                    # A later C6 generation registered ahead of the first
                    # overlapping key is NOT a valid first send. Preserve the
                    # existing actual FIFO guard; test permutation-independent
                    # maximum arithmetic separately, not with a fake send.
                    reached = []
                    try:
                        with self.completed_and_pending(reverse_catalog=True) as result:
                            reached.append(result)
                    except Exception as error:
                        from monitor import issue_tracker_global_attempt_journal as actual_globals
                        self.assertIs(type(error), actual_globals.GlobalAttemptHold)
                    else:
                        self.fail('reversed pending key order admitted the first native attempt')
                    self.assertEqual([], reached)
                    continue
                with self.completed_and_pending() as (case, catalog, _remote, inventory, _old, writer, owner, bound, originals):
                    before = original_read_files(case.root)
                    handles = dict(catalog.local._owner(writer).handles)
                    with inventory._hold_catalog_key_order(writer, owner, bound) as (observed, verify):
                        project = case.root / 'project'
                        self.assertEqual((project.stat().st_dev, project.stat().st_ino), observed.project_identity)
                        self.assertEqual(((('switch', 'node0001', 'down', 'fabric'), 1),), observed.applied_maxima)
                        self.assertEqual(((originals[1].unit_id, 2, ((('switch', 'node0001', 'down', 'fabric'), 1),)),),
                                         observed.pending_keys)
                        self.assertFalse(hasattr(observed, 'permit') or hasattr(observed, 'settled'))
                        verify()
                    self.assertEqual(handles, catalog.local._owner(writer).handles)
                    self.assertEqual(before, original_read_files(case.root))

    def test_actual_key_order_consumer_keeps_applied_and_pending_originals_held(self):
        inventory = load_component('issue_tracker_retained_inventory')
        self.assertTrue(callable(getattr(inventory, '_hold_catalog_key_order', None)),
                        'key order cannot outlive its original C6/APPLIED readers')
        with self.completed_and_pending() as (case, _catalog, _remote, inventory, _old, writer, owner, bound, originals):
            target = case.root / 'project/.tracker' / ('REMOTE-KEY-HIGH-WATER-' + originals[0].unit_id)
            original = target.read_bytes(); reached = []
            with self.assertRaises(inventory.RetainedInventoryHold):
                with inventory._hold_catalog_key_order(writer, owner, bound) as (observed, verify):
                    reached.append(observed.applied_maxima)
                    target.rename(case.root / 'preserved-key-order-original')
                    target.write_bytes(original); target.chmod(0o600); verify()
            self.assertEqual([((('switch', 'node0001', 'down', 'fabric'), 1),)], reached)
            self.assertEqual(original, target.read_bytes())
            self.assertEqual(original, (case.root / 'preserved-key-order-original').read_bytes())

    def test_actual_applied_key_order_cold_process_uses_originals_without_parent_handles(self):
        inventory = load_component('issue_tracker_retained_inventory')
        self.assertTrue(callable(getattr(inventory, '_hold_catalog_key_order', None)))
        with self.completed_and_pending(cold_handoff=True) as (case, _catalog, _remote, _inventory, _api, _writer, _owner, bound, _originals):
            before = original_read_files(case.root)
            program = '''import importlib.util,json,sys
from pathlib import Path
sys.path[:0]=[sys.argv[1],str(Path(sys.argv[1])/'tools')]
spec=importlib.util.spec_from_file_location('cold_catalog_contract',sys.argv[3])
tests=importlib.util.module_from_spec(spec); spec.loader.exec_module(tests)
catalog=tests.load(); inventory=tests.load_component('issue_tracker_retained_inventory')
from monitor import issue_tracker_spreadsheet_owner as ownership,issue_tracker_global_attempt_journal as globals_
from monitor.issue_tracker_online_target import OnlineTargetBinding
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
root=Path(sys.argv[2]); bound=OnlineTargetBinding(**json.loads(sys.stdin.buffer.read()))
with catalog.local.writer_owner(root/'project',root/'project/publication') as writer,scoped_fixture(root,ownership),ownership.spreadsheet_owner(bound) as owner:
 assert catalog.local._owner(writer).handles=={}
 with inventory._hold_catalog_key_order(writer,owner,bound) as (observed,verify):
  assert observed.project_identity==(root.joinpath('project').stat().st_dev,root.joinpath('project').stat().st_ino)
  assert observed.applied_maxima==((('switch','node0001','down','fabric'),1),)
  assert tuple((sequence,keys) for _unit,sequence,keys in observed.pending_keys)==((2,((('switch','node0001','down','fabric'),1),)),)
  assert not hasattr(observed,'permit') and not hasattr(observed,'settled')
  verify()
 states=globals_.inspect_catalog_global_units(owner,bound)
 assert tuple((row.attempt_count,row.outcome) for _unit,row in states)==((1,'UNKNOWN'),(0,'UNATTEMPTED_OBSERVATION'))
 assert catalog.local._owner(writer).handles=={}
 print('catalog-key-order cold APPLIED original UNKNOWN retained')
'''
            root_source = Path(__import__('test_cases').__file__).resolve().parents[1]
            child = subprocess.run([sys.executable, '-B', '-c', program,
                str(root_source), str(case.root), str(Path(__file__))],
                input=json.dumps(asdict(bound)).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(0, child.returncode, child.stderr)
            self.assertEqual(b'catalog-key-order cold APPLIED original UNKNOWN retained\n', child.stdout)
            self.assertEqual(b'', child.stderr)
            self.assertEqual(before, original_read_files(case.root))

    def test_actual_later_applied_old_unsent_supersession_inputs_hold_all_originals(self):
        inventory = load_component('issue_tracker_retained_inventory')
        api = getattr(inventory, '_hold_catalog_unsent_supersession_inputs', None)
        self.assertTrue(callable(api), 'actual later APPLIED must dominate every key of an old UNSENT unit')
        with self.completed_and_pending(older_unsent=True) as (case, catalog, _remote, inventory, _api, writer, owner, bound, originals):
            before = original_read_files(case.root)
            handles = dict(catalog.local._owner(writer).handles)
            expected = ((originals[1].unit_id, 1, ((('switch', 'node0001', 'down', 'fabric'), 2),)),)
            with inventory._hold_catalog_unsent_supersession_inputs(writer, owner, bound) as (candidates, verify):
                self.assertEqual(expected, candidates); verify()
            self.assertEqual(before, original_read_files(case.root))
            self.assertEqual(handles, catalog.local._owner(writer).handles)
            target = case.root / 'project/.tracker' / ('REMOTE-KEY-HIGH-WATER-' + originals[0].unit_id)
            raw = target.read_bytes(); reached = []
            with self.assertRaises(inventory.RetainedInventoryHold):
                with inventory._hold_catalog_unsent_supersession_inputs(writer, owner, bound) as (candidates, verify):
                    reached.append(candidates)
                    target.rename(case.root / 'preserved-supersession-key-original')
                    target.write_bytes(raw); target.chmod(0o600); verify()
            self.assertEqual([expected], reached)
            self.assertEqual(raw, (case.root / 'preserved-supersession-key-original').read_bytes())
            self.assertEqual(raw, target.read_bytes())

    def test_original_applied_first_and_unattempted_second_are_held_without_releasing_unknown(self):
        with self.completed_and_pending() as (case, catalog, _remote, _inventory, api, writer, owner, bound, originals):
            before = original_read_files(case.root)
            handles = dict(catalog.local._owner(writer).handles)
            with api(writer, owner, bound) as (observed, verify):
                self.assertEqual(originals, tuple(row.unit for row in observed))
                self.assertEqual((1, 0), tuple(row.attempt_count for row in observed))
                self.assertEqual((((('switch', 'node0001', 'down', 'fabric'), 1),), ()),
                                 tuple(row.key_watermarks for row in observed))
                self.assertFalse(any(hasattr(row, 'permit') or hasattr(row, 'applied') for row in observed))
                verify()
            self.assertEqual(handles, catalog.local._owner(writer).handles)
            self.assertEqual(before, original_read_files(case.root))
            from monitor import issue_tracker_global_attempt_journal as globals_
            self.assertEqual(((1, 'UNKNOWN'), (0, 'UNATTEMPTED_OBSERVATION')),
                             tuple((state.attempt_count, state.outcome) for _unit, state in globals_.inspect_catalog_global_units(owner, bound)))

    def test_actual_unsent_disposition_durable_pair_and_independent_cold_replay(self):
        inventory = load_component('issue_tracker_retained_inventory')
        self.assertTrue(callable(getattr(inventory, '_record_catalog_unsent_dispositions', None)),
                        'UNSENT disposition requires a durable original pair, not a transient comparison')
        with self.completed_and_pending(older_unsent=True) as (case, catalog, _remote, inventory, _api, writer, owner, bound, originals):
            before = original_read_files(case.root)
            expected = ((originals[1].unit_id, 1, ((('switch', 'node0001', 'down', 'fabric'), 2),)),)
            self.assertEqual(expected, inventory._record_catalog_unsent_dispositions(writer, owner, bound))
            after = original_read_files(case.root)
            for name, original in before.items():
                self.assertEqual(original, after[name])
            added = set(after) - set(before)
            self.assertEqual({
                'project/.tracker/REMOTE-UNSENT-SUPERSESSION-WITNESS-' + originals[1].unit_id,
                'project/.tracker/REMOTE-UNSENT-SUPERSESSION-STARTED-' + originals[1].unit_id,
                'project/.tracker/REMOTE-UNSENT-SUPERSESSION-' + originals[1].unit_id}, added)
            with inventory._hold_catalog_unsent_dispositions(writer, owner, bound) as (seen, verify):
                self.assertEqual(expected, seen); verify()
            self.assertEqual(expected, inventory._record_catalog_unsent_dispositions(writer, owner, bound))
            self.assertEqual(after, original_read_files(case.root))
            from monitor import issue_tracker_global_attempt_journal as globals_
            self.assertEqual((1, 0), tuple(state.attempt_count for _unit, state in globals_.inspect_catalog_global_units(owner, bound)))
            # Close every real parent owner before independent process replay.
            # Metadata is only a binding selector; the child derives all proof
            # and dispositions from the fixed original namespaces.
            # Release via the fixture's own owner contexts, not token registry
            # mutation. ExitStack callback is supplied by the fixture below.
            case.catalog_release_owners()
            before = original_read_files(case.root)
            program = '''import importlib.util,json,sys
from pathlib import Path
sys.path[:0]=[sys.argv[1],str(Path(sys.argv[1])/'tools')]
spec=importlib.util.spec_from_file_location('cold_catalog_contract',sys.argv[3])
tests=importlib.util.module_from_spec(spec);spec.loader.exec_module(tests)
catalog=tests.load();inventory=tests.load_component('issue_tracker_retained_inventory')
from monitor import issue_tracker_spreadsheet_owner as ownership,issue_tracker_global_attempt_journal as globals_
from monitor.issue_tracker_online_target import OnlineTargetBinding
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
root=Path(sys.argv[2]);bound=OnlineTargetBinding(**json.loads(sys.stdin.buffer.read()))
with catalog.local.writer_owner(root/'project',root/'project/publication') as writer,scoped_fixture(root,ownership),ownership.spreadsheet_owner(bound) as owner:
 assert catalog.local._owner(writer).handles=={}
 with inventory._hold_catalog_unsent_dispositions(writer,owner,bound) as (seen,verify):
  assert seen==((sys.argv[4],1,((('switch','node0001','down','fabric'),2),)),)
  verify()
 assert tuple(state.attempt_count for _unit,state in globals_.inspect_catalog_global_units(owner,bound))==(1,0)
 assert catalog.local._owner(writer).handles=={}
 print('UNSENT original disposition cold, UNKNOWN unchanged, no permit')
'''
            root_source = Path(__import__('test_cases').__file__).resolve().parents[1]
            child = subprocess.run([sys.executable, '-B', '-c', program, str(root_source),
                str(case.root), str(Path(__file__)), originals[1].unit_id], input=json.dumps(asdict(bound)).encode(),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(0, child.returncode, child.stderr)
            self.assertEqual(b'UNSENT original disposition cold, UNKNOWN unchanged, no permit\n', child.stdout)
            self.assertEqual(b'', child.stderr); self.assertEqual(before, original_read_files(case.root))

    def test_actual_unsent_disposition_rebound_or_partial_pair_never_repairs(self):
        inventory = load_component('issue_tracker_retained_inventory')
        self.assertTrue(callable(getattr(inventory, '_record_catalog_unsent_dispositions', None)))
        for fault in ('same-bytes-new-inode', 'missing-final'):
            with self.subTest(fault=fault), self.completed_and_pending(older_unsent=True) as (case, _catalog, _remote, inventory, _api, writer, owner, bound, originals):
                inventory._record_catalog_unsent_dispositions(writer, owner, bound)
                path = case.root / 'project/.tracker' / ('REMOTE-UNSENT-SUPERSESSION-' + originals[1].unit_id)
                raw = path.read_bytes(); path.rename(case.root / 'preserved-original-unsent-disposition')
                if fault == 'same-bytes-new-inode':
                    path.write_bytes(raw); path.chmod(0o600)
                before = original_read_files(case.root)
                with self.assertRaises(inventory.RetainedInventoryHold):
                    inventory._record_catalog_unsent_dispositions(writer, owner, bound)
                with self.assertRaises(inventory.RetainedInventoryHold):
                    with inventory._hold_catalog_unsent_dispositions(writer, owner, bound):
                        self.fail('rebound or incomplete pair became durable supersession')
                self.assertEqual(before, original_read_files(case.root))
                self.assertEqual(raw, (case.root / 'preserved-original-unsent-disposition').read_bytes())

    def test_actual_unsent_disposition_second_rename_interruption_keeps_started_and_pending(self):
        inventory = load_component('issue_tracker_retained_inventory')
        self.assertTrue(callable(getattr(inventory, '_record_catalog_unsent_dispositions', None)))
        with self.completed_and_pending(older_unsent=True) as (case, _catalog, remote, inventory, _api, writer, owner, bound, originals):
            original_rename = inventory.local._rename_new; renamed = []
            def stop_second(parent, source, target):
                if target == 'REMOTE-UNSENT-SUPERSESSION-' + originals[1].unit_id:
                    raise OSError('owned representative second commit interruption')
                original_rename(parent, source, target); renamed.append(target)
            with mock.patch.object(inventory.local, '_rename_new', side_effect=stop_second), self.assertRaises(inventory.RetainedInventoryHold):
                inventory._record_catalog_unsent_dispositions(writer, owner, bound)
            tracker = case.root / 'project/.tracker'
            self.assertEqual(['REMOTE-UNSENT-SUPERSESSION-STARTED-' + originals[1].unit_id], renamed)
            self.assertFalse((tracker / ('REMOTE-UNSENT-SUPERSESSION-' + originals[1].unit_id)).exists())
            self.assertEqual(1, len(tuple(tracker.glob('.pending-*'))))
            before = original_read_files(case.root)
            with self.assertRaises(inventory.RetainedInventoryHold):
                inventory._record_catalog_unsent_dispositions(writer, owner, bound)
            self.assertEqual(before, original_read_files(case.root))

    def test_actual_unsent_disposition_both_record_images_lost_never_first_use(self):
        inventory = load_component('issue_tracker_retained_inventory')
        self.assertTrue(callable(getattr(inventory, '_record_catalog_unsent_dispositions', None)))
        with self.completed_and_pending(older_unsent=True) as (case, _catalog, _remote, inventory, _api, writer, owner, bound, originals):
            inventory._record_catalog_unsent_dispositions(writer, owner, bound)
            tracker = case.root / 'project/.tracker'
            for prefix in ('REMOTE-UNSENT-SUPERSESSION-STARTED-', 'REMOTE-UNSENT-SUPERSESSION-'):
                name = prefix + originals[1].unit_id
                (tracker / name).rename(case.root / ('preserved-' + name))
            before = original_read_files(case.root)
            with self.assertRaises(inventory.RetainedInventoryHold):
                inventory._record_catalog_unsent_dispositions(writer, owner, bound)
            with self.assertRaises(inventory.RetainedInventoryHold):
                with inventory._hold_catalog_unsent_dispositions(writer, owner, bound):
                    self.fail('loss of the entire recorded pair became first use')
            self.assertEqual(before, original_read_files(case.root))

    def test_actual_fifo_frontier_discharge_requires_original_applied_and_keeps_raw_count(self):
        inventory = load_component('issue_tracker_retained_inventory')
        self.assertTrue(callable(getattr(inventory, '_hold_catalog_fifo_frontier', None)))
        with self.completed_and_pending() as (case, catalog, _remote, inventory, _api, writer, owner, bound, originals):
            before = original_read_files(case.root)
            handles = dict(catalog.local._owner(writer).handles)
            with inventory._hold_catalog_fifo_frontier(writer, owner, bound) as (observed, verify):
                self.assertEqual((originals[0].unit_id,), observed.applied)
                self.assertEqual((originals[1].unit_id,), observed.frontier)
                self.assertEqual((), observed.superseded)
                self.assertEqual((), observed.blocked)
                self.assertFalse(hasattr(observed, 'permit') or hasattr(observed, 'settled'))
                verify()
            from monitor import issue_tracker_global_attempt_journal as globals_
            # Original count remains UNKNOWN-form journal evidence. Only
            # separately verified actual COMPLETE/APPLIED discharges FIFO.
            self.assertEqual(((1, 'UNKNOWN'), (0, 'UNATTEMPTED_OBSERVATION')),
                             tuple((row.attempt_count, row.outcome) for _unit, row in globals_.inspect_catalog_global_units(owner, bound)))
            self.assertEqual(handles, catalog.local._owner(writer).handles)
            self.assertEqual(before, original_read_files(case.root))

    def test_actual_fifo_frontier_supersession_requires_complete_original_disposition_not_maximum_alone(self):
        inventory = load_component('issue_tracker_retained_inventory')
        self.assertTrue(callable(getattr(inventory, '_hold_catalog_fifo_frontier', None)))
        with self.completed_and_pending(older_unsent=True) as (case, _catalog, _remote, inventory, _api, writer, owner, bound, originals):
            before = original_read_files(case.root)
            with self.assertRaises(inventory.RetainedInventoryHold):
                with inventory._hold_catalog_fifo_frontier(writer, owner, bound):
                    self.fail('computed later maximum silently settled UNSENT without its original record')
            self.assertEqual(before, original_read_files(case.root))
            inventory._record_catalog_unsent_dispositions(writer, owner, bound)
            recorded = original_read_files(case.root)
            with inventory._hold_catalog_fifo_frontier(writer, owner, bound) as (observed, verify):
                self.assertEqual((originals[0].unit_id,), observed.applied)
                self.assertEqual((originals[1].unit_id,), observed.superseded)
                self.assertEqual((), observed.frontier)
                self.assertEqual((), observed.blocked)
                verify()
            self.assertEqual(recorded, original_read_files(case.root))

    def test_actual_fifo_frontier_rebound_applied_pair_revokes_all_consumers(self):
        inventory = load_component('issue_tracker_retained_inventory')
        self.assertTrue(callable(getattr(inventory, '_hold_catalog_fifo_frontier', None)))
        with self.completed_and_pending() as (case, _catalog, _remote, inventory, _api, writer, owner, bound, originals):
            path = case.root / 'project/.tracker' / ('REMOTE-KEY-HIGH-WATER-' + originals[0].unit_id)
            image = path.read_bytes(); entered = []
            with self.assertRaises(inventory.RetainedInventoryHold):
                with inventory._hold_catalog_fifo_frontier(writer, owner, bound) as (observed, verify):
                    entered.append(observed.frontier)
                    path.rename(case.root / 'preserved-fifo-applied')
                    path.write_bytes(image); path.chmod(0o600); verify()
            self.assertEqual([(originals[1].unit_id,)], entered)
            self.assertEqual(image, path.read_bytes())
            self.assertEqual(image, (case.root / 'preserved-fifo-applied').read_bytes())

    def test_original_applied_key_and_pending_receipt_rebind_revoke_entire_held_catalog(self):
        for fault in ('applied-key', 'pending-receipt'):
            with self.subTest(fault=fault), self.completed_and_pending() as (case, catalog, _remote, inventory, api, writer, owner, bound, originals):
                tracker = case.root / 'project/.tracker'
                pending_id = json.loads(originals[1].action_preimage)['identity']['generation_id']
                path = (tracker / ('REMOTE-KEY-HIGH-WATER-' + originals[0].unit_id)
                        if fault == 'applied-key' else tracker / 'generations' / pending_id / 'RECEIPT')
                image = path.read_bytes(); entered = []; replaced = []
                with self.assertRaises(inventory.RetainedInventoryHold):
                    with api(writer, owner, bound) as (observed, verify):
                        entered.append(tuple(row.unit for row in observed))
                        preserved = case.root / 'preserved-catalog-applied-original'
                        path.rename(preserved); path.write_bytes(image); path.chmod(0o600)
                        replaced.append(True); verify()
                self.assertEqual([originals], entered); self.assertEqual([True], replaced)
                self.assertEqual(image, preserved.read_bytes()); self.assertEqual(image, path.read_bytes())
                self.assertNotEqual(preserved.stat().st_ino, path.stat().st_ino)

    def test_catalog_complete_with_missing_applied_or_key_pair_never_repairs_or_yields_valid_prefix(self):
        for prefix in ('REMOTE-APPLIED-', 'REMOTE-KEY-HIGH-WATER-'):
            with self.subTest(prefix=prefix), self.completed_and_pending() as (case, _catalog, _remote, inventory, api, writer, owner, bound, originals):
                path = case.root / 'project/.tracker' / (prefix + originals[0].unit_id)
                image = path.read_bytes(); path.rename(case.root / 'preserved-missing-pair-original')
                before = original_read_files(case.root); reached = []
                with self.assertRaises(inventory.RetainedInventoryHold):
                    with api(writer, owner, bound) as result:
                        reached.append(result)
                self.assertEqual([], reached); self.assertEqual(before, original_read_files(case.root))
                self.assertFalse(path.exists())
                self.assertEqual(image, (case.root / 'preserved-missing-pair-original').read_bytes())


class SharedCatalogFifoTests(unittest.TestCase):
    """Spreadsheet-wide key order, with project-local APPLIED sequences."""

    def api(self):
        inventory = load_component('issue_tracker_retained_inventory')
        api = getattr(inventory, '_hold_all_project_fifo_frontier', None)
        self.assertTrue(callable(api), 'shared FIFO needs ALL held project C6/APPLIED and original UNSENT records')
        return inventory, api

    @contextmanager
    def pending(self, keys=('node-A', 'node-A', 'node-B')):
        case = UnitCatalogTests()
        case.setUp()
        try:
            inventory, api = self.api()
            with ExitStack() as scope:
                first, first_project, _publication = case.local_owner(scope)
                second, second_project, _other = case.local_owner(scope, 'other')
                token = case.owner(scope)
                # The first original has sequence 4; the second project starts
                # at 1. Neither number is a spreadsheet-global high-water.
                for _unused in range(3):
                    case.c6_unit(first)
                originals = []
                for writer, node in zip((first, second, second), keys):
                    args = send_inputs(1)
                    document = json.loads(args['manifest'])
                    document['operations'][0]['activity_key'] = ['switch', node, 'down', 'fabric']
                    args['manifest'] = (json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n').encode()
                    args['manifest_id'] = hashlib.sha256(args['manifest']).hexdigest()
                    generation = case.module.local.begin_generation(writer, args['manifest'])
                    case.module.local.record_intent(writer, generation, literal_xlsx(), kind='xlsx')
                    receipt = case.module.local.commit(writer, generation)
                    args.update(generation_id=generation.generation_id, publish_id=receipt.published_sha256)
                    original = case.module.composer.freeze_send_unit(**args)
                    case.module.register_pending_c6_unit(writer, token, binding(), original)
                    case.globals_api().prepare_global_unit(token, binding(), original)
                    originals.append(original)
                yield case, inventory, api, scope, token, tuple(originals), (first_project, second_project)
        finally:
            case.doCleanups()

    def test_shared_fifo_refuses_unissued_owner_and_detached_release_claims_before_read(self):
        inventory, api = self.api()
        with mock.patch.object(inventory, '_hold_all_project_applied_keys') as reading:
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(object(), binding()):
                    self.fail('unissued owner received shared FIFO')
            reading.assert_not_called()
        for claim in ({'writers': ()}, {'rows': ()}, {'maxima': ()}, {'settled': True}, {'permit': True}):
            with self.subTest(claim=tuple(claim)), self.assertRaises(TypeError):
                api(object(), binding(), **claim)

    def test_shared_fifo_orders_overlapping_keys_across_original_projects_without_global_sequences(self):
        self.api()
        with self.pending() as (case, _inventory, api, _scope, token, originals, projects):
            before = original_read_files(case.root)
            handles = {writer: dict(active.handles) for writer, active in case.module.local._ACTIVE.items()}
            with api(token, binding()) as (observed, verify):
                self.assertEqual((originals[0].unit_id, originals[2].unit_id), observed.frontier)
                self.assertEqual(((originals[1].unit_id, (originals[0].unit_id,)),), observed.blocked)
                self.assertEqual((), observed.applied)
                self.assertEqual((), observed.superseded)
                identities = tuple((path.stat().st_dev, path.stat().st_ino) for path in projects)
                self.assertEqual(((originals[0].unit_id, identities[0]),
                                  (originals[1].unit_id, identities[1]),
                                  (originals[2].unit_id, identities[1])), observed.projects)
                self.assertFalse(any(hasattr(observed, key) for key in ('permit', 'settled', 'writer_token', 'global_sequence')))
                verify()
            self.assertEqual(before, original_read_files(case.root))
            self.assertEqual(handles, {writer: dict(active.handles) for writer, active in case.module.local._ACTIVE.items()})
            self.assertEqual((0, 0, 0), tuple(state.attempt_count for _unit, state in case.globals_api().inspect_catalog_global_units(token, binding())))

    def test_shared_fifo_actual_unknown_refuses_entire_view_without_prefix_or_count_reset(self):
        self.api()
        with self.pending() as (case, inventory, api, _scope, token, originals, _projects):
            case.globals_api().record_global_attempt_intent(token, binding(), originals[0])
            before = original_read_files(case.root); entered = []
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(token, binding()) as result:
                    entered.append(result)
            self.assertEqual([], entered)
            self.assertEqual(before, original_read_files(case.root))
            self.assertEqual((1, 0, 0), tuple(state.attempt_count for _unit, state in case.globals_api().inspect_catalog_global_units(token, binding())))

    def test_shared_fifo_missing_foreign_receipt_never_returns_local_prefix_or_repairs(self):
        self.api()
        with self.pending() as (case, inventory, api, _scope, token, originals, projects):
            generation = json.loads(originals[1].action_preimage)['identity']['generation_id']
            receipt = projects[1] / '.tracker/generations' / generation / 'RECEIPT'
            receipt.rename(case.root / 'preserved-foreign-fifo-receipt')
            before = original_read_files(case.root); entered = []
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(token, binding()) as result:
                    entered.append(result)
            self.assertEqual([], entered)
            self.assertEqual(before, original_read_files(case.root))
            self.assertFalse(receipt.exists())

    def test_shared_fifo_partial_original_unsent_witness_refuses_without_adoption(self):
        self.api()
        with self.pending() as (case, inventory, api, _scope, token, originals, projects):
            path = projects[1] / '.tracker' / ('REMOTE-UNSENT-SUPERSESSION-WITNESS-' + originals[1].unit_id)
            path.write_bytes(b'partial-original-do-not-repair\n'); path.chmod(0o600)
            before = original_read_files(case.root); entered = []
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(token, binding()) as result:
                    entered.append(result)
            self.assertEqual([], entered)
            self.assertEqual(before, original_read_files(case.root))

    def test_shared_fifo_foreign_project_new_disposition_namespace_revokes_consumer_at_exit(self):
        self.api()
        with self.pending() as (case, inventory, api, _scope, token, originals, projects):
            entered = []
            path = projects[1] / '.tracker' / ('REMOTE-UNSENT-SUPERSESSION-WITNESS-' + originals[1].unit_id)
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(token, binding()) as (observed, _verify):
                    entered.append(observed.frontier)
                    path.write_bytes(b'foreign-interrupted-disposition\n'); path.chmod(0o600)
            self.assertEqual([(originals[0].unit_id, originals[2].unit_id)], entered)
            self.assertEqual(b'foreign-interrupted-disposition\n', path.read_bytes())

    def test_shared_fifo_foreign_receipt_same_bytes_rebind_revokes_consumer_and_preserves_objects(self):
        self.api()
        with self.pending() as (case, inventory, api, _scope, token, originals, projects):
            generation = json.loads(originals[1].action_preimage)['identity']['generation_id']
            path = projects[1] / '.tracker/generations' / generation / 'RECEIPT'
            raw = path.read_bytes(); saved = case.root / 'original-foreign-fifo-receipt'
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(token, binding()) as (observed, verify):
                    self.assertEqual((originals[0].unit_id, originals[2].unit_id), observed.frontier)
                    path.rename(saved); path.write_bytes(raw); path.chmod(0o600)
                    verify()
            self.assertEqual(raw, saved.read_bytes()); self.assertEqual(raw, path.read_bytes())
            self.assertNotEqual(saved.stat().st_ino, path.stat().st_ino)

    def test_shared_fifo_cold_process_reopens_all_origins_without_reissuing_handles_or_writes(self):
        self.api()
        with self.pending() as (case, _inventory, _api, scope, _token, originals, _projects):
            scope.close()
            before = original_read_files(case.root)
            program = '''import importlib.util,sys
from pathlib import Path
sys.path[:0]=[sys.argv[1],str(Path(sys.argv[1])/'tools')]
spec=importlib.util.spec_from_file_location('shared_fifo_cold_contract',sys.argv[3])
tests=importlib.util.module_from_spec(spec);spec.loader.exec_module(tests)
catalog=tests.load();inventory=tests.load_component('issue_tracker_retained_inventory')
tests.load_component('issue_tracker_remote_history_match')
from test_cases.test_req7_spreadsheet_owner import scoped_fixture,binding
assert catalog.local._ACTIVE=={}
with scoped_fixture(Path(sys.argv[2]),catalog.ownership),catalog.ownership.spreadsheet_owner(binding()) as owner:
 with inventory._hold_all_project_fifo_frontier(owner,binding()) as (observed,verify):
  assert observed.frontier==(sys.argv[4],sys.argv[6])
  assert observed.blocked==((sys.argv[5],(sys.argv[4],)),)
  assert observed.applied==() and observed.superseded==()
  assert len(catalog.local._ACTIVE)==2 and all(active.handles=={} for active in catalog.local._ACTIVE.values())
  assert not hasattr(observed,'permit') and not hasattr(observed,'writer_token')
  verify()
 assert catalog.local._ACTIVE=={}
print('COLD_SHARED_FIFO_ORIGINALS_NO_HANDLES_OR_AUTHORITY')
'''
            result = subprocess.run([sys.executable, '-B', '-c', program,
                str(SOURCE.parents[1]), str(case.root), __file__, *(unit.unit_id for unit in originals)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertEqual('COLD_SHARED_FIFO_ORIGINALS_NO_HANDLES_OR_AUTHORITY\n', result.stdout)
            self.assertEqual(before, original_read_files(case.root))

    def test_shared_fifo_actual_foreign_applied_same_sequence_is_not_local_supersession(self):
        self.api()
        with CatalogAppliedNativeWorkflowTests.completed_and_pending(self, cross_project=True) as (
                case, _catalog, _remote, inventory, _old, _writer, owner, bound, originals):
            before = original_read_files(case.root)
            with inventory._hold_all_project_fifo_frontier(owner, bound) as (observed, verify):
                self.assertEqual((originals[1].unit_id,), observed.frontier)
                self.assertEqual((), observed.blocked)
                self.assertEqual((originals[0].unit_id,), observed.applied)
                self.assertEqual((), observed.superseded)
                self.assertNotEqual(observed.projects[0][1], observed.projects[1][1])
                verify()
            self.assertEqual(before, original_read_files(case.root))

    def test_shared_fifo_actual_original_unsent_pair_removes_only_its_local_unit_without_writes(self):
        self.api()
        with CatalogAppliedNativeWorkflowTests.completed_and_pending(self, older_unsent=True, project_origins=True) as (
                case, catalog, _remote, inventory, _old, writer, owner, bound, originals):
            expected = ((originals[1].unit_id, 1, ((('switch', 'node0001', 'down', 'fabric'), 2),)),)
            before_record = original_read_files(case.root)
            with self.assertRaises(inventory.RetainedInventoryHold):
                with inventory._hold_all_project_fifo_frontier(owner, bound):
                    self.fail('computed supersession without original disposition released a unit')
            self.assertEqual(before_record, original_read_files(case.root))
            self.assertEqual(expected, inventory._record_catalog_unsent_dispositions(writer, owner, bound))
            before = original_read_files(case.root)
            with inventory._hold_all_project_fifo_frontier(owner, bound) as (observed, verify):
                self.assertEqual((), observed.frontier)
                self.assertEqual((), observed.blocked)
                self.assertEqual((originals[0].unit_id,), observed.applied)
                self.assertEqual((originals[1].unit_id,), observed.superseded)
                self.assertEqual(observed.projects[0][1], observed.projects[1][1])
                verify()
            self.assertEqual(before, original_read_files(case.root))
            from monitor import issue_tracker_global_attempt_journal as globals_
            self.assertEqual((1, 0), tuple(state.attempt_count for _unit, state in globals_.inspect_catalog_global_units(owner, bound)))

    def test_shared_fifo_actual_unsent_witness_same_bytes_rebind_revokes_all_and_preserves_foreign(self):
        self.api()
        with CatalogAppliedNativeWorkflowTests.completed_and_pending(self, older_unsent=True, project_origins=True) as (
                case, _catalog, _remote, inventory, _old, writer, owner, bound, originals):
            inventory._record_catalog_unsent_dispositions(writer, owner, bound)
            path = case.root / 'project/.tracker' / ('REMOTE-UNSENT-SUPERSESSION-WITNESS-' + originals[1].unit_id)
            raw = path.read_bytes(); preserved = case.root / 'preserved-shared-fifo-witness'
            with self.assertRaises(inventory.RetainedInventoryHold):
                with inventory._hold_all_project_fifo_frontier(owner, bound) as (observed, verify):
                    self.assertEqual((originals[1].unit_id,), observed.superseded)
                    path.rename(preserved); path.write_bytes(raw); path.chmod(0o600)
                    verify()
            self.assertEqual(raw, path.read_bytes()); self.assertEqual(raw, preserved.read_bytes())
            self.assertNotEqual(path.stat().st_ino, preserved.stat().st_ino)


class UnitCatalogTests(unittest.TestCase):
    def last_original_owner_api(self):
        remote=load_component('issue_tracker_remote_history_match')
        api=getattr(remote,'_hold_current_project_last_original_owners',None)
        self.assertTrue(callable(api),'default tail needs genuine ALL-located foreign owners before strict core acquisition')
        return remote,api

    @contextmanager
    def two_original_owner_projects(self, *, current_last=True):
        registering,_reading=self.project_origins_api()
        with ExitStack() as creation:
            first,first_project,first_publication=self.local_owner(creation,'foreign-first')
            last,last_project,last_publication=self.local_owner(creation,'current-last')
            token=self.owner(creation)
            originals=(self.c6_unit(first)[0],self.c6_unit(last)[0])
            for writer,original in zip((first,last),originals):registering(writer,token,binding(),original)
        self.assertEqual({},self.module.local._ACTIVE)
        current=(last_project,last_publication) if current_last else (first_project,first_publication)
        with ExitStack() as scope:
            writer=scope.enter_context(self.module.local.writer_owner(*current));token=self.owner(scope)
            yield writer,token,originals,(first_project,last_project)

    def test_default_last_original_owner_tail_keeps_foreign_lock_after_semantic_readers_close(self):
        _remote,api=self.last_original_owner_api()
        with self.two_original_owner_projects() as (writer,token,originals,projects):
            before=original_read_files(self.root);current=self.module.local._owner(writer)
            actual_join=self.module._hold_project_c6_from_origins;closed=[]
            @contextmanager
            def joined(*args,**options):
                with actual_join(*args,**options) as packet:yield packet
                closed.append(True)
            with mock.patch.object(self.module,'_hold_project_c6_from_origins',side_effect=joined):
                with api(writer,token,binding()) as locator:
                    self.assertEqual([True],closed,'strict semantic reader must already be closed')
                    self.assertEqual(originals[-1],locator.unit)
                    self.assertEqual((projects[-1].stat().st_dev,projects[-1].stat().st_ino),locator.project_identity)
                    foreign=[key for key in self.module.local._ACTIVE if key is not writer]
                    self.assertEqual(1,len(foreign));foreign=foreign[0]
                    actual=self.module.local._owner(foreign)
                    self.assertEqual(projects[0],actual.project);self.assertEqual({},actual.handles)
                    import fcntl
                    fd=os.open(projects[0]/'.tracker/LOCK',os.O_RDWR)
                    try:
                        with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    finally:os.close(fd)
                    self.assertIs(current,self.module.local._owner(writer))
            self.assertEqual([writer],list(self.module.local._ACTIVE))
            with self.assertRaises(self.module.local.LocalCommitHold):self.module.local._owner(foreign)
            self.assertIs(current,self.module.local._owner(writer));self.assertEqual(before,original_read_files(self.root))

    def test_default_last_original_owner_tail_rejects_unissued_and_caller_selection_before_read(self):
        remote,api=self.last_original_owner_api()
        with mock.patch.object(self.module,'hold_pending_project_origins') as reading:
            with self.assertRaises(remote.RemoteHistoryHold):
                with api(object(),object(),binding()):self.fail('unissued owner yielded a locator')
            reading.assert_not_called()
        for claims in ({'unit':self.first},{'projects':()},{'owner_tail':ExitStack()},{'complete':True}):
            with self.subTest(claim=tuple(claims)),self.assertRaises(TypeError):api(object(),object(),binding(),**claims)

    def test_default_last_original_owner_tail_refuses_last_other_project_without_mutation(self):
        remote,api=self.last_original_owner_api()
        with self.two_original_owner_projects(current_last=False) as (writer,token,_originals,_projects):
            before=original_read_files(self.root);current=self.module.local._owner(writer);entered=[]
            with self.assertRaises(remote.RemoteHistoryHold):
                with api(writer,token,binding()) as locator:entered.append(locator)
            self.assertEqual([],entered);self.assertEqual([writer],list(self.module.local._ACTIVE))
            self.assertIs(current,self.module.local._owner(writer));self.assertEqual(before,original_read_files(self.root))

    def test_default_last_original_owner_tail_preserves_interrupt_and_releases_only_new_owners(self):
        _remote,api=self.last_original_owner_api()
        with self.two_original_owner_projects() as (writer,token,_originals,projects):
            before=original_read_files(self.root);current=self.module.local._owner(writer)
            primary=KeyboardInterrupt('owned default foreign-lock tail interruption');entered=[]
            with self.assertRaises(KeyboardInterrupt) as caught:
                with api(writer,token,binding()):
                    entered.append(True);foreign=next(key for key in self.module.local._ACTIVE if key is not writer)
                    self.module.local._owner(foreign);raise primary
            self.assertIs(primary,caught.exception);self.assertEqual([True],entered)
            self.assertEqual([writer],list(self.module.local._ACTIVE));self.assertIs(current,self.module.local._owner(writer))
            with self.assertRaises(self.module.local.LocalCommitHold):self.module.local._owner(foreign)
            import fcntl
            fd=os.open(projects[0]/'.tracker/LOCK',os.O_RDWR)
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);fcntl.flock(fd,fcntl.LOCK_UN)
            finally:os.close(fd)
            self.assertEqual(before,original_read_files(self.root))

    def test_count_claim_nested_holder_borrows_same_live_originals_without_reacquiring_catalog(self):
        with self._simple_count_claim_originals() as (globals_,writer,token,bound):
            before=original_read_files(self.root)
            with globals_._hold_selected_last_catalog_write_originals(writer,token,bound,self.first) as outer:
                with mock.patch.object(globals_,'_catalog_present',side_effect=AssertionError('nested holder must not reacquire the catalog')):
                    with globals_._hold_selected_last_catalog_write_originals(writer,token,bound,self.first) as borrowed:
                        self.assertIs(outer,borrowed);borrowed();outer()
                outer()
            self.assertEqual(before,original_read_files(self.root))
            with self.assertRaises(globals_.GlobalAttemptHold):borrowed()

    def test_count_claim_nested_holder_rejects_different_originals_and_exited_context(self):
        from contextvars import copy_context
        from dataclasses import replace
        with self._simple_count_claim_originals() as (globals_,writer,token,bound):
            before=original_read_files(self.root)
            with globals_._hold_selected_last_catalog_write_originals(writer,token,bound,self.first) as outer:
                stale=copy_context()
                for args in ((object(),token,bound,self.first),(writer,object(),bound,self.first),
                        (writer,token,replace(bound,spreadsheet_id='other-target'),self.first),
                        (writer,token,bound,replace(self.first))):
                    with self.subTest(field=next(i for i,(old,new) in enumerate(zip((writer,token,bound,self.first),args)) if old is not new)):
                        entered=[]
                        with self.assertRaises(globals_.GlobalAttemptHold):
                            with globals_._hold_selected_last_catalog_write_originals(*args):entered.append(True)
                        self.assertEqual([],entered);outer()
            manager=globals_._hold_selected_last_catalog_write_originals(writer,token,bound,self.first)
            with mock.patch.object(globals_,'_catalog_present',side_effect=AssertionError('exited context must not issue a fresh original graph')):
                with self.assertRaises(globals_.GlobalAttemptHold):stale.run(manager.__enter__)
            self.assertEqual(before,original_read_files(self.root))

    def test_count_claim_nested_interruption_preserves_primary_and_checks_originals_on_exit(self):
        import errno
        with self._simple_count_claim_originals() as (globals_,writer,token,bound):
            primary=KeyboardInterrupt('owned nested count/claim interruption')
            init=self.module._Originals.__init__;graphs=[];seen=[]
            def capture(graph,*args,**options):
                init(graph,*args,**options);graphs.append(graph)
            with mock.patch.object(self.module._Originals,'__init__',capture):
                with self.assertRaises(KeyboardInterrupt) as caught:
                    with globals_._hold_selected_last_catalog_write_originals(writer,token,bound,self.first) as outer:
                        with globals_._hold_selected_last_catalog_write_originals(writer,token,bound,self.first) as borrowed:
                            self.assertIs(outer,borrowed);borrowed();seen.append('entered-original-borrow')
                            path=next(self.root.rglob('WIRE'));raw=path.read_bytes()
                            preserved=self.root/'preserved-interrupted-original-wire'
                            path.rename(preserved);path.write_bytes(raw);path.chmod(0o600)
                            self.assertNotEqual(path.stat().st_ino,preserved.stat().st_ino)
                            raise primary
            self.assertIs(primary,caught.exception);self.assertEqual(['entered-original-borrow'],seen)
            for graph in graphs:
                for _parent,_name,fd,*_rest in (*graph.files,*graph.directories):
                    with self.assertRaises(OSError) as closed:os.fstat(fd)
                    self.assertEqual(errno.EBADF,closed.exception.errno)
            self.assertFalse(tuple(self.root.rglob('ATTEMPT-*')))
            self.assertFalse(tuple(self.root.rglob('CLAIM-*')))

    @contextmanager
    def _simple_count_claim_originals(self):
        globals_=self.globals_api()
        with ExitStack() as scope:
            token=self.owner(scope);bound=binding()
            project=self.root/'count-claim-project';project.mkdir(mode=0o700)
            publication=project/'publication';publication.mkdir(mode=0o700)
            self.module.local.create_local_commit_store(project,publication)
            writer=scope.enter_context(self.module.local.writer_owner(project,publication))
            self.module.register_pending_unit(token,bound,self.first)
            globals_.prepare_global_unit(token,bound,self.first)
            yield globals_,writer,token,bound

    def test_count_claim_original_verifier_rejects_missing_live_context_and_thread(self):
        from contextvars import Context
        import threading
        with self._simple_count_claim_originals() as (globals_,writer,token,bound):
            answers=[]
            with globals_._hold_selected_last_catalog_write_originals(writer,token,bound,self.first) as verify:
                verify()
                try:Context().run(verify)
                except Exception as error:answers.append(type(error))
                else:answers.append(None)
                def other_thread():
                    try:verify()
                    except Exception as error:answers.append(type(error))
                    else:answers.append(None)
                thread=threading.Thread(target=other_thread);thread.start();thread.join(2)
            self.assertFalse(thread.is_alive());self.assertEqual([globals_.GlobalAttemptHold]*2,answers)
            with self.assertRaises(globals_.GlobalAttemptHold):verify()

    def test_count_claim_original_context_reset_failure_still_closes_all_actual_graphs(self):
        from contextvars import copy_context
        with self._simple_count_claim_originals() as (globals_,writer,token,bound):
            init=self.module._Originals.__init__;close=self.module._Originals.close
            graphs=[];closed=[]
            def capturing(graph,*args,**options):
                init(graph,*args,**options);graphs.append(graph)
            def closing(graph):
                closed.append(graph);return close(graph)
            manager=globals_._hold_selected_last_catalog_write_originals(writer,token,bound,self.first)
            context=copy_context()
            try:
                with mock.patch.object(self.module._Originals,'__init__',capturing), \
                        mock.patch.object(self.module._Originals,'close',closing):
                    verify=context.run(manager.__enter__);context.run(verify)
                    # Real Token.reset rejects use in another Context. It must
                    # revoke issuance but cannot bypass owned graph cleanup.
                    with self.assertRaises(globals_.GlobalAttemptHold):manager.__exit__(None,None,None)
                originals=[graph for graph in graphs if graph._image_budget is not None]
                self.assertEqual(3,len(originals));self.assertTrue(all(graph in closed for graph in originals))
                self.assertEqual(1,len({id(graph._image_budget) for graph in originals}))
                for graph in originals:
                    for _parent,_name,fd,*_rest in (*graph.files,*graph.directories):
                        with self.assertRaises(OSError):os.fstat(fd)
            finally:
                # Baseline RED must not leave even the faulted test's owned FDs.
                for graph in graphs:close(graph)

    def test_native_count_catalog_borrow_uses_same_selection_without_second_issuer(self):
        globals_,issuer=self.catalog_replay_api()
        borrow=getattr(globals_,'_hold_native_catalog_write_replay',None)
        self.assertTrue(callable(borrow),'fixed count path must borrow its already held original catalog')
        from contextvars import copy_context
        with ExitStack() as scope:
            token=self.owner(scope);bound=binding()
            self.module.register_pending_unit(token,bound,self.first)
            globals_.prepare_global_unit(token,bound,self.first)
            before=original_read_files(self.root); entered=[]
            with issuer(token,bound,self.first) as outer:
                with mock.patch.object(globals_,'_hold_native_catalog_replay',wraps=issuer) as issuing:
                    with borrow(token,bound,self.first) as verify:
                        entered.append('same-original-selected'); verify(); outer()
                        stale_context=copy_context()
                    self.assertEqual(0,issuing.call_count,'borrow must not reissue or recapture ALL originals')
                outer()
            self.assertEqual(['same-original-selected'],entered)
            with self.assertRaises(globals_.GlobalAttemptHold):verify()
            with self.assertRaises(globals_.GlobalAttemptHold):stale_context.run(verify)
            self.assertEqual(before,original_read_files(self.root))

    def test_native_count_catalog_borrow_rejects_different_selected_unit_before_count(self):
        globals_,issuer=self.catalog_replay_api()
        borrow=getattr(globals_,'_hold_native_catalog_write_replay',None)
        self.assertTrue(callable(borrow),'held catalog membership alone cannot change the selected writer')
        with ExitStack() as scope:
            token=self.owner(scope);bound=binding()
            self.module.register_pending_unit(token,bound,self.first)
            self.module.register_pending_unit(token,bound,self.second)
            for unit in (self.first,self.second):globals_.prepare_global_unit(token,bound,unit)
            before=original_read_files(self.root);entered=[]
            with issuer(token,bound,self.first) as outer:
                with self.assertRaises(globals_.GlobalAttemptHold):
                    with borrow(token,bound,self.second):entered.append(True)
                with self.assertRaises(globals_.GlobalAttemptHold):
                    with borrow(object(),bound,self.first):entered.append(True)
                outer()
            self.assertEqual([],entered)
            self.assertEqual((0,0),tuple(globals_.inspect_global_unit(token,bound,unit).attempt_count
                for unit in (self.first,self.second)))
            self.assertEqual(before,original_read_files(self.root));self.assertFalse(list(self.root.rglob('CLAIM-*')))

    def catalog_replay_api(self):
        globals_=self.globals_api()
        api=getattr(globals_,'_hold_native_catalog_replay',None)
        self.assertTrue(callable(api),'actual immutable catalog must remain original through repeated reads')
        return globals_,api

    def test_catalog_replay_reuses_only_original_semantics_and_preserves_actual_count(self):
        globals_,api=self.catalog_replay_api()
        with ExitStack() as scope:
            token=self.owner(scope);bound=binding()
            self.module.register_pending_unit(token,bound,self.first)
            globals_.prepare_global_unit(token,bound,self.first)
            before=original_read_files(self.root)
            actual=self.module._inspect
            with api(token,bound,self.first) as verify:
                with mock.patch.object(self.module,'_inspect',wraps=actual) as replay:
                    for _ in range(3):
                        with globals_._hold_catalog_originals(token,bound) as (units,check):
                            self.assertEqual((self.first,),units);check()
                        self.assertEqual(0,globals_.inspect_global_unit(token,bound,self.first).attempt_count)
                    self.assertEqual(0,replay.call_count,'continuously held originals must not be reopened and reparsed')
                verify()
                result=globals_.record_global_attempt_intent(token,bound,self.first)
                self.assertEqual((1,'UNKNOWN'),(result.attempt_count,result.outcome))
                verify()
            after=original_read_files(self.root)
            added=set(after)-set(before)
            self.assertEqual({STEM+'.unit-'+self.first.unit_id+'.journal/ATTEMPT-1'},
                {name.rsplit('issue-tracker/',1)[-1] for name in added})
            self.assertEqual(before,{name:value for name,value in after.items() if name in before})

    def test_catalog_replay_original_rebind_refuses_before_count_and_retains_count_after(self):
        globals_,api=self.catalog_replay_api()
        for counted in (False,True):
            with self.subTest(counted=counted),ExitStack() as scope:
                # Each scenario owns an independent original namespace.
                if counted:
                    other=self.root/'other';other.mkdir()
                    self.parent=other/'var/lib/http-ztp-container/issue-tracker'
                    self.parent.mkdir(parents=True,mode=0o700)
                    scope.enter_context(scoped_fixture(other,self.module.ownership))
                    token=scope.enter_context(self.module.ownership.spreadsheet_owner(binding()))
                else:token=self.owner(scope)
                bound=binding();self.module.register_pending_unit(token,bound,self.first)
                globals_.prepare_global_unit(token,bound,self.first)
                original=self.parent/(STEM+'.units')/self.first.unit_id/'WIRE'
                journal_dir=self.parent/(STEM+'.unit-'+self.first.unit_id+'.journal')
                before=original_read_files(self.root);fault=[]
                with self.assertRaises(globals_.GlobalAttemptHold):
                    with api(token,bound,self.first):
                        if counted:globals_.record_global_attempt_intent(token,bound,self.first)
                        raw=original.read_bytes();old=original.stat().st_ino
                        original.rename(self.root/('preserved-wire-'+str(counted)))
                        original.write_bytes(raw);original.chmod(0o600)
                        fault.append((old,original.stat().st_ino,raw,original.read_bytes()))
                        globals_.inspect_global_unit(token,bound,self.first)
                self.assertEqual(1,len(fault));self.assertNotEqual(fault[0][0],fault[0][1])
                self.assertEqual(fault[0][2],fault[0][3])
                self.assertEqual({'HEADER','INITIALIZED','ACTION-PREIMAGE','WIRE'}|
                    ({'ATTEMPT-1'} if counted else set()),set(os.listdir(journal_dir)))
                if counted:self.assertEqual('UNKNOWN',json.loads((journal_dir/'ATTEMPT-1').read_bytes())['outcome'])
                self.assertFalse((self.parent/(STEM+'.unit-'+self.first.unit_id+'.dispatch')).exists())

    def test_catalog_replay_copied_context_revokes_and_caller_overrides_are_not_accepted(self):
        from contextvars import copy_context
        globals_,api=self.catalog_replay_api()
        for extra in ({'verify':lambda:None},{'units':(self.first,)},{'allow_additions':set()},{'qualified':True}):
            with self.subTest(extra=tuple(extra)),self.assertRaises(TypeError):
                with api(object(),object(),object(),**extra):self.fail('caller supplied original authority')
        with ExitStack() as scope:
            token=self.owner(scope);bound=binding()
            self.module.register_pending_unit(token,bound,self.first)
            globals_.prepare_global_unit(token,bound,self.first)
            before=original_read_files(self.root)
            with api(token,bound,self.first) as verify:
                copied=copy_context()
                with self.assertRaises(globals_.GlobalAttemptHold):
                    with api(token,bound,self.first):self.fail('nested issuer adopted held result')
                with self.assertRaises(globals_.GlobalAttemptHold):
                    with globals_._hold_catalog_originals(object(),bound):self.fail('foreign owner borrowed graph')
                verify()
            def borrow():
                with globals_._hold_catalog_originals(token,bound):self.fail('closed original scope survived context copy')
            with self.assertRaises(globals_.GlobalAttemptHold):copied.run(borrow)
            with self.assertRaises(globals_.GlobalAttemptHold):verify()
            self.assertEqual(before,original_read_files(self.root))

    def test_catalog_replay_retains_explicit_legacy_c6_bridge_originals(self):
        globals_,api=self.catalog_replay_api()
        with ExitStack() as scope:
            writer,_project,_publication=self.local_owner(scope)
            token=self.owner(scope);bound=binding()
            original,_generation=self.c6_unit(writer)
            self.module.register_pending_c6_unit(writer,token,bound,original)
            globals_.prepare_global_unit(token,bound,original)
            header=self.parent/(STEM+'.units')/original.unit_id/'HEADER'
            self.assertIsNone(json.loads(header.read_bytes()).get('project_origin'))
            origin=self.parent/(STEM+'.unit-'+original.unit_id+'.project-origin/ORIGIN')
            journal_dir=self.parent/(STEM+'.unit-'+original.unit_id+'.journal');fault=[]
            with self.assertRaises(globals_.GlobalAttemptHold):
                with api(token,bound,original):
                    raw=origin.read_bytes();old=origin.stat().st_ino
                    origin.rename(self.root/'preserved-legacy-origin')
                    origin.write_bytes(raw);origin.chmod(0o600)
                    fault.append((old,origin.stat().st_ino,raw,origin.read_bytes()))
                    with globals_._hold_catalog_originals(token,bound) as (_units,check):check()
            self.assertEqual(1,len(fault));self.assertNotEqual(fault[0][0],fault[0][1])
            self.assertEqual(fault[0][2],fault[0][3])
            self.assertEqual({'HEADER','INITIALIZED','ACTION-PREIMAGE','WIRE'},set(os.listdir(journal_dir)))

    def test_catalog_replay_live_context_rebind_and_cross_thread_verifier_refuse(self):
        from contextvars import copy_context
        import threading
        globals_,api=self.catalog_replay_api()
        with ExitStack() as scope:
            token=self.owner(scope);bound=binding()
            self.module.register_pending_unit(token,bound,self.first)
            globals_.prepare_global_unit(token,bound,self.first)
            before=original_read_files(self.root);cross_thread=[]
            with api(token,bound,self.first) as verify:
                borrowed=globals_._hold_catalog_originals(token,bound)
                borrowed.__enter__()
                swapped=globals_._HELD_CATALOG_REPLAY.set(object())
                try:
                    with self.assertRaises(globals_.GlobalAttemptHold):borrowed.__exit__(None,None,None)
                finally:globals_._HELD_CATALOG_REPLAY.reset(swapped)
                context=copy_context()
                def worker():
                    try:context.run(verify)
                    except BaseException as error:cross_thread.append(type(error))
                    else:cross_thread.append('accepted-foreign-thread')
                thread=threading.Thread(target=worker);thread.start();thread.join(2)
                self.assertFalse(thread.is_alive(),'owned verifier diagnostic did not finish')
                self.assertEqual([globals_.GlobalAttemptHold],cross_thread)
                verify()
            self.assertEqual(before,original_read_files(self.root))

    def test_catalog_replay_cross_context_exit_revokes_registry_and_closes_original_fds(self):
        from contextvars import copy_context
        globals_,api=self.catalog_replay_api()
        with ExitStack() as scope:
            token=self.owner(scope);bound=binding()
            self.module.register_pending_unit(token,bound,self.first)
            globals_.prepare_global_unit(token,bound,self.first)
            before=original_read_files(self.root);fds=[];closed=[]
            actual_close=self.module._Originals.close
            def close(held):
                fds.extend(entry[2] for entry in held.files)
                fds.extend(entry[2] for entry in held.directories)
                closed.append(True);return actual_close(held)
            previous=globals_._HELD_CATALOG_REPLAY.get()
            holder=api(token,bound,self.first);holder.__enter__();context=copy_context()
            try:
                with mock.patch.object(self.module._Originals,'close',close):
                    with self.assertRaises(globals_.GlobalAttemptHold):context.run(holder.__exit__,None,None,None)
                self.assertEqual({},globals_._LIVE_CATALOG_REPLAYS)
                self.assertEqual([True],closed);self.assertTrue(fds)
                for descriptor in fds:
                    with self.assertRaises(OSError):os.fstat(descriptor)
            finally:globals_._HELD_CATALOG_REPLAY.set(previous)
            self.assertEqual(before,original_read_files(self.root))

    def test_catalog_replay_actual_verifier_rejects_copied_live_scope_on_other_thread(self):
        from contextvars import copy_context
        import threading
        globals_,api=self.catalog_replay_api()
        with ExitStack() as scope:
            token=self.owner(scope);bound=binding()
            self.module.register_pending_unit(token,bound,self.first)
            globals_.prepare_global_unit(token,bound,self.first)
            with api(token,bound,self.first) as verify:
                context=copy_context();seen=[]
                def worker():
                    try:context.run(verify)
                    except BaseException as error:seen.append(type(error))
                    else:seen.append('accepted-foreign-thread')
                thread=threading.Thread(target=worker);thread.start();thread.join(2)
                self.assertFalse(thread.is_alive(),'actual verifier thread did not finish')
                self.assertEqual([globals_.GlobalAttemptHold],seen)
                verify()

    def test_catalog_fixture_reload_preserves_preimported_real_local_owner_registry(self):
        # Ordinary full discovery imports consumers before catalog tests run.
        # A fixture must not replace their production owner registry behind
        # their already imported functions; a new opaque token then cannot
        # be interpreted by the canonical old consumer.
        from monitor import issue_tracker_local_commit as original
        from monitor import issue_tracker_send_intent as intent
        from monitor import issue_tracker_state_owner as states
        before = original._ACTIVE
        catalog = load()
        self.assertIs(original, catalog.local)
        self.assertIs(original, sys.modules['monitor.issue_tracker_local_commit'])
        self.assertIs(original, intent.local)
        self.assertIs(before, states._owner.__globals__['_ACTIVE'])

    def fifo_api(self):
        inventory, _reader = self.inventory_api()
        api = getattr(inventory, '_hold_catalog_fifo_frontier', None)
        self.assertTrue(callable(api), 'FIFO must derive its frontier from held original APPLIED and UNSENT records')
        return inventory, api

    def test_fifo_frontier_refuses_unissued_writer_and_caller_release_claims(self):
        inventory, api = self.fifo_api()
        with mock.patch.object(inventory, '_hold_catalog_applied_keys') as reading:
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(object(), object(), binding()):
                    self.fail('unissued writer obtained a FIFO release view')
            reading.assert_not_called()
        for claim in ({'settled': ()}, {'units': ()}, {'maxima': ()}, {'superseded': ()}, {'permit': True}):
            with self.subTest(claim=tuple(claim)), self.assertRaises(TypeError):
                api(object(), object(), binding(), **claim)

    def test_fifo_frontier_original_pending_same_key_preserves_order_and_does_not_count_or_issue(self):
        inventory, api = self.fifo_api(); globals_ = self.globals_api()
        with ExitStack() as scope:
            writer, project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            originals = tuple(self.c6_unit(writer)[0] for _ in range(3))
            for original in originals:
                self.module.register_pending_unit(token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
            before = original_read_files(self.root)
            handles = dict(self.module.local._owner(writer).handles)
            with api(writer, token, binding()) as (observed, verify):
                self.assertEqual((project.stat().st_dev, project.stat().st_ino), observed.project_identity)
                self.assertEqual((originals[0].unit_id,), observed.frontier)
                self.assertEqual(((originals[1].unit_id, (originals[0].unit_id,)),
                                  (originals[2].unit_id, (originals[0].unit_id, originals[1].unit_id))), observed.blocked)
                self.assertEqual((), observed.applied)
                self.assertEqual((), observed.superseded)
                self.assertFalse(hasattr(observed, 'permit') or hasattr(observed, 'settled'))
                verify()
            self.assertEqual(handles, self.module.local._owner(writer).handles)
            self.assertEqual(before, original_read_files(self.root))
            self.assertEqual((0, 0, 0), tuple(row.attempt_count for _unit, row in globals_.inspect_catalog_global_units(token, binding())))

    def test_fifo_frontier_unknown_holds_entire_view_and_never_releases_valid_prefix(self):
        inventory, api = self.fifo_api(); globals_ = self.globals_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            originals = tuple(self.c6_unit(writer)[0] for _ in range(2))
            for original in originals:
                self.module.register_pending_unit(token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
            globals_.record_global_attempt_intent(token, binding(), originals[0])
            before = original_read_files(self.root); reached = []
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(writer, token, binding()) as result:
                    reached.append(result)
            self.assertEqual([], reached)
            self.assertEqual(before, original_read_files(self.root))
            self.assertEqual(((1, 'UNKNOWN'), (0, 'UNATTEMPTED_OBSERVATION')),
                             tuple((row.attempt_count, row.outcome) for _unit, row in globals_.inspect_catalog_global_units(token, binding())))

    def test_fifo_frontier_unrelated_keys_are_independent_but_overlapping_successor_waits(self):
        inventory, api = self.fifo_api(); globals_ = self.globals_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            originals = []
            for node in ('node-A', 'node-B', 'node-A'):
                args = send_inputs(1)
                # Independently chosen fixture keys; not reverse-generated
                # from the FIFO implementation or its reported frontier.
                document = json.loads(args['manifest'])
                document['operations'][0]['activity_key'] = ['switch', node, 'down', 'fabric']
                args['manifest'] = (json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n').encode()
                args['manifest_id'] = hashlib.sha256(args['manifest']).hexdigest()
                generation = self.module.local.begin_generation(writer, args['manifest'])
                self.module.local.record_intent(writer, generation, literal_xlsx(), kind='xlsx')
                receipt = self.module.local.commit(writer, generation)
                args.update(generation_id=generation.generation_id, publish_id=receipt.published_sha256)
                original = self.module.composer.freeze_send_unit(**args)
                originals.append(original)
                self.module.register_pending_unit(token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
            before = original_read_files(self.root)
            with api(writer, token, binding()) as (observed, verify):
                self.assertEqual((originals[0].unit_id, originals[1].unit_id), observed.frontier)
                self.assertEqual(((originals[2].unit_id, (originals[0].unit_id,)),), observed.blocked)
                self.assertEqual((), observed.applied)
                self.assertEqual((), observed.superseded)
                verify()
            self.assertEqual(before, original_read_files(self.root))

    def test_fifo_frontier_cold_process_reopens_originals_without_parent_handles_or_detached_claim(self):
        _inventory, api = self.fifo_api(); globals_ = self.globals_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            originals = tuple(self.c6_unit(writer)[0] for _ in range(2))
            for original in originals:
                self.module.register_pending_unit(token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
            with api(writer, token, binding()) as (observed, verify):
                self.assertEqual((originals[0].unit_id,), observed.frontier)
                verify()
        before = original_read_files(self.root)
        program = '''import importlib.util,json,sys
from pathlib import Path
sys.path[:0]=[sys.argv[1],str(Path(sys.argv[1])/'tools')]
spec=importlib.util.spec_from_file_location('cold_fifo_test_contract',sys.argv[3])
tests=importlib.util.module_from_spec(spec); spec.loader.exec_module(tests)
catalog=tests.load(); inventory=tests.load_component('issue_tracker_retained_inventory')
from monitor import issue_tracker_spreadsheet_owner as ownership
from test_cases.test_req7_spreadsheet_owner import scoped_fixture,binding
root=Path(sys.argv[2])
with catalog.local.writer_owner(root/'project',root/'project/publication') as writer,scoped_fixture(root,ownership),ownership.spreadsheet_owner(binding()) as owner:
 assert catalog.local._owner(writer).handles=={}
 with inventory._hold_catalog_fifo_frontier(writer,owner,binding()) as (observed,verify):
  assert observed.frontier==(sys.argv[4],)
  assert observed.blocked==((sys.argv[5],(sys.argv[4],)),)
  assert observed.applied==() and observed.superseded==()
  assert not hasattr(observed,'permit') and not hasattr(observed,'settled')
  verify()
 assert catalog.local._owner(writer).handles=={}
print('COLD_FIFO_ORIGINALS_ONLY_NO_AUTHORITY')
'''
        result = subprocess.run([sys.executable, '-B', '-c', program,
            str(Path(__import__('test_cases').__file__).resolve().parents[1]), str(self.root), __file__,
            originals[0].unit_id, originals[1].unit_id], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual('COLD_FIFO_ORIGINALS_ONLY_NO_AUTHORITY\n', result.stdout)
        self.assertEqual(before, original_read_files(self.root))

    def test_fifo_frontier_receipt_rebind_revokes_consumer_without_repair(self):
        inventory, api = self.fifo_api(); globals_ = self.globals_api()
        with ExitStack() as scope:
            writer, project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            original, generation = self.c6_unit(writer)
            self.module.register_pending_unit(token, binding(), original)
            globals_.prepare_global_unit(token, binding(), original)
            path = project / '.tracker/generations' / generation.generation_id / 'RECEIPT'
            image = path.read_bytes(); entered = []
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(writer, token, binding()) as (observed, verify):
                    entered.append(observed.frontier)
                    path.rename(self.root / 'preserved-fifo-original')
                    path.write_bytes(image); path.chmod(0o600); verify()
            self.assertEqual([(original.unit_id,)], entered)
            self.assertEqual(image, path.read_bytes())
            self.assertEqual(image, (self.root / 'preserved-fifo-original').read_bytes())
            self.assertNotEqual(path.stat().st_ino, (self.root / 'preserved-fifo-original').stat().st_ino)

    def applied_pair_foreign_descriptor_case(self, *, writing, content_drift=False):
        remote = load_component('issue_tracker_remote_history_match')
        parent = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, parent)
        names = ('OWNED-PAIR-STARTED', 'OWNED-PAIR')
        body = {'schema_version': 1, 'unit_id': 'a' * 64, 'fixture': 'FD cleanup only, not C6 authority'}
        if not writing:
            with remote._write_applied_pair(parent, names, body, lambda: None) as verify:
                verify()
        foreign_path = self.root / 'foreign-owned-descriptor'
        foreign_path.write_bytes(b'owned foreign FD must survive rejected proof consumer\n')
        foreign_path.chmod(0o600)
        foreign = os.open(foreign_path, os.O_RDONLY | os.O_NOFOLLOW)
        self.addCleanup(os.close, foreign)
        foreign_object = (os.fstat(foreign).st_dev, os.fstat(foreign).st_ino)
        opened = []; reached = []; original_open = os.open
        def capture(path, flags, *args, **kwargs):
            fd = original_open(path, flags, *args, **kwargs)
            if kwargs.get('dir_fd') == parent and type(path) is str and (
                    path.startswith('.pending-') if writing else path in names):
                opened.append(fd)
            return fd
        def close_owned_duplicate(fd):
            try:
                info = os.fstat(fd)
            except OSError:
                return
            if (info.st_dev, info.st_ino) == foreign_object:
                os.close(fd)
        operation = (remote._write_applied_pair(parent, names, body, lambda: None)
                     if writing else remote._hold_applied_records(parent, names, body))
        from monitor.issue_tracker_attempt_journal import AttemptJournalHold
        with mock.patch.object(remote.os, 'open', side_effect=capture), self.assertRaises((remote.RemoteHistoryHold, AttemptJournalHold)):
            with operation as verify:
                self.assertEqual(2, len(opened))
                replaced = opened[0]
                self.addCleanup(close_owned_duplicate, replaced)
                if content_drift:
                    # Changed bytes do not transfer FD ownership. The still
                    # original descriptors must close after rejecting drift.
                    (self.root / names[0]).write_bytes(b'owned original content drift; preserve evidence\n')
                else:
                    os.close(replaced); os.dup2(foreign, replaced)
                reached.append(replaced)
                verify()
        self.assertEqual(1, len(reached))
        if content_drift:
            for fd in opened:
                with self.assertRaises(OSError):
                    os.fstat(fd)
            self.assertEqual(b'owned original content drift; preserve evidence\n', (self.root / names[0]).read_bytes())
            self.assertEqual(foreign_object, (os.fstat(foreign).st_dev, os.fstat(foreign).st_ino))
            return
        try:
            info = os.fstat(reached[0])
        except OSError:
            self.fail('APPLIED pair cleanup closed a recycled FD now owned by another object')
        self.assertEqual(foreign_object, (info.st_dev, info.st_ino))
        self.assertEqual(b'owned foreign FD must survive rejected proof consumer\n', os.pread(reached[0], 128, 0))

    def test_original_applied_pair_reader_rejects_recycled_fd_but_preserves_foreign_object(self):
        self.applied_pair_foreign_descriptor_case(writing=False)

    def test_original_applied_pair_writer_rejects_recycled_fd_but_preserves_foreign_object(self):
        self.applied_pair_foreign_descriptor_case(writing=True)

    def test_original_applied_pair_reader_closes_still_owned_descriptors_after_content_drift(self):
        self.applied_pair_foreign_descriptor_case(writing=False, content_drift=True)

    def test_original_applied_pair_writer_closes_still_owned_descriptors_after_content_drift(self):
        self.applied_pair_foreign_descriptor_case(writing=True, content_drift=True)

    def original_c6_foreign_descriptor_case(self, entry):
        remote = load_component('issue_tracker_remote_history_match')
        with ExitStack() as scope:
            writer, project, _publication = self.local_owner(scope, 'c6-foreign-' + entry)
            original, generation = self.c6_unit(writer)
            token = self.owner(scope)
            self.module.register_pending_unit(token, binding(), original)
            original_path = project / '.tracker/generations' / generation.generation_id
            if entry == 'RECEIPT':
                original_path = original_path / entry
            original_object = (original_path.stat().st_dev, original_path.stat().st_ino)
            foreign_path = self.root / ('foreign-c6-' + entry)
            foreign_path.write_bytes(b'owned foreign object must survive C6 rejection\n')
            foreign = os.open(foreign_path, os.O_RDONLY)
            scope.callback(os.close, foreign)
            foreign_object = (os.fstat(foreign).st_dev, os.fstat(foreign).st_ino)
            opening = remote.os.open; opened = []; borrowed = []
            def capture(*args, **kwargs):
                fd = opening(*args, **kwargs)
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) == original_object:
                    opened.append(fd)
                return fd
            def close_borrowed_foreign():
                if borrowed:
                    try:
                        info = os.fstat(borrowed[0])
                        if (info.st_dev, info.st_ino) == foreign_object:
                            os.close(borrowed[0])
                    except OSError:
                        pass
            scope.callback(close_borrowed_foreign)
            with mock.patch.object(remote.os, 'open', side_effect=capture):
                with self.assertRaises(self.module.UnitCatalogHold):
                    with self.module.hold_pending_c6_units(writer, token, binding()) as (observed, verify):
                        self.assertEqual((original,), observed)
                        live = []
                        for fd in set(opened):
                            try:
                                info = os.fstat(fd)
                                if (info.st_dev, info.st_ino) == original_object:
                                    live.append(fd)
                            except OSError:
                                pass
                        self.assertEqual(1, len(live))
                        os.close(live[0]); os.dup2(foreign, live[0]); borrowed.append(live[0])
                        verify()
            try:
                info = os.fstat(borrowed[0])
            except OSError:
                self.fail('C6 cleanup closed a rejected recycled FD belonging to another object')
            self.assertEqual(foreign_object, (info.st_dev, info.st_ino))
            self.assertEqual(b'owned foreign object must survive C6 rejection\n', os.pread(borrowed[0], 128, 0))

    def test_original_c6_reader_rejects_recycled_receipt_fd_without_closing_foreign_object(self):
        self.original_c6_foreign_descriptor_case('RECEIPT')

    def test_original_c6_reader_rejects_recycled_directory_fd_without_closing_foreign_object(self):
        self.original_c6_foreign_descriptor_case('generation-directory')

    def project_origins_api(self):
        registering = getattr(self.module, 'register_pending_c6_unit', None)
        reading = getattr(self.module, 'hold_pending_project_origins', None)
        self.assertTrue(callable(registering) and callable(reading),
                        'cross-project replay needs original writer-issued project origins for EVERY catalog unit')
        return registering, reading

    def project_c6_api(self):
        api = getattr(self.module, 'hold_pending_project_c6_units', None)
        self.assertTrue(callable(api), 'ALL project origins must join genuine owned C6 originals, not stored locator claims')
        return api

    def all_project_applied_api(self):
        inventory, _reading = self.inventory_api()
        api = getattr(inventory, '_hold_all_project_applied_keys', None)
        self.assertTrue(callable(api), 'ALL native project C6 and original APPLIED keys must join without caller writers or maxima')
        return inventory, api

    def test_all_project_applied_unissued_global_owner_and_caller_proof_claims_fail_before_read(self):
        inventory, api = self.all_project_applied_api()
        with mock.patch.object(self.module, 'hold_pending_project_c6_units') as reading:
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(object(), binding()):
                    self.fail('unissued owner read historical APPLIED')
            reading.assert_not_called()
        for claims in ({'writers': ()}, {'projects': ()}, {'keys': ()}, {'complete': True}, {'maxima': {}}):
            with self.subTest(claims=tuple(claims)), self.assertRaises(TypeError):
                api(object(), binding(), **claims)

    def test_all_project_applied_uncounted_real_c6_never_fabricates_keys_and_actual_unknown_holds_all(self):
        inventory, api = self.all_project_applied_api(); registering, _reading = self.project_origins_api()
        globals_ = self.globals_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            other, _other_project, _other_publication = self.local_owner(scope, 'other')
            token = self.owner(scope)
            originals = (self.c6_unit(writer)[0], self.c6_unit(other)[0])
            for source, original in zip((writer, other), originals):
                registering(source, token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
            before = original_read_files(self.root)
            with api(token, binding()) as (observed, verify):
                self.assertEqual(originals, tuple(row.unit for row in observed))
                self.assertEqual((0, 0), tuple(row.attempt_count for row in observed))
                self.assertTrue(all(row.key_watermarks == () for row in observed))
                self.assertNotEqual(observed[0].project_identity, observed[1].project_identity)
                verify()
            self.assertEqual(before, original_read_files(self.root))
            globals_.record_global_attempt_intent(token, binding(), originals[0])
            before = original_read_files(self.root); reached = []
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(token, binding()) as result:
                    reached.append(result)
            self.assertEqual([], reached); self.assertEqual(before, original_read_files(self.root))
            self.assertEqual((1, 'UNKNOWN'), (globals_.inspect_global_unit(token, binding(), originals[0]).attempt_count,
                                            globals_.inspect_global_unit(token, binding(), originals[0]).outcome))

    def test_all_project_applied_pending_receipt_rebind_revokes_entire_consumer(self):
        inventory, api = self.all_project_applied_api(); registering, _reading = self.project_origins_api()
        globals_ = self.globals_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            other, other_project, _other_publication = self.local_owner(scope, 'other')
            token = self.owner(scope)
            first, _one = self.c6_unit(writer); second, _two = self.c6_unit(other)
            for source, original in ((writer, first), (other, second)):
                registering(source, token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
            generation = json.loads(second.action_preimage)['identity']['generation_id']
            receipt = other_project / '.tracker/generations' / generation / 'RECEIPT'
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(token, binding()) as (observed, verify):
                    self.assertEqual((first, second), tuple(row.unit for row in observed))
                    self.assertEqual((0, 0), tuple(row.attempt_count for row in observed))
                    raw = receipt.read_bytes(); previous = receipt.stat().st_ino
                    preserved = self.root / 'preserved-all-project-applied-receipt'
                    receipt.rename(preserved); receipt.write_bytes(raw); receipt.chmod(0o600)
                    self.assertNotEqual(previous, receipt.stat().st_ino)
                    verify()
            self.assertEqual(raw, preserved.read_bytes()); self.assertEqual(raw, receipt.read_bytes())
            self.assertEqual((0, 0), tuple(globals_.inspect_global_unit(token, binding(), original).attempt_count
                                          for original in (first, second)))

    def test_all_project_applied_cold_uncounted_originals_do_not_reissue_handles_or_write(self):
        _inventory, _api = self.all_project_applied_api(); registering, _reading = self.project_origins_api()
        globals_ = self.globals_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            other, _other_project, _other_publication = self.local_owner(scope, 'other')
            token = self.owner(scope)
            first, _one = self.c6_unit(writer); second, _two = self.c6_unit(other)
            for source, original in ((writer, first), (other, second)):
                registering(source, token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
        before = original_read_files(self.root)
        program = '''import importlib.util,sys
from pathlib import Path
sys.path[:0]=[sys.argv[1],str(Path(sys.argv[1])/'tools')]
spec=importlib.util.spec_from_file_location('cold_uncounted_applied_test_contract',sys.argv[3])
tests=importlib.util.module_from_spec(spec);spec.loader.exec_module(tests)
catalog=tests.load();inventory=tests.load_component('issue_tracker_retained_inventory')
tests.load_component('issue_tracker_remote_history_match')
from test_cases.test_req7_spreadsheet_owner import scoped_fixture,binding
assert catalog.local._ACTIVE=={}
with scoped_fixture(Path(sys.argv[2]),catalog.ownership),catalog.ownership.spreadsheet_owner(binding()) as owner:
 with inventory._hold_all_project_applied_keys(owner,binding()) as (observed,verify):
  assert tuple(row.unit.unit_id for row in observed)==tuple(sys.argv[4:])
  assert tuple(row.attempt_count for row in observed)==(0,0)
  assert observed[0].project_identity!=observed[1].project_identity
  assert all(row.key_watermarks==() for row in observed)
  assert len(catalog.local._ACTIVE)==2 and all(active.handles=={} for active in catalog.local._ACTIVE.values())
  assert not any(hasattr(row,'permit') or hasattr(row,'settled') for row in observed)
  verify()
 assert catalog.local._ACTIVE=={}
print('COLD_TWO_PROJECT_UNCOUNTED_ORIGINALS_NO_APPLIED_OR_HANDLES')
'''
        result = subprocess.run([sys.executable, '-B', '-c', program,
            str(Path(__import__('test_cases').__file__).resolve().parents[1]), str(self.root), __file__,
            first.unit_id, second.unit_id], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual('COLD_TWO_PROJECT_UNCOUNTED_ORIGINALS_NO_APPLIED_OR_HANDLES\n', result.stdout)
        self.assertEqual(before, original_read_files(self.root))

    def test_all_project_c6_unissued_owner_and_path_claims_never_open_foreign_projects(self):
        api = self.project_c6_api()
        with mock.patch.object(self.module.local, '_open_absolute_directory') as opening:
            with self.assertRaises(self.module.UnitCatalogHold):
                with api(object(), binding()):
                    self.fail('unissued spreadsheet owner read a project')
            opening.assert_not_called()
        for claim in ({'projects': ()}, {'writers': ()}, {'receipt': True}, {'settled': True}):
            with self.subTest(claim=tuple(claim)), self.assertRaises(TypeError):
                api(object(), binding(), **claim)

    def test_all_project_c6_real_distinct_projects_with_equal_local_sequences_preserve_original_handles(self):
        api = self.project_c6_api(); registering, _reading = self.project_origins_api()
        with ExitStack() as scope:
            writer, project, _publication = self.local_owner(scope)
            other, other_project, _other_publication = self.local_owner(scope, 'other')
            token = self.owner(scope)
            first, one = self.c6_unit(writer); second, two = self.c6_unit(other)
            registering(writer, token, binding(), first); registering(other, token, binding(), second)
            before = original_read_files(self.root)
            handles = (dict(self.module.local._owner(writer).handles), dict(self.module.local._owner(other).handles))
            with api(token, binding()) as (observed, verify):
                self.assertEqual((first, second), tuple(item.unit for item in observed))
                self.assertEqual(((project.stat().st_dev, project.stat().st_ino),
                    (other_project.stat().st_dev, other_project.stat().st_ino)), tuple(item.project_identity for item in observed))
                self.assertEqual((1, 1), tuple(json.loads(item.c6_facts)['sequence'] for item in observed))
                self.assertEqual((one.sequence, two.sequence), (1, 1))
                self.assertFalse(any(hasattr(item, name) for item in observed for name in ('permit', 'settled', 'writer_token')))
                verify()
            self.assertEqual(before, original_read_files(self.root))
            self.assertEqual(handles, (dict(self.module.local._owner(writer).handles), dict(self.module.local._owner(other).handles)))

    def test_foreign_project_owner_tail_outlives_c6_readers_without_reissuing_handles(self):
        registering, reading = self.project_origins_api()
        with ExitStack() as creation:
            writer, project, _publication = self.local_owner(creation)
            token = self.owner(creation)
            first, _generation = self.c6_unit(writer)
            registering(writer, token, binding(), first)
        self.assertEqual({}, self.module.local._ACTIVE)
        before = original_read_files(self.root)
        with ExitStack() as scope:
            token = self.owner(scope)
            with reading(token, binding()) as (origins, verify_origins):
                with ExitStack() as owner_tail:
                    with self.module._hold_project_c6_from_origins(
                            token, binding(), origins, _owner_tail=owner_tail) as (rows, verify):
                        self.assertEqual((first,), tuple(row.unit for row in rows))
                        self.assertEqual(1, len(self.module.local._ACTIVE))
                        foreign = next(iter(self.module.local._ACTIVE))
                        actual_owner = self.module.local._owner(foreign)
                        self.assertEqual(str(project), str(actual_owner.project))
                        self.assertEqual({}, actual_owner.handles)
                        verify_origins(); verify()
                    # Semantic C6 readers have exited, but the genuine owner
                    # and its original exclusion must survive raw tail checks.
                    self.assertIs(actual_owner, self.module.local._owner(foreign))
                    self.assertEqual({}, actual_owner.handles)
                    import fcntl
                    fd = os.open(project / '.tracker/LOCK', os.O_RDWR)
                    try:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    finally:
                        os.close(fd)
                    verify_origins()
                self.assertEqual({}, self.module.local._ACTIVE)
                with self.assertRaises(self.module.local.LocalCommitHold):
                    self.module.local._owner(foreign)
        self.assertEqual(before, original_read_files(self.root))

    def test_foreign_project_owner_tail_rejects_non_stack_before_acquisition(self):
        with ExitStack() as scope:
            token = self.owner(scope)
            with mock.patch.object(self.module.local, '_try_original_writer_owner') as acquiring:
                for tail in (object(), {'scope': ExitStack()}, True):
                    reached = []
                    with self.subTest(tail=type(tail).__name__), self.assertRaises(self.module.UnitCatalogHold):
                        with self.module._hold_project_c6_from_origins(
                                token, binding(), (), _owner_tail=tail):
                            reached.append(True)
                    self.assertEqual([], reached, 'caller-shaped owner tail yielded a proof')
                acquiring.assert_not_called()

    def test_all_project_c6_missing_second_project_receipt_yields_no_valid_prefix_or_repair(self):
        api = self.project_c6_api(); registering, _reading = self.project_origins_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            other, other_project, _other_publication = self.local_owner(scope, 'other')
            token = self.owner(scope)
            first, _one = self.c6_unit(writer); second, two = self.c6_unit(other)
            registering(writer, token, binding(), first); registering(other, token, binding(), second)
            receipt = other_project / '.tracker/generations' / two.generation_id / 'RECEIPT'
            receipt.rename(self.root / 'preserved-second-receipt')
            before = original_read_files(self.root); reached = []
            with self.assertRaises(self.module.UnitCatalogHold):
                with api(token, binding()) as result:
                    reached.append(result)
            self.assertEqual([], reached)
            self.assertEqual(before, original_read_files(self.root))
            self.assertFalse(receipt.exists())

    def test_all_project_c6_second_receipt_same_byte_rebind_revokes_whole_consumer(self):
        api = self.project_c6_api(); registering, _reading = self.project_origins_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            other, other_project, _other_publication = self.local_owner(scope, 'other')
            token = self.owner(scope)
            first, _one = self.c6_unit(writer); second, two = self.c6_unit(other)
            registering(writer, token, binding(), first); registering(other, token, binding(), second)
            receipt = other_project / '.tracker/generations' / two.generation_id / 'RECEIPT'
            with self.assertRaises(self.module.UnitCatalogHold):
                with api(token, binding()) as (observed, verify):
                    self.assertEqual(2, len(observed))
                    raw = receipt.read_bytes(); original_ino = receipt.stat().st_ino
                    preserved = self.root / 'original-second-receipt'
                    receipt.rename(preserved); receipt.write_bytes(raw); receipt.chmod(0o600)
                    self.assertNotEqual(original_ino, receipt.stat().st_ino)
                    verify()
            self.assertEqual(raw, preserved.read_bytes())
            self.assertEqual(raw, receipt.read_bytes())

    def test_all_project_c6_cold_independent_process_reacquires_original_projects_without_handles(self):
        api = self.project_c6_api(); registering, _reading = self.project_origins_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            other, _other_project, _other_publication = self.local_owner(scope, 'other')
            token = self.owner(scope)
            first, _one = self.c6_unit(writer); second, _two = self.c6_unit(other)
            registering(writer, token, binding(), first); registering(other, token, binding(), second)
        before = original_read_files(self.root)
        program = '''import importlib.util,sys
from pathlib import Path
sys.path[:0]=[sys.argv[1],str(Path(sys.argv[1])/'tools')]
spec=importlib.util.spec_from_file_location('cold_projects_test_contract',sys.argv[3])
tests=importlib.util.module_from_spec(spec);spec.loader.exec_module(tests)
catalog=tests.load();root=Path(sys.argv[2])
from test_cases.test_req7_spreadsheet_owner import scoped_fixture,binding
assert catalog.local._ACTIVE=={}
with scoped_fixture(root,catalog.ownership),catalog.ownership.spreadsheet_owner(binding()) as owner:
 with catalog.hold_pending_project_c6_units(owner,binding()) as (observed,verify):
  assert tuple(item.unit.unit_id for item in observed)==tuple(sys.argv[4:])
  assert len(catalog.local._ACTIVE)==2
  assert all(active.handles=={} for active in catalog.local._ACTIVE.values())
  assert not any(hasattr(item,'permit') or hasattr(item,'writer_token') for item in observed)
  verify()
 assert catalog.local._ACTIVE=={}
print('COLD_TWO_REAL_PROJECT_C6_ORIGINALS_NO_HANDLES')
'''
        result = subprocess.run([sys.executable, '-B', '-c', program,
            str(Path(__import__('test_cases').__file__).resolve().parents[1]), str(self.root), __file__,
            first.unit_id, second.unit_id], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual('COLD_TWO_REAL_PROJECT_C6_ORIGINALS_NO_HANDLES\n', result.stdout)
        self.assertEqual(before, original_read_files(self.root))

    def test_all_project_c6_busy_foreign_real_lock_holds_without_waiting_or_partial_prefix(self):
        api = self.project_c6_api(); registering, _reading = self.project_origins_api()
        import time
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            other, other_project, _other_publication = self.local_owner(scope, 'other')
            token = self.owner(scope)
            first, _one = self.c6_unit(writer); second, _two = self.c6_unit(other)
            registering(writer, token, binding(), first); registering(other, token, binding(), second)
        before = original_read_files(self.root)
        from test_cases.test_req7_native_supervised_workflow import owned_ready_lock_holder
        with owned_ready_lock_holder(other_project / '.tracker/LOCK') as child:
            with ExitStack() as scope:
                token = self.owner(scope); reached = []; started = time.monotonic()
                with self.assertRaises(self.module.UnitCatalogHold):
                    with api(token, binding()) as result:
                        reached.append(result)
                self.assertLess(time.monotonic() - started, 2.0)
                self.assertEqual([], reached)
                self.assertEqual({}, self.module.local._ACTIVE)
            self.assertEqual(before, original_read_files(self.root))
        self.assertEqual(0, child.returncode)

    def test_all_project_c6_cold_same_byte_writer_lock_replacement_is_not_original_exclusion(self):
        api = self.project_c6_api(); registering, _reading = self.project_origins_api()
        with ExitStack() as scope:
            writer, project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            original, _one = self.c6_unit(writer)
            registering(writer, token, binding(), original)
        lock = project / '.tracker/LOCK'; lock_object = (lock.stat().st_dev, lock.stat().st_ino)
        preserved = self.root / 'preserved-original-writer-lock'
        raw = lock.read_bytes(); lock.rename(preserved); lock.write_bytes(raw); lock.chmod(0o600)
        self.assertNotEqual(lock_object, (lock.stat().st_dev, lock.stat().st_ino))
        before = original_read_files(self.root); reached = []
        with ExitStack() as scope:
            token = self.owner(scope)
            with self.assertRaises(self.module.UnitCatalogHold):
                with api(token, binding()) as result:
                    reached.append(result)
            self.assertEqual([], reached)
            self.assertEqual({}, self.module.local._ACTIVE)
        self.assertEqual(before, original_read_files(self.root))
        self.assertEqual(raw, preserved.read_bytes())

    def cold_project_replacement_must_not_acquire_foreign_lock(self, replacement):
        import shutil
        api = self.project_c6_api(); registering, _reading = self.project_origins_api()
        with ExitStack() as scope:
            writer, project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            original, _one = self.c6_unit(writer)
            registering(writer, token, binding(), original)
        if replacement == 'LOCK':
            lock = project / '.tracker/LOCK'
            raw = lock.read_bytes()
            lock.rename(self.root / 'preserved-original-lock-before-acquire')
            lock.write_bytes(raw); lock.chmod(0o600)
        else:
            preserved = self.root / 'preserved-original-project-before-acquire'
            project.rename(preserved)
            shutil.copytree(preserved, project)
            lock = project / '.tracker/LOCK'
        foreign = (lock.stat().st_dev, lock.stat().st_ino)
        before = original_read_files(self.root); acquired = []; reached = []
        flock = self.module.local.fcntl.flock
        def observe_acquisition(fd, flags):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == foreign and flags & self.module.local.fcntl.LOCK_EX:
                acquired.append(foreign)
            return flock(fd, flags)
        with ExitStack() as scope:
            token = self.owner(scope)
            with mock.patch.object(self.module.local.fcntl, 'flock', side_effect=observe_acquisition):
                with self.assertRaises(self.module.UnitCatalogHold):
                    with api(token, binding()) as result:
                        reached.append(result)
            self.assertEqual([], acquired, 'a rejected foreign replacement must never be locked as the original project')
            self.assertEqual([], reached)
            self.assertEqual({}, self.module.local._ACTIVE)
        self.assertEqual(before, original_read_files(self.root))

    def test_all_project_c6_cold_replaced_lock_is_refused_before_foreign_flock(self):
        self.cold_project_replacement_must_not_acquire_foreign_lock('LOCK')

    def test_all_project_c6_cold_replaced_project_is_refused_before_foreign_flock(self):
        self.cold_project_replacement_must_not_acquire_foreign_lock('project')

    def test_project_origin_unissued_writer_and_caller_path_or_receipt_overrides_never_read(self):
        registering, reading = self.project_origins_api()
        with mock.patch.object(self.module.local, '_open_absolute_directory') as opening:
            with self.assertRaises(self.module.UnitCatalogHold):
                registering(object(), object(), binding(), self.first)
            opening.assert_not_called()
        for claim in ({'project': self.root}, {'publication': self.root}, {'generation': object()}, {'receipt': True}):
            with self.subTest(claim=tuple(claim)), self.assertRaises(TypeError):
                registering(object(), object(), binding(), self.first, **claim)
        for claim in ({'projects': ()}, {'units': ()}, {'paths': ()}, {'settled': True}):
            with self.subTest(claim=tuple(claim)), self.assertRaises(TypeError):
                reading(object(), binding(), **claim)

    def test_project_origin_two_real_projects_bind_distinct_original_roots_without_global_sequence_comparison(self):
        registering, reading = self.project_origins_api()
        with ExitStack() as scope:
            writer, project, publication = self.local_owner(scope)
            other, other_project, other_publication = self.local_owner(scope, 'other')
            token = self.owner(scope)
            first, generation = self.c6_unit(writer)
            second, other_generation = self.c6_unit(other)
            registering(writer, token, binding(), first)
            registering(other, token, binding(), second)
            before = original_read_files(self.root)
            handles = (dict(self.module.local._owner(writer).handles), dict(self.module.local._owner(other).handles))
            with reading(token, binding()) as (origins, verify):
                self.assertEqual((first, second), tuple(item.unit for item in origins))
                self.assertEqual((str(project), str(other_project)), tuple(item.project_path for item in origins))
                self.assertEqual((str(publication), str(other_publication)), tuple(item.publication_path for item in origins))
                self.assertEqual(((project.stat().st_dev, project.stat().st_ino),
                                  (other_project.stat().st_dev, other_project.stat().st_ino)), tuple(item.project_identity for item in origins))
                # Both projects legitimately have local sequence 1. Never
                # compare these numbers as a spreadsheet-wide high-water.
                self.assertEqual((1, 1), (generation.sequence, other_generation.sequence))
                self.assertFalse(any(hasattr(item, 'permit') or hasattr(item, 'settled') for item in origins))
                verify()
            self.assertEqual(handles, (dict(self.module.local._owner(writer).handles), dict(self.module.local._owner(other).handles)))
            self.assertEqual(before, original_read_files(self.root))

    def test_project_origin_unreceipted_c6_never_creates_catalog_or_origin_witness(self):
        registering, _reading = self.project_origins_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            original, _generation = self.c6_unit(writer, committed=False)
            before = original_read_files(self.root)
            with self.assertRaises(self.module.UnitCatalogHold):
                registering(writer, token, binding(), original)
            self.assertEqual(before, original_read_files(self.root))
            self.assertFalse((self.parent / (STEM + '.units')).exists())

    def test_project_origin_existing_empty_store_never_adopted_or_catalog_appended(self):
        registering, _reading = self.project_origins_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            self.module.register_pending_unit(token, binding(), self.first)
            original, _generation = self.c6_unit(writer)
            folder = self.parent / (STEM + '.unit-' + original.unit_id + '.project-origin')
            folder.mkdir(mode=0o700)
            before = original_read_files(self.root)
            self.assertTrue((self.parent / (STEM + '.units')).exists())
            folder_object = (folder.stat().st_dev, folder.stat().st_ino)
            with self.assertRaises(self.module.UnitCatalogHold):
                registering(writer, token, binding(), original)
            self.assertEqual(before, original_read_files(self.root))
            self.assertEqual(folder_object, (folder.stat().st_dev, folder.stat().st_ino))
            self.assertEqual([], list(folder.iterdir()))
            self.assertTrue((self.parent / (STEM + '.units')).exists())

    def test_project_origin_missing_whole_store_remains_hold_without_repair_or_valid_prefix(self):
        registering, reading = self.project_origins_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            originals = tuple(self.c6_unit(writer)[0] for _ in range(2))
            for original in originals:
                registering(writer, token, binding(), original)
            folder = self.parent / (STEM + '.unit-' + originals[1].unit_id + '.project-origin')
            folder.rename(self.root / 'preserved-project-origin')
            before = original_read_files(self.root); reached = []
            with self.assertRaises(self.module.UnitCatalogHold):
                with reading(token, binding()) as result:
                    reached.append(result)
            with self.assertRaises(self.module.UnitCatalogHold):
                registering(writer, token, binding(), originals[1])
            self.assertEqual([], reached)
            self.assertEqual(before, original_read_files(self.root))
            self.assertFalse(folder.exists())

    def test_project_origins_are_covered_by_actual_global_counts_and_retained_inventory(self):
        registering, _reading = self.project_origins_api()
        globals_ = self.globals_api(); inventory, _unused = self.inventory_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            other, _other_project, _other_publication = self.local_owner(scope, 'other')
            token = self.owner(scope)
            originals = (self.c6_unit(writer)[0], self.c6_unit(other)[0])
            for source, original in zip((writer, other), originals):
                registering(source, token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
            first_count = globals_.record_global_attempt_intent(token, binding(), originals[0])
            self.assertEqual((1, 'UNKNOWN'), (first_count.attempt_count, first_count.outcome))
            before = original_read_files(self.root)
            counts = globals_.inspect_catalog_global_units(token, binding())
            self.assertEqual((1, 0), tuple(state.attempt_count for _unit, state in counts))
            with inventory._hold_catalog_retained_inventory(token, binding()) as (observed, verify):
                self.assertEqual(originals, tuple(item.unit for item in observed))
                self.assertEqual((1, 0), tuple(item.attempt_count for item in observed))
                self.assertTrue(all('project-origin' in item.families for item in observed))
                for item in observed:
                    self.assertEqual({'STARTED', 'ORIGIN', 'WITNESS'},
                        {relative.rsplit('/', 1)[1] for relative, _identity, _sha in item.originals
                         if '.project-origin/' in relative})
                verify()
            self.assertEqual(before, original_read_files(self.root))
            self.assertEqual((1, 'UNKNOWN'), (globals_.inspect_global_unit(token, binding(), originals[0]).attempt_count,
                                            globals_.inspect_global_unit(token, binding(), originals[0]).outcome))

    def test_missing_older_project_origin_blocks_new_registration_before_catalog_append(self):
        registering, _reading = self.project_origins_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            first, _one = self.c6_unit(writer)
            registering(writer, token, binding(), first)
            second, _two = self.c6_unit(writer)
            old_origin = self.parent / (STEM + '.unit-' + first.unit_id + '.project-origin')
            old_origin.rename(self.root / 'preserved-old-origin')
            before = original_read_files(self.root)
            with self.assertRaises(self.module.UnitCatalogHold):
                registering(writer, token, binding(), second)
            self.assertEqual(before, original_read_files(self.root))
            with self.module.hold_pending_units(token, binding()) as (observed, verify):
                self.assertEqual((first,), observed)
                verify()
            self.assertFalse((self.parent / (STEM + '.unit-' + second.unit_id + '.project-origin')).exists())

    def test_project_origin_same_byte_rebind_revokes_actual_global_count_scope_without_repair(self):
        registering, _reading = self.project_origins_api(); globals_ = self.globals_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            original, _generation = self.c6_unit(writer)
            registering(writer, token, binding(), original)
            globals_.prepare_global_unit(token, binding(), original)
            origin = self.parent / (STEM + '.unit-' + original.unit_id + '.project-origin/ORIGIN')
            with self.assertRaises(globals_.GlobalAttemptHold):
                with globals_._hold_catalog_attempts(token, binding()) as (observed, verify):
                    self.assertEqual(((original, 0),), tuple((unit, state.attempt_count) for unit, state in observed))
                    raw = origin.read_bytes(); original_ino = origin.stat().st_ino
                    preserved = self.root / 'preserved-origin-pair'
                    origin.rename(preserved); origin.write_bytes(raw); origin.chmod(0o600)
                    self.assertNotEqual(original_ino, origin.stat().st_ino)
                    verify()
            self.assertEqual(raw, origin.read_bytes()); self.assertEqual(raw, preserved.read_bytes())
            before = original_read_files(self.root)
            with self.assertRaises(globals_.GlobalAttemptHold):
                globals_.record_global_attempt_intent(token, binding(), original)
            self.assertEqual(before, original_read_files(self.root))

    def setUp(self):
        self.module = load()
        self.temporary = tempfile.TemporaryDirectory(prefix='req7-unit-catalog-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.parent = self.root / 'var/lib/http-ztp-container/issue-tracker'
        self.parent.mkdir(parents=True, mode=0o700)
        self.first = unit(); self.second = unit(generation_id='f' * 64)

    def owner(self, scope):
        module = self.module.ownership
        scope.enter_context(scoped_fixture(self.root, module))
        return scope.enter_context(module.spreadsheet_owner(binding()))

    def c6_api(self):
        api = getattr(self.module, 'hold_pending_c6_units', None)
        self.assertTrue(callable(api), 'pending originals must join actual C6 receipts without caller generations')
        return api

    def applied_api(self):
        inventory, _reading = self.inventory_api()
        api = getattr(inventory, '_hold_catalog_applied_keys', None)
        self.assertTrue(callable(api), 'ALL catalog units must bind actual C6/COMPLETE/APPLIED/key originals')
        return inventory, api

    def key_order_api(self):
        inventory, _applied = self.applied_api()
        api = getattr(inventory, '_hold_catalog_key_order', None)
        self.assertTrue(callable(api), 'key maxima and pending order must use ALL held original APPLIED/C6 units')
        return inventory, api

    def test_key_maximum_fold_is_order_independent_and_never_counts_unattempted_or_noop_keys(self):
        inventory, _reading = self.inventory_api()
        fold = getattr(inventory, '_project_applied_maxima', None)
        self.assertTrue(callable(fold), 'original APPLIED per-key maximum fold is absent')
        project = (7, 11)
        # Pure arithmetic contract only: these constructed observations are
        # NOT original proof. The actual held reader is tested separately.
        key_a = ('switch', 'node0001', 'down', 'fabric')
        key_b = ('switch', 'node0002', 'down', 'fabric')
        rows = (inventory.CatalogUnitAppliedKeys(None, 1, ((key_a, 9), (key_b, 3)), project),
                inventory.CatalogUnitAppliedKeys(None, 2, ((key_a, 5),), project),
                inventory.CatalogUnitAppliedKeys(None, 0, (), project))
        expected = ((key_a, 9), (key_b, 3))
        self.assertEqual(expected, fold(rows, project))
        self.assertEqual(expected, fold(tuple(reversed(rows)), project))

    def test_key_maximum_fold_refuses_cross_project_sequences_and_unattempted_applied_claims(self):
        inventory, _reading = self.inventory_api()
        fold = getattr(inventory, '_project_applied_maxima', None)
        self.assertTrue(callable(fold), 'per-project sequences cannot be compared across project identities')
        project = (7, 11); key = ('switch', 'node0001', 'down', 'fabric')
        for row in (inventory.CatalogUnitAppliedKeys(None, 1, ((key, 99),), (7, 12)),
                    inventory.CatalogUnitAppliedKeys(None, 0, ((key, 99),), project)):
            with self.subTest(row=row), self.assertRaises(inventory.RetainedInventoryHold):
                fold((row,), project)

    def test_catalog_key_order_unissued_writer_and_caller_maxima_never_open_originals(self):
        inventory, api = self.key_order_api()
        with mock.patch.object(inventory, '_hold_catalog_applied_keys') as reading:
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(object(), object(), binding()):
                    self.fail('caller obtained original key order without the writer')
            reading.assert_not_called()
        for claim in ({'maxima': ()}, {'observations': ()}, {'project_identity': (1, 2)}, {'settled': True}):
            with self.subTest(claim=tuple(claim)), self.assertRaises(TypeError):
                api(object(), object(), binding(), **claim)

    def test_catalog_key_order_pending_native_c6_has_no_applied_maximum_or_reissued_handle(self):
        _inventory, api = self.key_order_api(); globals_ = self.globals_api()
        with ExitStack() as scope:
            writer, project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            originals = tuple(self.c6_unit(writer)[0] for _ in range(2))
            for original in originals:
                self.module.register_pending_unit(token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
            before = original_read_files(self.root)
            handles = dict(self.module.local._owner(writer).handles)
            with api(writer, token, binding()) as (observed, verify):
                self.assertEqual((project.stat().st_dev, project.stat().st_ino), observed.project_identity)
                self.assertEqual((), observed.applied_maxima)
                # This file fixture has TWO manifest keys, unlike the native
                # completed fixture's one actually-sent key. Literal expected
                # values come from this independent fixture contract.
                self.assertEqual(((originals[0].unit_id, 1, ((('switch', 'node0000', 'down', 'fabric'), 0),
                                                            (('switch', 'node0001', 'down', 'fabric'), 0))),
                                  (originals[1].unit_id, 2, ((('switch', 'node0000', 'down', 'fabric'), 0),
                                                            (('switch', 'node0001', 'down', 'fabric'), 0)))),
                                 observed.pending_keys)
                self.assertFalse(hasattr(observed, 'permit') or hasattr(observed, 'settled'))
                verify()
            self.assertEqual(handles, self.module.local._owner(writer).handles)
            self.assertEqual(before, original_read_files(self.root))

    def test_catalog_key_order_unknown_cannot_yield_partial_maximum_or_pending_order(self):
        inventory, api = self.key_order_api(); globals_ = self.globals_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            originals = tuple(self.c6_unit(writer)[0] for _ in range(2))
            for original in originals:
                self.module.register_pending_unit(token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
            globals_.record_global_attempt_intent(token, binding(), originals[0])
            before = original_read_files(self.root); reached = []
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(writer, token, binding()) as result:
                    reached.append(result)
            self.assertEqual([], reached)
            self.assertEqual(before, original_read_files(self.root))
            self.assertEqual(((1, 'UNKNOWN'), (0, 'UNATTEMPTED_OBSERVATION')),
                             tuple((row.attempt_count, row.outcome) for _unit, row in globals_.inspect_catalog_global_units(token, binding())))

    def test_catalog_applied_unissued_writer_or_caller_settlement_claim_never_reads_inventory(self):
        inventory, api = self.applied_api()
        with mock.patch.object(inventory, '_hold_catalog_retained_inventory') as reading:
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(object(), object(), binding()):
                    self.fail('unissued writer reached catalog settlement')
            reading.assert_not_called()
        for claims in ({'units': ()}, {'generation': object()}, {'keys': ()}, {'applied': True}, {'project': self.root}):
            with self.subTest(claim=tuple(claims)), self.assertRaises(TypeError):
                api(object(), object(), binding(), **claims)

    def test_catalog_applied_unattempted_original_c6_units_have_no_applied_keys_or_new_authority(self):
        inventory, api = self.applied_api(); globals_ = self.globals_api()
        with ExitStack() as scope:
            writer, project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            originals = tuple(self.c6_unit(writer)[0] for _ in range(2))
            for original in originals:
                self.module.register_pending_unit(token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
            before = original_read_files(self.root)
            handles = dict(self.module.local._owner(writer).handles)
            with api(writer, token, binding()) as (observations, verify):
                self.assertEqual(originals, tuple(item.unit for item in observations))
                self.assertEqual((0, 0), tuple(item.attempt_count for item in observations))
                self.assertEqual(((), ()), tuple(item.key_watermarks for item in observations))
                identity = (project.stat().st_dev, project.stat().st_ino)
                self.assertEqual((identity, identity), tuple(item.project_identity for item in observations))
                self.assertFalse(any(hasattr(item, 'permit') or hasattr(item, 'applied') for item in observations))
                verify()
            self.assertEqual(handles, self.module.local._owner(writer).handles)
            self.assertEqual(before, original_read_files(self.root))
            self.assertFalse(any('REMOTE-APPLIED' in name or 'REMOTE-KEY-HIGH' in name for name in before))

    def test_catalog_applied_any_unknown_without_complete_rejects_all_and_preserves_count(self):
        inventory, api = self.applied_api(); globals_ = self.globals_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            originals = tuple(self.c6_unit(writer)[0] for _ in range(2))
            for original in originals:
                self.module.register_pending_unit(token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
            globals_.record_global_attempt_intent(token, binding(), originals[0])
            before = original_read_files(self.root); yielded = []
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(writer, token, binding()) as result:
                    yielded.append(result)
            self.assertEqual([], yielded)
            self.assertEqual(before, original_read_files(self.root))
            actual = globals_.inspect_catalog_global_units(token, binding())
            self.assertEqual(((1, 'UNKNOWN'), (0, 'UNATTEMPTED_OBSERVATION')),
                             tuple((state.attempt_count, state.outcome) for _unit, state in actual))

    def test_catalog_applied_owner_reacquisition_preserves_all_originals_and_issues_no_generation_handles(self):
        _inventory, api = self.applied_api(); globals_ = self.globals_api()
        with ExitStack() as scope:
            writer, project, publication = self.local_owner(scope)
            token = self.owner(scope)
            originals = tuple(self.c6_unit(writer)[0] for _ in range(2))
            for original in originals:
                self.module.register_pending_unit(token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
        before = original_read_files(self.root)
        with ExitStack() as scope:
            writer = scope.enter_context(self.module.local.writer_owner(project, publication))
            token = self.owner(scope)
            actual_writer = self.module.local._owner(writer)
            self.assertEqual({}, actual_writer.handles)
            with api(writer, token, binding()) as (observed, verify):
                self.assertEqual(originals, tuple(row.unit for row in observed))
                self.assertEqual(((), ()), tuple(row.key_watermarks for row in observed))
                self.assertEqual({}, actual_writer.handles); verify()
            self.assertEqual({}, actual_writer.handles)
        self.assertEqual(before, original_read_files(self.root))

    def test_key_order_independent_cold_process_reopens_pending_and_holds_actual_unknown(self):
        _inventory, _api = self.key_order_api(); globals_ = self.globals_api()
        with ExitStack() as scope:
            writer, project, publication = self.local_owner(scope)
            token = self.owner(scope)
            originals = tuple(self.c6_unit(writer)[0] for _ in range(2))
            for original in originals:
                self.module.register_pending_unit(token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
        program = '''import importlib.util,sys
from pathlib import Path
sys.path[:0]=[sys.argv[1],str(Path(sys.argv[1])/'tools')]
spec=importlib.util.spec_from_file_location('cold_catalog_contract',sys.argv[3])
tests=importlib.util.module_from_spec(spec); spec.loader.exec_module(tests)
catalog=tests.load(); inventory=tests.load_component('issue_tracker_retained_inventory')
from monitor import issue_tracker_spreadsheet_owner as ownership,issue_tracker_global_attempt_journal as globals_
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
root=Path(sys.argv[2]); bound=tests.binding()
with catalog.local.writer_owner(root/'project',root/'project/publication') as writer,scoped_fixture(root,ownership),ownership.spreadsheet_owner(bound) as owner:
 assert catalog.local._owner(writer).handles=={}
 if sys.argv[4]=='pending':
  with inventory._hold_catalog_key_order(writer,owner,bound) as (observed,verify):
   assert observed.applied_maxima==()
   assert tuple((sequence,keys) for _unit,sequence,keys in observed.pending_keys)==(
    (1,((('switch','node0000','down','fabric'),0),(('switch','node0001','down','fabric'),0))),
    (2,((('switch','node0000','down','fabric'),0),(('switch','node0001','down','fabric'),0))))
   verify()
  print('catalog-key-order cold PENDING original')
 else:
  reached=[]
  try:
   with inventory._hold_catalog_key_order(writer,owner,bound) as result: reached.append(result)
  except inventory.RetainedInventoryHold: pass
  else: raise AssertionError('actual UNKNOWN yielded a cold partial key order')
  assert reached==[]
  states=globals_.inspect_catalog_global_units(owner,bound)
  assert tuple((row.attempt_count,row.outcome) for _unit,row in states)==((1,'UNKNOWN'),(0,'UNATTEMPTED_OBSERVATION'))
  print('catalog-key-order cold UNKNOWN retained')
 assert catalog.local._owner(writer).handles=={}
'''
        root_source = Path(__import__('test_cases').__file__).resolve().parents[1]
        def cold(phase):
            before = original_read_files(self.root)
            result = subprocess.run([sys.executable, '-B', '-c', program,
                str(root_source), str(self.root), str(Path(__file__)), phase],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(0, result.returncode, result.stderr)
            expected = (b'catalog-key-order cold PENDING original\n' if phase == 'pending'
                        else b'catalog-key-order cold UNKNOWN retained\n')
            self.assertEqual(expected, result.stdout); self.assertEqual(b'', result.stderr)
            self.assertEqual(before, original_read_files(self.root))
        cold('pending')
        with ExitStack() as scope:
            writer = scope.enter_context(self.module.local.writer_owner(project, publication))
            token = self.owner(scope)
            globals_.record_global_attempt_intent(token, binding(), originals[0])
        cold('unknown')

    def test_unsent_supersession_requires_every_sent_candidate_key_strictly_later_applied(self):
        inventory, _api = self.key_order_api()
        decide = getattr(inventory, '_superseded_unsent_candidates', None)
        self.assertTrue(callable(decide), 'C6 supersession needs every key later APPLIED, not later SENT')
        a = ('switch', 'node0000', 'down', 'fabric')
        b = ('switch', 'node0001', 'down', 'fabric')
        # This is only the comparison contract, never original proof.
        order = inventory.CatalogProjectKeyOrder((7, 11), ((a, 9), (b, 5)), (
            ('fully-covered', 3, ((a, 9), (b, 5))),
            ('partial-only', 6, ((a, 9), (b, 5))),
            ('equal-is-not-later', 5, ((b, 5),)),
            ('missing-applied', 1, ((('switch', 'other', 'down', 'fabric'), 0),))))
        self.assertEqual((('fully-covered', 3, ((a, 9), (b, 5))),), decide(order))

    def test_unsent_supersession_unissued_writer_or_caller_claims_never_open_originals(self):
        inventory, _api = self.key_order_api()
        api = getattr(inventory, '_hold_catalog_unsent_supersession_inputs', None)
        self.assertTrue(callable(api), 'supersession must hold actual C6/APPLIED inputs throughout consumption')
        with mock.patch.object(inventory, '_hold_catalog_key_order') as read:
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(object(), object(), binding()):
                    self.fail('unissued writer obtained supersession inputs')
            read.assert_not_called()
        for claim in ({'settled': True}, {'maxima': ()}, {'sent': True}, {'unit_id': 'caller'}):
            with self.subTest(claim=tuple(claim)), self.assertRaises(TypeError):
                api(object(), object(), binding(), **claim)

    def test_unattempted_and_actual_unknown_never_become_supersession_inputs(self):
        inventory, _api = self.key_order_api(); globals_ = self.globals_api()
        api = getattr(inventory, '_hold_catalog_unsent_supersession_inputs', None)
        self.assertTrue(callable(api), 'UNSENT supersession cannot be inferred from a later pending unit')
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            originals = tuple(self.c6_unit(writer)[0] for _ in range(2))
            for original in originals:
                self.module.register_pending_unit(token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
            before = original_read_files(self.root)
            with api(writer, token, binding()) as (candidates, verify):
                self.assertEqual((), candidates); verify()
            self.assertEqual(before, original_read_files(self.root))
            globals_.record_global_attempt_intent(token, binding(), originals[0])
            before = original_read_files(self.root)
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(writer, token, binding()):
                    self.fail('actually counted UNKNOWN was called superseded-not-sent')
            self.assertEqual(before, original_read_files(self.root))

    def test_unsent_disposition_unissued_writer_and_caller_supersession_flags_are_refused(self):
        inventory, _api = self.key_order_api()
        read = getattr(inventory, '_hold_catalog_unsent_dispositions', None)
        record = getattr(inventory, '_record_catalog_unsent_dispositions', None)
        self.assertTrue(callable(read) and callable(record), 'durable UNSENT disposition needs original-only read/write APIs')
        with mock.patch.object(inventory, '_hold_catalog_applied_keys') as originals:
            with self.assertRaises(inventory.RetainedInventoryHold):
                record(object(), object(), binding())
            with self.assertRaises(inventory.RetainedInventoryHold):
                with read(object(), object(), binding()):
                    self.fail('unissued writer read a durable supersession')
            originals.assert_not_called()
        for api in (read, record):
            for claim in ({'settled': True}, {'maxima': ()}, {'unit_id': 'caller'}, {'record': True}):
                with self.subTest(api=api.__name__, claim=tuple(claim)), self.assertRaises(TypeError):
                    api(object(), object(), binding(), **claim)

    def test_unsent_disposition_no_later_applied_never_writes_or_promotes_pending(self):
        inventory, _api = self.key_order_api(); globals_ = self.globals_api()
        read = getattr(inventory, '_hold_catalog_unsent_dispositions', None)
        record = getattr(inventory, '_record_catalog_unsent_dispositions', None)
        self.assertTrue(callable(read) and callable(record), 'later pending must not manufacture a supersession record')
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope); token = self.owner(scope)
            originals = tuple(self.c6_unit(writer)[0] for _ in range(2))
            for original in originals:
                self.module.register_pending_unit(token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
            before = original_read_files(self.root)
            self.assertEqual((), record(writer, token, binding()))
            with read(writer, token, binding()) as (observed, verify):
                self.assertEqual((), observed); verify()
            self.assertEqual(before, original_read_files(self.root))
            self.assertEqual((0, 0), tuple(state.attempt_count for _unit, state in globals_.inspect_catalog_global_units(token, binding())))

    def test_unsent_disposition_actual_unknown_remains_hold_with_no_new_record(self):
        inventory, _api = self.key_order_api(); globals_ = self.globals_api()
        read = getattr(inventory, '_hold_catalog_unsent_dispositions', None)
        record = getattr(inventory, '_record_catalog_unsent_dispositions', None)
        self.assertTrue(callable(read) and callable(record), 'UNKNOWN can never become SUPERSEDED-NOT-SENT')
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope); token = self.owner(scope)
            originals = tuple(self.c6_unit(writer)[0] for _ in range(2))
            for original in originals:
                self.module.register_pending_unit(token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
            globals_.record_global_attempt_intent(token, binding(), originals[0])
            before = original_read_files(self.root)
            with self.assertRaises(inventory.RetainedInventoryHold):
                record(writer, token, binding())
            with self.assertRaises(inventory.RetainedInventoryHold):
                with read(writer, token, binding()):
                    self.fail('UNKNOWN gained a durable not-sent disposition')
            self.assertEqual(before, original_read_files(self.root))
            self.assertEqual((1, 0), tuple(state.attempt_count for _unit, state in globals_.inspect_catalog_global_units(token, binding())))

    def globals_api(self):
        from monitor import issue_tracker_global_attempt_journal as global_journal
        self.assertTrue(callable(getattr(global_journal, 'inspect_catalog_global_units', None)),
                        'original multi-unit global journals must not share/reset the legacy unit counter')
        return global_journal

    def inventory_api(self):
        path = SOURCE.with_name('issue_tracker_retained_inventory.py')
        spec = importlib.util.spec_from_file_location('monitor.issue_tracker_retained_inventory', path)
        inventory = importlib.util.module_from_spec(spec); sys.modules[spec.name] = inventory
        spec.loader.exec_module(inventory)
        import monitor
        monitor.issue_tracker_retained_inventory = inventory
        api = getattr(inventory, '_hold_catalog_retained_inventory', None)
        self.assertTrue(callable(api), 'ALL original catalog unit families must stay held, not just their counter')
        return inventory, api

    def test_catalog_inventory_holds_both_journals_and_consumed_dispatch_without_any_authority(self):
        inventory, api = self.inventory_api(); globals_ = self.globals_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            for original in (self.first, self.second):
                self.module.register_pending_unit(token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
            globals_.record_global_attempt_intent(token, binding(), self.first)
            with globals_._hold_counted_original_wire(writer, token, binding(), self.first):
                pass
            before = original_read_files(self.root)
            with api(token, binding()) as (observed, verify):
                self.assertEqual((self.first, self.second), tuple(item.unit for item in observed))
                self.assertEqual((1, 0), tuple(item.attempt_count for item in observed))
                self.assertIn('dispatch', observed[0].families); self.assertNotIn('dispatch', observed[1].families)
                self.assertFalse(any(hasattr(item, 'permit') or hasattr(item, 'applied') for item in observed))
                self.assertTrue(any(name.endswith('/CLAIM-1') for name, _stat, _sha in observed[0].originals))
                verify()
            self.assertEqual(before, original_read_files(self.root))

    def test_catalog_inventory_replays_shared_original_nonces_and_per_unit_history(self):
        _inventory, api = self.inventory_api()
        case, catalog, _remote = self.native_remote_case()
        # Native setup reloads canonical owners/readers; load the private
        # inventory AFTER it, before using their genuine issued tokens.
        inventory, api = self.inventory_api()
        with ExitStack() as scope:
            token = self.prepare_native_remote(case, catalog, scope)
            before = original_read_files(case.root)
            with api(token, binding()) as (observed, verify):
                self.assertEqual(2, len(observed)); self.assertEqual((1, 0), tuple(item.attempt_count for item in observed))
                self.assertTrue(all('enrollment' in item.families for item in observed))
                self.assertIn('history', observed[0].families); self.assertNotIn('history', observed[1].families)
                shared = [next(item for item in row.originals if item[0] == STEM + '.enrollment/NONCES') for row in observed]
                self.assertEqual(shared[0], shared[1]); verify()
            self.assertEqual(before, original_read_files(case.root))

    def test_catalog_inventory_rejects_held_second_unit_replacement(self):
        inventory, api = self.inventory_api(); globals_ = self.globals_api()
        with ExitStack() as scope:
            token = self.owner(scope)
            for original in (self.first, self.second):
                self.module.register_pending_unit(token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
            before = original_read_files(self.root); entered = []
            wire = self.parent / (STEM + '.unit-' + self.second.unit_id + '.journal') / 'WIRE'
            raw = wire.read_bytes()
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(token, binding()) as (observed, verify):
                    entered.append(tuple(row.unit for row in observed))
                    wire.rename(self.root / 'preserved-second-wire')
                    wire.write_bytes(raw); wire.chmod(0o600); verify()
            self.assertEqual([(self.first, self.second)], entered)
            self.assertEqual(raw, (self.root / 'preserved-second-wire').read_bytes())

    def test_catalog_inventory_rejects_partial_later_family_without_a_confounded_wire_fault(self):
        inventory, api = self.inventory_api(); globals_ = self.globals_api()
        with ExitStack() as scope:
            token = self.owner(scope)
            for original in (self.first, self.second):
                self.module.register_pending_unit(token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
            with api(token, binding()) as (observed, verify):
                self.assertEqual((self.first, self.second), tuple(row.unit for row in observed)); verify()
            # Original partial reservation in a later unit cannot be ignored
            # while handing off the apparently valid first-unit prefix.
            folder = self.parent / (STEM + '.unit-' + self.second.unit_id + '.nv')
            folder.mkdir(mode=0o700)
            (folder / 'RESERVATIONS').write_bytes(b'partial later-unit reservation\n')
            (folder / 'RESERVATIONS').chmod(0o600)
            after = original_read_files(self.root); yielded = []
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(token, binding()) as (observed, _verify):
                    yielded.append(observed)
            self.assertEqual([], yielded); self.assertEqual(after, original_read_files(self.root))

    def test_catalog_inventory_required_later_original_fsync_failure_never_yields_a_prefix(self):
        inventory, api = self.inventory_api(); globals_ = self.globals_api()
        with ExitStack() as scope:
            token = self.owner(scope)
            for original in (self.first, self.second):
                self.module.register_pending_unit(token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
            before = original_read_files(self.root)
            path = self.parent / (STEM + '.unit-' + self.second.unit_id + '.journal') / 'WIRE'
            target = (path.stat().st_dev, path.stat().st_ino)
            real_sync = os.fsync; real_completion = inventory._verify_legacy_completion
            armed = []; faulted = []; yielded = []
            def checked(*args, **kwargs):
                result = real_completion(*args, **kwargs)
                if args[4] == self.second:
                    armed.append(True)
                return result
            def sync(fd):
                info = os.fstat(fd)
                if armed and (info.st_dev, info.st_ino) == target:
                    faulted.append(target); raise OSError('owned later original recovery fsync')
                return real_sync(fd)
            with mock.patch.object(inventory, '_verify_legacy_completion', side_effect=checked), \
                    mock.patch.object(os, 'fsync', side_effect=sync), self.assertRaises(inventory.RetainedInventoryHold):
                with api(token, binding()) as (observed, _verify):
                    yielded.append(observed)
            self.assertEqual([True], armed); self.assertEqual([target], faulted)
            self.assertEqual([], yielded); self.assertEqual(before, original_read_files(self.root))

    def test_catalog_inventory_missing_later_journal_is_hold_not_empty_first_use(self):
        inventory, api = self.inventory_api(); globals_ = self.globals_api()
        with ExitStack() as scope:
            token = self.owner(scope)
            for original in (self.first, self.second):
                self.module.register_pending_unit(token, binding(), original)
            globals_.prepare_global_unit(token, binding(), self.first)
            before = original_read_files(self.root)
            with self.assertRaises(inventory.RetainedInventoryHold):
                with api(token, binding()):
                    self.fail('absence was returned as a complete original inventory')
            self.assertEqual(before, original_read_files(self.root))

    def native_remote_case(self):
        from test_cases import test_req7_remote_history_match as native
        from test_cases import test_req7_global_attempt_journal as global_tests
        case = native.Req7RemoteHistoryMatchDirectTests(
            'test_actual_journals_and_both_nonces_fence_all_sent_and_audit_match_without_clearing_unknown')
        with mock.patch.object(global_tests, 'SOURCE', SOURCE.with_name('issue_tracker_global_attempt_journal.py')):
            case.setUp()
        self.addCleanup(case.doCleanups)
        catalog = load(reset_dependencies=False)
        path = SOURCE.with_name('issue_tracker_remote_history_match.py')
        if not path.is_file():
            path = Path(native.__file__).resolve().parents[1] / 'monitor/issue_tracker_remote_history_match.py'
        spec = importlib.util.spec_from_file_location('monitor.issue_tracker_remote_history_match', path)
        remote = importlib.util.module_from_spec(spec); sys.modules[spec.name] = remote
        spec.loader.exec_module(remote)
        import monitor
        monitor.issue_tracker_remote_history_match = remote
        return case, catalog, remote

    def prepare_native_remote(self, case, catalog, scope):
        from test_cases.test_req7_spreadsheet_owner import fixture
        from test_cases.test_req7_history_read import response
        scope.enter_context(fixture(case.root))
        token = scope.enter_context(case.owner.spreadsheet_owner(binding()))
        with mock.patch('secrets.token_hex', side_effect=['a' * 64, 'b' * 64, 'c' * 64, 'd' * 64]):
            case.enrollment.prepare_enrollment_journal(token, binding(), case.identity)
        catalog.register_pending_unit(token, binding(), case.unit)
        other = unit(generation_id='f' * 64, sheet_id=101, history_sheet_id=105,
                     target_nonce='a' * 64, history_nonce='d' * 64)
        catalog.register_pending_unit(token, binding(), other)
        for original in (case.unit, other):
            case.global_journal.prepare_global_unit(token, binding(), original)
        case.before.prepare_history_preread(token, binding(), case.unit, case.plan, response(case.empty))
        case.global_journal.record_global_attempt_intent(token, binding(), case.unit)
        return token

    def test_catalog_remote_match_uses_shared_original_nonce_and_unit_history_without_clearing_unknown(self):
        case, catalog, remote = self.native_remote_case()
        with ExitStack() as scope:
            token = self.prepare_native_remote(case, catalog, scope)
            before = original_read_files(case.root)
            seen = case.observe(remote, token)
            self.assertEqual(('MATCHED_OBSERVATION', 2, 2, 1),
                             (seen.state, seen.history_rows_expected, seen.history_rows_matched, seen.attempt_count))
            self.assertTrue(seen.fence_present); self.assertTrue(seen.target_nonce_valid); self.assertTrue(seen.history_nonce_valid)
            self.assertEqual(before, original_read_files(case.root))
            self.assertEqual((1, 'UNKNOWN'), (case.global_journal.inspect_global_unit(token, binding(), case.unit).attempt_count,
                                             case.global_journal.inspect_global_unit(token, binding(), case.unit).outcome))
            self.assertEqual([STEM + '.enrollment'], sorted(path.name for path in case.state.glob('*.enrollment')))
            self.assertFalse(any('COMPLETE' in key or 'REMOTE-APPLIED' in key for key in before))

    def test_catalog_remote_scope_rejects_same_byte_shared_nonce_rebind_after_actual_handoff(self):
        case, catalog, remote = self.native_remote_case()
        with ExitStack() as scope:
            token = self.prepare_native_remote(case, catalog, scope)
            path = case.state / (STEM + '.enrollment') / 'NONCES'
            raw = path.read_bytes(); before = original_read_files(case.root); entered = []
            with self.assertRaises(remote.RemoteHistoryHold):
                with remote._hold_match_originals(token, binding(), case.unit) as (verify, witness):
                    entered.append(witness)
                    path.rename(case.root / 'preserved-nonces')
                    path.write_bytes(raw); path.chmod(0o600)
                    verify()
            self.assertEqual(1, len(entered), 'the actual reader must yield before the replacement is tested')
            self.assertEqual({STEM + '.unit-' + case.unit.unit_id + '.journal',
                              STEM + '.unit-' + case.unit.unit_id + '.history', STEM + '.enrollment'}, set(entered[0]))
            self.assertEqual(raw, (case.root / 'preserved-nonces').read_bytes())
            after = original_read_files(case.root)
            self.assertEqual(before, {key: (before[key] if key.endswith('.enrollment/NONCES') else value)
                                     for key, value in after.items() if key in before})
            self.assertNotEqual(before[str(path.relative_to(case.root))][0], path.stat().st_ino)
            self.assertEqual(1, case.global_journal.inspect_global_unit(token, binding(), case.unit).attempt_count)

    def test_catalog_global_units_have_distinct_original_journals_and_preserve_pending_images(self):
        globals_ = self.globals_api()
        with ExitStack() as scope:
            token = self.owner(scope)
            for original in (self.first, self.second):
                self.module.register_pending_unit(token, binding(), original)
            globals_.prepare_global_unit(token, binding(), self.first)
            before = original_read_files(self.root)
            globals_.prepare_global_unit(token, binding(), self.second)
            self.assertEqual(before, {key: value for key, value in original_read_files(self.root).items() if key in before})
            observed = globals_.inspect_catalog_global_units(token, binding())
            self.assertEqual(((self.first, 0, 'UNATTEMPTED_OBSERVATION'),
                              (self.second, 0, 'UNATTEMPTED_OBSERVATION')),
                             tuple((original, state.attempt_count, state.outcome) for original, state in observed))
            for original in (self.first, self.second):
                folder = self.parent / (STEM + '.unit-' + original.unit_id + '.journal')
                self.assertEqual(original.wire_bytes, (folder / 'WIRE').read_bytes())
                self.assertEqual(original.action_preimage, (folder / 'ACTION-PREIMAGE').read_bytes())
            self.assertFalse((self.parent / (STEM + '.journal')).exists())
            self.assertFalse(any('ATTEMPT-' in key for key in original_read_files(self.root)))

    def test_catalog_original_key_order_and_any_unknown_block_other_unit_before_count(self):
        globals_ = self.globals_api()
        third = unit(generation_id='9' * 64)
        with ExitStack() as scope:
            token = self.owner(scope)
            for original in (self.first, self.second, third):
                self.module.register_pending_unit(token, binding(), original)
            for original in (self.first, self.second):
                globals_.prepare_global_unit(token, binding(), original)
            before = original_read_files(self.root)
            with self.assertRaises(globals_.GlobalAttemptHold):
                globals_.record_global_attempt_intent(token, binding(), self.second)
            self.assertEqual(before, original_read_files(self.root))
            state = globals_.record_global_attempt_intent(token, binding(), self.first)
            self.assertEqual((1, 'UNKNOWN'), (state.attempt_count, state.outcome))
            after = original_read_files(self.root)
            with self.assertRaises(globals_.GlobalAttemptHold):
                globals_.record_global_attempt_intent(token, binding(), self.second)
            with self.assertRaises(globals_.GlobalAttemptHold):
                globals_.prepare_global_unit(token, binding(), third)
            self.assertEqual(after, original_read_files(self.root))
            self.assertEqual(1, globals_.inspect_global_unit(token, binding(), self.first).attempt_count)
            self.assertEqual(0, globals_.inspect_global_unit(token, binding(), self.second).attempt_count)

    def test_catalog_attempt_limit_survives_owner_reacquisition_without_reset_or_new_wire(self):
        globals_ = self.globals_api()
        with ExitStack() as scope:
            token = self.owner(scope)
            self.module.register_pending_unit(token, binding(), self.first)
            globals_.prepare_global_unit(token, binding(), self.first)
            for count in range(1, 7):
                state = globals_.record_global_attempt_intent(token, binding(), self.first)
                self.assertEqual((count, 'UNKNOWN'), (state.attempt_count, state.outcome))
        before = original_read_files(self.root)
        with ExitStack() as scope:
            token = self.owner(scope)
            self.assertEqual(6, globals_.inspect_global_unit(token, binding(), self.first).attempt_count)
            with self.assertRaises(globals_.GlobalAttemptHold):
                globals_.record_global_attempt_intent(token, binding(), self.first)
            with self.assertRaises(globals_.GlobalAttemptHold):
                globals_.prepare_global_unit(token, binding(), self.first)
        self.assertEqual(before, original_read_files(self.root))

    def test_catalog_counted_original_wire_has_unit_dispatch_and_cold_consumption_not_a_send_permit(self):
        globals_ = self.globals_api()
        project = publication = None
        with ExitStack() as scope:
            writer, project, publication = self.local_owner(scope)
            token = self.owner(scope)
            for original in (self.first, self.second):
                self.module.register_pending_unit(token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
            globals_.record_global_attempt_intent(token, binding(), self.first)
            original_images = original_read_files(self.root)
            with globals_._hold_counted_original_wire(writer, token, binding(), self.first) as image:
                self.assertEqual((1, self.first.wire_sha256), (image.attempt_count, image.wire_sha256))
                self.assertEqual(self.first.wire_bytes, os.pread(image.fd, 1024 * 1024 + 1, 0))
                self.assertEqual(self.first.action_preimage, os.pread(image.action_fd, 1024 * 1024 + 1, 0))
                self.assertFalse(os.get_inheritable(image.fd)); self.assertFalse(hasattr(image, 'permit'))
                dispatch = self.parent / (STEM + '.unit-' + self.first.unit_id + '.dispatch')
                self.assertTrue(dispatch.is_dir(), 'durable consumption must belong to THIS original unit')
                self.assertEqual({'HEADER', 'INITIALIZED', 'CLAIM-1'}, {path.name for path in dispatch.iterdir()})
                self.assertFalse((self.parent / (STEM + '.dispatch')).exists())
                with self.assertRaises(globals_.GlobalAttemptHold):
                    with globals_._hold_counted_original_wire(writer, token, binding(), self.first):
                        self.fail('same durable count was consumed twice')
            self.assertEqual(original_images, {key: value for key, value in original_read_files(self.root).items() if key in original_images})
            observed = globals_.inspect_catalog_global_units(token, binding())
            self.assertEqual(((1, 'UNKNOWN'), (0, 'UNATTEMPTED_OBSERVATION')),
                             tuple((state.attempt_count, state.outcome) for _original, state in observed))
        before = original_read_files(self.root)
        with ExitStack() as scope:
            writer = scope.enter_context(self.module.local.writer_owner(project, publication))
            token = self.owner(scope)
            with self.assertRaises(globals_.GlobalAttemptHold):
                with globals_._hold_counted_original_wire(writer, token, binding(), self.first):
                    self.fail('owner reacquisition resurrected a consumed count')
            self.assertEqual(before, original_read_files(self.root))

    def test_catalog_unknown_blocks_disjoint_keys_and_sheets_but_keeps_same_unit_retry(self):
        from monitor.issue_tracker_send_unit import freeze_send_unit
        globals_ = self.globals_api()
        arguments = send_inputs()
        document = json.loads(arguments['manifest'])
        document['operations'][0]['activity_key'] = ['switch', 'other0000', 'down', 'fabric']
        document['operations'][1]['activity_key'] = ['switch', 'other0001', 'down', 'fabric']
        raw = (json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(',', ':')) + '\n').encode()
        arguments.update(manifest=raw, manifest_id=hashlib.sha256(raw).hexdigest(),
                         generation_id='8' * 64, publish_id='7' * 64, sheet_id=18)
        different = freeze_send_unit(**arguments)
        third = unit(generation_id='6' * 64)
        self.assertEqual([['switch', 'other0000', 'down', 'fabric'], ['switch', 'other0001', 'down', 'fabric']],
                         [row['activity_key'] for row in json.loads(different.action_preimage)['business']])
        with ExitStack() as scope:
            token = self.owner(scope)
            for original in (self.first, different, third):
                self.module.register_pending_unit(token, binding(), original)
            for original in (self.first, different):
                globals_.prepare_global_unit(token, binding(), original)
            # Earlier pending units with DISJOINT keys are not a false FIFO barrier.
            observed = globals_.record_global_attempt_intent(token, binding(), different)
            self.assertEqual((1, 'UNKNOWN'), (observed.attempt_count, observed.outcome))
            before = original_read_files(self.root)
            with self.assertRaises(globals_.GlobalAttemptHold):
                globals_.record_global_attempt_intent(token, binding(), self.first)
            with self.assertRaises(globals_.GlobalAttemptHold):
                globals_.prepare_global_unit(token, binding(), third)
            self.assertEqual(before, original_read_files(self.root))
            observed = globals_.record_global_attempt_intent(token, binding(), different)
            self.assertEqual((2, 'UNKNOWN'), (observed.attempt_count, observed.outcome))
            self.assertEqual(before, {key: value for key, value in original_read_files(self.root).items() if key in before})
            self.assertEqual(0, globals_.inspect_global_unit(token, binding(), self.first).attempt_count)

    def test_cold_catalog_loss_with_original_unknown_must_not_switch_to_legacy_or_register_first_use(self):
        globals_ = self.globals_api()
        for operation in ('prepare-global', 'register-catalog'):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory(prefix='req7-catalog-total-loss-') as temporary:
                old_root, old_parent = self.root, self.parent
                self.root = Path(temporary).resolve()
                self.parent = self.root / 'var/lib/http-ztp-container/issue-tracker'
                self.parent.mkdir(parents=True, mode=0o700)
                try:
                    with ExitStack() as scope:
                        token = self.owner(scope)
                        self.module.register_pending_unit(token, binding(), self.first)
                        globals_.prepare_global_unit(token, binding(), self.first)
                        globals_.record_global_attempt_intent(token, binding(), self.first)
                    for name in (STEM + '.units', STEM + '.units-started', STEM + '.units-position-00000000000000000001'):
                        (self.parent / name).rename(self.root / ('preserved-' + name))
                    before = original_read_files(self.root)
                    with ExitStack() as scope:
                        token = self.owner(scope)
                        exception = globals_.GlobalAttemptHold if operation == 'prepare-global' else self.module.UnitCatalogHold
                        with self.assertRaises(exception):
                            if operation == 'prepare-global':
                                globals_.prepare_global_unit(token, binding(), self.first)
                            else:
                                self.module.register_pending_unit(token, binding(), self.second)
                        self.assertEqual(before, original_read_files(self.root))
                        self.assertFalse((self.parent / (STEM + '.journal')).exists())
                        self.assertFalse((self.parent / (STEM + '.units')).exists())
                finally:
                    self.root, self.parent = old_root, old_parent

    def test_catalog_missing_counted_journal_and_legacy_unknown_cannot_be_recreated_or_ignored(self):
        globals_ = self.globals_api()
        with ExitStack() as scope:
            token = self.owner(scope)
            self.module.register_pending_unit(token, binding(), self.first)
            globals_.prepare_global_unit(token, binding(), self.first)
            globals_.record_global_attempt_intent(token, binding(), self.first)
        folder = self.parent / (STEM + '.unit-' + self.first.unit_id + '.journal')
        folder.rename(self.root / 'preserved-counted-journal')
        before = original_read_files(self.root)
        with ExitStack() as scope:
            token = self.owner(scope)
            for action in ('read', 'prepare'):
                with self.subTest(action=action), self.assertRaises(globals_.GlobalAttemptHold):
                    if action == 'read':
                        globals_.inspect_catalog_global_units(token, binding())
                    else:
                        globals_.prepare_global_unit(token, binding(), self.first)
            self.assertEqual(before, original_read_files(self.root))
            legacy = self.parent / (STEM + '.journal-started')
            legacy.write_bytes(b'original legacy unknown witness\n'); legacy.chmod(0o600)
            with self.assertRaises(globals_.GlobalAttemptHold):
                globals_.inspect_catalog_global_units(token, binding())
            self.assertEqual(b'original legacy unknown witness\n', legacy.read_bytes())

    def local_owner(self, scope, name='project'):
        project = self.root / name; project.mkdir(mode=0o700)
        publication = project / 'publication'; publication.mkdir(mode=0o700)
        self.module.local.create_local_commit_store(project, publication)
        writer = scope.enter_context(self.module.local.writer_owner(project, publication))
        return writer, project, publication

    def c6_unit(self, writer, *, committed=True):
        arguments = send_inputs()
        generation = self.module.local.begin_generation(writer, arguments['manifest'])
        workbook = literal_xlsx()
        self.module.local.record_intent(writer, generation, workbook, kind='xlsx')
        if committed:
            receipt = self.module.local.commit(writer, generation)
            self.assertEqual(hashlib.sha256(workbook).hexdigest(), receipt.published_sha256)
        arguments.update(generation_id=generation.generation_id, publish_id=hashlib.sha256(workbook).hexdigest())
        return self.module.composer.freeze_send_unit(**arguments), generation

    def test_multiple_pending_units_join_actual_receipts_without_issuing_generation_handles(self):
        api = self.c6_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            first, first_generation = self.c6_unit(writer)
            second, second_generation = self.c6_unit(writer)
            for original in (first, second):
                self.module.register_pending_unit(token, binding(), original)
            before = original_read_files(self.root)
            owner = self.module.local._owner(writer)
            handles = dict(owner.handles)
            with api(writer, token, binding()) as (observed, verify):
                self.assertEqual((first, second), observed)
                self.assertFalse(any(hasattr(value, 'permit') for value in observed))
                verify()
            self.assertEqual(handles, owner.handles)
            self.assertEqual(before, original_read_files(self.root))
            self.assertEqual((1, 2), (first_generation.sequence, second_generation.sequence))
            self.assertFalse(any('ATTEMPT-' in path or 'CLAIM-' in path for path in before))

    def test_c6_join_unissued_writer_and_caller_generation_claims_stop_before_catalog(self):
        api = self.c6_api()
        with mock.patch.object(self.module, 'hold_pending_units') as reading:
            with self.assertRaises(self.module.UnitCatalogHold):
                with api(object(), object(), binding()):
                    self.fail('unissued writer joined originals')
            reading.assert_not_called()
        for claims in ({'generations': ()}, {'project': self.root}, {'complete': True}, {'keys': ()}):
            with self.subTest(claims=tuple(claims)), self.assertRaises(TypeError):
                api(object(), object(), binding(), **claims)

    def test_cold_acquisition_reads_original_c6_without_reissuing_mutation_handles(self):
        api = self.c6_api()
        with ExitStack() as scope:
            writer, project, publication = self.local_owner(scope)
            token = self.owner(scope)
            original, _generation = self.c6_unit(writer)
            self.module.register_pending_unit(token, binding(), original)
        before = original_read_files(self.root)
        with ExitStack() as scope:
            writer = scope.enter_context(self.module.local.writer_owner(project, publication))
            token = self.owner(scope)
            owner = self.module.local._owner(writer)
            self.assertEqual({}, owner.handles)
            with api(writer, token, binding()) as (observed, verify):
                self.assertEqual((original,), observed)
                self.assertEqual({}, owner.handles)
                verify()
            self.assertEqual({}, owner.handles)
        self.assertEqual(before, original_read_files(self.root))

    def test_unresolved_c6_and_another_projects_receipt_never_yield_partial_inventory(self):
        api = self.c6_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            other, _other_project, _other_publication = self.local_owner(scope, 'other')
            token = self.owner(scope)
            first, _first_generation = self.c6_unit(writer)
            unresolved, _unresolved_generation = self.c6_unit(writer, committed=False)
            for original in (first, unresolved):
                self.module.register_pending_unit(token, binding(), original)
            before = original_read_files(self.root)
            for source in (writer, other):
                reached = []
                with self.subTest(other_project=source is other), self.assertRaises(self.module.UnitCatalogHold):
                    with api(source, token, binding()) as result:
                        reached.append(result)
                self.assertEqual([], reached)
                self.assertEqual(before, original_read_files(self.root))

    def test_pending_c6_original_receipt_and_published_replacement_revoke(self):
        api = self.c6_api()
        for fault in ('receipt', 'published'):
            with self.subTest(fault=fault), ExitStack() as scope:
                writer, project, publication = self.local_owner(scope, 'replace-' + fault)
                # Distinct spreadsheet keeps this test's two independent stores.
                bound = binding(TARGET + '_' + fault)
                owner_module = self.module.ownership
                scope.enter_context(scoped_fixture(self.root, owner_module))
                token = scope.enter_context(owner_module.spreadsheet_owner(bound))
                arguments = send_inputs(); arguments['spreadsheet_id'] = bound.spreadsheet_id
                generation = self.module.local.begin_generation(writer, arguments['manifest'])
                self.module.local.record_intent(writer, generation, literal_xlsx(), kind='xlsx')
                receipt = self.module.local.commit(writer, generation)
                arguments.update(generation_id=generation.generation_id, publish_id=receipt.published_sha256)
                original = self.module.composer.freeze_send_unit(**arguments)
                self.module.register_pending_unit(token, bound, original)
                path = (project / '.tracker/generations' / generation.generation_id / 'RECEIPT'
                        if fault == 'receipt' else publication / (generation.generation_id + '.xlsx'))
                image = path.read_bytes()
                entered = []; replaced = []
                with self.assertRaises(self.module.UnitCatalogHold):
                    with api(writer, token, bound) as (observed, verify):
                        entered.append(observed)
                        path.rename(project / 'preserved')
                        path.write_bytes(image); path.chmod(0o600)
                        replaced.append(True)
                        verify()
                self.assertEqual([(original,)], entered)
                self.assertEqual([True], replaced)
                self.assertEqual(image, (project / 'preserved').read_bytes())

    def test_two_pending_originals_recover_in_order_without_overwriting_legacy_or_counting(self):
        with ExitStack() as scope:
            token = self.owner(scope)
            legacy = self.parent / (STEM + '.journal-started')
            legacy.write_bytes(b'owned unresolved legacy witness\n'); legacy.chmod(0o600)
            original = (legacy.stat().st_ino, legacy.read_bytes())
            self.assertIsNone(self.module.register_pending_unit(token, binding(), self.first))
            first_files = original_read_files(self.root)
            self.assertIsNone(self.module.register_pending_unit(token, binding(), self.second))
            self.assertEqual(first_files, {key: value for key, value in original_read_files(self.root).items()
                                          if key in first_files})
            before = original_read_files(self.root)
            with self.module.hold_pending_units(token, binding()) as (units, verify):
                self.assertEqual((self.first, self.second), units)
                self.assertFalse(any(hasattr(value, 'permit') for value in units))
                verify()
            self.assertEqual(before, original_read_files(self.root))
            self.assertEqual(original, (legacy.stat().st_ino, legacy.read_bytes()))
            self.assertFalse(any('ATTEMPT-' in name or 'CLAIM-' in name for name in before))
        with ExitStack() as scope:
            token = self.owner(scope)
            with self.module.hold_pending_units(token, binding()) as (units, verify):
                self.assertEqual((self.first, self.second), units); verify()

    def test_same_unit_or_changed_image_is_not_idempotent_repair(self):
        with ExitStack() as scope:
            token = self.owner(scope)
            self.module.register_pending_unit(token, binding(), self.first)
            before = original_read_files(self.root)
            for value in (self.first, replace(self.first, wire_bytes=b'{}')):
                with self.subTest(changed=value is not self.first), self.assertRaises(self.module.UnitCatalogHold):
                    self.module.register_pending_unit(token, binding(), value)
                self.assertEqual(before, original_read_files(self.root))

    def test_unissued_owner_and_caller_root_or_state_never_open_files(self):
        with mock.patch.object(self.module.local, '_directory') as opening:
            with self.assertRaises(self.module.UnitCatalogHold):
                self.module.register_pending_unit(object(), binding(), self.first)
            opening.assert_not_called()
        for claims in ({'root': self.root}, {'count': 0}, {'applied': True}, {'keys': ()}):
            with self.subTest(claims=tuple(claims)), self.assertRaises(TypeError):
                self.module.register_pending_unit(object(), binding(), self.first, **claims)

    def test_catalog_never_issues_a_second_spreadsheet_lock_or_owner_token(self):
        with ExitStack() as scope:
            token = self.owner(scope)
            owner_module = self.module.ownership
            fd = owner_module.owner_lock_fd(token, binding())
            self.module.register_pending_unit(token, binding(), self.first)
            self.module.register_pending_unit(token, binding(), self.second)
            with self.module.hold_pending_units(token, binding()) as (units, _verify):
                self.assertEqual(fd, owner_module.owner_lock_fd(token, binding()))
                self.assertEqual([STEM + '.lock'], sorted(path.name for path in self.parent.glob('*.lock')))
                with self.assertRaises(owner_module.SpreadsheetOwnerHold):
                    with owner_module.spreadsheet_owner(binding()):
                        pass
                for value in units:
                    with self.assertRaises(owner_module.SpreadsheetOwnerHold):
                        owner_module.owner_lock_fd(value, binding())

    def counted_scope_other_original_fault(self, *, start):
        globals_ = self.globals_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            for original in (self.first, self.second):
                self.module.register_pending_unit(token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
            globals_.record_global_attempt_intent(token, binding(), self.first)
            prefix = STEM + '.unit-' + self.second.unit_id
            path = (self.parent / (prefix + '.journal-started') if start else
                    self.parent / (prefix + '.journal') / 'WIRE')
            image = path.read_bytes(); entered = []; changed = []
            with self.assertRaises(globals_.GlobalAttemptHold):
                with globals_._hold_counted_original_wire(writer, token, binding(), self.first) as original:
                    globals_._require_original_wire_launch(writer, token, binding(), self.first, original, consume=True)
                    entered.append(original.attempt_count)
                    path.rename(self.root / 'preserved-other-dispatch-original')
                    path.write_bytes(image); path.chmod(0o600); changed.append(True)
                    globals_._require_original_wire_launch(writer, token, binding(), self.first, original, consume=False)
            self.assertEqual([1], entered); self.assertEqual([True], changed)
            self.assertEqual(image, (self.root / 'preserved-other-dispatch-original').read_bytes())
            self.assertEqual(image, path.read_bytes())
            self.assertNotEqual(path.stat().st_ino, (self.root / 'preserved-other-dispatch-original').stat().st_ino)
            first_journal = self.parent / (STEM + '.unit-' + self.first.unit_id + '.journal')
            self.assertEqual(['ATTEMPT-1'], sorted(name for name in os.listdir(first_journal) if name.startswith('ATTEMPT-')))
            self.assertFalse(any(name.startswith('ATTEMPT-') for name in os.listdir(self.parent / (prefix + '.journal'))))

    def test_counted_wire_holds_other_original_unit_wire_through_actual_consume_and_exit(self):
        self.counted_scope_other_original_fault(start=False)

    def test_counted_wire_holds_other_original_unit_start_through_actual_consume_and_exit(self):
        self.counted_scope_other_original_fault(start=True)

    def counted_scope_other_project_origin_fault(self, entry):
        globals_ = self.globals_api(); registering, _reading = self.project_origins_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            originals = []
            for _index in range(2):
                original, _generation = self.c6_unit(writer)
                registering(writer, token, binding(), original)
                globals_.prepare_global_unit(token, binding(), original)
                originals.append(original)
            globals_.record_global_attempt_intent(token, binding(), originals[0])
            path = self.parent / (STEM + '.unit-' + originals[1].unit_id + '.project-origin') / entry
            raw = path.read_bytes(); previous = path.stat().st_ino
            reached = []; changed = []
            with self.assertRaises(globals_.GlobalAttemptHold):
                with globals_._hold_counted_original_wire(writer, token, binding(), originals[0]) as image:
                    globals_._require_original_wire_launch(writer, token, binding(), originals[0], image, consume=True)
                    reached.append(image.attempt_count)
                    preserved = self.root / 'preserved-counted-other-project-origin'
                    path.rename(preserved); path.write_bytes(raw); path.chmod(0o600)
                    self.assertNotEqual(previous, path.stat().st_ino); changed.append(True)
                    globals_._require_original_wire_launch(writer, token, binding(), originals[0], image, consume=False)
            self.assertEqual([1], reached); self.assertEqual([True], changed)
            self.assertEqual(raw, path.read_bytes()); self.assertEqual(raw, preserved.read_bytes())
            first_journal = self.parent / (STEM + '.unit-' + originals[0].unit_id + '.journal')
            second_journal = self.parent / (STEM + '.unit-' + originals[1].unit_id + '.journal')
            self.assertEqual(['ATTEMPT-1'], sorted(name for name in os.listdir(first_journal) if name.startswith('ATTEMPT-')))
            self.assertFalse(any(name.startswith('ATTEMPT-') for name in os.listdir(second_journal)))

    def test_counted_wire_holds_other_original_project_origin_through_actual_consume_and_exit(self):
        self.counted_scope_other_project_origin_fault('ORIGIN')

    def test_counted_wire_holds_other_original_project_origin_witness_through_actual_consume_and_exit(self):
        self.counted_scope_other_project_origin_fault('WITNESS')

    def test_last_wire_semantic_replay_cannot_replace_other_original_before_returning_consumed_image(self):
        globals_ = self.globals_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            for unit in (self.first, self.second):
                self.module.register_pending_unit(token, binding(), unit)
                globals_.prepare_global_unit(token, binding(), unit)
            globals_.record_global_attempt_intent(token, binding(), self.first)
            path = self.parent / (STEM + '.unit-' + self.second.unit_id + '.journal-started')
            raw = path.read_bytes(); changed = []; rejected_before_return = []
            actual = globals_._inspect_wire_claims
            def replace_after_replay(*args):
                result = actual(*args)
                if not changed:
                    path.rename(self.root / 'preserved-last-semantic-original')
                    path.write_bytes(raw); path.chmod(0o600); changed.append(True)
                return result
            with self.assertRaises(globals_.GlobalAttemptHold):
                with globals_._hold_counted_original_wire(writer, token, binding(), self.first) as original:
                    globals_._require_original_wire_launch(writer, token, binding(), self.first, original, consume=True)
                    with mock.patch.object(globals_, '_inspect_wire_claims', side_effect=replace_after_replay):
                        try:
                            globals_._require_original_wire_launch(writer, token, binding(), self.first, original, consume=False)
                        except globals_.GlobalAttemptHold:
                            rejected_before_return.append(True)
            self.assertEqual([True], changed)
            self.assertEqual([True], rejected_before_return, 'exit rejection cannot replace the last pre-launch rejection')
            self.assertEqual(raw, path.read_bytes())
            self.assertNotEqual(path.stat().st_ino, (self.root / 'preserved-last-semantic-original').stat().st_ino)

    def test_new_dispatch_header_is_held_before_first_claim_semantics_not_adopted_afterward(self):
        globals_ = self.globals_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            for unit in (self.first, self.second):
                self.module.register_pending_unit(token, binding(), unit)
                globals_.prepare_global_unit(token, binding(), unit)
            globals_.record_global_attempt_intent(token, binding(), self.first)
            path = self.parent / (STEM + '.unit-' + self.first.unit_id + '.dispatch') / 'HEADER'
            actual = globals_._inspect_wire_claims; changed = []; yielded = []
            def replace_before_replay(*args):
                if not changed:
                    raw = path.read_bytes(); path.rename(self.root / 'preserved-new-dispatch-header')
                    path.write_bytes(raw); path.chmod(0o600); changed.append(raw)
                return actual(*args)
            with mock.patch.object(globals_, '_inspect_wire_claims', side_effect=replace_before_replay):
                with self.assertRaises(globals_.GlobalAttemptHold):
                    with globals_._hold_counted_original_wire(writer, token, binding(), self.first):
                        yielded.append(True)
            self.assertEqual(1, len(changed)); self.assertEqual([], yielded)
            self.assertEqual(changed[0], path.read_bytes())
            self.assertNotEqual(path.stat().st_ino, (self.root / 'preserved-new-dispatch-header').stat().st_ino)
            self.assertFalse((path.parent / 'CLAIM-1').exists(), 'reject replaced initialization before consuming a claim')
            self.assertEqual(1, globals_.inspect_global_unit(token, binding(), self.first).attempt_count)

    def test_same_catalog_unit_retry_appends_claims_without_replacing_prior_consumed_originals(self):
        globals_ = self.globals_api()
        with ExitStack() as scope:
            writer, _project, _publication = self.local_owner(scope)
            token = self.owner(scope)
            for unit in (self.first, self.second):
                self.module.register_pending_unit(token, binding(), unit)
                globals_.prepare_global_unit(token, binding(), unit)
            held_claims = {}
            dispatch = self.parent / (STEM + '.unit-' + self.first.unit_id + '.dispatch')
            for count in range(1, 7):
                globals_.record_global_attempt_intent(token, binding(), self.first)
                with globals_._hold_counted_original_wire(writer, token, binding(), self.first) as original:
                    self.assertEqual(count, original.attempt_count)
                    globals_._require_original_wire_launch(writer, token, binding(), self.first, original, consume=True)
                    globals_._require_original_wire_launch(writer, token, binding(), self.first, original, consume=False)
                    self.assertEqual({'HEADER', 'INITIALIZED', *(f'CLAIM-{i}' for i in range(1, count + 1))},
                                     {path.name for path in dispatch.iterdir()})
                    for name, (identity, raw) in held_claims.items():
                        path = dispatch / name
                        self.assertEqual(identity, globals_.journal._identity(path.stat()))
                        self.assertEqual(raw, path.read_bytes())
                    claim = dispatch / f'CLAIM-{count}'
                    held_claims[claim.name] = (globals_.journal._identity(claim.stat()), claim.read_bytes())
                with self.assertRaises(globals_.GlobalAttemptHold):
                    with globals_._hold_counted_original_wire(writer, token, binding(), self.first):
                        self.fail('a consumed count cannot be resurrected')
            observed = globals_.inspect_catalog_global_units(token, binding())
            self.assertEqual(((6, 'UNKNOWN'), (0, 'UNATTEMPTED_OBSERVATION')),
                             tuple((state.attempt_count, state.outcome) for _unit, state in observed))
            with self.assertRaises(globals_.GlobalAttemptHold):
                globals_.record_global_attempt_intent(token, binding(), self.first)
            self.assertFalse((self.parent / (STEM + '.dispatch')).exists())

    def test_missing_whole_catalog_and_partial_started_are_hold_not_first_use(self):
        with ExitStack() as scope:
            token = self.owner(scope)
            with self.assertRaises(self.module.UnitCatalogHold):
                with self.module.hold_pending_units(token, binding()):
                    pass
            started = self.parent / (STEM + '.units-started')
            started.write_bytes(b'partial\n'); started.chmod(0o600)
            before = original_read_files(self.root)
            with self.assertRaises(self.module.UnitCatalogHold):
                self.module.register_pending_unit(token, binding(), self.first)
            self.assertEqual(before, original_read_files(self.root))

    def test_interrupted_entry_survives_and_blocks_recreation_and_reading(self):
        with ExitStack() as scope:
            token = self.owner(scope)
            actual = self.module.local._write_new
            def interrupt(parent, name, data):
                actual(parent, name, data)
                if name == 'WIRE':
                    raise OSError('owned unit image boundary')
            with mock.patch.object(self.module.local, '_write_new', side_effect=interrupt), self.assertRaises(self.module.UnitCatalogHold):
                self.module.register_pending_unit(token, binding(), self.first)
            before = original_read_files(self.root)
            for action in ('read', 'append'):
                with self.subTest(action=action), self.assertRaises(self.module.UnitCatalogHold):
                    if action == 'append':
                        self.module.register_pending_unit(token, binding(), self.first)
                    else:
                        with self.module.hold_pending_units(token, binding()):
                            pass
                self.assertEqual(before, original_read_files(self.root))

    def test_held_same_byte_replacement_and_namespace_loss_revoke(self):
        for fault in ('replace-wire', 'remove-entry'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix='req7-catalog-change-') as temporary:
                original_root, original_parent = self.root, self.parent
                self.root = Path(temporary).resolve()
                self.parent = self.root / 'var/lib/http-ztp-container/issue-tracker'
                self.parent.mkdir(parents=True, mode=0o700)
                try:
                    with ExitStack() as scope:
                        token = self.owner(scope)
                        self.module.register_pending_unit(token, binding(), self.first)
                        catalog = self.parent / (STEM + '.units')
                        entered = []
                        with self.assertRaises(self.module.UnitCatalogHold):
                            with self.module.hold_pending_units(token, binding()) as (units, verify):
                                entered.append(units)
                                path = catalog / self.first.unit_id / 'WIRE' if fault == 'replace-wire' else catalog / 'ENTRY-00000000000000000001'
                                image = path.read_bytes(); path.rename(self.root / 'preserved')
                                if fault == 'replace-wire':
                                    path.write_bytes(image); path.chmod(0o600)
                                verify()
                        self.assertEqual([(self.first,)], entered)
                        self.assertEqual(image, (self.root / 'preserved').read_bytes())
                        with self.assertRaises(self.module.UnitCatalogHold):
                            self.module.register_pending_unit(token, binding(), self.second)
                finally:
                    self.root, self.parent = original_root, original_parent

    def test_cold_tail_loss_cannot_rewind_catalog_or_reuse_a_position(self):
        with ExitStack() as scope:
            token = self.owner(scope)
            self.module.register_pending_unit(token, binding(), self.first)
            self.module.register_pending_unit(token, binding(), self.second)
        catalog = self.parent / (STEM + '.units')
        (catalog / self.second.unit_id).rename(self.root / 'preserved-unit')
        (catalog / 'ENTRY-00000000000000000002').rename(self.root / 'preserved-entry')
        preserved = original_read_files(self.root)
        with ExitStack() as scope:
            token = self.owner(scope)
            for action in ('read', 'append'):
                with self.subTest(action=action), self.assertRaises(self.module.UnitCatalogHold):
                    if action == 'read':
                        with self.module.hold_pending_units(token, binding()):
                            pass
                    else:
                        self.module.register_pending_unit(token, binding(), self.second)
                self.assertEqual(preserved, original_read_files(self.root))

    def test_cold_numeric_coercion_cannot_adopt_nonoriginal_index_or_marker(self):
        for fault in ('catalog-schema-bool', 'catalog-header-inode-float', 'entry-schema-bool'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix='req7-catalog-grammar-') as temporary:
                original_root, original_parent = self.root, self.parent
                self.root = Path(temporary).resolve()
                self.parent = self.root / 'var/lib/http-ztp-container/issue-tracker'
                self.parent.mkdir(parents=True, mode=0o700)
                try:
                    with ExitStack() as scope:
                        token = self.owner(scope)
                        self.module.register_pending_unit(token, binding(), self.first)
                    catalog = self.parent / (STEM + '.units')
                    path = catalog / ('ENTRY-00000000000000000001' if fault == 'entry-schema-bool' else 'INITIALIZED')
                    document = json.loads(path.read_bytes())
                    if fault == 'catalog-header-inode-float':
                        document['header_identity'][1] = float(document['header_identity'][1])
                    else:
                        document['schema_version'] = True
                    image = (json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n').encode()
                    path.write_bytes(image)
                    before = original_read_files(self.root)
                    with ExitStack() as scope:
                        token = self.owner(scope)
                        with self.assertRaises(self.module.UnitCatalogHold):
                            with self.module.hold_pending_units(token, binding()):
                                pass
                        self.assertEqual(before, original_read_files(self.root))
                finally:
                    self.root, self.parent = original_root, original_parent
