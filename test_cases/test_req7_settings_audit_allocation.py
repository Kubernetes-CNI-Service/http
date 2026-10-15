"""Actual locked C25 event -> immutable C19 unit, never remote delivery."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import importlib
from importlib import metadata as distribution_metadata
import json
import os
from pathlib import Path
from types import SimpleNamespace
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


def allocation_image_barrier(case, fd):
    """Fixture fault scope: original allocation images, not GLOBAL prereads.

    All fsyncs still execute natively. Only the fault/count selector uses these
    actual dev/inode pairs from this test's private namespace; a path, FD number
    or filename alone never identifies a barrier. Pending witness images are
    included because the first failed barrier must precede witness publication.
    This helper supplies no production ownership or durability certificate.
    """
    info = os.fstat(fd)
    tracker = case.project / '.tracker'
    candidates = [tracker, tracker / 'SETTINGS-AUDIT-ALLOCATED']
    candidates.extend(path for path in tracker.iterdir() if path.name.startswith('.pending-'))
    if case.allocation.is_dir():
        candidates.extend((case.allocation, *case.allocation.iterdir()))
    for path in candidates:
        try:
            named = os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if (named.st_dev, named.st_ino) == (info.st_dev, info.st_ino):
            return True
    return False


class Req7NativeProjectAuditAssignmentTests(unittest.TestCase):
    @contextmanager
    def _warm_metadata_sync_owned_fds(self):
        # Only the fixed warm synchronization primitive, not an issuer or
        # source/COUNT permission. Cold recovery barriers stay independent.
        module = load()
        with tempfile.TemporaryDirectory(prefix='req7-warm-sync-') as temporary:
            parent = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
            a = os.open(Path(temporary) / 'a', os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            b = os.open(Path(temporary) / 'b', os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            alias = os.dup(a)
            owned = (parent, a, b, alias)
            try:
                yield module, (a, b, parent, alias)
            finally:
                for fd in reversed(owned):
                    os.close(fd)

    def test_warm_metadata_sync_keeps_literal_last_occurrence_and_repeats_fresh_each_call(self):
        with self._warm_metadata_sync_owned_fds() as (module, (a, b, parent, _alias)):
            barriers = (((a, parent), (b, parent), (a, parent)),)
            holder = SimpleNamespace(barriers=barriers)
            sync = module._ReceivedCountSourceSettings._sync_barriers
            actual = []; original = os.fsync
            def observed(fd):
                os.fstat(fd)  # real owned descriptor, not a path-only stand-in
                actual.append(fd)
                return original(fd)
            with mock.patch.object(module.os, 'fsync', side_effect=observed):
                sync(holder)
                self.assertEqual([b, a, parent], actual)
                sync(holder)
            self.assertEqual([b, a, parent, b, a, parent], actual)
            self.assertIs(barriers, holder.barriers)

    def test_warm_metadata_sync_never_merges_different_fds_of_same_inode(self):
        with self._warm_metadata_sync_owned_fds() as (module, (a, _b, parent, alias)):
            self.assertNotEqual(a, alias)
            self.assertEqual((os.fstat(a).st_dev, os.fstat(a).st_ino),
                (os.fstat(alias).st_dev, os.fstat(alias).st_ino))
            holder = SimpleNamespace(barriers=(((a, parent), (alias, parent)),))
            actual = []; original = os.fsync
            def observed(fd):
                actual.append(fd)
                return original(fd)
            with mock.patch.object(module.os, 'fsync', side_effect=observed):
                module._ReceivedCountSourceSettings._sync_barriers(holder)
            self.assertEqual([a, alias, parent], actual)

    def test_warm_metadata_sync_propagates_same_original_error_without_retry(self):
        with self._warm_metadata_sync_owned_fds() as (module, (a, b, parent, _alias)):
            holder = SimpleNamespace(barriers=(((a, parent), (b, parent)),))
            primary = OSError('literal owned synchronization failure')
            actual = []; original = os.fsync
            def fails(fd):
                actual.append(fd)
                if fd == b:
                    raise primary
                return original(fd)
            with mock.patch.object(module.os, 'fsync', side_effect=fails):
                with self.assertRaises(OSError) as caught:
                    module._ReceivedCountSourceSettings._sync_barriers(holder)
            self.assertIs(primary, caught.exception)
            self.assertEqual(1, actual.count(b))
            self.assertEqual(b, actual[-1])

    def test_fixed_non_yield_k_checkpoint_replays_its_original_c6_once(self):
        import ast,inspect,textwrap
        module=load()
        tree=ast.parse(textwrap.dedent(inspect.getsource(module._hold_received_count_source_k.__wrapped__)))
        verify=next(node for node in ast.walk(tree) if isinstance(node,ast.FunctionDef) and node.name=='verify')
        interior=next(node for node in verify.body if isinstance(node,ast.Try)).body
        selected=next(node for node in interior if isinstance(node,ast.If)
            and isinstance(node.test,ast.Name) and node.test.id=='evaluating')
        calls=[node for statement in selected.body for node in ast.walk(statement)
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='c6_verify']
        self.assertEqual(1,len(calls),
            'each fixed non-yield K checkpoint needs one complete original C6 replay, not two adjacent replays')
        # Ordinary K and evaluator ENTRY/EXIT retain the original full body.
        self.assertEqual(['body(actual)'],[ast.unparse(node) for statement in selected.orelse
            for node in ast.walk(statement) if isinstance(node,ast.Call)])

    def test_received_receipt_evaluation_accepts_only_fixed_receipt_data_not_callbacks(self):
        import inspect
        module=load();entry=getattr(module,'_evaluate_received_count_receipt',None)
        self.assertTrue(callable(entry),'fixed entire current receipt evaluation is missing')
        self.assertEqual(('writer','sheet','bound','unit','store','qualified_source','generation_id',
            'settings','whitelist_snapshot','expected_template_sha256'),tuple(inspect.signature(entry).parameters))
        with self.assertRaises(module.SettingsAuditHold):
            entry(object(),object(),binding(),object(),object(),qualified_source=object(),
                generation_id='unissued',settings=object(),whitelist_snapshot=object(),
                expected_template_sha256='0'*64)

    def test_fixed_receipt_evaluation_keeps_full_original_body_on_both_boundaries(self):
        import ast,inspect,textwrap
        module=load()
        tree=ast.parse(textwrap.dedent(inspect.getsource(module._hold_received_count_source_k.__wrapped__)))
        functions={node.name:node for node in ast.walk(tree) if isinstance(node,ast.FunctionDef)}
        self.assertIn('evaluate_receipt',functions,'receipt cannot use a caller-selected generic read scope')
        evaluator=functions['evaluate_receipt']
        calls=[node for node in ast.walk(evaluator) if isinstance(node,ast.Call)
            and isinstance(node.func,ast.Name) and node.func.id=='body']
        self.assertEqual(2,len(calls),'actual receipt is enclosed by complete original ENTRY/EXIT')
        self.assertEqual(1,len([node for node in ast.walk(evaluator) if isinstance(node,ast.Call)
            and isinstance(node.func,ast.Attribute) and node.func.attr=='_original_receipt_identity']),
            'fixed receipt delegate runs once, with its original two K and complete C6 recovery checks')

    def test_fixed_source_evaluation_c19_sync_keeps_complete_boundaries_and_ordinary_k(self):
        import ast,inspect,textwrap
        module=load()
        tree=ast.parse(textwrap.dedent(inspect.getsource(module._hold_received_count_source_k.__wrapped__)))
        functions={node.name:node for node in ast.walk(tree) if isinstance(node,ast.FunctionDef)}
        interior=next(node for node in ast.walk(functions['verify'])
            if isinstance(node,ast.If) and isinstance(node.test,ast.Name) and node.test.id=='evaluating')
        self.assertEqual([], [node for statement in interior.body for node in ast.walk(statement)
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='_sync_barriers'],
            'fixed non-yielding source computation syncs C19 at whole boundaries, not internal K returns')
        evaluator=functions['evaluate_source']
        calls=[node for node in ast.walk(evaluator) if isinstance(node,ast.Call)
            and isinstance(node.func,ast.Name) and node.func.id=='body']
        self.assertEqual(2,len(calls),'whole entry and complete exit each keep original full C19 body')
        body=ast.parse(textwrap.dedent(inspect.getsource(module._ReceivedCountSourceSettings._verify_original_c6_body)))
        self.assertEqual(1,len([node for node in ast.walk(body) if isinstance(node,ast.Call)
            and isinstance(node.func,ast.Attribute) and node.func.attr=='_sync_barriers']),
            'ordinary K/full source/receipt original body keeps its exact original synchronization')

    def test_received_source_evaluation_accepts_only_fixed_source_data_not_callbacks(self):
        import inspect
        module=load();entry=getattr(module,'_evaluate_received_count_source',None)
        self.assertTrue(callable(entry),'fixed complete source evaluation receiver is missing')
        self.assertEqual(('writer','sheet','bound','unit','store','http_root','settings',
            'whitelist_snapshot','whitelist_path','local_generation_id','expected_template_sha256'),
            tuple(inspect.signature(entry).parameters))
        with self.assertRaises(module.SettingsAuditHold):
            entry(object(),object(),binding(),object(),object(),http_root=ROOT,settings=object(),
                whitelist_snapshot=object(),whitelist_path=ROOT/'unissued.xlsx')

    def test_first_count_settings_transfer_has_only_fixed_owner_and_unit_arguments(self):
        import inspect
        module=load();entry=getattr(module,'_receive_first_original_count_source',None)
        self.assertTrue(callable(entry),'same LIVE source settings transfer is missing')
        self.assertEqual(('writer','sheet','bound','unit'),tuple(inspect.signature(entry).parameters))
        with self.assertRaises(module.SettingsAuditHold):entry(object(),object(),binding(),object())

    def test_received_count_k_cannot_adopt_raw_provider_or_caller_images(self):
        import inspect
        module=load();entry=getattr(module,'_hold_received_count_source_k',None)
        self.assertTrue(callable(entry),'Count-owned original short K reception is missing')
        self.assertEqual(('writer','sheet','bound','unit'),tuple(inspect.signature(entry).parameters))
        with self.assertRaises(module.SettingsAuditHold):
            with entry(object(),object(),binding(),object()):self.fail('unissued source enrolled K')

    def test_first_source_settings_metadata_has_no_caller_images_or_verifier_admission(self):
        import inspect
        module=load();entry=getattr(module,'_owned_source_k_settings_originals',None)
        self.assertTrue(callable(entry),'actual source settings FD lifetime anchor missing')
        self.assertEqual(('writer','sheet','bound'),tuple(inspect.signature(entry).parameters))
        with self.assertRaises(module.SettingsAuditHold):entry(object(),object(),binding())

    def test_source_factory_publishes_actual_settings_refs_before_yield_and_revokes_metadata(self):
        import ast,inspect,textwrap
        module=load();tree=ast.parse(textwrap.dedent(inspect.getsource(
            module._hold_owned_completed_source_read_originals.__wrapped__)))
        calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call)
            and isinstance(node.func,ast.Name) and node.func.id=='_publish_owned_source_k_settings']
        self.assertEqual(1,len(calls),'only the actual original factory may publish the source settings refs')
        self.assertEqual(['bridge','packet','native','actual','issued','k_packet','images','settings_scope','settings_verify','verify'],
            [ast.unparse(argument) for argument in calls[0].args])
        yielded=[node for node in ast.walk(tree) if isinstance(node,ast.Yield)]
        self.assertLess(calls[0].lineno,min(node.lineno for node in yielded))
        revoked=[node for node in ast.walk(tree) if isinstance(node,ast.Call)
            and isinstance(node.func,ast.Attribute) and node.func.attr=='pop'
            and isinstance(node.func.value,ast.Name) and node.func.value.id=='_LIVE_SOURCE_K_SETTINGS']
        self.assertEqual(1,len(revoked),'source closure must revoke its own metadata, never revive it from a receiver')

    def test_actual_source_leaf_retains_original_barriers_before_semantic_yield(self):
        import ast,inspect,textwrap
        module=load();tree=ast.parse(textwrap.dedent(inspect.getsource(
            module._hold_native_completed_delivery_originals.__wrapped__)))
        calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call)
            and isinstance(node.func,ast.Attribute) and node.func.attr=='retain_completed_leaf']
        self.assertEqual(1,len(calls),'actual source leaf must retain original C19 barrier groups before IO')
        self.assertEqual('_source_handoff',ast.unparse(calls[0].func.value))
        self.assertEqual(['held','ancestors','project_originals','unit','parent','completed','tuple(witness)'],
            [ast.unparse(argument) for argument in calls[0].args])
        yielded=[node for node in ast.walk(tree) if isinstance(node,ast.Yield)]
        self.assertLess(calls[0].lineno,min(node.lineno for node in yielded))

    def test_count_source_raw_data_cannot_enroll_k_or_adopt_unissued_provider(self):
        module=load();entry=getattr(module,'_CountSourceRawOriginals',None)
        self.assertTrue(callable(entry),'Count-backed raw data receiver is missing')
        before=dict(module._LIVE_NATIVE_CATALOG_K_CONTEXTS)
        writer,sheet,unit=object(),object(),object()
        provider=SimpleNamespace(writer=writer,sheet=sheet,bound=object(),verify=lambda:True)
        with self.assertRaises(module.SettingsAuditHold):entry(writer,sheet,provider.bound,unit,provider)
        self.assertEqual(before,module._LIVE_NATIVE_CATALOG_K_CONTEXTS)
        self.assertIsNone(module._NATIVE_CATALOG_K_CONTEXT.get())

    def _completion_sync_control(self, fault=None):
        # Real original-FD/barrier mechanics only, not COUNT/source permission.
        module=load();entry=getattr(module,'_sync_completed_source_leaf_originals',None)
        self.assertTrue(callable(entry),'read-only C19 replay must preserve original recovery barriers')
        from monitor import issue_tracker_unit_catalog as catalog
        with tempfile.TemporaryDirectory(prefix='req7-completion-sync-') as temporary:
            root=Path(temporary).resolve();root.chmod(0o700)
            folder=root/'completion';folder.mkdir(mode=0o700)
            for name,raw in (('HEADER',b'literal original header\n'),('COMPLETE',b'literal original complete\n')):
                (folder/name).write_bytes(raw);(folder/name).chmod(0o600)
            parent=os.open(root,local._flags(directory=True));held=catalog._Originals()
            expected=[(path.stat().st_dev,path.stat().st_ino) for path in
                      (folder/'HEADER',folder/'COMPLETE',folder,root)]
            seen=[];native_sync=os.fsync;triggered=[]
            try:
                original=held.directory(parent,'completion')
                for name in ('HEADER','COMPLETE'):held.file(original,name,16384)
                held.namespace=(parent,'',frozenset(('completion',)))
                def synchronize(fd):
                    metadata=os.fstat(fd);key=(metadata.st_dev,metadata.st_ino);seen.append(key)
                    if fault and key==expected[0] and not triggered:
                        triggered.append(key)
                        if fault=='barrier':raise OSError('literal original recovery barrier failure')
                        replacement=folder/'replacement'
                        replacement.write_bytes(b'literal original header\n');replacement.chmod(0o600)
                        os.replace(replacement,folder/'HEADER')
                    return native_sync(fd)
                with mock.patch.object(module.os,'fsync',side_effect=synchronize):
                    if fault:
                        with self.assertRaises((module.SettingsAuditHold,catalog.UnitCatalogHold,OSError)):
                            entry(held,parent)
                        self.assertEqual([expected[0]],triggered)
                    else:
                        self.assertIsNone(entry(held,parent))
                        self.assertEqual(expected,seen,'all proof files/folders and shared parent retain real barriers')
            finally:
                held.close();os.close(parent)

    def test_completed_source_leaf_keeps_real_file_folder_and_parent_barriers(self):
        self._completion_sync_control()

    def test_completed_source_leaf_recovery_failure_or_same_bytes_replacement_refuses(self):
        for fault in ('barrier','replace'):
            with self.subTest(fault=fault):self._completion_sync_control(fault)

    def _completion_exact_sync_control(self, fault=None, *, capture=False):
        # Actual FD mechanics, not semantic COMPLETE or source permission.
        module=load()
        from monitor import issue_tracker_unit_catalog as catalog
        with tempfile.TemporaryDirectory(prefix='req7-exact-c19-barriers-') as temporary:
            root=Path(temporary).resolve();root.chmod(0o700)
            image_names={
                'unit.journal':('ACTION-PREIMAGE','WIRE','HEADER','INITIALIZED','ATTEMPT-1','ATTEMPT-2'),
                'unit.history':('HISTORY-RAW','HEADER','INITIALIZED'),
                'sheet.enrollment':('NONCES','HEADER','INITIALIZED'),
                'unit.completion':('IDENTITY-RAW','HEADERS-RAW','METADATA-RAW','HISTORY-RAW','HEADER','COMPLETE'),
                'unrelated-c6':('STATE',),
            }
            for folder, names in image_names.items():
                (root/folder).mkdir(mode=0o700)
                for name in names:
                    path=root/folder/name;path.write_bytes(b'literal original '+name.encode()+b'\n');path.chmod(0o600)
            for name in ('unit.journal-started','unit.completion-started'):
                (root/name).write_bytes(b'literal started\n');(root/name).chmod(0o600)
            parent=os.open(root,local._flags(directory=True));held=catalog._Originals()
            expected_paths=[root/'unit.completion-started',root,
                root/'unit.journal-started',*(root/'unit.journal'/name for name in sorted(image_names['unit.journal'])),
                root/'unit.journal',root,
                root/'unit.history'/'INITIALIZED',root/'unit.history',root,
                root/'sheet.enrollment'/'INITIALIZED',root/'sheet.enrollment',root,
                *(root/'unit.completion'/name for name in sorted(image_names['unit.completion'])),
                root/'unit.completion',root]
            expected=[(path.stat().st_dev,path.stat().st_ino) for path in expected_paths]
            seen=[];native_sync=os.fsync;triggered=[]
            try:
                directories={name:held.directory(parent,name) for name in image_names}
                for folder,names in image_names.items():
                    for name in names:held.file(directories[folder],name,16384)
                for name in ('unit.journal-started','unit.completion-started'):held.file(parent,name,16384)
                held.namespace=(parent,'',frozenset(os.listdir(parent)))
                if capture:
                    entry=getattr(module,'_completed_source_leaf_original_barriers',None)
                    self.assertTrue(callable(entry),'pre-IO C19 original barrier capture missing')
                    groups=entry(held,parent,completion_folder=directories['unit.completion'],
                        match_folders=('unit.journal','unit.history','sheet.enrollment'))
                    self.assertEqual(expected,[(os.fstat(fd).st_dev,os.fstat(fd).st_ino)
                        for group in groups for fd in group])
                def synchronize(fd):
                    info=os.fstat(fd);key=(info.st_dev,info.st_ino);seen.append(key)
                    if fault and not triggered:
                        triggered.append(key)
                        if fault=='barrier':raise OSError('literal original barrier refusal')
                        path=root/'unrelated-c6'/'STATE';replacement=path.with_name('replacement')
                        replacement.write_bytes(path.read_bytes());replacement.chmod(0o600);os.replace(replacement,path)
                    return native_sync(fd)
                with mock.patch.object(module.os,'fsync',side_effect=synchronize):
                    if fault:
                        with self.assertRaises((module.SettingsAuditHold,catalog.UnitCatalogHold,OSError)):
                            module._sync_completed_source_leaf_originals(held,parent,
                                completion_folder=directories['unit.completion'],
                                match_folders=('unit.journal','unit.history','sheet.enrollment'))
                        self.assertEqual([expected[0]],triggered)
                    else:
                        try:
                            result=module._sync_completed_source_leaf_originals(held,parent,
                                completion_folder=directories['unit.completion'],
                                match_folders=('unit.journal','unit.history','sheet.enrollment'))
                        except TypeError:
                            self.fail('exact original cold C19 barrier footprint is absent')
                        self.assertIsNone(result)
                        self.assertEqual(expected,seen,'STARTED/GLOBAL/INITIALIZED/C19 barriers keep their exact original order')
            finally:held.close();os.close(parent)

    def test_completed_source_exact_barriers_do_not_sync_unrelated_c6_but_keep_all_original_checks(self):
        self._completion_exact_sync_control()

    def test_completed_source_original_barrier_capture_matches_fixed_recovery_order(self):
        self._completion_exact_sync_control(capture=True)

    def test_completed_source_exact_barrier_failure_or_unsynced_original_replacement_refuses(self):
        for fault in ('barrier','replace'):
            with self.subTest(fault=fault):self._completion_exact_sync_control(fault)

    def test_readonly_source_join_checks_original_bridge_without_count_and_after_delegate(self):
        # Original relationship/lifetime control only; no real C19/K permit.
        module=load();entry=getattr(module,'_hold_source_original_verifier',None)
        self.assertTrue(callable(entry),'strict source C6 requires its genuine bridge on every callback')
        writer,sheet,bridge=object(),object(),module._OwnedPriorSourceRead();bound=binding()
        raw=object.__new__(module._OwnedPriorSourceOriginals);raw.writer,raw.sheet,raw.bound=writer,sheet,bound
        packet={'writer':writer,'raw':raw,'retired':False,'received':False,'attached':False}
        calls=[];value=object()
        def original():calls.append('real verifier');return value
        with mock.patch.dict(module._LIVE_OWNED_PRIOR_SOURCE_READS,{bridge:packet},clear=True), \
                mock.patch.object(module,'_owned_prior_source_packet',return_value=packet):
            with entry(writer,sheet,bound,raw,original) as check:
                self.assertIs(value,check());self.assertEqual(['real verifier'],calls)
                packet['retired']=True
                with self.assertRaises(module.SettingsAuditHold):check()
                packet['retired']=False
            with self.assertRaises(module.SettingsAuditHold):check()
            def inserted():
                module._LIVE_OWNED_PRIOR_SOURCE_READS[module._OwnedPriorSourceRead()]=dict(packet)
            with self.assertRaises(module.SettingsAuditHold):
                with entry(writer,sheet,bound,raw,inserted) as check:check()

    def test_count_c6_source_join_without_handoff_keeps_cold_constructor(self):
        module=load();entry=getattr(module,'_hold_source_count_c6',None)
        self.assertTrue(callable(entry),'only a genuine source issuer may borrow COUNT-held C6')
        with mock.patch.object(module.global_journal,'_hold_count_claim_project_c6') as loan:
            with entry(object(),object(),binding(),(),_source_handoff=None) as result:
                self.assertIsNone(result)
        loan.assert_not_called()

    def test_count_c6_source_join_refuses_unissued_same_class_handoff_before_loan(self):
        module=load();entry=getattr(module,'_hold_source_count_c6',None)
        self.assertTrue(callable(entry))
        writer,sheet=object(),object();bound=binding()
        raw=object.__new__(module._OwnedPriorSourceOriginals)
        raw.writer,raw.sheet,raw.bound=writer,sheet,bound
        with mock.patch.dict(module._LIVE_OWNED_PRIOR_SOURCE_READS,{},clear=True), \
                mock.patch.object(module.global_journal,'_hold_count_claim_project_c6') as loan:
            with self.assertRaises(module.SettingsAuditHold):
                with entry(writer,sheet,bound,(),_source_handoff=raw):
                    self.fail('typed caller raw became a source issuer')
        loan.assert_not_called()

    def test_count_c6_source_join_retains_actual_record_identity_through_loan_cleanup(self):
        # Registry/lifetime control, not an actual origin/C6 or owner proof.
        module=load();entry=getattr(module,'_hold_source_count_c6',None)
        self.assertTrue(callable(entry))
        writer,sheet,bridge=object(),object(),module._OwnedPriorSourceRead();bound=binding()
        raw=object.__new__(module._OwnedPriorSourceOriginals)
        raw.writer,raw.sheet,raw.bound=writer,sheet,bound
        packet={'writer':writer,'raw':raw,'retired':False,'received':False,'attached':False}
        events=[];rows=(object(),)
        @contextmanager
        def original_loan(*args):
            self.assertEqual((writer,sheet,bound,()),args)
            events.append('loan enter')
            try:yield rows,lambda:events.append('original C6 verify')
            finally:events.append('loan exit')
        with mock.patch.dict(module._LIVE_OWNED_PRIOR_SOURCE_READS,{bridge:packet},clear=True), \
                mock.patch.object(module,'_owned_prior_source_packet',return_value=packet), \
                mock.patch.object(module.global_journal,'_hold_count_claim_project_c6',original_loan):
            with entry(writer,sheet,bound,(),_source_handoff=raw) as result:
                self.assertIs(rows,result[0]);result[1]()
            self.assertEqual(['loan enter','original C6 verify','loan exit'],events)
            with self.assertRaises(module.SettingsAuditHold):
                result[1]()
            with self.assertRaises(module.SettingsAuditHold):
                with entry(writer,sheet,bound,(),_source_handoff=raw):
                    module._LIVE_OWNED_PRIOR_SOURCE_READS[bridge]=dict(packet)

    def test_count_c6_source_join_second_bridge_inserted_by_original_check_refuses(self):
        # The original bridge/packet remain unchanged. A second same-source
        # relation introduced by the delegated verifier must still be refused.
        module=load();writer,sheet=object(),object();bound=binding()
        bridge,second=module._OwnedPriorSourceRead(),module._OwnedPriorSourceRead()
        raw=object.__new__(module._OwnedPriorSourceOriginals)
        raw.writer,raw.sheet,raw.bound=writer,sheet,bound
        packet={'writer':writer,'raw':raw,'retired':False,'received':False,'attached':False}
        def inserted():module._LIVE_OWNED_PRIOR_SOURCE_READS[second]=dict(packet)
        @contextmanager
        def original_loan(*args):yield (),inserted
        with mock.patch.dict(module._LIVE_OWNED_PRIOR_SOURCE_READS,{bridge:packet},clear=True), \
                mock.patch.object(module,'_owned_prior_source_packet',return_value=packet), \
                mock.patch.object(module.global_journal,'_hold_count_claim_project_c6',original_loan):
            with self.assertRaises(module.SettingsAuditHold):
                with module._hold_source_count_c6(writer,sheet,bound,(),_source_handoff=raw) as result:
                    result[1]()

    def test_fixed_completed_source_k_scope_has_no_caller_allowance_or_preparation(self):
        import inspect
        module = load()
        entry = getattr(module, '_hold_owned_native_completed_source_k', None)
        self.assertTrue(callable(entry), 'FIRST source needs actual dual-owner completed K reception')
        self.assertEqual(('writer', 'sheet', 'bound'), tuple(inspect.signature(entry).parameters))
        with mock.patch.object(module.global_journal, 'prepare_global_unit') as writes:
            with self.assertRaises(module.SettingsAuditHold):
                with entry(object(), object(), object()):
                    self.fail('unissued owners became a source K allowance')
        writes.assert_not_called()

    def test_completed_source_k_readonly_exit_never_claims_creator_handoff(self):
        """Control order only; genuine archived NEW/FIRST workflow is separate."""
        module = load()
        entry = getattr(module, '_hold_owned_native_completed_source_k', None)
        self.assertTrue(callable(entry), 'fixed readonly K source receiver absent')
        from monitor import issue_tracker_state_owner as state
        writer, sheet, bound, bridge = object(), object(), object(), object()
        for changed in (None, 'retired', 'received', 'attached'):
            with self.subTest(changed=changed):
                calls = []
                packet = {'retired': False, 'received': False, 'attached': False}
                @contextmanager
                def original(*args):
                    self.assertEqual((writer, sheet, bound), args); calls.append('original-enter')
                    try: yield bridge
                    finally: calls.append('original-exit')
                def current(*args):
                    self.assertEqual((writer,), args); calls.append('current-K')
                def actual_packet(*args):
                    self.assertEqual((bridge, sheet, bound), args); return packet
                with mock.patch.object(module, '_hold_owned_completed_source_read_originals', original), \
                        mock.patch.object(module, '_owned_prior_source_packet', side_effect=actual_packet), \
                        mock.patch.object(state, 'current_k', side_effect=current):
                    if changed is None:
                        with entry(writer, sheet, bound) as result:
                            self.assertIsNone(result); calls.append('consumer')
                        self.assertEqual(['original-enter', 'consumer', 'current-K', 'original-exit'], calls)
                    else:
                        with self.assertRaises(module.SettingsAuditHold):
                            with entry(writer, sheet, bound): packet[changed] = True
                        self.assertEqual(['original-enter', 'original-exit'], calls)

    def test_native_completed_delivery_original_holder_is_separate_from_mutable_projection_reader(self):
        module=load()
        self.assertTrue(callable(getattr(module,'_hold_native_completed_delivery_originals',None)),
            'ALL discovery must prove actual immutable pairs before any missing-projection allowance')

    def native_delivery_locator_literal(self, **changes):
        header={'state':'NATIVE_SETTINGS_ALLOCATION','unit_id':'a'*64,
            'spreadsheet_id':'literal-approved-sheet','allowlist_sha256':'b'*64,'policy_sha256':'c'*64,
            'project_identity':[7,11],'tracker_identity':[7,12]}
        body={'schema_version':1,'unit_id':'a'*64,'native_allocation_header':header,
            'allocation_header_sha256':hashlib.sha256(canonical(header)).hexdigest()}
        body.update(changes)
        return canonical({'schema_version':1,'complete_allocation':body,
            'delivery_start_identity':[7,13,33152,501,1,0,123,1,1]})

    def test_native_delivery_locator_decodes_exact_embedded_original_not_reconstructed_header(self):
        module=load();raw=self.native_delivery_locator_literal()
        header=module._native_delivery_locator(raw)
        self.assertEqual({'state':'NATIVE_SETTINGS_ALLOCATION','unit_id':'a'*64,
            'spreadsheet_id':'literal-approved-sheet','allowlist_sha256':'b'*64,'policy_sha256':'c'*64,
            'project_identity':[7,11],'tracker_identity':[7,12]},header)

    def test_native_delivery_locator_refuses_hash_unit_type_and_canonical_mismatch(self):
        module=load()
        images=[self.native_delivery_locator_literal(allocation_header_sha256='d'*64),
            self.native_delivery_locator_literal(unit_id='d'*64),
            self.native_delivery_locator_literal(native_allocation_header=None),
            b' '+self.native_delivery_locator_literal()]
        for raw in images:
            with self.subTest(raw=raw),self.assertRaises(module.SettingsAuditHold):
                module._native_delivery_locator(raw)

    def test_legacy_delivery_locator_does_not_invent_native_coordinate_or_change_raw(self):
        module=load();raw=canonical({'schema_version':1,'complete_allocation':{'schema_version':1,
            'unit_id':'a'*64,'allocation_header_sha256':'b'*64},'delivery_start_identity':[7,13]})
        self.assertIsNone(module._native_delivery_locator(raw))

    def test_native_later_delivery_names_bind_exact_original_unit_not_caller_path(self):
        module=load();body=json.loads(self.native_delivery_locator_literal())['complete_allocation']
        body['native_delivery_unit_id']='a'*64
        expected=('settings-audit-delivery-'+'a'*64,'SETTINGS-AUDIT-DELIVERY-STARTED-'+'a'*64)
        self.assertEqual(expected,module._delivery_names(canonical(body)))
        self.assertEqual(expected,module._delivery_names(canonical({'schema_version':1,
            'complete_allocation':body,'delivery_start_identity':[7,13]})))

    def test_native_later_delivery_names_refuse_wrong_unit_path_injection_and_legacy_claim(self):
        module=load();body=json.loads(self.native_delivery_locator_literal())['complete_allocation']
        for claim in ('d'*64,'../foreign',None,True):
            value={**body,'native_delivery_unit_id':claim}
            with self.subTest(claim=claim),self.assertRaises(module.SettingsAuditHold):
                module._delivery_names(canonical(value))
        body.pop('native_allocation_header');body['native_delivery_unit_id']='a'*64
        with self.assertRaises(module.SettingsAuditHold):module._delivery_names(canonical(body))

    def test_initial_native_and_legacy_delivery_names_keep_original_fixed_pair(self):
        module=load();native=json.loads(self.native_delivery_locator_literal())['complete_allocation']
        expected=('settings-audit-delivery','SETTINGS-AUDIT-DELIVERY-STARTED')
        self.assertEqual(expected,module._delivery_names(canonical(native)))
        self.assertEqual(expected,module._delivery_names(canonical({'schema_version':1,'unit_id':'a'*64})))

    def test_delivery_names_refuse_unbound_embedded_header_and_unsupported_wrapper(self):
        module=load();body=json.loads(self.native_delivery_locator_literal())['complete_allocation']
        body['native_delivery_unit_id']='a'*64
        wrapper={'schema_version':1,'complete_allocation':body,'delivery_start_identity':[7,13]}
        images=[{**body,'allocation_header_sha256':'d'*64},
            {**body,'schema_version':True},{**body,'caller_path':'foreign'},
            {**wrapper,'schema_version':2},{**wrapper,'schema_version':True},
            {**wrapper,'extra_wrapper':body},
            {'schema_version':1,'complete_allocation':wrapper,'delivery_start_identity':[7,13]}]
        initial={**body};initial.pop('native_delivery_unit_id')
        images.append({**initial,'allocation_header_sha256':'d'*64})
        for value in images:
            with self.subTest(value=value),self.assertRaises(module.SettingsAuditHold):
                module._delivery_names(canonical(value))

    def test_delivery_catalog_replay_issues_one_actual_scope_and_revalidates_live_originals(self):
        from contextlib import contextmanager
        allocation=load();calls=[];writer=object();bound=object();unit=object()
        @contextmanager
        def issue(*args):
            self.assertEqual((writer,bound,unit),args);calls.append('issue')
            yield lambda:calls.append('verify')
            calls.append('close')
        with mock.patch.object(allocation.global_journal,'_HELD_CATALOG_REPLAY',mock.Mock(get=mock.Mock(return_value=None))), \
                mock.patch.object(allocation.global_journal,'_hold_native_catalog_replay',side_effect=issue):
            with allocation._hold_delivery_catalog_replay(writer,bound,unit) as verify:
                self.assertEqual(['issue','verify'],calls);verify()
            self.assertEqual(['issue','verify','verify','verify','close'],calls)

    def test_delivery_catalog_replay_borrows_existing_exact_scope_never_issues_nested_cache(self):
        from contextlib import contextmanager
        allocation=load();calls=[];writer=object();bound=object();unit=object()
        @contextmanager
        def borrow(*args):
            self.assertEqual((writer,bound),args);calls.append('borrow')
            yield (unit,),lambda:calls.append('verify')
        with mock.patch.object(allocation.global_journal,'_HELD_CATALOG_REPLAY',mock.Mock(get=mock.Mock(return_value=object()))), \
                mock.patch.object(allocation.global_journal,'_hold_catalog_originals',side_effect=borrow), \
                mock.patch.object(allocation.global_journal,'_hold_native_catalog_replay') as issue:
            with allocation._hold_delivery_catalog_replay(writer,bound,unit) as verify:verify()
            issue.assert_not_called();self.assertEqual(['borrow','verify','verify','verify'],calls)

    def test_delivery_allocation_selector_uses_held_native_bytes_and_live_guard(self):
        module=load()
        self.assertTrue(callable(getattr(module,'_hold_delivery_allocation_originals',None)),
            'delivery needs the retained native allocation, not a legacy reconstruction')
        selected=object(); header=b'literal-native-header\n'; assignments=b'literal-native-assignment\n'
        checks=[]
        @contextmanager
        def native(*args,**options):
            yield selected,header,assignments,lambda:checks.append('held-original')
        with mock.patch.object(module,'_hold_native_catalog_audit_originals',side_effect=native), \
                mock.patch.object(module,'_originals') as legacy:
            with module._hold_delivery_allocation_originals(object(),object(),object(),object()) as held:
                self.assertEqual((selected,header,assignments),held[:3]); held[3]()
            self.assertTrue(checks); legacy.assert_not_called()

    def test_delivery_broken_native_anchor_never_falls_back_to_legacy_images(self):
        module=load()
        self.assertTrue(callable(getattr(module,'_hold_delivery_allocation_originals',None)),
            'native delivery failures must remain fail closed')
        @contextmanager
        def broken(*args,**options):
            raise module.SettingsAuditHold()
            yield
        with mock.patch.object(module,'_hold_native_catalog_audit_originals',side_effect=broken), \
                mock.patch.object(module,'_originals') as legacy:
            with self.assertRaises(module.SettingsAuditHold):
                with module._hold_delivery_allocation_originals(object(),object(),object(),object()):
                    self.fail('broken native anchor cannot grant delivery authority')
            legacy.assert_not_called()

    def record(self):
        first=SimpleNamespace(unit_id='a'*64,action_preimage=canonical({'audits':[{'event_id':'literal-event-0'}]}))
        second=SimpleNamespace(unit_id='b'*64,action_preimage=canonical({'audits':[{'event_id':'literal-event-0'}]}))
        held=SimpleNamespace(directories=[(11,'stem.unit-'+first.unit_id+'.project-origin',21,(),()),
                                         (11,'stem.unit-'+second.unit_id+'.project-origin',22,(),())],
            files=[(21,'ORIGIN',31,(),canonical({'unit_id':first.unit_id,'project_identity':[7,101]})),
                   (22,'ORIGIN',32,(),canonical({'unit_id':second.unit_id,'project_identity':[7,102]}))])
        return {'old':held,'units':(first,second),'parent':11,'stem':'stem'}

    def test_literal_event_assignment_is_scoped_by_original_project_not_global_id(self):
        module=load();record=self.record()
        self.assertEqual({'literal-event-0'},module._native_assigned_event_ids(record,(7,101)))
        self.assertEqual({'literal-event-0'},module._native_assigned_event_ids(record,(7,102)))
        self.assertEqual(set(),module._native_assigned_event_ids(record,(7,103)))

    def test_missing_ambiguous_unread_or_wrong_unit_original_never_becomes_unassigned(self):
        module=load()
        for defect in ('missing-folder','duplicate-folder','missing-image','duplicate-image','unread','wrong-unit','bool-identity'):
            with self.subTest(defect=defect):
                record=self.record();held=record['old']
                if defect=='missing-folder': held.directories.pop()
                elif defect=='duplicate-folder': held.directories.append(held.directories[-1])
                elif defect=='missing-image': held.files.pop()
                elif defect=='duplicate-image': held.files.append(held.files[-1])
                else:
                    raw=None if defect=='unread' else canonical({'unit_id':'c'*64 if defect=='wrong-unit' else 'b'*64,
                        'project_identity':[True,102] if defect=='bool-identity' else [7,102]})
                    held.files[-1]=(22,'ORIGIN',32,(),raw)
                with self.assertRaises(module.SettingsAuditHold): module._native_assigned_event_ids(record,(7,101))


class Req7SettingsAuditAllocationTests(unittest.TestCase):
    def test_settings_scope_cleanup_preserves_foreign_reused_fd_and_other_originals_close(self):
        native_open=os.open; originals=[]; reused=[]
        foreign=self.root/'held-settings-foreign'; foreign.write_bytes(b'foreign still open\n')
        foreign.chmod(0o600)
        def capture(name,*args,**options):
            descriptor=native_open(name,*args,**options)
            if name=='0.json': originals.append(descriptor)
            return descriptor
        try:
            with self.owners() as (writer,_sheet):
                with mock.patch.object(self.module.os,'open',side_effect=capture):
                    with self.assertRaises((self.module.SettingsAuditHold,local.LocalCommitHold,
                                            self.module.journal.AttemptJournalHold)):
                        with self.module._hold_settings_originals(writer) as (_images,verify):
                            verify(); self.assertEqual(2,len(originals))
                            descriptor=originals[0]; os.close(descriptor)
                            other=native_open(foreign,os.O_RDONLY)
                            if other!=descriptor: os.dup2(other,descriptor); os.close(other)
                            reused.append(descriptor)
                self.assertEqual(b'foreign still open\n',os.pread(reused[0],128,0))
                self.assertEqual(foreign.stat().st_ino,os.fstat(reused[0]).st_ino)
                with self.assertRaises(OSError): os.fstat(originals[1])
        finally:
            for descriptor in reused:
                try: os.close(descriptor)
                except OSError: pass

    def test_settings_scope_cleanup_preserves_primary_interrupt_and_foreign_fd(self):
        native_open=os.open; originals=[]; reused=[]
        foreign=self.root/'held-settings-interrupt-foreign'; foreign.write_bytes(b'foreign on interrupt\n')
        foreign.chmod(0o600); primary=KeyboardInterrupt('original settings interruption')
        def capture(name,*args,**options):
            descriptor=native_open(name,*args,**options)
            if name=='0.json': originals.append(descriptor)
            return descriptor
        try:
            with self.owners() as (writer,_sheet):
                with mock.patch.object(self.module.os,'open',side_effect=capture):
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        with self.module._hold_settings_originals(writer):
                            self.assertEqual(2,len(originals))
                            descriptor=originals[0]; os.close(descriptor)
                            other=native_open(foreign,os.O_RDONLY)
                            if other!=descriptor: os.dup2(other,descriptor); os.close(other)
                            reused.append(descriptor)
                            raise primary
                self.assertIs(primary,caught.exception)
                self.assertEqual(b'foreign on interrupt\n',os.pread(reused[0],128,0))
                self.assertIsInstance(caught.exception.__cause__,self.module.SettingsAuditHold)
                with self.assertRaises(OSError): os.fstat(originals[1])
        finally:
            for descriptor in reused:
                try: os.close(descriptor)
                except OSError: pass

    def test_settings_scope_first_file_check_failure_closes_its_owned_fd(self):
        native_open=os.open; native_check=local._check; originals=[]
        def capture(name,*args,**options):
            descriptor=native_open(name,*args,**options)
            if name=='0.json': originals.append(descriptor)
            return descriptor
        def check(descriptor,**options):
            if descriptor in originals: raise OSError('fixture first file check refused')
            return native_check(descriptor,**options)
        with self.owners() as (writer,_sheet):
            with mock.patch.object(self.module.os,'open',side_effect=capture),mock.patch.object(local,'_check',side_effect=check):
                with self.assertRaises(OSError):
                    with self.module._hold_settings_originals(writer): self.fail('unproved scope yielded')
            self.assertEqual(1,len(originals))
            with self.assertRaises(OSError): os.fstat(originals[0])

    def test_creator_finalizer_interrupt_still_closes_the_actual_allocation_folder(self):
        native_folder=self.global_journal._create_folder
        native_cleanup=local._close_written_original
        native_write=local._write_new
        folders=[]; reached=[]; creators=[]; primary=KeyboardInterrupt('creator finalizer interrupted')
        def folder(parent,name):
            descriptor=native_folder(parent,name)
            if name=='settings-audit-allocation': folders.append(descriptor)
            return descriptor
        def cleanup(descriptor,identity):
            native_cleanup(descriptor,identity)
            if identity[:2] in creators and not reached:
                reached.append(identity)
                raise primary
        def writing(parent,name,raw,**options):
            result=native_write(parent,name,raw,**options)
            if name in ('SETTINGS-AUDIT-ALLOCATED','HEADER','ASSIGNMENTS','INITIALIZED') and options.get('_return_original'):
                creators.append(result[1][:2])
            return result
        with self.owners() as (writer,sheet):
            value=self.unit(); self.global_journal.prepare_global_unit(sheet,binding(),value)
            with mock.patch.object(self.global_journal,'_create_folder',side_effect=folder),mock.patch.object(local,'_close_written_original',side_effect=cleanup),mock.patch.object(local,'_write_new',side_effect=writing):
                with self.assertRaises(KeyboardInterrupt) as caught:
                    self.module.prepare_settings_audit_allocation(writer,sheet,binding(),value)
            self.assertIs(primary,caught.exception)
            self.assertEqual(1,len(reached)); self.assertEqual(1,len(folders))
            with self.assertRaises(OSError): os.fstat(folders[0])
            self.assertEqual(0,self.global_journal.inspect_global_unit(sheet,binding(),value).attempt_count)
            self.assertTrue((self.allocation/'INITIALIZED').is_file())
            self.assertEqual(canonical({'schema_version':1,'revision':0,
                'event_sha256':hashlib.sha256(self.event0).hexdigest()}),
                (self.project/'.tracker/settings/outbox/0.json').read_bytes())

    def test_first_creator_stat_cannot_be_recaptured_after_same_inode_rewrite(self):
        native=local._write_new; reached=[]
        with self.owners() as (writer,sheet):
            value=self.unit(); self.global_journal.prepare_global_unit(sheet,binding(),value)
            target=self.allocation/'ASSIGNMENTS'
            def rewritten(parent,name,raw,**options):
                result=native(parent,name,raw,**options)
                if name=='ASSIGNMENTS' and not reached:
                    before=target.stat(); target.write_bytes(raw)
                    os.utime(target,ns=(before.st_atime_ns,before.st_mtime_ns+1000000000))
                    after=target.stat(); reached.append((before,after))
                return result
            with mock.patch.object(local,'_write_new',side_effect=rewritten):
                with self.assertRaises(self.module.SettingsAuditHold):
                    self.module.prepare_settings_audit_allocation(writer,sheet,binding(),value)
            self.assertEqual(1,len(reached)); before,after=reached[0]
            self.assertEqual(before.st_ino,after.st_ino); self.assertNotEqual(before.st_mtime_ns,after.st_mtime_ns)
            self.assertFalse((self.allocation/'INITIALIZED').exists())
            state=self.global_journal.inspect_global_unit(sheet,binding(),value)
            self.assertEqual((0,'UNATTEMPTED_OBSERVATION'),(state.attempt_count,state.outcome))

    def test_first_writer_cleanup_never_closes_a_foreign_reused_descriptor(self):
        native=local._write_new; retained=[]; replacement=[]
        foreign=self.root/'owned-foreign-fd'; foreign.write_bytes(b'foreign original preserved\n'); foreign.chmod(0o600)
        try:
            with self.owners() as (writer,sheet):
                value=self.unit(); self.global_journal.prepare_global_unit(sheet,binding(),value)
                def reused(parent,name,raw,**options):
                    result=native(parent,name,raw,**options)
                    if name=='ASSIGNMENTS' and not replacement:
                        fd=result[0] if isinstance(result,tuple) else result
                        os.close(fd)
                        other=os.open(foreign,os.O_RDONLY)
                        if other!=fd: os.dup2(other,fd); os.close(other)
                        replacement.append(fd); retained.append(os.fstat(fd))
                    return result
                with mock.patch.object(local,'_write_new',side_effect=reused):
                    with self.assertRaises(self.module.SettingsAuditHold):
                        self.module.prepare_settings_audit_allocation(writer,sheet,binding(),value)
                self.assertEqual(1,len(replacement))
                actual=os.fstat(replacement[0])
                self.assertEqual((retained[0].st_dev,retained[0].st_ino),(actual.st_dev,actual.st_ino))
                self.assertEqual(b'foreign original preserved\n',os.pread(replacement[0],128,0))
        finally:
            for fd in replacement:
                try: os.close(fd)
                except OSError: pass

    def test_first_allocation_cannot_adopt_same_byte_replacement_before_reader_capture(self):
        for name in ('SETTINGS-AUDIT-ALLOCATED','HEADER','ASSIGNMENTS','INITIALIZED'):
            with self.subTest(first_written=name):
                case=type(self)('test_pending_projection_comes_from_exact_actual_event_and_retains_outbox'); case.setUp()
                try:
                    native=local._write_new; reached=[]; closed=[]
                    with case.owners() as (writer,sheet):
                        value=case.unit(); case.global_journal.prepare_global_unit(sheet,binding(),value)
                        target=(case.project/'.tracker'/name if name=='SETTINGS-AUDIT-ALLOCATED' else case.allocation/name)
                        preserved=case.root/'preserved-first-allocation-original'
                        def replace_after_writer(parent,actual,raw,**options):
                            result=native(parent,actual,raw,**options)
                            if actual==name and not reached:
                                original=target.stat(); target.rename(preserved)
                                target.write_bytes(raw); target.chmod(0o600)
                                reached.append((original.st_ino,target.stat().st_ino))
                                if options.get('_return_original'): closed.append(result[0])
                            return result
                        with mock.patch.object(local,'_write_new',side_effect=replace_after_writer):
                            with self.assertRaises(case.module.SettingsAuditHold):
                                case.module.prepare_settings_audit_allocation(writer,sheet,binding(),value)
                        self.assertEqual(1,len(reached),'must reach original first writer return before reader capture')
                        self.assertNotEqual(*reached[0]); self.assertEqual(preserved.read_bytes(),target.read_bytes())
                        state=case.global_journal.inspect_global_unit(sheet,binding(),value)
                        self.assertEqual((0,'UNATTEMPTED_OBSERVATION'),(state.attempt_count,state.outcome))
                        self.assertEqual((case.audit0,),case.module.pending_settings_audits(writer))
                        self.assertEqual(['0.json'],sorted(p.name for p in (case.project/'.tracker/settings/outbox').iterdir()))
                        if name!='INITIALIZED': self.assertFalse((case.allocation/'INITIALIZED').exists())
                        for descriptor in closed:
                            with self.assertRaises(OSError): os.fstat(descriptor)
                finally: case.doCleanups()

    def test_pending_reader_requires_actual_active_owner_and_preserves_ordinary_contract(self):
        from monitor import issue_tracker_state_owner as state
        before=self.image()
        with state.tracker_settings_writer(self.project,self.publication) as writer:
            self.assertNotIn(writer,state._COMPLETED_READ_CONTEXT)
            self.assertEqual((self.audit0,),self.module.pending_settings_audits(writer))
        for token in (writer,object()):
            with self.subTest(expired=token is writer),self.assertRaises(self.module.SettingsAuditHold):
                self.module.pending_settings_audits(token)
        self.assertEqual({},state._COMPLETED_ORIGINAL_GUARDS)
        self.assertEqual(before,self.image())

    def test_completed_discovery_refuses_unissued_writer_before_acquiring_sheet(self):
        before=self.image()
        with mock.patch.object(self.module.ownership,'spreadsheet_owner') as acquire:
            with self.assertRaises(local.LocalCommitHold):
                with self.module._hold_discovered_completed_settings(object()):
                    self.fail('unissued writer yielded a delivery context')
            acquire.assert_not_called()
        self.assertEqual(before,self.image())

    def test_cleanup_requires_actual_complete_delivery_pair_before_any_move(self):
        with self.owners() as (writer,sheet):
            value=self.unit(); self.prepare(writer,sheet,value); before=self.image()
            for actual_writer,actual_sheet in ((writer,sheet),(object(),sheet),(writer,object())):
                with self.subTest(writer=actual_writer is writer,sheet=actual_sheet is sheet),self.assertRaises(self.module.SettingsAuditHold):
                    self.module.cleanup_completed_settings_outbox(actual_writer,actual_sheet,binding(),value)
            self.assertEqual(before,self.image())

    def test_native_current_install_never_overwrites_substituted_evidence(self):
        from contextlib import ExitStack
        from types import SimpleNamespace
        with local.writer_owner(self.project,self.publication) as token,ExitStack() as scope:
            transition=self.module._CompletedSettingsTransition(scope,local._owner(token),SimpleNamespace(event_ids=()))
            payload={'new_k':6,'actor':'operator:fixture','expected_revision':0,'request_id':'native-pointer'}
            event=canonical({'schema_version':1,'revision':1,'type':'set_k','old_k':3,'new_k':6,
                'actor':'operator:fixture','recorded_at':'2026-10-08T10:01:00Z','request_id':'native-pointer',
                'payload_sha256':hashlib.sha256(canonical(payload)).hexdigest(),
                'predecessor_sha256':hashlib.sha256(self.event0).hexdigest()})
            pointer=canonical({'schema_version':1,'revision':1,'event_sha256':hashlib.sha256(event).hexdigest()})
            transition.begin(scope,b'owned private unresolved pointer intent\n')
            transition.install(scope,transition.events,'1.json',event); transition.stage=1
            transition.install(scope,transition.outbox,'1.json',pointer); transition.stage=2
            transition.verify()
            current=self.project/'.tracker/settings/current'; foreign=b'owned foreign pointer; preserve native evidence\n'
            replace=os.replace; rename=local._rename_new; reached=[]
            def insert():
                if not reached:
                    current.rename(self.root/'preserved-native-old-current')
                    current.write_bytes(foreign); current.chmod(0o600); reached.append(True)
            def replaced(source,destination,**options):
                if destination=='current': insert()
                return replace(source,destination,**options)
            def moved(parent,source,destination,**options):
                if source=='current': insert()
                return rename(parent,source,destination,**options)
            with mock.patch.object(os,'replace',side_effect=replaced),mock.patch.object(local,'_rename_new',side_effect=moved):
                try: transition.install(scope,transition.settings,'current',pointer,replace=True)
                except (OSError,ValueError): pass
            self.assertEqual([True],reached)
            self.assertEqual(1,sum(p.read_bytes()==foreign for p in (self.project/'.tracker').rglob('*') if p.is_file()),
                'native install must never overwrite an unproved replacement object')

    def test_completed_k_change_requires_actual_complete_delivery_before_any_write(self):
        with self.owners() as (writer,sheet):
            value=self.unit(); self.prepare(writer,sheet,value); before=self.image()
            for actual_writer,actual_sheet in ((writer,sheet),(object(),sheet),(writer,object())):
                with self.subTest(writer=actual_writer is writer,sheet=actual_sheet is sheet),self.assertRaises(self.module.SettingsAuditHold):
                    self.module.apply_completed_k_change(actual_writer,actual_sheet,binding(),value,
                        new_k=6,actor='operator:fixture',recorded_at='2026-10-08T10:01:00Z',
                        request_id='unproved-change',expected_revision=0)
            self.assertEqual(before,self.image())

    def test_current_k_reader_requires_actual_original_completion_delivery_pair(self):
        with self.owners() as (writer,sheet):
            value=self.unit(); self.prepare(writer,sheet,value)
            before=self.image()
            with self.assertRaises(self.module.SettingsAuditHold):
                self.module.read_current_k_after_completed_unit(writer,sheet,binding(),value)
            self.assertEqual(before,self.image())

    def test_absent_outbox_without_actual_complete_delivered_pair_never_becomes_pending_success(self):
        with self.owners() as (writer,sheet):
            value=self.unit(); self.prepare(writer,sheet,value)
            projection=self.project/'.tracker/settings/outbox/0.json'
            projection.rename(self.root/'preserved-unproved-projection')
            before=self.image()
            for observer in (self.module.inspect_completed_settings_delivery,
                             self.module.pending_settings_audits_after_completed_unit):
                with self.subTest(observer=observer.__name__),self.assertRaises(self.module.SettingsAuditHold):
                    observer(writer,sheet,binding(),value)
            with self.assertRaises(self.module.SettingsAuditHold):
                self.module.pending_settings_audits(writer)
            self.assertEqual(before,self.image()); self.assertFalse(projection.exists())

    def test_delivery_direct_rejects_unproved_complete_without_creating_local_success(self):
        self.assertTrue(hasattr(self.module,'record_completed_settings_delivery'),
                        'original allocation is not delivery: validate COMPLETE before the local record')
        with self.owners() as (writer,sheet):
            value=self.unit(); self.prepare(writer,sheet,value)
            before=self.image()
            with self.assertRaises(self.module.SettingsAuditHold):
                self.module.record_completed_settings_delivery(writer,sheet,binding(),value)
            self.assertEqual(before,self.image())
            self.assertFalse((self.project/'.tracker/settings-audit-delivery').exists())
            self.assertEqual((self.audit0,),self.module.pending_settings_audits(writer))

    def test_initial_allocation_cannot_omit_an_already_committed_pending_event(self):
        with self.owners() as (writer,sheet):
            settings.apply_local_k_change(self.project/'.tracker',token=writer,new_k=4,
                actor='operator:fixture',recorded_at='2026-10-08T10:01:00Z',request_id='change-1',expected_revision=0)
            value=self.unit()  # Deliberately retains only independently authored revision 0.
            self.global_journal.prepare_global_unit(sheet,binding(),value)
            original=self.image()
            with self.assertRaises(self.module.SettingsAuditHold):
                self.module.prepare_settings_audit_allocation(writer,sheet,binding(),value)
            self.assertEqual(original,self.image()); self.assertFalse(self.allocation.exists())
            self.assertFalse((self.project/'.tracker/SETTINGS-AUDIT-ALLOCATED').exists())

    def test_initial_allocation_persists_all_committed_events_in_original_revision_order(self):
        payload={'new_k':4,'actor':'operator:fixture','expected_revision':0,'request_id':'change-1'}
        event1=canonical({'schema_version':1,'revision':1,'type':'set_k','old_k':3,'new_k':4,
            'actor':'operator:fixture','recorded_at':'2026-10-08T10:01:00Z','request_id':'change-1',
            'payload_sha256':hashlib.sha256(canonical(payload)).hexdigest(),
            'predecessor_sha256':hashlib.sha256(self.event0).hexdigest()})
        audit1={'event_id':'settings:1:'+hashlib.sha256(event1).hexdigest(),
            'recorded_at_utc':'2026-10-08T10:01:00Z','details':event1.decode().rstrip('\n')}
        with self.owners() as (writer,sheet):
            settings.apply_local_k_change(self.project/'.tracker',token=writer,new_k=4,
                actor='operator:fixture',recorded_at='2026-10-08T10:01:00Z',request_id='change-1',expected_revision=0)
            value=self.unit(audits=(self.audit0,audit1)); self.prepare(writer,sheet,value)
            self.assertEqual([{'revision':0,'event_sha256':hashlib.sha256(self.event0).hexdigest(),'audit':self.audit0},
                              {'revision':1,'event_sha256':hashlib.sha256(event1).hexdigest(),'audit':audit1}],
                             json.loads((self.allocation/'ASSIGNMENTS').read_bytes()))
            self.assertEqual((self.audit0,audit1),self.module.pending_settings_audits(writer))

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
            def write_then_replace(parent,name,raw,**options):
                result=native_write(parent,name,raw,**options)
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
                            if allocation_image_barrier(case, fd):
                                calls.append(fd)
                                if len(calls) == boundary: raise OSError('owned allocation barrier fault')
                            return native_fsync(fd)
                        with mock.patch.object(case.module.os, 'fsync', side_effect=fsync), self.assertRaises(case.module.SettingsAuditHold):
                            case.module.prepare_settings_audit_allocation(writer, sheet, binding(), value)
                        # Independent physical order: two witness barriers,
                        # then mkdir parent/folder, then both evidence files.
                        self.assertEqual(boundary >= 3, case.allocation.is_dir())
                        self.assertEqual(boundary, len(calls))
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
            def write(parent, name, raw, **options):
                result=native_write(parent, name, raw, **options)
                if name == 'ASSIGNMENTS': self.global_journal.record_global_attempt_intent(sheet, binding(), value)
                return result
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
                if allocation_image_barrier(self, fd):
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

    def test_global_original_sync_failure_stops_before_allocation_witness(self):
        value = self.unit(); native_fsync = os.fsync; reached = []
        with self.owners() as (writer, sheet):
            self.global_journal.prepare_global_unit(sheet, binding(), value)
            before = self.image()
            global_parent = self.root / 'var/lib/http-ztp-container/issue-tracker'
            original = {path: path.read_bytes() for path in global_parent.rglob('*') if path.is_file()}
            objects = {(path.stat().st_dev, path.stat().st_ino)
                       for path in global_parent.rglob('*')}
            def fsync(fd):
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) in objects:
                    self.assertFalse(allocation_image_barrier(self, fd))
                    reached.append(True)
                    raise OSError('owned original GLOBAL re-sync fault')
                return native_fsync(fd)
            with mock.patch.object(os, 'fsync', side_effect=fsync), self.assertRaises(self.module.SettingsAuditHold):
                self.module.prepare_settings_audit_allocation(writer, sheet, binding(), value)
            self.assertEqual([True], reached)
            self.assertFalse(self.allocation.exists())
            self.assertFalse((self.project / '.tracker/SETTINGS-AUDIT-ALLOCATED').exists())
            self.assertFalse(any(path.name.startswith('.pending-') for path in (self.project / '.tracker').iterdir()))
            self.assertEqual(before, self.image())
            self.assertEqual(original, {path: path.read_bytes() for path in original})

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


class Req7NativeDeliveryCreatorOriginalsTests(unittest.TestCase):
    @contextmanager
    def _live_native_delivery_capture(self):
        from monitor import issue_tracker_unit_catalog as catalog
        allocation=load()
        directory=getattr(allocation,'_native_delivery_directory',None)
        file=getattr(allocation,'_native_delivery_file',None)
        self.assertTrue(callable(directory) and callable(file),
            'fixed native delivery capture must retain one original record per live edge')
        with tempfile.TemporaryDirectory(prefix='req7-native-delivery-capture-') as temporary:
            root=Path(temporary).resolve();root.chmod(0o700)
            folder=root/'literal-delivery';folder.mkdir(mode=0o700)
            image=folder/'HEADER';image.write_bytes(b'independent native original\n');image.chmod(0o600)
            parent=os.open(root,local._flags(directory=True));held=catalog._Originals()
            try:
                actual=directory(held,parent,'literal-delivery')
                observed=file(held,actual,'HEADER',16384)
                self.assertEqual(b'independent native original\n',observed[0])
                yield allocation,held,parent,actual,image,directory,file
            finally:
                held.close();os.close(parent)

    def test_live_native_delivery_capture_keeps_one_record_and_freshly_reads_each_request(self):
        with self._live_native_delivery_capture() as (allocation,held,parent,folder,image,directory,file):
            original_directories=tuple(held.directories);original_files=tuple(held.files)
            actual_pread=os.pread;reads=[]
            def fresh(fd,size,offset):
                raw=actual_pread(fd,size,offset);reads.append((fd,raw));return raw
            for _ in range(3):
                with mock.patch.object(allocation.os,'pread',side_effect=fresh):
                    self.assertEqual(folder,directory(held,parent,'literal-delivery'))
                    before=len(reads);raw,identity=file(held,folder,'HEADER',16384)
                    self.assertGreater(len(reads),before,'reuse must read actual bytes anew, not cached decode')
                self.assertEqual(b'independent native original\n',raw)
                self.assertEqual(original_files[0][3],identity)
                self.assertEqual(original_directories,tuple(held.directories))
                self.assertEqual(original_files,tuple(held.files))
            held.verify()

    def test_live_native_delivery_capture_refuses_same_byte_named_replacement_without_adoption(self):
        with self._live_native_delivery_capture() as (allocation,held,parent,folder,image,directory,file):
            before=tuple(held.files);original=image.stat().st_ino
            image.rename(image.with_name('displaced-original'))
            image.write_bytes(b'independent native original\n');image.chmod(0o600)
            self.assertNotEqual(original,image.stat().st_ino)
            with self.assertRaises((allocation.SettingsAuditHold,local.LocalCommitHold)):
                file(held,folder,'HEADER',16384)
            self.assertEqual(before,tuple(held.files),'failed reuse must not adopt the replacement')

    def test_live_native_delivery_capture_refuses_original_descriptor_flag_drift(self):
        import fcntl
        with self._live_native_delivery_capture() as (allocation,held,parent,folder,image,directory,file):
            fd=held.files[0][2];flags=fcntl.fcntl(fd,fcntl.F_GETFL)
            try:
                fcntl.fcntl(fd,fcntl.F_SETFL,flags ^ os.O_NONBLOCK)
                self.assertNotEqual(flags,fcntl.fcntl(fd,fcntl.F_GETFL))
                with self.assertRaises(allocation.SettingsAuditHold):file(held,folder,'HEADER',16384)
            finally:fcntl.fcntl(fd,fcntl.F_SETFL,flags)
            actual_pread=os.pread;drift=[]
            def change_after_original_read(actual,size,offset):
                raw=actual_pread(actual,size,offset)
                if actual==fd and not drift:
                    fcntl.fcntl(fd,fcntl.F_SETFL,flags ^ os.O_NONBLOCK);drift.append(True)
                return raw
            try:
                with mock.patch.object(allocation.os,'pread',side_effect=change_after_original_read):
                    with self.assertRaises(allocation.SettingsAuditHold):file(held,folder,'HEADER',16384)
                self.assertEqual([True],drift,'fault must follow the actual original pread return')
            finally:fcntl.fcntl(fd,fcntl.F_SETFL,flags)
            held.verify()

    def test_native_k_reader_uses_both_pure_parse_boundaries_and_refuses_after_boundary_failure(self):
        import threading
        from contextlib import ExitStack
        from monitor import issue_tracker_spreadsheet_owner as ownership,issue_tracker_state_owner as state
        allocation=load()
        # Internal consumer control test, not a completed-delivery issuer.
        # Genuine archived ALL/preparation issuance is covered by workflow.
        with tempfile.TemporaryDirectory(prefix='req7-k-read-boundary-') as temporary,ExitStack() as scope:
            root=Path(temporary).resolve();project=root/'project';project.mkdir(mode=0o700)
            publication=project/'publication';publication.mkdir(mode=0o755)
            (root/'var/lib/http-ztp-container/issue-tracker').mkdir(parents=True,mode=0o700)
            scope.enter_context(scoped_fixture(root,ownership));local.create_local_commit_store(project,publication)
            writer=scope.enter_context(local.try_writer_owner(project,publication))
            settings.initialize_local_k_store(project/'.tracker',initialized_at='2026-10-13T00:00:00Z',
                acquisition_id='independent-k-read-boundary',token=writer)
            images,original=scope.enter_context(allocation._hold_settings_originals(writer))
            order=[];fail_after=[False]
            def before():original();order.append('before')
            def after():
                original();order.append('after')
                if fail_after[0]:raise allocation.SettingsAuditHold()
            passes=[]
            def original_boundary():
                (before if not passes else after)();passes.append(True)
            issued=allocation._NativeCatalogKContext()
            packet={'token':writer,'owner':local._owner(writer),'pid':os.getpid(),
                'thread':threading.get_ident(),'images':images,'verify':original_boundary}
            reset=allocation._NATIVE_CATALOG_K_CONTEXT.set(issued)
            allocation._LIVE_NATIVE_CATALOG_K_CONTEXTS[issued]=packet
            state._NATIVE_CATALOG_K_READ_CONTEXT[writer]=issued
            actual_chain=allocation.chain.validate_k_chain_snapshot
            def chain(*args):
                result=actual_chain(*args);order.append('pure-chain');return result
            try:
                with mock.patch.object(allocation.chain,'validate_k_chain_snapshot',chain):
                    actual=allocation._read_native_catalog_k(writer,issued)
                    self.assertEqual((0,3),(actual.revision,actual.k))
                    self.assertEqual(['before','pure-chain','after'],order)
                    order.clear();passes.clear();fail_after[0]=True
                    with self.assertRaises(allocation.SettingsAuditHold):
                        allocation._read_native_catalog_k(writer,issued)
                    self.assertEqual(['before','pure-chain','after'],order,
                        'a successful pure parse cannot hide the final original refusal')
            finally:
                state._NATIVE_CATALOG_K_READ_CONTEXT.pop(writer,None)
                allocation._LIVE_NATIVE_CATALOG_K_CONTEXTS.pop(issued,None)
                allocation._NATIVE_CATALOG_K_CONTEXT.reset(reset)
            with self.assertRaises(allocation.SettingsAuditHold):allocation._read_native_catalog_k(writer,issued)

    def test_native_catalog_k_prior_identity_is_only_an_exact_relation_not_an_issuer(self):
        allocation=load();check=getattr(allocation,'_require_native_catalog_k_prior_identity',None)
        self.assertTrue(callable(check),'K replay needs exact original prior identity at each semantic boundary')
        writer,owner,sheet=object(),object(),object();bound=binding()
        events=('settings:0:literal-original','settings:1:literal-original')
        raw=SimpleNamespace(events=events)
        prior={'writer':writer,'owner':owner,'raw':raw,'events':events}
        record={'token':sheet,'binding':bound,'prior_delivery_events':[prior]}
        with mock.patch.object(allocation,'_hold_settings_originals') as acquire:
            self.assertIsNone(check(record,writer,owner,sheet,bound,prior=prior,raw=raw,events=events))
        acquire.assert_not_called()  # This relation alone never issues a K context.

    def test_native_catalog_k_prior_identity_refuses_equal_replacement_and_ambiguous_originals(self):
        allocation=load();check=getattr(allocation,'_require_native_catalog_k_prior_identity',None)
        self.assertTrue(callable(check),'equal copied rows/raw/events cannot replace a prior original')
        writer,owner,sheet=object(),object(),object();bound=binding()
        events=('settings:0:literal-original','settings:1:literal-original')
        raw=SimpleNamespace(events=events)
        prior={'writer':writer,'owner':owner,'raw':raw,'events':events}
        def record(rows):return {'token':sheet,'binding':bound,'prior_delivery_events':rows}
        replacements=[record([dict(prior)]),record([prior,dict(prior)]),record([]),
            {**record([prior]),'token':object()},
            record([{**prior,'raw':SimpleNamespace(events=events)}]),
            record([{**prior,'events':tuple(list(events))}])]
        for replaced in replacements:
            with self.subTest(replaced=replaced),self.assertRaises(allocation.SettingsAuditHold):
                check(replaced,writer,owner,sheet,bound,prior=prior,raw=raw,events=events)
        raw.events=tuple(list(events))
        with self.assertRaises(allocation.SettingsAuditHold):
            check(record([prior]),writer,owner,sheet,bound,prior=prior,raw=raw,events=events)

    def test_native_catalog_k_read_refuses_unissued_preparation_before_settings_or_sheet_acquisition(self):
        allocation=load();entry=getattr(allocation,'_hold_native_catalog_k_read',None)
        self.assertTrue(callable(entry),'native preparation needs original read-only K reception')
        from monitor import issue_tracker_nv_reservation as nv
        with mock.patch.object(allocation,'_hold_settings_originals') as settings_images, \
                mock.patch.object(allocation.ownership,'spreadsheet_owner') as sheet:
            with self.assertRaises((allocation.SettingsAuditHold,nv.NvReservationHold,local.LocalCommitHold)):
                with entry(object(),object(),object(),binding()):
                    self.fail('unissued preparation reached K read enrollment')
        settings_images.assert_not_called();sheet.assert_not_called()

    def test_native_allocation_prior_events_rejects_unissued_preparation_before_settings(self):
        allocation=load();entry=getattr(allocation,'_native_allocation_prior_events',None)
        self.assertTrue(callable(entry),'native allocation needs fixed actual preparation provenance')
        from monitor import issue_tracker_nv_reservation as nv
        with mock.patch.object(allocation,'_hold_settings_originals') as settings:
            with self.assertRaises((allocation.SettingsAuditHold,nv.NvReservationHold,local.LocalCommitHold)):
                entry(object(),object(),object(),binding())
        settings.assert_not_called()

    def test_default_delivery_disposition_rejects_unissued_writer_before_sheet_or_creation(self):
        allocation=load();entry=getattr(allocation,'_finalize_native_completed_settings_delivery',None)
        self.assertTrue(callable(entry),'default worker needs fixed original-only C25 disposition')
        with mock.patch.object(allocation.ownership,'spreadsheet_owner') as sheet, \
                mock.patch.object(allocation,'record_completed_settings_delivery') as create:
            with self.assertRaises((allocation.SettingsAuditHold,local.LocalCommitHold)):
                entry(object(),binding())
        sheet.assert_not_called();create.assert_not_called()

    def _writer_source_cleanup(self, interrupt=False):
        allocation=load();primary=KeyboardInterrupt('literal first writer interrupted')
        with tempfile.TemporaryDirectory(prefix='req7-delivery-writer-cleanup-') as temporary:
            root=Path(temporary).resolve();root.chmod(0o700)
            foreign=root/'literal-foreign';foreign.write_bytes(b'foreign original preserved\n');foreign.chmod(0o600)
            parent=os.open(root,local._flags(directory=True));replaced=[]
            expected=foreign.stat().st_dev,foreign.stat().st_ino
            class CaptureFault:
                def capture_written(_self,actual_parent,name,fd,identity,raw):
                    self.assertEqual(parent,actual_parent);self.assertEqual('STARTED',name)
                    self.assertEqual(b'literal new delivery\n',raw)
                    self.assertEqual((root/name).stat().st_ino,os.fstat(fd).st_ino)
                    os.close(fd);other=os.open(foreign,os.O_RDONLY)
                    if other!=fd:os.dup2(other,fd);os.close(other)
                    os.lseek(fd,3,os.SEEK_SET);replaced.append(fd)
                    if interrupt:raise primary
            try:
                if interrupt:
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        allocation._write_delivery_file(parent,'STARTED',b'literal new delivery\n',_creator=CaptureFault())
                    self.assertIs(primary,caught.exception)
                    self.assertIsNotNone(caught.exception.__cause__)
                else:
                    with self.assertRaises((allocation.SettingsAuditHold,local.LocalCommitHold)):
                        allocation._write_delivery_file(parent,'STARTED',b'literal new delivery\n',_creator=CaptureFault())
                self.assertEqual(1,len(replaced));actual=os.fstat(replaced[0])
                self.assertEqual(expected,(actual.st_dev,actual.st_ino))
                self.assertEqual(3,os.lseek(replaced[0],0,os.SEEK_CUR))
                self.assertEqual(b'foreign original preserved\n',os.pread(replaced[0],100,0))
                self.assertEqual(b'literal new delivery\n',(root/'STARTED').read_bytes())
            finally:
                for fd in replaced:
                    try:
                        actual=os.fstat(fd)
                        if (actual.st_dev,actual.st_ino)==expected:os.close(fd)
                    except OSError:pass
                os.close(parent)

    def test_actual_writer_source_cleanup_refuses_foreign_slot_without_closing_it(self):
        self._writer_source_cleanup()

    def test_actual_writer_source_cleanup_preserves_primary_interrupt_and_foreign_slot(self):
        self._writer_source_cleanup(interrupt=True)

    def _actual_original_graph(self, fault=None):
        from contextlib import ExitStack
        from monitor import issue_tracker_spreadsheet_owner as ownership, issue_tracker_unit_catalog as catalog
        allocation=load()
        self.assertTrue(hasattr(allocation,'_DeliveryCreatorOriginals'),
            'new delivery requires its own immutable raw handoff, not LocalC6 permission')
        with tempfile.TemporaryDirectory(prefix='req7-delivery-raw-') as temporary, ExitStack() as scope:
            root=Path(temporary).resolve();project=root/'project';project.mkdir(mode=0o700)
            publication=project/'publication';publication.mkdir(mode=0o755)
            (root/'var/lib/http-ztp-container/issue-tracker').mkdir(parents=True,mode=0o700)
            scope.enter_context(scoped_fixture(root,ownership))
            local.create_local_commit_store(project,publication)
            token=scope.enter_context(local.try_writer_owner(project,publication))
            sheet=scope.enter_context(ownership.spreadsheet_owner(binding()))
            owner=local._owner(token);original=project/'.tracker/literal-original'
            original.write_bytes(b'literal-delivery-original\n');original.chmod(0o600)
            before=original.stat().st_ino,original.read_bytes()
            held=catalog._Originals();scope.callback(held.close)
            held.file(owner.root_fd,'literal-original',16384)
            raw=allocation._DeliveryCreatorOriginals(token,sheet,binding())
            raw.retain(held);held.close();raw.verify()
            if fault in ('rebind','interrupt'):
                original.rename(original.with_name('displaced-original'))
                original.write_bytes(before[1]);original.chmod(0o600)
                self.assertNotEqual(before[0],original.stat().st_ino)
                with self.assertRaises(allocation.SettingsAuditHold):raw.verify()
                if fault=='interrupt':
                    self.assertTrue(hasattr(raw,'finish'),'raw finalization must receive the original interruption')
                    primary=KeyboardInterrupt('literal raw original interruption')
                    self.assertFalse(raw.finish(type(primary),primary,None))
                    self.assertIsInstance(primary.__cause__,allocation.SettingsAuditHold)
                else:
                    with self.assertRaises(allocation.SettingsAuditHold):raw.close()
            elif fault=='unissued-write':
                descriptor=os.open('literal-unissued',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=owner.root_fd)
                try:
                    os.write(descriptor,b'literal\n')
                    with self.assertRaises(allocation.SettingsAuditHold):
                        raw.capture_written(owner.root_fd,'literal-unissued',descriptor,
                            allocation.journal._identity(os.fstat(descriptor)),b'literal\n')
                    self.assertEqual([],raw.created_files)
                    self.assertEqual(before,(original.stat().st_ino,original.read_bytes()))
                finally:os.close(descriptor)
                raw.close()
            else:
                raw.verify();raw.close()
                self.assertEqual(before,(original.stat().st_ino,original.read_bytes()))
            self.assertEqual([],raw.slots)

    def test_delivery_raw_handoff_preserves_actual_original_after_leaf_close(self):
        self._actual_original_graph()

    def test_delivery_raw_handoff_refuses_same_bytes_new_original_inode(self):
        self._actual_original_graph('rebind')

    def test_unissued_delivery_raw_graph_cannot_adopt_a_created_pair(self):
        self._actual_original_graph('unissued-write')

    def test_delivery_raw_tail_preserves_incoming_interrupt_and_closes_every_original(self):
        self._actual_original_graph('interrupt')

    def test_delivery_raw_repeated_capture_keeps_one_exact_named_edge_not_one_record_per_reader(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_spreadsheet_owner as ownership,issue_tracker_unit_catalog as catalog
        allocation=load()
        with tempfile.TemporaryDirectory(prefix='req7-raw-unique-edge-') as temporary,ExitStack() as scope:
            root=Path(temporary).resolve();project=root/'project';project.mkdir(mode=0o700)
            publication=project/'publication';publication.mkdir(mode=0o755)
            (root/'var/lib/http-ztp-container/issue-tracker').mkdir(parents=True,mode=0o700)
            scope.enter_context(scoped_fixture(root,ownership))
            local.create_local_commit_store(project,publication)
            writer=scope.enter_context(local.try_writer_owner(project,publication))
            sheet=scope.enter_context(ownership.spreadsheet_owner(binding()));owner=local._owner(writer)
            folder=project/'.tracker/literal-folder';folder.mkdir(mode=0o700)
            for path in (folder/'IMAGE',project/'.tracker/literal-flat'):
                path.write_bytes(b'independent original bytes\n');path.chmod(0o600)
            raw=allocation._DeliveryCreatorOriginals(writer,sheet,binding())
            scope.callback(raw.close)
            readers=ExitStack();scope.callback(readers.close)
            names=frozenset({'literal-folder','literal-flat'})
            for _ in range(3):
                held=catalog._Originals()
                readers.callback(held.close)
                original_folder=held.directory(owner.root_fd,'literal-folder')
                held.file(original_folder,'IMAGE',16384);held.file(owner.root_fd,'literal-flat',16384)
                held.namespace=(owner.root_fd,'literal-',names)
                raw.retain(held)
                raw.verify()
                self.assertEqual((1,2,1),(len(raw.directories),len(raw.files),len(raw.namespaces)),
                    'coherent same named originals from separate live readers must not multiply guard work')
                self.assertEqual(4,len(raw.slots),
                    'one continuous original root/folder/two file FDs suffice; source readers still own their cleanup')
            self.assertEqual({b'independent original bytes\n'}, {row[4] for row in raw.files})
            self.assertEqual(2,len({row[3][:2] for row in raw.files}),
                'equal bytes on different named edges never collapse')
            raw.verify()

    def _actual_raw_namespace_views(self, fault=None):
        # Independent contract: eight prefixes of ONE owned original parent
        # share two fresh name views bracketing a real verification, never a
        # successful result retained for another call. Real immutable file
        # reads must remain inside that bracket, so mid-read insertion refuses.
        from contextlib import ExitStack
        from monitor import issue_tracker_spreadsheet_owner as ownership, issue_tracker_unit_catalog as catalog
        allocation=load()
        with tempfile.TemporaryDirectory(prefix='req7-raw-name-views-') as temporary, ExitStack() as scope:
            root=Path(temporary).resolve();project=root/'project';project.mkdir(mode=0o700)
            publication=project/'publication';publication.mkdir(mode=0o755)
            (root/'var/lib/http-ztp-container/issue-tracker').mkdir(parents=True,mode=0o700)
            scope.enter_context(scoped_fixture(root,ownership));local.create_local_commit_store(project,publication)
            writer=scope.enter_context(local.try_writer_owner(project,publication))
            sheet=scope.enter_context(ownership.spreadsheet_owner(binding()));owner=local._owner(writer)
            prefixes=tuple('literal-%d-'%i for i in range(8))
            for prefix in prefixes:
                path=project/'.tracker'/(prefix+'original');path.write_bytes(b'independent namespace image\n');path.chmod(0o600)
            raw=allocation._DeliveryCreatorOriginals(writer,sheet,binding());scope.callback(raw.close)
            with ExitStack() as readers:
                for prefix in prefixes:
                    held=catalog._Originals();readers.callback(held.close)
                    held.file(owner.root_fd,prefix+'original',16384)
                    held.namespace=(owner.root_fd,prefix,frozenset((prefix+'original',)))
                    raw.retain(held)
                parent_identity=allocation.journal._identity(os.fstat(owner.root_fd))[:2]
                native_listdir=os.listdir;native_pread=os.pread;views=[];changed=[]
                inserted=project/'.tracker'/('unrelated-new-edge' if fault=='unrelated-during-file'
                    else prefixes[-1]+'unapproved')
                def names(fd):
                    result=native_listdir(fd)
                    if type(fd) is int and allocation.journal._identity(os.fstat(fd))[:2]==parent_identity:
                        views.append(tuple(result))
                    return result
                def read(fd,length,offset):
                    result=native_pread(fd,length,offset)
                    if fault in ('during-file','unrelated-during-file') and not changed:
                        inserted.write_bytes(b'independent unexpected edge\n');inserted.chmod(0o600);changed.append(True)
                    return result
                with mock.patch.object(allocation.os,'listdir',side_effect=names), \
                        mock.patch.object(allocation.os,'pread',side_effect=read):
                    if fault=='during-file':
                        try:
                            with self.assertRaises(allocation.SettingsAuditHold):raw.verify()
                            self.assertEqual([True],changed)
                        finally:inserted.unlink(missing_ok=True)
                    elif fault=='unrelated-during-file':
                        try:
                            raw.verify()
                            self.assertEqual([True],changed,'a fresh unrelated append is not a changed monitored prefix')
                        finally:inserted.unlink(missing_ok=True)
                    else:
                        raw.verify();raw.verify()
                        self.assertEqual(4,len(views),'two actual parent snapshots per call, not one enumeration per prefix')
                if fault=='between-calls':
                    inserted.write_bytes(b'independent unexpected edge\n');inserted.chmod(0o600)
                    try:
                        with self.assertRaises(allocation.SettingsAuditHold):raw.verify()
                    finally:inserted.unlink()
                raw.verify()

    def test_delivery_raw_namespace_views_are_fresh_and_bounded_per_original_parent(self):
        self._actual_raw_namespace_views()

    def test_delivery_raw_namespace_insertion_during_real_file_read_refuses_before_return(self):
        self._actual_raw_namespace_views('during-file')

    def test_delivery_raw_namespace_view_cannot_cache_success_between_calls(self):
        self._actual_raw_namespace_views('between-calls')

    def test_delivery_raw_unrelated_name_append_preserves_filtered_namespace_contract(self):
        self._actual_raw_namespace_views('unrelated-during-file')

    def test_delivery_raw_duplicate_capture_refuses_conflicting_bytes_without_replacing_original_expectation(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_spreadsheet_owner as ownership,issue_tracker_unit_catalog as catalog
        allocation=load()
        with tempfile.TemporaryDirectory(prefix='req7-raw-conflict-') as temporary,ExitStack() as scope:
            root=Path(temporary).resolve();project=root/'project';project.mkdir(mode=0o700)
            publication=project/'publication';publication.mkdir(mode=0o755)
            (root/'var/lib/http-ztp-container/issue-tracker').mkdir(parents=True,mode=0o700)
            scope.enter_context(scoped_fixture(root,ownership));local.create_local_commit_store(project,publication)
            writer=scope.enter_context(local.try_writer_owner(project,publication))
            sheet=scope.enter_context(ownership.spreadsheet_owner(binding()));owner=local._owner(writer)
            path=project/'.tracker/literal-flat';path.write_bytes(b'independent original\n');path.chmod(0o600)
            raw=allocation._DeliveryCreatorOriginals(writer,sheet,binding());scope.callback(raw.close)
            with ExitStack() as readers:
                first=catalog._Originals();readers.callback(first.close)
                first.file(owner.root_fd,'literal-flat',16384);raw.retain(first)
                second=catalog._Originals();readers.callback(second.close)
                second.file(owner.root_fd,'literal-flat',16384)
                changed=SimpleNamespace(directories=second.directories,
                    files=[(*row[:4],b'foreign expectation\n') for row in second.files],
                    namespace=None,verify=second.verify)
                with self.assertRaises(allocation.SettingsAuditHold):raw.retain(changed)
                self.assertEqual([b'independent original\n'],[row[4] for row in raw.files])
                raw.verify()

    def test_native_prior_raw_repeated_capture_keeps_exact_one_catalog_edge_and_namespace(self):
        from contextlib import ExitStack
        from monitor import issue_tracker_spreadsheet_owner as ownership,issue_tracker_unit_catalog as catalog
        allocation=load()
        with tempfile.TemporaryDirectory(prefix='req7-prior-unique-edge-') as temporary,ExitStack() as scope:
            root=Path(temporary).resolve();project=root/'project';project.mkdir(mode=0o700)
            publication=project/'publication';publication.mkdir(mode=0o755)
            state=root/'var/lib/http-ztp-container/issue-tracker';state.mkdir(parents=True,mode=0o700)
            scope.enter_context(scoped_fixture(root,ownership));local.create_local_commit_store(project,publication)
            writer=scope.enter_context(local.try_writer_owner(project,publication))
            sheet=scope.enter_context(ownership.spreadsheet_owner(binding()))
            actual=ownership._validated_owner(sheet,binding());parent=actual.directories[-1][0]
            stem=actual.lock_name[:-5];name=stem+'.units';(state/name).mkdir(mode=0o700)
            old=catalog._Originals();scope.callback(old.close)
            old.directory(parent,name);old.namespace=(parent,stem+'.',frozenset({name,actual.lock_name}))
            prior=allocation._NativeAllocationPriorOriginals(writer,sheet,binding(),old)
            scope.push(prior.finish)
            readers=ExitStack();scope.callback(readers.close)
            for _ in range(3):
                held=catalog._Originals()
                readers.callback(held.close)
                held.directory(parent,name);held.namespace=old.namespace
                prior.retain(held)
                prior.verify()
                self.assertEqual((1,1),(len(prior.catalog_edges),len(prior.namespaces)),
                    'same original catalog/name scope must not multiply repeated guard work')
                self.assertEqual(2,len(prior.raw.slots),'keep only original namespace parent and catalog FD')
            self.assertIsNone(prior.record);self.assertIsNone(prior.frozen)
            self.assertEqual((frozenset(),None,frozenset()),prior._expected_tail(),
                'raw capture issues no preparation, namespace addition or count permission')

    def test_delivery_raw_duplicate_inode_does_not_merge_write_only_and_read_only_descriptions(self):
        import fcntl
        from contextlib import ExitStack
        from monitor import issue_tracker_spreadsheet_owner as ownership
        allocation=load()
        with tempfile.TemporaryDirectory(prefix='req7-raw-description-') as temporary,ExitStack() as scope:
            root=Path(temporary).resolve();project=root/'project';project.mkdir(mode=0o700)
            publication=project/'publication';publication.mkdir(mode=0o755)
            (root/'var/lib/http-ztp-container/issue-tracker').mkdir(parents=True,mode=0o700)
            scope.enter_context(scoped_fixture(root,ownership));local.create_local_commit_store(project,publication)
            writer=scope.enter_context(local.try_writer_owner(project,publication))
            sheet=scope.enter_context(ownership.spreadsheet_owner(binding()))
            path=project/'.tracker/literal-description';path.write_bytes(b'original description\n');path.chmod(0o600)
            write_only=os.open(path,os.O_WRONLY);scope.callback(os.close,write_only)
            read_only=os.open(path,os.O_RDONLY);scope.callback(os.close,read_only)
            raw=allocation._DeliveryCreatorOriginals(writer,sheet,binding());scope.callback(raw.close)
            retained_writer=raw._dup(write_only)
            retained_reader=raw._dup(read_only)
            self.assertEqual(os.O_WRONLY,fcntl.fcntl(retained_writer,fcntl.F_GETFL)&os.O_ACCMODE)
            self.assertEqual(os.O_RDONLY,fcntl.fcntl(retained_reader,fcntl.F_GETFL)&os.O_ACCMODE)
            self.assertNotEqual(retained_writer,retained_reader)
            self.assertEqual(b'original description\n',os.pread(retained_reader,100,0))
            fresh_reader=os.open(path,os.O_RDONLY);scope.callback(os.close,fresh_reader)
            flags=fcntl.fcntl(retained_reader,fcntl.F_GETFL)
            try:
                fcntl.fcntl(retained_reader,fcntl.F_SETFL,flags|os.O_NONBLOCK)
                with self.assertRaises(allocation.SettingsAuditHold):
                    raw._dup(fresh_reader)
            finally:
                fcntl.fcntl(retained_reader,fcntl.F_SETFL,flags)


if __name__ == '__main__': unittest.main()
