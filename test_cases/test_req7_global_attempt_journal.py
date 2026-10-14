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

if len(sys.argv) > 1 and sys.argv[1] in ('--owned-retry','--owned-wire-claim','--owned-start-hold','--owned-original-read'):
    sys.path.insert(0, sys.argv[3]); sys.path.insert(0, str(Path(sys.argv[3]) / 'tools'))
import test_cases
ROOT = Path(test_cases.__file__).resolve().parents[1]
from test_cases.test_req7_spreadsheet_owner import fixture, scoped_fixture, binding, TARGET, load as load_owner
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


def original_read_files(root):
    return {str(path.relative_to(root)): (path.stat().st_ino, path.read_bytes())
            for path in root.rglob('*') if path.is_file()}


class Req7GlobalAttemptJournalTests(unittest.TestCase):
    def _literal_count_tail_phase_entry_failure(self,primary):
        # Synthetic private lifecycle control only, not Count/source admission.
        # Its two actual local FDs and cleanup expectations are independent.
        import errno
        from types import SimpleNamespace
        from monitor import issue_tracker_settings_audit_allocation as allocation
        packet={name:object() for name in
            ('writer','token','binding','unit','project','owner','context','verify')}
        calls=[];slots=[];settings=[]
        for name,target in (('literal-raw',slots),('literal-settings',settings)):
            path=self.root/name;path.write_bytes(b'literal owned cleanup file\n');path.chmod(0o600)
            fd=os.open(path,os.O_RDONLY)
            target.append((fd,self.module.journal._identity(os.fstat(fd))))
        raw=SimpleNamespace(slots=list(slots))
        receiver=allocation._CountSourceRawOriginals.__new__(allocation._CountSourceRawOriginals)
        receiver.raw=raw;receiver.owned_slots=tuple(slots);receiver.closed=False;receiver.source_failed=False
        stack=ExitStack()
        def settings_close():
            calls.append('settings')
            self.module.local._close_written_original(*settings[0])
        stack.callback(settings_close)
        def forbidden(*args):calls.append('semantic');raise AssertionError('phase failure cannot use revoked verifier')
        anchor=self.module._CountSourceRawTail(object(),packet,object(),forbidden)
        anchor._binding=(receiver,forbidden,raw,tuple(slots),stack)
        context=self.module._COUNT_SOURCE_RAW_TAIL_CONTEXT
        def fail_phase(value):raise primary
        observed=SimpleNamespace(get=context.get,set=fail_phase,reset=lambda value:calls.append('reset'))
        def closed(fd):
            try:os.fstat(fd);return False
            except OSError as error:
                self.assertEqual(errno.EBADF,error.errno);return True
        try:
            with mock.patch.object(self.module,'_COUNT_SOURCE_RAW_TAIL_CONTEXT',observed):
                with self.assertRaises(type(primary)) as caught:anchor.finish()
            self.assertIs(primary,caught.exception)
            self.assertEqual({'closed':True,'raw':True,'settings':True,'closing':False,'calls':['settings']},
                {'closed':receiver.closed,'raw':closed(slots[0][0]),'settings':closed(settings[0][0]),
                 'closing':anchor.closing,'calls':calls})
            self.assertEqual([],raw.slots);self.assertIsNone(context.get())
        finally:
            for fd,identity in (*slots,*settings):
                try:self.module.local._close_written_original(fd,identity)
                except (OSError,ValueError):pass

    def test_count_tail_phase_entry_interrupt_cleans_owned_slots_without_semantic_grant(self):
        self._literal_count_tail_phase_entry_failure(KeyboardInterrupt('literal phase entry interruption'))

    def test_count_tail_phase_entry_memory_error_keeps_private_primary_and_cleans_slots(self):
        self._literal_count_tail_phase_entry_failure(MemoryError('literal phase entry allocation failure'))

    @contextmanager
    def _actual_catalog_replay_control(self):
        # Real local catalog bytes and actual sheet owner only. This does not
        # issue project C6, K, a counted wire, or a native send permission.
        from test_cases.test_req7_unit_catalog import load as load_catalog
        catalog=load_catalog(reset_dependencies=False)
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            catalog.register_pending_unit(token,binding(),self.value)
            with self.module._hold_native_catalog_replay(token,binding(),self.value):
                yield catalog,token

    def test_catalog_input_membership_retains_only_the_enclosing_original_entry_and_exit(self):
        with self._actual_catalog_replay_control() as (catalog,token):
            checks=[];original=catalog._Originals.verify
            def inspect(held,*args,**kwargs):
                result=original(held,*args,**kwargs);checks.append(held);return result
            with mock.patch.object(catalog._Originals,'verify',new=inspect):
                owner,parent,name,header=self.module._inputs(token,binding(),self.value)
        # Assert outside the actual issuer: its intentional sanitized HOLD
        # must not turn an independent expected-call-count FAIL into ERROR.
        self.assertEqual(2,len(checks),'pure membership needs original ENTER/EXIT, not a third adjacent replay')
        self.assertIs(checks[0],checks[1])
        self.assertEqual(owner.directories[-1][0],parent)
        self.assertEqual(owner.lock_name[:-5]+'.unit-'+self.value.unit_id+'.journal',name)
        self.assertEqual(TARGET,header['spreadsheet_id'])

    def test_catalog_writer_borrow_keeps_post_membership_entry_but_no_adjacent_exit_replay(self):
        with self._actual_catalog_replay_control() as (catalog,token):
            checks=[];original=catalog._Originals.verify;inside=[]
            def inspect(held,*args,**kwargs):
                result=original(held,*args,**kwargs);checks.append(held);return result
            with mock.patch.object(catalog._Originals,'verify',new=inspect):
                with self.module._hold_native_catalog_write_replay(token,binding(),self.value) as verify:
                    self.assertTrue(callable(verify))
                    inside.append(len(checks))
        self.assertEqual([2],inside,'membership must be checked before borrower body starts')
        self.assertEqual(3,len(checks),'body exit is enclosed by the original context EXIT once')
        self.assertTrue(all(held is checks[0] for held in checks))

    def test_data_only_launch_consumption_spends_original_without_semantic_read_or_grant(self):
        entry = getattr(self.module, '_consume_original_wire_launch_attempt', None)
        self.assertTrue(callable(entry), 'one-use DATA consumption must be separate from fresh launch validation')
        with Req7GlobalAttemptJournalWorkflowTests.counted_wire_owners(self) as (writer, owner, target):
            with self.module._hold_counted_original_wire(writer, owner, target, self.value) as image:
                actual_inspect = self.module._inspect
                with mock.patch.object(self.module, '_inspect', wraps=actual_inspect) as inspected:
                    self.assertIsNone(entry(writer, owner, target, self.value, image))
                    self.assertEqual(0, inspected.call_count, 'spending an image is DATA, not a fresh semantic PASS')
                    self.assertIs(True, self.module._LIVE_WIRE_CLAIMS[image][-1])
                    for candidate in (image, replace(image)):
                        with self.assertRaises(self.module.GlobalAttemptHold):
                            entry(writer, owner, target, self.value, candidate)
                    self.assertEqual(0, inspected.call_count)
                    # The unchanged original prelaunch API, not consumption,
                    # must still perform the complete real verifier.
                    self.module._require_original_wire_launch(writer, owner, target, self.value, image, consume=False)
                    self.assertGreater(inspected.call_count, 0)
            current = self.module.inspect_global_unit(owner, target, self.value)
            self.assertEqual((1, 'UNKNOWN'), (current.attempt_count, current.outcome))

    def test_first_prefetch_transfers_live_source_after_original_count_graph_is_anchored(self):
        import ast,inspect,textwrap
        tree=ast.parse(textwrap.dedent(inspect.getsource(self.module._prefetch_first_original_count_graph)))
        calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call)
            and isinstance(node.func,ast.Attribute) and node.func.attr=='_receive_first_original_count_source']
        self.assertEqual(1,len(calls),'FIRST pre-IO receiver must overlap the actual source with Count')
        self.assertEqual(["packet['writer']","packet['token']","packet['binding']",'unit'],
            [ast.unparse(argument) for argument in calls[0].args])
        assigned=[node for node in ast.walk(tree) if isinstance(node,ast.Assign)
            and any(isinstance(target,ast.Attribute) and target.attr=='prefetched' for target in node.targets)]
        self.assertLess(assigned[0].lineno,calls[0].lineno)

    @contextmanager
    def _count_source_edge_control(self):
        # Actual original FD/bytes overlap only. This does NOT issue a COUNT,
        # native K identity, semantic retirement or online execution permit.
        from monitor import issue_tracker_unit_catalog as catalog
        parent_path=Path(tempfile.mkdtemp(prefix='edge-overlap-',dir=self.root))
        (parent_path/'native.units').mkdir(mode=0o700)
        (parent_path/'native.unit-one.journal').mkdir(mode=0o700)
        (parent_path/'native.units'/'HEADER').write_bytes(b'literal catalog original\n')
        (parent_path/'native.unit-one.journal'/'WIRE').write_bytes(b'literal immutable wire\n')
        (parent_path/'native.units'/'HEADER').chmod(0o600)
        (parent_path/'native.unit-one.journal'/'WIRE').chmod(0o600)
        parent=os.open(parent_path,os.O_RDONLY|os.O_DIRECTORY)
        source=catalog._Originals()
        graphs=tuple(catalog._Originals() for _ in range(3))
        try:
            names={'native.units','native.unit-one.journal'}
            source.namespace=(parent,'native.',set(names))
            graphs[0].namespace=(parent,'native.',set(names))
            for name,leaf,index in (('native.units','HEADER',0),('native.unit-one.journal','WIRE',1)):
                received=graphs[index].directory(parent,name)
                graphs[index].file(received,leaf,1024)
                original=source.directory(parent,name)
                source.file(original,leaf,1024)
            yield source,graphs,parent_path
        finally:
            source.close()
            for graph in reversed(graphs):graph.close()
            os.close(parent)

    def test_count_source_overlap_requires_every_real_shared_edge_not_equal_content(self):
        entry=getattr(self.module,'_verify_count_source_original_overlap',None)
        self.assertTrue(callable(entry),'actual three-graph shared original overlap is missing')
        with self._count_source_edge_control() as (source,graphs,parent):
            self.assertIsNone(entry(source,graphs))
            original=graphs[1].files[0]
            graphs[1].files=[]
            try:
                with self.assertRaises(self.module.GlobalAttemptHold):entry(source,graphs)
            finally:graphs[1].files=[original]
            foreign=parent/'foreign-wire';foreign.write_bytes(b'literal immutable wire\n')
            fd=os.open(foreign,os.O_RDONLY)
            try:
                # A same-byte replacement FD is not the acquired named edge.
                graphs[1].files[0]=(*original[:2],fd,*original[3:])
                with self.assertRaises(self.module.GlobalAttemptHold):entry(source,graphs)
            finally:
                graphs[1].files[0]=original;os.close(fd)

    def test_count_source_overlap_checks_directory_and_namespace_coverage_before_transition(self):
        entry=getattr(self.module,'_verify_count_source_original_overlap',None)
        self.assertTrue(callable(entry))
        with self._count_source_edge_control() as (source,graphs,_parent):
            original=graphs[1].directories[0]
            graphs[1].directories=[]
            try:
                with self.assertRaises(self.module.GlobalAttemptHold):entry(source,graphs)
            finally:graphs[1].directories=[original]
            before=graphs[0].namespace
            graphs[0].namespace=(*before[:2],{'native.units'})
            try:
                with self.assertRaises(self.module.GlobalAttemptHold):entry(source,graphs)
            finally:graphs[0].namespace=before
            with self.assertRaises(self.module.GlobalAttemptHold):entry(source,(graphs[0],)*3)

    def test_count_source_overlap_does_not_discard_unshared_project_originals(self):
        entry=getattr(self.module,'_verify_count_source_original_overlap',None)
        self.assertTrue(callable(entry))
        with self._count_source_edge_control() as (source,graphs,parent):
            unrelated=parent/'project-originals';unrelated.mkdir(mode=0o700)
            original_file=unrelated/'EVENT';original_file.write_bytes(b'literal retained event\n')
            original_file.chmod(0o600)
            fd=os.open(unrelated,os.O_RDONLY|os.O_DIRECTORY)
            try:
                source.file(fd,'EVENT',1024)
                retained=tuple(source.files)
                self.assertIsNone(entry(source,graphs))
                self.assertEqual(retained,tuple(source.files))
                original_file.write_bytes(b'foreign event\n')
                with self.assertRaises(self.module.GlobalAttemptHold):entry(source,graphs)
            finally:os.close(fd)

    def test_count_source_overlap_cannot_hide_shared_children_by_deleting_parent_records(self):
        entry=getattr(self.module,'_verify_count_source_original_overlap',None)
        self.assertTrue(callable(entry))
        for which in ('source','both'):
            with self.subTest(which=which), self._count_source_edge_control() as (source,graphs,_parent):
                original=source.directories[1];received=graphs[1].directories[0]
                source.directories.remove(original)
                if which=='both':graphs[1].directories.remove(received)
                try:
                    with self.assertRaises(self.module.GlobalAttemptHold):entry(source,graphs)
                finally:
                    source.directories.append(original)
                    if which=='both':graphs[1].directories.append(received)

    @contextmanager
    def _first_prefix_control(self, *, suffix_drift=False, cleanup_failure=False, exit_calls=None):
        # Lifecycle/order control only. Inert owners and a body stand-in do
        # not issue native source, COUNT, read or send permission.
        from types import SimpleNamespace
        names=('_hold_first_original_source_prefix','_prepare_first_original_source_prefix',
            '_bind_first_original_source_prefix','_consume_first_original_source_prefix')
        for name in names:self.assertTrue(callable(getattr(self.module,name,None)),name)
        writer,sheet,project,owner=object(),object(),object(),object()
        bound=binding();row=SimpleNamespace(unit=self.value,project_identity=(11,22),c6_facts=b'literal C6')
        observation=SimpleNamespace(attempt_count=0)
        events=[];result=('literal receipt','literal source','literal reservations','literal business','literal audits')
        arguments=dict(qualified_source=object(),store=object(),writer_token=writer,settings=object(),
            whitelist_snapshot=object(),expected_template_sha256='a'*64,http_root=self.root,
            whitelist_path=self.root/'literal-W1',_shared_retry=False)
        packet={'writer':writer,'project':project,'token':sheet,'owner':owner,'binding':bound,
            'unit':row.unit,'context':(os.getpid(),__import__('threading').get_ident()),
            'verify':lambda:events.append('COUNT originals')}
        @contextmanager
        def body_inner(*args,**kwargs):
            self.assertEqual((sheet,bound,row.unit),args);self.assertEqual(arguments,kwargs)
            events.extend(('source prefix','receipt prefix'))
            def observe(identity):events.append('identity-dependent facts');return result
            try:
                yield observe
                events.extend(('source suffix','receipt suffix'))
                if suffix_drift:raise self.module.GlobalAttemptHold()
            finally:
                events.append('body closed')
                if cleanup_failure:raise OSError('literal secondary prefix cleanup failure')
        class BodyExitObserver:
            def __init__(self,inner):self.inner=inner
            def __enter__(self):return self.inner.__enter__()
            def __exit__(self,kind,value,traceback):
                if exit_calls is not None:exit_calls.append('normal' if kind is None else 'interrupted')
                return self.inner.__exit__(kind,value,traceback)
        def body(*args,**kwargs):return BodyExitObserver(body_inner(*args,**kwargs))
        @contextmanager
        def short_k(*args):
            self.assertEqual((writer,sheet,bound,row.unit),args)
            events.append('new short K entered')
            try:yield
            finally:events.append('new short K closed')
        with mock.patch.object(self.module.local,'_owner',return_value=project), \
                mock.patch.object(self.module.ownership,'_validated_owner',return_value=owner), \
                mock.patch.object(self.module,'_hold_receipted_original_source_inputs_body',new=body), \
                mock.patch.object(self.module,'_hold_receipted_count_source_k',new=short_k), \
                mock.patch.object(self.module,'_count_claim_original_packet',return_value=packet), \
                mock.patch.object(self.module,'inspect_global_unit',return_value=observation):
            with self.module._hold_first_original_source_prefix(writer,sheet,bound,row):
                yield writer,sheet,bound,row,observation,arguments,packet,events,result

    def test_first_prefix_precedes_reads_and_full_suffix_finishes_before_count(self):
        with self._first_prefix_control() as (writer,sheet,bound,row,observed,args,packet,events,result):
            self.module._prepare_first_original_source_prefix(row,observed,**args)
            self.assertEqual(['source prefix','receipt prefix'],events)
            events.append('nine actual read boundary')
            self.module._bind_first_original_source_prefix(row)
            value=self.module._consume_first_original_source_prefix(writer,sheet,bound,row.unit,object(),**args)
            self.assertEqual(result,value)
            relevant=[e for e in events if e!='COUNT originals']
            self.assertEqual(['source prefix','receipt prefix','nine actual read boundary',
                'new short K entered','identity-dependent facts','source suffix','receipt suffix',
                'body closed','new short K closed'],relevant)
            with self.assertRaises(self.module.GlobalAttemptHold):
                self.module._consume_first_original_source_prefix(writer,sheet,bound,row.unit,object(),**args)
        self.assertIsNone(self.module._FIRST_ORIGINAL_SOURCE_PREFIX.get())
        self.assertEqual({},self.module._LIVE_FIRST_ORIGINAL_SOURCE_PREFIXES)

    @contextmanager
    def _prefetched_first_control(self, *, acquisition_failure=False):
        # Registry/order controls only; no native source/COUNT permission.
        from monitor import issue_tracker_unit_catalog as catalog
        with self._first_prefix_control() as actual:
            writer,sheet,bound,row,_observed,_args,packet,events,_result=actual
            live=[None];count_key=object();graphs=tuple(catalog._Originals() for _ in range(3))
            record=(packet,graphs);packet['_source_graphs']=record
            @contextmanager
            def issuer(*args):
                self.assertEqual((writer,sheet,bound,row.unit),args)
                events.append('actual cold graph entry')
                if acquisition_failure:raise self.module.GlobalAttemptHold()
                reset=self.module._HELD_COUNT_CLAIM_ORIGINALS.set(count_key)
                self.module._LIVE_COUNT_SOURCE_GRAPHS[count_key]=record;live[0]=packet
                try:yield packet['verify']
                finally:
                    live[0]=None;self.module._LIVE_COUNT_SOURCE_GRAPHS.pop(count_key,None)
                    self.module._HELD_COUNT_CLAIM_ORIGINALS.reset(reset)
                    events.append('original Count issuer closed')
            with mock.patch.object(self.module,'_count_claim_original_packet',side_effect=lambda:live[0]), \
                    mock.patch.object(self.module,'_hold_selected_last_catalog_write_originals',new=issuer):
                yield actual,live,count_key,record

    def test_first_count_graph_prefetch_precedes_reads_without_count_and_closes_after_body(self):
        entry=getattr(self.module,'_prefetch_first_original_count_graph',None)
        self.assertTrue(callable(entry),'first original Count graph must be acquired before online IO')
        with self._prefetched_first_control() as (actual,live,_key,_record):
            writer,sheet,bound,row,observed,args,packet,events,result=actual
            self.module._prepare_first_original_source_prefix(row,observed,**args)
            entry()
            self.assertEqual(['source prefix','receipt prefix','actual cold graph entry'],
                [event for event in events if event!='COUNT originals'])
            self.assertIs(packet,live[0]);events.append('nine original IO completed')
            self.module._bind_first_original_source_prefix(row)
            self.assertEqual(result,self.module._consume_first_original_source_prefix(
                writer,sheet,bound,row.unit,object(),**args))
            self.assertNotIn('original Count issuer closed',events)
        self.assertLess(events.index('nine original IO completed'),events.index('new short K entered'))
        self.assertLess(events.index('body closed'),events.index('original Count issuer closed'))
        self.assertEqual(1,events.count('actual cold graph entry'))

    def test_first_prefetch_cannot_adopt_later_equal_packet_record_or_row(self):
        entry=getattr(self.module,'_prefetch_first_original_count_graph',None)
        self.assertTrue(callable(entry))
        for which in ('packet','record','row'):
            with self.subTest(which=which),self._prefetched_first_control() as (actual,live,key,record):
                writer,sheet,bound,row,observed,args,packet,events,_result=actual
                self.module._prepare_first_original_source_prefix(row,observed,**args);entry()
                try:
                    if which=='packet':live[0]=dict(packet)
                    elif which=='record':self.module._LIVE_COUNT_SOURCE_GRAPHS[key]=tuple(list(record))
                    else:packet['unit']=unit()
                    with self.assertRaises(self.module.GlobalAttemptHold):
                        self.module._bind_first_original_source_prefix(row)
                finally:
                    live[0]=packet;packet['unit']=row.unit
                    self.module._LIVE_COUNT_SOURCE_GRAPHS[key]=record
                self.assertEqual(1,events.count('actual cold graph entry'))

    def test_failed_first_count_prefetch_is_poisoned_and_cannot_reacquire_cold_graph(self):
        entry=getattr(self.module,'_prefetch_first_original_count_graph',None)
        self.assertTrue(callable(entry))
        with self.assertRaises(self.module.GlobalAttemptHold):
            with self._prefetched_first_control(acquisition_failure=True) as (actual,_live,_key,_record):
                writer,sheet,bound,row,observed,args,_packet,events,_result=actual
                self.module._prepare_first_original_source_prefix(row,observed,**args)
                with self.assertRaises(self.module.GlobalAttemptHold):entry()
                with self.assertRaises(self.module.GlobalAttemptHold):entry()
                self.assertEqual(1,events.count('actual cold graph entry'))
                with mock.patch.object(self.module,'_hold_receipted_original_source_inputs',
                        side_effect=AssertionError('failed prefetch cold fallback')):
                    with self.assertRaises(self.module.GlobalAttemptHold):
                        self.module._receipted_original_facts(sheet,bound,object(),row.unit,**args)

    def test_prefetched_first_count_tail_preserves_operator_interrupt_and_releases_registry(self):
        entry=getattr(self.module,'_prefetch_first_original_count_graph',None)
        self.assertTrue(callable(entry));primary=KeyboardInterrupt('literal prefetched Count interruption')
        with self.assertRaises(KeyboardInterrupt) as caught:
            with self._prefetched_first_control() as (actual,_live,_key,_record):
                _writer,_sheet,_bound,row,observed,args,_packet,events,_result=actual
                self.module._prepare_first_original_source_prefix(row,observed,**args);entry()
                raise primary
        self.assertIs(primary,caught.exception)
        self.assertEqual(1,events.count('original Count issuer closed'))
        self.assertEqual({},self.module._LIVE_COUNT_SOURCE_GRAPHS)
        self.assertIsNone(self.module._HELD_COUNT_CLAIM_ORIGINALS.get())

    def test_first_prefetch_cannot_use_substituted_cleanup_scope(self):
        entry=getattr(self.module,'_prefetch_first_original_count_graph',None)
        self.assertTrue(callable(entry))
        with self._prefetched_first_control() as (actual,_live,_key,_record):
            _writer,_sheet,_bound,row,observed,args,_packet,events,_result=actual
            self.module._prepare_first_original_source_prefix(row,observed,**args)
            anchor=self.module._FIRST_ORIGINAL_SOURCE_PREFIX.get()
            original=anchor.prefetch_scope
            with ExitStack() as foreign:
                anchor.prefetch_scope=foreign
                try:
                    with self.assertRaises(self.module.GlobalAttemptHold):entry()
                finally:anchor.prefetch_scope=original
            self.assertNotIn('actual cold graph entry',events)

    def test_first_prefix_same_value_row_or_unit_and_revoked_context_cannot_bind(self):
        from types import SimpleNamespace
        with self._first_prefix_control() as (writer,sheet,bound,row,observed,args,packet,events,result):
            self.module._prepare_first_original_source_prefix(row,observed,**args)
            copied_row=SimpleNamespace(**vars(row))
            with self.assertRaises(self.module.GlobalAttemptHold):
                self.module._bind_first_original_source_prefix(copied_row)
            original=packet['unit'];packet['unit']=unit()
            self.assertEqual(original,packet['unit']);self.assertIsNot(original,packet['unit'])
            with self.assertRaises(self.module.GlobalAttemptHold):self.module._bind_first_original_source_prefix(row)
            packet['unit']=original
            key=self.module._FIRST_ORIGINAL_SOURCE_PREFIX.get()
            saved=self.module._LIVE_FIRST_ORIGINAL_SOURCE_PREFIXES.pop(key)
            try:
                with self.assertRaises(self.module.GlobalAttemptHold):self.module._bind_first_original_source_prefix(row)
            finally:self.module._LIVE_FIRST_ORIGINAL_SOURCE_PREFIXES[key]=saved
        self.assertEqual(['source prefix','receipt prefix','body closed'],events)

    def test_first_prefix_suffix_drift_is_not_cached_success_and_is_permanently_consumed(self):
        with self._first_prefix_control(suffix_drift=True) as (writer,sheet,bound,row,observed,args,packet,events,result):
            self.module._prepare_first_original_source_prefix(row,observed,**args)
            self.module._bind_first_original_source_prefix(row)
            with self.assertRaises(self.module.GlobalAttemptHold):
                self.module._consume_first_original_source_prefix(writer,sheet,bound,row.unit,object(),**args)
            with self.assertRaises(self.module.GlobalAttemptHold):
                self.module._consume_first_original_source_prefix(writer,sheet,bound,row.unit,object(),**args)
            self.assertEqual(1,events.count('source prefix'))
            self.assertEqual(1,events.count('source suffix'))
            self.assertEqual(1,events.count('body closed'))
            self.assertEqual(1,events.count('new short K closed'))

    def test_first_prefix_interruption_survives_cleanup_failure_and_revoke_happens_first(self):
        primary=KeyboardInterrupt('literal operator interruption')
        with self.assertRaises(KeyboardInterrupt) as caught:
            with self._first_prefix_control(cleanup_failure=True) as (writer,sheet,bound,row,observed,args,packet,events,result):
                self.module._prepare_first_original_source_prefix(row,observed,**args)
                raise primary
        self.assertIs(primary,caught.exception)
        self.assertIsNone(self.module._FIRST_ORIGINAL_SOURCE_PREFIX.get())
        self.assertEqual({},self.module._LIVE_FIRST_ORIGINAL_SOURCE_PREFIXES)
        self.assertEqual(['source prefix','receipt prefix','body closed'],events)

    def test_failed_first_prefix_cannot_fall_back_to_cold_facts(self):
        with self._first_prefix_control(suffix_drift=True) as (writer,sheet,bound,row,observed,args,packet,events,result):
            self.module._prepare_first_original_source_prefix(row,observed,**args)
            self.module._bind_first_original_source_prefix(row)
            with self.assertRaises(self.module.GlobalAttemptHold):
                self.module._consume_first_original_source_prefix(writer,sheet,bound,row.unit,object(),**args)
            with mock.patch.object(self.module,'_hold_receipted_original_source_inputs',
                    side_effect=AssertionError('failed declared FIRST fell back to cold source')):
                with self.assertRaises(self.module.GlobalAttemptHold):
                    self.module._receipted_original_facts(sheet,bound,object(),row.unit,**args)

    def test_bound_first_prefix_rejects_same_value_registry_or_row_replacement(self):
        from types import SimpleNamespace
        for which in ('row','registry'):
            with self.subTest(which=which), self._first_prefix_control() as (writer,sheet,bound,row,observed,args,count,events,result):
                self.module._prepare_first_original_source_prefix(row,observed,**args)
                self.module._bind_first_original_source_prefix(row)
                key=self.module._FIRST_ORIGINAL_SOURCE_PREFIX.get()
                original=self.module._LIVE_FIRST_ORIGINAL_SOURCE_PREFIXES[key]
                try:
                    if which=='row':original['row']=SimpleNamespace(**vars(row))
                    else:self.module._LIVE_FIRST_ORIGINAL_SOURCE_PREFIXES[key]=dict(original)
                    with self.assertRaises(self.module.GlobalAttemptHold):
                        self.module._consume_first_original_source_prefix(writer,sheet,bound,row.unit,object(),**args)
                finally:
                    original['row']=row
                    self.module._LIVE_FIRST_ORIGINAL_SOURCE_PREFIXES[key]=original

    def test_failed_original_body_normal_exit_is_attempted_only_once(self):
        exits=[]
        with self._first_prefix_control(suffix_drift=True,exit_calls=exits) as (writer,sheet,bound,row,observed,args,packet,events,result):
            self.module._prepare_first_original_source_prefix(row,observed,**args)
            self.module._bind_first_original_source_prefix(row)
            with self.assertRaises(self.module.GlobalAttemptHold):
                self.module._consume_first_original_source_prefix(writer,sheet,bound,row.unit,object(),**args)
            self.assertEqual(['normal'],exits,'a failed original suffix is not a second cleanup domain')
        self.assertEqual(['normal'],exits)

    def test_deleted_bound_first_row_cannot_fall_back_to_cold_facts(self):
        with self._first_prefix_control() as (writer,sheet,bound,row,observed,args,count,events,result):
            self.module._prepare_first_original_source_prefix(row,observed,**args)
            self.module._bind_first_original_source_prefix(row)
            packet=self.module._first_original_source_prefix_packet()
            del packet['row']
            try:
                with mock.patch.object(self.module,'_hold_receipted_original_source_inputs',
                        side_effect=AssertionError('deleted declared FIRST fell back to cold source')):
                    with self.assertRaises(self.module.GlobalAttemptHold):
                        self.module._receipted_original_facts(sheet,bound,object(),row.unit,**args)
            finally:packet['row']=row

    def test_successful_first_prefix_does_not_replace_later_full_facts(self):
        with self._first_prefix_control() as (writer,sheet,bound,row,observed,args,count,events,result):
            self.module._prepare_first_original_source_prefix(row,observed,**args)
            self.module._bind_first_original_source_prefix(row)
            self.assertEqual(result,self.module._receipted_original_facts(sheet,bound,object(),row.unit,**args))
            later=('independent later source',);reads=[]
            @contextmanager
            def fresh(*a,**kw):
                reads.append('fresh full prefix')
                yield lambda identity:later
                reads.append('fresh full suffix')
            with mock.patch.object(self.module,'_hold_receipted_original_source_inputs',new=fresh):
                self.assertEqual(later,self.module._receipted_original_facts(sheet,bound,object(),row.unit,**args))
            self.assertEqual(['fresh full prefix','fresh full suffix'],reads)

    def test_first_count_original_join_fields_are_rechecked_after_real_delegate(self):
        for which in ('unit','verify','context'):
            with self.subTest(which=which), self._first_prefix_control() as (writer,sheet,bound,row,observed,args,count,events,result):
                self.module._prepare_first_original_source_prefix(row,observed,**args)
                original_unit=count['unit'];original_verify=count['verify'];original_context=count['context']
                def changed_delegate():
                    original_verify()
                    count[which]=(unit() if which=='unit' else
                        ((0,0) if which=='context' else lambda:events.append('foreign callback')))
                count['verify']=changed_delegate
                try:
                    with self.assertRaises(self.module.GlobalAttemptHold):
                        self.module._bind_first_original_source_prefix(row)
                    self.assertNotIn('identity-dependent facts',events)
                    self.assertNotIn('foreign callback',events)
                finally:
                    count['unit']=original_unit;count['verify']=original_verify;count['context']=original_context

    def test_count_project_c6_without_live_join_keeps_cold_path(self):
        entry = getattr(self.module, '_hold_count_claim_project_c6', None)
        self.assertTrue(callable(entry), 'source K needs an original-only C6 borrow, not a row cache')
        with entry(object(), object(), binding(), (self.value,)) as borrowed:
            self.assertIsNone(borrowed)

    def _count_c6_control(self):
        # Registry/lifetime control only; this does not issue actual C6 proof.
        from monitor import issue_tracker_unit_catalog as catalog
        writer, sheet, key = object(), object(), object()
        bound = binding(); events = []
        packet = {'writer': writer, 'token': sheet, 'binding': bound,
                  'unit': self.value, 'verify': lambda: events.append('COUNT originals')}
        rows = (catalog.CatalogProjectC6(self.value, (101, 202), b'control-only'),)
        record = (packet, (self.value,), rows, lambda: events.append('C6 originals'))
        return writer, sheet, key, bound, events, packet, rows, record

    def test_count_project_c6_borrows_exact_registered_originals_and_revokes_escaped_verifier(self):
        entry = getattr(self.module, '_hold_count_claim_project_c6', None)
        self.assertTrue(callable(entry), 'only an actual live COUNT issuer may lend its C6 graph')
        writer, sheet, key, bound, events, packet, rows, record = self._count_c6_control()
        with mock.patch.object(self.module, '_count_claim_original_packet', return_value=packet), \
                mock.patch.dict(self.module._LIVE_COUNT_PROJECT_C6, {key: record}):
            reset = self.module._HELD_COUNT_CLAIM_ORIGINALS.set(key)
            try:
                with entry(writer, sheet, bound, (self.value,)) as borrowed:
                    actual_rows, verify = borrowed
                    self.assertIs(rows, actual_rows)
                    verify()
                    self.assertGreaterEqual(events.count('COUNT originals'), 1,
                                            'the genuine COUNT entry boundary already ran')
                    self.assertGreaterEqual(events.count('C6 originals'), 2)
                # Check both lexical COUNT boundaries after the scope exits;
                # its final boundary has not run inside the with-body.
                self.assertGreaterEqual(events.count('COUNT originals'), 2)
                with self.assertRaises(self.module.GlobalAttemptHold):
                    verify()
            finally:
                self.module._HELD_COUNT_CLAIM_ORIGINALS.reset(reset)

    def test_count_project_c6_same_value_record_replacement_is_not_an_original_loan(self):
        entry = getattr(self.module, '_hold_count_claim_project_c6', None)
        self.assertTrue(callable(entry))
        writer, sheet, key, bound, _events, packet, _rows, record = self._count_c6_control()
        with mock.patch.object(self.module, '_count_claim_original_packet', return_value=packet), \
                mock.patch.dict(self.module._LIVE_COUNT_PROJECT_C6, {key: record}):
            reset = self.module._HELD_COUNT_CLAIM_ORIGINALS.set(key)
            try:
                with self.assertRaises(self.module.GlobalAttemptHold):
                    with entry(writer, sheet, bound, (self.value,)) as (_rows, verify):
                        self.module._LIVE_COUNT_PROJECT_C6[key] = tuple(list(record))
                        verify()
            finally:
                self.module._HELD_COUNT_CLAIM_ORIGINALS.reset(reset)

    def test_count_project_c6_revoked_join_preserves_body_interruption(self):
        entry = getattr(self.module, '_hold_count_claim_project_c6', None)
        self.assertTrue(callable(entry))
        class Interrupted(BaseException): pass
        primary = Interrupted()
        writer, sheet, key, bound, _events, packet, _rows, record = self._count_c6_control()
        current = [packet]
        with mock.patch.object(self.module, '_count_claim_original_packet', side_effect=lambda: current[0]), \
                mock.patch.dict(self.module._LIVE_COUNT_PROJECT_C6, {key: record}):
            reset = self.module._HELD_COUNT_CLAIM_ORIGINALS.set(key)
            try:
                with self.assertRaises(Interrupted) as caught:
                    with entry(writer, sheet, bound, (self.value,)):
                        current[0] = None
                        raise primary
                self.assertIs(primary, caught.exception)
                self.assertIsInstance(primary.__cause__, self.module.GlobalAttemptHold)
            finally:
                self.module._HELD_COUNT_CLAIM_ORIGINALS.reset(reset)

    def test_count_project_c6_tail_operator_interruption_dominates_ordinary_body_error(self):
        writer, sheet, key, bound, _events, packet, _rows, record = self._count_c6_control()
        ordinary = ValueError('independent original body failure')
        interrupted = KeyboardInterrupt(); body_finished = []
        def verify_c6():
            if body_finished: raise interrupted
        record = (*record[:3], verify_c6)
        with mock.patch.object(self.module, '_count_claim_original_packet', return_value=packet), \
                mock.patch.dict(self.module._LIVE_COUNT_PROJECT_C6, {key: record}):
            reset = self.module._HELD_COUNT_CLAIM_ORIGINALS.set(key)
            try:
                with self.assertRaises(KeyboardInterrupt) as caught:
                    with self.module._hold_count_claim_project_c6(writer, sheet, bound, (self.value,)):
                        body_finished.append(True)
                        raise ordinary
                self.assertIs(interrupted, caught.exception)
                self.assertIs(ordinary, interrupted.__cause__)
            finally:
                self.module._HELD_COUNT_CLAIM_ORIGINALS.reset(reset)

    def test_count_project_c6_fresh_rechecks_do_not_rebuild_unrelated_count_graph_checks(self):
        # C6-only rechecks retain original C6 checks each time. The independent
        # COUNT graph is already held and checked at the lexical boundaries.
        writer, sheet, key, bound, events, packet, _rows, record = self._count_c6_control()
        with mock.patch.object(self.module, '_count_claim_original_packet', return_value=packet), \
                mock.patch.dict(self.module._LIVE_COUNT_PROJECT_C6, {key: record}):
            reset = self.module._HELD_COUNT_CLAIM_ORIGINALS.set(key)
            try:
                with self.module._hold_count_claim_project_c6(writer, sheet, bound, (self.value,)) as (_rows, verify):
                    for _ in range(8): verify()
                self.assertEqual(2, events.count('COUNT originals'))
                self.assertGreaterEqual(events.count('C6 originals'), 10)
            finally:
                self.module._HELD_COUNT_CLAIM_ORIGINALS.reset(reset)

    def test_count_source_k_without_original_join_keeps_ordinary_reader(self):
        from monitor import issue_tracker_settings_audit_allocation as allocation
        entry=getattr(self.module,'_hold_receipted_count_source_k',None)
        self.assertTrue(callable(entry),'COUNT source reads need a fixed original-only K read domain')
        with mock.patch.object(self.module,'_count_claim_original_packet',return_value=None), \
                mock.patch.object(allocation,'_hold_owned_native_completed_source_k') as issued:
            with entry(object(),object(),binding(),self.value):pass
        issued.assert_not_called()

    def test_count_source_k_mismatched_original_join_refuses_before_issuer(self):
        from monitor import issue_tracker_settings_audit_allocation as allocation
        entry=getattr(self.module,'_hold_receipted_count_source_k',None)
        self.assertTrue(callable(entry),'foreign COUNT graph cannot issue archived-settings K')
        writer=object();sheet=object();bound=binding()
        original={'writer':writer,'token':sheet,'binding':bound,'unit':self.value,'verify':mock.Mock()}
        for field in ('writer','token','binding','unit'):
            changed={**original,field:object()}
            with self.subTest(field=field), \
                    mock.patch.object(self.module,'_count_claim_original_packet',return_value=changed), \
                    mock.patch.object(allocation,'_hold_owned_native_completed_source_k') as issued:
                with self.assertRaises(self.module.GlobalAttemptHold):
                    with entry(writer,sheet,bound,self.value):self.fail('foreign original joined')
                issued.assert_not_called()

    def test_count_source_k_original_join_dominates_read_scope_and_checks_after_revoke(self):
        # Ordering/identity control only. Actual archived FIRST is the real
        # ALL/COUNT/source workflow; this fake issuer grants no production proof.
        from types import SimpleNamespace
        from monitor import issue_tracker_settings_audit_allocation as allocation
        entry=getattr(self.module,'_hold_receipted_count_source_k',None)
        self.assertTrue(callable(entry),'original COUNT/source graph must dominate K read cleanup')
        writer=object();sheet=object();bound=binding();events=[]
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        (self.root/allocation._DELIVERY_STARTED).write_bytes(b'control-only')
        packet={'writer':writer,'token':sheet,'binding':bound,'unit':self.value,
                'project':SimpleNamespace(root_fd=fd),'verify':lambda:events.append('original verify')}
        @contextmanager
        def read_k(*args):
            self.assertEqual((writer,sheet,bound),args)
            events.append('original K enter')
            try:yield
            finally:events.append('original K revoked')
        try:
            with mock.patch.object(self.module,'_count_claim_original_packet',return_value=packet), \
                    mock.patch.object(allocation,'_hold_owned_native_completed_source_k',side_effect=read_k):
                with entry(writer,sheet,bound,self.value):events.append('source and receipt domain')
            self.assertLess(events.index('original verify'),events.index('original K enter'))
            self.assertLess(events.index('original K enter'),events.index('source and receipt domain'))
            self.assertLess(events.index('source and receipt domain'),events.index('original K revoked'))
            self.assertEqual('original verify',events[-1])
        finally:os.close(fd)

    def test_count_source_k_preserves_original_interruption_when_tail_join_is_revoked(self):
        from types import SimpleNamespace
        entry=getattr(self.module,'_hold_receipted_count_source_k',None)
        self.assertTrue(callable(entry))
        class OriginalInterruption(BaseException):pass
        primary=OriginalInterruption();writer=object();sheet=object();bound=binding()
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        packet={'writer':writer,'token':sheet,'binding':bound,'unit':self.value,
                'project':SimpleNamespace(root_fd=fd),'verify':lambda:None}
        current=[packet]
        try:
            with mock.patch.object(self.module,'_count_claim_original_packet',side_effect=lambda:current[0]):
                with self.assertRaises(OriginalInterruption) as caught:
                    with entry(writer,sheet,bound,self.value):
                        current[0]=None
                        raise primary
            self.assertIs(primary,caught.exception)
            self.assertIsInstance(primary.__cause__,self.module.GlobalAttemptHold)
        finally:os.close(fd)

    def test_count_source_k_preserves_body_interruption_before_actual_reader_cleanup(self):
        from types import SimpleNamespace
        from monitor import issue_tracker_settings_audit_allocation as allocation
        class OriginalInterruption(BaseException):pass
        primary=OriginalInterruption();cleanup=allocation.SettingsAuditHold()
        writer=object();sheet=object();bound=binding();fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        (self.root/allocation._DELIVERY_STARTED).write_bytes(b'control-only')
        packet={'writer':writer,'token':sheet,'binding':bound,'unit':self.value,
                'project':SimpleNamespace(root_fd=fd),'verify':lambda:None}
        @contextmanager
        def failing_reader(*args):
            try:yield
            finally:raise cleanup
        try:
            with mock.patch.object(self.module,'_count_claim_original_packet',return_value=packet), \
                    mock.patch.object(allocation,'_hold_owned_native_completed_source_k',side_effect=failing_reader):
                with self.assertRaises(OriginalInterruption) as caught:
                    with self.module._hold_receipted_count_source_k(writer,sheet,bound,self.value):raise primary
            self.assertIs(primary,caught.exception);self.assertIs(cleanup,primary.__cause__)
        finally:os.close(fd)

    def test_count_source_k_cleanup_interrupt_dominates_ordinary_body_and_final_hold(self):
        # Exception ordering only; this control never issues native K or GO.
        from types import SimpleNamespace
        from monitor import issue_tracker_settings_audit_allocation as allocation
        body=ValueError('literal ordinary source body')
        interrupted=KeyboardInterrupt('literal original reader cleanup')
        last=self.module.GlobalAttemptHold()
        revoked=[];final_checks=[]
        writer=object();sheet=object();bound=binding()
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        (self.root/allocation._DELIVERY_STARTED).write_bytes(b'control-only')
        def verify():
            if revoked:
                final_checks.append(True)
                raise last
        packet={'writer':writer,'token':sheet,'binding':bound,'unit':self.value,
                'project':SimpleNamespace(root_fd=fd),'verify':verify}
        @contextmanager
        def reader(*args):
            try:yield
            finally:
                revoked.append(True)
                raise interrupted
        try:
            with mock.patch.object(self.module,'_count_claim_original_packet',return_value=packet), \
                    mock.patch.object(allocation,'_hold_owned_native_completed_source_k',side_effect=reader):
                with self.assertRaises(KeyboardInterrupt) as caught:
                    with self.module._hold_receipted_count_source_k(writer,sheet,bound,self.value):
                        raise body
            self.assertIs(interrupted,caught.exception)
            self.assertIs(last,interrupted.__cause__)
            self.assertEqual([True],revoked);self.assertEqual([True],final_checks)
        finally:os.close(fd)

    def test_count_source_k_last_verifier_cannot_replace_same_value_unit_after_reader_cleanup(self):
        from types import SimpleNamespace
        from monitor import issue_tracker_settings_audit_allocation as allocation
        writer=object();sheet=object();bound=binding();fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        (self.root/allocation._DELIVERY_STARTED).write_bytes(b'control-only')
        revoked=[]
        packet={'writer':writer,'token':sheet,'binding':bound,'unit':self.value,
                'project':SimpleNamespace(root_fd=fd)}
        def verify():
            if revoked:packet['unit']=replace(self.value)
        packet['verify']=verify
        @contextmanager
        def reader(*args):
            try:yield
            finally:revoked.append(True)
        try:
            with mock.patch.object(self.module,'_count_claim_original_packet',return_value=packet), \
                    mock.patch.object(allocation,'_hold_owned_native_completed_source_k',side_effect=reader):
                with self.assertRaises(self.module.GlobalAttemptHold):
                    with self.module._hold_receipted_count_source_k(writer,sheet,bound,self.value):pass
            self.assertEqual(self.value,packet['unit']);self.assertIsNot(self.value,packet['unit'])
        finally:os.close(fd)

    def _receipted_local_prefix_probe(self, *, source_drift=False):
        # Fixed-order/lifetime oracle only, not an actual qualification issuer.
        from types import SimpleNamespace
        from monitor import issue_tracker_stage_l_consumer as source
        from monitor import issue_tracker_cycle_source as cycles
        from monitor import issue_tracker_send_unit as send
        from monitor import issue_tracker_history_preread_journal as preread
        from monitor import issue_tracker_local_workbook_commit as workbook
        from monitor import issue_tracker_online_target as target
        entry=getattr(self.module,'_hold_receipted_original_source_inputs',None)
        self.assertTrue(callable(entry),'actual local source prefix must precede FIRST reads in one bounded scope')
        qualified=SimpleNamespace(cycle_ids=('original-cycle',));events=[]
        receipt=('a'*64,'b'*64,hashlib.sha256(inputs()['manifest']).hexdigest())
        business=object();reserved=('literal-reservation',);identity=object()
        def replay(*args,**options):
            events.append('source')
            return object() if source_drift and events.count('source')==2 else qualified
        def original_receipt(*args,**options):events.append('receipt');return receipt
        def reservations(*args):events.append('reservations');return reserved
        def original_business(*args):events.append('business');return business
        arguments=dict(qualified_source=qualified,store=object(),writer_token=object(),settings=object(),
            whitelist_snapshot=object(),expected_template_sha256='f'*64,http_root=self.root,whitelist_path=self.root/'W1')
        with ExitStack() as patches:
            patches.enter_context(mock.patch.object(self.module,'_inputs'))
            patches.enter_context(mock.patch.object(target,'inspect_project_online_target'))
            patches.enter_context(mock.patch.object(cycles,'read_completed_cycle_evidence',
                return_value=(SimpleNamespace(cycle_id='original-cycle'),)))
            patches.enter_context(mock.patch.object(source,'qualify_prod_stage_l',side_effect=replay))
            patches.enter_context(mock.patch.object(send,'_original_receipt_identity',side_effect=original_receipt))
            patches.enter_context(mock.patch.object(self.module,'_reserved_images',side_effect=reservations))
            patches.enter_context(mock.patch.object(preread,'inspect_business_preread',side_effect=original_business))
            patches.enter_context(mock.patch.object(workbook,'_source_rows',return_value=(('literal-cabling',),('literal-switch',))))
            patches.enter_context(mock.patch.object(preread,'inspect_business_source_projection',return_value=business))
            patches.enter_context(mock.patch.object(self.module.ownership,'_validated_owner'))
            with entry(object(),binding(),self.value,**arguments) as observe:
                self.assertEqual(['source','receipt'],events)
                events.append('actual-online-read-boundary')
                result=observe(identity)
                self.assertEqual((receipt,qualified,reserved,business,b''),result)
                self.assertEqual(['source','receipt','actual-online-read-boundary','reservations','business'],events)
                with self.assertRaises(self.module.GlobalAttemptHold):observe(identity)
            self.assertEqual(['source','receipt','actual-online-read-boundary','reservations','business','source','receipt'],events)
            with self.assertRaises(self.module.GlobalAttemptHold):observe(identity)

    def test_receipted_source_prefix_precedes_reads_and_keeps_both_original_checks(self):
        self._receipted_local_prefix_probe()

    def test_receipted_source_prefix_never_accepts_postread_source_drift(self):
        with self.assertRaises(self.module.GlobalAttemptHold):
            self._receipted_local_prefix_probe(source_drift=True)

    def _exercise_global_creator_first_stat(self, *, recycle=False):
        original_open=os.open;original_stat=os.fstat;opened=[];hit=[]
        error=OSError('injected first creator fstat')
        folder=original_open(self.root,self.module.local._flags(directory=True))
        foreign_path=self.root/'foreign-creator-slot';foreign_path.write_bytes(b'foreign-original')
        foreign=original_open(foreign_path,self.module.local._flags())
        def open_file(name,*args,**options):
            fd=original_open(name,*args,**options)
            if name=='STOP':opened.append(fd)
            return fd
        def first_stat(fd):
            if opened and fd==opened[0] and not hit:
                hit.append(True)
                if recycle:os.dup2(foreign,fd)
                raise error
            return original_stat(fd)
        caught=[]
        try:
            with mock.patch.object(os,'open',side_effect=open_file),mock.patch.object(os,'fstat',side_effect=first_stat):
                try:
                    with self.module._write_global_start(folder,'STOP',b'partial-stop'):pass
                except OSError as failure:caught.append(failure)
            self.assertEqual([error],caught);self.assertEqual([True],hit);self.assertEqual(1,len(opened))
            self.assertEqual(b'',(self.root/'STOP').read_bytes())
            if recycle:
                self.assertEqual((original_stat(foreign).st_dev,original_stat(foreign).st_ino),
                    (original_stat(opened[0]).st_dev,original_stat(opened[0]).st_ino))
                self.assertEqual(b'foreign-original',os.pread(opened[0],100,0))
            else:
                with self.assertRaises(OSError):original_stat(opened[0])
        finally:
            for fd in (*opened,foreign,folder):
                try:os.close(fd)
                except OSError:pass

    def test_actual_global_creator_first_fstat_failure_closes_only_owned_original(self):
        self._exercise_global_creator_first_stat()

    def test_actual_global_creator_first_fstat_recycled_slot_keeps_foreign_original(self):
        self._exercise_global_creator_first_stat(recycle=True)

    def test_native_count_claim_overlap_requires_actual_both_owners_before_catalog(self):
        holder=getattr(self.module,'_hold_selected_last_catalog_write_originals',None)
        self.assertTrue(callable(holder),'COUNT and CLAIM must share original ALL family FDs')
        from monitor import issue_tracker_unit_catalog as catalog
        with mock.patch.object(catalog,'_inspect') as read:
            entered=[]
            with self.assertRaises(self.module.GlobalAttemptHold):
                with holder(object(),object(),binding(),self.value):entered.append(True)
            self.assertEqual([],entered);read.assert_not_called()

    def test_native_count_claim_overlap_accepts_no_caller_graph_or_allowance(self):
        holder=getattr(self.module,'_hold_selected_last_catalog_write_originals',None)
        self.assertTrue(callable(holder),'original graph cannot be supplied by the caller')
        for extra in ({'verify':lambda:None},{'paths':()},{'count':0},{'allowance':True},{'budget':object()}):
            with self.subTest(extra=tuple(extra)),self.assertRaises(TypeError):
                with holder(object(),object(),binding(),self.value,**extra):pass

    def test_all_protected_count_boundaries_join_the_shared_original_counter(self):
        import ast, inspect, textwrap
        # One semantic counter must inspect actual catalog settlement for all
        # protected sources; bypassing it reinstates the old blanket HOLD.
        names = ('record_reserved_attempt_intent',
            'record_original_business_reserved_attempt_intent',
            'record_receipted_original_attempt_intent',
            '_hold_shared_retry_counted_sources', '_hold_continuous_owned_attempt_wire')
        for name in names:
            with self.subTest(boundary=name):
                tree = ast.parse(textwrap.dedent(inspect.getsource(getattr(self.module,name))))
                calls = [node.func.id for node in ast.walk(tree)
                    if isinstance(node,ast.Call) and isinstance(node.func,ast.Name)]
                self.assertEqual(1,calls.count('record_global_attempt_intent'),
                    'protected boundary must retain its gates and join the canonical actual catalog counter')
                self.assertEqual(0,calls.count('_observe'),'legacy local append bypasses actual OTHER settlement')

    def test_settled_claim_inputs_require_actual_writer_before_catalog_reads(self):
        holder = getattr(self.module, '_hold_settled_catalog_claim_inputs', None)
        self.assertTrue(callable(holder), 'fixed original settlement must dominate actual CLAIM consumers')
        from monitor import issue_tracker_unit_catalog as catalog
        with mock.patch.object(catalog, '_inspect') as read:
            yielded = []
            with self.assertRaises(self.module.GlobalAttemptHold):
                with holder(object(),object(),object(),object()):
                    yielded.append(True)
            self.assertEqual([],yielded,'unissued writer reached shared evidence')
            read.assert_not_called()

    def test_settled_claim_inputs_have_no_caller_settlement_mode_paths_or_callbacks(self):
        holder = getattr(self.module, '_hold_settled_catalog_claim_inputs', None)
        self.assertTrue(callable(holder), 'caller settlement labels cannot release UNKNOWN')
        for extra in ({'applied':True},{'path':'foreign'},{'verify':lambda:None},{'units':()},{'mode':'settled'}):
            with self.subTest(extra=tuple(extra)),self.assertRaises(TypeError):
                with holder(object(),object(),object(),object(),**extra):
                    self.fail('caller override reached claim inputs')

    def test_settled_successor_counter_requires_real_owner_before_catalog_reads(self):
        module = self.module
        counter = getattr(module, '_record_settled_successor_attempt', None)
        self.assertTrue(callable(counter), 'fixed counter must hold actual originals through its one append')
        from monitor import issue_tracker_unit_catalog as catalog
        with mock.patch.object(catalog, '_inspect') as read:
            with self.assertRaises(module.GlobalAttemptHold):
                counter(object(),object(),object())
            read.assert_not_called()

    def test_settled_successor_counter_accepts_no_caller_settlement_paths_or_override(self):
        counter = getattr(self.module, '_record_settled_successor_attempt', None)
        self.assertTrue(callable(counter), 'no caller verifier or settlement label is an original proof')
        for extra in ({'applied':True},{'path':'foreign'},{'verify':lambda:None},{'attempt_count':1}):
            with self.subTest(extra=tuple(extra)),self.assertRaises(TypeError):
                counter(object(),object(),object(),**extra)

    def test_successor_preparation_rejects_unissued_owner_before_catalog_read(self):
        with mock.patch.object(self.module, '_catalog_present') as catalog:
            with self.assertRaises(self.module.GlobalAttemptHold):
                self.module.prepare_global_unit(object(), binding(), self.value)
            catalog.assert_not_called()
        self.assertFalse(self.store.exists())

    def test_public_successor_preparation_accepts_no_settlement_override(self):
        for override in ({'applied': True}, {'keys': ()}, {'verify': lambda: None},
                         {'_verify_settlement': lambda: None}):
            with self.subTest(override=tuple(override)), self.assertRaises(TypeError):
                self.module.prepare_global_unit(object(), binding(), self.value, **override)
        self.assertFalse(self.store.exists())

    def test_retry_guard_fixture_does_not_capture_mock_workbook_reader_in_cold_receipt_import(self):
        program = '''import unittest
from monitor import issue_tracker_local_workbook_commit as workbook
original = workbook._latest_receipted_prod_xlsx
from test_cases.test_req7_global_attempt_journal import Req7GlobalAttemptJournalTests
case = Req7GlobalAttemptJournalTests('test_shared_retry_pins_worker_and_policy_inputs_before_any_facts_or_opportunity')
result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite((case,)))
if not result.wasSuccessful(): raise AssertionError('the original guard assertion failed')
from monitor import issue_tracker_receipt_snapshot as receipt
if receipt._latest_receipted_prod_xlsx is not original:
    raise AssertionError('guard fixture captured temporary mock as canonical receipt reader')
'''
        result = subprocess.run([sys.executable,'-B','-c',program],cwd=ROOT,
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
        self.assertEqual(0,result.returncode,result.stdout+result.stderr)

    def test_shared_retry_wire_refuses_first_or_exhausted_count_before_source_or_opportunity(self):
        from monitor import issue_tracker_stage_l_consumer as consumer
        from monitor import issue_tracker_admission as admission
        holding = getattr(self.module, '_hold_shared_retry_owned_attempt_wire', None)
        self.assertTrue(callable(holding), 'shared admitted retry must hold actual originals through fixed launch')
        for count in (0, 6):
            with self.subTest(count=count), Req7GlobalAttemptJournalWorkflowTests.counted_wire_owners(self,count=count) as (writer,owner,target):
                original = {p.name:p.read_bytes() for p in self.store.iterdir()}
                with mock.patch.object(consumer,'_hold_original_replay_inputs') as sources, \
                        mock.patch.object(admission,'_hold_shared_retry_opportunity') as opportunity:
                    with self.assertRaises(self.module.GlobalAttemptHold):
                        with holding(owner,target,self.value,writer_token=writer,
                                identity_response=None,history_response=None,business_reads=(),qualified_source=None,
                                store=None,settings=None,whitelist_snapshot=None,expected_template_sha256='a'*64,
                                http_root=self.root,whitelist_path=self.root/'not-used',headers_response=None,
                                whitelist_response=None,metadata_response=None,boot_id='owned-boot',monotonic_ns=1):
                            self.fail('fresh/exhausted unit yielded a retry wire')
                    sources.assert_not_called(); opportunity.assert_not_called()
                self.assertEqual(original,{p.name:p.read_bytes() for p in self.store.iterdir()})
                self.assertEqual(count,self.module.inspect_global_unit(owner,target,self.value).attempt_count)

    def test_continuous_first_count_wire_scope_refuses_a_preexisting_unknown_attempt(self):
        self.assertTrue(hasattr(self.module,'_hold_continuous_owned_attempt_wire'),
            'fresh original C6 scopes must remain held through fixed launch; bare count is not this handoff')
        with Req7GlobalAttemptJournalWorkflowTests.counted_wire_owners(self) as (writer,owner,target):
            saved={p.name:p.read_bytes() for p in self.store.iterdir()}; issued=[]
            with self.assertRaises(self.module.GlobalAttemptHold):
                with self.module._hold_continuous_owned_attempt_wire(owner,target,self.value,
                    writer_token=writer,identity_response=None,history_response=None,business_reads=(),
                    qualified_source=None,store=None,settings=None,whitelist_snapshot=None,
                    expected_template_sha256='a'*64,http_root=self.root,whitelist_path=self.root/'not-used',
                    headers_response=None,whitelist_response=None,metadata_response=None) as image:
                    issued.append(image)
            self.assertEqual([],issued)
            self.assertEqual(saved,{p.name:p.read_bytes() for p in self.store.iterdir()})
            seen=self.module.inspect_global_unit(owner,target,self.value)
            self.assertEqual((1,'UNKNOWN'),(seen.attempt_count,seen.outcome))
            self.assertFalse((self.store/'ATTEMPT-2').exists())
            self.assertFalse((self.locks/(hashlib.sha256(TARGET.encode()).hexdigest()+'.dispatch')).exists())

    def test_shared_retry_holds_real_catalog_replay_before_invalid_source_without_new_count(self):
        # Same actual owner and existing UNKNOWN, not a caller-built cache or
        # permission. A bad source must unwind the retained catalog scope and
        # leave all original durable bytes/counts unchanged.
        replay=self.module._hold_native_catalog_replay;events=[]
        @contextmanager
        def retained(*args):
            with replay(*args) as verify:
                verify();events.append('entered')
                try:yield verify
                finally:verify();events.append('closed')
        with Req7GlobalAttemptJournalWorkflowTests.counted_wire_owners(self) as (writer,owner,target):
            original=original_read_files(self.root)
            with mock.patch.object(self.module,'_hold_native_catalog_replay',new=retained):
                with self.assertRaises(self.module.GlobalAttemptHold):
                    with self.module._hold_shared_retry_owned_attempt_wire(owner,target,self.value,
                            writer_token=writer,identity_response=None,history_response=None,business_reads=(),
                            qualified_source=None,store=None,settings=None,whitelist_snapshot=None,
                            expected_template_sha256='a'*64,http_root=self.root,whitelist_path=self.root/'absent',
                            headers_response=None,whitelist_response=None,metadata_response=None,
                            boot_id='owned-boot',monotonic_ns=1):
                        self.fail('invalid source received an owned retry wire')
            self.assertEqual(['entered','closed'],events)
            self.assertEqual(original,original_read_files(self.root))
            self.assertEqual((1,'UNKNOWN'),(self.module.inspect_global_unit(owner,target,self.value).attempt_count,
                self.module.inspect_global_unit(owner,target,self.value).outcome))

    def test_live_count_verification_rechecks_originals_after_its_semantic_read(self):
        with Req7GlobalAttemptJournalWorkflowTests.counted_wire_owners(self) as (writer,owner,target):
            path=self.store/'ATTEMPT-1'; raw=path.read_bytes(); original=path.stat()
            real_inspect=self.module._inspect; injected=[]; rejected=[]
            def after_read(*args):
                result=real_inspect(*args)
                if not injected:
                    path.write_bytes(b'x'*len(raw)); path.write_bytes(raw)
                    os.utime(path,ns=(original.st_atime_ns,original.st_mtime_ns))
                    injected.append(result[0])
                return result
            with self.assertRaises(self.module.GlobalAttemptHold):
                with self.module._hold_counted_original_wire(writer,owner,target,self.value) as image:
                    with mock.patch.object(self.module,'_inspect',side_effect=after_read), self.assertRaises(self.module.GlobalAttemptHold):
                        self.module._require_original_wire_launch(writer,owner,target,self.value,image,consume=True)
                    rejected.append(True)
            self.assertEqual([1],injected); self.assertEqual([True],rejected,'reject inside live verification, not only context exit')
            self.assertEqual(original.st_ino,path.stat().st_ino); self.assertEqual(original.st_mtime_ns,path.stat().st_mtime_ns)
            self.assertNotEqual(original.st_ctime_ns,path.stat().st_ctime_ns); self.assertEqual(raw,path.read_bytes())
            seen=self.module.inspect_global_unit(owner,target,self.value)
            self.assertEqual((1,'UNKNOWN'),(seen.attempt_count,seen.outcome)); self.assertFalse((self.store/'ATTEMPT-2').exists())

    def test_original_images_are_pinned_before_the_first_count_is_interpreted(self):
        for entry in ('HEADER','INITIALIZED','ATTEMPT-1','WIRE','ACTION-PREIMAGE'):
            for fault in ('replace','inplace-restore'):
                with self.subTest(entry=entry,fault=fault), Req7GlobalAttemptJournalWorkflowTests.counted_wire_owners(self) as (writer,owner,target):
                    path=self.store/entry; raw=path.read_bytes(); initial=path.stat()
                    real_inspect=self.module._inspect; injected=[]; issued=[]
                    def after_count(*args):
                        result=real_inspect(*args)
                        if not injected:
                            if fault=='replace':
                                path.rename(self.locks/('owned-count-read-'+entry))
                                path.write_bytes(raw); path.chmod(0o600)
                                self.assertNotEqual(initial.st_ino,path.stat().st_ino)
                            else:
                                path.write_bytes(b'x'*len(raw)); path.write_bytes(raw)
                                os.utime(path,ns=(initial.st_atime_ns,initial.st_mtime_ns))
                                self.assertEqual(initial.st_ino,path.stat().st_ino)
                                self.assertEqual(initial.st_mtime_ns,path.stat().st_mtime_ns)
                                self.assertNotEqual(initial.st_ctime_ns,path.stat().st_ctime_ns)
                            self.assertEqual(raw,path.read_bytes()); injected.append(result[0])
                        return result
                    with mock.patch.object(self.module,'_inspect',side_effect=after_count), self.assertRaises(self.module.GlobalAttemptHold):
                        with self.module._hold_counted_original_wire(writer,owner,target,self.value) as image:
                            issued.append(image)
                    self.assertEqual([1],injected)
                    self.assertEqual([],issued,'a coherent replacement after count interpretation is not an original launch image')
                    seen=self.module.inspect_global_unit(owner,target,self.value)
                    self.assertEqual((1,'UNKNOWN'),(seen.attempt_count,seen.outcome))
                    self.assertEqual(raw,path.read_bytes()); self.assertFalse((self.store/'ATTEMPT-2').exists())

    def test_live_counted_launch_requires_original_journal_prefix_not_same_byte_replacements(self):
        for entry in ('HEADER', 'INITIALIZED', 'ATTEMPT-1', 'inplace-restore', 'directory-ABA', 'dispatch-ABA'):
            with self.subTest(entry=entry), Req7GlobalAttemptJournalWorkflowTests.counted_wire_owners(self) as (writer, owner, target):
                rejected = []
                raw_before = {p.name:p.read_bytes() for p in self.store.iterdir()}
                with self.assertRaises(self.module.GlobalAttemptHold):
                    with self.module._hold_counted_original_wire(writer, owner, target, self.value) as image:
                        if entry == 'dispatch-ABA':
                            dispatch = self.locks/(hashlib.sha256(TARGET.encode()).hexdigest()+'.dispatch')
                            original = dispatch.stat()
                            moved = self.locks/'owned-retained-dispatch'
                            dispatch.rename(moved); moved.rename(dispatch)
                            self.assertEqual(original.st_ino,dispatch.stat().st_ino)
                            self.assertNotEqual(original.st_ctime_ns,dispatch.stat().st_ctime_ns)
                        elif entry == 'directory-ABA':
                            original = self.store.stat()
                            moved = self.locks/'owned-retained-journal'
                            self.store.rename(moved); moved.rename(self.store)
                            self.assertEqual(original.st_ino, self.store.stat().st_ino)
                            self.assertNotEqual(original.st_ctime_ns, self.store.stat().st_ctime_ns)
                        elif entry == 'inplace-restore':
                            path = self.store/'ATTEMPT-1'; raw = path.read_bytes(); before = path.stat()
                            path.write_bytes(b'x' * len(raw)); path.write_bytes(raw)
                            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
                            self.assertEqual(before.st_ino, path.stat().st_ino)
                            self.assertEqual(before.st_mtime_ns, path.stat().st_mtime_ns)
                            self.assertNotEqual(before.st_ctime_ns, path.stat().st_ctime_ns)
                        else:
                            path = self.store/entry; raw = path.read_bytes(); inode = path.stat().st_ino
                            path.rename(self.locks/('owned-retained-'+entry))
                            path.write_bytes(raw); path.chmod(0o600)
                            self.assertEqual(raw, path.read_bytes())
                            self.assertNotEqual(inode, path.stat().st_ino)
                        with self.assertRaises(self.module.GlobalAttemptHold):
                            self.module._require_original_wire_launch(writer, owner, target, self.value, image, consume=True)
                        rejected.append(True)
                self.assertEqual([True], rejected, 'reject at the live pre-launch boundary, not only context exit')
                self.assertEqual(raw_before, {p.name:p.read_bytes() for p in self.store.iterdir()})
                retained = self.module.inspect_global_unit(owner, target, self.value)
                self.assertEqual((1, 'UNKNOWN'), (retained.attempt_count, retained.outcome))
                self.assertFalse((self.store/'ATTEMPT-2').exists())
                dispatch = self.locks/(hashlib.sha256(TARGET.encode()).hexdigest()+'.dispatch')
                self.assertEqual({'HEADER','INITIALIZED','CLAIM-1'}, {p.name for p in dispatch.iterdir()})

    def test_second_counted_launch_pins_the_earlier_original_attempt_too(self):
        with Req7GlobalAttemptJournalWorkflowTests.counted_wire_owners(self) as (writer, owner, target):
            with self.module._hold_counted_original_wire(writer,owner,target,self.value) as image:
                self.module._require_original_wire_launch(writer,owner,target,self.value,image,consume=True)
            self.module.record_global_attempt_intent(owner,target,self.value)
            path = self.store/'ATTEMPT-1'; raw, inode = path.read_bytes(), path.stat().st_ino
            rejected = []
            with self.assertRaises(self.module.GlobalAttemptHold):
                with self.module._hold_counted_original_wire(writer,owner,target,self.value) as image:
                    self.assertEqual(2,image.attempt_count)
                    path.rename(self.locks/'owned-retained-earlier-attempt')
                    path.write_bytes(raw); path.chmod(0o600)
                    self.assertNotEqual(inode,path.stat().st_ino)
                    with self.assertRaises(self.module.GlobalAttemptHold):
                        self.module._require_original_wire_launch(writer,owner,target,self.value,image,consume=True)
                    rejected.append(True)
            self.assertEqual([True],rejected,'the newest count alone is not the complete original prefix')
            retained = self.module.inspect_global_unit(owner,target,self.value)
            self.assertEqual((2,'UNKNOWN'),(retained.attempt_count,retained.outcome))
            self.assertEqual(raw,path.read_bytes()); self.assertFalse((self.store/'ATTEMPT-3').exists())
            dispatch = self.locks/(hashlib.sha256(TARGET.encode()).hexdigest()+'.dispatch')
            self.assertEqual({'HEADER','INITIALIZED','CLAIM-1','CLAIM-2'}, {p.name for p in dispatch.iterdir()})

    def test_ordinary_receipted_count_cannot_enter_older_cycle_replay(self):
        from contextlib import nullcontext
        from types import SimpleNamespace
        from monitor import issue_tracker_cycle_source as cycles
        from monitor import issue_tracker_stage_l_consumer as consumer
        from monitor import issue_tracker_receipt_snapshot as receipts
        from monitor import issue_tracker_online_target as targets
        from monitor import issue_tracker_send_unit as send_unit
        qualified = SimpleNamespace(cycle_ids=('original-cycle',))
        options = dict(qualified_source=qualified, store=object(), writer_token=None,
            settings=None, whitelist_snapshot=None, expected_template_sha256='a'*64,
            http_root=self.root, whitelist_path=self.root/'absent')
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.module.prepare_global_unit(token, binding(), self.value)
            self.module.record_global_attempt_intent(token, binding(), self.value)
            with ExitStack() as patches:
                patches.enter_context(mock.patch.object(receipts, '_hold_history_originals',
                    side_effect=lambda *a: nullcontext(lambda: None)))
                patches.enter_context(mock.patch.object(self.module, '_hold_receipted_audit_originals',
                    side_effect=lambda *a: nullcontext(lambda: None)))
                patches.enter_context(mock.patch.object(self.module, '_hold_reserved_quota_originals',
                    side_effect=lambda *a: nullcontext(lambda: None)))
                patches.enter_context(mock.patch.object(targets, 'inspect_project_online_target'))
                patches.enter_context(mock.patch.object(cycles, 'read_completed_cycle_evidence',
                    return_value=(SimpleNamespace(cycle_id='newer-cycle'),)))
                replay = patches.enter_context(mock.patch.object(consumer, 'replay_original_receipted_prod_source',
                    return_value=qualified))
                patches.enter_context(mock.patch.object(send_unit, '_read_original_generation_identity',
                    side_effect=self.module.GlobalAttemptHold()))
                with self.assertRaises(self.module.GlobalAttemptHold):
                    self.module.record_receipted_original_attempt_intent(
                        token, binding(), object(), self.value, **options)
                replay.assert_not_called()
            retained = self.module.inspect_global_unit(token, binding(), self.value)
            self.assertEqual((1, 'UNKNOWN'), (retained.attempt_count, retained.outcome))
            self.assertFalse((self.store/'ATTEMPT-2').exists())

    def test_shared_retry_pins_worker_and_policy_inputs_before_any_facts_or_opportunity(self):
        from contextlib import nullcontext
        from types import SimpleNamespace
        from monitor import issue_tracker_stage_l_consumer as consumer
        from monitor import issue_tracker_admission as admission
        from monitor import issue_tracker_history_preread_journal as continuity
        from monitor import issue_tracker_remote_history_match as gates
        from monitor import issue_tracker_local_workbook_commit as workbooks
        # The production receipt module captures this canonical function at
        # import time. Load it before temporarily patching the workbook API;
        # otherwise a later real workflow retains the fixture's mock forever.
        from monitor import issue_tracker_receipt_snapshot as receipts
        gate = SimpleNamespace(identity=object())
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self.module.prepare_global_unit(token, binding(), self.value)
            self.module.record_global_attempt_intent(token, binding(), self.value)
            with ExitStack() as patches:
                inputs_guard = patches.enter_context(mock.patch.object(consumer, '_hold_original_replay_inputs',
                    side_effect=consumer.StageLConsumerHold('missing original namespace')))
                facts = patches.enter_context(mock.patch.object(self.module, '_receipted_original_facts',
                    return_value=('unchanged original',)))
                opportunity = patches.enter_context(mock.patch.object(admission, '_hold_shared_retry_opportunity',
                    side_effect=lambda *a, **kw: nullcontext()))
                patches.enter_context(mock.patch.object(self.module, '_hold_receipted_audit_originals',
                    side_effect=lambda *a: nullcontext(lambda: None)))
                patches.enter_context(mock.patch.object(self.module, '_hold_reserved_quota_originals',
                    side_effect=lambda *a: nullcontext(lambda: None)))
                patches.enter_context(mock.patch.object(continuity, 'observe_owned_business_continuity',
                    return_value='unchanged issued continuity'))
                patches.enter_context(mock.patch.object(gates, 'observe_owned_unit_read_gates', return_value=gate))
                patches.enter_context(mock.patch.object(workbooks, '_latest_receipted_prod_xlsx', return_value=b'original'))
                with self.assertRaises(self.module.GlobalAttemptHold):
                    self.module.record_shared_retry_continuous_owned_attempt_intent(
                        token, binding(), self.value, writer_token=None, identity_response=None,
                        history_response=None, business_reads=(), qualified_source=None, store=SimpleNamespace(project_identity=self.root),
                        settings=None, whitelist_snapshot=SimpleNamespace(whitelist=None),
                        expected_template_sha256='a'*64, http_root=self.root, whitelist_path=self.root/'absent',
                        headers_response=None, whitelist_response=None, metadata_response=None,
                        boot_id='owned-test-boot', monotonic_ns=1)
                inputs_guard.assert_called_once()
                facts.assert_not_called()
                opportunity.assert_not_called()
            observation = self.module.inspect_global_unit(token, binding(), self.value)
            self.assertEqual((1, 'UNKNOWN'), (observation.attempt_count, observation.outcome))
            self.assertFalse((self.store/'ATTEMPT-2').exists())

    def test_completion_start_witness_refuses_fresh_journal_even_without_proof_directory(self):
        witness=self.locks/(hashlib.sha256(TARGET.encode()).hexdigest()+'.completion-started')
        witness.write_bytes(b'interrupted completion witness\n'); witness.chmod(0o600)
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            with self.assertRaises(self.module.GlobalAttemptHold):
                self.module.prepare_global_unit(token,binding(),self.value)
        self.assertFalse(self.store.exists())
        self.assertEqual(b'interrupted completion witness\n',witness.read_bytes())

    def test_completion_start_witness_blocks_count_after_proof_namespace_disappears(self):
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            self.module.prepare_global_unit(token,binding(),self.value)
            self.module.record_global_attempt_intent(token,binding(),self.value)
            witness=self.locks/(hashlib.sha256(TARGET.encode()).hexdigest()+'.completion-started')
            witness.write_bytes(b'not settlement authority\n'); witness.chmod(0o600)
            retained={p:p.read_bytes() for p in self.locks.rglob('*') if p.is_file()}
            with self.assertRaises(self.module.GlobalAttemptHold):
                self.module.record_global_attempt_intent(token,binding(),self.value)
            self.assertEqual(retained,{p:p.read_bytes() for p in retained})
            self.assertEqual((1,'UNKNOWN'),(self.module.inspect_global_unit(token,binding(),self.value).attempt_count,
                                           self.module.inspect_global_unit(token,binding(),self.value).outcome))

    def test_completion_marker_presence_refuses_new_count_without_claiming_applied(self):
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            self.module.prepare_global_unit(token,binding(),self.value)
            self.module.record_global_attempt_intent(token,binding(),self.value)
            proof=self.locks/(hashlib.sha256(TARGET.encode()).hexdigest()+'.completion')
            proof.mkdir(mode=0o700)
            # Deliberately invalid: marker presence is a conservative STOP,
            # never remote resolution evidence or permission to free a fence.
            (proof/'COMPLETE').write_bytes(b'not a proof\n'); (proof/'COMPLETE').chmod(0o600)
            retained={p:p.read_bytes() for p in self.locks.rglob('*') if p.is_file()}
            with self.assertRaises(self.module.GlobalAttemptHold):
                self.module.record_global_attempt_intent(token,binding(),self.value)
            self.assertEqual(retained,{p:p.read_bytes() for p in retained})
            self.assertFalse((self.store/'ATTEMPT-2').exists())
            self.assertEqual((1,'UNKNOWN'),(self.module.inspect_global_unit(token,binding(),self.value).attempt_count,
                                           self.module.inspect_global_unit(token,binding(),self.value).outcome))

    def test_original_receipt_namespace_guard_must_precede_any_protected_count(self):
        from monitor import issue_tracker_receipt_snapshot as receipts
        options=dict(qualified_source=None,store=None,writer_token=None,settings=None,
                     whitelist_snapshot=None,expected_template_sha256='a'*64,
                     http_root=self.root,whitelist_path=self.root/'absent')
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            self.module.prepare_global_unit(token,binding(),self.value)
            with mock.patch.object(receipts,'_hold_history_originals',side_effect=receipts.LocalReceiptSnapshotHold('original missing')) as guard, \
                    mock.patch.object(self.module,'_receipted_original_facts',return_value=('unchanged diagnostic image',)) as facts:
                with self.assertRaises(self.module.GlobalAttemptHold) as caught:
                    self.module.record_receipted_original_attempt_intent(token,binding(),object(),self.value,**options)
                guard.assert_called_once_with(None); facts.assert_not_called()
            self.assertIsNone(caught.exception.__context__)
            self.assertEqual(0,self.module.inspect_global_unit(token,binding(),self.value).attempt_count)
            self.assertFalse((self.store/'ATTEMPT-1').exists())

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
            # The permanent start barriers are tested separately; retain all
            # original image/INITIALIZED assertions at their original indices.
            if self.store.exists(): observed.append(set(os.listdir(self.store)))
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
                        # Keep the original eight image fault sites unchanged.
                        if store.exists():
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


    def test_lost_original_unknown_same_unit_cannot_reset_count(self):
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            self.module.prepare_global_unit(token,binding(),self.value)
            first=self.module.record_global_attempt_intent(token,binding(),self.value)
            self.assertEqual((1,"UNKNOWN"),(first.attempt_count,first.outcome))
            saved={p.name:(p.stat().st_ino,p.read_bytes()) for p in self.store.iterdir()}
            preserved=self.root/"preserved-original-unknown"
            self.store.rename(preserved)
            with self.assertRaises(self.module.GlobalAttemptHold):
                self.module.prepare_global_unit(token,binding(),self.value)
            self.assertFalse(self.store.exists(),"namespace loss is not first use")
            self.assertEqual(saved,{p.name:(p.stat().st_ino,p.read_bytes()) for p in preserved.iterdir()})
            self.assertIn("ATTEMPT-1",saved)


    def test_lost_exhausted_original_cannot_start_different_generation(self):
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            self.module.prepare_global_unit(token,binding(),self.value)
            for expected in range(1,7):
                seen=self.module.record_global_attempt_intent(token,binding(),self.value)
                self.assertEqual((expected,"UNKNOWN"),(seen.attempt_count,seen.outcome))
            saved={p.name:(p.stat().st_ino,p.read_bytes()) for p in self.store.iterdir()}
            preserved=self.root/"preserved-exhausted-original"
            self.store.rename(preserved)
            successor=unit(generation_id="c"*64)
            self.assertNotEqual(self.value.unit_id,successor.unit_id)
            with self.assertRaises(self.module.GlobalAttemptHold):
                self.module.prepare_global_unit(token,binding(),successor)
            self.assertFalse(self.store.exists(),"a new generation is not UNKNOWN resolution")
            self.assertEqual(saved,{p.name:(p.stat().st_ino,p.read_bytes()) for p in preserved.iterdir()})
            self.assertIn("ATTEMPT-6",saved)


    def test_normal_first_use_keeps_original_count_and_wire(self):
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            self.module.prepare_global_unit(token,binding(),self.value)
            original=self.store/"WIRE"
            before=(original.stat().st_ino,original.read_bytes())
            seen=self.module.record_global_attempt_intent(token,binding(),self.value)
            self.assertEqual((1,"UNKNOWN"),(seen.attempt_count,seen.outcome))
            self.assertEqual(before,(original.stat().st_ino,original.read_bytes()))
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            seen=self.module.inspect_global_unit(token,binding(),self.value)
            self.assertEqual((1,"UNKNOWN"),(seen.attempt_count,seen.outcome))
            self.assertEqual(before,(original.stat().st_ino,original.read_bytes()))


    def test_start_witness_file_and_parent_barriers_precede_any_unit_folder(self):
        for fault in ("zero-write", "file-fsync", "parent-fsync"):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory(prefix="req7-start-barrier-") as temporary:
                root=Path(temporary).resolve()
                locks=root/"var/lib/http-ztp-container/issue-tracker"
                locks.mkdir(parents=True,mode=0o700)
                prefix=hashlib.sha256(TARGET.encode()).hexdigest()
                started=locks/(prefix+".journal-started")
                store=locks/(prefix+".journal")
                real_write=os.write; real_sync=os.fsync; reached=[]
                def write(fd,image):
                    if started.exists() and os.fstat(fd).st_ino==started.stat().st_ino:
                        if fault=="zero-write": reached.append(True); return 0
                    return real_write(fd,image)
                def sync(fd):
                    if fault in ("file-fsync", "parent-fsync") and started.exists():
                        inode=os.fstat(fd).st_ino
                        if inode==(started.stat().st_ino if fault=="file-fsync" else locks.stat().st_ino):
                            reached.append(True); raise OSError("owned synthetic barrier failure")
                    return real_sync(fd)
                with fixture(root),self.owner.spreadsheet_owner(binding()) as token:
                    with mock.patch("os.write",side_effect=write),mock.patch("os.fsync",side_effect=sync):
                        with self.assertRaises(self.module.GlobalAttemptHold):
                            self.module.prepare_global_unit(token,binding(),self.value)
                    self.assertEqual([True],reached,"the start barrier must run before journal creation")
                    self.assertTrue(started.exists(),"partial start remains a conservative STOP")
                    self.assertFalse(store.exists())
                    saved=(started.stat().st_ino,started.read_bytes())
                    with self.assertRaises(self.module.GlobalAttemptHold):
                        self.module.prepare_global_unit(token,binding(),self.value)
                    self.assertEqual(saved,(started.stat().st_ino,started.read_bytes()))
                    self.assertFalse(store.exists())


    def test_retained_start_adds_two_barriers_without_erasing_eight_image_barriers(self):
        real_sync=os.fsync; observed=[]
        started=self.store.with_name(self.store.name[:-len(".journal")]+".journal-started")
        def syncing(fd):
            observed.append((os.fstat(fd).st_ino,
                set(os.listdir(self.store)) if self.store.exists() else set()))
            return real_sync(fd)
        with fixture(self.root),self.owner.spreadsheet_owner(binding()) as token:
            with mock.patch("os.fsync",side_effect=syncing):
                self.module.prepare_global_unit(token,binding(),self.value)
            self.assertEqual(12,len(observed))
            self.assertEqual([(started.stat().st_ino,set()),(self.locks.stat().st_ino,set())],observed[:2])
            image=[names for _inode,names in observed[2:]]
            self.assertEqual(10,len(image))
            self.assertTrue(all("INITIALIZED" not in names for names in image[:9]))
            self.assertEqual({"ACTION-PREIMAGE","WIRE","HEADER"},image[7])
            self.assertEqual({"ACTION-PREIMAGE","WIRE","HEADER","INITIALIZED"},image[9])


    def test_all_original_eight_partial_image_barriers_remain_non_adoptable(self):
        real_sync=os.fsync
        for boundary in range(1,9):
            with self.subTest(boundary=boundary),tempfile.TemporaryDirectory(prefix="req7-start-original-barriers-") as temporary:
                root=Path(temporary).resolve()
                locks=root/"var/lib/http-ztp-container/issue-tracker"; locks.mkdir(parents=True,mode=0o700)
                store=locks/self.store.name; calls=[]
                def failing(fd):
                    # Preserve the original eight image boundaries exactly;
                    # the separate start barriers have their own fault test.
                    if store.exists():
                        calls.append(fd)
                        if len(calls)==boundary: raise OSError("owned original image barrier failure")
                    return real_sync(fd)
                with fixture(root),self.owner.spreadsheet_owner(binding()) as token:
                    with mock.patch("os.fsync",side_effect=failing),self.assertRaises(self.module.GlobalAttemptHold):
                        self.module.prepare_global_unit(token,binding(),self.value)
                    self.assertEqual(boundary,len(calls)); self.assertTrue(store.is_dir())
                    with self.assertRaises(self.module.GlobalAttemptHold):
                        self.module.prepare_global_unit(token,binding(),self.value)
                    with self.assertRaises(self.module.GlobalAttemptHold):
                        self.module.record_global_attempt_intent(token,binding(),self.value)
                    self.assertFalse((store/"ATTEMPT-1").exists())


    def test_start_original_handoff_rejects_displacement_before_any_unit_folder(self):
        for fault in ("lost-name","same-byte-replacement","same-inode-rewrite"):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory(prefix="req7-start-handoff-") as temporary:
                root=Path(temporary).resolve()
                locks=root/"var/lib/http-ztp-container/issue-tracker"; locks.mkdir(parents=True,mode=0o700)
                prefix=hashlib.sha256(TARGET.encode()).hexdigest()
                started=locks/(prefix+".journal-started"); store=locks/(prefix+".journal")
                real_validate=self.owner._validated_owner; injected=[]
                def after_validation(*args):
                    phase='actual-owner';original=None
                    try:
                        owner=real_validate(*args);phase='select-fault'
                        if started.exists() and not store.exists() and not injected:
                            phase='read-original'
                            raw=started.read_bytes(); original=started.stat()
                            if fault in ("lost-name","same-byte-replacement"):
                                phase='rename-original';started.rename(root/"preserved-start-original")
                                if fault=="same-byte-replacement":
                                    phase='write-replacement';started.write_bytes(raw); started.chmod(0o600)
                                    phase='replacement-inode-assertion'
                                    self.assertNotEqual(original.st_ino,started.stat().st_ino)
                            else:
                                phase='rewrite-original'
                                started.write_bytes(b"x"*len(raw)); started.write_bytes(raw)
                                phase='restore-original-mtime'
                                os.utime(started,ns=(original.st_atime_ns,original.st_mtime_ns))
                                phase='same-original-inode-assertion'
                                self.assertEqual(original.st_ino,started.stat().st_ino)
                                phase='restored-original-mtime-assertion'
                                self.assertEqual(original.st_mtime_ns,started.stat().st_mtime_ns)
                                phase='changed-original-ctime-assertion'
                                self.assertNotEqual(original.st_ctime_ns,started.stat().st_ctime_ns)
                            injected.append((original.st_ino,raw))
                        return owner
                    except BaseException as primary:
                        # Failure-only facts before production sanitizes the
                        # fixture exception. Never change the original fault,
                        # assertions, timestamp restoration, or primary object.
                        try:
                            record={'fault':fault,'phase':phase,'type':type(primary).__name__}
                            if original is not None:
                                record['original_stat']=[original.st_ino,original.st_mtime_ns,original.st_ctime_ns]
                                if started.exists():
                                    current=started.stat()
                                    record['current_stat']=[current.st_ino,current.st_mtime_ns,current.st_ctime_ns]
                            print('GLOBAL_START_FAULT_CALLBACK_FAILURE '+json.dumps(record,sort_keys=True),flush=True)
                        except BaseException:pass
                        raise
                with fixture(root),self.owner.spreadsheet_owner(binding()) as token:
                    with mock.patch.object(self.owner,"_validated_owner",side_effect=after_validation), \
                            mock.patch.object(self.module,"_create_folder",wraps=self.module._create_folder) as creating:
                        with self.assertRaises(self.module.GlobalAttemptHold):
                            self.module.prepare_global_unit(token,binding(),self.value)
                    self.assertEqual(1,len(injected)); creating.assert_not_called()
                    self.assertFalse(store.exists())
                    retained=started if fault=="same-inode-rewrite" else root/"preserved-start-original"
                    self.assertEqual(injected[0],(retained.stat().st_ino,retained.read_bytes()))


    def test_special_file_original_never_waits_for_a_pipe_writer_or_repairs_evidence(self):
        code = '''import importlib.util,pathlib,sys
sys.path.insert(0,sys.argv[3])
from test_cases.test_req7_spreadsheet_owner import load as load_owner, fixture, binding
spec=importlib.util.spec_from_file_location('monitor.issue_tracker_global_attempt_journal',sys.argv[2])
subject=importlib.util.module_from_spec(spec); sys.modules[spec.name]=subject; spec.loader.exec_module(subject)
owner=load_owner()
with fixture(pathlib.Path(sys.argv[1])),owner.spreadsheet_owner(binding()) as token:
 try: subject.inspect_original_global_unit(token,binding())
 except subject.GlobalAttemptHold: print('HOLD ORIGINAL FIFO')
 else: raise AssertionError('FIFO is not original regular-file evidence')
'''
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self._prepare_original_read(token)
        for path in (self._original_started, self.store / 'ACTION-PREIMAGE', self.store / 'WIRE',
                     self.store / 'HEADER', self.store / 'INITIALIZED', self.store / 'ATTEMPT-1'):
            with self.subTest(name=path.name):
                preserved = self.root / ('preserved-fifo-' + path.name)
                path.rename(preserved)
                os.mkfifo(path, 0o600)
                inode = path.stat().st_ino
                before = original_read_files(self.root)
                try:
                    try:
                        child = subprocess.run([sys.executable, '-B', '-c', code,
                            str(self.root), str(SOURCE), str(ROOT)], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
                    except subprocess.TimeoutExpired:
                        self.fail('original reader blocked on FIFO without an owned pipe writer')
                    self.assertEqual(0, child.returncode, child.stdout + child.stderr)
                    self.assertEqual(b'HOLD ORIGINAL FIFO\n', child.stdout)
                    self.assertEqual(inode, path.stat().st_ino)
                    self.assertEqual(before, original_read_files(self.root))
                finally:
                    path.unlink()
                    preserved.rename(path)

    def _require_original_read_api(self):
        self.assertTrue(callable(getattr(self.module, 'inspect_original_global_unit', None)),
                        'cold history must come from held ACTION/WIRE, not a caller unit')
        self.assertTrue(callable(getattr(self.module, '_hold_original_global_unit', None)))
        self._original_started = self.store.with_name(self.store.stem + '.journal-started')

    def _prepare_original_read(self, token, count=1):
        Req7GlobalAttemptJournalTests._require_original_read_api(self)
        self.module.prepare_global_unit(token, binding(), self.value)
        for _ in range(count):
            self.module.record_global_attempt_intent(token, binding(), self.value)

    def test_original_read_restores_exact_action_wire_zero_unknown_and_exhausted_counts(self):
        self._require_original_read_api()
        from monitor import issue_tracker_send_unit as units
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self._prepare_original_read(token, count=0)
            for count in range(7):
                before = original_read_files(self.root)
                with mock.patch.object(units, 'freeze_send_unit', side_effect=AssertionError('no current compilation')):
                    original, seen = self.module.inspect_original_global_unit(token, binding())
                self.assertEqual(self.value, original)
                self.assertEqual((count, 'UNKNOWN' if count else 'UNATTEMPTED_OBSERVATION'),
                                 (seen.attempt_count, seen.outcome))
                self.assertFalse(hasattr(seen, 'permit'))
                self.assertEqual(before, original_read_files(self.root))
                if count < 6:
                    self.module.record_global_attempt_intent(token, binding(), self.value)

    def test_missing_journal_or_start_witness_is_hold_not_empty_inventory(self):
        self._require_original_read_api()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            with self.assertRaises(self.module.GlobalAttemptHold):
                self.module.inspect_original_global_unit(token, binding())
            self._prepare_original_read(token)
            for path in (self._original_started, self.store):
                saved = path.with_name(path.name + '.preserved')
                path.rename(saved)
                try:
                    before = original_read_files(self.root)
                    with self.assertRaises(self.module.GlobalAttemptHold):
                        self.module.inspect_original_global_unit(token, binding())
                    self.assertEqual(before, original_read_files(self.root))
                finally:
                    saved.rename(path)

    def test_bad_start_binding_or_gap_cannot_be_a_coherent_original(self):
        self._require_original_read_api()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self._prepare_original_read(token, count=2)
            original = self._original_started.read_bytes()
            for raw in (b'', b'partial', original.replace(self.value.unit_id.encode(), b'f' * 64)):
                self._original_started.write_bytes(raw)
                before = original_read_files(self.root)
                with self.assertRaises(self.module.GlobalAttemptHold):
                    self.module.inspect_original_global_unit(token, binding())
                self.assertEqual(before, original_read_files(self.root))
            self._original_started.write_bytes(original)
            (self.store / 'ATTEMPT-1').rename(self.root / 'preserved-attempt-one')
            with self.assertRaises(self.module.GlobalAttemptHold):
                self.module.inspect_original_global_unit(token, binding())
            self.assertFalse((self.store / 'ATTEMPT-1').exists())

    def test_original_pins_precede_interpretation_and_reject_same_bytes_replacement(self):
        self._require_original_read_api()
        from monitor import issue_tracker_send_unit as units
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self._prepare_original_read(token)
            reconstruct = units._original_unit
            for path in (self._original_started, self.store / 'ACTION-PREIMAGE', self.store / 'WIRE',
                         self.store / 'HEADER', self.store / 'INITIALIZED', self.store / 'ATTEMPT-1'):
                with self.subTest(name=path.name):
                    preserved = self.root / ('preserved-' + path.name)
                    reached = []
                    def replacing(action, wire):
                        reached.append(True)
                        path.rename(preserved)
                        path.write_bytes(preserved.read_bytes())
                        path.chmod(0o600)
                        return reconstruct(action, wire)
                    with mock.patch.object(units, '_original_unit', side_effect=replacing):
                        with self.assertRaises(self.module.GlobalAttemptHold):
                            self.module.inspect_original_global_unit(token, binding())
                    self.assertEqual([True], reached)
                    path.unlink()
                    preserved.rename(path)

    def test_held_original_scope_rechecks_namespace_and_count_after_consumer(self):
        self._require_original_read_api()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self._prepare_original_read(token)
            before = original_read_files(self.root)
            with self.assertRaises(self.module.GlobalAttemptHold):
                with self.module._hold_original_global_unit(token, binding()) as (original, seen, verify):
                    self.assertEqual((self.value, 1), (original, seen.attempt_count))
                    verify()
                    self.module.record_global_attempt_intent(token, binding(), self.value)
            self.assertEqual(before['var/lib/http-ztp-container/issue-tracker/' + self.store.name + '/WIRE'],
                             original_read_files(self.root)['var/lib/http-ztp-container/issue-tracker/' + self.store.name + '/WIRE'])
            self.assertTrue((self.store / 'ATTEMPT-2').is_file())

    def test_required_recovery_barriers_fail_without_mutation_or_adoption(self):
        self._require_original_read_api()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self._prepare_original_read(token)
            original = original_read_files(self.root)
            for path in (self._original_started, self.store / 'WIRE', self.store, self.locks):
                with self.subTest(name=path.name):
                    sync = os.fsync
                    reached = []
                    def failing(fd):
                        if os.fstat(fd).st_ino == path.stat().st_ino:
                            reached.append(True)
                            raise OSError('owned recovery barrier failure')
                        return sync(fd)
                    with mock.patch('os.fsync', side_effect=failing):
                        with self.assertRaises(self.module.GlobalAttemptHold):
                            self.module.inspect_original_global_unit(token, binding())
                    self.assertEqual([True], reached)
                    self.assertEqual(original, original_read_files(self.root))

    def test_existing_public_reader_cannot_bypass_missing_original_start(self):
        self._require_original_read_api()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self._prepare_original_read(token)
            self._original_started.rename(self.root / 'preserved-original-start')
            before = original_read_files(self.root)
            with self.assertRaises(self.module.GlobalAttemptHold):
                self.module.inspect_global_unit(token, binding(), self.value)
            self.assertEqual(before, original_read_files(self.root))

    def test_existing_public_reader_pins_originals_before_semantic_count_read(self):
        self._require_original_read_api()
        with fixture(self.root), self.owner.spreadsheet_owner(binding()) as token:
            self._prepare_original_read(token)
            inspect = self.module._inspect; replaced = []
            def after_count(*args):
                result = inspect(*args)
                if not replaced:
                    replaced.append(True)
                    path = self.store / 'ACTION-PREIMAGE'
                    path.rename(self.root / 'preserved-original-action')
                    path.write_bytes(self.value.action_preimage)
                    path.chmod(0o600)
                return result
            with mock.patch.object(self.module, '_inspect', side_effect=after_count):
                with self.assertRaises(self.module.GlobalAttemptHold):
                    self.module.inspect_global_unit(token, binding(), self.value)
            self.assertEqual([True], replaced)
            self.assertEqual(self.value.action_preimage, (self.store / 'ACTION-PREIMAGE').read_bytes())
            self.assertFalse((self.store / 'ATTEMPT-2').exists())


class Req7GlobalAttemptJournalWorkflowTests(unittest.TestCase):
    def test_actual_catalog_membership_rebind_is_rejected_before_borrower_body(self):
        from test_cases.test_req7_unit_catalog import load as load_catalog
        owner_module=load_owner();module=load();catalog=load_catalog(reset_dependencies=False)
        with tempfile.TemporaryDirectory(prefix='req7-catalog-membership-rebind-') as temporary:
            root=Path(temporary).resolve();selected=unit();injected=[];entered=[]
            (root/'var/lib/http-ztp-container/issue-tracker').mkdir(parents=True,mode=0o700)
            with fixture(root),owner_module.spreadsheet_owner(binding()) as token:
                with self.assertRaises(module.GlobalAttemptHold):
                    catalog.register_pending_unit(token,binding(),selected)
                    with module._hold_native_catalog_replay(token,binding(),selected):
                        issued=module._LIVE_CATALOG_REPLAYS[module._HELD_CATALOG_REPLAY.get()]
                        original_unit=issued[3][0]
                        original_equal=type(selected).__eq__
                        path=root/'var/lib/http-ztp-container/issue-tracker'/(
                            hashlib.sha256(TARGET.encode()).hexdigest()+'.units')/'HEADER'
                        original_bytes=path.read_bytes();original_inode=path.stat().st_ino
                        def equal(left,right):
                            result=original_equal(left,right)
                            if left is original_unit and right is selected and not injected:
                                path.rename(path.with_name('HEADER-preserved-original'))
                                path.write_bytes(original_bytes);path.chmod(0o600)
                                injected.append(path.stat().st_ino)
                            return result
                        with mock.patch.object(type(selected),'__eq__',new=equal):
                            with module._hold_native_catalog_write_replay(token,binding(),selected):
                                entered.append(True)
                self.assertEqual([],entered,'EXIT refusal cannot replace refusal before borrower body')
                self.assertEqual(1,len(injected));self.assertNotEqual(original_inode,injected[0])
                self.assertEqual(original_bytes,path.read_bytes())
                self.assertEqual(original_bytes,path.with_name('HEADER-preserved-original').read_bytes())

    setUp = Req7GlobalAttemptJournalTests.setUp

    def test_actual_local_intent_and_cold_owner_never_recreate_lost_unknown(self):
        from monitor import issue_tracker_local_commit as local
        from monitor import issue_tracker_send_intent as intent
        project=self.root/"project"; project.mkdir(mode=0o700)
        publication=project/"publication"; publication.mkdir(mode=0o700)
        local.create_local_commit_store(project,publication)
        with local.writer_owner(project,publication) as writer:
            intent.prepare_send_intent(writer,self.value)
            local_seen=intent.record_compiled_attempt_intent(writer,self.value)
            with scoped_fixture(self.root,self.owner),self.owner.spreadsheet_owner(binding()) as token:
                self.module.prepare_global_unit(token,binding(),self.value)
                global_seen=self.module.record_global_attempt_intent(token,binding(),self.value)
            self.assertEqual((1,"UNKNOWN"),(local_seen.attempt_count,local_seen.outcome))
            self.assertEqual((1,"UNKNOWN"),(global_seen.attempt_count,global_seen.outcome))
        saved={p.name:(p.stat().st_ino,p.read_bytes()) for p in self.store.iterdir()}
        preserved=self.root/"preserved-cold-unknown"; self.store.rename(preserved)
        result=subprocess.run([sys.executable,"-B",str(Path(__file__).resolve()),
            "--owned-start-hold",str(self.root),str(ROOT)],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(0,result.returncode,result.stdout+result.stderr)
        self.assertEqual(b"GLOBAL HOLD; LOCAL 1 UNKNOWN; NO NEW JOURNAL\n",result.stdout)
        self.assertFalse(self.store.exists())
        self.assertEqual(saved,{p.name:(p.stat().st_ino,p.read_bytes()) for p in preserved.iterdir()})


    @contextmanager
    def counted_wire_owners(self,*,count=1):
        from test_cases.test_req7_history_read_launcher import Req7HistoryReadLauncherWorkflowTests as native
        self.root = self.root/'owned-claim-boundary'; self.root.mkdir()
        self.locks = self.root/'var/lib/http-ztp-container/issue-tracker'
        self.store = self.locks/(hashlib.sha256(TARGET.encode()).hexdigest()+'.journal')
        with ExitStack() as stack:
            _local,_owner,writer,sheet_token,target,_credential,_config = native.owners(self,stack,target_id=TARGET)
            self.module.prepare_global_unit(sheet_token,target,self.value)
            for _ in range(count):
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

    def test_partial_completion_refuses_wire_claim_before_creating_dispatch(self):
        with self.counted_wire_owners() as (writer,token,target):
            proof=self.locks/(hashlib.sha256(TARGET.encode()).hexdigest()+'.completion')
            proof.mkdir(mode=0o700)
            # Even an interrupted proof writer must be reconciled; no guessed
            # COMPLETE, deletion, count reset or transport is allowed here.
            retained={p:p.read_bytes() for p in self.locks.rglob('*') if p.is_file()}
            issued=[]
            with self.assertRaises(self.module.GlobalAttemptHold):
                with self.module._hold_counted_original_wire(writer,token,target,self.value) as image:
                    issued.append(image)
            self.assertEqual([],issued)
            self.assertFalse((self.locks/(hashlib.sha256(TARGET.encode()).hexdigest()+'.dispatch')).exists())
            self.assertEqual(retained,{p:p.read_bytes() for p in retained})
            self.assertEqual(1,self.module.inspect_global_unit(token,target,self.value).attempt_count)

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


    def test_cold_process_uses_retained_global_unit_to_reopen_actual_local_intent(self):
        from monitor import issue_tracker_local_commit as local, issue_tracker_send_intent as intent
        project = self.root / 'project'; project.mkdir(mode=0o700)
        publication = project / 'publication'; publication.mkdir(mode=0o700)
        local.create_local_commit_store(project, publication)
        with local.writer_owner(project, publication) as writer:
            intent.prepare_send_intent(writer, self.value)
            intent.record_compiled_attempt_intent(writer, self.value)
            with scoped_fixture(self.root, self.owner), self.owner.spreadsheet_owner(binding()) as token:
                Req7GlobalAttemptJournalTests._prepare_original_read(self, token)
        before = original_read_files(self.root)
        child = subprocess.run([sys.executable, '-B', str(Path(__file__).resolve()), '--owned-original-read', str(self.root), str(ROOT)],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(0, child.returncode, child.stdout + child.stderr)
        self.assertEqual((self.value.unit_id + ' 1 1 UNKNOWN\n').encode(), child.stdout)
        self.assertEqual(before, original_read_files(self.root))


def cold_hold(root):
    from monitor import issue_tracker_local_commit as local
    from monitor import issue_tracker_send_intent as intent
    owner=load_owner(); module=load(); value=unit()
    store=root/"var/lib/http-ztp-container/issue-tracker"/(hashlib.sha256(TARGET.encode()).hexdigest()+".journal")
    with local.writer_owner(root/"project",root/"project/publication") as writer:
        seen=intent.inspect_send_intent(writer,value)
        if (seen.attempt_count,seen.outcome)!=(1,"UNKNOWN"): return 5
        with scoped_fixture(root,owner),owner.spreadsheet_owner(binding()) as token:
            try:
                module.prepare_global_unit(token,binding(),value)
            except module.GlobalAttemptHold:
                if store.exists(): return 6
            else: return 4
        if intent.inspect_send_intent(writer,value).attempt_count!=1: return 7
    print("GLOBAL HOLD; LOCAL 1 UNKNOWN; NO NEW JOURNAL",flush=True)
    return 0

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--owned-original-read':
        from monitor import issue_tracker_local_commit as local, issue_tracker_send_intent as intent
        from monitor import issue_tracker_send_unit as units
        root = Path(sys.argv[2]).resolve()
        owner = load_owner(); subject = load()
        with local.writer_owner(root / 'project', root / 'project/publication') as writer:
            with scoped_fixture(root, owner), owner.spreadsheet_owner(binding()) as token:
                with mock.patch.object(units, 'freeze_send_unit', side_effect=AssertionError('cold recompile forbidden')):
                    original, global_seen = subject.inspect_original_global_unit(token, binding())
                    local_seen = intent.inspect_send_intent(writer, original)
                    assert (global_seen.attempt_count, local_seen.attempt_count,
                            global_seen.outcome, local_seen.outcome) == (1, 1, 'UNKNOWN', 'UNKNOWN')
                    print(original.unit_id, global_seen.attempt_count, local_seen.attempt_count, global_seen.outcome)
    elif len(sys.argv) > 1 and sys.argv[1] == '--owned-start-hold':
        raise SystemExit(cold_hold(Path(sys.argv[2]).resolve()))
    elif len(sys.argv) > 1 and sys.argv[1] == '--owned-wire-claim':
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
