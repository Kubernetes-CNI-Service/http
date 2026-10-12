"""Real protected Stage-L source, C5/C6 and fail-closed workflow contracts."""

from __future__ import annotations

from dataclasses import asdict, replace
from contextlib import ExitStack, contextmanager
import datetime as dt
import hashlib
import json
from io import BytesIO
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest import mock
import zipfile

import xlsxwriter

from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
from monitor.issue_tracker_ib_runtime import IbBoundCycleReport, IbReportLink
from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
from test_cases.test_issue_tracker_local_workbook import fake_workbook
from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx

from test_cases.test_issue_tracker_stage_l_consumer import ProdStageLFixture


class ProdStageLConsumerWorkflowTests(ProdStageLFixture):
    @contextmanager
    def _assertion_preserving_preparation(self, preparation):
        # A production HOLD deliberately hides consumer exception text. Keep
        # an independent expectation visible only after real scope cleanup.
        primary = None
        try:
            with preparation as borrowed:
                try: yield borrowed
                except BaseException as exc:
                    primary = exc
                    raise
        except BaseException:
            if primary is not None: raise primary
            raise

    def _fixture_certificate_supplier(self, builder):
        # One scenario's server material only, never a cached read/result,
        # deadline, client connection or production authorization. Rebuild if
        # host/root changes or any original certificate/key file drifts.
        last=None
        def originals(fixture):
            paths=(fixture.path,fixture.root/'owned-server.pem',fixture.root/'owned-server-key.pem')
            fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
                    'st_size','st_mtime_ns','st_ctime_ns')
            result=[]
            for path in paths:
                before=tuple(getattr(path.stat(),name) for name in fields)
                raw=path.read_bytes()
                after=tuple(getattr(path.stat(),name) for name in fields)
                self.assertEqual(before,after,'owned certificate changed during fixture read')
                result.append((str(path),before,raw))
            return tuple(result)
        def supply(fixture,hostname='oauth2.googleapis.com'):
            nonlocal last
            key=(str(fixture.root),str(fixture.path),hostname)
            if last is not None and last[0]==key and originals(fixture)==last[1]:
                return last[2]
            context=builder(fixture,hostname)
            last=(key,originals(fixture),context)
            return context
        return supply

    def test_fixture_certificate_reuses_only_exact_current_same_host_originals(self):
        from types import SimpleNamespace
        import tempfile
        with tempfile.TemporaryDirectory(prefix='req7-certificate-isolation-') as directory:
            root=Path(directory);fixture=SimpleNamespace(root=root,path=root/'ca.pem')
            files=(fixture.path,root/'owned-server.pem',root/'owned-server-key.pem')
            built=[]
            def builder(actual,host):
                self.assertIs(fixture,actual)
                context=object();built.append((host,context))
                for index,path in enumerate(files):path.write_bytes(('literal-%d-%s-%d'%(index,host,len(built))).encode())
                return context
            supplied=self._fixture_certificate_supplier(builder)
            first=supplied(fixture,'sheets.googleapis.com')
            self.assertIs(first,supplied(fixture,'sheets.googleapis.com'))
            self.assertEqual(1,len(built))
            for path in files:
                raw=path.read_bytes();old=path.stat().st_ino
                path.rename(root/'owned-prior-certificate');path.write_bytes(raw)
                self.assertNotEqual(old,path.stat().st_ino)
                prior=built[-1][1];current=supplied(fixture,'sheets.googleapis.com')
                self.assertIsNot(prior,current)
                self.assertIs(current,supplied(fixture,'sheets.googleapis.com'))
            prior=built[-1][1]
            self.assertIsNot(prior,supplied(fixture,'oauth2.googleapis.com'))
            self.assertEqual(['sheets.googleapis.com']*4+['oauth2.googleapis.com'],[host for host,_ in built])

    def _assert_original_stat_preserved(self, before, after):
        # Reads may update atime. Preserve every persistent identity/permission/
        # content-size/change field instead, including sub-second timestamps.
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns')
        self.assertEqual(tuple(getattr(before, name) for name in fields),
                         tuple(getattr(after, name) for name in fields))

    def test_preservation_oracle_allows_read_atime_but_refuses_all_persistent_stat_drift(self):
        from types import SimpleNamespace
        values = dict(st_dev=11, st_ino=23, st_mode=0o100600, st_uid=501,
            st_gid=20, st_nlink=1, st_size=41, st_mtime_ns=100000003,
            st_ctime_ns=200000005, st_atime_ns=300000007)
        original = SimpleNamespace(**values)
        read_only = SimpleNamespace(**{**values, 'st_atime_ns': 400000009})
        self._assert_original_stat_preserved(original, read_only)
        for field in tuple(values):
            if field == 'st_atime_ns':
                continue
            with self.subTest(field=field), self.assertRaises(AssertionError):
                self._assert_original_stat_preserved(original,
                    SimpleNamespace(**{**values, field: values[field]+1}))

    def test_actual_default_worker_qualifies_before_lazy_oauth_and_retains_nine_original_images(self):
        observed = []
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_cabling_insert_probe=True, receipted_intent_probe=True,
            native_catalog_probe=True, native_catalog_c6_origin_probe=True,
            native_catalog_retained_probe=True,
            native_catalog_launch_probe=('default-worker-original-images', observed))
        self.assertEqual(['ETH Cabling:actual-default-worker:nine-original-images:hold',
            'IB Cabling:actual-default-worker:nine-original-images:hold'], observed)

    def test_actual_default_worker_dedicated_quota_originals_outlive_strict_input_finalizers(self):
        self._exercise_default_dedicated_quota_originals()

    def _exercise_default_dedicated_quota_originals(self, *, retry_probe=False):
        from test_cases import test_req7_spreadsheet_owner as owner_fixture
        from test_cases import test_req7_metadata_reservation as quota_fixture
        from test_cases.test_req7_sheets_read_decode import identity_response
        from monitor import issue_tracker_local_commit as local
        real_fixture=owner_fixture.scoped_fixture;real_load=quota_fixture.load
        roots={};created=[];received=[];post_strict=[];closed=[];graphs=[];exited=[]
        with ExitStack() as patches:
            @contextmanager
            def actual_fixture(root,module):
                if module.__name__=='monitor.issue_tracker_spreadsheet_owner':roots[id(module)]=root
                with real_fixture(root,module):yield
            def loaded_quota():
                module=real_load();actual_overlap=module._hold_owned_project_dedicated_quota_images
                # This NEW fixture creates genuine authenticated quota originals
                # from fresh native OAuth/TLS reads. Never edit a legacy HEADER,
                # derive expectations from it or patch a production predicate.
                def prepare(owner,bound,_identity,unit,_plan,raw):
                    ownership=module.ownership;root=roots[id(ownership)]
                    writers=[writer for writer in local._ACTIVE if local._owner(writer).project==self.project]
                    self.assertEqual(1,len(writers));writer=writers[0]
                    native=quota_fixture.Req7MetadataReservationProjectWorkflowTests()
                    native.root=root;native.path=root/'etc/ssl/certs/ca-certificates.crt'
                    native.path.parent.mkdir(parents=True,exist_ok=True);native.addCleanup=self.addCleanup
                    with ExitStack() as scope:
                        auth,_credential,_bytes=native.project_auth(scope,ownership,owner,bound)
                        native.certificates('sheets.googleapis.com')
                        def original_read(kind,document):
                            import socket
                            from monitor.issue_tracker_history_read_launcher import OwnedProjectSheetsReadUnit
                            # Match the unchanged enrollment/default-worker
                            # wire image exactly. Equivalent JSON with different
                            # spacing has a different immutable identity hash.
                            body=json.dumps(document,allow_nan=False).encode()
                            reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
                            with native.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors),ExitStack() as launched:
                                port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                                calls,children=native.intercept(launched,native.child_fixture(port),writer,owner,bound)
                                result=OwnedProjectSheetsReadUnit(writer,owner,bound,auth,read_kind=kind).read_once()
                            self.assertEqual([],errors);self.assertEqual(1,len(records));self.assertEqual(1,len(calls))
                            self.assertEqual(0,children[0].returncode);self.assertEqual(body,result.data)
                            return result
                        identity_doc=identity_response();identity_doc['spreadsheetId']=bound.spreadsheet_id
                        identity_read=original_read('template_identity',identity_doc)
                        metadata_read=original_read('metadata',json.loads(raw.data))
                        result=module.prepare_owned_project_metadata_reservation(writer,owner,bound,auth,unit,
                            identity_response=identity_read,metadata_response=metadata_read)
                    # The unchanged consumer fixture creates its own CA root
                    # with mkdir(exist_ok=False). Retain our entirely owned
                    # constructor CA elsewhere after all constructor children
                    # have been reaped; do not delete or reuse it as evidence.
                    native.path.parent.rename(root/'constructor-ca-preserved')
                    created.append(unit.unit_id)
                    return result
                @contextmanager
                def overlap(*args,**options):
                    from monitor import issue_tracker_unit_catalog as catalog
                    # Track only the actual overlap's dup calls, not other
                    # graphs or unrelated child descriptor inheritance.
                    duplicates=[];original_dup=os.dup;strict_exits=len(closed)
                    def duplicate(fd):
                        result=original_dup(fd);info=os.fstat(fd)
                        import stat
                        raw=None if stat.S_ISDIR(info.st_mode) else os.pread(fd,info.st_size+1,0)
                        duplicates.append((result,info,raw));return result
                    with mock.patch.object(catalog.os,'dup',side_effect=duplicate):
                        manager=actual_overlap(*args,**options)
                        budget,verify=manager.__enter__()
                    graphs.append(duplicates);received.append((budget.outcome,budget.inventory_complete))
                    # Acquisition is already under the genuine core; its
                    # actual finalizer event is recorded by the wrapper below.
                    def checked():
                        verify()
                        if len(closed)>strict_exits:
                            fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink',
                                'st_size','st_mtime_ns','st_ctime_ns')
                            post_strict.append(tuple((os.fstat(fd),
                                tuple(getattr(os.fstat(fd),name) for name in fields)==tuple(getattr(info,name) for name in fields)
                                and (raw is None or os.pread(fd,len(raw)+1,0)==raw))
                                for fd,info,raw in duplicates))
                    try:
                        yield budget,checked
                    finally:manager.__exit__(*sys.exc_info())
                patches.enter_context(mock.patch.object(module,'prepare_metadata_reservation',side_effect=prepare))
                patches.enter_context(mock.patch.object(module,'_hold_owned_project_dedicated_quota_images',side_effect=overlap))
                return module
            actual_worker=self._default_worker_original_images
            def worker(**arguments):
                from monitor import issue_tracker_remote_history_match as remote
                original_core=remote._hold_current_project_online_inputs
                @contextmanager
                def core(*args,**options):
                    try:
                        with original_core(*args,**options) as packet:yield packet
                    finally: exited.append(arguments['sheet'])
                    closed.append(arguments['sheet'])
                with mock.patch.object(remote,'_hold_current_project_online_inputs',side_effect=core):
                    return actual_worker(**arguments)
            patches.enter_context(mock.patch.object(owner_fixture,'scoped_fixture',side_effect=actual_fixture))
            patches.enter_context(mock.patch.object(quota_fixture,'load',side_effect=loaded_quota))
            patches.enter_context(mock.patch.object(self,'_default_worker_original_images',side_effect=worker))
            observed=[]
            self._exercise_real_protected_three_panel_fixture(skip_history=False,
                observed_cabling_insert_probe=True,receipted_intent_probe=True,native_catalog_probe=True,
                native_catalog_c6_origin_probe=True,native_catalog_retained_probe=True,
                native_catalog_launch_probe=('default-worker-original-images',observed))
        # Independent expectations after actual worker and every sanitizer:
        # two real C6 panels, five quota FDs each still live after strict close,
        # then all owned duplicates closed. The old fixture asserts no COUNT,
        # CLAIM/send, unchanged durable originals/cycles and read-only status.
        self.assertEqual(2,len(created))
        self.assertEqual([('DEDICATED_PROJECT_CAPACITY',True)]*(4 if retry_probe else 2),received)
        expected_panels = ['ETH Cabling','ETH Cabling','IB Cabling','IB Cabling'] if retry_probe else ['ETH Cabling','IB Cabling']
        self.assertEqual(expected_panels, exited)
        self.assertEqual(expected_panels, closed); self.assertTrue(post_strict)
        self.assertEqual([5,5,5,5] if retry_probe else [5,5],[len(items) for items in graphs])
        for originals in post_strict:self.assertTrue(all(preserved for _info,preserved in originals))
        for originals in graphs:
            for fd,_info,_raw in originals:
                with self.assertRaises(OSError):os.fstat(fd)

    def test_actual_default_worker_all_write_originals_outlive_strict_input_finalizers(self):
        actual_worker=self._default_worker_original_images;received=[];post_strict=[];completed=[];packets=[]
        tail_inputs=[];tail_errors=[]
        def worker(**arguments):
            from monitor import issue_tracker_remote_history_match as remote
            from monitor import issue_tracker_global_attempt_journal as globals_
            from monitor import issue_tracker_stage_l_consumer as source
            from monitor import issue_tracker_cycle_source as cycles
            original_core=remote._hold_current_project_online_inputs
            original_all=globals_._hold_selected_last_catalog_write_originals
            original_inputs=source._hold_original_replay_inputs
            closed=[];active_inputs={};input_sequence=[]
            @contextmanager
            def inputs(*args,**options):
                key=len(input_sequence);input_sequence.append(key)
                try:
                    with original_inputs(*args,**options) as original:
                        active_inputs[key]=original;yield original
                finally:active_inputs.pop(key,None)
            @contextmanager
            def core(*args,**options):
                with original_core(*args,**options) as packet:packets.append(packet);yield packet
                closed.append(True)
            @contextmanager
            def all_originals(writer,token,bound,unit):
                with original_all(writer,token,bound,unit) as original:
                    received.append((arguments['sheet'],unit));original()
                    def verify():
                        original()
                        if closed:post_strict.append(arguments['sheet'])
                    yield verify
                completed.append(arguments['sheet'])
                active=cycles._HELD_CYCLE_REPLAY.get()
                tail_inputs.append((arguments['sheet'],active is not None and active[0] is self.store,bool(active_inputs)))
                try:
                    cycles._require_live_cycle_replay(active);active[1]()
                    for original in active_inputs.values():original()
                except Exception as error:tail_errors.append(type(error).__name__)
            with mock.patch.object(remote,'_hold_current_project_online_inputs',side_effect=core), \
                    mock.patch.object(globals_,'_hold_selected_last_catalog_write_originals',side_effect=all_originals), \
                    mock.patch.object(source,'_hold_original_replay_inputs',side_effect=inputs):
                return actual_worker(**arguments)
        with mock.patch.object(self,'_default_worker_original_images',side_effect=worker):
            observed=[]
            self._exercise_real_protected_three_panel_fixture(skip_history=False,
                observed_cabling_insert_probe=True,receipted_intent_probe=True,native_catalog_probe=True,
                native_catalog_c6_origin_probe=True,native_catalog_retained_probe=True,
                native_catalog_launch_probe=('default-worker-original-images',observed))
        # These independent observations are outside production HOLD sanitizers.
        # The unchanged actual fixture proves 8 fresh reads, zero COUNT/CLAIM/
        # request, original durable files/cycles and business-FD cleanup.
        self.assertEqual(['ETH Cabling','IB Cabling'],[sheet for sheet,_unit in received])
        self.assertEqual(['ETH Cabling','IB Cabling'],completed)
        self.assertEqual({'ETH Cabling','IB Cabling'},set(post_strict));self.assertEqual(2,len(packets))
        self.assertEqual([('ETH Cabling',True,True),('IB Cabling',True,True)],tail_inputs,
            'actual cycle/policy/W1 originals must remain live through the LAST ALL finalizer')
        self.assertEqual([],tail_errors)
        for (_sheet,unit),packet in zip(received,packets):
            self.assertIs(unit,packet[3][-1][0].unit,'borrow actual prepared last unit, never a reconstructed locator object')

    def test_actual_default_live_input_context_holds_selected_images_and_dedicated_quota(self):
        from monitor import issue_tracker_remote_history_match as remote
        api=getattr(remote,'_hold_current_project_online_original_inputs',None)
        self.assertTrue(callable(api),'default dispatch cannot adopt images returned after original cleanup')
        entered=[];completed=[];originals=[]
        @contextmanager
        def held(writer,owner,bound,authentication,**options):
            from monitor import issue_tracker_cycle_source as current_cycles
            from monitor import issue_tracker_history_read_launcher as current_reads
            from monitor import issue_tracker_token_launcher as current_tokens
            from monitor import issue_tracker_history_preread_journal as current_preread
            with actual_api(writer,owner,bound,authentication,**options) as packet:
                self.assertEqual(6,len(packet))
                settings,whitelist,responses,graph,actual_auth,budget=packet
                row,actual_source,guard,image,verify=graph
                self.assertEqual('DEDICATED_PROJECT_CAPACITY',budget.outcome)
                self.assertTrue(budget.inventory_complete)
                self.assertIs(image[0],responses['template_identity'])
                self.assertIs(self.store,current_cycles._HELD_CYCLE_REPLAY.get()[0])
                current_cycles._require_live_cycle_replay(current_cycles._HELD_CYCLE_REPLAY.get())
                with current_preread._BUSINESS_READ_GUARD_LOCK:
                    self.assertEqual('CLOSED',current_preread._BUSINESS_READ_GUARDS[guard][0])
                with self.assertRaises(current_preread.HistoryPrereadHold):guard()
                verify()
                for kind,response in responses.items():
                    current_reads.require_current_owned_project_read(writer,owner,bound,response,actual_auth,read_kind=kind)
                current_tokens.require_current_owned_project_token(owner,bound,actual_auth)
                self.assertTrue(actual_source.cycle_ids);self.assertEqual(settings.k,actual_source.k)
                entered.append(row.unit.unit_id);originals.append((guard,image,verify,current_preread.HistoryPrereadHold))
                yield packet
            completed.append(row.unit.unit_id)
        # The entire unchanged native dedicated-quota workflow still proves
        # actual C6/OAuth/TLS/8 reads, no COUNT/CLAIM/send, immutable originals
        # and all owned image descriptors closed after both panels finish.
        actual_worker=self._default_worker_original_images;actual_api=None
        def worker(**arguments):
            nonlocal actual_api
            from monitor import issue_tracker_remote_history_match as current_remote
            # The genuine fixture intentionally reloads canonical components.
            # Bind this observation only at the actual worker's live boundary,
            # not to a stale pre-fixture module object.
            actual_api=current_remote._hold_current_project_online_original_inputs
            with mock.patch.object(current_remote,'_hold_current_project_online_original_inputs',side_effect=held):
                return actual_worker(**arguments)
        with mock.patch.object(self,'_default_worker_original_images',side_effect=worker):
            self.test_actual_default_worker_dedicated_quota_originals_outlive_strict_input_finalizers()
        self.assertEqual(2,len(entered));self.assertEqual(entered,completed)
        self.assertEqual(2,len(set(entered)))
        for guard,_image,verify,typed_hold in originals:
            with self.assertRaises(typed_hold):verify()

    def test_actual_fixed_default_first_dispatch_retains_original_context_through_native_claim(self):
        from test_cases.test_collection_cycle_persistence import WORKER
        self.assertTrue(callable(getattr(WORKER,'_dispatch_current_project_online_originals',None)),
            'fixed driver must compose actual default images and existing original FIRST/CLAIM')
        actual_worker=self._default_worker_original_images;completed=[]
        def worker(**arguments):
            result=actual_worker(**arguments,dispatch_probe=True)
            completed.append(arguments['sheet']);return result
        # Genuine dedicated quota construction and both original C6 panels;
        # all prior zero-count tests keep their original default fixture lane.
        with mock.patch.object(self,'_default_worker_original_images',side_effect=worker):
            self.test_actual_default_worker_dedicated_quota_originals_outlive_strict_input_finalizers()
        self.assertEqual(['ETH Cabling','IB Cabling'],completed)

    def test_actual_terminal_default_first_hook_keeps_native_c6_quota_claim_and_unknown_wire(self):
        from test_cases.test_collection_cycle_persistence import WORKER
        self.assertTrue(callable(getattr(WORKER, '_dispatch_issue_tracker_online_after_completion', None)),
            'the terminal owner scope must run fixed FIRST without a closed observation permit')
        actual_worker = self._default_worker_original_images; completed = []
        def worker(**arguments):
            result = actual_worker(**arguments, dispatch_probe=True, terminal_dispatch_probe=True)
            completed.append(arguments['sheet']); return result
        with mock.patch.object(self, '_default_worker_original_images', side_effect=worker):
            self._exercise_default_dedicated_quota_originals()
        self.assertEqual(['ETH Cabling', 'IB Cabling'], completed)

    def test_actual_fixed_default_retry_reopens_owned_reads_and_keeps_identical_unknown_wire(self):
        actual_worker=self._default_worker_original_images;completed=[]
        def worker(**arguments):
            actual_worker(**arguments,dispatch_probe=True)
            result=actual_worker(**arguments,dispatch_probe=True,retry_probe=True)
            completed.append(arguments['sheet']);return result
        with mock.patch.object(self,'_default_worker_original_images',side_effect=worker):
            self._exercise_default_dedicated_quota_originals(retry_probe=True)
        self.assertEqual(['ETH Cabling','IB Cabling'],completed)

    def test_actual_terminal_default_retry_reconciles_original_unknown_before_identical_second_wire(self):
        actual_worker = self._default_worker_original_images; completed = []
        def worker(**arguments):
            actual_worker(**arguments, dispatch_probe=True, terminal_dispatch_probe=True)
            result = actual_worker(**arguments, dispatch_probe=True, retry_probe=True,
                terminal_dispatch_probe=True)
            completed.append(arguments['sheet']); return result
        with mock.patch.object(self, '_default_worker_original_images', side_effect=worker):
            self._exercise_default_dedicated_quota_originals(retry_probe=True)
        self.assertEqual(['ETH Cabling', 'IB Cabling'], completed)

    def test_actual_terminal_conflicting_history_stops_before_second_count_or_current_reads(self):
        actual_worker = self._default_worker_original_images; completed = []
        def worker(**arguments):
            actual_worker(**arguments, dispatch_probe=True, terminal_dispatch_probe=True)
            result = actual_worker(**arguments, dispatch_probe=True, retry_probe=True,
                terminal_dispatch_probe=True, original_conflict_probe=True)
            completed.append(arguments['sheet']); return result
        # Only FIRST reaches the current source/quota graph. The conflict is
        # decoded from a real subsequent historical TLS read, not a supplied
        # observation or a patched reconciliation result.
        with mock.patch.object(self, '_default_worker_original_images', side_effect=worker):
            self._exercise_default_dedicated_quota_originals()
        self.assertEqual(['ETH Cabling', 'IB Cabling'], completed)

    def test_actual_terminal_post_count_read_expiry_keeps_unknown_without_claim_send_or_empty_status(self):
        actual_worker = self._default_worker_original_images; completed = []
        def worker(**arguments):
            result = actual_worker(**arguments, dispatch_probe=True, terminal_dispatch_probe=True,
                post_count_expiry_probe=True)
            completed.append(arguments['sheet']); return result
        with mock.patch.object(self, '_default_worker_original_images', side_effect=worker):
            self._exercise_default_dedicated_quota_originals()
        self.assertEqual(['ETH Cabling', 'IB Cabling'], completed)

    def _default_worker_original_images(self, *, native, whitelist_doc, private_context,
            global_root, writer_token, spreadsheet_token, binding, unit, qualified,
            settings, quota_raw, history_raw, reads, sheet, state, owner_module, global_journal,
            dispatch_probe=False,retry_probe=False,terminal_dispatch_probe=False,
            original_conflict_probe=False,post_count_expiry_probe=False):
        """Actual worker composition; borrow already-held owners, never mint a permit.

        The surrounding real C6 fixture owns both original locks. Borrow only
        these tokens; this test does not prove first lock acquisition/revocation.
        OAuth/read transport is the existing private native TLS fixture. Source,
        reconciliation, image guards and every strict finalizer remain actual.
        """
        import errno
        import importlib
        import socket
        import stat
        from types import SimpleNamespace
        from test_cases.test_req7_history_read_launcher import scoped_fixture
        from test_cases.test_req7_sdk_authentication import fresh_info
        from test_cases.test_req7_token_launcher import Req7FixedTokenLauncherWorkflowTests
        from test_cases.test_req7_sheets_read_decode import header_response, identity_response, response
        from test_cases.test_collection_cycle_persistence import WORKER as worker
        from monitor import issue_tracker_token_launcher as tokens
        from monitor import issue_tracker_history_read_launcher as fixed_reads
        from monitor import issue_tracker_local_commit as local
        from monitor import issue_tracker_remote_history_match as remote
        from monitor import issue_tracker_stage_l_consumer as source
        from monitor import issue_tracker_history_preread_journal as preread
        from monitor import issue_tracker_mutation_launcher as mutation
        from monitor import issue_tracker_cycle_source as cycles
        sdk = importlib.import_module('monitor.issue_tracker_sdk_authentication')
        private_context.enter_context(scoped_fixture(global_root, sdk))
        credential = global_root/'var/lib/http-ztp-container/service-account/cre.json'
        if not credential.exists():
            info = fresh_info(); info['project_id'] = 'synthetic-cloud-project'
            credential.write_bytes(json.dumps(info).encode()); credential.chmod(0o600)
        credential_original = credential.read_bytes()
        before = {str(path.relative_to(state)): (path.stat().st_ino, path.read_bytes())
            for path in state.rglob('*') if path.is_file()}
        cycle_before = {str(path): (path.stat().st_ino, path.read_bytes())
            for path in self.store.status_dir.rglob('*') if path.is_file()}
        writer_original = local._owner(writer_token)
        owner_original = owner_module._validated_owner(spreadsheet_token, binding)
        real_refresh = tokens.OwnedProjectTokenRefreshUnit.refresh_once
        real_read = fixed_reads.OwnedProjectSheetsReadUnit.read_once
        real_source = source.qualify_prod_stage_l
        real_reconcile = remote._reconcile_pending_project_units_and_project_auth
        real_consume = remote._consume_current_project_online_original_inputs
        real_core = remote._hold_current_project_online_inputs
        real_images = preread._OriginalBusinessReadGuard._hold_original_images
        real_inputs = source._hold_original_replay_inputs
        real_send=mutation._send_counted_original_once
        real_dup = os.dup
        issued = []; oauth = []; projections = []; reconciled = []; consumed = []
        graphs = []; packets = []; core_closed = []; after_strict = []; input_verified = []
        documents = {'template_identity': identity_response(), 'template_headers': header_response(),
            'whitelist': whitelist_doc, 'metadata': json.loads(quota_raw.data),
            'history_tail': json.loads(history_raw.data),
            'activity': json.loads(reads[0]['discovery_response'].data),
            'insertion': json.loads(reads[0]['occupancy_response'].data),
            'row': json.loads(next(item['row_response'].data for item in reads if item['row_response'] is not None))}
        if original_conflict_probe:
            self.assertTrue(dispatch_probe and retry_probe and terminal_dispatch_probe)
            documents['history_tail']['sheets'][0]['data'][0].setdefault('rowData', []).append(
                {'values': [{'userEnteredValue': {'stringValue': 'foreign append'}}]})
        @contextmanager
        def borrowed_writer(project, publication):
            self.assertEqual((self.project, self.publication), (project, publication))
            self.assertIs(writer_original, local._owner(writer_token))
            yield writer_token
            self.assertIs(writer_original, local._owner(writer_token))
        @contextmanager
        def borrowed_owner(actual_binding):
            self.assertEqual(binding, actual_binding)
            self.assertIs(owner_original, owner_module._validated_owner(spreadsheet_token, binding))
            yield spreadsheet_token
            self.assertIs(owner_original, owner_module._validated_owner(spreadsheet_token, binding))
        def qualify(*args, **options):
            value = real_source(*args, **options); projections.append(value); return value
        def refresh(refresh_unit):
            if terminal_dispatch_probe and retry_probe:
                # The terminal entry authenticates the existing counted unit
                # before qualifying the current cycle for a new opportunity.
                self.assertEqual([], projections); self.assertEqual([], reconciled)
            else:
                self.assertTrue(projections, 'genuine qualified source must precede the first OAuth child')
                self.assertEqual([] if retry_probe else [((), None, 0)], reconciled)
            body = b'{"access_token":"owned-project-token","expires_in":3600}'
            reply = b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
            with native.server(reply) as (records, errors), ExitStack() as launched:
                port = socket.getaddrinfo('oauth2.googleapis.com',443)[0][4][1]
                program = Req7FixedTokenLauncherWorkflowTests.child_fixture(native,port,project_scope=True)
                original_popen = subprocess.Popen; children = []
                def launch(argv, **options):
                    self.assertEqual([str(Path(sys.executable).resolve()),'-I','-B','-c'],argv[:4])
                    self.assertEqual(tokens._PROJECT_CHILD_PROGRAM,argv[4])
                    self.assertEqual(str(Path(__file__).resolve().parents[1]),argv[5])
                    self.assertEqual(7,len(argv)); self.assertEqual({'LC_ALL':'C'},options['env'])
                    self.assertIs(subprocess.DEVNULL,options['stdin'])
                    self.assertEqual((owner_module.owner_lock_fd(spreadsheet_token,binding),),options['pass_fds'])
                    changed = list(argv); changed[4] = program
                    child = original_popen(changed,**options); children.append(child); return child
                launched.enter_context(mock.patch.object(tokens,'subprocess',SimpleNamespace(
                    Popen=launch,PIPE=subprocess.PIPE,DEVNULL=subprocess.DEVNULL)))
                with self.assertWarnsRegex(FutureWarning,'Python version 3.9 past its end of life') if sys.version_info[:2]==(3,9) else ExitStack():
                    actual = real_refresh(refresh_unit)
                self.assertEqual(1,len(children)); self.assertEqual(0,children[0].returncode)
                self.assertTrue(children[0].stdout.closed); self.assertTrue(children[0].stderr.closed)
            self.assertEqual([],errors); self.assertEqual(1,len(records))
            self.assertEqual(credential_original,credential.read_bytes())
            oauth.append(actual)
            native.certificates('sheets.googleapis.com')
            return actual
        def read(reader):
            self.assertEqual(1,len(oauth))
            if terminal_dispatch_probe and retry_probe and not projections:
                self.assertEqual([], reconciled)
                self.assertIn(reader._kind, ('template_identity', 'template_headers', 'metadata', 'history_tail'))
            else:
                self.assertTrue(projections)
            body = response(documents[reader._kind]).data
            reply = b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
            with native.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors), ExitStack() as launched:
                port = socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                calls,children = native.intercept(launched,native.child_fixture(port),writer_token,spreadsheet_token,binding)
                actual = real_read(reader)
            issued.append((reader._kind,len(records),len(calls),tuple(errors),children[0].returncode))
            return actual
        def reconcile(*args, **options):
            actual = real_reconcile(*args, **options)
            reconciled.append((*actual,len(oauth))); return actual
        def consume(*args, **options):
            self.assertEqual((writer_token,spreadsheet_token,binding,None),args)
            self.assertEqual({'_store':self.store,'http_root':self.root},options)
            consumed.append('entered')
            try: real_consume(*args, **options)
            except remote.RemoteHistoryHold:
                consumed.append('actual-typed-hold'); raise
        mutation_facts=[]
        def native_send(writer,owner,bound,token,actual_unit,image):
            from test_cases.test_req7_mutation_launcher import Req7MutationLauncherWorkflowTests
            self.assertEqual((writer_token,spreadsheet_token,binding),(writer,owner,bound))
            self.assertEqual(unit,actual_unit)
            self.assertIs(packets[0][3][0][0].unit,actual_unit)
            reply=b'HTTP/1.1 401 Denied\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
            with native.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors),ExitStack() as launched:
                port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                native_popen=subprocess.Popen;children=[];calls=[]
                def launch(argv,**options):
                    self.assertEqual([str(Path(sys.executable).resolve()),'-I','-B','-c',mutation._CHILD_PROGRAM,
                        str(Path(__file__).resolve().parents[1])],argv[:6])
                    self.assertEqual([str(image.action_fd),str(image.fd)],argv[7:])
                    self.assertEqual((writer_original.lock_fd,owner_module.owner_lock_fd(owner,bound),
                        image.action_fd,image.fd),options['pass_fds'])
                    self.assertEqual({'LC_ALL':'C'},options['env']);self.assertNotIn(token.value,repr(argv))
                    self.assertTrue(options['close_fds']);self.assertTrue(options['start_new_session'])
                    changed=list(argv);changed[4]=Req7MutationLauncherWorkflowTests.child_fixture(native,port)
                    child=native_popen(changed,**options);children.append(child);calls.append(argv)
                    from test_cases.test_req7_native_supervised_workflow import cleanup_owned_fixture_child
                    self.addCleanup(cleanup_owned_fixture_child,child);return child
                launched.enter_context(mock.patch.object(mutation,'subprocess',SimpleNamespace(Popen=launch,PIPE=subprocess.PIPE)))
                result=real_send(writer,owner,bound,token,actual_unit,image)
            self.assertEqual([],errors);self.assertEqual(1,len(records));self.assertEqual(unit.wire_bytes,records[0][2])
            self.assertEqual(1,len(calls));self.assertEqual(0,children[0].returncode)
            self.assertTrue(all(stream.closed for stream in (children[0].stdin,children[0].stdout,children[0].stderr)))
            mutation_facts.append((result.attempt_count,result.status,result.outcome,result.termination_confirmed))
            return result
        @contextmanager
        def held_inputs(*args, **options):
            with real_inputs(*args, **options) as actual_verify:
                def verify():
                    actual_verify()
                    input_verified.append((bool(core_closed),len(graphs)))
                yield verify
        @contextmanager
        def core(*args, **options):
            with real_core(*args, **options) as packet:
                packets.append(packet); yield packet
            core_closed.append(True)
        @contextmanager
        def images(guard):
            duplicates = []
            def duplicate(fd):
                value = real_dup(fd); info = os.fstat(fd)
                duplicates.append((value,info,None if stat.S_ISDIR(info.st_mode) else os.pread(fd,info.st_size+1,0)))
                return value
            # Patch this module's OS facade, not the shared os.dup function.
            # FIRST/CLAIM also duplicates temporary original descriptors in
            # other real modules; those are not this nine-image graph and may
            # legitimately close before the next image verification.
            image_os=SimpleNamespace(**{name:getattr(preread.os,name) for name in dir(preread.os)})
            image_os.dup=duplicate
            with mock.patch.object(preread,'os',image_os):
                with real_images(guard) as packet:
                    self.assertIs(real_dup,os.dup)
                    graphs.append((guard,duplicates,packet))
                    def verify():
                        packet[1]()
                        if core_closed:
                            with preread._BUSINESS_READ_GUARD_LOCK:
                                phase = preread._BUSINESS_READ_GUARDS[guard][0]
                            after_strict.append((phase,cycles._HELD_CYCLE_REPLAY.get()[0],
                                tuple((os.fstat(fd),None if raw is None else os.pread(fd,len(raw)+1,0))
                                    for fd,_info,raw in duplicates)))
                    yield packet[0],verify
        with ExitStack() as boundary:
            if post_count_expiry_probe:
                self.assertTrue(dispatch_probe and terminal_dispatch_probe and not retry_probe)
                # The continuously held FIRST lane performs its own original
                # checks around this primitive; it does not call the separate
                # record_receipted_original_attempt_intent helper.
                actual_counter = global_journal.record_global_attempt_intent
                actual_clock = fixed_reads._monotonic; expired = []
                def expire_after_original_count(*args, **options):
                    counted = actual_counter(*args, **options)
                    expired.append(counted.attempt_count)
                    return counted
                boundary.enter_context(mock.patch.object(fixed_reads, '_monotonic',
                    side_effect=lambda: actual_clock()+(31 if expired else 0)))
                import io
                diagnostic = boundary.enter_context(mock.patch.object(worker.sys, 'stderr', io.StringIO()))
            boundary.enter_context(mock.patch.object(local,'try_writer_owner',side_effect=borrowed_writer))
            boundary.enter_context(mock.patch.object(owner_module,'spreadsheet_owner',side_effect=borrowed_owner))
            boundary.enter_context(mock.patch.object(source,'qualify_prod_stage_l',side_effect=qualify))
            boundary.enter_context(mock.patch.object(tokens.OwnedProjectTokenRefreshUnit,'refresh_once',autospec=True,side_effect=refresh))
            boundary.enter_context(mock.patch.object(fixed_reads.OwnedProjectSheetsReadUnit,'read_once',autospec=True,side_effect=read))
            boundary.enter_context(mock.patch.object(remote,'_reconcile_pending_project_units_and_project_auth',side_effect=reconcile))
            boundary.enter_context(mock.patch.object(remote,'_consume_current_project_online_original_inputs',side_effect=consume))
            boundary.enter_context(mock.patch.object(remote,'_hold_current_project_online_inputs',side_effect=core))
            boundary.enter_context(mock.patch.object(source,'_hold_original_replay_inputs',side_effect=held_inputs))
            boundary.enter_context(mock.patch.object(preread._OriginalBusinessReadGuard,'_hold_original_images',images))
            old_prepare = boundary.enter_context(mock.patch.object(remote,'_prepare_current_project_online_observation'))
            no_first = boundary.enter_context(mock.patch.object(global_journal,'_hold_continuous_owned_attempt_wire',
                side_effect=global_journal._hold_continuous_owned_attempt_wire if dispatch_probe else None))
            no_retry = boundary.enter_context(mock.patch.object(global_journal,'_hold_shared_retry_owned_attempt_wire',
                side_effect=global_journal._hold_shared_retry_owned_attempt_wire if dispatch_probe else None))
            no_claim = boundary.enter_context(mock.patch.object(global_journal,'_hold_counted_original_wire',
                side_effect=global_journal._hold_counted_original_wire if dispatch_probe else None))
            no_count = boundary.enter_context(mock.patch.object(global_journal,'record_global_attempt_intent',
                **({'side_effect': expire_after_original_count} if post_count_expiry_probe
                   else {'wraps': global_journal.record_global_attempt_intent})))
            no_send = boundary.enter_context(mock.patch.object(mutation,'_send_counted_original_once',
                side_effect=native_send if dispatch_probe else None))
            boundary.enter_context(mock.patch.object(worker,'STATUS_DIR',self.root/'monitor/status'))
            if dispatch_probe:
                from monitor.issue_tracker_online_target import _hold_current_project_online_target
                if retry_probe:
                    from monitor import issue_tracker_admission as admission
                    from monitor.issue_tracker_local_workbook_commit import _latest_receipted_prod_xlsx
                    from tools.project_contract import MIN_CONTINUOUS_INTERVAL_MINUTES
                    prior=admission.read_shared_local_admission(writer_token,self.store,
                        _latest_receipted_prod_xlsx(writer_token,self.snapshot.workbook_sha256))
                    self.assertEqual(1,global_journal.inspect_global_unit(spreadsheet_token,binding,unit).attempt_count)
                    # Only the fixture's elapsed shared interval is supplied.
                    # The production driver obtains its own boot/time; the
                    # real opportunity still validates/persists the prior floor.
                    now=prior['monotonic_ns']+MIN_CONTINUOUS_INTERVAL_MINUTES*60*1_000_000_000
                    boundary.enter_context(mock.patch.object(worker,'_current_boot_identity',return_value=prior['boot_id']))
                    boundary.enter_context(mock.patch.object(worker,'time',SimpleNamespace(monotonic_ns=lambda:now)))
                    boundary.enter_context(mock.patch.object(admission,'time',SimpleNamespace(monotonic_ns=lambda:now)))
                # Restore the real outer prerequisites of the default worker,
                # not a fabricated target/cycle callback or a caller GO.
                if terminal_dispatch_probe:
                    observations = worker._dispatch_issue_tracker_online_after_completion(self.store)
                    if retry_probe:
                        self.assertEqual(1, len(observations))
                        self.assertEqual(('CONFLICT' if original_conflict_probe else 'UNKNOWN', 1),
                            (observations[0].state, observations[0].attempt_count))
                    else:
                        self.assertEqual((), observations)
                    status = json.loads((self.root/'monitor/status/issue-tracker-online.status.json').read_bytes())
                    expected_status = ('conflict' if original_conflict_probe else
                        'attempt_unproved' if post_count_expiry_probe else 'attempted_unknown')
                    self.assertEqual((1, expected_status, True, True),
                        (status['schema_version'], status['state'], status['read_only'], status['mutation_disabled']))
                else:
                    with cycles._hold_current_completed_cycle_replay(self.store) as verify_cycles, \
                        _hold_current_project_online_target(writer_token) as actual_binding:
                        self.assertEqual(binding,actual_binding);verify_cycles()
                        if not retry_probe:
                            self.assertEqual(((),None),remote._reconcile_pending_project_units_and_project_auth(
                                writer_token,spreadsheet_token,actual_binding,_store=self.store))
                        dispatched=worker._dispatch_current_project_online_originals(writer_token,spreadsheet_token,actual_binding,None,
                            _store=self.store,http_root=self.root)
                        verify_cycles()
                    self.assertEqual((2 if retry_probe else 1,401,'UNKNOWN',True),(dispatched.attempt_count,dispatched.status,
                        dispatched.outcome,dispatched.termination_confirmed))
            else:self.assertEqual((),worker._reconcile_issue_tracker_online_after_completion(self.store))
        # Independent facts outside the worker/core exception sanitizers.
        self.assertEqual([] if dispatch_probe else ['entered','actual-typed-hold'],consumed)
        if post_count_expiry_probe:
            self.assertEqual([1], expired)
            self.assertEqual('Issue Tracker online attempt unproved; original count/UNKNOWN retained; mutation disabled\n',
                diagnostic.getvalue())
            self.assertEqual([((), None, 0)], reconciled); self.assertEqual(1, len(oauth))
            self.assertTrue(projections); self.assertTrue(all(value == qualified for value in projections))
            self.assertEqual([(kind, 1, 1, (), 0) for kind in ('template_identity', 'template_headers',
                'whitelist', 'metadata', 'history_tail', 'activity', 'insertion', 'row')], issued)
            self.assertEqual(1, len(packets)); self.assertEqual(1, len(graphs))
            self.assertEqual(9, len(graphs[0][1])); self.assertEqual([], mutation_facts)
            for fd, _info, _raw in graphs[0][1]:
                with self.assertRaises(OSError) as caught: os.fstat(fd)
                self.assertEqual(errno.EBADF, caught.exception.errno)
            old_prepare.assert_not_called(); no_first.assert_called_once(); no_retry.assert_not_called()
            no_count.assert_called_once(); no_claim.assert_not_called(); no_send.assert_not_called()
            original_intent = global_journal.inspect_global_unit(spreadsheet_token, binding, unit)
            self.assertEqual((1, 'UNKNOWN'), (original_intent.attempt_count, original_intent.outcome))
            self.assertEqual(['ATTEMPT-1'], sorted(path.name for path in state.rglob('ATTEMPT-*')))
            self.assertFalse(list(state.rglob('CLAIM-*'))); self.assertFalse(list(state.rglob('COMPLETE')))
            after = {str(path.relative_to(state)): (path.stat().st_ino, path.read_bytes())
                for path in state.rglob('*') if path.is_file()}
            self.assertEqual(before, {name: after[name] for name in before})
            stem = hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()+'.unit-'+unit.unit_id
            self.assertEqual({stem+'.journal/ATTEMPT-1'}, set(after)-set(before))
            self.assertEqual(cycle_before, {str(path): (path.stat().st_ino, path.read_bytes())
                for path in self.store.status_dir.rglob('*') if path.is_file()})
            return sheet+':actual-default-worker:post-count-expiry:unknown-no-claim-send'
        if original_conflict_probe:
            self.assertEqual(1, len(reconciled))
            original_observations, auth, refresh_count = reconciled[0]
            self.assertEqual([('CONFLICT', 1)],
                [(item.state, item.attempt_count) for item in original_observations])
            self.assertIs(oauth[0], auth); self.assertEqual(1, refresh_count)
            self.assertEqual(1, len(oauth))
            self.assertEqual([(kind, 1, 1, (), 0) for kind in
                ('template_identity', 'template_headers', 'metadata', 'history_tail')], issued)
            for values in (projections, packets, graphs, core_closed, mutation_facts):
                self.assertEqual([], values)
            for operation in (old_prepare, no_first, no_retry, no_claim, no_count, no_send):
                operation.assert_not_called()
            original_intent = global_journal.inspect_global_unit(spreadsheet_token, binding, unit)
            self.assertEqual((1, 'UNKNOWN'), (original_intent.attempt_count, original_intent.outcome))
            self.assertEqual(['ATTEMPT-1'], sorted(path.name for path in state.rglob('ATTEMPT-*')))
            self.assertEqual(['CLAIM-1'], sorted(path.name for path in state.rglob('CLAIM-*')))
            self.assertEqual(before, {str(path.relative_to(state)): (path.stat().st_ino, path.read_bytes())
                for path in state.rglob('*') if path.is_file()})
            self.assertEqual(cycle_before, {str(path): (path.stat().st_ino, path.read_bytes())
                for path in self.store.status_dir.rglob('*') if path.is_file()})
            self.assertFalse(list(state.rglob('COMPLETE')))
            return sheet+':actual-default-worker:original-conflict:no-second-attempt'
        if terminal_dispatch_probe and retry_probe:
            self.assertEqual(1, len(reconciled))
            observations, auth, refresh_count = reconciled[0]
            self.assertEqual(1, len(observations))
            self.assertEqual(('UNKNOWN', 1), (observations[0].state, observations[0].attempt_count))
            self.assertIs(oauth[0], auth); self.assertEqual(1, refresh_count)
        else:
            self.assertEqual([] if retry_probe else [((),None,0)],reconciled)
        self.assertEqual(1,len(oauth))
        self.assertTrue(projections); self.assertTrue(all(value==qualified for value in projections))
        historical_kinds = ('template_identity', 'template_headers', 'metadata', 'history_tail') \
            if terminal_dispatch_probe and retry_probe else ()
        self.assertEqual([(kind,1,1,(),0) for kind in historical_kinds + ('template_identity','template_headers',
            'whitelist','metadata','history_tail','activity','insertion','row')],issued)
        self.assertEqual(1,len(packets)); self.assertEqual(1,len(graphs)); self.assertEqual([True],core_closed)
        actual_settings,_whitelist,responses,prepared,authentication = packets[0]
        self.assertEqual(settings,actual_settings); self.assertIs(oauth[0],authentication)
        self.assertEqual(1,len(prepared)); row,actual_source,guard = prepared[0]
        self.assertEqual(unit,row.unit); self.assertEqual(qualified,actual_source)
        self.assertIs(guard,graphs[0][0]); self.assertIs(responses['template_identity'],graphs[0][2][0][0])
        self.assertEqual(9,len(graphs[0][1]))
        self.assertEqual(2,sum(stat.S_ISDIR(info.st_mode) for _,info,_ in graphs[0][1]))
        self.assertIn((True,1),input_verified,'actual outer original-input verifier must succeed after strict closure')
        self.assertTrue(after_strict,'genuine nine-FD graph must remain verifiable after strict closure')
        for phase,store,originals in after_strict:
            self.assertEqual('CLOSED',phase); self.assertIs(self.store,store)
            self.assertEqual(tuple((info,raw) for _fd,info,raw in graphs[0][1]),originals)
        for fd,_info,_raw in graphs[0][1]:
            with self.assertRaises(OSError) as caught: os.fstat(fd)
            self.assertEqual(errno.EBADF,caught.exception.errno)
        if dispatch_probe:
            old_prepare.assert_not_called()
            if retry_probe:no_first.assert_not_called();no_retry.assert_called_once()
            else:no_retry.assert_not_called();no_first.assert_called_once()
            for operation in (no_claim,no_count,no_send):operation.assert_called_once()
            expected_count=2 if retry_probe else 1
            self.assertEqual([(expected_count,401,'UNKNOWN',True)],mutation_facts)
            self.assertEqual(expected_count,global_journal.inspect_global_unit(spreadsheet_token,binding,unit).attempt_count)
            self.assertEqual(['ATTEMPT-1','ATTEMPT-2'] if retry_probe else ['ATTEMPT-1'],
                sorted(path.name for path in state.rglob('ATTEMPT-*')))
            self.assertEqual(['CLAIM-1','CLAIM-2'] if retry_probe else ['CLAIM-1'],
                sorted(path.name for path in state.rglob('CLAIM-*')))
            after={str(path.relative_to(state)):(path.stat().st_ino,path.read_bytes())
                for path in state.rglob('*') if path.is_file()}
            self.assertEqual(before,{name:after[name] for name in before})
            stem=hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()+'.unit-'+unit.unit_id
            # Existing durable CLAIM schema has no dispatch-started family.
            # The independent original-claim tests require exactly HEADER,
            # INITIALIZED and CLAIM-1; do not invent a fifth persistence file.
            self.assertEqual({stem+'.journal/ATTEMPT-2',stem+'.dispatch/CLAIM-2'} if retry_probe else
                {stem+'.journal/ATTEMPT-1',stem+'.dispatch/HEADER',stem+'.dispatch/INITIALIZED',stem+'.dispatch/CLAIM-1'},
                set(after)-set(before))
            self.assertFalse((state/(stem+'.dispatch-started')).exists())
            claim=json.loads(after[stem+'.dispatch/CLAIM-'+str(expected_count)][1])
            self.assertEqual((1,unit.unit_id,unit.wire_sha256,expected_count,'CONSUMED_UNKNOWN_NOT_SEND_PROOF'),
                (claim['schema_version'],claim['unit_id'],claim['wire_sha256'],
                 claim['attempt_count'],claim['outcome']))
            self.assertEqual(hashlib.sha256(after[stem+'.journal/ATTEMPT-'+str(expected_count)][1]).hexdigest(),
                claim['original_intent_sha256'])
            self.assertFalse(list(state.rglob('COMPLETE')))
        else:
            for operation in (old_prepare,no_first,no_retry,no_claim,no_count,no_send): operation.assert_not_called()
            self.assertEqual(0,global_journal.inspect_global_unit(spreadsheet_token,binding,unit).attempt_count)
            self.assertFalse(list(state.rglob('ATTEMPT-*'))); self.assertFalse(list(state.rglob('CLAIM-*')))
            self.assertEqual(before,{str(path.relative_to(state)):(path.stat().st_ino,path.read_bytes())
                for path in state.rglob('*') if path.is_file()})
        self.assertEqual(cycle_before,{str(path):(path.stat().st_ino,path.read_bytes())
            for path in self.store.status_dir.rglob('*') if path.is_file()})
        if not dispatch_probe:
            status = json.loads((self.root/'monitor/status/issue-tracker-online.status.json').read_bytes())
            self.assertEqual((1,True,True,'no_counted_units'),
                (status['schema_version'],status['read_only'],status['mutation_disabled'],status['state']))
        observed_label = sheet+':actual-default-worker:nine-original-images:hold'
        return observed_label

    def _fixed_default_original_inputs_probe(self, fault=None):
        from monitor import issue_tracker_remote_history_match as remote
        self.assertTrue(callable(getattr(remote, '_consume_current_project_online_original_inputs', None)),
            'default consumer must overlap genuine originals before closing strict read scopes')
        from test_cases import test_req7_remote_history_match as fixture
        import errno
        import importlib
        import stat
        actual_load = fixture.load; actual_native = self._exercise_native_original_counted_launch
        witnesses = []
        def native_probe(**arguments):
            with ExitStack() as boundary:
                def after_load(*args, **options):
                    result = actual_load(*args, **options)
                    remote = importlib.import_module('monitor.issue_tracker_remote_history_match')
                    preread = importlib.import_module('monitor.issue_tracker_history_preread_journal')
                    catalog = importlib.import_module('monitor.issue_tracker_unit_catalog')
                    cycles = importlib.import_module('monitor.issue_tracker_cycle_source')
                    source_module = importlib.import_module('monitor.issue_tracker_stage_l_consumer')
                    attempts = importlib.import_module('monitor.issue_tracker_global_attempt_journal')
                    real_core = remote._hold_current_project_online_inputs
                    real_images = preread._OriginalBusinessReadGuard._hold_original_images
                    real_catalog = catalog.hold_pending_project_c6_units
                    real_inputs = source_module._hold_original_replay_inputs
                    real_dup = os.dup
                    graphs = []; selected = []; core_closed = []; rebound = []; stopped = []; holder_calls = []
                    preserved_after_refusal = []
                    fixture_restorations = []
                    after_strict = []
                    input_holders = []; input_verifications = []; input_refusals = []
                    @contextmanager
                    def held_inputs(*args, **options):
                        number = len(input_holders); input_holders.append((args,options))
                        with real_inputs(*args, **options) as actual_verify:
                            def verify():
                                # Record the real original verifier's outcome
                                # before production sanitizes it to generic HOLD.
                                stage = (number,bool(core_closed),len(rebound))
                                try:
                                    actual_verify()
                                except Exception as error:
                                    input_refusals.append((stage,error))
                                    raise
                                else:
                                    input_verifications.append(stage)
                            yield verify
                    @contextmanager
                    def core(*args, **options):
                        with real_core(*args, **options) as packet:
                            selected.append(packet)
                            yield packet
                        core_closed.append(True)
                    @contextmanager
                    def images(guard):
                        duplicates = []
                        def duplicate(fd):
                            duplicate = real_dup(fd)
                            info = os.fstat(fd)
                            duplicates.append((duplicate,info,None if stat.S_ISDIR(info.st_mode)
                                else os.pread(fd,info.st_size+1,0)))
                            return duplicate
                        with mock.patch.object(preread.os,'dup',side_effect=duplicate):
                            with real_images(guard) as packet:
                                graphs.append((guard,duplicates,packet))
                                def verify():
                                    packet[1]()
                                    if core_closed:
                                        with preread._BUSINESS_READ_GUARD_LOCK:
                                            phase = preread._BUSINESS_READ_GUARDS[guard][0]
                                        after_strict.append((phase,cycles._HELD_CYCLE_REPLAY.get()[0],
                                            tuple((os.fstat(fd),None if raw is None else os.pread(fd,len(raw)+1,0))
                                                for fd,_info,raw in duplicates)))
                                yield packet[0],verify
                    @contextmanager
                    def held_catalog(*args, **options):
                        first = not holder_calls; holder_calls.append(True)
                        with real_catalog(*args, **options) as packet:
                            yield packet
                        if first and fault:
                            path = (self.project/'01-global.yaml' if fault=='policy' else self.template)
                            info = path.stat(); raw = path.read_bytes()
                            retained = arguments['global_root']/('preserved-default-'+fault)
                            path.rename(retained); path.write_bytes(raw); path.chmod(info.st_mode & 0o777)
                            rebound.append((path,retained,info,raw,path.stat()))
                    def consume(*args, **options):
                        try:
                            remote._consume_current_project_online_original_inputs(*args, **options)
                        except remote.RemoteHistoryHold:
                            stopped.append(True)
                        else:
                            stopped.append(False)
                        # The native fixture legitimately removes its own
                        # temporary root on return. Capture preservation while
                        # it still exists, after actual production refusal.
                        for path,retained,_info,_raw,_replacement in rebound:
                            preserved_after_refusal.append((path.stat(),path.read_bytes(),
                                retained.stat(),retained.read_bytes()))
                            if fault == 'w1':
                                # The original two-sheet fixture independently
                                # binds W1's device/inode, not just its bytes.
                                # Only AFTER the actual consumer has refused
                                # and preservation is witnessed, restore this
                                # fixture's original inode for the next sheet.
                                # Keep the replacement too; never refresh the
                                # old snapshot or alter production cleanup.
                                self.assertEqual([True],stopped)
                                self.assertTrue(input_refusals)
                                self.assertEqual((0,True,1),input_refusals[0][0])
                                self.assertIsInstance(input_refusals[0][1],source_module.StageLConsumerHold)
                                replacement_path = arguments['global_root']/'preserved-default-w1-replacement'
                                self.assertFalse(replacement_path.exists())
                                path.rename(replacement_path)
                                retained.rename(path)
                                fixture_restorations.append((path.stat(),path.read_bytes(),
                                    replacement_path.stat(),replacement_path.read_bytes()))
                        witnesses.append((arguments,graphs,selected,core_closed,rebound,stopped,
                            after_strict,no_first,no_retry,no_claim,input_holders,
                            input_verifications,input_refusals,source_module.StageLConsumerHold,
                            preserved_after_refusal,fixture_restorations))
                        # This adapter exists only inside the original read-only
                        # fixture. Independent checks below require actual HOLD,
                        # not this fixture's diagnostic return or a send permit.
                        return 'VISIBLE_ONLY_UNPROVED'
                    boundary.enter_context(mock.patch.object(remote,'_hold_current_project_online_inputs',side_effect=core))
                    boundary.enter_context(mock.patch.object(remote,'_prepare_current_project_online_observation',side_effect=consume))
                    boundary.enter_context(mock.patch.object(preread._OriginalBusinessReadGuard,'_hold_original_images',images))
                    boundary.enter_context(mock.patch.object(catalog,'hold_pending_project_c6_units',side_effect=held_catalog))
                    boundary.enter_context(mock.patch.object(source_module,'_hold_original_replay_inputs',side_effect=held_inputs))
                    no_first = boundary.enter_context(mock.patch.object(attempts,'_hold_continuous_owned_attempt_wire'))
                    no_retry = boundary.enter_context(mock.patch.object(attempts,'_hold_shared_retry_owned_attempt_wire'))
                    no_claim = boundary.enter_context(mock.patch.object(attempts,'_hold_counted_original_wire'))
                    return result
                boundary.enter_context(mock.patch.object(fixture,'load',side_effect=after_load))
                return actual_native(**arguments)
        with mock.patch.object(self,'_exercise_native_original_counted_launch',side_effect=native_probe):
            self._default_source_read_preparation_probe('prepare-business')
        self.assertEqual(2,len(witnesses))
        for (arguments,graphs,selected,core_closed,rebound,stopped,after_strict,
                no_first,no_retry,no_claim,input_holders,input_verifications,
                input_refusals,actual_hold_type,preserved_after_refusal,fixture_restorations) in witnesses:
            self.assertEqual([True],stopped)
            self.assertEqual(1,len(selected)); self.assertEqual(1,len(graphs))
            settings,whitelist,responses,prepared,authentication = selected[0]
            self.assertEqual(arguments['settings'],settings)
            self.assertEqual(('template_identity','template_headers','whitelist','metadata'),tuple(responses))
            self.assertEqual(1,len(prepared))
            row,source,guard = prepared[0]
            self.assertEqual(arguments['unit'].unit_id,row.unit.unit_id)
            self.assertEqual(arguments['unit'].action_preimage,row.unit.action_preimage)
            self.assertEqual(arguments['unit'].wire_bytes,row.unit.wire_bytes)
            self.assertEqual(arguments['qualified'],source)
            self.assertIs(guard,graphs[0][0]); self.assertIs(responses['template_identity'],graphs[0][2][0][0])
            self.assertEqual(9,len(graphs[0][1]))
            self.assertEqual(2,sum(stat.S_ISDIR(info.st_mode) for _,info,_ in graphs[0][1]))
            self.assertEqual([True],core_closed)
            no_first.assert_not_called(); no_retry.assert_not_called(); no_claim.assert_not_called()
            for fd,_info,_raw in graphs[0][1]:
                with self.assertRaises(OSError) as caught: os.fstat(fd)
                self.assertEqual(errno.EBADF,caught.exception.errno)
            if fault:
                self.assertIs(self.store,input_holders[0][0][0])
                self.assertEqual(self.project,input_holders[0][0][1])
                self.assertEqual(self.template,input_holders[0][0][2])
                self.assertTrue(input_refusals,
                    'generic G1 HOLD cannot substitute for actual original-input drift refusal')
                self.assertEqual((0,True,1),input_refusals[0][0],
                    'the original outer verifier must reject after the last strict finalizer')
                self.assertIsInstance(input_refusals[0][1],actual_hold_type)
                self.assertNotIn((0,True,1),input_verifications)
                self.assertEqual(1,len(rebound))
                path,retained,original,raw,replacement = rebound[0]
                self.assertEqual(1,len(preserved_after_refusal))
                current,current_bytes,preserved,preserved_bytes = preserved_after_refusal[0]
                self.assertNotEqual(original.st_ino,replacement.st_ino)
                self._assert_original_stat_preserved(replacement,current)
                self.assertEqual(original.st_ino,preserved.st_ino)
                self.assertEqual(raw,current_bytes); self.assertEqual(raw,preserved_bytes)
                if fault == 'w1':
                    self.assertEqual(1,len(fixture_restorations))
                    restored,restored_bytes,kept,kept_bytes = fixture_restorations[0]
                    self.assertEqual((original.st_dev,original.st_ino),
                        (restored.st_dev,restored.st_ino))
                    self.assertEqual((replacement.st_dev,replacement.st_ino),
                        (kept.st_dev,kept.st_ino))
                    self.assertEqual(raw,restored_bytes); self.assertEqual(raw,kept_bytes)
                else:
                    self.assertEqual([],fixture_restorations)
                self.assertFalse(arguments['global_root'].exists(),
                    'native fixture must finish its own temporary cleanup')
            else:
                self.assertEqual([],preserved_after_refusal)
                self.assertEqual([],fixture_restorations)
                self.assertEqual([],input_refusals)
                self.assertIn((0,True,0),input_verifications)
                self.assertEqual([],rebound)
                self.assertTrue(after_strict,'actual graph must be verified after all strict readers close')
                for phase,store,images in after_strict:
                    self.assertEqual('CLOSED',phase); self.assertIs(self.store,store)
                    self.assertEqual(tuple((info,raw) for _fd,info,raw in graphs[0][1]),images)

    def test_fixed_default_consumer_overlaps_actual_images_but_unproved_g1_never_counts_or_sends(self):
        self._fixed_default_original_inputs_probe()

    def test_fixed_default_consumer_last_strict_finalizer_rebinds_policy_or_w1_and_holds(self):
        for fault in ('policy','w1'):
            with self.subTest(fault=fault):
                # Each real three-panel workflow builds a complete private
                # source tree once; a second variant must not reuse that tree.
                case = type(self)('runTest')
                try:
                    case.setUp()
                    case._fixed_default_original_inputs_probe(fault)
                finally:
                    case.doCleanups()

    def _original_business_image_handoff_probe(self, fault):
        from monitor import issue_tracker_history_preread_journal as preread
        from monitor import issue_tracker_history_read_launcher as reads
        import stat
        self.assertTrue(callable(getattr(preread._OriginalBusinessReadGuard, '_hold_original_images', None)),
                        'actual business originals lack continuously overlapped image handoff')
        original_scope = preread._hold_owned_original_business_history_reads
        real_dup, real_fstat, real_open = os.dup, os.fstat, os.open
        witnessed = []
        @contextmanager
        def bridge(*args, **kwargs):
            duplicates = []; checked = []; revoked = []; substituted = []
            with ExitStack() as images:
                with original_scope(*args, **kwargs) as pair:
                    if fault == 'first-stat-cleanup':
                        import tempfile
                        actual_fstat = preread.os.fstat
                        for variant in ('owned', 'foreign'):
                            acquired = []; interrupted = []
                            with tempfile.TemporaryFile() as foreign:
                                foreign.write(b'foreign descriptor remains caller-owned'); foreign.flush()
                                foreign_identity = real_fstat(foreign.fileno())
                                def early_duplicate(fd):
                                    value = real_dup(fd); acquired.append(value); return value
                                def first_stat(fd):
                                    if fd in acquired and not interrupted:
                                        interrupted.append(fd)
                                        if variant == 'foreign': os.dup2(foreign.fileno(),fd)
                                        raise KeyboardInterrupt('owned first duplicate stat interruption')
                                    return actual_fstat(fd)
                                with mock.patch.object(preread.os,'dup',side_effect=early_duplicate), \
                                        mock.patch.object(preread.os,'fstat',side_effect=first_stat), \
                                        self.assertRaises(KeyboardInterrupt):
                                    with pair[1]._hold_original_images():
                                        self.fail('interrupted first stat yielded original images')
                                self.assertEqual(1,len(acquired)); self.assertEqual(acquired,interrupted)
                                if variant == 'owned':
                                    with self.assertRaises(OSError): real_fstat(acquired[0])
                                else:
                                    self.assertEqual(foreign_identity,real_fstat(acquired[0]))
                                    self.assertEqual(b'foreign descriptor remains caller-owned',
                                                     os.pread(acquired[0],64,0))
                                    os.close(acquired[0])  # only the fixture's preserved foreign alias
                            pair[1]()  # the old strict holder was never substituted/revoked
                    def duplicate(fd):
                        value = real_dup(fd)
                        before = real_fstat(fd)
                        duplicates.append((value, before, None if stat.S_ISDIR(before.st_mode)
                                           else os.pread(fd, before.st_size+1, 0)))
                        return value
                    with mock.patch.object(preread.os, 'dup', side_effect=duplicate):
                        packet, verify = images.enter_context(pair[1]._hold_original_images())
                    self.assertEqual(9, len(duplicates))
                    self.assertEqual(2, sum(stat.S_ISDIR(before.st_mode) for _, before, _ in duplicates))
                    old_packet = pair[1]._original_issued_inputs()
                    self.assertIs(old_packet[0], packet[0]); self.assertIs(old_packet[1], packet[1])
                    self.assertEqual(old_packet[2], packet[2])
                    self.assertIsNot(old_packet[2][0], packet[2][0])
                    yield pair
                # The strict read holder and its old originals have CLOSED.
                # Independently prove the actual duplicate graph survived it.
                for fd, before, raw in duplicates:
                    self.assertEqual(before, real_fstat(fd))
                    if raw is not None: self.assertEqual(raw, os.pread(fd, len(raw)+1, 0))
                opened = []
                def opening(name, flags, **options):
                    opened.append(str(name)); return real_open(name, flags, **options)
                verify()
                if fault == 'rebind':
                    folder = next(fd for fd, before, _raw in duplicates
                                  if stat.S_ISDIR(before.st_mode) and 'BUSINESS-RAW' in os.listdir(fd))
                    before = os.stat('BUSINESS-RAW', dir_fd=folder, follow_symlinks=False)
                    fd = real_open('BUSINESS-RAW', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=folder)
                    try: raw = os.pread(fd, before.st_size+1, 0)
                    finally: os.close(fd)
                    os.rename('BUSINESS-RAW','preserved-owned-business-raw',src_dir_fd=folder,dst_dir_fd=folder)
                    fd = real_open('BUSINESS-RAW',os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                   dir_fd=folder,mode=0o600)
                    try: self.assertEqual(len(raw),os.write(fd,raw))
                    finally: os.close(fd)
                    self.assertNotEqual(before.st_ino,os.stat('BUSINESS-RAW',dir_fd=folder).st_ino)
                    substituted.append(folder)
                elif fault == 'revoke':
                    response = next(item['row_response'] for item in packet[2] if item['row_response'] is not None)
                    with reads._PROJECT_READ_GUARD:
                        saved = reads._PROJECT_READS.pop(response)
                    revoked.append((response, saved))
                try:
                    with mock.patch.object(preread.os, 'open', side_effect=opening):
                        if fault in ('rebind','revoke'):
                            with self.assertRaises(preread.HistoryPrereadHold): verify()
                            checked.append('HOLD')
                        else:
                            verify(); checked.append('LIVE')
                finally:
                    for response, saved in revoked:
                        with reads._PROJECT_READ_GUARD: reads._PROJECT_READS[response] = saved
                self.assertFalse(set(opened) & {'MANIFEST','BUSINESS-RAW','HISTORY-RAW','HEADER','INITIALIZED'},
                                 'verification reopened original fixed images')
                if fault in ('rebind','revoke'):
                    with self.assertRaises(preread.HistoryPrereadHold): verify()
                # Restore only this fixture's original name for the existing
                # outer no-mutation assertions; the failed handoff stays failed.
                for folder in substituted:
                    os.unlink('BUSINESS-RAW',dir_fd=folder)
                    os.rename('preserved-owned-business-raw','BUSINESS-RAW',src_dir_fd=folder,dst_dir_fd=folder)
                if fault in ('close-revoke','close-foreign'):
                    from monitor import issue_tracker_unit_catalog as catalog
                    actual_close = catalog._close_original
                    response = next(item['row_response'] for item in packet[2] if item['row_response'] is not None)
                    cleanup_revocations = []; cleanup_rebindings = []
                    def revoke_after_last_owned_close(fd, identity):
                        if fault == 'close-foreign' and fd == duplicates[0][0]:
                            import tempfile
                            foreign = tempfile.TemporaryFile()
                            foreign.write(b'foreign cleanup descriptor'); foreign.flush()
                            os.dup2(foreign.fileno(),fd)
                            cleanup_rebindings.append((fd,foreign,real_fstat(fd)))
                        result = actual_close(fd, identity)
                        if fault == 'close-revoke' and fd == duplicates[0][0]:
                            with reads._PROJECT_READ_GUARD:
                                cleanup_revocations.append((response,reads._PROJECT_READS.pop(response)))
                        return result
                    try:
                        with mock.patch.object(catalog,'_close_original',side_effect=revoke_after_last_owned_close), \
                                self.assertRaises(preread.HistoryPrereadHold):
                            images.close()
                    finally:
                        for response, saved in cleanup_revocations:
                            with reads._PROJECT_READ_GUARD: reads._PROJECT_READS[response] = saved
                        for fd, foreign, identity in cleanup_rebindings:
                            try:
                                self.assertEqual(identity,real_fstat(fd))
                                self.assertEqual(b'foreign cleanup descriptor',os.pread(fd,64,0))
                            finally:
                                os.close(fd); foreign.close()  # the fixture, never the image holder
                    self.assertEqual(1,len(cleanup_revocations)+len(cleanup_rebindings))
                    checked[0] = 'CLOSE-HOLD'
                if fault == 'first-stat-cleanup': checked[0] = 'FIRST-STAT-HOLD'
                witnessed.append(checked[0])
                if fault in ('rebind','revoke'):
                    with self.assertRaises(preread.HistoryPrereadHold): images.close()
            with self.assertRaises(preread.HistoryPrereadHold): verify()
            for fd, _before, _raw in duplicates:
                with self.assertRaises(OSError): real_fstat(fd)
        original_native = self._exercise_native_original_counted_launch
        def scoped_native(**arguments):
            from test_cases import test_req7_remote_history_match as gate_fixture
            import importlib
            actual_load = gate_fixture.load
            with ExitStack() as boundary:
                def after_actual_load(*args, **kwargs):
                    nonlocal preread, reads, original_scope
                    result = actual_load(*args, **kwargs)
                    # The real native fixture deliberately reloads its modules.
                    # Bind only the actual module it now consumes, not a stale
                    # pre-fixture Python object with the same import name.
                    preread = importlib.import_module('monitor.issue_tracker_history_preread_journal')
                    reads = importlib.import_module('monitor.issue_tracker_history_read_launcher')
                    original_scope = preread._hold_owned_original_business_history_reads
                    boundary.enter_context(mock.patch.object(preread,
                        '_hold_owned_original_business_history_reads',side_effect=bridge))
                    return result
                boundary.enter_context(mock.patch.object(gate_fixture,'load',side_effect=after_actual_load))
                return original_native(**arguments)
        with mock.patch.object(self,'_exercise_native_original_counted_launch',side_effect=scoped_native):
            self._original_business_read_acquisition_probe('business-live-inputs')
        expected = ('CLOSE-HOLD' if fault in ('close-revoke','close-foreign') else
                    'FIRST-STAT-HOLD' if fault == 'first-stat-cleanup' else 'HOLD' if fault else 'LIVE')
        self.assertEqual([expected]*2, witnessed)

    def test_actual_business_original_images_overlap_strict_close_without_reopening_or_count(self):
        self._original_business_image_handoff_probe(None)

    def test_actual_business_image_handoff_same_bytes_rebind_retains_original_and_holds(self):
        self._original_business_image_handoff_probe('rebind')

    def test_actual_business_image_handoff_original_issued_revocation_is_irreversible_hold(self):
        self._original_business_image_handoff_probe('revoke')

    def test_actual_business_image_handoff_last_owned_cleanup_revocation_cannot_return_success(self):
        self._original_business_image_handoff_probe('close-revoke')

    def test_actual_business_image_handoff_first_stat_interrupt_closes_only_owned_duplicate(self):
        self._original_business_image_handoff_probe('first-stat-cleanup')

    def test_actual_business_image_handoff_foreign_cleanup_descriptor_is_retained_and_holds(self):
        self._original_business_image_handoff_probe('close-foreign')

    def _original_business_read_acquisition_probe(self, mode):
        from monitor import issue_tracker_history_preread_journal as preread
        self.assertTrue(callable(getattr(preread, '_hold_owned_original_business_history_reads', None)),
            'actual protected source needs fixed original business/History fresh reads')
        observed = []
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_cabling_insert_probe=True, receipted_intent_probe=True,
            native_catalog_probe=True, native_catalog_c6_origin_probe=True,
            native_catalog_retained_probe=True, native_catalog_launch_probe=(mode, observed))
        suffix = {'business-originals': 'fresh-read-only',
                  'business-originals-rebind': 'original-rebind-hold',
                  'business-postclose': 'actual-issued-postclose-revocation-hold',
                  'business-failed': 'actual-issued-failed-scope-hold',
                  'business-live-inputs': 'actual-live-issued-inputs-only'}[mode]
        self.assertEqual(['ETH Cabling:' + suffix, 'IB Cabling:' + suffix], observed)

    def test_actual_protected_business_and_history_fixed_acquisition_preserves_original_count(self):
        self._original_business_read_acquisition_probe('business-originals')

    def test_actual_business_original_rebound_during_last_native_read_refuses_without_count(self):
        self._original_business_read_acquisition_probe('business-originals-rebind')

    def test_actual_business_postclose_guard_rejects_closed_fds_and_revoked_original_issued_read(self):
        from monitor import issue_tracker_history_preread_journal as preread
        self.assertTrue(callable(getattr(preread, '_OriginalBusinessReadGuard', None)),
                        'actual issued reads need a postclose-only genuine guard')
        self._original_business_read_acquisition_probe('business-postclose')

    def test_actual_business_failed_scope_cannot_reuse_original_issued_guard(self):
        from monitor import issue_tracker_history_preread_journal as preread
        self.assertTrue(callable(getattr(preread, '_OriginalBusinessReadGuard', None)),
                        'failed actual business scope must revoke its genuine issued guard')
        self._original_business_read_acquisition_probe('business-failed')

    def test_actual_business_issued_inputs_keep_original_response_identity_and_refuse_after_close(self):
        from monitor import issue_tracker_history_preread_journal as preread
        self.assertTrue(callable(getattr(preread._OriginalBusinessReadGuard, '_original_issued_inputs', None)),
                        'actual held business replies cannot be replaced by caller-created plans')
        self._original_business_read_acquisition_probe('business-live-inputs')

    def test_default_preparation_acquires_all_actual_business_history_reads_without_count(self):
        self._default_source_read_preparation_probe('prepare-business')

    def test_default_preparation_holds_business_original_through_last_actual_outer_finalizer(self):
        self._default_source_read_preparation_probe('prepare-business-finalizer-rebind')

    def test_default_preparation_rechecks_original_business_issued_read_after_all_holder_closures(self):
        self._default_source_read_preparation_probe('prepare-business-postclose-revoke')

    def _default_source_read_preparation_probe(self, mode):
        from monitor import issue_tracker_remote_history_match as remote
        self.assertTrue(callable(getattr(remote,'_prepare_current_project_online_observation',None)),
            'default coordinator must prepare actual current source and fresh project reads')
        observed=[]
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_cabling_insert_probe=True,receipted_intent_probe=True,
            native_catalog_probe=True,native_catalog_c6_origin_probe=True,
            native_catalog_retained_probe=True,native_catalog_launch_probe=(mode,observed))
        suffix={'prepare':'visible-only-no-count',
            'prepare-mixed-accounting':'mixed-original-visible-only-no-count',
            'prepare-quota-rebind':'original-rebind-hold-no-count',
            'prepare-finalizer-expiry':'post-finalizer-expiry-hold-no-count',
            'prepare-business':'business-history-visible-only-no-count',
            'prepare-business-finalizer-rebind':'business-finalizer-rebind-hold-no-count',
            'prepare-business-postclose-revoke':'business-postclose-revoke-hold-no-count'}[mode]
        self.assertEqual(['ETH Cabling:'+suffix,'IB Cabling:'+suffix],observed)

    def test_default_preparation_replays_actual_source_then_fresh_project_gate_reads_without_count(self):
        self._default_source_read_preparation_probe('prepare')

    def test_default_preparation_actual_protected_pending_uses_mixed_original_quota_without_count(self):
        self._default_source_read_preparation_probe('prepare-mixed-accounting')

    def test_default_preparation_original_quota_rebind_during_actual_last_read_refuses_without_count(self):
        self._default_source_read_preparation_probe('prepare-quota-rebind')

    def test_default_preparation_actual_read_expiry_after_last_original_finalizer_refuses_without_count(self):
        self._default_source_read_preparation_probe('prepare-finalizer-expiry')

    def _protected_shared_counter_route(self, *, launch=False, retry=False):
        from test_cases import test_req7_global_attempt_journal as fixtures
        actual_load = fixtures.load; routed = []; results = []
        with ExitStack() as patches:
            def load_and_observe():
                module = actual_load(); counter = module.record_global_attempt_intent
                def count(owner,bound,unit):
                    routed.append(unit.unit_id)
                    result = counter(owner,bound,unit)
                    results.append((result.attempt_count,result.outcome))
                    return result
                patches.enter_context(mock.patch.object(module,'record_global_attempt_intent',side_effect=count))
                return module
            patches.enter_context(mock.patch.object(fixtures,'load',side_effect=load_and_observe))
            if retry:
                self._exercise_real_protected_three_panel_fixture(skip_history=False,
                    observed_cabling_insert_probe=True,business_preread_probe=True,
                    original_reserved_probe=True,receipted_intent_probe=True,
                    owned_read_gates_probe=True,owned_continuity_probe=True,retry_launch_probe='normal')
            else:
                marks = []
                options = dict(native_catalog_launch_probe=('normal',marks)) if launch else dict(
                    native_catalog_receipted_count_probe=marks)
                self._exercise_real_protected_three_panel_fixture(skip_history=False,
                    observed_cabling_insert_probe=True,receipted_intent_probe=True,
                    native_catalog_probe=True,native_catalog_c6_origin_probe=True,
                    native_catalog_retained_probe=True,**options)
                self.assertEqual(2,len(marks))
        # Outside all sanitized production contexts: actual protected C5/C6,
        # and where selected, fresh reads/CLAIM/TLS must reach this boundary.
        self.assertEqual([(1,'UNKNOWN'),(2 if retry else 1,'UNKNOWN')],results,
            'every actual protected count, including identical retry, must reach the shared counter exactly once')
        self.assertEqual(2,len(routed))
        self.assertEqual(retry,routed[0]==routed[1],
            'retry binds one original unit; native ETH/IB source panels bind distinct units')

    def test_actual_protected_native_receipted_count_joins_shared_catalog_counter(self):
        self._protected_shared_counter_route()

    def test_actual_protected_native_fixed_request_joins_shared_catalog_counter(self):
        self._protected_shared_counter_route(launch=True)

    def test_actual_original_shared_retry_joins_the_same_catalog_counter(self):
        self._protected_shared_counter_route(retry=True)

    def test_original_unknown_unit_retries_after_a_new_real_cycle_without_recompile(self):
        self._exercise_original_unknown_retry()

    def test_same_byte_original_c6_replacement_after_old_retry_count_keeps_unpaired_intent(self):
        self._exercise_original_unknown_retry(replace_c6_after_count=True)

    def test_same_byte_current_high_water_replacement_after_old_retry_count_keeps_unpaired_intent(self):
        self._exercise_original_unknown_retry(replace_input_after_count='high_water')

    def test_same_byte_policy_replacement_after_old_retry_count_keeps_unpaired_intent(self):
        self._exercise_original_unknown_retry(replace_input_after_count='policy')

    def test_same_byte_w1_replacement_after_old_retry_count_keeps_unpaired_intent(self):
        self._exercise_original_unknown_retry(replace_input_after_count='w1')

    def _exercise_original_unknown_retry(self, *, replace_c6_after_count=False, replace_input_after_count=None):
        from test_cases import test_req7_global_attempt_journal as journal_fixture
        from monitor.collection_ib_producer import produce_worker_ib_analysis
        from tools.project_contract import build_collection_cycle_identity
        from test_cases.test_collection_cycle_persistence import TOKEN_2
        from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence

        native_load = journal_fixture.load
        advanced = []
        faults = []
        class OwnedRetryFaultObserved(Exception):
            pass

        def with_original_count_boundary():
            module = native_load()
            first = module.record_continuous_owned_attempt_intent
            retry = module.record_shared_retry_continuous_owned_attempt_intent

            def first_then_new_cycle(*args, **kwargs):
                result = first(*args, **kwargs)
                self.assertEqual((1, 'UNKNOWN'), (result.attempt_count, result.outcome))
                before = read_completed_cycle_evidence(self.store)
                self.assertEqual(1, len(before))
                identity = build_collection_cycle_identity(str(self.project), 'prod', 2, TOKEN_2)
                ib = produce_worker_ib_analysis(identity, project_root=self.project,
                    http_root=self.root,
                    clock=lambda: dt.datetime(2026, 9, 26, 4, 31, tzinfo=dt.timezone.utc),
                    runner=lambda _argv: self.fail('transport must remain the owned fixture'))
                cycle, _ = self._cycle(activity=True, derivation=True, ib_analysis=ib,
                    observed_peer='newer-not-original-peer', additional_eth_activity=True,
                    fabric_templates={'ethernet/prod': 'tan-leaf', 'nvlink/prod': 'border-leaf'})
                self.assertEqual(identity['cycle_id'], cycle['cycle_id'])
                self.assertNotEqual(before[-1].cycle_id, cycle['cycle_id'])
                advanced.append(True)
                return result

            def check_original_retry(*args, **kwargs):
                unit = args[2]
                wire, action = unit.wire_bytes, unit.action_preimage
                image = {p.relative_to(self.project).as_posix(): p.read_bytes()
                         for p in (self.project / '.tracker/generations').rglob('*') if p.is_file()}
                if not replace_c6_after_count and replace_input_after_count is None:
                    from monitor.issue_tracker_remote_history_match import observe_owned_unit_read_gates
                    gates = observe_owned_unit_read_gates(kwargs['writer_token'], args[0], args[1], unit,
                        whitelist_snapshot=kwargs['whitelist_snapshot'].whitelist,
                        identity_response=kwargs['identity_response'], headers_response=kwargs['headers_response'],
                        whitelist_response=kwargs['whitelist_response'], metadata_response=kwargs['metadata_response'])
                    ordinary = {key:kwargs[key] for key in ('qualified_source','store','writer_token',
                        'settings','whitelist_snapshot','expected_template_sha256','http_root','whitelist_path')}
                    with self.assertRaises(module.GlobalAttemptHold):
                        module.record_receipted_original_attempt_intent(
                            args[0], args[1], gates.identity, unit, **ordinary)
                    retained = module.inspect_global_unit(*args[:3])
                    self.assertEqual((1, 'UNKNOWN'), (retained.attempt_count, retained.outcome))
                    self.assertEqual([], list((self.project / '.tracker/admissions').glob('retry-*-intent.json')))
                if replace_c6_after_count or replace_input_after_count is not None:
                    manifest = self.project / '.tracker/generations' / json.loads(action)['identity']['generation_id'] / 'MANIFEST'
                    if replace_input_after_count is not None:
                        manifest = {'high_water':self.store.witness_path,
                                    'policy':self.project/'01-global.yaml', 'w1':self.template}[replace_input_after_count]
                    raw, inode = manifest.read_bytes(), manifest.stat().st_ino
                    mode = manifest.stat().st_mode & 0o777
                    preserved = self.project / 'owned-original-old-retry-manifest'
                    observe = module._observe
                    def replace_after_count(*values, **options):
                        result = observe(*values, **options)
                        if values[3]:
                            self.assertEqual((2, 'UNKNOWN'), (result.attempt_count, result.outcome))
                            manifest.rename(preserved)
                            manifest.write_bytes(raw); manifest.chmod(mode)
                            faults.append(True)
                        return result
                    with mock.patch.object(module, '_observe', side_effect=replace_after_count):
                        with self.assertRaises(module.GlobalAttemptHold):
                            retry(*args, **kwargs)
                    self.assertEqual([True], faults, 'reach the actual original durable second count')
                    retained = module.inspect_global_unit(*args[:3])
                    self.assertEqual((2, 'UNKNOWN'), (retained.attempt_count, retained.outcome))
                    self.assertEqual((wire, action), (unit.wire_bytes, unit.action_preimage))
                    self.assertEqual(raw, manifest.read_bytes()); self.assertEqual(raw, preserved.read_bytes())
                    self.assertNotEqual(inode, manifest.stat().st_ino)
                    self.assertTrue(list((self.project / '.tracker/admissions').glob('retry-*-intent.json')))
                    self.assertEqual([], list((self.project / '.tracker/admissions').glob('retry-*-count.json')))
                    self.assertEqual(image, {p.relative_to(self.project).as_posix(): p.read_bytes()
                        for p in (self.project / '.tracker/generations').rglob('*') if p.is_file()})
                    self.assertFalse(hasattr(retained, 'send_authority'))
                    raise OwnedRetryFaultObserved()
                result = retry(*args, **kwargs)
                self.assertEqual((2, 'UNKNOWN'), (result.attempt_count, result.outcome))
                self.assertEqual((wire, action), (unit.wire_bytes, unit.action_preimage))
                self.assertEqual(image, {p.relative_to(self.project).as_posix(): p.read_bytes()
                    for p in (self.project / '.tracker/generations').rglob('*') if p.is_file()})
                self.assertFalse(hasattr(result, 'send_authority'))
                return result

            module.record_continuous_owned_attempt_intent = first_then_new_cycle
            module.record_shared_retry_continuous_owned_attempt_intent = check_original_retry
            return module

        with mock.patch.object(journal_fixture, 'load', side_effect=with_original_count_boundary):
            def exercise():
                self._exercise_real_protected_three_panel_fixture(skip_history=False,
                    observed_cabling_insert_probe=True, business_preread_probe=True,
                    original_reserved_probe=True, receipted_intent_probe=True,
                    owned_read_gates_probe=True, owned_continuity_probe=True, shared_retry_probe=True)
            if replace_c6_after_count or replace_input_after_count is not None:
                with self.assertRaises(OwnedRetryFaultObserved):
                    exercise()
            else:
                exercise()
        self.assertEqual([True], advanced)


    def _exercise_timed_out_boot_probe(self, **options):
        from test_cases.test_collection_cycle_persistence import WORKER

        original_run = subprocess.run
        original_is_file = Path.is_file
        timed_out_probes = []

        def bounded_probe(command, *args, **kwargs):
            if command == ["/usr/sbin/sysctl", "-n", "kern.boottime"]:
                timed_out_probes.append(command)
                raise subprocess.TimeoutExpired(command, 2)
            return original_run(command, *args, **kwargs)

        def no_linux_boot_file(path):
            return False if str(path) == "/proc/sys/kernel/random/boot_id" \
                else original_is_file(path)

        with mock.patch.object(WORKER.subprocess, "run", side_effect=bounded_probe), \
                mock.patch.object(WORKER.Path, "is_file", autospec=True,
                                  side_effect=no_linux_boot_file):
            self._exercise_real_protected_three_panel_fixture(
                skip_history=False, **options,
            )
        self.assertTrue(timed_out_probes, "the workflow must execute the injected fault")

    def test_boot_probe_timeout_does_not_admit_n_two_local_c6(self):
        self._exercise_timed_out_boot_probe(
            automatic_first=True, automatic_not_due=True,
        )

    def test_boot_probe_timeout_does_not_auto_readmit_manual_receipt(self):
        self._exercise_timed_out_boot_probe(replayed_auto=True)

    def test_real_nine_role_ib_and_eth_fourth_role_qualify_and_c5_reject_drift(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False)

    def test_real_protected_three_panel_sources_compile_literal_units_and_refuse_invented_values(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, source_unit_probe=True)

    def test_actual_protected_workbook_receipt_admission_bind_all_source_units_and_reject_drift(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, receipted_source_probe=True)

    def test_actual_receipt_source_and_full_row_images_derive_all_update_coordinates_and_preread(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_source_probe=True)

    def test_actual_source_receipt_global_owner_and_original_enrollment_derive_switch_inserts(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_switch_insert_probe=True)

    def test_actual_c6_switch_nonallocating_scope_registers_catalog_without_any_nv_family(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_switch_insert_probe=True, nonallocating_switch_catalog_probe=True)

    def test_actual_nonallocating_switch_refuses_legacy_nv_registrar_before_any_catalog_write(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_switch_insert_probe=True, nonallocating_switch_catalog_probe=True,
            nonallocating_switch_alias_probe='old-nv-registry')

    def test_actual_nonallocating_switch_refuses_legacy_c6_nv_parameter_before_any_origin_write(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_switch_insert_probe=True, nonallocating_switch_catalog_probe=True,
            nonallocating_switch_alias_probe='old-c6-parameter')

    def test_actual_nonallocating_switch_c6_keeps_real_settings_audit_anchor_without_nv(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_switch_insert_probe=True, nonallocating_switch_catalog_probe=True,
            nonallocating_switch_audit_probe=True)

    def test_actual_nonallocating_switch_refuses_another_live_project_writer_before_source_or_c6(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_switch_insert_probe=True, nonallocating_switch_catalog_probe=True,
            nonallocating_switch_alias_probe='other-live-writer')

    def test_actual_source_receipt_and_original_two_sheet_nv_derive_mixed_cabling_units(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True)

    def test_actual_c6_all_update_eth_ib_catalog_units_keep_original_ids_without_nv_allocation(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_cabling_insert_probe=True, nonallocating_cabling_catalog_probe=True)

    def test_actual_protected_c6_source_compiles_native_nv_and_reads_same_original_catalog_unit(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_cabling_insert_probe=True, native_catalog_probe=True)

    def test_actual_protected_c6_native_nv_registers_unique_catalog_and_original_project_origin(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_cabling_insert_probe=True, native_catalog_probe=True, native_catalog_c6_origin_probe=True)

    def test_actual_protected_c6_native_nv_origin_global_and_retained_originals_stay_read_only(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_cabling_insert_probe=True, native_catalog_probe=True, native_catalog_c6_origin_probe=True,
            native_catalog_retained_probe=True)

    def test_actual_protected_c6_native_nv_creator_receive_fault_holds_before_compile_and_closes_owned_fd(self):
        observed = []
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_cabling_insert_probe=True, native_catalog_probe=True,
            native_catalog_creator_first_stat_probe=observed)
        self.assertEqual(['ETH Cabling:actual-first-stat-fault:owned-fd-closed',
                          'IB Cabling:actual-first-stat-fault:owned-fd-closed'], observed)

    def test_actual_protected_native_nv_origin_history_quota_and_receipted_first_count_preserve_unknown(self):
        observed = []
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_cabling_insert_probe=True, receipted_intent_probe=True,
            native_catalog_probe=True, native_catalog_c6_origin_probe=True,
            native_catalog_retained_probe=True, native_catalog_receipted_count_probe=observed)
        self.assertEqual(['ETH Cabling:actual-receipted-count:unknown',
            'IB Cabling:actual-receipted-count:unknown'], observed)

    def _native_original_settings_audit_oracle(self):
        # Literal fixture contract, constructed before any settings/source
        # implementation runs; never decode an EVENT or pending-reader result.
        def canonical(value):
            return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
        events=[];previous=None
        for revision,kind,old,new,actor,when,request in (
                (0,'init',None,3,'system:default','2026-09-25T00:00:00Z','req7-three-panel-protected-fixture'),
                (1,'set_k',3,1,'operator:fixture','2026-09-25T00:01:00Z','req7-three-panel-k1')):
            payload={'new_k':new,'actor':actor,'expected_revision':None if revision==0 else 0,
                     'request_id':request}
            event=canonical({'schema_version':1,'revision':revision,'type':kind,'old_k':old,'new_k':new,
                'actor':actor,'recorded_at':when,'request_id':request,
                'payload_sha256':hashlib.sha256(canonical(payload)).hexdigest(),'predecessor_sha256':previous})
            digest=hashlib.sha256(event).hexdigest()
            events.append({'event_id':'settings:%d:%s'%(revision,digest),
                'recorded_at_utc':when,'details':event.decode().rstrip('\n')})
            previous=digest
        return tuple(events)

    def _native_original_launch_probe(self, mode, *, settings_audit=False):
        observed = []
        expected_audits=self._native_original_settings_audit_oracle() if settings_audit else ()
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_cabling_insert_probe=True, receipted_intent_probe=True,
            native_catalog_probe=True, native_catalog_c6_origin_probe=True,
            native_catalog_retained_probe=True, native_catalog_launch_probe=(mode, observed,expected_audits),
            settings_audit_probe=settings_audit)
        self.assertEqual(['ETH Cabling:native-launch:' + mode,
            'IB Cabling:native-launch:' + mode], observed)

    def test_native_original_fresh_reads_count_claim_and_one_fixed_local_request(self):
        self._native_original_launch_probe('normal')

    def test_native_original_settings_audit_count_claim_and_one_fixed_local_request_without_legacy_shadow(self):
        self._native_original_launch_probe('normal',settings_audit=True)

    def _native_completed_archive_preview_probe(self, *, receipt_rebind=False, local_c6=False, settings_finalizer=False,
                                              native_current_compiler=False, current_receipt_tail=False,issued_current_compiler=False,
                                              issued_read_tail=False):
        observed = []
        mode = 'complete-after-archive-receipt-rebind' if receipt_rebind else 'complete-after-archive'
        if settings_finalizer:
            mode += '-settings-finalizer'
        if local_c6:
            mode += '-local-c6'
        if native_current_compiler:
            mode += '-native-current-compiler'
        if current_receipt_tail:
            mode += '-receipt-tail'
        if issued_current_compiler:
            mode += '-issued-reads'
        if issued_read_tail:
            mode += '-issued-tail'
        from test_cases.test_req7_remote_history_match import Req7OwnedHistoryMatchWorkflowTests
        from test_cases.test_req7_mutation_launcher import Req7MutationLauncherWorkflowTests
        supplied=self._fixture_certificate_supplier(Req7OwnedHistoryMatchWorkflowTests.certificates)
        with mock.patch.object(Req7OwnedHistoryMatchWorkflowTests,'certificates',supplied), \
                mock.patch.object(Req7MutationLauncherWorkflowTests,'certificates',supplied):
            def exercise():
                self._exercise_real_protected_three_panel_fixture(skip_history=False,
                    observed_cabling_insert_probe=True, receipted_intent_probe=True,
                    native_catalog_probe=True, native_catalog_c6_origin_probe=True,
                    native_catalog_retained_probe=True, settings_audit_probe=True,
                    native_catalog_launch_probe=(mode, observed, self._native_original_settings_audit_oracle()))
            if current_receipt_tail:
                class CurrentReceiptTailFinished(BaseException):pass
                self.current_receipt_tail_primary=CurrentReceiptTailFinished('actual current receipt tail finished')
                with self.assertRaises(CurrentReceiptTailFinished) as caught:exercise()
                self.assertIs(self.current_receipt_tail_primary,caught.exception)
                self.assertEqual((True,True,True),self.current_receipt_tail_facts)
            elif issued_read_tail:
                class IssuedReadTailFinished(BaseException):pass
                self.issued_read_tail_primary=IssuedReadTailFinished('actual issued read tail finished')
                with self.assertRaises(IssuedReadTailFinished) as caught:exercise()
                self.assertIs(self.issued_read_tail_primary,caught.exception)
                self.assertEqual((True,True,True),self.issued_read_tail_facts)
            else:exercise()
        self.assertEqual(['ETH Cabling:native-launch:normal',
            'ETH Cabling:archived:fresh-preview:' + ('HOLD' if receipt_rebind else 'read-only')]
            + (['ETH Cabling:archived:next-local-c6:' + ('HOLD' if receipt_rebind or settings_finalizer else 'committed')]
               if local_c6 else [])
            + (['ETH&IB Switch:archived:current-cycle-compiler:'+
                ('tail-refused' if current_receipt_tail or issued_read_tail else 'registered')] if native_current_compiler else []), observed)

    def test_real_complete_archive_then_fresh_owner_manual_preview_preserves_all_originals(self):
        self._native_completed_archive_preview_probe()

    def test_real_complete_archive_receipt_rebind_refuses_fresh_manual_preview_without_repair(self):
        self._native_completed_archive_preview_probe(receipt_rebind=True)

    def test_real_complete_archive_then_new_eligible_cycle_commits_default_local_c6(self):
        self._native_completed_archive_preview_probe(local_c6=True)

    def test_real_archived_delivery_next_cycle_receipt_replays_c5_and_registers_observed_switch_unit(self):
        from monitor import issue_tracker_remote_history_match as remote
        self.assertTrue(callable(getattr(remote,'_hold_native_current_cycle_compiler_inputs',None)),
            'fixed native source/receipt reception must feed the actual observed compiler')
        self._native_completed_archive_preview_probe(local_c6=True,native_current_compiler=True)

    def test_real_current_cycle_switch_compiler_acquires_original_project_auth_and_fixed_issued_reads(self):
        from monitor import issue_tracker_remote_history_match as remote
        self.assertTrue(callable(getattr(remote,'_hold_native_current_cycle_observed_switch_unit',None)),
            'native current-cycle compiler must acquire its actual authenticated business images')
        self._native_completed_archive_preview_probe(local_c6=True,native_current_compiler=True,issued_current_compiler=True)

    def test_real_native_switch_compiler_brackets_pure_derivation_with_two_manifests_and_four_original_receipts(self):
        from monitor import issue_tracker_send_unit as compiler,issue_tracker_manifest as manifest
        original = compiler.freeze_observed_receipted_switch_unit
        real_manifest = manifest.freeze_prod_stage_l_manifest
        real_receipt = compiler._original_receipt_identity
        facts=[]
        def observe(*args,**kwargs):
            self.assertIsNotNone(kwargs.get('_unit_preparation'))
            calls=[];receipts=[]
            def replay(*values,**options):
                result=real_manifest(*values,**options);calls.append(result);return result
            def receipt(*values,**options):
                result=real_receipt(*values,**options);receipts.append(result);return result
            with mock.patch.object(manifest,'freeze_prod_stage_l_manifest',side_effect=replay), \
                    mock.patch.object(compiler,'_original_receipt_identity',side_effect=receipt):
                unit=original(*args,**kwargs)
            facts.append((len(calls),len(receipts)))
            self.assertEqual(2,len(calls),'outer complete replay must bracket single-invocation pure derivation')
            self.assertEqual(4,len(receipts),'C6 before/after and both nonce observations must remain real')
            self.assertTrue(all(value==calls[0] for value in calls))
            self.assertTrue(all(value==receipts[0] for value in receipts))
            self.assertFalse(hasattr(unit,'send_once'));self.assertFalse(hasattr(unit,'permit'))
            return unit
        with mock.patch.object(compiler,'freeze_observed_receipted_switch_unit',side_effect=observe):
            self._native_completed_archive_preview_probe(local_c6=True,native_current_compiler=True)
        self.assertEqual([(2,4)],facts)

    def test_real_native_switch_last_manifest_rejects_original_template_drift_after_pure_builder(self):
        from monitor import issue_tracker_send_unit as compiler,issue_tracker_manifest as manifest
        build=getattr(compiler,'_freeze_prod_source_business',None)
        self.assertTrue(callable(build),'negative must reach actual pure derivation before source-tail fault')
        class FaultFinished(BaseException):pass
        primary=FaultFinished();facts=[]
        original=compiler.freeze_observed_receipted_switch_unit
        real_manifest=manifest.freeze_prod_stage_l_manifest
        def fault(*args,**kwargs):
            from monitor import issue_tracker_nv_reservation as native
            record=native._verify_catalog_preparation(kwargs['_unit_preparation'])
            built=[];attempts=[];drift=[]
            def derive(*values,**options):
                result=build(*values,**options);built.append(True);return result
            def replay(*values,**options):
                attempts.append(bool(built))
                if built and not drift:
                    raw=self.template.read_bytes()
                    self.template.write_bytes(b'not-an-xlsx-original')
                    drift.append(raw!=self.template.read_bytes())
                return real_manifest(*values,**options)
            refused=False
            with mock.patch.object(compiler,'_freeze_prod_source_business',side_effect=derive), \
                    mock.patch.object(manifest,'freeze_prod_stage_l_manifest',side_effect=replay):
                try:original(*args,**kwargs)
                except compiler.SendUnitHold:refused=True
            facts.append((tuple(built),tuple(attempts),tuple(drift),refused,record['registered'],record['unit']))
            # Consumer primary survives actual unregistered preparation cleanup;
            # that cleanup's HOLD cannot masquerade as the compiler-tail refusal.
            raise primary
        with mock.patch.object(compiler,'freeze_observed_receipted_switch_unit',side_effect=fault):
            with self.assertRaises(FaultFinished) as caught:
                self._native_completed_archive_preview_probe(local_c6=True,native_current_compiler=True)
        self.assertIs(primary,caught.exception)
        self.assertEqual([((True,),(False,True),(True,),True,False,None)],facts)

    def test_real_issued_read_revoked_after_actual_k_settings_close_refuses_compiler_receiver_return(self):
        self._native_completed_archive_preview_probe(local_c6=True,native_current_compiler=True,
            issued_current_compiler=True,issued_read_tail=True)

    def test_real_registered_switch_original_read_revoked_after_native_preparation_cleanup_refuses_return(self):
        from monitor import issue_tracker_nv_reservation as native
        from monitor import issue_tracker_remote_history_match as remote
        from monitor import issue_tracker_history_read_launcher as reads
        from monitor import issue_tracker_token_launcher as tokens
        original_pin=native._pin_catalog_prefix
        original_receiver=remote._hold_native_current_cycle_observed_switch_unit
        original_require=reads.require_current_owned_project_read
        original_compile=self._compile_current_issued_switch_after_actual_archive
        captured=[];returned=[];facts=[];revoked=[];images=[];late_tail_refusals=[]
        @contextmanager
        def after_all_preparation_originals_close():
            yield
            if not returned:return
            prepared,record,writer,owner,binding,auth,response=captured[0]
            all_closed=True
            for descriptor in images:
                try:os.fstat(descriptor)
                except OSError as exc:all_closed=all_closed and exc.errno==9
                else:all_closed=False
            tokens.require_current_owned_project_token(owner,binding,auth)
            original_require(writer,owner,binding,response,auth,read_kind='template_identity')
            with reads._PROJECT_READ_GUARD:saved=reads._PROJECT_READS.pop(response)
            revoked.append((response,saved))
            facts.append((prepared not in native._ACTIVE_CATALOG_PREPARATIONS,
                all_closed,record['registered'],saved is auth,response not in reads._PROJECT_READS))
        def pin(*args,**kwargs):
            # Enter first: LIFO closes every actual ALL/C6/delivery owner tail
            # before this fault; no finalizer or successful verifier is faked.
            proofs=kwargs.get('_project_proofs')
            if proofs is not None:
                proofs['owner_tail'].enter_context(after_all_preparation_originals_close())
            return original_pin(*args,**kwargs)
        @contextmanager
        def receive(prepared,writer,owner,binding,auth,**kwargs):
            record=native._verify_catalog_preparation(prepared)
            def observe(*values,**options):
                result=original_require(*values,**options)
                if options['read_kind']=='template_identity' and not captured:
                    captured.append((prepared,record,writer,owner,binding,auth,values[3]))
                return result
            with mock.patch.object(reads,'require_current_owned_project_read',side_effect=observe):
                with original_receiver(prepared,writer,owner,binding,auth,**kwargs) as unit:yield unit
            images.extend({item[2] for holder in (record['old'],record['current']) for item in holder.files})
            returned.append(unit.unit_id)
        def compile_current(**kwargs):
            # Real old-cycle setup reloads the canonical modules. Bind only
            # at the actual new-cycle compiler entrance, not to a stale module
            # facade/registry or an exception class from before those reloads.
            nonlocal native,remote,reads,tokens,original_pin,original_receiver,original_require
            native=sys.modules['monitor.issue_tracker_nv_reservation']
            remote=sys.modules['monitor.issue_tracker_remote_history_match']
            reads=sys.modules['monitor.issue_tracker_history_read_launcher']
            tokens=sys.modules['monitor.issue_tracker_token_launcher']
            original_pin=native._pin_catalog_prefix
            original_receiver=remote._hold_native_current_cycle_observed_switch_unit
            original_require=reads.require_current_owned_project_read
            original_tail=getattr(native,'_verify_nonallocating_project_read_tail',None)
            def tail(record,state):
                try:return original_tail(record,state)
                except native.NvReservationHold:
                    if captured and record is captured[0][1] and revoked:
                        late_tail_refusals.append(True)
                    raise
            with ExitStack() as patches:
                patches.enter_context(mock.patch.object(native,'_pin_catalog_prefix',side_effect=pin))
                patches.enter_context(mock.patch.object(remote,'_hold_native_current_cycle_observed_switch_unit',side_effect=receive))
                if callable(original_tail):
                    patches.enter_context(mock.patch.object(native,'_verify_nonallocating_project_read_tail',side_effect=tail))
                return original_compile(**kwargs)
        try:
            failure=None
            with mock.patch.object(self,'_compile_current_issued_switch_after_actual_archive',side_effect=compile_current):
                try:
                    self._native_completed_archive_preview_probe(local_c6=True,native_current_compiler=True,
                        issued_current_compiler=True)
                except ValueError as exc:failure=exc
            self.assertIsNotNone(failure,
                'native preparation escaped late original-read revocation: returned=%r original-tail-facts=%r revoked=%d' %
                (returned,facts,len(revoked)))
            self.assertIs(type(failure),native.NvReservationHold,
                'the actual new-cycle native preparation, not another HOLD or stale exception class, must refuse return')
            self.assertEqual(1,len(returned),'actual compilation and registration must precede the late fault')
            self.assertTrue(images,'original catalog file descriptors must actually be closed')
            self.assertEqual([(True,True,True,True,True)],facts,
                'the last native preparation tail must reject the revoked original read with both real owners still live')
            self.assertEqual(1,len(revoked))
            self.assertEqual([True],late_tail_refusals,
                'the actual final issued-read helper must reject this original packet; another cleanup HOLD is insufficient')
        finally:
            # Restore only the exact fixture issuer entry after native tail
            # completion. Neither an earlier cleanup HOLD nor this restoration
            # may stand in for the required preparation-return refusal.
            for response,saved in revoked:
                with reads._PROJECT_READ_GUARD:reads._PROJECT_READS[response]=saved

    def test_issued_read_tail_fixture_prepares_the_original_root_template_before_preview(self):
        # The literal scenario must enter the same template preparation as its
        # positive control, before any production preview/receiver is invoked.
        import ast
        import inspect
        import textwrap
        source=ast.parse(textwrap.dedent(inspect.getsource(
            self._exercise_real_protected_three_panel_fixture)))
        assignments=[node for node in ast.walk(source) if isinstance(node,ast.Assign)
            and any(isinstance(target,ast.Name) and target.id=='default_preparation'
                    for target in node.targets)]
        self.assertEqual(1,len(assignments))
        modes=[ast.literal_eval(node) for node in ast.walk(assignments[0].value)
            if isinstance(node,ast.Tuple)]
        self.assertEqual(1,len(modes))
        self.assertIn('complete-after-archive-local-c6-native-current-compiler-issued-reads-issued-tail',
                      modes[0])

    def test_real_native_k_has_one_full_graph_per_boundary_and_rejects_post_settings_original_rebind(self):
        # Actual old COMPLETE/archive -> current C6 -> genuine preparation/K.
        # Four semantic boundaries: before/after settings on both sides of the
        # real K chain. Every observed graph check delegates to production;
        # no qualification, owner, raw holder or successful verifier is faked.
        from monitor import issue_tracker_remote_history_match as remote
        from test_cases.test_req7_remote_history_match import Req7OwnedHistoryMatchWorkflowTests
        from test_cases.test_req7_mutation_launcher import Req7MutationLauncherWorkflowTests
        class ProbeFinished(BaseException):pass
        primary=ProbeFinished();facts=[];observed=[]
        supplied=self._fixture_certificate_supplier(Req7OwnedHistoryMatchWorkflowTests.certificates)
        original_inputs=None
        original_switch=self._compile_current_switch_after_actual_archive
        @contextmanager
        def inspect_original_boundaries(prepared,writer,sheet,bound,**kwargs):
            from monitor import issue_tracker_nv_reservation as nv,issue_tracker_state_owner as state
            from monitor import issue_tracker_settings_audit_allocation as allocation
            original_settings=allocation._hold_settings_originals;armed=[];drift=[]
            record=nv._verify_catalog_preparation(prepared)
            original_graph=nv._verify_catalog_preparation;calls=[]
            def observe_graph(actual):
                result=original_graph(actual)
                if actual is prepared:calls.append(True)
                return result
            @contextmanager
            def observed_settings(*args,**kw):
                with original_settings(*args,**kw) as (images,verify):
                    def after_original_settings():
                        verify()
                        if not armed or drift:return
                        # The actual old delivery graph supplies its retained
                        # DELIVERED original. Rebind only after real settings
                        # verification has returned, with exactly the old bytes.
                        prior=next(row for row in record['prior_delivery_events'] if row['writer'] is writer)
                        parent,name,fd,identity,raw=next(row for row in prior['raw'].raw.files if row[1]=='DELIVERED')
                        os.rename(name,'owned-displaced-delivered',src_dir_fd=parent,dst_dir_fd=parent)
                        replacement=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
                        try:
                            self.assertEqual(len(raw),os.write(replacement,raw));os.fsync(replacement)
                            current=os.fstat(replacement)
                            drift.append((identity[:2]!=(current.st_dev,current.st_ino),
                                os.pread(fd,len(raw)+1,0)==raw))
                        finally:os.close(replacement)
                    yield images,after_original_settings
            with mock.patch.object(allocation,'_hold_settings_originals',observed_settings):
                with self._assertion_preserving_preparation(
                        original_inputs(prepared,writer,sheet,bound,**kwargs)) as packet:
                    with mock.patch.object(nv,'_verify_catalog_preparation',side_effect=observe_graph):
                        actual=state.current_k(writer)
                    count=len(calls)
                    print('NATIVE_K_ACTUAL_GRAPH_COUNT '+str(count),flush=True)
                    self.assertEqual(4,count,'one complete original graph at each K semantic boundary')
                    armed.append(True);refused=False
                    try:state.current_k(writer)
                    except ValueError:refused=True
                    facts.append((actual.revision,actual.k,count,refused,tuple(drift),
                        not record['registered'],not record['additions'],record['appended'] is None,
                        not list((Path(self.store.project_identity)/'.tracker/settings/outbox').iterdir())))
                    print('NATIVE_K_ACTUAL_BOUNDARY_OBSERVATION '+json.dumps(facts),flush=True)
                    # Finish the genuine unregistered preparation through its
                    # original primary path, not a forged registration flag.
                    raise primary
                    yield packet
        def after_actual_archive(**kwargs):
            nonlocal original_inputs
            # Old native fixtures reload canonical registries. Attach the
            # delegating observer only at the actual new-owner boundary.
            from monitor import issue_tracker_remote_history_match as current
            original_inputs=current._hold_native_current_cycle_compiler_inputs
            with mock.patch.object(current,'_hold_native_current_cycle_compiler_inputs',inspect_original_boundaries):
                return original_switch(**kwargs)
        with mock.patch.object(Req7OwnedHistoryMatchWorkflowTests,'certificates',supplied), \
                mock.patch.object(Req7MutationLauncherWorkflowTests,'certificates',supplied), \
                mock.patch.object(self,'_compile_current_switch_after_actual_archive',after_actual_archive):
            with self.assertRaises(ProbeFinished) as caught:
                self._exercise_real_protected_three_panel_fixture(skip_history=False,
                    observed_cabling_insert_probe=True,receipted_intent_probe=True,native_catalog_probe=True,
                    native_catalog_c6_origin_probe=True,native_catalog_retained_probe=True,settings_audit_probe=True,
                    native_catalog_launch_probe=('complete-after-archive-local-c6-native-current-compiler',
                        observed,self._native_original_settings_audit_oracle()))
        self.assertIs(primary,caught.exception)
        print('NATIVE_K_ACTUAL_BOUNDARIES '+json.dumps(facts),flush=True)
        self.assertEqual([(1,1,4,True,((True,True),),True,True,True,True)],facts)

    def test_actual_project_auth_requires_current_credential_and_target_root_fixture_after_old_scope_close(self):
        from test_cases.test_req7_history_read_launcher import Req7HistoryReadLauncherWorkflowTests
        from monitor import issue_tracker_credential_shape as credentials,issue_tracker_online_target as target
        from monitor import issue_tracker_token_launcher as tokens
        class MissingRootBoundary:
            # Deterministic absence of the fixture boundary on any host. Never
            # allow a root test runner to fall through to real private paths.
            def geteuid(self):return 501
            def open(self,*args,**kwargs):raise AssertionError('private path reached past nonroot guard')
            def __getattr__(self,name):return getattr(os,name)
        native=Req7HistoryReadLauncherWorkflowTests();native.setUp();self.addCleanup(native.doCleanups)
        with ExitStack() as current:
            _local,ownership,writer,sheet,binding,_token,_config=native.owners(current)
            auth,_path,_raw=native.project_auth(current,ownership,sheet,binding)
            original=tokens.require_current_owned_project_token(sheet,binding,auth)
            # Drop ONLY the root metadata/path transport boundary, not issuer,
            # decoder, credential bytes, token, owners or production checks.
            with mock.patch.object(credentials,'os',MissingRootBoundary()):
                with self.assertRaises(tokens.TokenLauncherHold):
                    tokens.require_current_owned_project_token(sheet,binding,auth)
            self.assertEqual(original,tokens.require_current_owned_project_token(sheet,binding,auth))
            with mock.patch.object(target,'os',MissingRootBoundary()):
                with self.assertRaises(target.OnlineTargetHold):
                    target.inspect_project_online_target(writer,binding)
            self.assertEqual(binding,target.inspect_project_online_target(writer,binding))

    def test_real_current_receipt_replaced_after_actual_k_settings_finalizer_refuses_compiler_receiver_return(self):
        self._native_completed_archive_preview_probe(local_c6=True,native_current_compiler=True,current_receipt_tail=True)

    def test_real_complete_archive_old_receipt_rebind_refuses_next_default_local_c6(self):
        self._native_completed_archive_preview_probe(receipt_rebind=True, local_c6=True)

    def test_real_complete_archive_settings_last_finalizer_receipt_rebind_never_acks_next_local_c6(self):
        self._native_completed_archive_preview_probe(local_c6=True,settings_finalizer=True)

    def _complete_original_audits_then_preview(self, *, mode, observed, global_root,
            private_context, native_count_context, fixture_owners, writer_token,
            spreadsheet_token, binding, credential, unit, state, owner_module,
            global_journal, committed, expected_audits, quota_raw, history_raw):
        # Business expectations are literal source-fixture inputs, not WIRE,
        # matcher output, catalog business rows or an implementation helper.
        from copy import deepcopy
        from test_cases.test_req7_remote_history_match import Req7OwnedHistoryMatchWorkflowTests, load as load_remote
        from test_cases.test_req7_sheets_read_decode import header_response, identity_response
        from test_cases.test_req7_history_read_launcher import scoped_fixture
        from test_cases.test_req7_settings_audit_allocation import load as load_allocation
        from monitor import issue_tracker_manual_preview as manual
        from monitor.issue_tracker_publish_runtime import StageLHold
        def canonical(value):
            return (json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n').encode()
        # The authored discovery fixture puts the first operation-id-sorted
        # edge (leaf-b, 2b71...) in row 3; leaf-a is the absent/new edge.
        business = (
            ('2b71fef8673bdb94157801218f88b6d9f4fe20af2f6f2a9985c60f78f76af7ab',
             'update', 2, {'G':'[MONITOR][eth_cabling][2b71fef8673bdb94] WRONG_PEER: Miswired_Links: leaf-b:swp3 -> leaf-c:swp4',
              'M':'foreign-c','N':'swp10','S':'leaf-b','T':'swp3'}),
            ('633644dc08963f192f3fef7a1fd9ba7133a275c9879d62c02c09928765a072bc',
             'insert', None, {'A':'NV40000','B':'ZTP Monitor','C':'ZTP Monitor','D':'2026-09-26',
              'E':'ETH','F':'Mis-wiring','G':'[MONITOR][eth_cabling][633644dc08963f19] WRONG_PEER: Miswired_Links: leaf-a:swp1 -> leaf-z:swp2',
              'K':'leaf-a','L':'swp1','M':'foreign-z','N':'swp9','Q':'leaf-z','R':'swp2',
              'S':'leaf-a','T':'swp1','U':'New'}))
        action = json.loads(unit.action_preimage)
        rows=[]
        common={'schema_version':1,'unit_id':unit.unit_id,'manifest_id':action['manifest_id'],
            'generation_id':committed.receipt.generation_id,'publish_id':committed.receipt.published_sha256,
            'action_digest':unit.action_digest,'outcome_mapping_sha256':unit.outcome_mapping_sha256,
            'target_nonce':action['target_nonce'],'history_nonce':action['history_nonce'],
            'preread_sha256':action['preread_sha256']}
        self.assertEqual(2,len(action['business']))
        for actual,(key,kind,row_index,values) in zip(action['business'],business):
            operation='stl-'+key
            intended=hashlib.sha256(canonical({'sheet':'ETH Cabling','sheet_id':102,
                'action':kind,'row_index':row_index,
                'values':{column:{'stringValue':value} for column,value in values.items()}})).hexdigest()
            self.assertEqual((operation,key,kind,'2026-09-26T04:20:00Z',intended),
                (actual['operation_id'],hashlib.sha256(json.dumps(actual['activity_key'],separators=(',',':')).encode()).hexdigest(),actual['action'],
                 actual['recorded_at_utc'],actual['intended_sha256']))
            rows.append(('2026-09-26T04:20:00Z','ETH Cabling',kind,operation,
                canonical({**common,'operation_id':operation,'intended_sha256':intended}).decode().rstrip('\n')))
        self.assertEqual(list(expected_audits),action['audits'])
        for audit in expected_audits:
            rows.append((audit['recorded_at_utc'],'ETH Cabling','settings-audit',audit['event_id'],
                canonical({**common,'event_id':audit['event_id'],'event_details':audit['details']}).decode().rstrip('\n')))
        post=deepcopy(json.loads(history_raw.data))
        post['sheets'][0]['data'][0]['rowData']=[{'values':[
            {'userEnteredValue':{'stringValue':value}} for value in row]} for row in rows]
        metadata=deepcopy(json.loads(quota_raw.data))
        metadata['matchedDeveloperMetadata'].append({'developerMetadata':{
            'metadataId':unit.fence_metadata_id,'metadataKey':'z','metadataValue':'1',
            'visibility':'DOCUMENT','location':{'locationType':'SHEET','sheetId':102}}})
        native=Req7OwnedHistoryMatchWorkflowTests();native.root=global_root
        native.path=global_root/'etc/ssl/certs/ca-certificates.crt';native.addCleanup=self.addCleanup
        documents={'identity_response':('template_identity',identity_response()),
            'headers_response':('template_headers',header_response()),
            'metadata_response':('metadata',metadata),'history_response':('history_tail',post)}
        responses={name:native.read_owned(private_context,writer_token,spreadsheet_token,
            binding,credential,kind,value) for name,(kind,value) in documents.items()}
        remote=load_remote();allocation=load_allocation()
        remote.record_owned_completion_evidence(writer_token,spreadsheet_token,binding,unit,**responses)
        if '-native-current-compiler' in mode:
            remote.record_owned_applied_evidence(writer_token,spreadsheet_token,binding,unit,generation=committed.generation)
            remote.record_owned_applied_key_watermarks(writer_token,spreadsheet_token,binding,unit,generation=committed.generation)
        tracker=Path(self.store.project_identity)/'.tracker'
        projections={str(revision)+'.json':(tracker/'settings/outbox'/(str(revision)+'.json')).read_bytes()
            for revision in (0,1)}
        allocation.record_completed_settings_delivery(writer_token,spreadsheet_token,binding,unit)
        prior={p.name for p in (tracker/'quarantine').iterdir()}
        result=allocation.cleanup_completed_settings_outbox(writer_token,spreadsheet_token,binding,unit)
        self.assertEqual(('DELIVERED-PRESENT-OUTBOX-ABSENT-VALID',tuple(a['event_id'] for a in expected_audits)),
            (result.state,result.event_ids))
        archived=[p for p in (tracker/'quarantine').iterdir() if p.name not in prior]
        self.assertEqual(2,len(archived));self.assertEqual(sorted(projections.values()),sorted(p.read_bytes() for p in archived))
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in archived))
        self.assertEqual([],list((tracker/'settings/outbox').iterdir()))
        retained=global_journal.inspect_global_unit(spreadsheet_token,binding,unit)
        self.assertEqual((1,'UNKNOWN'),(retained.attempt_count,retained.outcome))
        # Leave every old read/preparation and both old owner locks before
        # asking the real broker to acquire its own default read owner.
        native_count_context.close();private_context.close();fixture_owners.close()
        receipt_rebind = 'receipt-rebind' in mode
        if receipt_rebind:
            receipt=tracker/'generations'/committed.receipt.generation_id/'RECEIPT'
            old=(receipt.stat().st_ino,receipt.read_bytes())
            receipt.rename(global_root/'owned-original-receipt');receipt.write_bytes(old[1]);receipt.chmod(0o600)
            self.assertEqual(old[1],receipt.read_bytes());self.assertNotEqual(old[0],receipt.stat().st_ino)
        before={str(p):(p.stat().st_ino,p.read_bytes())
            for root in (Path(self.store.project_identity),state) for p in root.rglob('*') if p.is_file()}
        broker=manual.make_complete_protected_stage_l_broker(self.store,http_root=self.root,
            project=Path(self.store.project_identity),publication=self.publication,template_path=self.template,
            boot_id='completed-archive-read-only',clock=lambda:1000.,monotonic_ns=time.monotonic_ns)
        with scoped_fixture(global_root,owner_module):
            if receipt_rebind:
                # Original source-authority failure belongs to the Stage L
                # reader contract, not the browser-request validation contract.
                with self.assertRaises(StageLHold):broker.preview('nvis','Switch Status')
                self.assertEqual(0,broker.pending_count)
            else:
                preview=broker.preview('nvis','Switch Status')
                self.assertEqual(('Switch Status','ETH&IB Switch','disabled_no_send_authority'),
                    (preview['panel'],preview['target_sheet'],preview['online']))
                self.assertEqual((2,0,0,0,2),tuple(preview[name] for name in (
                    'qualified_operation_count','whitelist_skip_count','new_count','update_count','skip_count')))
                self.assertEqual(2,len(preview['row_digests']));self.assertEqual(2,len(preview['source_files']))
                for source in preview['source_files']:
                    self.assertEqual(source['sha256'],hashlib.sha256((self.root/source['path']).read_bytes()).hexdigest())
        after={str(p):(p.stat().st_ino,p.read_bytes())
            for root in (Path(self.store.project_identity),state) for p in root.rglob('*') if p.is_file()}
        self.assertEqual(before,after)
        observed.append('ETH Cabling:archived:fresh-preview:'+('HOLD' if receipt_rebind else 'read-only'))
        if '-local-c6' in mode:
            from monitor.collection_ib_producer import produce_worker_ib_analysis
            from monitor.issue_tracker_publish_runtime import commit_qualified_prod_local
            from monitor.issue_tracker_local_workbook_commit import CommittedProdWorkbook
            from test_cases.test_collection_cycle_persistence import TOKEN_2
            from tools.project_contract import build_collection_cycle_identity, MIN_CONTINUOUS_INTERVAL_MINUTES
            project = Path(self.store.project_identity)
            identity = build_collection_cycle_identity(str(project), 'prod', 2, TOKEN_2)
            ib = produce_worker_ib_analysis(identity, project_root=project, http_root=self.root,
                clock=lambda: dt.datetime(2026, 9, 26, 4, 31, tzinfo=dt.timezone.utc),
                runner=lambda _argv: self.fail('transport is supplied by fixture'))
            cycle, _ = self._cycle(activity=True, derivation=True, observed_peer='changed-peer',
                ib_analysis=ib, fabric_templates={'ethernet/prod':'tan-leaf','nvlink/prod':'border-leaf'})
            self.assertEqual(identity['cycle_id'], cycle['cycle_id'])
            admissions = sorted((tracker/'admissions').iterdir())
            self.assertEqual(1, len(admissions))
            prior = json.loads(admissions[0].read_bytes())
            later = prior['monotonic_ns'] + MIN_CONTINUOUS_INTERVAL_MINUTES * 60 * 1_000_000_000 + 1
            witness = (prior['policy_sha256'], prior['publish_every_cycles'], prior['boot_id'], later)
            originals = {str(p):(p.stat().st_ino,p.read_bytes())
                for root in (tracker, state) for p in root.rglob('*') if p.is_file()}
            from monitor import issue_tracker_settings_audit_allocation as allocation
            native_settings=allocation._hold_settings_originals;closed=[];selected_finalizer=[]
            receipt=tracker/'generations'/committed.receipt.generation_id/'RECEIPT'
            @contextmanager
            def finalizer_drift(*args,**kwargs):
                from monitor import issue_tracker_state_owner as actual_state
                native_context=actual_state._COMPLETED_READ_CONTEXT.get(args[0])
                # Fault only the outer handoff's retained settings holder,
                # not nested actual settings inspections before C6 writes.
                selected=(not selected_finalizer
                    and native_context in allocation._LIVE_NATIVE_SETTINGS_CONTEXTS)
                if selected:selected_finalizer.append(True)
                with native_settings(*args,**kwargs) as original:
                    yield original
                if not selected:return
                # Real settings finalization has finished, not a fake guard.
                self.assertEqual(1,len(owner_module._ACTIVE))
                self.assertEqual({},allocation._LIVE_NATIVE_SETTINGS_CONTEXTS)
                self.assertEqual({},allocation._LIVE_LOCAL_C6_CONTEXTS)
                raw=receipt.read_bytes();receipt.rename(global_root/'owned-last-finalizer-receipt')
                receipt.write_bytes(raw);receipt.chmod(0o600);closed.append(True)
            with scoped_fixture(global_root,owner_module), ExitStack() as patches:
                patches.enter_context(mock.patch('monitor.issue_tracker_admission.time.monotonic_ns',return_value=later))
                # Bounded diagnostics retain the FIRST unsanitized original
                # fault, without replacing any actual holder/check or oracle.
                from monitor import issue_tracker_unit_catalog as actual_catalog
                diagnostics=[]
                def diagnosed(function):
                    def actual(*args,**kwargs):
                        try:return function(*args,**kwargs)
                        except BaseException as exc:
                            if len(diagnostics)<8:
                                import traceback
                                diagnostics.append((function.__qualname__,type(exc).__name__))
                                print('OWNED_LOCAL_C6_ORIGINAL_FAILURE',diagnostics[-1],flush=True)
                                traceback.print_exc(file=sys.stdout)
                            raise
                    return actual
                for actual_type,name in ((allocation._LocalC6Originals,'retain'),
                        (allocation._LocalC6Originals,'verify'),
                        (actual_catalog._Originals,'directory'),(actual_catalog._Originals,'file'),
                        (actual_catalog._Originals,'verify')):
                    patches.enter_context(mock.patch.object(actual_type,name,
                        new=diagnosed(getattr(actual_type,name))))
                if '-settings-finalizer-' in mode:
                    patches.enter_context(mock.patch.object(allocation,'_hold_settings_originals',side_effect=finalizer_drift))
                if receipt_rebind or '-settings-finalizer-' in mode:
                    with self.assertRaises(StageLHold):
                        commit_qualified_prod_local(self.store,http_root=self.root,project=project,
                            publication=self.publication,template_path=self.template,manual_admission=witness)
                else:
                    result = commit_qualified_prod_local(self.store,http_root=self.root,project=project,
                        publication=self.publication,template_path=self.template,manual_admission=witness)
                    self.assertIsInstance(result, CommittedProdWorkbook)
                    self.assertNotEqual(committed.receipt.generation_id,result.receipt.generation_id)
                    self.assertEqual(2,len(list((tracker/'generations').iterdir())))
                    records = sorted((tracker/'admissions').iterdir())
                    self.assertEqual(2,len(records))
                    admitted = json.loads(records[-1].read_bytes())
                    self.assertEqual(('manual',cycle['cycle_id'],result.receipt.generation_id),
                        (admitted['lane'],admitted['cycle_id'],admitted['generation_id']))
            for name,image in originals.items():
                path = Path(name)
                if '-settings-finalizer-' in mode and path==receipt:
                    self.assertEqual(image[1],path.read_bytes());self.assertNotEqual(image[0],path.stat().st_ino)
                    continue
                self.assertEqual(image,(path.stat().st_ino,path.read_bytes()),name)
            self.assertEqual([],list((tracker/'settings/outbox').iterdir()))
            if receipt_rebind:
                self.assertEqual(1,len(list((tracker/'generations').iterdir())))
                self.assertEqual(1,len(list((tracker/'admissions').iterdir())))
            if '-settings-finalizer-' in mode:
                self.assertEqual([True],closed)
                self.assertEqual(2,len(list((tracker/'generations').iterdir())))
            observed.append('ETH Cabling:archived:next-local-c6:'+('HOLD' if receipt_rebind or closed else 'committed'))
            if '-native-current-compiler' in mode:
                self._compile_current_switch_after_actual_archive(global_root=global_root,owner_module=owner_module,
                    binding=binding,credential=credential,committed=result,cycle_id=cycle['cycle_id'],observed=observed,
                    receipt_tail='-receipt-tail' in mode,native=native,issued_reads='-issued-reads' in mode,
                    issued_read_tail='-issued-tail' in mode)

    def _compile_current_switch_after_actual_archive(self, *, global_root,owner_module,binding,credential,
                                                    committed,cycle_id,observed,receipt_tail=False,native=None,issued_reads=False,
                                                    issued_read_tail=False):
        if issued_reads:
            self._compile_current_issued_switch_after_actual_archive(global_root=global_root,owner_module=owner_module,
                binding=binding,credential=credential,committed=committed,observed=observed,native=native,
                issued_read_tail=issued_read_tail)
            return
        from monitor import issue_tracker_local_commit as local,issue_tracker_nv_reservation as native
        from monitor import issue_tracker_remote_history_match as remote,issue_tracker_unit_catalog as catalog
        from monitor import issue_tracker_send_unit as compiler
        from monitor.issue_tracker_sheets_read_plan import (
            prepare_activity_sheet_read,prepare_insertion_sheet_read,prepare_sheets_read,
            prepare_history_tail_read,prepare_template_identity_read)
        from monitor.issue_tracker_sheets_read_decode import decode_template_identity
        from test_cases.test_req7_sheets_read_decode import identity_response,response
        from test_cases.test_req7_activity_discovery import (
            reserved_switch_row,sheet_document,insertion_document,exact_row_document)
        from test_cases.test_req7_history_read_launcher import scoped_fixture
        project=Path(self.store.project_identity);tracker=project/'.tracker'
        identity=decode_template_identity(prepare_template_identity_read(binding,credential),response(identity_response()))
        rows=[reserved_switch_row(index) for index in range(2,6)]
        discovery=sheet_document('ETH&IB Switch',rows,100)
        occupancy=insertion_document('ETH&IB Switch',rows,100)
        for document in (discovery,occupancy):document['sheets'][0]['properties']['sheetId']=101
        history=response({'spreadsheetId':binding.spreadsheet_id,'sheets':[{'properties':{
            'sheetId':105,'title':'Update_History','sheetType':'GRID',
            'gridProperties':{'rowCount':100,'columnCount':5}},'data':[{'startRow':2,'startColumn':0}]}]})
        discovery_plan=prepare_activity_sheet_read(binding,credential,sheet='ETH&IB Switch')
        occupancy_plan=prepare_insertion_sheet_read(binding,credential,sheet='ETH&IB Switch')
        metadata={'project_id':str(project),'schema_version':1,'producer_version':'stage-l-runtime-v1',
            'template_contract_version':'local-xlsx-v1','template_sha256':self.snapshot.workbook_sha256}
        from monitor import issue_tracker_settings_audit_allocation as allocation,issue_tracker_state_owner as state_owner
        compiled=[];switched=[];original_settings=allocation._hold_settings_originals
        current_receipt=tracker/'generations'/committed.receipt.generation_id/'RECEIPT'
        @contextmanager
        def after_actual_settings_close(*args,**kwargs):
            with original_settings(*args,**kwargs) as actual:yield actual
            if not compiled or switched:return
            raw=current_receipt.read_bytes();before=current_receipt.stat().st_ino
            original=global_root/'owned-current-c6-original-receipt'
            current_receipt.rename(original);current_receipt.write_bytes(raw);current_receipt.chmod(0o600)
            self.current_receipt_tail_facts=(
                not state_owner._NATIVE_CATALOG_K_READ_CONTEXT and not allocation._LIVE_NATIVE_CATALOG_K_CONTEXTS,
                before!=current_receipt.stat().st_ino,original.read_bytes()==current_receipt.read_bytes())
            switched.append(True)
        with local.writer_owner(project,self.publication) as writer,scoped_fixture(global_root,owner_module), \
                owner_module.spreadsheet_owner(binding) as sheet,ExitStack() as patches:
            if receipt_tail:patches.enter_context(mock.patch.object(allocation,'_hold_settings_originals',after_actual_settings_close))
            with self._assertion_preserving_preparation(native.hold_catalog_nonallocating_preparation(
                    writer,sheet,binding,identity,generation_id=committed.receipt.generation_id,
                    publish_id=committed.receipt.published_sha256,sheet='ETH&IB Switch')) as prepared:
                receiver_refused=False
                try:
                    with self._assertion_preserving_preparation(remote._hold_native_current_cycle_compiler_inputs(prepared,writer,sheet,binding,
                        _store=self.store,http_root=self.root)) as packet:
                        settings,whitelist,qualified,receipts=packet
                        self.assertEqual((1,1),(settings.revision,settings.k))
                        self.assertEqual((cycle_id,),qualified.cycle_ids)
                        self.assertEqual((cycle_id,1,(committed.receipt.generation_id,)),
                            (receipts.cycle_id,receipts.published,receipts.generation_ids))
                        candidates=tuple(item for item in qualified.candidates if item.activity_key[0]=='switch')
                        self.assertEqual(2,len(candidates));reads=[]
                        for offset,candidate in enumerate(candidates):
                            exact=exact_row_document('ETH&IB Switch',rows[offset],offset+2)
                            exact['sheets'][0]['properties']['sheetId']=101
                            reads.append({'operation_id':candidate.operation_id,'discovery_plan':discovery_plan,
                                'discovery_response':response(discovery),'occupancy_plan':occupancy_plan,
                                'occupancy_response':response(occupancy),'row_plan':prepare_sheets_read(binding,credential,
                                    mode='row_rectangle',sheet='ETH&IB Switch',first_row=offset+3),'row_response':response(exact)})
                        unit=compiler.freeze_observed_receipted_switch_unit(qualified,self.store,http_root=self.root,
                            settings=settings,whitelist_snapshot=whitelist,whitelist_path=self.template,metadata=metadata,
                            expected_template_sha256=whitelist.workbook_sha256,
                            local_generation_id=committed.receipt.generation_id,business_reads=tuple(reads),
                            history_plan=prepare_history_tail_read(binding,credential),history_response=history,
                            spreadsheet_token=sheet,binding=binding,identity=identity,writer_token=writer,
                            _unit_preparation=prepared)
                        action=json.loads(unit.action_preimage)
                        self.assertEqual(committed.receipt.generation_id,action['identity']['generation_id'])
                        self.assertEqual(committed.receipt.published_sha256,action['identity']['publish_id'])
                        self.assertEqual(committed.receipt.manifest_id,action['manifest_id'],
                            'local default C6 and online compiler must freeze the same changeset')
                        self.assertEqual(['insert','insert'],[item['action'] for item in action['business']])
                        self.assertEqual([[(101,row,column) for column in (1,5,9,13)] for row in (2,3)],
                            [[(request['updateCells']['start']['sheetId'],
                               request['updateCells']['start']['rowIndex'],
                               request['updateCells']['start']['columnIndex'])
                              for request in item['requests']] for item in action['business']])
                        self.assertEqual([],action['audits'])
                        compiled.append(True)
                        if not receipt_tail:catalog.register_pending_c6_unit(writer,sheet,binding,unit,_unit_preparation=prepared)
                except remote.RemoteHistoryHold:
                    if not receipt_tail:raise
                    receiver_refused=True
                if receipt_tail:
                    observed.append('ETH&IB Switch:archived:current-cycle-compiler:'+('tail-refused' if receiver_refused else 'tail-escaped'))
                    # Exact operator interruption exits the unregistered real
                    # native scope, retaining the fault; its own unregistered
                    # HOLD cannot substitute for receiver refusal above.
                    raise self.current_receipt_tail_primary
            with catalog.hold_pending_project_c6_units(sheet,binding) as (units,verify):
                self.assertEqual(2,len(units));self.assertEqual(unit.unit_id,units[-1].unit.unit_id);verify()
        self.assertEqual([],list((tracker/'settings/outbox').iterdir()))
        observed.append('ETH&IB Switch:archived:current-cycle-compiler:registered')

    def _compile_current_issued_switch_after_actual_archive(self, *, global_root,owner_module,binding,
                                                           credential,committed,observed,native,issued_read_tail=False):
        import socket
        from monitor import issue_tracker_local_commit as local,issue_tracker_nv_reservation as preparation
        from monitor import issue_tracker_remote_history_match as remote,issue_tracker_unit_catalog as catalog
        from monitor import issue_tracker_history_read_launcher as launcher
        from monitor import issue_tracker_credential_shape as credentials,issue_tracker_online_target as target
        from monitor import issue_tracker_settings_audit_allocation as allocation,issue_tracker_state_owner as state_owner
        from test_cases.test_req7_history_read_launcher import Req7HistoryReadLauncherWorkflowTests,scoped_fixture
        from test_cases.test_req7_sheets_read_decode import identity_response,response
        from test_cases.test_req7_activity_discovery import reserved_switch_row,sheet_document,insertion_document,exact_row_document
        from monitor.issue_tracker_sheets_read_plan import prepare_template_identity_read
        from monitor.issue_tracker_sheets_read_decode import decode_template_identity
        rows=[reserved_switch_row(index) for index in range(2,6)]
        discovery=sheet_document('ETH&IB Switch',rows,100);occupancy=insertion_document('ETH&IB Switch',rows,100)
        for document in (discovery,occupancy):document['sheets'][0]['properties']['sheetId']=101
        history={'spreadsheetId':binding.spreadsheet_id,'sheets':[{'properties':{
            'sheetId':105,'title':'Update_History','sheetType':'GRID','gridProperties':{'rowCount':100,'columnCount':5}},
            'data':[{'startRow':2,'startColumn':0}]}]}
        documents={'template_identity':identity_response(),'metadata':{'matchedDeveloperMetadata':[]},
            'activity':discovery,'insertion':occupancy,'history_tail':history}
        issued=[];actual_reads=[];compiled=[];revoked=[]
        real_read=launcher.OwnedProjectSheetsReadUnit.read_once
        original_settings=allocation._hold_settings_originals
        def read(reader):
            if reader._kind=='row':
                self.assertIn(reader._row,(3,4))
                document=exact_row_document('ETH&IB Switch',rows[reader._row-3],reader._row-1)
                document['sheets'][0]['properties']['sheetId']=101
            else:document=documents[reader._kind]
            body=response(document).data
            reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
            with native.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors),ExitStack() as launched:
                port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                calls,children=native.intercept(launched,native.child_fixture(port),writer,sheet,binding)
                actual=real_read(reader)
            self.assertEqual((1,1,(),0),(len(records),len(calls),tuple(errors),children[0].returncode))
            issued.append((reader._kind,reader._row));actual_reads.append(actual);return actual
        @contextmanager
        def revoke_after_actual_settings_close(*args,**kwargs):
            with original_settings(*args,**kwargs) as actual:yield actual
            if not compiled or revoked:return
            self.assertEqual(7,len(actual_reads),'fault must follow successful actual compilation and all issued reads')
            response=actual_reads[0]
            with launcher._PROJECT_READ_GUARD:saved=launcher._PROJECT_READS.pop(response)
            revoked.append((response,saved))
            self.issued_read_tail_facts=(
                not state_owner._NATIVE_CATALOG_K_READ_CONTEXT and not allocation._LIVE_NATIVE_CATALOG_K_CONTEXTS,
                saved is auth,response not in launcher._PROJECT_READS)
        project=Path(self.store.project_identity)
        with local.writer_owner(project,self.publication) as writer,scoped_fixture(global_root,owner_module), \
                owner_module.spreadsheet_owner(binding) as sheet,ExitStack() as private:
            # The old cycle's credential/target fixtures are already closed.
            # A new actual project-auth flow needs its own path/root transport
            # boundaries; the production source and owner checks stay intact.
            private.enter_context(scoped_fixture(global_root,credentials))
            private.enter_context(scoped_fixture(global_root,target))
            auth,_path,_raw=Req7HistoryReadLauncherWorkflowTests.project_auth(native,private,owner_module,sheet,binding)
            if issued_read_tail:
                private.enter_context(mock.patch.object(allocation,'_hold_settings_originals',revoke_after_actual_settings_close))
                before_files={str(path):(path.stat().st_ino,path.read_bytes())
                    for root in (project/'.tracker',global_root/'var/lib/http-ztp-container/issue-tracker')
                    for path in root.rglob('*') if path.is_file()}
            identity=decode_template_identity(prepare_template_identity_read(binding,credential),response(identity_response()))
            with self._assertion_preserving_preparation(preparation.hold_catalog_nonallocating_preparation(
                    writer,sheet,binding,identity,generation_id=committed.receipt.generation_id,
                    publish_id=committed.receipt.published_sha256,sheet='ETH&IB Switch')) as prepared, \
                    mock.patch.object(launcher.OwnedProjectSheetsReadUnit,'read_once',autospec=True,side_effect=read):
                receiver_refused=False
                try:
                    with self._assertion_preserving_preparation(remote._hold_native_current_cycle_observed_switch_unit(
                        prepared,writer,sheet,binding,auth,_store=self.store,http_root=self.root)) as unit:
                        action=json.loads(unit.action_preimage)
                        self.assertEqual(committed.receipt.manifest_id,action['manifest_id'])
                        self.assertEqual((committed.receipt.generation_id,committed.receipt.published_sha256),
                            (action['identity']['generation_id'],action['identity']['publish_id']))
                        self.assertEqual(['insert','insert'],[item['action'] for item in action['business']])
                        self.assertEqual([[(101,row,column) for column in (1,5,9,13)] for row in (2,3)],
                            [[(r['updateCells']['start']['sheetId'],r['updateCells']['start']['rowIndex'],
                                r['updateCells']['start']['columnIndex']) for r in item['requests']] for item in action['business']])
                        compiled.append(True)
                        if not issued_read_tail:catalog.register_pending_c6_unit(writer,sheet,binding,unit,_unit_preparation=prepared)
                except remote.RemoteHistoryHold:
                    if not issued_read_tail:raise
                    receiver_refused=True
                finally:
                    # Restore only this fixture's exact original registry entry
                    # AFTER the receiver tail has actually refused it.
                    for response,saved in revoked:
                        with launcher._PROJECT_READ_GUARD:launcher._PROJECT_READS[response]=saved
                if issued_read_tail:
                    self.assertEqual([True],compiled)
                    self.assertTrue(receiver_refused)
                    self.assertEqual(1,len(revoked))
                    self.assertEqual([('template_identity',None),('metadata',None),('activity',None),('insertion',None),
                        ('row',3),('row',4),('history_tail',None)],issued)
                    record=preparation._verify_catalog_preparation(prepared)
                    self.assertFalse(record['registered']);self.assertIsNone(record['origin'])
                    self.assertIsNone(record['unit']);self.assertEqual(set(),record['additions'])
                    self.assertIsNone(record['appended'])
                    self.assertEqual([],list((project/'.tracker/settings/outbox').iterdir()))
                    self.assertEqual(before_files,{str(path):(path.stat().st_ino,path.read_bytes())
                        for root in (project/'.tracker',global_root/'var/lib/http-ztp-container/issue-tracker')
                        for path in root.rglob('*') if path.is_file()},
                        'issued-tail refusal must not change original catalog/count/CLAIM/WIRE or allocate files')
                    observed.append('ETH&IB Switch:archived:current-cycle-compiler:tail-refused')
                    # The original interruption exits the unregistered native
                    # preparation; its own HOLD cannot fake receiver refusal.
                    raise self.issued_read_tail_primary
            with catalog.hold_pending_project_c6_units(sheet,binding) as (units,verify):
                self.assertEqual(2,len(units));self.assertEqual(unit.unit_id,units[-1].unit.unit_id);verify()
        self.assertEqual([('template_identity',None),('metadata',None),('activity',None),('insertion',None),
            ('row',3),('row',4),('history_tail',None)],issued)
        self.assertEqual([],list((project/'.tracker/settings/outbox').iterdir()))
        observed.append('ETH&IB Switch:archived:current-cycle-compiler:registered')

    def test_real_fresh_c6_all_switch_noops_close_without_catalog_or_audit_consumption(self):
        self.native_no_send_expectation_failure=None
        try:self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe=True)
        except BaseException:
            if self.native_no_send_expectation_failure is not None:raise self.native_no_send_expectation_failure
            raise

    def test_real_fresh_no_send_original_read_revocation_after_preparation_cleanup_refuses_return(self):
        self.native_no_send_expectation_failure=None
        try:self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='tail-revoke')
        except BaseException:
            if self.native_no_send_expectation_failure is not None:raise self.native_no_send_expectation_failure
            raise

    def test_real_fresh_c6_all_cabling_noops_use_original_issued_rows_without_nv_or_catalog(self):
        self.native_no_send_expectation_failure=None
        try:self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='cabling')
        finally:
            if self.native_no_send_expectation_failure is not None:raise self.native_no_send_expectation_failure

    def test_real_fresh_cabling_original_row_revocation_after_cleanup_refuses_zero_write_return(self):
        self.native_no_send_expectation_failure=None
        try:self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='cabling-tail-revoke')
        finally:
            if self.native_no_send_expectation_failure is not None:raise self.native_no_send_expectation_failure

    def test_real_fresh_nonallocating_cabling_closed_or_missing_key_refuses_before_history_or_nv(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='cabling-inactive')

    def test_real_fresh_fixed_cabling_issued_compiler_registers_all_update_wire_without_allocating_ids(self):
        self.native_no_send_expectation_failure=None
        try:self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='cabling-wire')
        finally:
            if self.native_no_send_expectation_failure is not None:raise self.native_no_send_expectation_failure

    def test_real_fresh_fixed_cabling_nv_compiler_uses_both_issued_original_columns_and_reserved_insert_ids(self):
        self.native_no_send_expectation_failure=None
        try:self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='cabling-nv')
        finally:
            if self.native_no_send_expectation_failure is not None:raise self.native_no_send_expectation_failure

    def test_real_fresh_cabling_nv_other_issued_column_drift_refuses_before_compile_and_retains_ids(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='cabling-nv-other-drift')

    def test_real_fresh_cabling_nv_other_original_read_revocation_after_all_preparation_closes_retains_registered_unit(self):
        self.native_no_send_expectation_failure=None
        try:self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='cabling-nv-tail-revoke')
        finally:
            if self.native_no_send_expectation_failure is not None:raise self.native_no_send_expectation_failure

    def test_real_fresh_cabling_nv_bound_tail_and_record_clear_after_cleanup_cannot_downgrade_to_legacy(self):
        self.native_no_send_expectation_failure=None
        try:self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='cabling-nv-tail-clear')
        finally:
            if self.native_no_send_expectation_failure is not None:raise self.native_no_send_expectation_failure

    def test_real_fresh_fixed_current_native_receipt_locator_discovery_reads_actual_c5_c6_without_online_owners(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='native-receipt-locators')

    def test_real_fresh_current_native_locator_original_receipt_rebind_refuses_at_held_history_guard(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='native-receipt-locators-rebind')

    def test_real_current_native_locator_context_receipt_rebind_after_yield_refuses_before_context_completion(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='native-receipt-locators-late-rebind')

    def test_real_fixed_current_native_switch_creator_discovers_c6_and_keeps_no_send_zero_write(self):
        self.native_no_send_expectation_failure=None
        try:self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='fixed-switch-creator')
        finally:
            if self.native_no_send_expectation_failure is not None:raise self.native_no_send_expectation_failure

    def test_real_fixed_current_native_switch_creator_registers_only_original_current_c6_wire(self):
        self.native_no_send_expectation_failure=None
        try:self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='fixed-switch-creator-wire')
        finally:
            if self.native_no_send_expectation_failure is not None:raise self.native_no_send_expectation_failure

    def test_real_fixed_switch_creator_initial_identity_issuer_revoked_after_source_cleanup_cannot_return(self):
        self.native_no_send_expectation_failure=None
        try:self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='fixed-switch-creator-initial-revoke')
        finally:
            if self.native_no_send_expectation_failure is not None:raise self.native_no_send_expectation_failure

    def test_real_fixed_current_eth_ib_cabling_creators_keep_no_send_zero_write(self):
        self.native_no_send_expectation_failure=None
        try:self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='fixed-cabling-creator')
        finally:
            if self.native_no_send_expectation_failure is not None:raise self.native_no_send_expectation_failure

    def test_real_fixed_current_eth_ib_cabling_creators_register_original_active_row_wire(self):
        self.native_no_send_expectation_failure=None
        try:self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='fixed-cabling-creator-wire')
        finally:
            if self.native_no_send_expectation_failure is not None:raise self.native_no_send_expectation_failure

    def test_real_fixed_current_cabling_creator_initial_identity_issuer_revoked_after_source_cleanup_cannot_return(self):
        self.native_no_send_expectation_failure=None
        try:self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='fixed-cabling-creator-initial-revoke')
        finally:
            if self.native_no_send_expectation_failure is not None:raise self.native_no_send_expectation_failure

    def test_real_fixed_current_eth_ib_cabling_creators_choose_original_nv_for_closed_keys(self):
        self.native_no_send_expectation_failure=None
        try:self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='fixed-cabling-creator-nv')
        finally:
            if self.native_no_send_expectation_failure is not None:raise self.native_no_send_expectation_failure

    def test_real_fixed_current_nv_cabling_creator_initial_identity_issuer_revoked_after_source_cleanup_cannot_return(self):
        self.native_no_send_expectation_failure=None
        try:self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='fixed-cabling-creator-nv-initial-revoke')
        finally:
            if self.native_no_send_expectation_failure is not None:raise self.native_no_send_expectation_failure

    def test_real_fixed_current_eth_ib_cabling_creators_choose_original_nv_for_missing_keys(self):
        self.native_no_send_expectation_failure=None
        try:self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='fixed-cabling-creator-nv-missing')
        finally:
            if self.native_no_send_expectation_failure is not None:raise self.native_no_send_expectation_failure

    def test_real_fixed_current_nv_cabling_creator_selection_column_issuer_revoked_after_source_cleanup_cannot_return(self):
        self.native_no_send_expectation_failure=None
        try:self._exercise_real_protected_three_panel_fixture(skip_history=False,native_current_no_send_probe='fixed-cabling-creator-nv-selection-revoke')
        finally:
            if self.native_no_send_expectation_failure is not None:raise self.native_no_send_expectation_failure

    def _verify_fresh_native_switch_no_send(self,committed,qualified,*,tail_revoke=False,_sheet='ETH&IB Switch',_inactive=None,_wire=False,_nv=False,_other_drift=False,_tail_clear=False,_fixed_creation=False,_initial_revoke=False,_selection_revoke=False):
        import tempfile
        import socket
        from test_cases.test_req7_spreadsheet_owner import load as load_owner,scoped_fixture
        from test_cases.test_req7_enrollment_journal import load as load_enrollment
        from test_cases.test_req7_global_attempt_journal import load as load_global
        from test_cases.test_req7_nv_reservation import load as load_native
        from test_cases.test_req7_unit_catalog import load as load_catalog
        from test_cases.test_req7_remote_history_match import Req7OwnedHistoryMatchWorkflowTests,load as load_remote
        from test_cases.test_req7_history_read_launcher import Req7HistoryReadLauncherWorkflowTests
        from test_cases.test_req7_sdk_authentication import fresh_info
        from test_cases.test_req7_sheets_read_decode import identity_response,response
        from test_cases.test_req7_activity_discovery import reserved_switch_row,cabling_row,literal,sheet_document,insertion_document,exact_row_document
        from monitor import issue_tracker_online_target as target
        from monitor.issue_tracker_online_target import bind_online_target,freeze_target_allowlist
        from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
        from monitor.issue_tracker_sheets_read_plan import prepare_template_identity_read,prepare_activity_sheet_read
        from monitor.issue_tracker_sheets_read_decode import decode_template_identity
        from tools.project_contract import safe_load_global_yaml
        project=Path(self.store.project_identity)
        binding=bind_online_target(safe_load_global_yaml((project/'01-global.yaml').read_text(encoding='utf-8')),
            freeze_target_allowlist(b'["synthetic_spreadsheet_id_0001"]\n'))
        expected_keys=(('switch','leaf-a','fan','PSU1/FAN1'),('switch','nvsw01','asic_temp','ASIC1'))
        self.assertEqual(tuple(sorted(expected_keys)),tuple(sorted(item.activity_key for item in qualified.candidates
            if item.activity_key[0]=='switch')))
        descriptions=(
            '[MONITOR][fan][PSU1/FAN1] [fabric_source=template] PSU1/FAN1: state=fail',
            # NVL device type is authoritative; the Ethernet template rule
            # must not be projected onto this independent NVLink row.
            '[MONITOR][asic_temp][ASIC1] [fabric_source=type] ASIC1: state=ok; current=75 C; max=70 C; critical=80 C')
        if _sheet!='ETH&IB Switch':
            expected_keys=((('eth_cabling','leaf-a','swp1','Mis-wiring'),) if _sheet=='ETH Cabling'
                else (('ib_cabling','leaf01','sw1p1','Mis-wiring'),))
        family={'ETH&IB Switch':'switch','ETH Cabling':'eth_cabling','IB Cabling':'ib_cabling'}[_sheet]
        sid={'ETH&IB Switch':101,'ETH Cabling':102,'IB Cabling':103}[_sheet]
        self.assertEqual(tuple(sorted(expected_keys)),tuple(sorted(item.activity_key for item in qualified.candidates
            if item.activity_key[0]==family)))
        rows=[reserved_switch_row(index) for index in range(2,4)]
        for row,key,description in zip(rows,expected_keys,descriptions):
            row.update({'F':literal(key[1]),'L':literal(description),'N':literal('New')})
        if _wire and _sheet=='ETH&IB Switch':
            old_descriptions=(
                '[MONITOR][fan][PSU1/FAN1] [fabric_source=template] PSU1/FAN1: state=ok',
                '[MONITOR][asic_temp][ASIC1] [fabric_source=type] ASIC1: state=ok; current=70 C; max=70 C; critical=80 C')
            for row,description in zip(rows,old_descriptions):row['L']=literal(description)
        if _sheet!='ETH&IB Switch':
            key=expected_keys[0]
            # Literal source fixtures and independent key hash, never values
            # copied from the compiler, ACTION, WIRE or source_tool_values.
            # Existing source key-digest contract hashes compact JSON itself,
            # not the newline-terminated journal image format.
            digest=hashlib.sha256(json.dumps(key,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()[:16]
            if _sheet=='ETH Cabling':
                values={'G':f'[MONITOR][eth_cabling][{digest}] WRONG_PEER: Miswired_Links: leaf-a:swp1 -> leaf-z:swp2',
                    'M':'foreign-z','N':'swp9','S':'leaf-a','T':'swp1'}
            else:
                values={'G':f'[MONITOR][ib_cabling][{digest}] Mis-wiring: Miswired_Links!2: leaf01:sw1p1 -> server01:mlx5_0',
                    'M':'leaf01','N':'sw1p1','S':'server02','T':'mlx5_1'}
            active=cabling_row('NV30016')
            active.update({column:literal(value) for column,value in {**values,'K':key[1],'L':key[2],'F':key[3]}.items()})
            if _wire:active['G']=literal('older original business evidence')
            if _nv:active['U']=literal('Closed')
            rows=[active]
            if _inactive=='closed':active['U']=literal('Closed')
            elif _inactive=='missing':rows=[]
        discovery=sheet_document(_sheet,rows,100)
        occupancy=insertion_document(_sheet,rows,100)
        for document in (discovery,occupancy):document['sheets'][0]['properties']['sheetId']=sid
        documents={'template_identity':identity_response(),'metadata':{'matchedDeveloperMetadata':[]},
            'activity':discovery,'insertion':occupancy,'history_tail':{'spreadsheetId':binding.spreadsheet_id,
                'sheets':[{'properties':{'sheetId':105,'title':'Update_History','sheetType':'GRID',
                    'gridProperties':{'rowCount':100,'columnCount':5}},'data':[{'startRow':2,'startColumn':0}]}]}}
        if _nv:
            other_sheet='IB Cabling' if _sheet=='ETH Cabling' else 'ETH Cabling'
            other=cabling_row('NV39999','Closed');other['K']=literal('unrelated-original-seed')
            other_document=sheet_document(other_sheet,[other],100)
            other_document['sheets'][0]['properties']['sheetId']=103 if other_sheet=='IB Cabling' else 102
        with tempfile.TemporaryDirectory(prefix='req7-fresh-native-no-send-') as directory:
            global_root=Path(directory).resolve()
            state=global_root/'var/lib/http-ztp-container/issue-tracker';state.mkdir(parents=True,mode=0o700)
            private_dir=global_root/'var/lib/http-ztp-container/service-account';private_dir.mkdir(mode=0o700)
            private_dir.joinpath('issue-tracker-spreadsheet-whitelist.json').write_bytes(b'["synthetic_spreadsheet_id_0001"]\n')
            private_dir.joinpath('issue-tracker-spreadsheet-whitelist.json').chmod(0o600)
            credential_info=fresh_info();credential_info['project_id']='synthetic-cloud-project'
            credential_path=private_dir/'cre.json';credential_path.write_bytes(json.dumps(credential_info).encode())
            credential_path.chmod(0o600)
            owner_module=load_owner();enrollment=load_enrollment();load_global()
            native_module=load_native();catalog_module=load_catalog(reset_dependencies=False);load_remote()
            from monitor import issue_tracker_local_commit as local,issue_tracker_remote_history_match as remote
            from monitor import issue_tracker_history_read_launcher as launcher,issue_tracker_send_unit as compiler
            from monitor import issue_tracker_credential_shape as credentials
            native=Req7OwnedHistoryMatchWorkflowTests();native.root=global_root
            native.path=global_root/'etc/ssl/certs/ca-certificates.crt';native.path.parent.mkdir(parents=True)
            native.addCleanup=self.addCleanup
            certificates=self._fixture_certificate_supplier(type(native).certificates)
            native.certificates=lambda hostname='oauth2.googleapis.com':certificates(native,hostname)
            issued=[];compiled=[];units=[];issued_objects=[]
            real_read=launcher.OwnedProjectSheetsReadUnit.read_once
            compiler_name=('freeze_observed_receipted_switch_unit' if _sheet=='ETH&IB Switch'
                else 'freeze_observed_receipted_cabling_unit')
            actual_compiler=getattr(compiler,compiler_name)
            def compile_actual(*args,**kwargs):
                unit=actual_compiler(*args,**kwargs)
                try:
                    self.assertEqual('WIRE-CANDIDATE' if _wire or _nv else 'NO_SEND',unit.outcome)
                    self.assertEqual((6 if _nv else 5+len(expected_keys))
                        +(3 if _nv and _fixed_creation else 2 if _fixed_creation and _sheet!='ETH&IB Switch'
                            else int(_fixed_creation)),len(issued),
                        'target RED must follow every genuine issued read, including the fixed creator identity read')
                    self.assertEqual(('WIRE-CANDIDATE' if _wire or _nv else 'OBSERVED-SATISFIED-AT-READ',)*len(expected_keys),
                        tuple(outcome for _key,outcome in unit.outcomes))
                    self.assertEqual(committed.receipt.manifest_id,json.loads(unit.action_preimage)['manifest_id'])
                    if _nv:
                        self.assertEqual(1,unit.history_rows_expected);self.assertIs(type(unit.fence_metadata_id),int)
                        requests=json.loads(unit.wire_bytes)['requests']
                        inserts=[request['appendCells'] for request in requests
                            if 'appendCells' in request and request['appendCells']['sheetId']==sid]
                        self.assertEqual(1,len(inserts));self.assertEqual('userEnteredValue',inserts[0]['fields'])
                        cells=inserts[0]['rows'][0]['values']
                        expected={'A':'NV40000','G':values['G'],'K':key[1],'L':key[2],
                            'M':values['M'],'N':values['N'],'Q':'leaf-z' if _sheet=='ETH Cabling' else 'server01',
                            'R':'swp2' if _sheet=='ETH Cabling' else 'mlx5_0','S':values['S'],'T':values['T'],'U':'New'}
                        self.assertEqual({column:{'stringValue':value} for column,value in expected.items()},
                            {column:cells[ord(column)-65]['userEnteredValue'] for column in expected})
                        self.assertFalse(any('updateCells' in request for request in requests))
                    elif _wire:
                        self.assertTrue(unit.wire_bytes);self.assertIs(type(unit.fence_metadata_id),int)
                        self.assertEqual(2 if _sheet=='ETH&IB Switch' else 1,unit.history_rows_expected)
                        requests=json.loads(unit.wire_bytes)['requests']
                        updates=[request['updateCells'] for request in requests if 'updateCells' in request]
                        if _sheet=='ETH&IB Switch':
                            self.assertEqual([(101,3,11),(101,2,11)],
                                [(item['start']['sheetId'],item['start']['rowIndex'],item['start']['columnIndex']) for item in updates])
                            self.assertEqual([[{'stringValue':description}] for description in reversed(descriptions)],
                                [[cell['userEnteredValue'] for cell in item['rows'][0]['values']] for item in updates])
                        else:
                            self.assertEqual([(sid,2,6),(sid,2,12),(sid,2,18)],
                                [(item['start']['sheetId'],item['start']['rowIndex'],item['start']['columnIndex']) for item in updates])
                            self.assertEqual([[{'stringValue':values[column]} for column in run]
                                for run in (('G',),('M','N'),('S','T'))],
                                [[cell['userEnteredValue'] for cell in item['rows'][0]['values']] for item in updates])
                        self.assertFalse(any('appendCells' in request and request['appendCells']['sheetId']==sid for request in requests))
                    else:self.assertEqual((b'',None,0),(unit.wire_bytes,unit.fence_metadata_id,unit.history_rows_expected))
                except AssertionError as exc:
                    self.native_no_send_expectation_failure=exc
                    print('NO_SEND_FIXTURE_COMPILER_RETURN',unit.outcome,json.loads(unit.action_preimage)['business'],flush=True)
                    raise
                compiled.append(unit)
                print('FIXED_COMPILER_PHASE',_sheet,unit.outcome,'actual-C5/C6 compiler,',len(issued),
                    'original issued reads,',unit.history_rows_expected,'History rows',flush=True)
                return unit
            def read(reader):
                if reader._kind=='row':
                    self.assertIn(reader._row,tuple(range(3,3+len(rows))))
                    document=exact_row_document(_sheet,rows[reader._row-3],reader._row-1)
                    document['sheets'][0]['properties']['sheetId']=sid
                elif _nv and reader._kind=='activity' and reader._sheet==other_sheet:
                    document=other_document
                    if _other_drift:
                        from copy import deepcopy
                        document=deepcopy(document)
                        document['sheets'][0]['data'][0]['rowData'][0]['values'][0]['userEnteredValue']=literal('NV49999')
                else:document=documents[reader._kind]
                body=response(document).data
                reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
                with native.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors),ExitStack() as launched:
                    port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                    calls,children=native.intercept(launched,native.child_fixture(port),writer,sheet,binding)
                    actual=real_read(reader)
                self.assertEqual((1,1,(),0),(len(records),len(calls),tuple(errors),children[0].returncode))
                issued.append((reader._kind,reader._row));issued_objects.append(actual);return actual
            locator=AuthenticatedToken('synthetic.private-locator',time.time()+3600)
            identity=decode_template_identity(prepare_template_identity_read(binding,locator),response(identity_response()))
            with local.writer_owner(project,self.publication) as writer,scoped_fixture(global_root,owner_module), \
                    owner_module.spreadsheet_owner(binding) as sheet,ExitStack() as private:
                private.enter_context(scoped_fixture(global_root,credentials))
                private.enter_context(scoped_fixture(global_root,target))
                auth,_path,_raw=Req7HistoryReadLauncherWorkflowTests.project_auth(native,private,owner_module,sheet,binding)
                enrollment.prepare_enrollment_journal(sheet,binding,identity)
                roots=(project/'.tracker',state)
                def originals():return {str(path):(path.stat().st_ino,path.read_bytes())
                    for root in roots for path in root.rglob('*') if path.is_file()}
                before=originals();outbox=project/'.tracker/settings/outbox'
                audits_before={path.name:(path.stat().st_ino,path.read_bytes()) for path in outbox.iterdir()}
                self.assertTrue(audits_before,'the real K change remains pending, not an empty fixture')
                if _fixed_creation:
                    actual_context=remote._hold_current_cycle_native_receipt_locators;revoked=[];returned=[]
                    create_name={'ETH&IB Switch':'_prepare_current_cycle_native_switch_unit',
                        'ETH Cabling':'_prepare_current_cycle_native_eth_cabling_unit',
                        'IB Cabling':'_prepare_current_cycle_native_ib_cabling_unit'}[_sheet]
                    @contextmanager
                    def context(*args,**kwargs):
                        with actual_context(*args,**kwargs) as labels:yield labels
                        if _initial_revoke or _selection_revoke:
                            self.assertFalse(native_module._ACTIVE_CATALOG_PREPARATIONS)
                            first=issued_objects[2 if _selection_revoke else 0]
                            launcher.require_current_owned_project_read(writer,sheet,binding,first,auth,
                                read_kind='activity' if _selection_revoke else 'template_identity',
                                sheet=other_sheet if _selection_revoke else None)
                            with launcher._PROJECT_READ_GUARD:saved=launcher._PROJECT_READS.pop(first)
                            self.assertIs(auth,saved);revoked.append((first,saved))
                    with mock.patch.object(launcher.OwnedProjectSheetsReadUnit,'read_once',autospec=True,side_effect=read), \
                            mock.patch.object(compiler,compiler_name,side_effect=compile_actual), \
                            mock.patch.object(remote,'_hold_current_cycle_native_receipt_locators',side_effect=context):
                        try:
                            if _initial_revoke or _selection_revoke:
                                with self.assertRaises(remote.RemoteHistoryHold):
                                    returned.append(getattr(remote,create_name)(
                                        writer,sheet,binding,auth,_store=self.store,http_root=self.root))
                            else:returned.append(getattr(remote,create_name)(
                                writer,sheet,binding,auth,_store=self.store,http_root=self.root))
                        finally:
                            for first,saved in revoked:
                                with launcher._PROJECT_READ_GUARD:launcher._PROJECT_READS[first]=saved
                    if _initial_revoke or _selection_revoke:self.assertEqual(1,len(revoked));self.assertEqual([],returned)
                    else:self.assertEqual([('WIRE_REGISTERED' if _wire or _nv else 'NO_SEND',compiled[0].unit_id)],returned)
                    if _wire or _nv:
                        after=originals();self.assertEqual(before,{path:after[path] for path in before})
                        self.assertTrue(after.keys()-before.keys())
                        with catalog_module.hold_pending_project_c6_units(sheet,binding) as (pending,verify):
                            self.assertEqual((compiled[0],),tuple(item.unit for item in pending));verify()
                        self.assertFalse(any('.journal' in path.name for path in state.iterdir()))
                        if _nv:
                            stem=hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()
                            folder=state/(stem+'.unit-'+compiled[0].unit_id+'.nv')
                            original_documents=(discovery,other_document) if _sheet=='ETH Cabling' else (other_document,discovery)
                            self.assertEqual(tuple(response(item).data for item in original_documents),
                                tuple((folder/name).read_bytes() for name in ('ETH-RAW','IB-RAW')))
                            self.assertEqual([list(expected_keys[0])+['NV40000']],
                                [list(row[0])+[row[1]] for row in json.loads((folder/'RESERVATIONS').read_bytes())])
                        else:self.assertFalse(any('.nv' in path.name for path in state.iterdir()))
                    else:self.assertEqual(before,originals(),'fixed NO_SEND creation must not write catalog/NV/count/origin')
                    self.assertEqual(audits_before,{path.name:(path.stat().st_ino,path.read_bytes()) for path in outbox.iterdir()})
                    self.assertEqual(1,len(compiled));self.assertFalse(native_module._ACTIVE_CATALOG_PREPARATIONS)
                    self.assertEqual([('template_identity',None)]
                        +([('activity',None),('activity',None)] if _nv else [('activity',None)]
                            if _sheet!='ETH&IB Switch' else [])
                        +[('template_identity',None),('metadata',None),('activity',None)]
                        +([('activity',None)] if _nv else [])+[('insertion',None)]
                        +([] if _nv else [('row',4),('row',3)] if _sheet=='ETH&IB Switch' else [('row',3)])
                        +[('history_tail',None)],issued)
                    return
                original_pin=native_module._pin_catalog_prefix
                tail_name='_verify_nv_project_read_tail' if _nv else '_verify_nonallocating_project_read_tail'
                original_tail=getattr(native_module,tail_name,None)
                retained=[];revoked=[];fault_facts=[];target_holds=[];refused=False
                nv_before=[];column_holds=[]
                actual_column_check=getattr(remote,'_verify_native_issued_nv_columns',None)
                def check_columns(prepared,*args):
                    try:return actual_column_check(prepared,*args)
                    except remote.RemoteHistoryHold:
                        if _other_drift:
                            from monitor.issue_tracker_token_launcher import require_current_owned_project_token
                            require_current_owned_project_token(sheet,binding,auth)
                            for family,completion in zip(('ETH Cabling','IB Cabling'),args[-2:]):
                                launcher.require_current_owned_project_read(writer,sheet,binding,completion,auth,
                                    read_kind='activity',sheet=family)
                            actual=tuple(hashlib.sha256(item.data).hexdigest() for item in args[-2:])
                            expected=(prepared.observation.eth_source_sha256,prepared.observation.ib_source_sha256)
                            column_holds.append(actual!=expected)
                        raise
                def revoke_after_all_closes():
                    record,fds=retained[0]
                    self.assertFalse(native_module._ACTIVE_CATALOG_PREPARATIONS)
                    for fd in fds:
                        with self.assertRaises(OSError):os.fstat(fd)
                    state=record.get('nv_project_read_tail' if _nv else 'project_read_tail')
                    if state is None:
                        fault_facts.append((False,True,False,len(fds)>0))
                        return
                    packet=state.packet
                    self.assertIs(units[0],packet[7]);self.assertIs(auth,packet[5])
                    original_response=packet[6][3 if _nv else 0 if _sheet=='ETH&IB Switch' else 4][3]
                    if _tail_clear:
                        launcher.require_current_owned_project_read(writer,sheet,binding,original_response,auth,
                            read_kind='activity',sheet=other_sheet)
                        state.bound=False;state.packet=None;state._issued_packet=None
                        for name in ('nv_read_writer','nv_read_owner','nv_read_observation'):record[name]=None
                        fault_facts.append((record['registered'],not native_module._ACTIVE_CATALOG_PREPARATIONS,
                            original_response in launcher._PROJECT_READS,len(fds)>0))
                        revoked.append((None,None))
                        return
                    with launcher._PROJECT_READ_GUARD:saved=launcher._PROJECT_READS.pop(original_response)
                    revoked.append((original_response,saved))
                    self.assertIs(auth,saved)
                    fault_facts.append((record['registered'] if _nv else not record['registered'],not native_module._ACTIVE_CATALOG_PREPARATIONS,
                        original_response not in launcher._PROJECT_READS,len(fds)>0))
                def pin(*args,**kwargs):
                    if tail_revoke:kwargs['_project_proofs']['owner_tail'].callback(revoke_after_all_closes)
                    return original_pin(*args,**kwargs)
                def tail(record,state):
                    try:return original_tail(record,state)
                    except native_module.NvReservationHold:
                        if revoked and retained and record is retained[0][0]:target_holds.append(True)
                        raise
                try:
                    if _nv:
                        original_pair=(prepare_activity_sheet_read(binding,locator,sheet=_sheet),response(discovery),
                            prepare_activity_sheet_read(binding,locator,sheet=other_sheet),response(other_document))
                        if _sheet=='IB Cabling':original_pair=(*original_pair[2:],*original_pair[:2])
                        preparation=native_module.hold_catalog_nv_preparation(sheet,binding,identity,*original_pair,
                            generation_id=committed.receipt.generation_id,publish_id=committed.receipt.published_sha256,
                            sheet=_sheet,requested_keys=expected_keys)
                    else:
                        preparation=native_module.hold_catalog_nonallocating_preparation(writer,sheet,binding,identity,
                            generation_id=committed.receipt.generation_id,
                            publish_id=committed.receipt.published_sha256,sheet=_sheet)
                    with mock.patch.object(native_module,'_pin_catalog_prefix',side_effect=pin), \
                            mock.patch.object(native_module,tail_name,side_effect=tail,create=True), \
                            mock.patch.object(remote,'_verify_native_issued_nv_columns',side_effect=check_columns,create=True):
                        with self._assertion_preserving_preparation(preparation) as prepared, \
                                mock.patch.object(launcher.OwnedProjectSheetsReadUnit,'read_once',autospec=True,side_effect=read), \
                                mock.patch.object(compiler,compiler_name,side_effect=compile_actual):
                            if _nv:
                                nv_name=hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()+'.unit-'+prepared.observation.unit_id+'.nv'
                                nv_before.append({path.name:(path.stat().st_ino,path.read_bytes()) for path in (state/nv_name).iterdir()})
                            receiver=(remote._hold_native_current_cycle_observed_switch_unit if _sheet=='ETH&IB Switch'
                                else remote._hold_native_current_cycle_observed_nv_cabling_unit if _nv
                                else remote._hold_native_current_cycle_observed_cabling_unit)
                            try:
                                with self._assertion_preserving_preparation(receiver(
                                        prepared,writer,sheet,binding,auth,_store=self.store,http_root=self.root)) as unit:
                                    self.assertIs(compiled[0],unit);units.append(unit)
                                    record=native_module._verify_catalog_preparation(prepared)
                                    self.assertFalse(record['registered']);self.assertIsNone(record['unit'])
                                    self.assertIsNone(record['origin']);self.assertIsNone(record['indexed'])
                                    if _nv:
                                        stem=hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()
                                        name=stem+'.unit-'+unit.unit_id+'.nv'
                                        self.assertEqual({name,name+'-started'},record['additions'])
                                        self.assertEqual(((expected_keys[0],'NV40000'),),prepared.observation.reservations)
                                    else:self.assertEqual(set(),record['additions'])
                                    self.assertIsNone(record['appended'])
                                    retained.append((record,tuple(item[2] for held in (record['old'],record['current'])
                                        for item in held.files)))
                                    if _wire or _nv:
                                        registration=({'_nv_preparation':prepared} if _nv else {'_unit_preparation':prepared})
                                        catalog_module.register_pending_c6_unit(writer,sheet,binding,unit,**registration)
                                        with catalog_module.hold_pending_project_c6_units(sheet,binding) as (pending,verify):
                                            self.assertEqual((unit,),tuple(item.unit for item in pending));verify()
                                        self.assertTrue(record['registered']);self.assertIs(record['unit'],unit)
                            except remote.RemoteHistoryHold:
                                if _inactive is None and not _other_drift:raise
                                record=native_module._verify_catalog_preparation(prepared)
                                fault_facts.append((len(issued)==4,not compiled,not units,
                                    not record['registered'] and record['origin'] is None
                                        and (record['additions']=={nv_name,nv_name+'-started'} if _nv else not record['additions'])))
                                target_holds.append(True)
                                # Keep the receiver's actual refusal fact
                                # outside sanitized contexts. Let the real
                                # unregistered preparation then close/HOLD;
                                # its HOLD alone cannot satisfy this test.
                except native_module.NvReservationHold:
                    if not tail_revoke and _inactive is None and not _other_drift:raise
                    refused=True
                finally:
                    for original_response,saved in revoked:
                        if original_response is None:continue
                        with launcher._PROJECT_READ_GUARD:launcher._PROJECT_READS[original_response]=saved
                self.assertEqual(tail_revoke or _inactive is not None or _other_drift,refused)
                if tail_revoke or _inactive is not None or _other_drift:
                    self.assertEqual([(True,True,True,True)],fault_facts)
                    self.assertEqual([True],target_holds,'unrelated cleanup HOLD is not target revocation proof')
                if _other_drift:self.assertEqual([True],column_holds,'refusal must be the original two-column verifier with still-valid issuers')
                after=originals()
                if _wire or _nv:
                    self.assertEqual(before,{path:after[path] for path in before},'registration cannot rewrite any prior original')
                    self.assertTrue(after.keys()-before.keys(),'WIRE needs actual unique catalog/origin originals')
                    self.assertFalse(any('.journal' in path.name for path in state.iterdir()),'receiving registration cannot count an attempt')
                    if _nv:
                        folder=state/nv_name
                        original_documents=(discovery,other_document) if _sheet=='ETH Cabling' else (other_document,discovery)
                        self.assertEqual(tuple(response(item).data for item in original_documents),
                            tuple((folder/name).read_bytes() for name in ('ETH-RAW','IB-RAW')))
                        if _other_drift:
                            self.assertEqual(nv_before[0],{path.name:(path.stat().st_ino,path.read_bytes()) for path in folder.iterdir()})
                            self.assertFalse(any('.units' in path.name or '.project-origin' in path.name for path in state.iterdir()))
                    else:self.assertFalse(any('.nv' in path.name for path in state.iterdir()),'all-update registration cannot allocate NV')
                else:self.assertEqual(before,after,'NO_SEND cannot create catalog/NV/INTENT/GLOBAL/COUNT/CLAIM')
                self.assertEqual(audits_before,{path.name:(path.stat().st_ino,path.read_bytes()) for path in outbox.iterdir()})
                self.assertFalse(native_module._ACTIVE_CATALOG_PREPARATIONS)
            if _inactive is not None or _other_drift:
                self.assertEqual([],units);self.assertEqual([],compiled)
                self.assertEqual([('template_identity',None),('metadata',None),('activity',None),
                    ('activity' if _other_drift else 'insertion',None)],issued)
                return
            self.assertEqual(1,len(units));self.assertIs(compiled[0],units[0])
            if _nv:
                self.assertEqual([('template_identity',None),('metadata',None),('activity',None),
                    ('activity',None),('insertion',None),('history_tail',None)],issued)
                return
            expected_rows=[('row',4),('row',3)] if _sheet=='ETH&IB Switch' else [('row',3)]
            self.assertEqual([('template_identity',None),('metadata',None),('activity',None),('insertion',None),
                *expected_rows,('history_tail',None)],issued)

    def test_native_original_settings_audit_receipt_rebind_after_count_refuses_fixed_local_request(self):
        self._native_original_launch_probe('receipt-rebind',settings_audit=True)

    def test_native_original_settings_audit_issued_read_expiry_after_count_refuses_fixed_local_request(self):
        self._native_original_launch_probe('read-expiry',settings_audit=True)

    def test_native_original_receipt_rebind_after_count_refuses_fixed_local_request(self):
        self._native_original_launch_probe('receipt-rebind')

    def test_native_original_issued_read_expiry_after_count_refuses_fixed_local_request(self):
        self._native_original_launch_probe('read-expiry')

    def _exercise_native_original_counted_launch(self, *, mode, observed, global_root, private_context,
            writer_token, spreadsheet_token, binding, credential, unit, identity, quota_raw, history_raw,
            reads, sheet, qualified, settings, committed, state, owner_module, global_journal,
            expected_audits=None):
        from test_cases.test_req7_remote_history_match import Req7OwnedHistoryMatchWorkflowTests, load as load_read_gates
        from test_cases.test_req7_mutation_launcher import Req7MutationLauncherWorkflowTests, load as load_mutation
        from test_cases.test_req7_sheets_read_decode import header_response, identity_response, response
        from test_cases.test_req7_online_whitelist_read import document as whitelist_document
        from monitor import issue_tracker_history_read_launcher as fixed_reads, issue_tracker_local_commit as local
        from contextlib import ExitStack
        import xml.etree.ElementTree as ET
        import socket
        if expected_audits is not None:
            # Outside all counted/launcher exception sanitizers. A compiler
            # that silently drops either audit must fail before this flow,
            # not turn the native-audit case into an unaudited success.
            self.assertEqual(list(expected_audits),json.loads(unit.action_preimage)['audits'])
        load_read_gates()
        native = Req7OwnedHistoryMatchWorkflowTests()
        native.root = global_root; native.path = global_root/'etc/ssl/certs/ca-certificates.crt'
        native.path.parent.mkdir(parents=True); native.addCleanup = self.addCleanup
        namespace = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
        with zipfile.ZipFile(self.template) as archive:
            original_sheet = ET.fromstring(archive.read('xl/worksheets/sheet13.xml'))
        rows = []
        for original_row in original_sheet.find(namespace+'sheetData'):
            cells = [None]*6
            for cell in original_row:
                self.assertEqual('inlineStr', cell.get('t')); self.assertIsNone(cell.find(namespace+'f'))
                column = ord(cell.get('r')[0])-ord('A'); self.assertTrue(0 <= column < 6)
                cells[column] = ''.join(cell.itertext())
            rows.append(tuple(cells))
        whitelist_doc = whitelist_document(())
        whitelist_doc['sheets'][0]['properties']['sheetId'] = dict(identity.sheet_ids)['Whitelist']
        whitelist_doc['sheets'][0]['data'][0]['rowData'] = [
            {'values': [{} if value is None else {'userEnteredValue': {'stringValue': value}}
                for value in row]} for row in rows]
        def owned(kind, raw, **options):
            return native.read_owned(private_context, writer_token, spreadsheet_token,
                binding, credential, kind, json.loads(raw), raw_body=raw, **options)
        if mode == 'default-worker-original-images':
            observed.append(self._default_worker_original_images(native=native,whitelist_doc=whitelist_doc,
                private_context=private_context,global_root=global_root,writer_token=writer_token,
                spreadsheet_token=spreadsheet_token,binding=binding,unit=unit,qualified=qualified,
                settings=settings,quota_raw=quota_raw,history_raw=history_raw,reads=reads,sheet=sheet,
                state=state,owner_module=owner_module,global_journal=global_journal))
            return
        if mode in ('business-originals', 'business-originals-rebind', 'business-postclose', 'business-failed', 'business-live-inputs'):
            from test_cases.test_req7_history_read_launcher import Req7HistoryReadLauncherWorkflowTests
            from monitor import issue_tracker_history_preread_journal as preread
            from monitor import issue_tracker_mutation_launcher as mutation
            before = {str(path.relative_to(state)): (path.stat().st_ino, path.read_bytes())
                for path in state.rglob('*') if path.is_file()}
            actual, _credential, _raw = Req7HistoryReadLauncherWorkflowTests.project_auth(
                native, private_context, owner_module, spreadsheet_token, binding)
            documents = {'template_identity': response(identity_response()).data,
                'history_tail': history_raw.data, 'activity': reads[0]['discovery_response'].data,
                'insertion': reads[0]['occupancy_response'].data,
                'row': next(item['row_response'].data for item in reads if item['row_response'] is not None)}
            real_read = fixed_reads.OwnedProjectSheetsReadUnit.read_once
            issued = []; substituted = []; entered = []; refused = []; actual_responses = {}; guards = []; packets = []
            def read(reader):
                body = documents[reader._kind]
                reply = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body
                with native.server(reply, hostname='sheets.googleapis.com', destination='sheets.googleapis.com') as (records, errors), ExitStack() as launched:
                    port = socket.getaddrinfo('sheets.googleapis.com', 443)[0][4][1]
                    calls, children = native.intercept(launched, native.child_fixture(port), writer_token, spreadsheet_token, binding)
                    value = real_read(reader)
                issued.append((reader._kind, len(records), len(calls), tuple(errors), children[0].returncode))
                actual_responses[reader._kind] = value
                if mode == 'business-originals-rebind' and reader._kind == 'row':
                    path = next(path for path in state.rglob('BUSINESS-RAW'))
                    raw = path.read_bytes(); inode = path.stat().st_ino
                    path.rename(global_root / 'preserved-business-read-original')
                    path.write_bytes(raw); path.chmod(0o600)
                    substituted.append((str(path.relative_to(state)), inode, path.stat().st_ino))
                return value
            with mock.patch.object(fixed_reads.OwnedProjectSheetsReadUnit, 'read_once', autospec=True, side_effect=read), \
                    mock.patch.object(global_journal, 'record_global_attempt_intent', wraps=global_journal.record_global_attempt_intent) as no_count, \
                    mock.patch.object(mutation, '_send_counted_original_once') as no_mutation:
                identity_raw = fixed_reads.OwnedProjectSheetsReadUnit(writer_token, spreadsheet_token,
                    binding, actual, read_kind='template_identity').read_once()
                def observe():
                    with preread._hold_owned_original_business_history_reads(writer_token,
                            spreadsheet_token, binding, unit, actual, identity_response=identity_raw) as (result, verify):
                        entered.append(True)
                        self.assertEqual((2, 0), (result.operations_retained, result.noop_operations))
                        verify()
                        guards.append(verify)
                        if mode == 'business-live-inputs':
                            import copy
                            acquired_identity, acquired_history, acquired_business = verify._original_issued_inputs()
                            acquired_business[0]['operation_id'] = 'caller-mutated-copy'
                            again_identity, again_history, again_business = verify._original_issued_inputs()
                            packets.append((acquired_identity, acquired_history, acquired_business,
                                            again_identity, again_history, again_business))
                            with self.assertRaises(preread.HistoryPrereadHold): copy.copy(verify)._original_issued_inputs()
                        if mode == 'business-failed':
                            raise RuntimeError('owned fixture interrupts the actual consumer scope')
                if mode in ('business-originals', 'business-postclose', 'business-live-inputs'):
                    observe()
                    if mode == 'business-live-inputs':
                        with self.assertRaises(preread.HistoryPrereadHold): guards[0]._original_issued_inputs()
                    if mode == 'business-postclose':
                        import copy
                        guard = guards[0]
                        copied = copy.copy(guard)
                        with self.assertRaises(preread.HistoryPrereadHold): copied()
                        with self.assertRaises(preread.HistoryPrereadHold): copied._verify_issued_only()
                        with self.assertRaises(preread.HistoryPrereadHold): guard()
                        guard._verify_issued_only()
                        original = actual_responses['row']
                        with fixed_reads._PROJECT_READ_GUARD:
                            registered = fixed_reads._PROJECT_READS.pop(original)
                        try:
                            with self.assertRaises(preread.HistoryPrereadHold): guard._verify_issued_only()
                            refused.append(True)
                        finally:
                            with fixed_reads._PROJECT_READ_GUARD:
                                fixed_reads._PROJECT_READS[original] = registered
                else:
                    with self.assertRaises(preread.HistoryPrereadHold): observe()
                    refused.append(True)
                    if mode == 'business-failed':
                        fixed_reads.require_current_owned_project_read(writer_token,spreadsheet_token,
                            binding,actual_responses['row'],actual,read_kind='row',sheet=sheet,row=3)
                        with self.assertRaises(preread.HistoryPrereadHold): guards[0]()
                        with self.assertRaises(preread.HistoryPrereadHold): guards[0]._verify_issued_only()
                        with self.assertRaises(preread.HistoryPrereadHold): guards[0]._original_issued_inputs()
            # Facts outside every exception sanitizer; no synthetic read permit.
            if mode == 'business-live-inputs':
                self.assertEqual(1, len(packets))
                acquired_identity, acquired_history, acquired_business, again_identity, again_history, again_business = packets[0]
                self.assertIs(identity_raw, acquired_identity); self.assertIs(acquired_identity, again_identity)
                self.assertIs(actual_responses['history_tail'], acquired_history); self.assertIs(acquired_history, again_history)
                self.assertIs(type(acquired_business), tuple); self.assertEqual(2, len(acquired_business))
                self.assertEqual([item['operation_id'] for item in reads], [item['operation_id'] for item in again_business])
                self.assertIsNot(acquired_business[0], again_business[0])
                self.assertEqual('caller-mutated-copy', acquired_business[0]['operation_id'])
                for packet in (acquired_business, again_business):
                    for fresh in packet:
                        self.assertEqual({'operation_id', 'discovery_response', 'occupancy_response', 'row_response'}, set(fresh))
                        self.assertIs(actual_responses['activity'], fresh['discovery_response'])
                        self.assertIs(actual_responses['insertion'], fresh['occupancy_response'])
                    # Original fixture contract is exactly one update followed
                    # by one insert. An insert must retain row_response=None.
                    self.assertIs(actual_responses['row'], packet[0]['row_response'])
                    self.assertIsNone(packet[1]['row_response'])
            self.assertEqual([(kind, 1, 1, (), 0) for kind in
                ('template_identity', 'history_tail', 'activity', 'insertion', 'row')], issued)
            self.assertEqual([] if mode == 'business-originals-rebind' else [True], entered)
            self.assertEqual([] if mode in ('business-originals', 'business-live-inputs') else [True], refused)
            no_count.assert_not_called(); no_mutation.assert_not_called()
            self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
            self.assertFalse(list(state.rglob('ATTEMPT-*'))); self.assertFalse(list(state.rglob('CLAIM-*')))
            after = {str(path.relative_to(state)): (path.stat().st_ino, path.read_bytes())
                for path in state.rglob('*') if path.is_file()}
            if mode != 'business-originals-rebind': self.assertEqual(before, after)
            else:
                self.assertEqual(1, len(substituted)); name, old, new = substituted[0]
                self.assertNotEqual(old, new); self.assertEqual(before[name][1], after[name][1])
                self.assertEqual({k: v for k, v in before.items() if k != name},
                                 {k: v for k, v in after.items() if k != name})
            observed.append(sheet + {'business-originals': ':fresh-read-only',
                'business-originals-rebind': ':original-rebind-hold',
                'business-postclose': ':actual-issued-postclose-revocation-hold',
                'business-failed': ':actual-issued-failed-scope-hold',
                'business-live-inputs': ':actual-live-issued-inputs-only'}[mode])
            return
        if mode in ('prepare','prepare-mixed-accounting','prepare-quota-rebind','prepare-finalizer-expiry',
                    'prepare-business','prepare-business-finalizer-rebind','prepare-business-postclose-revoke'):
            from test_cases.test_req7_history_read_launcher import Req7HistoryReadLauncherWorkflowTests
            from monitor import issue_tracker_token_launcher as tokens
            from monitor import issue_tracker_remote_history_match as remote
            from monitor import issue_tracker_stage_l_consumer as source
            from monitor import issue_tracker_mutation_launcher as mutation
            from monitor import issue_tracker_unit_catalog as catalog
            from monitor import issue_tracker_metadata_reservation as quota
            from monitor import issue_tracker_history_preread_journal as preread
            before={str(path.relative_to(state)):(path.stat().st_ino,path.read_bytes())
                for path in state.rglob('*') if path.is_file()}
            actual, _credential, _raw=Req7HistoryReadLauncherWorkflowTests.project_auth(
                native,private_context,owner_module,spreadsheet_token,binding)
            native.certificates('sheets.googleapis.com')
            documents={'template_identity':identity_response(),'template_headers':header_response(),
                'whitelist':whitelist_doc,'metadata':json.loads(quota_raw.data)}
            documents.update(history_tail=json.loads(history_raw.data),
                activity=json.loads(reads[0]['discovery_response'].data),
                insertion=json.loads(reads[0]['occupancy_response'].data),
                row=json.loads(next(item['row_response'].data for item in reads if item['row_response'] is not None)))
            real_read=fixed_reads.OwnedProjectSheetsReadUnit.read_once
            real_source=source.qualify_prod_stage_l
            issued=[]; projections=[]; replaced=[]; refused=[]; actual_responses={}; business_closed=[]
            revoked=[]; restored=[]; issued_only_calls=[]; genuine_business_guards=[]
            closed=[]; first_holder=[]; mixed_observations=[]
            real_hold=catalog.hold_pending_project_c6_units
            real_mixed_quota=quota._hold_owned_project_mixed_metadata_capacity
            real_clock=fixed_reads._monotonic
            real_business=preread._hold_owned_original_business_history_reads
            real_issued_only=preread._OriginalBusinessReadGuard._verify_issued_only
            def verify_issued_only(guard):
                issued_only_calls.append((guard,len(business_closed),len(revoked)))
                return real_issued_only(guard)
            def replace_business_original():
                path=next(path for path in state.rglob('BUSINESS-RAW'))
                raw=path.read_bytes(); inode=path.stat().st_ino
                path.rename(global_root/'preserved-preparation-business')
                path.write_bytes(raw); path.chmod(0o600)
                replaced.append((str(path.relative_to(state)),inode,path.stat().st_ino))
            @contextmanager
            def held_business(*args,**options):
                with real_business(*args,**options) as original:
                    actual_read=actual_responses['row']
                    genuine_business_guards.append(original[1])
                    yield original
                business_closed.append(True)
                with fixed_reads._PROJECT_READ_GUARD:
                    registered=fixed_reads._PROJECT_READS.pop(actual_read)
                revoked.append((actual_read,registered))
                preparation_boundary.callback(restore_read,actual_read,registered)
            def restore_read(actual_read,registered):
                with fixed_reads._PROJECT_READ_GUARD:
                    fixed_reads._PROJECT_READS[actual_read]=registered
                restored.append((actual_read,registered))
            @contextmanager
            def held_catalog(*args,**options):
                first = not first_holder
                first_holder.append(True)
                with real_hold(*args,**options) as actual_rows:
                    yield actual_rows
                # First acquired holder is last released. Its actual verifier
                # and cleanup run before the original read deadlines expire.
                if first:
                    closed.append(True)
                    if mode=='prepare-business-finalizer-rebind': replace_business_original()
            @contextmanager
            def mixed_quota(*args,**options):
                with real_mixed_quota(*args,**options) as actual_budget:
                    budget,_verify=actual_budget
                    mixed_observations.append((budget.outcome,budget.outstanding_reservations))
                    yield actual_budget
            def post_finalizer_clock():
                return real_clock()+(31 if closed else 0)
            def qualify(*args,**options):
                value=real_source(*args,**options)
                projections.append(value); return value
            def read(reader):
                self.assertTrue(projections,'actual source must precede actual project reads')
                body=response(documents[reader._kind]).data
                reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
                with native.server(reply,hostname='sheets.googleapis.com',destination='sheets.googleapis.com') as (records,errors), ExitStack() as launched:
                    port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                    calls,children=native.intercept(launched,native.child_fixture(port),writer_token,spreadsheet_token,binding)
                    value=real_read(reader)
                issued.append((reader._kind,len(records),len(calls),tuple(errors),children[0].returncode))
                actual_responses[reader._kind]=value
                if mode=='prepare-quota-rebind' and reader._kind=='metadata':
                    path=next(path for path in state.rglob('RESERVATION') if path.parent.name.endswith('.metadata'))
                    raw=path.read_bytes(); inode=path.stat().st_ino
                    path.rename(global_root/'preserved-preparation-quota')
                    path.write_bytes(raw); path.chmod(0o600)
                    replaced.append((str(path.relative_to(state)),inode,path.stat().st_ino))
                return value
            with ExitStack() as preparation_boundary, \
                    mock.patch.object(source,'qualify_prod_stage_l',side_effect=qualify), \
                    mock.patch.object(fixed_reads.OwnedProjectSheetsReadUnit,'read_once',autospec=True,side_effect=read), \
                    mock.patch.object(tokens,'OwnedProjectTokenRefreshUnit') as no_second_oauth, \
                    mock.patch.object(global_journal,'record_global_attempt_intent',wraps=global_journal.record_global_attempt_intent) as no_count, \
                    mock.patch.object(mutation,'_send_counted_original_once') as no_mutation:
                if mode in ('prepare-finalizer-expiry','prepare-business-finalizer-rebind'):
                    preparation_boundary.enter_context(mock.patch.object(catalog,
                        'hold_pending_project_c6_units',side_effect=held_catalog))
                if mode=='prepare-finalizer-expiry':
                    preparation_boundary.enter_context(mock.patch.object(fixed_reads,
                        '_monotonic',side_effect=post_finalizer_clock))
                if mode=='prepare-mixed-accounting':
                    preparation_boundary.enter_context(mock.patch.object(quota,
                        '_hold_owned_project_mixed_metadata_capacity',side_effect=mixed_quota))
                if mode=='prepare-business-postclose-revoke':
                    preparation_boundary.enter_context(mock.patch.object(preread,
                        '_hold_owned_original_business_history_reads',side_effect=held_business))
                    preparation_boundary.enter_context(mock.patch.object(preread._OriginalBusinessReadGuard,
                        '_verify_issued_only',autospec=True,side_effect=verify_issued_only))
                if mode in ('prepare','prepare-mixed-accounting','prepare-business'):
                    result=remote._prepare_current_project_online_observation(writer_token,spreadsheet_token,
                        binding,actual,_store=self.store,http_root=self.root)
                    self.assertEqual('VISIBLE_ONLY_UNPROVED',result)
                else:
                    with self.assertRaises(remote.RemoteHistoryHold):
                        remote._prepare_current_project_online_observation(writer_token,spreadsheet_token,
                            binding,actual,_store=self.store,http_root=self.root)
                    refused.append(True)
                no_second_oauth.assert_not_called(); no_count.assert_not_called(); no_mutation.assert_not_called()
            # Independent facts outside every implementation sanitizer.
            expected_kinds=('template_identity','template_headers','whitelist','metadata')
            if mode!='prepare-quota-rebind':
                expected_kinds+=('history_tail','activity','insertion','row')
            self.assertEqual([(kind,1,1,(),0) for kind in expected_kinds],issued)
            positive = mode in ('prepare','prepare-mixed-accounting','prepare-business')
            self.assertGreaterEqual(len(projections),2 if positive else 1)
            self.assertEqual([] if positive else [True],refused)
            if mode=='prepare-mixed-accounting':
                self.assertEqual([('VISIBLE_ONLY_UNPROVED',1)],mixed_observations)
            if mode=='prepare-finalizer-expiry': self.assertEqual([True],closed)
            if mode=='prepare-business-finalizer-rebind': self.assertEqual([True],closed)
            if mode=='prepare-business-postclose-revoke':
                self.assertEqual([True],business_closed)
                self.assertEqual(1,len(revoked)); self.assertEqual(1,len(restored))
                self.assertIs(actual_responses['row'],revoked[0][0])
                self.assertIs(actual,revoked[0][1]); self.assertIs(revoked[0][0],restored[0][0])
                self.assertIs(revoked[0][1],restored[0][1])
                self.assertEqual(1,len(issued_only_calls)); self.assertEqual(1,len(genuine_business_guards))
                self.assertIs(genuine_business_guards[0],issued_only_calls[0][0])
                self.assertEqual((1,1),issued_only_calls[0][1:])
                with fixed_reads._PROJECT_READ_GUARD:
                    self.assertIs(actual,fixed_reads._PROJECT_READS[actual_responses['row']])
                    for kind in ('template_identity','template_headers','whitelist','metadata'):
                        self.assertIs(actual,fixed_reads._PROJECT_READS[actual_responses[kind]])
                for kind in ('template_identity','template_headers','whitelist','metadata'):
                    fixed_reads.require_current_owned_project_read(writer_token,spreadsheet_token,
                        binding,actual_responses[kind],actual,read_kind=kind)
            self.assertEqual(0,global_journal.inspect_global_unit(spreadsheet_token,binding,unit).attempt_count)
            self.assertFalse(list(state.rglob('ATTEMPT-*'))); self.assertFalse(list(state.rglob('CLAIM-*')))
            after={str(path.relative_to(state)):(path.stat().st_ino,path.read_bytes())
                for path in state.rglob('*') if path.is_file()}
            if mode not in ('prepare-quota-rebind','prepare-business-finalizer-rebind'): self.assertEqual(before,after)
            else:
                self.assertEqual(1,len(replaced)); name,old,new=replaced[0]
                self.assertNotEqual(old,new); self.assertEqual(before[name][1],after[name][1])
                self.assertEqual({k:v for k,v in before.items() if k!=name},{k:v for k,v in after.items() if k!=name})
            observed.append(sheet+{'prepare':':visible-only-no-count',
                'prepare-mixed-accounting':':mixed-original-visible-only-no-count',
                'prepare-quota-rebind':':original-rebind-hold-no-count',
                'prepare-finalizer-expiry':':post-finalizer-expiry-hold-no-count',
                'prepare-business':':business-history-visible-only-no-count',
                'prepare-business-finalizer-rebind':':business-finalizer-rebind-hold-no-count',
                'prepare-business-postclose-revoke':':business-postclose-revoke-hold-no-count'}[mode])
            return
        bundle = {name:owned(kind, response(doc).data) for name,kind,doc in (
            ('identity_response','template_identity',identity_response()),
            ('headers_response','template_headers',header_response()),
            ('whitelist_response','whitelist',whitelist_doc),
            ('metadata_response','metadata',json.loads(quota_raw.data)))}
        bundle['history_response'] = owned('history_tail', history_raw.data)
        current = {role+'_response':owned(kind, reads[0][role+'_response'].data, sheet=sheet)
            for role,kind in (('discovery','activity'),('occupancy','insertion'))}
        bundle['business_reads'] = tuple({'operation_id':reading['operation_id'], **current,
            'row_response':None if reading['row_response'] is None else owned('row',
                reading['row_response'].data, sheet=sheet, row=3)} for reading in reads)
        mutation_fixture = Req7MutationLauncherWorkflowTests()
        mutation_fixture.root = global_root; mutation_fixture.path = native.path
        mutation_fixture.addCleanup = self.addCleanup; mutation = load_mutation()
        audit_action=json.loads(unit.action_preimage)['audits']
        if audit_action:
            # The native creator, not this consumer fixture, wrote this graph.
            # Absence of both legacy names must NOT become missing allocation.
            project=Path(self.store.project_identity)
            self.assertFalse((project/'.tracker/settings-audit-allocation').exists())
            self.assertFalse((project/'.tracker/SETTINGS-AUDIT-ALLOCATED').exists())
            audit_folder=state/(hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()+'.unit-'+unit.unit_id+'.settings-audit')
            self.assertEqual({'HEADER','ASSIGNMENTS','INITIALIZED'},set(os.listdir(audit_folder)))
            self.assertEqual(list(expected_audits) if expected_audits is not None else audit_action,
                [row['audit'] for row in json.loads((audit_folder/'ASSIGNMENTS').read_bytes())])
        before = {str(path.relative_to(state)):(path.stat().st_ino,path.read_bytes())
            for path in state.rglob('*') if path.is_file()}
        wire_response = b'HTTP/1.1 401 Denied\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
        calls = []; children = []; reached = []; rejected = []
        if audit_action:
            # Like the catalog/retained fixtures above, attach this real
            # consumer to the actual registry issued for this sheet, not a
            # prior scenario's imported registry. No owner validation is mocked.
            from test_cases.test_req7_settings_audit_allocation import load as load_allocation
            allocation = load_allocation()
            self.assertIs(allocation.ownership, owner_module)
            self.assertIs(allocation.global_journal, global_journal)
        with mutation_fixture.server(wire_response, hostname='sheets.googleapis.com',
                destination='sheets.googleapis.com') as (requests, errors), ExitStack() as transport:
            port = socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
            def exercise():
                nonlocal calls, children
                with global_journal._hold_continuous_owned_attempt_wire(spreadsheet_token,binding,unit,
                        writer_token=writer_token,qualified_source=qualified,store=self.store,
                        settings=settings,whitelist_snapshot=self.snapshot,
                        expected_template_sha256=self.snapshot.workbook_sha256,http_root=self.root,
                        whitelist_path=self.template,**bundle) as image:
                    reached.append('original-count-and-claim'); self.assertEqual(1,image.attempt_count)
                    calls,children = mutation_fixture.intercept(transport,local,owner_module,
                        writer_token,spreadsheet_token,binding,image,port)
                    if mode == 'receipt-rebind':
                        path = Path(self.store.project_identity)/'.tracker/generations'/committed.receipt.generation_id/'RECEIPT'
                        raw = path.read_bytes(); inode = path.stat().st_ino
                        path.rename(global_root/'owned-prelaunch-original-receipt')
                        path.write_bytes(raw); path.chmod(0o600)
                        self.assertNotEqual(inode,path.stat().st_ino); self.assertEqual(raw,path.read_bytes())
                    if mode == 'normal':
                        result = mutation._send_counted_original_once(writer_token,spreadsheet_token,binding,credential,unit,image)
                        self.assertEqual((1,401,'UNKNOWN'),(result.attempt_count,result.status,result.outcome))
                        self.assertTrue(result.termination_confirmed)
                        with self.assertRaises(mutation.MutationLauncherHold):
                            mutation._send_counted_original_once(writer_token,spreadsheet_token,binding,credential,unit,image)
                    else:
                        if mode == 'read-expiry':
                            clock = fixed_reads._monotonic
                            transport.enter_context(mock.patch.object(fixed_reads,'_monotonic',side_effect=lambda:clock()+31))
                        with self.assertRaises(mutation.MutationLauncherHold) as caught:
                            mutation._send_counted_original_once(writer_token,spreadsheet_token,binding,credential,unit,image)
                        self.assertFalse(caught.exception.termination_confirmed); rejected.append('before-child')
            if mode == 'normal': exercise()
            else:
                with self.assertRaises(global_journal.GlobalAttemptHold): exercise()
            self.assertEqual(['original-count-and-claim'],reached)
            self.assertEqual([] if mode == 'normal' else ['before-child'],rejected)
            self.assertEqual(1 if mode == 'normal' else 0,len(calls))
            self.assertEqual(1 if mode == 'normal' else 0,len(children))
            self.assertEqual(1 if mode == 'normal' else 0,len(requests)); self.assertEqual([],errors)
            if requests: self.assertEqual(unit.wire_bytes,requests[0][2])
        retained = global_journal.inspect_global_unit(spreadsheet_token,binding,unit)
        self.assertEqual((1,'UNKNOWN'),(retained.attempt_count,retained.outcome))
        if audit_action:
            dispatch=state/(hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()+'.unit-'+unit.unit_id+'.dispatch')
            self.assertEqual({'HEADER','INITIALIZED','CLAIM-1'},set(os.listdir(dispatch)))
            self.assertFalse((Path(self.store.project_identity)/'.tracker/settings-audit-allocation').exists())
        after = {str(path.relative_to(state)):(path.stat().st_ino,path.read_bytes())
            for path in state.rglob('*') if path.is_file()}
        for name,image in before.items():
            if '.journal/' not in name: self.assertEqual(image,after[name],name)
        observed.append(sheet + ':native-launch:' + mode)

    def test_actual_protected_native_nv_all_project_c6_fifo_keeps_originals_and_issues_no_send_permission(self):
        observed = []
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            observed_cabling_insert_probe=True, native_catalog_probe=True, native_catalog_c6_origin_probe=True,
            native_catalog_retained_probe=True, native_catalog_all_c6_fifo_probe=observed)
        self.assertEqual(['ETH Cabling:actual-all-project-c6:no-applied', 'ETH Cabling:actual-fifo:read-only',
                          'IB Cabling:actual-all-project-c6:no-applied', 'IB Cabling:actual-fifo:read-only'], observed)

    def test_native_compiler_holds_nv_original_drift_during_final_real_receipt_read(self):
        self._exercise_native_compiler_return_fault('same_byte_replace')

    def test_native_compiler_holds_nv_same_inode_rewrite_during_final_real_receipt_read(self):
        self._exercise_native_compiler_return_fault('same_inode_rewrite')

    def _exercise_native_compiler_return_fault(self, mode):
        marks = []; error = None
        try:
            self._exercise_real_protected_three_panel_fixture(skip_history=False,
                observed_cabling_insert_probe=True, native_catalog_probe=True,
                native_catalog_return_fault=(mode, marks))
        except Exception as exc:
            error = exc
        # Each method gets a fresh actual project/cycle fixture. Outer scope
        # HOLD must not mask a compiler that already returned a frozen unit.
        self.assertEqual([('injected', mode), ('compiler', 'HOLD'), ('catalog_written', False)], marks)
        self.assertIs(type(error), sys.modules['monitor.issue_tracker_nv_reservation'].NvReservationHold)

    def test_actual_receipted_cabling_unit_retains_original_business_images_across_unknown(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True, business_preread_probe=True)

    def test_actual_receipted_cabling_original_chain_dominates_reserved_count(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True, business_preread_probe=True, original_reserved_probe=True)

    def test_actual_original_c6_receipt_dominates_every_business_count_and_post_count_drift_holds(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True, business_preread_probe=True, original_reserved_probe=True, receipted_intent_probe=True)

    def test_same_byte_original_c6_admission_replacement_after_count_is_hold_not_success(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            receipt_admission_rebind_probe=True)

    def test_same_byte_original_quota_replacement_during_protected_count_is_hold(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            quota_namespace_rebind_probe=True)

    def test_actual_c25_allocation_dominates_original_c6_counts_and_unknown_retains_audits(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True,
            business_preread_probe=True, original_reserved_probe=True, receipted_intent_probe=True, settings_audit_probe=True)

    def test_actual_c25_assignment_original_survives_the_entire_durable_count(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True,
            business_preread_probe=True, original_reserved_probe=True, receipted_intent_probe=True,
            settings_audit_probe=True, allocation_original_identity_probe=True)

    def test_actual_c25_assignment_replacement_after_shared_retry_keeps_terminal_unknown(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True,
            business_preread_probe=True, original_reserved_probe=True, receipted_intent_probe=True,
            settings_audit_probe=True, owned_read_gates_probe=True, owned_continuity_probe=True,
            shared_retry_probe=True, allocation_retry_identity_probe=True)

    def test_same_byte_quota_replacement_after_shared_retry_keeps_unpaired_intent_and_unknown(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            settings_audit_probe=True,owned_read_gates_probe=True,owned_continuity_probe=True,
            shared_retry_probe=True,quota_retry_identity_probe=True)

    def test_each_independent_c25_sheet_fixture_acquires_a_fresh_synthetic_credential(self):
        # Separate fixtures must not inherit an earlier fixture's expired
        # token. Preserve the production expiry contract and its 3600s TTL.
        clock=[time.time()]
        def starting(sheet):
            if sheet=='IB Cabling': clock[0]+=7200
        with mock.patch('monitor.issue_tracker_sheets_read_plan.time.time',side_effect=lambda:clock[0]):
            self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True,
                business_preread_probe=True, original_reserved_probe=True, receipted_intent_probe=True,
                settings_audit_probe=True, before_cabling_fixture=starting)

    def test_actual_native_read_gates_dominate_original_c6_count_and_expiry_retains_unknown(self):
        from monitor import issue_tracker_global_attempt_journal as journal
        self.assertTrue(hasattr(journal, 'record_owned_receipted_attempt_intent'),
                        'actual issued W1/template/nonces must dominate original protected C6 count')
        self._exercise_real_protected_three_panel_fixture(skip_history=False, observed_cabling_insert_probe=True,
            business_preread_probe=True, original_reserved_probe=True, receipted_intent_probe=True,
            owned_read_gates_probe=True)

    def test_actual_live_all_business_and_history_continuity_dominate_original_c6_count(self):
        from monitor import issue_tracker_global_attempt_journal as journal
        self.assertTrue(hasattr(journal,'record_continuous_owned_attempt_intent'),
                        'actual fixed ALL-business/History observations must gate original C6 count')
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            owned_read_gates_probe=True,owned_continuity_probe=True)

    def test_actual_continuous_count_scope_reaches_one_fixed_native_original_request(self):
        from monitor import issue_tracker_global_attempt_journal as journal
        self.assertTrue(hasattr(journal,'_hold_continuous_owned_attempt_wire'))
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            owned_read_gates_probe=True,owned_continuity_probe=True,continuous_launch_probe='normal')

    def test_actual_first_count_and_wire_borrow_already_held_native_catalog_originals(self):
        from contextlib import contextmanager
        from test_cases import test_req7_global_attempt_journal as fixtures
        actual_load=fixtures.load; reached=[]; completed=[]; failures=[]
        with ExitStack() as patches:
            def load_with_original_catalog_overlap():
                module=actual_load(); first=module._hold_continuous_owned_attempt_wire
                @contextmanager
                def overlapping(owner,bound,unit,**options):
                    with module._hold_native_catalog_replay(owner,bound,unit) as outer:
                        reached.append(unit.unit_id)
                        outer()
                        with first(owner,bound,unit,**options) as image:
                            outer(); yield image; outer()
                        outer()
                    completed.append(unit.unit_id)
                patches.enter_context(mock.patch.object(module,'_hold_continuous_owned_attempt_wire',side_effect=overlapping))
                return module
            patches.enter_context(mock.patch.object(fixtures,'load',side_effect=load_with_original_catalog_overlap))
            marks=[]
            try:
                self._exercise_real_protected_three_panel_fixture(skip_history=False,
                    observed_cabling_insert_probe=True,receipted_intent_probe=True,
                    native_catalog_probe=True,native_catalog_c6_origin_probe=True,
                    native_catalog_retained_probe=True,native_catalog_launch_probe=('normal',marks))
            except Exception:
                import traceback
                failures.append(traceback.format_exc())
        # Outside production sanitizers: actual protected C5/C6, ALL native
        # catalog, fresh owned reads, count/CLAIM and original encrypted request.
        self.assertEqual([],failures)
        self.assertEqual(2,len(reached));self.assertEqual(reached,completed)
        self.assertEqual(['ETH Cabling:native-launch:normal',
            'IB Cabling:native-launch:normal'],marks)

    def test_actual_first_count_and_wire_receive_already_held_all_write_aware_originals(self):
        from test_cases import test_req7_global_attempt_journal as fixtures
        actual_load=fixtures.load;reached=[];completed=[];failures=[]
        with ExitStack() as patches:
            def loaded():
                module=actual_load();first=module._hold_continuous_owned_attempt_wire
                @contextmanager
                def overlap(owner,bound,unit,**options):
                    with module._hold_selected_last_catalog_write_originals(options['writer_token'],owner,bound,unit) as original:
                        reached.append(unit.unit_id);original()
                        with first(owner,bound,unit,**options) as image:
                            original();yield image;original()
                        original()
                    completed.append(unit.unit_id)
                patches.enter_context(mock.patch.object(module,'_hold_continuous_owned_attempt_wire',side_effect=overlap))
                return module
            patches.enter_context(mock.patch.object(fixtures,'load',side_effect=loaded))
            marks=[]
            try:
                self._exercise_real_protected_three_panel_fixture(skip_history=False,
                    observed_cabling_insert_probe=True,receipted_intent_probe=True,
                    native_catalog_probe=True,native_catalog_c6_origin_probe=True,
                    native_catalog_retained_probe=True,native_catalog_launch_probe=('normal',marks))
            except Exception:
                import traceback
                failures.append(traceback.format_exc())
        # Outside production sanitizers: genuine complete ALL originals must
        # survive original C6/read/FIRST/COUNT/CLAIM/native request and cleanup.
        # No supplied graph, permission flag or alternative issuer is accepted.
        self.assertEqual([],failures)
        self.assertEqual(2,len(reached));self.assertEqual(reached,completed)
        self.assertEqual(['ETH Cabling:native-launch:normal','IB Cabling:native-launch:normal'],marks)

    def test_shared_retry_held_originals_reach_one_identical_native_request(self):
        from monitor import issue_tracker_global_attempt_journal as journal
        self.assertTrue(hasattr(journal,'_hold_shared_retry_owned_attempt_wire'))
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            owned_read_gates_probe=True,owned_continuity_probe=True,retry_launch_probe='normal')

    def test_shared_retry_after_new_real_cycle_sends_only_the_original_unknown_wire(self):
        from monitor import issue_tracker_global_attempt_journal as journal
        self.assertTrue(hasattr(journal, '_hold_shared_retry_owned_attempt_wire'))
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            owned_read_gates_probe=True,owned_continuity_probe=True,retry_launch_probe='old-cycle')

    def test_old_receipted_private_window_replays_semantics_once_per_actual_qualification(self):
        from monitor import issue_tracker_cycle_source as source
        from monitor import issue_tracker_stage_l_consumer as consumer
        actual_replay = consumer.replay_original_receipted_prod_source
        actual_read = source._read_completed_cycle_evidence
        reached = []
        observed = []

        def replay(*args, **kwargs):
            windows = {}
            def read(store):
                if store is not self.store:
                    item = windows.setdefault(id(store), [store, 0])
                    item[1] += 1
                return actual_read(store)
            with mock.patch.object(source, '_read_completed_cycle_evidence', side_effect=read):
                result = actual_replay(*args, **kwargs)
            observed.append((len(windows), tuple(item[1] for item in windows.values())))
            reached.append(result)
            return result

        try:
            with mock.patch.object(consumer, 'replay_original_receipted_prod_source', side_effect=replay):
                self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
                    business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
                    owned_read_gates_probe=True,owned_continuity_probe=True,retry_launch_probe='old-cycle')
        finally:
            # Keep the independent assertion outside production's sanitized
            # HOLD scopes; their exception cleanup must not mask its RED.
            self.assertTrue(reached, 'the original admitted window must actually be requalified')
            self.assertEqual([(1, (1,))] * len(observed), observed,
                             'held original worker bytes need one semantic replay per private window')

    def test_shared_retry_original_receipt_rebind_stops_before_second_native_launch(self):
        from monitor import issue_tracker_global_attempt_journal as journal
        self.assertTrue(hasattr(journal,'_hold_shared_retry_owned_attempt_wire'))
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            owned_read_gates_probe=True,owned_continuity_probe=True,retry_launch_probe='receipt-rebind')

    def test_shared_retry_original_read_expiry_stops_before_second_native_launch(self):
        from monitor import issue_tracker_global_attempt_journal as journal
        self.assertTrue(hasattr(journal,'_hold_shared_retry_owned_attempt_wire'))
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            owned_read_gates_probe=True,owned_continuity_probe=True,retry_launch_probe='read-expiry')

    def test_native_qualification_bounds_recursive_source_replays_without_shortening_final_checks(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            qualification_replay_probe='bounded')

    def test_real_protected_three_domains_keep_start_end_reads_without_recursive_bound_walks(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            qualification_replay_probe='composed-legs')

    def test_real_composed_switch_families_keep_two_fresh_windows_per_domain_leg(self):
        from monitor import issue_tracker_stage_l_consumer as consumer
        self.assertTrue(callable(getattr(consumer, '_observe_prod_stage_l_switch_sources', None)),
                        'actual composition must retain fresh source families without nested standalone walks')
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            qualification_replay_probe='switch-families')

    def test_real_w1_drift_after_first_eth_observation_is_hold_at_composed_end(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            qualification_replay_probe='composed-w1-drift')

    def test_real_ethernet_archive_drift_after_eth_observation_is_hold(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            qualification_replay_probe='composed-ethernet-archive-drift')

    def test_real_nvlink_archive_drift_after_eth_observation_is_hold(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            qualification_replay_probe='composed-nvlink-archive-drift')

    def test_native_qualification_still_rejects_whitelist_drift_at_final_projection_boundary(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,
            qualification_replay_probe='whitelist-drift')

    def test_original_receipt_rebind_after_continuous_count_stops_before_native_launch(self):
        from monitor import issue_tracker_global_attempt_journal as journal
        self.assertTrue(hasattr(journal,'_hold_continuous_owned_attempt_wire'))
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            owned_read_gates_probe=True,owned_continuity_probe=True,continuous_launch_probe='receipt-rebind')

    def test_issued_read_expiry_after_continuous_count_stops_before_native_launch(self):
        from monitor import issue_tracker_global_attempt_journal as journal
        self.assertTrue(hasattr(journal,'_hold_continuous_owned_attempt_wire'))
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            owned_read_gates_probe=True,owned_continuity_probe=True,continuous_launch_probe='read-expiry')

    def test_actual_protected_sources_native_reads_and_c6_share_retry_admission_without_new_publication(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=False,observed_cabling_insert_probe=True,
            business_preread_probe=True,original_reserved_probe=True,receipted_intent_probe=True,
            owned_read_gates_probe=True,owned_continuity_probe=True,shared_retry_probe=True)

    def test_two_real_cycles_keep_keys_and_commit_latest_business_values(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, two_cycle_changed_latest=True,
        )

    def test_authenticated_k_relay_persists_replays_and_invalidates_real_preview(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, settings_channel_probe=True,
        )

    def test_k_relay_interrupted_commit_retains_unknown_claim_not_success_or_retry(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, settings_channel_fault=True,
        )

    def _verify_authenticated_settings_channel(self, project, *, fault=False):
        from monitor.issue_tracker_manual_channel import DurableManualQueue, ManualQueueWorker
        from monitor.issue_tracker_manual_preview import make_protected_stage_l_broker
        from monitor.issue_tracker_state_owner import current_k, tracker_writer
        from test_cases.test_issue_tracker_manual_channel import cgi, valid_env

        root = project / ".tracker/manual-k-fixture"
        root.mkdir(mode=0o700)
        queue = DurableManualQueue(root, boot_id="settings-fixture")
        broker = make_protected_stage_l_broker(
            self.store, http_root=self.root, project=project,
            publication=self.publication, template_path=self.template,
            boot_id="settings-fixture", clock=lambda: 1000.0,
        )
        worker = ManualQueueWorker(queue, broker)
        jobs = []

        def submit(request):
            job = queue.enqueue(request)
            jobs.append(job)
            claimed, result = worker.process_job(job)
            self.assertEqual(job, claimed)
            self.assertEqual("done", queue.status(job)["state"])
            return result

        body = b"action=settings&panel=Switch+Status"
        status, initial = cgi.handle(valid_env(body), body, submit=submit)
        self.assertEqual("200 OK", status)
        self.assertEqual((1, 1), (initial["revision"], initial["k"]))
        preview = broker.preview("nvis", "Switch Status")
        generations = tuple((project / ".tracker/generations").iterdir())
        template = self.template.read_bytes()
        change = (b"action=set_k&panel=Eth+Link+Validation&new_k=5000"
                  b"&expected_revision=1&request_id=" + b"d" * 32)
        if fault:
            # Failure after immutable event/outbox installation, before the
            # current-pointer barrier: preserve the tail and this claimed job.
            with mock.patch("monitor.issue_tracker_k_store._replace_current",
                            side_effect=OSError("injected pointer barrier failure")):
                status, result = cgi.handle(valid_env(change), change, submit=submit)
            self.assertEqual(("503 Service Unavailable", {"error": "manual_worker_unavailable"}),
                             (status, result))
            self.assertEqual("unknown_after_claim", queue.status(jobs[-1])["state"])
            self.assertTrue((project / ".tracker/settings/events/2.json").is_file())
            self.assertTrue((project / ".tracker/settings/outbox/2.json").is_file())
            status, result = cgi.handle(valid_env(body), body, submit=submit)
            self.assertEqual("503 Service Unavailable", status)
            self.assertEqual("unknown_after_claim", queue.status(jobs[-1])["state"])
            self.assertEqual(generations, tuple((project / ".tracker/generations").iterdir()))
            self.assertEqual(template, self.template.read_bytes())
            return
        status, result = cgi.handle(valid_env(change), change, submit=submit)
        self.assertEqual("200 OK", status)
        self.assertEqual(("committed", 2, 5000, False),
                         (result["settings"], result["revision"], result["k"], result["replay"]))
        event_path = project / ".tracker/settings/events/2.json"
        event = json.loads(event_path.read_bytes())
        self.assertEqual(("operator:nvis", 1, 5000, "d" * 32),
                         (event["actor"], event["old_k"], event["new_k"], event["request_id"]))
        self.assertEqual(hashlib.sha256(event_path.read_bytes()).hexdigest(), result["event_sha256"])
        self.assertTrue((project / ".tracker/settings/outbox/2.json").is_file())
        restart = make_protected_stage_l_broker(
            self.store, http_root=self.root, project=project,
            publication=self.publication, template_path=self.template,
            boot_id="new-worker", clock=lambda: 1000.0,
        )
        self.assertEqual((2, 5000), (restart.settings("cumulus", "IB Link Validation")["revision"],
                                     restart.settings("cumulus", "IB Link Validation")["k"]))
        status, replay = cgi.handle(valid_env(change), change, submit=submit)
        self.assertEqual("200 OK", status)
        self.assertEqual({**result, "replay": True}, replay)
        for altered, environment in (
            (change.replace(b"new_k=5000", b"new_k=6"), None),
            (change.replace(b"d" * 32, b"e" * 32), None),
            (change, {**valid_env(change), "REMOTE_USER": "cumulus"}),
        ):
            status, refused = cgi.handle(environment or valid_env(altered), altered, submit=submit)
            self.assertEqual(("409 Conflict", {"error": "manual_hold"}), (status, refused))
        with tracker_writer(project, self.publication) as token:
            self.assertEqual((2, 5000), (current_k(token).revision, current_k(token).k))
        from monitor.issue_tracker_publish_runtime import inspect_stage_l
        status = inspect_stage_l(self.store, http_root=self.root, project=project,
                                 publication=self.publication, template_path=self.template)
        self.assertEqual((2, 5000), (status["k_revision"], status["k"]))
        self.assertEqual("pending", status["state"])
        self.assertEqual("disabled_no_send_authority", status["online"])
        from monitor.issue_tracker_manual_preview import ManualPreviewHold
        with self.assertRaises(ManualPreviewHold):
            broker.confirm("nvis", "Switch Status", preview["token"], confirmation="publish_local")
        self.assertEqual(generations, tuple((project / ".tracker/generations").iterdir()))
        self.assertEqual(template, self.template.read_bytes())


    def test_real_protected_eth_and_switch_skips_have_local_audit_history(self):
        self._exercise_real_protected_three_panel_fixture(skip_history=True)

    def test_real_protected_first_due_cycle_auto_commits_local_receipt(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, automatic_first=True,
        )

    def test_real_protected_second_due_cycle_auto_commits_distinct_local_receipt(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, automatic_first=True, automatic_second_due=True,
        )

    def test_manual_c6_cannot_bypass_prior_automatic_shared_admission(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, automatic_first=True, manual_second_probe=True,
        )

    def test_automatic_c6_then_manual_c6_uses_one_shared_admission_chain(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, automatic_first=True, manual_second_admit=True,
        )

    def test_invalid_auto_clock_refuses_before_local_c6_receipt(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, automatic_first=True, invalid_auto_clock=True,
        )

    def test_one_completed_cycle_cannot_admit_n_two_local_c6(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, automatic_first=True, automatic_not_due=True,
        )

    def test_replayed_completion_after_manual_receipt_cannot_auto_readmit(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, replayed_auto=True,
        )

    def test_first_manual_c6_records_shared_admission_for_later_automatic_lane(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, require_first_manual_admission=True,
        )

    def test_manual_c6_then_manual_c6_does_not_inherit_automatic_n(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, require_first_manual_admission=True,
            manual_after_manual=True,
        )

    def test_crash_after_c6_receipt_before_admission_is_terminal_visible_hold(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, terminal_orphan_probe=True,
        )

    def test_manual_switch_only_c5_to_c6_receipt_preserves_other_sheet_bytes(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, selected_manual_panel="Switch Status",
        )

    def test_manual_empty_switch_panel_creates_no_receipt_or_workbook_change(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, selected_manual_panel="Switch Status",
            selected_panel_empty=True,
        )

    def test_manual_queue_broker_requalifies_selected_panel_before_real_c6(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, selected_manual_panel="Switch Status",
            manual_channel_bridge=True,
        )

    def test_real_three_panel_source_paths_times_hashes_reopen_or_hold(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, source_identity_probe=True,
        )

    def test_real_protected_three_panel_preview_classifies_workbook_without_committing(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, panel_counts_probe=True,
        )

    def test_complete_manual_preview_binds_source_files_and_workbook_before_real_c6(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, complete_preview_probe=True,
        )

    def test_complete_manual_preview_source_stat_race_before_c6_never_receipts(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, complete_preview_probe=True, complete_preview_source_race=True,
        )

    def test_complete_manual_browser_confirm_crosses_real_cgi_queue_and_c6(self):
        self._exercise_real_protected_three_panel_fixture(
            skip_history=False, complete_preview_probe=True, complete_preview_cgi=True,
        )

    def _verify_manual_queue_protected_commit(
        self, project, original_template, before_generations, qualified,
    ):
        from monitor.issue_tracker_manual_channel import (
            DurableManualQueue, ManualChannelHold, ManualQueueWorker,
        )
        from monitor.issue_tracker_manual_preview import make_protected_stage_l_broker
        from monitor.issue_tracker_manifest import selected_panel_decision_sha256
        from monitor.issue_tracker_publish_runtime import (
            StageLHold, commit_qualified_prod_local,
        )
        from monitor.issue_tracker_local_workbook_commit import CommittedProdWorkbook

        queue_root = project / ".tracker/manual-fixture"
        queue_root.mkdir(mode=0o700)
        queue = DurableManualQueue(queue_root, boot_id="synthetic-boot")
        broker = make_protected_stage_l_broker(
            self.store, http_root=self.root, project=project,
            publication=self.publication, template_path=self.template,
            boot_id="synthetic-boot", monotonic_ns=time.monotonic_ns,
            clock=lambda: 1000.0,
        )
        worker = ManualQueueWorker(queue, broker)
        preview_request = {"action": "preview", "panel": "Switch Status",
                           "principal": "nvis"}

        def preview():
            job = queue.enqueue(preview_request)
            completed, result = worker.process_job(job)
            self.assertEqual(job, completed)
            self.assertEqual("done", queue.status(job)["state"])
            self.assertEqual(
                selected_panel_decision_sha256(qualified, "Switch Status"),
                result["selected_decision_sha256"],
            )
            return result["token"]

        def confirm(token, *, principal="nvis"):
            return queue.enqueue({
                "action": "confirm", "panel": "Switch Status",
                "principal": principal, "token": token,
                "confirmation": "publish_local",
            })

        generation_root = project / ".tracker/generations"

        def no_receipt():
            self.assertEqual(before_generations,
                             tuple(sorted(generation_root.iterdir())))
            self.assertFalse(any(generation_root.glob("*/RECEIPT")))

        token = preview()
        with self.assertRaises(ManualChannelHold):
            queue.enqueue({**preview_request, "principal": ""})
        wrong_job = confirm(token, principal="cumulus")
        self.assertEqual({"error": "manual_hold"}, worker.process_job(wrong_job)[1])
        self.assertEqual("done", queue.status(wrong_job)["state"])
        no_receipt()

        # The same preview is consumed before a failed source refresh.
        self.template.write_bytes(b"corrupt-source")
        drift_job = confirm(token)
        with self.assertRaises(StageLHold):
            worker.process_job(drift_job)
        self.assertEqual("unknown_after_claim", queue.status(drift_job)["state"])
        self.assertTrue((queue_root / f"claimed-{drift_job}.json").is_file())
        no_receipt()
        self.template.write_bytes(original_template)
        replay_job = confirm(token)
        self.assertEqual({"error": "manual_hold"}, worker.process_job(replay_job)[1])
        no_receipt()

        # A fresh status is valid, but a different selected C5 decision is
        # injected only when the protected writer requalifies under LK-P.
        token = preview()
        real_commit = commit_qualified_prod_local

        def changed_decision(*args, **kwargs):
            with mock.patch(
                "monitor.issue_tracker_publish_runtime.selected_panel_decision_sha256",
                return_value="0" * 64,
            ):
                return real_commit(*args, **kwargs)

        changed_job = confirm(token)
        with mock.patch(
            "monitor.issue_tracker_publish_runtime.commit_qualified_prod_local",
            side_effect=changed_decision,
        ), self.assertRaises(StageLHold):
            worker.process_job(changed_job)
        self.assertEqual("unknown_after_claim", queue.status(changed_job)["state"])
        no_receipt()

        token = preview()
        error_job = confirm(token)
        with mock.patch(
            "monitor.issue_tracker_publish_runtime.commit_qualified_prod_local",
            side_effect=RuntimeError("synthetic worker exception"),
        ), self.assertRaises(RuntimeError):
            worker.process_job(error_job)
        self.assertEqual("unknown_after_claim", queue.status(error_job)["state"])
        no_receipt()

        token = preview()
        real_results = []

        def capture_commit(*args, **kwargs):
            result = real_commit(*args, **kwargs)
            real_results.append(result)
            return result

        success_job = confirm(token)
        with mock.patch(
            "monitor.issue_tracker_publish_runtime.commit_qualified_prod_local",
            side_effect=capture_commit,
        ):
            completed, public = worker.process_job(success_job)
        self.assertEqual(success_job, completed)
        self.assertEqual("done", queue.status(success_job)["state"])
        self.assertEqual(1, len(real_results))
        committed = real_results[0]
        self.assertIsInstance(committed, CommittedProdWorkbook)
        self.assertEqual("committed", public["local"])
        self.assertEqual(committed.receipt.manifest_id, public["manifest_id"])
        self.assertEqual(committed.generation.generation_id,
                         public["generation_id"])
        self.assertIs(public["local_applied"], True)
        self.assertEqual("disabled_no_send_authority", public["online"])
        generation = generation_root / public["generation_id"]
        persisted = json.loads((generation / "MANIFEST").read_bytes())
        self.assertEqual("Switch Status",
                         persisted["qualified_source"]["selected_panel"])
        self.assertTrue((generation / "RECEIPT").is_file())
        with zipfile.ZipFile(BytesIO(original_template)) as before, \
             zipfile.ZipFile(BytesIO(committed.prepared.xlsx_bytes)) as after:
            for other in ("sheet3.xml", "sheet4.xml"):
                path = "xl/worksheets/" + other
                self.assertEqual(before.read(path), after.read(path), other)
        retry_job = confirm(token)
        self.assertEqual({"error": "manual_hold"}, worker.process_job(retry_job)[1])
        self.assertEqual(1, len(real_results))

    def _exercise_real_protected_three_panel_fixture(
        self, *, skip_history, automatic_first=False, replayed_auto=False,
        invalid_auto_clock=False, automatic_not_due=False,
        automatic_second_due=False, manual_second_probe=False,
        manual_second_admit=False,
        require_first_manual_admission=False, manual_after_manual=False,
        terminal_orphan_probe=False, selected_manual_panel=None,
        selected_panel_empty=False, manual_channel_bridge=False,
        source_identity_probe=False, two_cycle_changed_latest=False,
        settings_channel_probe=False, settings_channel_fault=False,
        panel_counts_probe=False, source_unit_probe=False, receipted_source_probe=False, observed_source_probe=False,
        observed_switch_insert_probe=False, observed_cabling_insert_probe=False, business_preread_probe=False, original_reserved_probe=False, receipted_intent_probe=False,
        settings_audit_probe=False, owned_read_gates_probe=False, owned_continuity_probe=False, complete_preview_probe=False,
        shared_retry_probe=False, allocation_original_identity_probe=False, allocation_retry_identity_probe=False,
        receipt_admission_rebind_probe=False,quota_namespace_rebind_probe=False,quota_retry_identity_probe=False,
        before_cabling_fixture=None, native_catalog_probe=False, native_catalog_return_fault=None,
        native_catalog_c6_origin_probe=False, nonallocating_switch_catalog_probe=False,
        nonallocating_switch_alias_probe=None, nonallocating_switch_audit_probe=False,
        nonallocating_cabling_catalog_probe=False,
        native_catalog_retained_probe=False,
        native_catalog_creator_first_stat_probe=None,
        native_catalog_all_c6_fifo_probe=None,
        native_catalog_receipted_count_probe=None,
        native_catalog_launch_probe=None,
        continuous_launch_probe=None,
        retry_launch_probe=None,
        qualification_replay_probe=None,
        complete_preview_source_race=False,
        complete_preview_cgi=False, native_current_no_send_probe=False,
    ):
        from monitor.collection_ib_producer import (
            IbProducerAuthoritySnapshot, parse_ib_producer_authority,
            produce_worker_ib_analysis,
        )
        from monitor.issue_tracker_manifest import freeze_prod_stage_l_manifest
        from monitor.issue_tracker_publish_runtime import (
            StageLHold, commit_qualified_prod_local, inspect_stage_l,
            local_publish_interval,
            read_auto_local_admission,
        )
        from monitor.issue_tracker_ib_runtime import read_prod_ib_k_window
        from monitor.issue_tracker_local_workbook_commit import (
            CommittedProdWorkbook, ProdWorkbookNoop,
            commit_prod_stage_l_workbook,
        )
        from monitor.issue_tracker_local_commit import LocalCommitHold
        from monitor.issue_tracker_local_workbook import _read_bound_source
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, qualify_prod_stage_l,
        )
        from monitor.issue_tracker_state_owner import (
            current_k, initialize_tracker_state, set_k, tracker_writer,
        )
        from test_cases.test_collection_cycle_persistence import WORKER, TOKEN_1, TOKEN_2
        from test_cases.test_collection_ib_producer import _record
        from test_cases.test_issue_tracker_ib_runtime_workflow import ROOT
        from tools.project_contract import (
            MIN_CONTINUOUS_INTERVAL_MINUTES, build_collection_cycle_identity,
        )
        from tools.ufm_collection_contract import publish_local_archive
        from tools.ufm_remote_producer import (
            RemoteCollectionObservation, VerifiedRetrievedObservation,
        )

        project = self.root / "DAY0-Prepare/fabric-a"
        project.mkdir(parents=True)
        self.gate.__exit__(None, None, None)
        protected_gate = WORKER.CollectionGate(
            str(project), "prod", status_dir=self.root / "monitor/status",
            enforce_cooldown=False, lane="collection",
        )
        held_gate = protected_gate.__enter__()
        self.addCleanup(lambda: protected_gate.__exit__(None, None, None))
        self.store = WORKER.CollectionCycleStore(gate=held_gate)
        self.project = project
        setup = self.root / "ztp/config/nvos/template/P2P"
        setup.mkdir(parents=True)
        selected = project / "fabric-blue.xlsx"
        with xlsxwriter.Workbook(str(selected)) as book:
            sheet = book.add_worksheet("CL links")
            for col, item in enumerate(("Name", "Port", "Name", "Port")):
                sheet.write(0, col, item)
            for col, item in enumerate(("leaf01", "sw1p1", "server01", "mlx5_0")):
                sheet.write(1, col, item)
            if observed_cabling_insert_probe:
                for col, item in enumerate(("leaf01", "sw1p2", "server03", "mlx5_2")):
                    sheet.write(2, col, item)
        (project / "p2p.xlsx").symlink_to(selected.name)
        (setup / "p2p.xlsx").symlink_to(
            "../../../../../DAY0-Prepare/fabric-a/p2p.xlsx")
        for name, body in (("01-inventory.log", "[ib-sw]\n*leaf*\n\n[server]\n*server*\n"),
                           ("02-port-mapping.log", ""), ("03-splitter.log", "")):
            (setup / name).write_text(body, encoding="utf-8")
        output = setup / "output-p2p"
        output.mkdir()
        cvt = output / "fabric-blue-cvt.xlsx"
        converted = subprocess.run(
            [sys.executable, "-B", str(ROOT / "ztp/config/nvos/template/P2P/p2p-to-validation.py"),
             "--output", str(cvt), "--inventory", str(setup / "01-inventory.log"),
             "--port-map", str(setup / "02-port-mapping.log"),
             "--splitter", str(setup / "03-splitter.log")],
            cwd=setup, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                            "XLSX_TO_CSV_BASE_DIR": str(setup)},
            capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(0, converted.returncode, converted.stdout + converted.stderr)
        incoming = project / "99-output-ufm/incoming"
        incoming.mkdir(parents=True)
        identity = build_collection_cycle_identity(str(project), "prod", 1, TOKEN_1)
        record = _record()
        record.update({
            "project_key": identity["project_key"], "project_root": str(project),
            "retrieval_dir": str(incoming),
            "p2p_sha256": hashlib.sha256(selected.read_bytes()).hexdigest(),
            "cvt_sha256": hashlib.sha256(cvt.read_bytes()).hexdigest(),
            "cvt_provenance_sha256": hashlib.sha256(
                Path(f"{cvt}.provenance.json").read_bytes()).hexdigest(),
        })
        authority = IbProducerAuthoritySnapshot(
            parse_ib_producer_authority(
                record, project_key=identity["project_key"], project_root=project),
            "b" * 64, (1, 2, 3),
        )
        vendor = self.root / "vendor-iblinkinfo.txt"
        vendor.write_text(
            "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
            ' 1 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
            '20 1[  ] "server02 mlx5_1"\n' + (
                ' 1 2[  ] ==( 4X 200 Gbps Active / LinkUp )==> 21 2[  ] "server04 mlx5_3"\n'
                if observed_cabling_insert_probe else ''), encoding="utf-8",
        )
        protected = self.root / "synthetic-root-attestation"
        protected.mkdir(mode=0o700)

        def retrieved(plan, **_kwargs):
            archive = publish_local_archive(plan, vendor, incoming)
            sha = hashlib.sha256(archive.read_bytes()).hexdigest()
            return VerifiedRetrievedObservation(
                RemoteCollectionObservation("EXAMPLE-UFM01", plan.run_id,
                                            "iblinkinfo", plan.ufm_remote_path, sha),
                archive, sha, sha, sha, "b" * 64, "b" * 64,
            )

        with mock.patch("monitor.collection_ib_producer._ROOT_UID", os.getuid()), \
             mock.patch("monitor.collection_ib_producer._open_protected_attestation_dir",
                        side_effect=lambda _key: os.open(protected, os.O_RDONLY)), \
             mock.patch("monitor.collection_ib_producer.load_ib_producer_authority",
                        return_value=authority), \
             mock.patch("monitor.collection_ib_producer.recheck_ib_producer_authority"), \
             mock.patch("monitor.collection_ib_producer.observe_and_retrieve_remote_producer",
                        side_effect=retrieved):
            binding = produce_worker_ib_analysis(
                identity, project_root=project, http_root=self.root,
                clock=lambda: dt.datetime(2026, 9, 26, 4, 20,
                                          tzinfo=dt.timezone.utc),
                runner=lambda _argv: self.fail("transport is supplied by fixture"),
            )
            if selected_panel_empty:
                from test_cases.test_issue_tracker_switch_info_source import (
                    _info as healthy_info, _nvl_info as healthy_nvl_info,
                )
                switch_inputs = (
                    mock.patch(
                        "test_cases.test_issue_tracker_switch_runtime_workflow._info",
                        side_effect=lambda host, **_kwargs: healthy_info(
                            host, fan_state="ok"),
                    ),
                    mock.patch(
                        "test_cases.test_issue_tracker_switch_runtime_workflow._nvl_info",
                        side_effect=lambda host, **_kwargs: healthy_nvl_info(
                            host, asic_current="30"),
                    ),
                )
                with switch_inputs[0], switch_inputs[1]:
                    cycle, artifacts = self._cycle(
                        activity=True, derivation=True, ib_analysis=binding,
                        fabric_templates={"ethernet/prod": "tan-leaf",
                                          "nvlink/prod": "border-leaf"},
                    )
            else:
                cycle, artifacts = self._cycle(
                    activity=True, derivation=True, ib_analysis=binding,
                    fabric_templates={"ethernet/prod": "tan-leaf",
                                      "nvlink/prod": "border-leaf"},
                    additional_eth_activity=observed_cabling_insert_probe,
                )
            self.assertEqual(identity["cycle_id"], cycle["cycle_id"])
            self.publication = project / "99-output-monitor"
            self.publication.mkdir()
            initialize_tracker_state(
                project, self.publication, initialized_at="2026-09-25T00:00:00Z",
                acquisition_id="req7-three-panel-protected-fixture",
            )
            self.template = self.publication / "local.xlsx"
            self.template.write_bytes(fake_workbook(reserved_switch_rows=4))
            default_preparation = (native_catalog_launch_probe is not None
                and native_catalog_launch_probe[0] in ('prepare','prepare-mixed-accounting','prepare-quota-rebind','prepare-finalizer-expiry',
                    'prepare-business','prepare-business-finalizer-rebind','prepare-business-postclose-revoke',
                    'default-worker-original-images','complete-after-archive','complete-after-archive-receipt-rebind',
                    'complete-after-archive-local-c6','complete-after-archive-receipt-rebind-local-c6',
                    'complete-after-archive-settings-finalizer-local-c6',
                    'complete-after-archive-local-c6-native-current-compiler',
                    'complete-after-archive-local-c6-native-current-compiler-issued-reads',
                    'complete-after-archive-local-c6-native-current-compiler-issued-reads-issued-tail',
                    'complete-after-archive-local-c6-native-current-compiler-receipt-tail'))
            if manual_channel_bridge or complete_preview_probe or default_preparation or native_current_no_send_probe:
                root_template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
                root_template.parent.mkdir(parents=True, exist_ok=True)
                root_template.write_bytes(self.template.read_bytes())
                self.template = root_template
            self.snapshot = read_whitelist_workbook(self.template)
            with tracker_writer(project, self.publication) as token:
                set_k(token, new_k=2 if two_cycle_changed_latest else 1,
                      actor="operator:fixture",
                      recorded_at="2026-09-25T00:01:00Z",
                      request_id=("req7-three-panel-k2" if two_cycle_changed_latest
                                  else "req7-three-panel-k1"), expected_revision=0)
                self.settings = current_k(token)
            args = {"http_root": self.root, "settings": self.settings,
                    "whitelist_snapshot": self.snapshot,
                    "whitelist_path": self.template}
            if skip_history:
                (project / "01-global.yaml").write_text(
                    "schema_version: 2\ncommon:\n  mgmt:\n"
                    "    issue-tracker:\n      status: disabled\n",
                    encoding="utf-8",
                )
                self._verify_protected_skip_commit(project, args)
                return
            if two_cycle_changed_latest:
                second_identity = build_collection_cycle_identity(
                    str(project), "prod", 2, TOKEN_2,
                )
                vendor.write_text(
                    "Switch: 0x1 MF0;leaf01:MQM9700/U1:\n"
                    ' 1 1[  ] ==( 4X 200 Gbps Active / LinkUp )==> '
                    '20 1[  ] "server03 mlx5_1"\n', encoding="utf-8",
                )
                second_binding = produce_worker_ib_analysis(
                    second_identity, project_root=project, http_root=self.root,
                    clock=lambda: dt.datetime(2026, 9, 26, 4, 31,
                                              tzinfo=dt.timezone.utc),
                    runner=lambda _argv: self.fail("transport is supplied by fixture"),
                )
                from test_cases.test_issue_tracker_switch_info_source import _nvl_info
                with mock.patch(
                    "test_cases.test_issue_tracker_switch_runtime_workflow._nvl_info",
                    side_effect=lambda host, **_kwargs: _nvl_info(host, asic_current="81"),
                ):
                    second_cycle, _ = self._cycle(
                        activity=True, derivation=True,
                        ib_analysis=second_binding, observed_peer="changed-peer",
                        fabric_templates={"ethernet/prod": "tan-leaf",
                                          "nvlink/prod": "border-leaf"},
                    )
                self.assertEqual(second_identity["cycle_id"], second_cycle["cycle_id"])
                self._verify_two_cycle_latest_local_commit(
                    project, args, (cycle["cycle_id"], second_cycle["cycle_id"]),
                )
                return
            if qualification_replay_probe is not None:
                from monitor import issue_tracker_stage_l_consumer as consumer
                if qualification_replay_probe in (
                        'composed-ethernet-archive-drift',
                        'composed-nvlink-archive-drift'):
                    slot = ('ethernet/prod' if qualification_replay_probe ==
                            'composed-ethernet-archive-drift' else 'nvlink/prod')
                    path = artifacts[slot]['info']
                    original_archive = path.read_bytes()
                    actual_read = consumer.read_prod_eth_activity_k_window
                    reached = []
                    def drift_after_eth(*values, **keywords):
                        result = actual_read(*values, **keywords)
                        reached.append(True)
                        if len(reached) == 1:
                            path.write_bytes(original_archive + b'changed Switch archive after ETH')
                        return result
                    try:
                        with mock.patch.object(consumer, 'read_prod_eth_activity_k_window',
                                               side_effect=drift_after_eth):
                            with self.assertRaises(consumer.StageLConsumerHold):
                                consumer.inspect_prod_stage_l_composed_sources(self.store, **args)
                        self.assertEqual([True], reached)
                        self.assertEqual((), tuple(self.publication.glob('Issue_Tracker*')))
                    finally:
                        path.write_bytes(original_archive)
                    return
                if qualification_replay_probe == 'switch-families':
                    actual_observe = consumer._observe_prod_stage_l_switch_sources
                    actual_window = consumer.read_prod_switch_k_window
                    legs = []
                    def observe(*values, **keywords):
                        with mock.patch.object(consumer, 'read_prod_switch_k_window',
                                               wraps=actual_window) as windows:
                            result = actual_observe(*values, **keywords)
                        legs.append(tuple(call.kwargs['source_slot'] for call in windows.call_args_list))
                        return result
                    with mock.patch.object(consumer, '_observe_prod_stage_l_switch_sources', side_effect=observe):
                        qualified = qualify_prod_stage_l(self.store, **args)
                    self.assertEqual([('ethernet/prod', 'nvlink/prod')] * 4, legs,
                                     'each actual composed start/end leg rereads both real Switch families once')
                    self.assertTrue(qualified.qualified)
                    self.assertEqual({'Switch Status', 'Eth Link Validation', 'IB Link Validation'},
                                     {item.panel for item in qualified.candidates})
                    self.assertEqual(4, len(qualified.candidates))
                    self.assertEqual((), tuple(self.publication.glob('Issue_Tracker*')))
                    return
                if qualification_replay_probe == 'composed-w1-drift':
                    actual_read = consumer.read_prod_eth_activity_k_window
                    original_template = self.template.read_bytes()
                    reached = []
                    def drift_after_read(*values, **keywords):
                        result = actual_read(*values, **keywords)
                        reached.append(True)
                        if len(reached) == 1:
                            self.template.write_bytes(b'changed W1 after actual ETH observation')
                        return result
                    try:
                        with mock.patch.object(consumer, 'read_prod_eth_activity_k_window',
                                               side_effect=drift_after_read):
                            with self.assertRaises(consumer.StageLConsumerHold):
                                consumer.inspect_prod_stage_l_composed_sources(self.store, **args)
                        self.assertEqual([True], reached)
                        self.assertEqual((), tuple(self.publication.glob('Issue_Tracker*')))
                    finally:
                        self.template.write_bytes(original_template)
                    return
                if qualification_replay_probe == 'composed-legs':
                    with mock.patch.object(consumer, 'read_whitelisted_ib_k_window',
                            wraps=consumer.read_whitelisted_ib_k_window) as ib_reads, \
                            mock.patch.object(consumer, '_observe_prod_stage_l_switch_sources',
                            wraps=consumer._observe_prod_stage_l_switch_sources) as switch_reads, \
                            mock.patch.object(consumer, 'inspect_prod_stage_l_composed_sources',
                            wraps=consumer.inspect_prod_stage_l_composed_sources) as composed_reads:
                        qualified = qualify_prod_stage_l(self.store, **args)
                    self.assertEqual(2, composed_reads.call_count)
                    self.assertEqual(4, ib_reads.call_count,
                        'actual IB start/end for both native qualification walks, not nested duplicate legs')
                    self.assertEqual(4, switch_reads.call_count)
                    self.assertTrue(qualified.qualified)
                    self.assertEqual({'Switch Status', 'Eth Link Validation', 'IB Link Validation'},
                                     {item.panel for item in qualified.candidates})
                    self.assertEqual(4, len(qualified.candidates))
                    self.assertEqual((), tuple(self.publication.glob('Issue_Tracker*')))
                    return
                if qualification_replay_probe == 'whitelist-drift':
                    real_final = consumer.validate_prod_stage_l_source_projection
                    reached = []
                    original_template = self.template.read_bytes()
                    def drift(*values, **keywords):
                        reached.append(True)
                        self.template.write_bytes(b'changed W1 at final projection boundary')
                        return real_final(*values, **keywords)
                    try:
                        with mock.patch.object(consumer,'validate_prod_stage_l_source_projection',side_effect=drift):
                            with self.assertRaises(consumer.StageLConsumerHold):
                                qualify_prod_stage_l(self.store,**args)
                        self.assertEqual([True],reached)
                    finally:
                        self.template.write_bytes(original_template)
                    return
                self.assertEqual('bounded',qualification_replay_probe)
                with mock.patch.object(consumer,'inspect_prod_stage_l_composed_sources',
                                       wraps=consumer.inspect_prod_stage_l_composed_sources) as replay:
                    qualified = qualify_prod_stage_l(self.store,**args)
                self.assertEqual(2,replay.call_count,
                    'one native qualification needs complete start/end source walks, not a third recursive walk')
                self.assertTrue(qualified.qualified)
                self.assertEqual({'Switch Status','Eth Link Validation','IB Link Validation'},
                                 {item.panel for item in qualified.candidates})
                self.assertEqual(4,len(qualified.candidates))
                return
            qualified = qualify_prod_stage_l(self.store, **args)
            self.assertTrue(qualified.qualified)
            self.assertEqual("prod-runtime-protected-v1", qualified.mode)
            self.assertEqual((cycle["cycle_id"],), qualified.cycle_ids)
            expected_panels = ({"Eth Link Validation", "IB Link Validation"}
                               if selected_panel_empty else
                               {"Switch Status", "Eth Link Validation",
                                "IB Link Validation"})
            expected_count = 2 if selected_panel_empty else (6 if observed_cabling_insert_probe else 4)
            self.assertEqual(expected_panels,
                             {item.panel for item in qualified.candidates})
            self.assertEqual(expected_count, len(qualified.candidates))
            if complete_preview_probe:
                from monitor import issue_tracker_manual_preview as manual
                from test_cases.test_issue_tracker_manual_ui import browser_settings_script
                (project / "01-global.yaml").write_text(
                    "schema_version: 2\ncommon:\n  mgmt:\n"
                    "    issue-tracker:\n      status: disabled\n", encoding="utf-8")
                broker = manual.make_complete_protected_stage_l_broker(
                    self.store, http_root=self.root, project=project,
                    publication=self.publication, template_path=self.template,
                    boot_id="complete-preview-fixture", monotonic_ns=time.monotonic_ns,
                    clock=lambda: 1000.0,
                )
                generated_confirm = {}
                if complete_preview_cgi:
                    from urllib.parse import urlencode
                    from monitor.issue_tracker_manual_channel import DurableManualQueue, ManualQueueWorker
                    from test_cases.test_issue_tracker_manual_ui_workflow import CGI, environ
                    queue_root = project / ".tracker/complete-preview-queue"
                    queue_root.mkdir(mode=0o700)
                    queue = DurableManualQueue(queue_root, boot_id="complete-preview-fixture")
                    worker = ManualQueueWorker(queue, broker)
                    def cgi(body):
                        def submit(request):
                            job = queue.enqueue(request)
                            done, result = worker.process_job(job)
                            self.assertEqual(job, done)
                            self.assertEqual("done", queue.status(job)["state"])
                            return result
                        return CGI.handle(environ(body), body, submit=submit)
                previews = {}
                for panel, count, files in (("Switch Status", 2, 2),
                                            ("Eth Link Validation", 1, 1),
                                            ("IB Link Validation", 1, 1)):
                    if complete_preview_cgi:
                        body = urlencode({"action": "preview", "panel": panel}).encode("ascii")
                        status, preview = cgi(body)
                        self.assertEqual("200 OK", status)
                    else:
                        preview = broker.preview("nvis", panel)
                    previews[panel] = preview
                    self.assertEqual((count, count, 0, 0), tuple(preview[key] for key in (
                        "qualified_operation_count", "new_count", "update_count", "skip_count")))
                    self.assertEqual(files, len(preview["source_files"]))
                    self.assertEqual(count, len(preview["row_digests"]))
                    for item in preview["source_files"]:
                        self.assertEqual(hashlib.sha256((self.root / item["path"]).read_bytes()).hexdigest(),
                                         item["sha256"])
                    browser = browser_settings_script(
                        "console.log(JSON.stringify({valid:validIssueTrackerPreview(" +
                        json.dumps(preview) + "," + json.dumps(panel) + ")}));")
                    self.assertEqual({"valid": True}, browser)
                    if complete_preview_cgi:
                        browser = browser_settings_script(
                            "replies.push(" + json.dumps(preview) + ");\n"
                            "await issueTrackerManualPreview(" + json.dumps(panel) + ");\n"
                            "replies.push({local_applied:false});\n"
                            "await issueTrackerManualConfirm();\n"
                            "console.log(JSON.stringify({calls}));")
                        self.assertEqual(body.decode("ascii"), browser["calls"][0]["body"])
                        generated_confirm[panel] = browser["calls"][1]["body"].encode("ascii")
                if complete_preview_source_race:
                    real_commit = broker._commit_local
                    def change_after_confirm_read(panel, fingerprint):
                        path = artifacts["ethernet/prod"]["info"]
                        stamp = path.stat().st_mtime_ns
                        os.utime(path, ns=(stamp + 2_000_000_000, stamp + 2_000_000_000))
                        return real_commit(panel, fingerprint)
                    broker._commit_local = change_after_confirm_read
                    with self.assertRaises(StageLHold):
                        broker.confirm("nvis", "Switch Status", previews["Switch Status"]["token"],
                                       confirmation="publish_local")
                    self.assertFalse(any((project / ".tracker/generations").glob("*/RECEIPT")))
                    with self.assertRaises(manual.ManualPreviewHold):
                        broker.confirm("nvis", "Switch Status", previews["Switch Status"]["token"],
                                       confirmation="publish_local")
                    return
                if complete_preview_cgi:
                    status, committed = cgi(generated_confirm["Switch Status"])
                    self.assertEqual("200 OK", status)
                else:
                    committed = broker.confirm("nvis", "Switch Status", previews["Switch Status"]["token"],
                                               confirmation="publish_local")
                self.assertTrue(committed["local_applied"])
                receipts = tuple((project / ".tracker/generations").glob("*/RECEIPT"))
                self.assertEqual(1, len(receipts))
                # Even an untouched ETH source cannot reuse counts computed
                # against the pre-Switch local workbook image.
                if complete_preview_cgi:
                    status, held = cgi(generated_confirm["Eth Link Validation"])
                    self.assertEqual(("409 Conflict", {"error": "manual_hold"}), (status, held))
                else:
                    with self.assertRaises(manual.ManualPreviewHold):
                        broker.confirm("nvis", "Eth Link Validation",
                                       previews["Eth Link Validation"]["token"],
                                       confirmation="publish_local")
                self.assertEqual(receipts, tuple((project / ".tracker/generations").glob("*/RECEIPT")))
                return
            if panel_counts_probe:
                from monitor.issue_tracker_local_workbook_commit import (
                    project_manual_panel_image, project_manual_panel_preview,
                )
                source = self.template.read_bytes()
                generation_root = project / ".tracker/generations"
                before_generations = tuple(generation_root.iterdir())
                for panel, count in (("Switch Status", 2),
                                     ("Eth Link Validation", 1),
                                     ("IB Link Validation", 1)):
                    _, manifest_id = freeze_prod_stage_l_manifest(
                        qualified, self.store, metadata={
                            "project_id": str(project), "schema_version": 1,
                            "producer_version": "stage-l-runtime-v1",
                            "template_contract_version": "local-xlsx-v1",
                            "template_sha256": self.snapshot.workbook_sha256,
                        }, expected_template_sha256=self.snapshot.workbook_sha256,
                        selected_panel=panel, **args,
                    )
                    preview = project_manual_panel_preview(source, qualified, panel, manifest_id)
                    self.assertEqual((count, count, 0, 0), tuple(preview[key] for key in (
                        "qualified_operation_count", "new_count", "update_count", "skip_count")))
                    self.assertEqual(count, len(preview["row_digests"]))
                    image = project_manual_panel_image(source, qualified, panel, manifest_id)
                    noop = project_manual_panel_preview(image, qualified, panel, manifest_id)
                    self.assertEqual((0, 0, count), tuple(noop[key] for key in (
                        "new_count", "update_count", "skip_count")))
                self.assertEqual(source, self.template.read_bytes())
                self.assertEqual(before_generations, tuple(generation_root.iterdir()))
                return
            if source_identity_probe:
                from monitor.issue_tracker_stage_l_consumer import (
                    read_prod_stage_l_panel_source_files,
                    validate_prod_stage_l_panel_source_files,
                )
                expected = {
                    "Switch Status": {
                        artifacts["ethernet/prod"]["info"],
                        artifacts["nvlink/prod"]["info"],
                    },
                    "Eth Link Validation": {
                        artifacts["ethernet/prod"]["activity"],
                    },
                    "IB Link Validation": {
                        project / "99-output-ufm/runs" / binding["run_id"] /
                        "EXAMPLE-UFM01" /
                        f"iblinkinfo_{binding['run_id']}-topology-validation.xlsx",
                    },
                }
                witnessed_by_panel = {}
                for panel, source_paths in expected.items():
                    witnessed = read_prod_stage_l_panel_source_files(
                        qualified, self.store, panel=panel, **args,
                    )
                    witnessed_by_panel[panel] = witnessed
                    self.assertEqual(
                        {str(path.relative_to(self.root)) for path in source_paths},
                        {item.path for item in witnessed},
                    )
                    self.assertTrue(all(item.recorded_at_utc and
                                        item.sha256 == hashlib.sha256(
                                            (self.root / item.path).read_bytes()
                                        ).hexdigest() for item in witnessed))
                    self.assertEqual(witnessed,
                        validate_prod_stage_l_panel_source_files(
                            witnessed, qualified, self.store, panel=panel,
                            **args,
                        ))
                altered = artifacts["ethernet/prod"]["info"]
                prior_ns = altered.stat().st_mtime_ns
                os.utime(altered, ns=(prior_ns + 2_000_000_000,
                                      prior_ns + 2_000_000_000))
                with self.assertRaises(StageLConsumerHold):
                    validate_prod_stage_l_panel_source_files(
                        witnessed_by_panel["Switch Status"], qualified, self.store,
                        panel="Switch Status", **args,
                    )
                altered.write_bytes(b"changed after protected preview")
                with self.assertRaises(StageLConsumerHold):
                    validate_prod_stage_l_panel_source_files(
                        witnessed_by_panel["Switch Status"], qualified, self.store,
                        panel="Switch Status", **args,
                    )
                return
            stage_status = inspect_stage_l(
                self.store, http_root=self.root, project=project,
                publication=self.publication, template_path=self.template,
            )
            self.assertEqual("qualified", stage_status["state"])
            self.assertEqual(expected_count, stage_status["qualified_operation_count"])
            self.assertEqual(0, stage_status["whitelist_skip_count"])
            self.assertEqual("disabled_no_send_authority", stage_status["online"])
            self.assertNotIn("receipt", stage_status)
            if settings_channel_probe or settings_channel_fault:
                self._verify_authenticated_settings_channel(project, fault=settings_channel_fault)
                return
            protected_time = read_prod_ib_k_window(self.store, **args).recorded_at_utc
            self.assertTrue(protected_time)
            self.assertEqual(protected_time, qualified.recorded_at_utc)
            self.assertEqual({protected_time},
                             {item.recorded_at_utc for item in qualified.candidates})
            observations = json.dumps({
                "candidates": [asdict(item) for item in qualified.candidates],
                "whitelist_skips": [asdict(item) for item in qualified.whitelist_skips],
                "hostname_fallback_count": sum(
                    item.fabric_source == "hostname-fallback"
                    for item in qualified.candidates
                ),
                "recorded_at_utc": protected_time,
            }, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False).encode("utf-8") + b"\n"
            self.assertEqual(hashlib.sha256(observations).hexdigest(),
                             qualified.observations_sha256)
            with tracker_writer(project, self.publication) as token:
                self.assertEqual(
                    qualified,
                    qualify_prod_stage_l(self.store, writer_token=token, **args),
                )
            metadata = {
                "project_id": str(project), "schema_version": 1,
                "producer_version": "req7-test-producer",
                "template_contract_version": "v1",
                "template_sha256": self.snapshot.workbook_sha256,
            }
            if native_current_no_send_probe:
                metadata.update(producer_version='stage-l-runtime-v1',template_contract_version='local-xlsx-v1')
            before_publication = tuple(sorted(self.publication.iterdir()))
            body, digest = freeze_prod_stage_l_manifest(
                qualified, self.store, metadata=metadata,
                expected_template_sha256=self.snapshot.workbook_sha256,
                **args,
            )
            self.assertEqual(hashlib.sha256(body).hexdigest(), digest)
            self.assertEqual(
                protected_time,
                json.loads(body)["qualified_source"]["recorded_at_utc"],
            )
            self.assertEqual(before_publication,
                             tuple(sorted(self.publication.iterdir())))
            generation_root = project / ".tracker/generations"
            before_generations = tuple(sorted(generation_root.iterdir()))
            original_template = self.template.read_bytes()
            if source_unit_probe:
                from monitor.issue_tracker_send_unit import freeze_prod_source_unit, SendUnitHold
                for sheet, family, sid in (('ETH&IB Switch', 'switch', 101), ('ETH Cabling', 'eth_cabling', 102),
                                           ('IB Cabling', 'ib_cabling', 103)):
                    candidates = tuple(item for item in qualified.candidates if item.activity_key[0] == family)
                    self.assertTrue(candidates, 'all three real protected families must be exercised')
                    placements = tuple({'operation_id': item.operation_id, 'action': 'update' if family == 'switch' else 'insert',
                        'row_index': index + 2 if family == 'switch' else None, 'observed_values': {'L': {}} if family == 'switch' else None,
                        'reserved_id': None if family == 'switch' else 'NV%05d' % (41001 + index)}
                        for index, item in enumerate(candidates))
                    options = dict(generation_id='a' * 64, publish_id='b' * 64,
                        spreadsheet_id='synthetic_spreadsheet_id_0001', sheet=sheet, sheet_id=sid, history_sheet_id=105,
                        target_nonce='c' * 64, history_nonce='d' * 64, preread_sha256='e' * 64,
                        audits=(), occupied_metadata_ids=())
                    with tracker_writer(project, self.publication) as token:
                        value = freeze_prod_source_unit(qualified, self.store, metadata=metadata,
                            expected_template_sha256=self.snapshot.workbook_sha256, placements=placements, writer_token=token,
                            **args, **options)
                        image = json.loads(value.action_preimage)
                        self.assertEqual(digest, image['manifest_id'])
                        self.assertEqual([item.operation_id for item in candidates], [item['operation_id'] for item in image['business']])
                        self.assertEqual([list(item.activity_key) for item in candidates], [item['activity_key'] for item in image['business']])
                        self.assertEqual([item.recorded_at_utc for item in candidates], [item['recorded_at_utc'] for item in image['business']])
                        for item, candidate in zip(image['business'], candidates):
                            if family == 'switch':
                                self.assertEqual({'stringValue': '[MONITOR][%s][%s] [fabric_source=%s] %s' %
                                    (candidate.activity_key[2], candidate.activity_key[3], candidate.fabric_source, candidate.evidence_description)},
                                    item['requests'][0]['updateCells']['rows'][0]['values'][0]['userEnteredValue'])
                            else:
                                cells = item['requests'][0]['appendCells']['rows'][0]['values']
                                self.assertEqual({'stringValue': 'ETH' if family == 'eth_cabling' else 'IB'}, cells[4]['userEnteredValue'])
                                self.assertEqual({'stringValue': 'New'}, cells[20]['userEnteredValue'])
                                self.assertEqual({'stringValue': candidate.activity_key[3]}, cells[5]['userEnteredValue'])
                        invented = tuple({**item, 'values': {'L': 'caller invented text'}} for item in placements)
                        with self.assertRaises(SendUnitHold):
                            freeze_prod_source_unit(qualified, self.store, metadata=metadata,
                                expected_template_sha256=self.snapshot.workbook_sha256, placements=invented, writer_token=token, **args, **options)
                        altered = replace(qualified, candidates=tuple(replace(item, evidence_description='caller invented text')
                                                                      for item in qualified.candidates))
                        with self.assertRaises(SendUnitHold):
                            freeze_prod_source_unit(altered, self.store, metadata=metadata,
                                expected_template_sha256=self.snapshot.workbook_sha256, placements=placements, writer_token=token, **args, **options)
                        if family == 'switch':
                            noop_placements = tuple({**placement, 'observed_values': {'L': {
                                'stringValue': '[MONITOR][%s][%s] [fabric_source=%s] %s' %
                                    (candidate.activity_key[2], candidate.activity_key[3], candidate.fabric_source,
                                     candidate.evidence_description)}}}
                                for placement, candidate in zip(placements, candidates))
                            noop = freeze_prod_source_unit(qualified, self.store, metadata=metadata,
                                expected_template_sha256=self.snapshot.workbook_sha256, placements=noop_placements,
                                writer_token=token, **args, **options)
                            self.assertEqual('NO_SEND', noop.outcome)
                            self.assertEqual(b'', noop.wire_bytes)
                            self.assertEqual(0, noop.history_rows_expected)
                            source_path = artifacts['ethernet/prod']['info']
                            source_before = source_path.read_bytes()
                            from monitor.issue_tracker_online_cells import source_tool_values as real_values
                            def drift_after_source_values(*values_args, **values_kwargs):
                                result = real_values(*values_args, **values_kwargs)
                                source_path.write_bytes(source_before + b'\nchanged during source compilation\n')
                                return result
                            try:
                                with mock.patch('monitor.issue_tracker_online_cells.source_tool_values',
                                                side_effect=drift_after_source_values), self.assertRaises(SendUnitHold):
                                    freeze_prod_source_unit(qualified, self.store, metadata=metadata,
                                        expected_template_sha256=self.snapshot.workbook_sha256, placements=placements,
                                        writer_token=token, **args, **options)
                            finally:
                                source_path.write_bytes(source_before)
                    self.assertEqual(before_publication, tuple(sorted(self.publication.iterdir())))
                    self.assertEqual(before_generations, tuple(sorted(generation_root.iterdir())))
                    self.assertEqual(original_template, self.template.read_bytes())
                return
            if selected_manual_panel is not None:
                selected_body, selected_id = freeze_prod_stage_l_manifest(
                    qualified, self.store, metadata=metadata,
                    expected_template_sha256=self.snapshot.workbook_sha256,
                    selected_panel=selected_manual_panel, **args,
                )
                scoped = json.loads(selected_body)
                self.assertEqual("Switch Status",
                                 scoped["qualified_source"]["selected_panel"])
                if selected_panel_empty:
                    self.assertEqual([], scoped["operations"])
                    self.assertEqual([], scoped["qualified_source"]["whitelist_skips"])
                    evaluations = scoped["qualified_source"]["panel_evaluation"]
                    self.assertEqual(
                        {"state": "evaluated", "whitelist_skips": "no-skips"},
                        evaluations["Switch Status"],
                    )
                    for other in ("Eth Link Validation", "IB Link Validation"):
                        self.assertEqual(
                            {"state": "not-evaluated-in-this-manifest"},
                            evaluations[other],
                        )
                    self.assertEqual(
                        qualified.source_authority_sha256,
                        scoped["qualified_source"]["source_authority_sha256"],
                    )
                    self.assertEqual(
                        qualified.observations_sha256,
                        scoped["qualified_source"]["observations_sha256"],
                    )
                self.assertEqual(set() if selected_panel_empty else {"Switch Status"},
                                 {item.panel for item in qualified.candidates
                                  if item.operation_id in {operation["operation_id"]
                                      for operation in scoped["operations"]}})
                (project / "01-global.yaml").write_text(
                    "schema_version: 2\ncommon:\n  mgmt:\n"
                    "    issue-tracker:\n      status: disabled\n",
                    encoding="utf-8",
                )
                if manual_channel_bridge:
                    self._verify_manual_queue_protected_commit(
                        project, original_template, before_generations,
                        qualified,
                    )
                    return
                interval, policy_sha = local_publish_interval(project)
                witness = (policy_sha, interval, "fixture-boot", time.monotonic_ns())
                with tracker_writer(project, self.publication) as token:
                    committed = commit_prod_stage_l_workbook(
                        token, qualified, self.store,
                        template_path=self.template, metadata=metadata,
                        expected_template_sha256=self.snapshot.workbook_sha256,
                        manual_admission=witness,
                        selected_panel=selected_manual_panel, **args,
                    )
                if selected_panel_empty:
                    self.assertIsInstance(committed, ProdWorkbookNoop)
                    self.assertEqual("no_candidates", committed.status)
                    self.assertEqual(selected_id, committed.manifest_id)
                    self.assertEqual(before_generations,
                                     tuple(sorted(generation_root.iterdir())))
                    self.assertFalse(any(generation_root.glob("*/RECEIPT")))
                    self.assertEqual(original_template, self.template.read_bytes())
                    with zipfile.ZipFile(BytesIO(original_template)) as before, \
                         zipfile.ZipFile(BytesIO(self.template.read_bytes())) as after:
                        for other in ("sheet3.xml", "sheet4.xml"):
                            path = "xl/worksheets/" + other
                            self.assertEqual(before.read(path), after.read(path))
                    return
                self.assertIsInstance(committed, CommittedProdWorkbook)
                self.assertEqual(3, committed.prepared.source_family_count)
                self.assertEqual(selected_id, committed.receipt.manifest_id)
                generation = (project / ".tracker/generations" /
                              committed.generation.generation_id)
                self.assertEqual(selected_body, (generation / "MANIFEST").read_bytes())
                self.assertTrue((generation / "RECEIPT").is_file())
                persisted_manifest = json.loads((generation / "MANIFEST").read_bytes())
                self.assertEqual(selected_manual_panel,
                                 persisted_manifest["qualified_source"]["selected_panel"])
                evaluations = persisted_manifest["qualified_source"]["panel_evaluation"]
                self.assertEqual({"state": "evaluated", "whitelist_skips": "no-skips"},
                                 evaluations["Switch Status"])
                for other in ("Eth Link Validation", "IB Link Validation"):
                    self.assertEqual({"state": "not-evaluated-in-this-manifest"},
                                     evaluations[other])
                persisted_receipt = json.loads((generation / "RECEIPT").read_bytes())
                self.assertEqual(selected_id, persisted_receipt["manifest_id"])
                self.assertEqual(1 + len(before_generations),
                                 len(tuple(generation_root.iterdir())))
                with zipfile.ZipFile(BytesIO(original_template)) as before, \
                     zipfile.ZipFile(BytesIO(committed.prepared.xlsx_bytes)) as after:
                    for other in ("sheet3.xml", "sheet4.xml"):
                        path = "xl/worksheets/" + other
                        self.assertEqual(before.read(path), after.read(path), other)
                    self.assertNotEqual(before.read("xl/worksheets/sheet2.xml"),
                                        after.read("xl/worksheets/sheet2.xml"))
                    self.assertNotEqual(before.read("xl/worksheets/sheet6.xml"),
                                        after.read("xl/worksheets/sheet6.xml"))
                return
            if automatic_first:
                root_template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
                root_template.parent.mkdir(parents=True, exist_ok=True)
                root_template.write_bytes(original_template)
                (project / "01-global.yaml").write_text(
                    "schema_version: 2\ncommon:\n  mgmt:\n"
                    "    issue-tracker:\n      status: disabled\n"
                    + ("      publish_every_cycles: 2\n"
                       if automatic_not_due else ""),
                    encoding="utf-8",
                )
                stage_status_path = (
                    self.root / "monitor/status/issue-tracker-stage-l.status.json"
                )
                with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                      mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                      mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                        stage_status_path),
                      mock.patch.object(WORKER, "_current_boot_identity",
                                        return_value="" if invalid_auto_clock
                                        else WORKER._current_boot_identity())):
                    result = WORKER._publish_stage_l_local_after_completion(self.store)
                if automatic_not_due:
                    self.assertIsNone(result)
                    self.assertEqual("qualified", json.loads(
                        stage_status_path.read_bytes())["state"])
                    self.assertEqual("not_due", json.loads(
                        stage_status_path.read_bytes())["local"])
                    self.assertEqual(before_generations,
                                     tuple(sorted(generation_root.iterdir())))
                    self.assertFalse((project / ".tracker/admissions").exists())
                    return
                if invalid_auto_clock:
                    self.assertIsNone(result)
                    self.assertEqual("hold", json.loads(
                        stage_status_path.read_bytes())["state"])
                    self.assertEqual(before_generations,
                                     tuple(sorted(generation_root.iterdir())))
                    self.assertFalse((project / ".tracker/admissions").exists())
                    return
                self.assertIsInstance(result, CommittedProdWorkbook)
                self.assertEqual("local_applied", json.loads(
                    stage_status_path.read_bytes())["state"])
                self.assertEqual("disabled_no_send_authority", json.loads(
                    stage_status_path.read_bytes())["online"])
                self.assertEqual(
                    hashlib.sha256(result.prepared.xlsx_bytes).hexdigest(),
                    result.receipt.published_sha256,
                )
                self.assertEqual(len(before_generations) + 1,
                                 len(tuple(generation_root.iterdir())))
                admission_files = tuple(sorted((project / ".tracker/admissions").iterdir()))
                self.assertEqual(1, len(admission_files))
                admission = json.loads(admission_files[0].read_bytes())
                self.assertEqual(result.receipt.generation_id,
                                 admission["generation_id"])
                self.assertEqual(result.receipt.published_sha256,
                                 admission["published_sha256"])
                self.assertEqual(self.store.project_key, admission["project_key"])
                self.assertEqual("prod", admission["scope"])
                self.assertEqual(1, admission["schema_version"])
                with tracker_writer(project, self.publication) as token:
                    self.assertEqual(admission, read_auto_local_admission(
                        token, self.store, self.snapshot.workbook_sha256,
                    ))
                with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                      mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                      mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                        stage_status_path),
                      mock.patch.object(WORKER, "_current_boot_identity",
                                        return_value=admission["boot_id"])):
                    self.assertIsNone(
                        WORKER._publish_stage_l_local_after_completion(self.store)
                    )
                self.assertEqual("qualified", json.loads(
                    stage_status_path.read_bytes())["state"])
                self.assertEqual("not_due", json.loads(
                    stage_status_path.read_bytes())["local"])
                self.assertEqual(len(before_generations) + 1,
                                 len(tuple(generation_root.iterdir())))
                if automatic_second_due or manual_second_probe or manual_second_admit:
                    second_identity = build_collection_cycle_identity(
                        str(project), "prod", 2, TOKEN_2,
                    )
                    second_binding = produce_worker_ib_analysis(
                        second_identity, project_root=project, http_root=self.root,
                        clock=lambda: dt.datetime(2026, 9, 26, 4, 31,
                                                  tzinfo=dt.timezone.utc),
                        runner=lambda _argv: self.fail(
                            "transport is supplied by fixture"),
                    )
                    second_cycle, _ = self._cycle(
                        activity=True, derivation=True,
                        observed_peer="changed-peer", ib_analysis=second_binding,
                        fabric_templates={"ethernet/prod": "tan-leaf",
                                          "nvlink/prod": "border-leaf"},
                    )
                    self.assertEqual(second_identity["cycle_id"],
                                     second_cycle["cycle_id"])
                    if manual_second_probe:
                        with self.assertRaises(StageLHold):
                            commit_qualified_prod_local(
                                self.store, http_root=self.root,
                                project=project, publication=self.publication,
                                template_path=self.root /
                                "monitor/Issue_Tracker_Template_v1.xlsx",
                            )
                        # The lower C6 helper is also callable with a real
                        # qualified set. It must not mint a second generation
                        # without the same shared admission proof.
                        with tracker_writer(project, self.publication) as token:
                            second_qualified = qualify_prod_stage_l(
                                self.store, writer_token=token, **args,
                            )
                            with self.assertRaisesRegex(
                                LocalCommitHold, "shared admission",
                            ):
                                commit_prod_stage_l_workbook(
                                    token, second_qualified, self.store,
                                    template_path=self.template,
                                    metadata=metadata,
                                    expected_template_sha256=(
                                        self.snapshot.workbook_sha256),
                                    **args,
                                )
                        self.assertEqual(1, len(tuple(
                            (project / ".tracker/admissions").iterdir())))
                        self.assertEqual(len(before_generations) + 1,
                                         len(tuple(generation_root.iterdir())))
                        return
                    later_ns = (admission["monotonic_ns"]
                                + MIN_CONTINUOUS_INTERVAL_MINUTES * 60
                                * 1_000_000_000 + 1)
                    if manual_second_admit:
                        manual_witness = (
                            admission["policy_sha256"],
                            admission["publish_every_cycles"],
                            admission["boot_id"], later_ns,
                        )
                        with mock.patch.object(WORKER.time, "monotonic_ns",
                                               return_value=later_ns):
                            manual_result = commit_qualified_prod_local(
                                self.store, http_root=self.root, project=project,
                                publication=self.publication,
                                template_path=root_template,
                                manual_admission=manual_witness,
                            )
                        self.assertIsInstance(manual_result, CommittedProdWorkbook)
                        with tracker_writer(project, self.publication) as token:
                            manual_event = read_auto_local_admission(
                                token, self.store, self.snapshot.workbook_sha256)
                        self.assertEqual("manual", manual_event["lane"])
                        self.assertEqual(second_cycle["cycle_id"],
                                         manual_event["cycle_id"])
                        self.assertEqual(manual_result.receipt.generation_id,
                                         manual_event["generation_id"])
                        self.assertEqual(2, len(tuple(
                            (project / ".tracker/admissions").iterdir())))
                        self.assertEqual(len(before_generations) + 2,
                                         len(tuple(generation_root.iterdir())))
                        with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                              mock.patch.object(WORKER, "STATUS_DIR",
                                                stage_status_path.parent),
                              mock.patch.object(WORKER,
                                                "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                                stage_status_path),
                              mock.patch.object(WORKER, "_current_boot_identity",
                                                return_value=admission["boot_id"]),
                              mock.patch.object(WORKER.time, "monotonic_ns",
                                                return_value=later_ns)):
                            self.assertIsNone(
                                WORKER._publish_stage_l_local_after_completion(
                                    self.store))
                        held_status = json.loads(stage_status_path.read_bytes())
                        self.assertEqual("not_due", held_status.get("local"),
                                         held_status)
                        self.assertEqual(len(before_generations) + 2,
                                         len(tuple(generation_root.iterdir())))
                        return
                    with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                          mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                          mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                            stage_status_path),
                          mock.patch.object(WORKER, "_current_boot_identity",
                                            return_value=admission["boot_id"]),
                          mock.patch.object(WORKER.time, "monotonic_ns",
                                            return_value=later_ns)):
                        second_result = WORKER._publish_stage_l_local_after_completion(
                            self.store)
                    self.assertIsInstance(second_result, CommittedProdWorkbook)
                    self.assertNotEqual(result.receipt.generation_id,
                                        second_result.receipt.generation_id)
                    self.assertEqual("local_applied", json.loads(
                        stage_status_path.read_bytes())["state"])
                    second_admissions = tuple(sorted(
                        (project / ".tracker/admissions").iterdir()))
                    self.assertEqual(2, len(second_admissions))
                    self.assertEqual(len(before_generations) + 2,
                                     len(tuple(generation_root.iterdir())))
                    with tracker_writer(project, self.publication) as token:
                        latest_admission = read_auto_local_admission(
                            token, self.store, self.snapshot.workbook_sha256)
                    self.assertEqual(second_cycle["cycle_id"],
                                     latest_admission["cycle_id"])
                    self.assertEqual(second_result.receipt.generation_id,
                                     latest_admission["generation_id"])
                    tampered = json.loads(second_admissions[1].read_bytes())
                    tampered["monotonic_ns"] = admission["monotonic_ns"] + 1
                    second_admissions[1].write_bytes(
                        json.dumps(tampered, sort_keys=True,
                                   separators=(",", ":")).encode() + b"\n"
                    )
                    with tracker_writer(project, self.publication) as token:
                        with self.assertRaises(StageLHold):
                            read_auto_local_admission(
                                token, self.store,
                                self.snapshot.workbook_sha256,
                            )
                    return
                # A new boot has no proved elapsed interval from this event.
                # It must remain a visible HOLD, not infer the time floor from
                # completed-cycle count or replay the first C6 image.
                with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                      mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                      mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                        stage_status_path),
                      mock.patch.object(WORKER, "_current_boot_identity",
                                        return_value="fixture-new-boot")):
                    self.assertIsNone(
                        WORKER._publish_stage_l_local_after_completion(self.store)
                    )
                self.assertEqual("hold", json.loads(
                    stage_status_path.read_bytes())["state"])
                self.assertEqual(len(before_generations) + 1,
                                 len(tuple(generation_root.iterdir())))
                admission_files[0].write_bytes(b"{}\n")
                with tracker_writer(project, self.publication) as token:
                    with self.assertRaises(StageLHold):
                        read_auto_local_admission(
                            token, self.store, self.snapshot.workbook_sha256,
                        )
                return

            def drift_after_bound_read(path, snapshot):
                source_bytes = _read_bound_source(path, snapshot)
                self.template.write_bytes(fake_workbook(
                    whitelist_rules=("leaf-z",), reserved_switch_rows=4,
                ))
                return source_bytes

            try:
                with tracker_writer(project, self.publication) as token, \
                     mock.patch(
                         "monitor.issue_tracker_local_workbook_commit._read_bound_source",
                         side_effect=drift_after_bound_read,
                     ):
                    with self.assertRaisesRegex(
                        LocalCommitHold,
                        "C-6 workbook source changed before generation",
                    ):
                        commit_prod_stage_l_workbook(
                            token, qualified, self.store,
                            template_path=self.template, metadata=metadata,
                            expected_template_sha256=self.snapshot.workbook_sha256,
                            **args,
                        )
            finally:
                self.template.write_bytes(original_template)
            self.assertEqual(before_generations,
                             tuple(sorted(generation_root.iterdir())))
            (project / "01-global.yaml").write_text(
                "schema_version: 2\ncommon:\n  mgmt:\n"
                "    issue-tracker:\n" + ("      status: enabled\n      spreadsheet_id: synthetic_spreadsheet_id_0001\n"
                    if receipted_intent_probe or native_current_no_send_probe else "      status: disabled\n")
                + ("      publish_every_cycles: 3\n"
                   if manual_after_manual else ""),
                encoding="utf-8",
            )
            interval, policy_sha = local_publish_interval(project)
            manual_witness = (policy_sha, interval, "fixture-boot",
                              time.monotonic_ns())
            with tracker_writer(project, self.publication) as token:
                if terminal_orphan_probe:
                    with (mock.patch("monitor.issue_tracker_admission._mkdir",
                                     side_effect=OSError(
                                         "injected post-receipt admission failure")),
                          self.assertRaisesRegex(
                              OSError, "injected post-receipt admission failure")):
                        commit_prod_stage_l_workbook(
                            token, qualified, self.store, template_path=self.template,
                            metadata=metadata,
                            expected_template_sha256=self.snapshot.workbook_sha256,
                            manual_admission=manual_witness,
                            **args,
                        )
                else:
                    committed = commit_prod_stage_l_workbook(
                        token, qualified, self.store, template_path=self.template,
                        metadata=metadata,
                        expected_template_sha256=self.snapshot.workbook_sha256,
                        manual_admission=manual_witness,
                        **args,
                    )
            if terminal_orphan_probe:
                self.assertEqual(len(before_generations) + 1,
                                 len(tuple(generation_root.iterdir())))
                self.assertTrue(any((generation / "RECEIPT").is_file()
                                    for generation in generation_root.iterdir()))
                self.assertFalse((project / ".tracker/admissions").exists())
                root_template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
                root_template.parent.mkdir(parents=True, exist_ok=True)
                root_template.write_bytes(self.template.read_bytes())
                stage_status_path = (
                    self.root / "monitor/status/issue-tracker-stage-l.status.json"
                )
                with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                      mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                      mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                        stage_status_path),
                      mock.patch.object(WORKER, "_current_boot_identity",
                                        return_value="fixture-boot")):
                    self.assertIsNone(
                        WORKER._publish_stage_l_local_after_completion(self.store)
                    )
                terminal_status = json.loads(stage_status_path.read_bytes())
                self.assertEqual("hold", terminal_status["state"])
                self.assertEqual("local_c6_terminal_admission_state",
                                 terminal_status["reason"])
                self.assertEqual("C6 RECEIPT has no admission evidence",
                                 terminal_status["terminal_detail"])
                self.assertEqual("disabled_no_send_authority",
                                 terminal_status["online"])
                self.assertEqual(len(before_generations) + 1,
                                 len(tuple(generation_root.iterdir())))
                return
            self.assertIsInstance(committed, CommittedProdWorkbook)
            self.assertEqual(digest, committed.receipt.manifest_id)
            self.assertEqual(hashlib.sha256(committed.prepared.xlsx_bytes).hexdigest(),
                             committed.receipt.published_sha256)
            if native_current_no_send_probe:
                if native_current_no_send_probe in ('native-receipt-locators','native-receipt-locators-rebind','native-receipt-locators-late-rebind'):
                    from test_cases.test_req7_remote_history_match import load as load_remote
                    remote=load_remote()
                    from monitor import issue_tracker_local_commit as local,issue_tracker_receipt_snapshot as receipts
                    from monitor import issue_tracker_send_unit as compiler
                    project=Path(self.store.project_identity)
                    before={str(path):(path.stat().st_ino,path.read_bytes())
                        for path in (project/'.tracker').rglob('*') if path.is_file()}
                    receipt=project/'.tracker/generations'/committed.receipt.generation_id/'RECEIPT'
                    preserved=self.root/'owned-locator-original-receipt'
                    original=(receipt.stat().st_ino,receipt.read_bytes())
                    real_identity=compiler._original_receipt_identity;real_history=receipts._hold_history_originals
                    faults=[];target_holds=[];returned=[];yielded=[]
                    def rebind():
                        receipt.rename(preserved);receipt.write_bytes(original[1]);receipt.chmod(0o600)
                        faults.append((preserved.stat().st_ino==original[0],receipt.stat().st_ino!=original[0]))
                    def identity(*args,**kwargs):
                        actual=real_identity(*args,**kwargs)
                        if native_current_no_send_probe=='native-receipt-locators-rebind' and not faults:
                            rebind()
                        return actual
                    @contextmanager
                    def history(*args,**kwargs):
                        with real_history(*args,**kwargs) as verify:
                            def actual():
                                try:verify()
                                except Exception:
                                    if faults:target_holds.append((preserved.stat().st_ino==original[0],
                                        receipt.read_bytes()==original[1],receipt.stat().st_ino!=original[0]))
                                    raise
                            yield actual
                    with local.writer_owner(project,self.publication) as writer:
                        with mock.patch.object(compiler,'_original_receipt_identity',side_effect=identity), \
                                mock.patch.object(receipts,'_hold_history_originals',side_effect=history):
                            if native_current_no_send_probe=='native-receipt-locators-late-rebind':
                                with self.assertRaises(remote.RemoteHistoryHold):
                                    with remote._hold_current_cycle_native_receipt_locators(
                                            writer,_store=self.store,http_root=self.root) as locators:
                                        yielded.append(locators);rebind()
                                    returned.append(locators)
                            elif native_current_no_send_probe=='native-receipt-locators-rebind':
                                with self.assertRaises(remote.RemoteHistoryHold):
                                    returned.append(remote._read_current_cycle_native_receipt_locators(
                                        writer,_store=self.store,http_root=self.root))
                            else:returned.append(remote._read_current_cycle_native_receipt_locators(
                                writer,_store=self.store,http_root=self.root))
                    if native_current_no_send_probe!='native-receipt-locators':
                        if native_current_no_send_probe=='native-receipt-locators-late-rebind':
                            self.assertEqual([((committed.receipt.generation_id,committed.receipt.published_sha256),)],yielded)
                        self.assertEqual([(True,True)],faults)
                        self.assertTrue(target_holds,'the real held history guard must reject, not an unrelated outer cleanup')
                        self.assertTrue(all(item==(True,True,True) for item in target_holds))
                        self.assertEqual([],returned)
                        self.assertEqual(original,(preserved.stat().st_ino,preserved.read_bytes()))
                        self.assertEqual(original[1],receipt.read_bytes())
                        return
                    self.assertEqual([((committed.receipt.generation_id,committed.receipt.published_sha256),)],returned)
                    after={str(path):(path.stat().st_ino,path.read_bytes())
                        for path in (project/'.tracker').rglob('*') if path.is_file()}
                    self.assertEqual(before,after,'locator discovery cannot create native NV/catalog/count or change C6/K')
                    return
                if native_current_no_send_probe in ('cabling','cabling-tail-revoke','cabling-inactive','cabling-wire','cabling-nv','cabling-nv-other-drift','cabling-nv-tail-revoke','cabling-nv-tail-clear','fixed-cabling-creator','fixed-cabling-creator-wire','fixed-cabling-creator-initial-revoke','fixed-cabling-creator-nv','fixed-cabling-creator-nv-initial-revoke','fixed-cabling-creator-nv-missing','fixed-cabling-creator-nv-selection-revoke'):
                    for target_sheet in ('ETH Cabling','IB Cabling'):
                        self._verify_fresh_native_switch_no_send(committed,qualified,_sheet=target_sheet,
                            tail_revoke=native_current_no_send_probe in ('cabling-tail-revoke','cabling-nv-tail-revoke','cabling-nv-tail-clear'),
                            _inactive=('closed' if target_sheet=='ETH Cabling' else 'missing')
                                if native_current_no_send_probe=='cabling-inactive' else 'missing'
                                if native_current_no_send_probe=='fixed-cabling-creator-nv-missing' else None,
                            _wire=native_current_no_send_probe in ('cabling-wire','fixed-cabling-creator-wire'),
                            _nv=native_current_no_send_probe in ('cabling-nv','cabling-nv-other-drift','cabling-nv-tail-revoke','cabling-nv-tail-clear','fixed-cabling-creator-nv','fixed-cabling-creator-nv-initial-revoke','fixed-cabling-creator-nv-missing','fixed-cabling-creator-nv-selection-revoke'),
                            _other_drift=native_current_no_send_probe=='cabling-nv-other-drift',
                            _tail_clear=native_current_no_send_probe=='cabling-nv-tail-clear',
                            _fixed_creation=native_current_no_send_probe in ('fixed-cabling-creator','fixed-cabling-creator-wire','fixed-cabling-creator-initial-revoke','fixed-cabling-creator-nv','fixed-cabling-creator-nv-initial-revoke','fixed-cabling-creator-nv-missing','fixed-cabling-creator-nv-selection-revoke'),
                            _initial_revoke=native_current_no_send_probe in ('fixed-cabling-creator-initial-revoke','fixed-cabling-creator-nv-initial-revoke'),
                            _selection_revoke=native_current_no_send_probe=='fixed-cabling-creator-nv-selection-revoke')
                else:self._verify_fresh_native_switch_no_send(committed,qualified,
                    tail_revoke=native_current_no_send_probe=='tail-revoke',
                    _wire=native_current_no_send_probe=='fixed-switch-creator-wire',
                    _fixed_creation=native_current_no_send_probe in ('fixed-switch-creator','fixed-switch-creator-wire','fixed-switch-creator-initial-revoke'),
                    _initial_revoke=native_current_no_send_probe=='fixed-switch-creator-initial-revoke')
                return
            if observed_cabling_insert_probe:
                import tempfile
                import monitor.issue_tracker_send_unit as compiler
                from monitor.issue_tracker_sheets_read_plan import prepare_activity_sheet_read, prepare_insertion_sheet_read, prepare_sheets_read, prepare_history_tail_read, prepare_template_identity_read
                from monitor.issue_tracker_sheets_read_decode import decode_template_identity
                from monitor.issue_tracker_online_target import OnlineTargetBinding
                from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
                from test_cases.test_req7_activity_discovery import sheet_document, insertion_document, exact_row_document, cabling_row, literal
                from test_cases.test_req7_sheets_read_decode import identity_response, response
                from test_cases.test_req7_spreadsheet_owner import load as load_owner, scoped_fixture
                from test_cases.test_req7_enrollment_journal import load as load_enrollment
                from test_cases.test_req7_nv_reservation import load as load_nv
                self.assertTrue(hasattr(compiler, 'freeze_observed_receipted_cabling_unit'), 'Cabling compiler must bind original source/receipt and durable IDs')
                binding = OnlineTargetBinding('synthetic_spreadsheet_id_0001', 'a'*64, 'b'*64)
                if receipted_intent_probe:
                    from monitor import issue_tracker_credential_shape as private_inputs, issue_tracker_online_target as current_target
                    from tools.project_contract import safe_load_global_yaml
                    allowlist_bytes = b'["synthetic_spreadsheet_id_0001"]\n'
                    binding = current_target.bind_online_target(safe_load_global_yaml((project/'01-global.yaml').read_text()),
                        current_target.freeze_target_allowlist(allowlist_bytes))
                for sheet, family, sid, other_sheet, other_sid in (('ETH Cabling', 'eth_cabling', 102, 'IB Cabling', 103),
                                                                  ('IB Cabling', 'ib_cabling', 103, 'ETH Cabling', 102)):
                    if before_cabling_fixture is not None: before_cabling_fixture(sheet)
                    # Each sheet below owns a separate native fixture/lock
                    # period. Acquire its synthetic credential/read plans here,
                    # never extend or ignore an earlier period's token expiry.
                    credential = AuthenticatedToken('synthetic.private-token', time.time()+3600)
                    identity = decode_template_identity(prepare_template_identity_read(binding, credential), response(identity_response()))
                    history_plan = prepare_history_tail_read(binding, credential)
                    history_raw = response({'spreadsheetId': binding.spreadsheet_id, 'sheets': [{'properties': {'sheetId': 105,
                        'title': 'Update_History', 'sheetType': 'GRID', 'gridProperties': {'rowCount': 100, 'columnCount': 5}},
                        'data': [{'startRow': 2, 'startColumn': 0}]}]})
                    candidates = tuple(item for item in qualified.candidates if item.activity_key[0] == family)
                    self.assertGreater(len(candidates), 1)
                    row = cabling_row('NV30016'); key = candidates[0].activity_key
                    row.update({column: literal(value) for column, value in zip(('K', 'L', 'F'), key[1:])})
                    closed = cabling_row('NV30017', 'Closed'); key = candidates[-1].activity_key
                    closed.update({column: literal(value) for column, value in zip(('K', 'L', 'F'), key[1:])})
                    rows = [row, closed, {'V': {'boolValue': False}}]
                    if nonallocating_cabling_catalog_probe:
                        rows = []
                        for index, candidate in enumerate(candidates):
                            active = cabling_row('NV%05d' % (30016 + index))
                            active.update({column: literal(value) for column, value in zip(('K', 'L', 'F'), candidate.activity_key[1:])})
                            rows.append(active)
                    discovery = sheet_document(sheet, rows, 100); discovery['sheets'][0]['properties']['sheetId'] = sid
                    occupancy = insertion_document(sheet, rows, 100); occupancy['sheets'][0]['properties']['sheetId'] = sid
                    other = cabling_row('NV39999', 'Closed'); other['K'] = literal('unrelated-original-seed')
                    other_raw = sheet_document(other_sheet, [other], 100); other_raw['sheets'][0]['properties']['sheetId'] = other_sid
                    try:
                        discovery_plan = prepare_activity_sheet_read(binding, credential, sheet=sheet)
                        occupancy_plan = prepare_insertion_sheet_read(binding, credential, sheet=sheet)
                        other_plan = prepare_activity_sheet_read(binding, credential, sheet=other_sheet)
                    except Exception as exc:
                        # Safe phase facts only; no credential/header/body/ID.
                        print('CABLING_FIXTURE_PLAN_ERROR',sheet,type(exc).__name__,{
                            'binding_class_current':type(binding) is sys.modules['monitor.issue_tracker_online_target'].OnlineTargetBinding,
                            'token_class_current':type(credential) is sys.modules['monitor.issue_tracker_sdk_authentication'].AuthenticatedToken,
                            'expires_in_seconds':credential.expires_at-time.time()},flush=True)
                        raise
                    original_read = response(discovery); other_read = response(other_raw)
                    reads = []
                    for offset, candidate in enumerate(candidates):
                        row_index = offset + 2 if nonallocating_cabling_catalog_probe else 2
                        exact = exact_row_document(sheet, rows[offset] if nonallocating_cabling_catalog_probe else rows[0], row_index)
                        exact['sheets'][0]['properties']['sheetId'] = sid
                        reads.append({'operation_id': candidate.operation_id, 'discovery_plan': discovery_plan,
                            'discovery_response': original_read, 'occupancy_plan': occupancy_plan, 'occupancy_response': response(occupancy),
                            'row_plan': prepare_sheets_read(binding, credential, mode='row_rectangle', sheet=sheet, first_row=row_index+1) if offset == 0 or nonallocating_cabling_catalog_probe else None,
                            'row_response': response(exact) if offset == 0 or nonallocating_cabling_catalog_probe else None})
                    requested = tuple(item.activity_key for item in candidates[1:])
                    expected = tuple((key, 'NV%05d' % (40000+index)) for index, key in enumerate(sorted(requested)))
                    with tempfile.TemporaryDirectory(prefix='req7-real-cabling-unit-') as directory:
                        global_root = Path(directory).resolve(); state = global_root/'var/lib/http-ztp-container/issue-tracker'
                        state.mkdir(parents=True, mode=0o700); owner_module = load_owner(); enrollment_module = load_enrollment(); nv_module = load_nv()
                        from contextlib import ExitStack
                        with ExitStack() as fixture_owners, ExitStack() as private_context, ExitStack() as native_count_context:
                            writer_token=fixture_owners.enter_context(tracker_writer(project,self.publication))
                            fixture_owners.enter_context(scoped_fixture(global_root,owner_module))
                            spreadsheet_token=fixture_owners.enter_context(owner_module.spreadsheet_owner(binding))
                            if receipted_intent_probe:
                                private_directory = global_root/'var/lib/http-ztp-container/service-account'
                                private_directory.mkdir(mode=0o700)
                                private_allowlist = private_directory/'issue-tracker-spreadsheet-whitelist.json'
                                private_allowlist.write_bytes(allowlist_bytes); private_allowlist.chmod(0o600)
                                private_context.enter_context(scoped_fixture(global_root, private_inputs))
                                private_context.enter_context(scoped_fixture(global_root, current_target))
                            original = enrollment_module.prepare_enrollment_journal(spreadsheet_token, binding, identity)
                            if nonallocating_cabling_catalog_probe:
                                from test_cases.test_req7_global_attempt_journal import load as load_global
                                from test_cases.test_req7_unit_catalog import load as load_catalog
                                load_global(); nv_module = load_nv(); catalog = load_catalog(reset_dependencies=False)
                                self.assertIs(nv_module.ownership, owner_module)
                                self.assertIs(catalog.ownership, owner_module)
                                stem = hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()
                                baseline = {path.name for path in state.iterdir()}
                                with self._assertion_preserving_preparation(nv_module.hold_catalog_nonallocating_preparation(
                                        writer_token, spreadsheet_token, binding, identity,
                                        generation_id=committed.receipt.generation_id,
                                        publish_id=committed.receipt.published_sha256, sheet=sheet)) as prepared:
                                    def compile_updates(**changes):
                                        options = dict(local_generation_id=committed.receipt.generation_id, sheet=sheet,
                                            business_reads=tuple(reads), history_plan=history_plan, history_response=history_raw,
                                            spreadsheet_token=spreadsheet_token, binding=binding, identity=identity,
                                            _unit_preparation=prepared)
                                        options.update(changes)
                                        return compiler.freeze_observed_receipted_cabling_unit(qualified, self.store,
                                            metadata=metadata, expected_template_sha256=self.snapshot.workbook_sha256,
                                            writer_token=writer_token, **args, **options)
                                    unit = compile_updates(); body = json.loads(unit.action_preimage)
                                    self.assertEqual(['update'] * len(candidates), [item['action'] for item in body['business']])
                                    self.assertEqual(committed.receipt.generation_id, body['identity']['generation_id'])
                                    self.assertEqual(committed.receipt.published_sha256, body['identity']['publish_id'])
                                    self.assertEqual(len(candidates), unit.history_rows_expected)
                                    requests = json.loads(unit.wire_bytes)['requests']
                                    self.assertFalse(any('appendCells' in item and item['appendCells']['sheetId'] == sid for item in requests))
                                    updates = [item['updateCells'] for item in requests if 'updateCells' in item]
                                    self.assertEqual(set(range(2, 2 + len(candidates))), {item['start']['rowIndex'] for item in updates})
                                    self.assertTrue(all(item['start']['sheetId'] == sid and item['start']['columnIndex'] != 0 for item in updates))
                                    independent = {'schema_version': 1, 'spreadsheet_id': binding.spreadsheet_id, 'sheet': sheet,
                                        'sheet_id': sid, 'history_sheet_id': 105, 'history_path': history_plan.path,
                                        'history_sha256': hashlib.sha256(history_raw.data).hexdigest(), 'nv_journal_sha256': None,
                                        'business': [{'operation_id': candidate.operation_id, 'discovery_path': discovery_plan.path,
                                            'discovery_sha256': hashlib.sha256(original_read.data).hexdigest(), 'occupancy_path': occupancy_plan.path,
                                            'occupancy_sha256': hashlib.sha256(reads[index]['occupancy_response'].data).hexdigest(),
                                            'row_path': reads[index]['row_plan'].path,
                                            'row_sha256': hashlib.sha256(reads[index]['row_response'].data).hexdigest(), 'append_start_row_index': None}
                                            for index, candidate in enumerate(candidates)]}
                                    self.assertEqual(hashlib.sha256((json.dumps(independent, ensure_ascii=False, sort_keys=True,
                                        separators=(',', ':')) + '\n').encode()).hexdigest(), body['preread_sha256'])
                                    self.assertEqual(baseline, {path.name for path in state.iterdir()})
                                    with self.assertRaises(compiler.SendUnitHold): compile_updates(_nv_preparation=prepared)
                                    catalog.register_pending_c6_unit(writer_token, spreadsheet_token, binding, unit, _unit_preparation=prepared)
                                    with catalog.hold_pending_project_c6_units(spreadsheet_token, binding) as (units, verify):
                                        self.assertEqual((unit,), tuple(item.unit for item in units)); verify()
                                    with self.assertRaises(compiler.SendUnitHold): compile_updates()
                                self.assertFalse(nv_module._ACTIVE_CATALOG_PREPARATIONS)
                                self.assertFalse(catalog._IMAGE_BUDGETS)
                                names = {path.name for path in state.iterdir()}
                                self.assertFalse(any(name.endswith('.nv') or name.endswith('.nv-started') or '.journal' in name for name in names))
                                folder = state / (stem + '.units') / unit.unit_id
                                self.assertNotIn('nv_original', json.loads((folder / 'HEADER').read_bytes()))
                                self.assertEqual(unit.wire_bytes, (folder / 'WIRE').read_bytes())
                                continue
                            nv_args = dict(generation_id=committed.receipt.generation_id, publish_id=committed.receipt.published_sha256,
                                sheet=sheet, requested_keys=requested)
                            pair = (discovery_plan, original_read, other_plan, other_read) if sheet == 'ETH Cabling' else (other_plan, other_read, discovery_plan, original_read)
                            prepared = None
                            if native_catalog_probe:
                                from test_cases.test_req7_global_attempt_journal import load as load_global
                                load_global(); nv_module = load_nv()
                                from test_cases.test_req7_unit_catalog import load as load_catalog
                                catalog = load_catalog(reset_dependencies=False)
                                self.assertIs(catalog.ownership, owner_module, 'native catalog must use this actual fixture owner registry')
                                if native_catalog_creator_first_stat_probe is not None:
                                    from test_cases.test_req7_nv_reservation import native_creator_first_stat_fault
                                    with native_creator_first_stat_fault(nv_module, global_root) as (created, marks, _foreign, real_fstat):
                                        with self.assertRaises(nv_module.NvReservationHold):
                                            with nv_module.hold_catalog_nv_preparation(spreadsheet_token, binding, identity, *pair, **nv_args):
                                                self.fail('actual protected C6 fault reached compiler handoff')
                                        self.assertEqual(['actual-first-stat-fault'], marks)
                                        self.assertEqual(1, len(created))
                                        with self.assertRaises(OSError, msg='actual protected C6 NV creator leaked owned FD'):
                                            real_fstat(created[0][0])
                                        self.assertFalse(any(path.name.endswith('.units') or path.name.endswith('.project-origin')
                                            or '.journal' in path.name for path in state.iterdir()))
                                        self.assertEqual(1, len(tuple(state.glob('*.nv-started'))))
                                        native_catalog_creator_first_stat_probe.append(sheet + ':actual-first-stat-fault:owned-fd-closed')
                                    continue
                                preparation_context = (native_count_context if native_catalog_receipted_count_probe is not None or native_catalog_launch_probe is not None else private_context)
                                prepared = preparation_context.enter_context(nv_module.hold_catalog_nv_preparation(
                                    spreadsheet_token, binding, identity, *pair, **nv_args))
                                reservation = prepared.observation
                            else:
                                reservation = nv_module.prepare_nv_reservation(spreadsheet_token, binding, identity, *pair, **nv_args)
                            self.assertEqual(expected, reservation.reservations)
                            def compile_cabling(**changes):
                                options = dict(local_generation_id=committed.receipt.generation_id, sheet=sheet, business_reads=tuple(reads),
                                    history_plan=history_plan, history_response=history_raw, spreadsheet_token=spreadsheet_token, binding=binding, identity=identity)
                                if prepared is not None: options['_nv_preparation'] = prepared
                                if settings_audit_probe and sheet == 'ETH Cabling':
                                    from monitor.issue_tracker_settings_audit_allocation import pending_settings_audits
                                    options['audits'] = pending_settings_audits(writer_token)
                                    self.assertTrue(options['audits'])
                                options.update(changes)
                                return compiler.freeze_observed_receipted_cabling_unit(qualified, self.store, metadata=metadata,
                                    expected_template_sha256=self.snapshot.workbook_sha256, writer_token=writer_token, **args, **options)
                            nv_suffix = '.nv' if prepared is None else '.unit-' + reservation.unit_id + '.nv'
                            before = {path.name: path.read_bytes() for path in (state/(hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()+nv_suffix)).iterdir()}
                            if native_catalog_return_fault is not None:
                                mode, marks = native_catalog_return_fault
                                original_freeze = compiler.freeze_receipted_prod_source_unit
                                original_receipt = compiler._original_receipt_identity
                                compiled_stage = []
                                raw_path = state/(hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()+nv_suffix)/'ETH-RAW'
                                def retain_real_frozen_unit(*arguments, **keywords):
                                    result = original_freeze(*arguments, **keywords)
                                    compiled_stage.append(True)
                                    return result
                                def drift_after_real_final_receipt(*arguments, **keywords):
                                    result = original_receipt(*arguments, **keywords)
                                    if compiled_stage and not marks:
                                        raw, old_stat = raw_path.read_bytes(), raw_path.stat()
                                        if mode == 'same_byte_replace':
                                            replacement = raw_path.with_name('owned-fault-replacement')
                                            replacement.write_bytes(raw); replacement.chmod(0o600)
                                            os.replace(replacement, raw_path)
                                            self.assertNotEqual(old_stat.st_ino, raw_path.stat().st_ino)
                                        else:
                                            raw_path.write_bytes(raw)
                                            os.utime(raw_path, ns=(old_stat.st_atime_ns, old_stat.st_mtime_ns+1000000))
                                            self.assertEqual(old_stat.st_ino, raw_path.stat().st_ino)
                                        marks.append(('injected', mode))
                                    return result
                                with mock.patch.object(compiler, 'freeze_receipted_prod_source_unit', side_effect=retain_real_frozen_unit), \
                                     mock.patch.object(compiler, '_original_receipt_identity', side_effect=drift_after_real_final_receipt):
                                    try: compile_cabling()
                                    except compiler.SendUnitHold: marks.append(('compiler', 'HOLD'))
                                    else: marks.append(('compiler', 'RETURNED'))
                                marks.append(('catalog_written', any(path.name.endswith('.units') for path in state.iterdir())))
                                raise RuntimeError('owned native compiler fault fixture complete; preserve original HOLD')
                            if native_catalog_probe:
                                try: unit = compile_cabling()
                                except compiler.SendUnitHold:
                                    print('NATIVE_C6_COMPILE_REJECTED_BEFORE_HANDOFF', sheet, flush=True)
                                    raise
                            else:
                                unit = compile_cabling()
                            action = json.loads(unit.action_preimage)
                            self.assertEqual(['update']+['insert']*(len(candidates)-1), [item['action'] for item in action['business']])
                            self.assertEqual(committed.receipt.generation_id, action['identity']['generation_id'])
                            self.assertEqual(committed.receipt.published_sha256, action['identity']['publish_id'])
                            nonces = {title: nonce for title, _sid, nonce in original.nonces}
                            self.assertEqual(nonces[sheet], action['target_nonce']); self.assertEqual(nonces['Update_History'], action['history_nonce'])
                            independent_read_image = {'schema_version': 1, 'spreadsheet_id': binding.spreadsheet_id, 'sheet': sheet,
                                'sheet_id': sid, 'history_sheet_id': 105, 'history_path': history_plan.path,
                                'history_sha256': hashlib.sha256(history_raw.data).hexdigest(), 'nv_journal_sha256': reservation.journal_sha256,
                                'business': [{'operation_id': candidate.operation_id, 'discovery_path': discovery_plan.path,
                                    'discovery_sha256': hashlib.sha256(original_read.data).hexdigest(), 'occupancy_path': occupancy_plan.path,
                                    'occupancy_sha256': hashlib.sha256(reads[index]['occupancy_response'].data).hexdigest(),
                                    'row_path': reads[index]['row_plan'].path if index == 0 else None,
                                    'row_sha256': hashlib.sha256(reads[index]['row_response'].data).hexdigest() if index == 0 else None,
                                    'append_start_row_index': None if index == 0 else 5}
                                    for index, candidate in enumerate(candidates)]}
                            self.assertEqual(hashlib.sha256((json.dumps(independent_read_image, ensure_ascii=False, sort_keys=True,
                                separators=(',', ':'))+'\n').encode()).hexdigest(), action['preread_sha256'])
                            requests = json.loads(unit.wire_bytes)['requests']
                            appends = [item['appendCells'] for item in requests if 'appendCells' in item and item['appendCells']['sheetId'] == sid]
                            self.assertEqual(len(candidates)-1, len(appends))
                            self.assertEqual([dict(expected)[item.activity_key] for item in candidates[1:]],
                                [item['rows'][0]['values'][0]['userEnteredValue']['stringValue'] for item in appends])
                            for item in appends:
                                self.assertEqual({'sheetId', 'rows', 'fields'}, set(item))
                                for index in (7, 8, 9, 14, 15): self.assertEqual({}, item['rows'][0]['values'][index])
                            for item in requests:
                                if 'updateCells' in item:
                                    self.assertEqual(2, item['updateCells']['start']['rowIndex']); self.assertNotEqual(0, item['updateCells']['start']['columnIndex'])
                            if prepared is not None:
                                self.assertEqual(reservation, nv_module._catalog_nv_compiled_observation(prepared, spreadsheet_token, binding, unit))
                                for changes in ({'_nv_preparation': replace(prepared)}, {'reserved_ids': ('NV99999',)},
                                                {'placements': ()}, {'target_nonce': 'c'*64}, {'business_reads': tuple(reads[:-1])}):
                                    with self.assertRaises(compiler.SendUnitHold): compile_cabling(**changes)
                                from monitor import issue_tracker_unit_catalog as catalog
                                if native_catalog_c6_origin_probe:
                                    actual_append = catalog.register_pending_unit; appended = []
                                    def append_once(*arguments, **keywords):
                                        appended.append(arguments[2].unit_id)
                                        return actual_append(*arguments, **keywords)
                                    with mock.patch.object(catalog, 'register_pending_unit', side_effect=append_once):
                                        catalog.register_pending_c6_unit(writer_token, spreadsheet_token, binding, unit,
                                            _nv_preparation=prepared)
                                    self.assertEqual([unit.unit_id], appended, 'one genuine C6 registration cannot double append')
                                    with catalog.hold_pending_project_c6_units(spreadsheet_token, binding) as (rows, verify_projects):
                                        self.assertEqual((unit,), tuple(row.unit for row in rows)); verify_projects()
                                else:
                                    nv_module.register_catalog_nv_unit(prepared, unit)
                                with catalog.hold_pending_c6_units(writer_token, spreadsheet_token, binding) as (units, verify_c6):
                                    self.assertEqual((unit,), units); verify_c6()
                                self.assertEqual(reservation, nv_module.require_unit_nv_reservation(spreadsheet_token, binding, identity, unit))
                                self.assertEqual(before, {path.name: path.read_bytes() for path in
                                    (state/(hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()+nv_suffix)).iterdir()})
                                origins = tuple(path for path in state.iterdir() if path.name.endswith('.project-origin'))
                                if native_catalog_c6_origin_probe:
                                    self.assertEqual(1, len(origins))
                                    self.assertEqual({'STARTED', 'ORIGIN', 'WITNESS'}, set(os.listdir(origins[0])))
                                else:
                                    self.assertFalse(origins, 'C6 original reader is not the separate project-origin writer')
                                if native_catalog_retained_probe:
                                    # Close the actual preparation before the genuine GLOBAL
                                    # writer adds its fixed journal; old namespace proof is
                                    # not silently refreshed to permit a foreign append.
                                    if native_catalog_receipted_count_probe is not None or native_catalog_launch_probe is not None:
                                        # Close only the completed native preparation. The
                                        # actual fixed credential/allowlist roots must stay
                                        # bound through protected source replay and count.
                                        native_count_context.close()
                                    else:
                                        private_context.close()
                                    from monitor import issue_tracker_global_attempt_journal as global_journal
                                    # This fixture creates canonical owner registries per
                                    # scenario. Bind the real consumer after that setup,
                                    # as the existing native inventory fixtures do; a
                                    # preimported prior scenario cannot own this token.
                                    from test_cases.test_req7_retained_global_inventory import load as inventory_load
                                    inventory = inventory_load(reset_support=False)
                                    global_journal.prepare_global_unit(spreadsheet_token, binding, unit)
                                    original_files = {str(path.relative_to(state)): (path.stat().st_ino, path.read_bytes())
                                        for path in state.rglob('*') if path.is_file()}
                                    with inventory._hold_catalog_retained_inventory(spreadsheet_token, binding) as (rows, verify):
                                        self.assertEqual((unit,), tuple(row.unit for row in rows))
                                        self.assertEqual((0,), tuple(row.attempt_count for row in rows))
                                        self.assertIn('nv-started', rows[0].families)
                                        self.assertTrue(any(name.endswith('.nv/PRIOR') for name, _stat, _sha in rows[0].originals))
                                        self.assertFalse(any(hasattr(rows[0], name) for name in ('permit', 'applied', 'fresh', 'new')))
                                        verify()
                                    if native_catalog_all_c6_fifo_probe is not None:
                                        with inventory._hold_all_project_applied_keys(spreadsheet_token, binding) as (rows, verify):
                                            self.assertEqual((unit,), tuple(row.unit for row in rows))
                                            self.assertEqual((0,), tuple(row.attempt_count for row in rows))
                                            self.assertEqual(((),), tuple(row.key_watermarks for row in rows))
                                            verify()
                                            native_catalog_all_c6_fifo_probe.append(sheet + ':actual-all-project-c6:no-applied')
                                        with inventory._hold_all_project_fifo_frontier(spreadsheet_token, binding) as (frontier, verify):
                                            self.assertEqual((unit.unit_id,), frontier.frontier)
                                            self.assertEqual((), frontier.blocked)
                                            self.assertEqual((), frontier.applied); self.assertEqual((), frontier.superseded)
                                            self.assertFalse(any(hasattr(frontier, name) for name in ('permit', 'fresh', 'new', 'writer_token')))
                                            verify()
                                            native_catalog_all_c6_fifo_probe.append(sheet + ':actual-fifo:read-only')
                                    self.assertEqual(original_files, {str(path.relative_to(state)): (path.stat().st_ino, path.read_bytes())
                                        for path in state.rglob('*') if path.is_file()})
                                if native_catalog_receipted_count_probe is not None or native_catalog_launch_probe is not None:
                                    from test_cases.test_req7_history_preread_journal import load as load_preread
                                    from test_cases.test_req7_metadata_reservation import load as load_quota
                                    from monitor.issue_tracker_metadata_capacity import prepare_metadata_capacity_read
                                    preread = load_preread(); quota_module = load_quota()
                                    preread.prepare_history_preread(spreadsheet_token, binding, unit, history_plan, history_raw)
                                    preread.prepare_business_preread(spreadsheet_token, binding, identity, unit,
                                        manifest=body, business_reads=tuple(reads))
                                    quota_raw = response({'matchedDeveloperMetadata': [
                                        {'developerMetadata': {'metadataId': index+1, 'metadataKey': 'http-ztp-enrollment-v1',
                                            'metadataValue': nonce, 'visibility': 'DOCUMENT',
                                            'location': {'locationType': 'SHEET', 'sheetId': sheet_id}}}
                                        for index, (_title, sheet_id, nonce) in enumerate(original.nonces)]})
                                    quota_module.prepare_metadata_reservation(spreadsheet_token, binding, identity, unit,
                                        prepare_metadata_capacity_read(binding, credential), quota_raw)
                                    frozen_images = {str(path.relative_to(state)): (path.stat().st_ino, path.read_bytes())
                                        for path in state.rglob('*') if path.is_file()}
                                    if native_catalog_launch_probe is not None:
                                        mode,observed = native_catalog_launch_probe[:2]
                                        self._exercise_native_original_counted_launch(mode='normal' if mode.startswith('complete-after-archive') else mode,observed=observed,
                                            global_root=global_root,private_context=private_context,
                                            writer_token=writer_token,spreadsheet_token=spreadsheet_token,
                                            binding=binding,credential=credential,unit=unit,identity=identity,
                                            quota_raw=quota_raw,history_raw=history_raw,reads=reads,sheet=sheet,
                                            qualified=qualified,settings=args['settings'],committed=committed,
                                            state=state,owner_module=owner_module,global_journal=global_journal,
                                            expected_audits=(native_catalog_launch_probe[2] if sheet=='ETH Cabling' else ())
                                                if len(native_catalog_launch_probe)==3 else None)
                                        if mode.startswith('complete-after-archive'):
                                            self._complete_original_audits_then_preview(mode=mode,observed=observed,
                                                global_root=global_root,private_context=private_context,
                                                native_count_context=native_count_context,fixture_owners=fixture_owners,
                                                writer_token=writer_token,spreadsheet_token=spreadsheet_token,
                                                binding=binding,credential=credential,unit=unit,state=state,
                                                owner_module=owner_module,global_journal=global_journal,committed=committed,
                                                expected_audits=native_catalog_launch_probe[2],quota_raw=quota_raw,history_raw=history_raw)
                                            return
                                        continue
                                    counted = global_journal.record_receipted_original_attempt_intent(
                                        spreadsheet_token, binding, identity, unit, qualified_source=qualified,
                                        store=self.store, writer_token=writer_token, settings=args['settings'],
                                        whitelist_snapshot=self.snapshot, expected_template_sha256=self.snapshot.workbook_sha256,
                                        http_root=self.root, whitelist_path=self.template)
                                    self.assertEqual((1, 'UNKNOWN'), (counted.attempt_count, counted.outcome))
                                    self.assertFalse(any(hasattr(counted, name) for name in ('permit', 'send_once', 'complete', 'applied')))
                                    self.assertEqual(expected, nv_module.require_unit_nv_reservation(
                                        spreadsheet_token, binding, identity, unit).reservations)
                                    after = {str(path.relative_to(state)): (path.stat().st_ino, path.read_bytes())
                                        for path in state.rglob('*') if path.is_file()}
                                    for name, image in frozen_images.items():
                                        if '.journal/' not in name:
                                            self.assertEqual(image, after[name], name)
                                    native_catalog_receipted_count_probe.append(sheet + ':actual-receipted-count:unknown')
                                continue
                            self.assertEqual(reservation, nv_module.require_unit_nv_reservation(spreadsheet_token, binding, identity, unit))
                            for claims in ({'reserved_ids': ('NV99999',)}, {'placements': ()}, {'target_nonce': 'c'*64}, {'business_reads': tuple(reads[:-1])}, {'sheet': 'ETH&IB Switch'}):
                                with self.assertRaises(compiler.SendUnitHold): compile_cabling(**claims)
                            saved = reads[-1]['discovery_response']; changed = json.loads(saved.data)
                            changed['sheets'][0]['data'][0]['rowData'][0]['values'][0] = {'userEnteredValue': literal('Closed')}
                            reads[-1]['discovery_response'] = response(changed)
                            try:
                                with self.assertRaises(compiler.SendUnitHold): compile_cabling()
                            finally: reads[-1]['discovery_response'] = saved
                            saved_occupancy = tuple(reading['occupancy_response'] for reading in reads)
                            full = json.loads(saved_occupancy[0].data)
                            for grid in full['sheets'][0]['data']:
                                if grid['startColumn'] == 21:
                                    grid['rowData'] = [{}, {}, {'values': [{'userEnteredValue': {'boolValue': False}}]}] + [{}]*94 + [
                                        {'values': [{'userEnteredValue': literal('operator at capacity boundary')}]}]
                            for reading in reads: reading['occupancy_response'] = response(full)
                            try:
                                with self.assertRaises(compiler.SendUnitHold): compile_cabling()
                            finally:
                                for reading, original_response in zip(reads, saved_occupancy): reading['occupancy_response'] = original_response
                            real_freeze = compiler.freeze_receipted_prod_source_unit
                            drift = json.loads(saved_occupancy[-1].data)
                            for grid in drift['sheets'][0]['data']:
                                if grid['startColumn'] == 21: grid['rowData'][2]['values'][0] = {'userEnteredValue': literal('changed during compile')}
                            def change_occupancy_during_freeze(*freeze_args, **freeze_kwargs):
                                result = real_freeze(*freeze_args, **freeze_kwargs)
                                reads[-1]['occupancy_response'] = response(drift)
                                return result
                            try:
                                with mock.patch.object(compiler, 'freeze_receipted_prod_source_unit', side_effect=change_occupancy_during_freeze):
                                    with self.assertRaises(compiler.SendUnitHold): compile_cabling()
                            finally: reads[-1]['occupancy_response'] = saved_occupancy[-1]
                            stem = hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()
                            ids_path = state/(stem+'.nv')/'RESERVATIONS'; saved_ids = ids_path.read_bytes()
                            ids_path.write_bytes(saved_ids.replace(b'NV40000', b'NV99999'))
                            try:
                                with self.assertRaises(compiler.SendUnitHold): compile_cabling()
                            finally: ids_path.write_bytes(saved_ids)
                            stem = hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()
                            if business_preread_probe:
                                from test_cases.test_req7_global_attempt_journal import load as load_global
                                from test_cases.test_req7_history_preread_journal import load as load_preread
                                # Mirror canonical imports after this fixture's
                                # owner reload; never relax real owner registries.
                                global_journal = load_global(); preread = load_preread()
                                self.assertIs(global_journal.ownership, owner_module)
                                self.assertIs(preread.ownership, owner_module)
                                self.assertTrue(hasattr(preread, 'prepare_business_preread'), 'original C5/C6 business images must survive cold/UNKNOWN')
                                global_journal.prepare_global_unit(spreadsheet_token, binding, unit)
                                preread.prepare_history_preread(spreadsheet_token, binding, unit, history_plan, history_raw)
                                preread.prepare_business_preread(spreadsheet_token, binding, identity, unit, manifest=body, business_reads=tuple(reads))
                                seen = preread.inspect_business_preread(spreadsheet_token, binding, identity, unit)
                                self.assertEqual((len(candidates), 0, action['preread_sha256']), (seen.operations_retained, seen.noop_operations, seen.preread_sha256))
                                retained = {path.name: path.read_bytes() for path in (state/(stem+'.business')).iterdir()}
                                if original_reserved_probe:
                                    from test_cases.test_req7_metadata_reservation import load as load_quota
                                    from monitor.issue_tracker_metadata_capacity import prepare_metadata_capacity_read
                                    quota_module = load_quota()
                                    quota_raw = response({'matchedDeveloperMetadata': [
                                        {'developerMetadata': {'metadataId': index+1, 'metadataKey': 'http-ztp-enrollment-v1',
                                            'metadataValue': nonce, 'visibility': 'DOCUMENT',
                                            'location': {'locationType': 'SHEET', 'sheetId': sheet_id}}}
                                        for index, (_title, sheet_id, nonce) in enumerate(original.nonces)]})
                                    quota = quota_module.prepare_metadata_reservation(spreadsheet_token, binding, identity, unit,
                                        prepare_metadata_capacity_read(binding, credential), quota_raw)
                                    self.assertTrue(hasattr(global_journal, 'record_original_business_reserved_attempt_intent'), 'complete original chain must dominate counted intent')
                                    record = lambda: global_journal.record_original_business_reserved_attempt_intent(spreadsheet_token, binding, identity, unit)
                                    if receipted_intent_probe:
                                        self.assertTrue(hasattr(global_journal, 'record_receipted_original_attempt_intent'), 'protected original C6 chain must dominate each counted intent')
                                        self.assertTrue(hasattr(preread, 'inspect_business_source_projection'), 'replayed C5 source values must bind ALL original wire and NOOP decisions')
                                        from monitor.issue_tracker_local_workbook_commit import _source_rows
                                        cabling_source, switch_source = _source_rows(qualified)
                                        source_rows = (*cabling_source, *switch_source)
                                        self.assertEqual(seen, preread.inspect_business_source_projection(spreadsheet_token, binding, identity, unit, source_rows))
                                        changed_rows = tuple(replace(row, evidence_description='caller invented original values') for row in source_rows)
                                        with self.assertRaises(preread.HistoryPrereadHold):
                                            preread.inspect_business_source_projection(spreadsheet_token, binding, identity, unit, changed_rows)
                                        self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                        def record(**changes):
                                            options = dict(qualified_source=qualified, store=self.store, writer_token=writer_token,
                                                settings=args['settings'], whitelist_snapshot=self.snapshot,
                                                expected_template_sha256=self.snapshot.workbook_sha256,
                                                http_root=self.root, whitelist_path=self.template)
                                            options.update(changes)
                                            return global_journal.record_receipted_original_attempt_intent(spreadsheet_token, binding, identity, unit, **options)
                                        if settings_audit_probe and sheet == 'ETH Cabling':
                                            from test_cases.test_req7_settings_audit_allocation import load as load_allocation
                                            allocation_module = load_allocation()
                                            self.assertTrue(action['audits'])
                                            # Existing coherent unit + C5/C6 + all reservations still
                                            # cannot count without ORIGINAL durable C25 assignments.
                                            with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                            self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                            allocation_module.prepare_settings_audit_allocation(writer_token, spreadsheet_token, binding, unit)
                                            allocation_path = project/'.tracker/settings-audit-allocation'
                                            allocation_image = {p.name: p.read_bytes() for p in allocation_path.iterdir()}
                                            assignments_path = allocation_path/'ASSIGNMENTS'
                                            assignments_path.write_bytes(b'foreign original allocation')
                                            try:
                                                with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                                self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                                self.assertEqual(b'foreign original allocation', assignments_path.read_bytes())
                                            finally: assignments_path.write_bytes(allocation_image['ASSIGNMENTS'])
                                        private_allowlist.write_bytes(b'[]\n')
                                        try:
                                            with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                            self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                            self.assertEqual(b'[]\n', private_allowlist.read_bytes())
                                        finally: private_allowlist.write_bytes(allowlist_bytes)
                                        for changes in ({'writer_token': None}, {'qualified_source': replace(qualified, observations_sha256='f'*64)},
                                                        {'expected_template_sha256': 'f'*64}):
                                            with self.assertRaises(global_journal.GlobalAttemptHold): record(**changes)
                                            self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                        generation_path = project/'.tracker/generations'/committed.receipt.generation_id
                                        c6_original = {name: (generation_path/name).read_bytes() for name in ('STATE', 'MANIFEST', 'INTENT', 'RECEIPT')}
                                        for name, raw in c6_original.items():
                                            path = generation_path/name; path.write_bytes(b'foreign C6 original')
                                            try:
                                                with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                                self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                                self.assertEqual(b'foreign C6 original', path.read_bytes())
                                            finally: path.write_bytes(raw)  # undo this owned fixture fault only
                                        source_path = artifacts['ethernet/prod']['info']
                                        source_before = source_path.read_bytes()
                                        source_path.write_bytes(source_before+b'\nchanged original producer source\n')
                                        try:
                                            with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                            self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                            self.assertEqual(source_before+b'\nchanged original producer source\n', source_path.read_bytes())
                                        finally: source_path.write_bytes(source_before)  # owned producer fault only
                                        actual_business_inspect = preread.inspect_business_preread
                                        def change_source_after_business(*inspect_args, **inspect_kwargs):
                                            result = actual_business_inspect(*inspect_args, **inspect_kwargs)
                                            source_path.write_bytes(source_before+b'\nchanged during original barrier\n')
                                            return result
                                        try:
                                            with mock.patch.object(preread, 'inspect_business_preread', side_effect=change_source_after_business):
                                                with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                            self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                            self.assertEqual(source_before+b'\nchanged during original barrier\n', source_path.read_bytes())
                                        finally: source_path.write_bytes(source_before)  # owned fixture only
                                        actual_source_projection = preread.inspect_business_source_projection
                                        def revoke_during_business(*inspect_args, **inspect_kwargs):
                                            result = actual_source_projection(*inspect_args, **inspect_kwargs)
                                            private_allowlist.write_bytes(b'[]\n'); return result
                                        try:
                                            with mock.patch.object(preread, 'inspect_business_source_projection', side_effect=revoke_during_business):
                                                with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                            self.assertEqual(0, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                            self.assertEqual(b'[]\n', private_allowlist.read_bytes())
                                        finally: private_allowlist.write_bytes(allowlist_bytes)  # owned fault only
                                    if owned_read_gates_probe:
                                        from test_cases.test_req7_remote_history_match import Req7OwnedHistoryMatchWorkflowTests, load as load_read_gates
                                        from test_cases.test_req7_sheets_read_decode import header_response
                                        from test_cases.test_req7_online_whitelist_read import document as whitelist_document
                                        from monitor import issue_tracker_history_read_launcher as fixed_reads
                                        read_gates = load_read_gates()
                                        self.assertIs(read_gates.global_journal, global_journal)
                                        self.assertIs(read_gates.enrollment, sys.modules['monitor.issue_tracker_enrollment_journal'])
                                        self.assertIs(read_gates.ownership, owner_module)
                                        import xml.etree.ElementTree as ET
                                        native_fixture = Req7OwnedHistoryMatchWorkflowTests()
                                        # The read child still uses the real fixed CA reader.
                                        # Its owned TLS root must not replace the CA/leaf
                                        # of an already prepared mutation endpoint.
                                        native_fixture.root = global_root/'owned-read-tls-root'
                                        native_fixture.path = native_fixture.root/'etc/ssl/certs/ca-certificates.crt'
                                        native_fixture.path.parent.mkdir(parents=True)
                                        native_fixture.addCleanup = self.addCleanup
                                        # Read actual fixture cells, not a whitelist generated
                                        # from the implementation's normalized digest/rules.
                                        namespace = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
                                        with zipfile.ZipFile(self.template) as archive:
                                            original_sheet = ET.fromstring(archive.read('xl/worksheets/sheet13.xml'))
                                        literal_rows = []
                                        for original_row in original_sheet.find(namespace+'sheetData'):
                                            cells = [None]*6
                                            for cell in original_row:
                                                self.assertEqual('inlineStr',cell.get('t'))
                                                self.assertIsNone(cell.find(namespace+'f'))
                                                column = ord(cell.get('r')[0])-ord('A')
                                                self.assertTrue(0 <= column < 6)
                                                cells[column] = ''.join(cell.itertext())
                                            literal_rows.append(tuple(cells))
                                        whitelist_doc = whitelist_document(())
                                        whitelist_doc['sheets'][0]['properties']['sheetId'] = dict(identity.sheet_ids)['Whitelist']
                                        whitelist_doc['sheets'][0]['data'][0]['rowData'] = [
                                            {'values': [{} if value is None else {'userEnteredValue': {'stringValue': value}}
                                                        for value in row[:6]]} for row in literal_rows]
                                        def fresh_bundle():
                                            bundle = {name:native_fixture.read_owned(private_context,writer_token,spreadsheet_token,
                                                binding,credential,kind,doc,raw_body=response(doc).data) for name,kind,doc in (
                                                    ('identity_response','template_identity',identity_response()),
                                                    ('headers_response','template_headers',header_response()),
                                                    ('whitelist_response','whitelist',whitelist_doc),
                                                    ('metadata_response','metadata',json.loads(quota_raw.data)))}
                                            if owned_continuity_probe:
                                                bundle['history_response'] = native_fixture.read_owned(private_context,writer_token,spreadsheet_token,
                                                    binding,credential,'history_tail',json.loads(history_raw.data),raw_body=history_raw.data)
                                                current = {}
                                                for role,kind in (('discovery','activity'),('occupancy','insertion')):
                                                    raw = reads[0][role+'_response'].data
                                                    current[role+'_response'] = native_fixture.read_owned(private_context,writer_token,spreadsheet_token,
                                                        binding,credential,kind,json.loads(raw),raw_body=raw,sheet=sheet)
                                                bundle['business_reads'] = tuple({'operation_id':reading['operation_id'],**current,
                                                    'row_response':None if reading['row_response'] is None else native_fixture.read_owned(
                                                        private_context,writer_token,spreadsheet_token,binding,credential,'row',
                                                        json.loads(reading['row_response'].data),raw_body=reading['row_response'].data,sheet=sheet,row=3)}
                                                    for reading in reads)
                                            return bundle
                                        def record_owned(bundle):
                                            counting = (global_journal.record_continuous_owned_attempt_intent if owned_continuity_probe
                                                        else global_journal.record_owned_receipted_attempt_intent)
                                            return counting(
                                                spreadsheet_token,binding,unit,qualified_source=qualified,store=self.store,
                                                writer_token=writer_token,settings=args['settings'],whitelist_snapshot=self.snapshot,
                                                expected_template_sha256=self.snapshot.workbook_sha256,http_root=self.root,
                                                whitelist_path=self.template,**bundle)
                                        original_bundle = fresh_bundle()
                                        for name in original_bundle:
                                            if name == 'business_reads': continue  # completions inside tuple are checked below
                                            with self.subTest(copied_read=name),self.assertRaises(global_journal.GlobalAttemptHold):
                                                record_owned({**original_bundle,name:replace(original_bundle[name])})
                                            self.assertEqual(0,global_journal.inspect_global_unit(spreadsheet_token,binding,unit).attempt_count)
                                        if owned_continuity_probe:
                                            with self.assertRaises(global_journal.GlobalAttemptHold):
                                                record_owned({**original_bundle,'business_reads':original_bundle['business_reads'][1:]})
                                            changed = [dict(item) for item in original_bundle['business_reads']]
                                            changed[0]['discovery_response'] = replace(changed[0]['discovery_response'])
                                            with self.assertRaises(global_journal.GlobalAttemptHold):
                                                record_owned({**original_bundle,'business_reads':tuple(changed)})
                                            self.assertEqual(0,global_journal.inspect_global_unit(spreadsheet_token,binding,unit).attempt_count)
                                    if retry_launch_probe is not None:
                                        from types import SimpleNamespace
                                        from monitor import issue_tracker_admission as admission
                                        from monitor import issue_tracker_local_commit as local
                                        from test_cases.test_req7_mutation_launcher import Req7MutationLauncherWorkflowTests, load as load_mutation
                                        from tools.project_contract import MIN_CONTINUOUS_INTERVAL_MINUTES
                                        import socket
                                        native_mutation=Req7MutationLauncherWorkflowTests()
                                        native_mutation.root=global_root
                                        native_mutation.path=global_root/'etc/ssl/certs/ca-certificates.crt'
                                        native_mutation.path.parent.mkdir(parents=True,exist_ok=True)
                                        native_mutation.addCleanup=self.addCleanup
                                        mutation=load_mutation(); original_wire=unit.wire_bytes; all_requests=[]; rejected=[]
                                        response_bytes=b'HTTP/1.1 401 Denied\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
                                        expected_requests = 2 if retry_launch_probe in ('normal', 'old-cycle') else 1
                                        for count in (1,2):
                                            scope=global_journal._hold_continuous_owned_attempt_wire if count==1 else global_journal._hold_shared_retry_owned_attempt_wire
                                            with native_mutation.server(response_bytes,hostname='sheets.googleapis.com',
                                                    destination='sheets.googleapis.com') as (requests,errors), ExitStack() as transport:
                                                port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                                                # Prepare the endpoint before issuing real
                                                # bounded reads; keep their original deadline.
                                                bundle=fresh_bundle()
                                                options=dict(qualified_source=qualified,store=self.store,writer_token=writer_token,
                                                    settings=args['settings'],whitelist_snapshot=self.snapshot,
                                                    expected_template_sha256=self.snapshot.workbook_sha256,http_root=self.root,
                                                    whitelist_path=self.template,**bundle)
                                                if count==2:
                                                    prior=admission.read_shared_local_admission(writer_token,self.store,committed.prepared.xlsx_bytes)
                                                    now=prior['monotonic_ns']+MIN_CONTINUOUS_INTERVAL_MINUTES*60*1_000_000_000
                                                    options.update(boot_id=prior['boot_id'],monotonic_ns=now)
                                                    # Fixture clock supplies the admitted interval; production
                                                    # still derives and validates the original shared floor.
                                                    transport.enter_context(mock.patch.object(admission,'time',SimpleNamespace(monotonic_ns=lambda:now)))
                                                calls=[]; children=[]
                                                def exercise():
                                                    nonlocal calls,children
                                                    with scope(spreadsheet_token,binding,unit,**options) as image:
                                                        self.assertEqual(count,image.attempt_count)
                                                        self.assertEqual(original_wire,os.pread(image.fd,len(original_wire)+1,0))
                                                        calls,children=native_mutation.intercept(transport,local,owner_module,
                                                            writer_token,spreadsheet_token,binding,image,port)
                                                        if count==2 and retry_launch_probe=='receipt-rebind':
                                                            path=generation_path/'RECEIPT'; raw=path.read_bytes(); inode=path.stat().st_ino
                                                            path.rename(project/'owned-retry-prelaunch-receipt'); path.write_bytes(raw); path.chmod(0o600)
                                                            self.assertNotEqual(inode,path.stat().st_ino)
                                                        if count==2 and retry_launch_probe=='read-expiry':
                                                            clock=fixed_reads._monotonic
                                                            transport.enter_context(mock.patch.object(fixed_reads,'_monotonic',side_effect=lambda:clock()+31))
                                                        if count==1 or retry_launch_probe in ('normal', 'old-cycle'):
                                                            result=mutation._send_counted_original_once(writer_token,spreadsheet_token,binding,credential,unit,image)
                                                            self.assertEqual((count,401,'UNKNOWN'),(result.attempt_count,result.status,result.outcome))
                                                            self.assertTrue(result.termination_confirmed)
                                                            self.assertEqual(1,len(calls)); self.assertEqual(1,len(children))
                                                            with self.assertRaises(mutation.MutationLauncherHold):
                                                                mutation._send_counted_original_once(writer_token,spreadsheet_token,binding,credential,unit,image)
                                                            self.assertEqual(1,len(calls))
                                                        else:
                                                            with self.assertRaises(mutation.MutationLauncherHold):
                                                                mutation._send_counted_original_once(writer_token,spreadsheet_token,binding,credential,unit,image)
                                                            self.assertEqual([],calls); self.assertEqual([],children); rejected.append(True)
                                                if count==1 or retry_launch_probe in ('normal', 'old-cycle'): exercise()
                                                else:
                                                    with self.assertRaises(global_journal.GlobalAttemptHold): exercise()
                                                    self.assertEqual([True],rejected)
                                            self.assertEqual([],errors)
                                            self.assertEqual(1 if count==1 or retry_launch_probe in ('normal', 'old-cycle') else 0,len(requests))
                                            if requests: self.assertEqual(original_wire,requests[0][2])
                                            all_requests.extend(requests)
                                            if count == 1 and retry_launch_probe == 'old-cycle':
                                                from monitor.collection_ib_producer import produce_worker_ib_analysis
                                                from tools.project_contract import build_collection_cycle_identity
                                                from test_cases.test_collection_cycle_persistence import TOKEN_2
                                                old_cycles = read_completed_cycle_evidence(self.store)
                                                self.assertEqual(1, len(old_cycles))
                                                identity_new = build_collection_cycle_identity(str(self.project), 'prod', 2, TOKEN_2)
                                                ib_new = produce_worker_ib_analysis(identity_new, project_root=self.project,
                                                    http_root=self.root,
                                                    clock=lambda: dt.datetime(2026,9,26,4,31,tzinfo=dt.timezone.utc),
                                                    runner=lambda _argv: self.fail('no external collection transport'))
                                                latest, _ = self._cycle(activity=True, derivation=True, ib_analysis=ib_new,
                                                    observed_peer='newer-not-original-peer', additional_eth_activity=True,
                                                    fabric_templates={'ethernet/prod':'tan-leaf', 'nvlink/prod':'border-leaf'})
                                                self.assertEqual(identity_new['cycle_id'], latest['cycle_id'])
                                                self.assertNotEqual(qualified.cycle_ids[-1], latest['cycle_id'])
                                                self.assertEqual(original_wire, unit.wire_bytes)
                                                self.assertEqual(c6_original,{name:(generation_path/name).read_bytes() for name in c6_original})
                                                self.assertEqual((1, 'UNKNOWN'),
                                                    (global_journal.inspect_global_unit(spreadsheet_token,binding,unit).attempt_count,
                                                     global_journal.inspect_global_unit(spreadsheet_token,binding,unit).outcome))
                                        self.assertEqual(expected_requests,len(all_requests))
                                        retained=global_journal.inspect_global_unit(spreadsheet_token,binding,unit)
                                        self.assertEqual((2,'UNKNOWN'),(retained.attempt_count,retained.outcome))
                                        self.assertEqual(c6_original,{name:(generation_path/name).read_bytes() for name in c6_original})
                                        self.assertEqual(quota,quota_module.inspect_metadata_reservation(spreadsheet_token,binding,identity,unit))
                                        state_path=state/(hashlib.sha256(binding.spreadsheet_id.encode('ascii')).hexdigest()+'.journal')
                                        self.assertFalse((state_path/'ATTEMPT-3').exists())
                                        shared=admission.read_shared_local_admission(writer_token,self.store,committed.prepared.xlsx_bytes)
                                        self.assertEqual('retry',shared['lane'])
                                        return
                                    if continuous_launch_probe is not None:
                                        from test_cases.test_req7_mutation_launcher import Req7MutationLauncherWorkflowTests, load as load_mutation
                                        from monitor import issue_tracker_local_commit as local
                                        native_mutation=Req7MutationLauncherWorkflowTests()
                                        native_mutation.root=global_root
                                        native_mutation.path=global_root/'etc/ssl/certs/ca-certificates.crt'
                                        native_mutation.path.parent.mkdir(parents=True,exist_ok=True)
                                        native_mutation.addCleanup=self.addCleanup
                                        mutation=load_mutation(); rejected=[]; calls=[]; children=[]
                                        import socket
                                        wire_response=b'HTTP/1.1 401 Denied\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}'
                                        with native_mutation.server(wire_response,hostname='sheets.googleapis.com',
                                                destination='sheets.googleapis.com') as (requests,errors), ExitStack() as transport:
                                            port=socket.getaddrinfo('sheets.googleapis.com',443)[0][4][1]
                                            bundle=fresh_bundle()
                                            def exercise():
                                                with global_journal._hold_continuous_owned_attempt_wire(
                                                        spreadsheet_token,binding,unit,qualified_source=qualified,store=self.store,
                                                        writer_token=writer_token,settings=args['settings'],whitelist_snapshot=self.snapshot,
                                                        expected_template_sha256=self.snapshot.workbook_sha256,http_root=self.root,
                                                        whitelist_path=self.template,**bundle) as image:
                                                    nonlocal calls,children
                                                    self.assertEqual(1,image.attempt_count)
                                                    calls,children=native_mutation.intercept(transport,local,owner_module,
                                                        writer_token,spreadsheet_token,binding,image,port)
                                                    if continuous_launch_probe=='receipt-rebind':
                                                        original=generation_path/'RECEIPT'; raw=original.read_bytes(); inode=original.stat().st_ino
                                                        original.rename(project/'owned-prelaunch-c6-receipt')
                                                        original.write_bytes(raw); original.chmod(0o600)
                                                        self.assertNotEqual(inode,original.stat().st_ino)
                                                        self.assertEqual(raw,original.read_bytes())
                                                    if continuous_launch_probe=='normal':
                                                        result=mutation._send_counted_original_once(writer_token,spreadsheet_token,binding,credential,unit,image)
                                                        self.assertEqual((1,401,'UNKNOWN'),(result.attempt_count,result.status,result.outcome))
                                                        self.assertTrue(result.termination_confirmed)
                                                        self.assertEqual(1,len(calls)); self.assertEqual(1,len(children))
                                                    else:
                                                        with ExitStack() as fault:
                                                            if continuous_launch_probe=='read-expiry':
                                                                original_clock=fixed_reads._monotonic
                                                                transport.enter_context(mock.patch.object(fixed_reads,'_monotonic',
                                                                    side_effect=lambda:original_clock()+31))
                                                            with self.assertRaises(mutation.MutationLauncherHold) as caught:
                                                                mutation._send_counted_original_once(writer_token,spreadsheet_token,binding,credential,unit,image)
                                                            self.assertFalse(caught.exception.termination_confirmed)
                                                            self.assertEqual([],calls); self.assertEqual([],children)
                                                            rejected.append(True)
                                            if continuous_launch_probe=='normal': exercise()
                                            else:
                                                with self.assertRaises(global_journal.GlobalAttemptHold): exercise()
                                                self.assertEqual([True],rejected)
                                            retained=global_journal.inspect_global_unit(spreadsheet_token,binding,unit)
                                            self.assertEqual((1,'UNKNOWN'),(retained.attempt_count,retained.outcome))
                                            self.assertEqual(c6_original,{name:(generation_path/name).read_bytes() for name in c6_original})
                                            self.assertEqual(quota,quota_module.inspect_metadata_reservation(spreadsheet_token,binding,identity,unit))
                                            self.assertFalse((state/(hashlib.sha256(binding.spreadsheet_id.encode('ascii')).hexdigest()+'.journal')/'ATTEMPT-2').exists())
                                        self.assertEqual([],errors)
                                        self.assertEqual(1 if continuous_launch_probe=='normal' else 0,len(requests))
                                        if requests: self.assertEqual(unit.wire_bytes,requests[0][2])
                                        return
                                    if shared_retry_probe:
                                        from types import SimpleNamespace
                                        from monitor import issue_tracker_admission as admission
                                        from monitor.issue_tracker_receipt_snapshot import read_current_cycle_local_receipts
                                        from tools.project_contract import MIN_CONTINUOUS_INTERVAL_MINUTES
                                        self.assertEqual(1,record_owned(fresh_bundle()).attempt_count)
                                        prior=admission.read_shared_local_admission(writer_token,self.store,committed.prepared.xlsx_bytes)
                                        now=prior['monotonic_ns']+MIN_CONTINUOUS_INTERVAL_MINUTES*60*1_000_000_000
                                        original_receipts=read_current_cycle_local_receipts(writer_token,self.store,
                                            expected_template_sha256=self.snapshot.workbook_sha256,settings=args['settings'],
                                            whitelist_sha256=self.snapshot.whitelist.sha256,qualified_source=qualified)
                                        bundle=fresh_bundle()
                                        if allocation_retry_identity_probe or quota_retry_identity_probe:
                                            original_observe=global_journal._observe
                                            quota_path=state/(hashlib.sha256(binding.spreadsheet_id.encode('ascii')).hexdigest()+'.metadata')
                                            quota_image={p.name:p.read_bytes() for p in quota_path.iterdir()}
                                            fault_path=quota_path/'HEADER' if quota_retry_identity_probe else assignments_path
                                            raw=fault_path.read_bytes(); inode=fault_path.stat().st_ino
                                            preserved=(project/'owned-original-retry-quota-header' if quota_retry_identity_probe
                                                else allocation_path.parent/'owned-original-retry-assignments')
                                            injected=[]
                                            def replace_after_retry(*values,**options):
                                                result=original_observe(*values,**options)
                                                if values[3]:
                                                    fault_path.rename(preserved)
                                                    fault_path.write_bytes(raw); fault_path.chmod(0o600)
                                                    injected.append(result.attempt_count)
                                                return result
                                            with mock.patch.object(admission,'time',SimpleNamespace(monotonic_ns=lambda:now)), \
                                                    mock.patch.object(global_journal,'_observe',side_effect=replace_after_retry):
                                                with self.assertRaises(global_journal.GlobalAttemptHold):
                                                    global_journal.record_shared_retry_continuous_owned_attempt_intent(
                                                        spreadsheet_token,binding,unit,qualified_source=qualified,store=self.store,
                                                        writer_token=writer_token,settings=args['settings'],whitelist_snapshot=self.snapshot,
                                                        expected_template_sha256=self.snapshot.workbook_sha256,http_root=self.root,
                                                        whitelist_path=self.template,boot_id=prior['boot_id'],monotonic_ns=now,**bundle)
                                            self.assertEqual([2],injected)
                                            self.assertNotEqual(inode,fault_path.stat().st_ino)
                                            self.assertEqual(raw,preserved.read_bytes()); self.assertEqual(raw,fault_path.read_bytes())
                                            intent=global_journal.inspect_global_unit(spreadsheet_token,binding,unit)
                                            self.assertEqual((2,'UNKNOWN'),(intent.attempt_count,intent.outcome))
                                            self.assertEqual(allocation_image,{p.name:p.read_bytes() for p in allocation_path.iterdir()})
                                            self.assertEqual(quota_image,{p.name:p.read_bytes() for p in quota_path.iterdir()})
                                            self.assertTrue(list((project/'.tracker/settings/outbox').iterdir()))
                                            admissions=project/'.tracker/admissions'
                                            self.assertTrue(list(admissions.glob('retry-*-intent.json')))
                                            self.assertEqual([],list(admissions.glob('retry-*-count.json')))
                                            retained={p.name:p.read_bytes() for p in admissions.iterdir()}
                                            with self.assertRaises(admission.AdmissionHold):
                                                admission.read_shared_local_admission(writer_token,self.store,committed.prepared.xlsx_bytes)
                                            self.assertEqual(retained,{p.name:p.read_bytes() for p in admissions.iterdir()})
                                            self.assertEqual(c6_original,{name:(generation_path/name).read_bytes() for name in c6_original})
                                            return
                                        from monitor import issue_tracker_history_preread_journal as continuity_module
                                        from monitor import issue_tracker_remote_history_match as gates_module
                                        phases=[]
                                        def traced(phase, original):
                                            def call(*values, **options):
                                                observed_phase=(phase+('_write' if values[3] else '_read')
                                                    if phase=='_observe' else phase)
                                                phases.append((observed_phase,'begin'))
                                                try: result=original(*values, **options)
                                                except Exception as exc:
                                                    frames=[]; trace=exc.__traceback__
                                                    while trace is not None:
                                                        frames.append((Path(trace.tb_frame.f_code.co_filename).name,
                                                            trace.tb_lineno,trace.tb_frame.f_code.co_name))
                                                        trace=trace.tb_next
                                                    print('SHARED_RETRY_PHASE_ERROR',observed_phase,type(exc).__name__,frames,flush=True)
                                                    raise
                                                phases.append((observed_phase,'complete'))
                                                return result
                                            return call
                                        with ExitStack() as diagnostics:
                                            diagnostics.enter_context(mock.patch.object(admission,'time',SimpleNamespace(monotonic_ns=lambda:now)))
                                            for module,name in ((global_journal,'_receipted_original_facts'),
                                                    (global_journal,'_observe'),
                                                    (continuity_module,'observe_owned_business_continuity'),
                                                    (gates_module,'observe_owned_unit_read_gates')):
                                                diagnostics.enter_context(mock.patch.object(module,name,
                                                    side_effect=traced(name,getattr(module,name))))
                                            result=global_journal.record_shared_retry_continuous_owned_attempt_intent(
                                                spreadsheet_token,binding,unit,qualified_source=qualified,store=self.store,
                                                writer_token=writer_token,settings=args['settings'],whitelist_snapshot=self.snapshot,
                                                expected_template_sha256=self.snapshot.workbook_sha256,http_root=self.root,
                                                whitelist_path=self.template,boot_id=prior['boot_id'],monotonic_ns=now,**bundle)
                                        self.assertEqual(2,sum(phase==('_receipted_original_facts','complete') for phase in phases))
                                        self.assertEqual(1,sum(phase==('_observe_write','complete') for phase in phases))
                                        self.assertEqual((2,'UNKNOWN'),(result.attempt_count,result.outcome))
                                        self.assertEqual('retry',admission.read_shared_local_admission(writer_token,self.store,committed.prepared.xlsx_bytes)['lane'])
                                        self.assertEqual(original_receipts,read_current_cycle_local_receipts(writer_token,self.store,
                                            expected_template_sha256=self.snapshot.workbook_sha256,settings=args['settings'],
                                            whitelist_sha256=self.snapshot.whitelist.sha256,qualified_source=qualified))
                                        self.assertEqual(c6_original,{name:(generation_path/name).read_bytes() for name in c6_original})
                                        return  # this new scenario asserts one complete protected ETH retry, not the fault loop below
                                    for count in range(1, 7):
                                        allocation_fault = settings_audit_probe and sheet == 'ETH Cabling' and count == 6
                                        if (receipt_admission_rebind_probe or quota_namespace_rebind_probe) and count==1:
                                            target=(state/(hashlib.sha256(binding.spreadsheet_id.encode('ascii')).hexdigest()+'.metadata')/'HEADER'
                                                if quota_namespace_rebind_probe else
                                                project/'.tracker/admissions/admission-00000000000000000001.json')
                                            raw=target.read_bytes(); inode=target.stat().st_ino
                                            preserved=project/('owned-original-quota-header' if quota_namespace_rebind_probe else 'owned-original-c6-admission'); injected=[]
                                            original_observe=global_journal._observe
                                            def replace_after_count(*values,**options):
                                                result=original_observe(*values,**options)
                                                if values[3]:
                                                    target.rename(preserved); target.write_bytes(raw); target.chmod(0o600)
                                                    injected.append(result.attempt_count)
                                                return result
                                            with mock.patch.object(global_journal,'_observe',side_effect=replace_after_count):
                                                with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                            self.assertEqual([1],injected)
                                            self.assertNotEqual(inode,target.stat().st_ino)
                                            self.assertEqual(raw,target.read_bytes()); self.assertEqual(raw,preserved.read_bytes())
                                            intent=global_journal.inspect_global_unit(spreadsheet_token,binding,unit)
                                            self.assertEqual((1,'UNKNOWN'),(intent.attempt_count,intent.outcome))
                                            self.assertEqual(c6_original,{name:(generation_path/name).read_bytes() for name in c6_original})
                                            self.assertEqual(seen,preread.inspect_business_preread(spreadsheet_token,binding,identity,unit))
                                            self.assertEqual(quota,quota_module.inspect_metadata_reservation(spreadsheet_token,binding,identity,unit))
                                            self.assertTrue(list((project/'.tracker/settings/outbox').iterdir()))
                                            return  # this independent fault keeps its retained originals; no fixture repair/retry
                                        elif allocation_original_identity_probe and sheet == 'ETH Cabling' and count == 1:
                                            original_observe = global_journal._observe
                                            original_bytes = assignments_path.read_bytes()
                                            original_inode = assignments_path.stat().st_ino
                                            preserved = allocation_path.parent/'owned-original-assignments'
                                            replaced = allocation_path.parent/'owned-replaced-assignments'
                                            injected = []
                                            def replace_after_count(*observe_args, **observe_kwargs):
                                                result = original_observe(*observe_args, **observe_kwargs)
                                                if observe_args[3]:
                                                    assignments_path.rename(preserved)
                                                    assignments_path.write_bytes(original_bytes)
                                                    assignments_path.chmod(0o600)
                                                    injected.append(result.attempt_count)
                                                return result
                                            try:
                                                with mock.patch.object(global_journal, '_observe', side_effect=replace_after_count):
                                                    with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                                self.assertEqual([1], injected)
                                                self.assertNotEqual(original_inode, assignments_path.stat().st_ino)
                                                self.assertEqual(original_bytes, assignments_path.read_bytes())
                                                self.assertEqual(original_bytes, preserved.read_bytes())
                                                intent = global_journal.inspect_global_unit(spreadsheet_token, binding, unit)
                                                self.assertEqual((1, 'UNKNOWN'), (intent.attempt_count, intent.outcome))
                                                self.assertEqual(allocation_image, {p.name: p.read_bytes() for p in allocation_path.iterdir()})
                                                self.assertTrue(list((project/'.tracker/settings/outbox').iterdir()))
                                            finally:
                                                if preserved.exists():
                                                    assignments_path.rename(replaced)
                                                    preserved.rename(assignments_path)  # owned fixture only; no production repair
                                        elif owned_read_gates_probe and count == 6:
                                            bundle = fresh_bundle(); expired = [False]
                                            original_counter = global_journal.record_receipted_original_attempt_intent
                                            def finish_after_read_deadline(*counter_args,**counter_kwargs):
                                                result = original_counter(*counter_args,**counter_kwargs)
                                                expired[0] = True; return result
                                            with mock.patch.object(global_journal,'record_receipted_original_attempt_intent',side_effect=finish_after_read_deadline), \
                                                    mock.patch.object(fixed_reads,'_monotonic',side_effect=lambda:time.monotonic()+(31 if expired[0] else 0)):
                                                with self.assertRaises(global_journal.GlobalAttemptHold): record_owned(bundle)
                                            intent = global_journal.inspect_global_unit(spreadsheet_token,binding,unit)
                                        elif receipted_intent_probe and (count in (2, 3, 4, 5) or allocation_fault):
                                            original_observe = global_journal._observe
                                            fault_path = assignments_path if allocation_fault else {2: private_allowlist, 3: generation_path/'RECEIPT',
                                                4: source_path, 5: project/'01-global.yaml'}[count]
                                            original_bytes = fault_path.read_bytes()
                                            def change_after_count(*observe_args, **observe_kwargs):
                                                result = original_observe(*observe_args, **observe_kwargs)
                                                if observe_args[3]: fault_path.write_bytes(b'changed after durable count')
                                                return result
                                            try:
                                                with mock.patch.object(global_journal, '_observe', side_effect=change_after_count):
                                                    with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                                intent = global_journal.inspect_global_unit(spreadsheet_token, binding, unit)
                                                self.assertEqual(b'changed after durable count', fault_path.read_bytes())
                                                with self.assertRaises(global_journal.GlobalAttemptHold): record()
                                                self.assertEqual(count, global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count)
                                            finally: fault_path.write_bytes(original_bytes)  # fault fixture only, no production recovery
                                        else: intent = record_owned(fresh_bundle()) if owned_read_gates_probe else record()
                                        self.assertEqual((count, 'UNKNOWN'), (intent.attempt_count, intent.outcome))
                                        self.assertFalse(hasattr(intent, 'permit')); self.assertFalse(hasattr(intent, 'complete'))
                                        self.assertEqual(seen, preread.inspect_business_preread(spreadsheet_token, binding, identity, unit))
                                        self.assertEqual(quota, quota_module.inspect_metadata_reservation(spreadsheet_token, binding, identity, unit))
                                    with self.assertRaises(global_journal.GlobalAttemptHold):
                                        record()
                                    if receipted_intent_probe:
                                        self.assertEqual(c6_original, {name: (generation_path/name).read_bytes() for name in c6_original})
                                    if settings_audit_probe and sheet == 'ETH Cabling':
                                        self.assertEqual(allocation_image, {p.name: p.read_bytes() for p in allocation_path.iterdir()})
                                        self.assertTrue(list((project/'.tracker/settings/outbox').iterdir()))
                                else:
                                    global_journal.record_global_attempt_intent(spreadsheet_token, binding, unit)
                                self.assertEqual(seen, preread.inspect_business_preread(spreadsheet_token, binding, identity, unit))
                                with self.assertRaises(preread.HistoryPrereadHold):
                                    preread.prepare_business_preread(spreadsheet_token, binding, identity, unit, manifest=body, business_reads=tuple(reads))
                                self.assertEqual(retained, {path.name: path.read_bytes() for path in (state/(stem+'.business')).iterdir()})
                                self.assertEqual(before, {path.name: path.read_bytes() for path in (state/(stem+'.nv')).iterdir()})
                                continue
                            blocked = state/(stem+'.journal'); blocked.mkdir(mode=0o700)
                            with self.assertRaises(compiler.SendUnitHold): compile_cabling()
                            self.assertEqual([], list(blocked.iterdir()))
                            self.assertEqual(before, {path.name: path.read_bytes() for path in (state/(stem+'.nv')).iterdir()})
                self.assertEqual(original_template, self.template.read_bytes())
                self.assertFalse((project/'.tracker/remote-actions').exists()); self.assertFalse((project/'.tracker/remote-attempts').exists())
                return
            if observed_switch_insert_probe:
                import tempfile
                import monitor.issue_tracker_send_unit as compiler
                from monitor.issue_tracker_sheets_read_plan import prepare_activity_sheet_read, prepare_insertion_sheet_read, prepare_sheets_read, prepare_history_tail_read, prepare_template_identity_read
                from monitor.issue_tracker_sheets_read_decode import decode_template_identity
                from monitor.issue_tracker_online_target import OnlineTargetBinding
                from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
                from test_cases.test_req7_activity_discovery import sheet_document, insertion_document, exact_row_document, reserved_switch_row, literal
                from test_cases.test_req7_sheets_read_decode import response, identity_response
                from test_cases.test_req7_spreadsheet_owner import load as load_owner, scoped_fixture
                from test_cases.test_req7_enrollment_journal import load as load_enrollment
                self.assertTrue(hasattr(compiler,'freeze_observed_receipted_switch_unit'),'original receipt, owner and enrollment must derive Switch inserts')
                binding = OnlineTargetBinding('synthetic_spreadsheet_id_0001','a'*64,'b'*64)
                credential = AuthenticatedToken('synthetic.private-token',time.time()+3600)
                identity = decode_template_identity(prepare_template_identity_read(binding,credential),response(identity_response()))
                candidates = tuple(item for item in qualified.candidates if item.activity_key[0] == 'switch')
                self.assertGreater(len(candidates),1)
                rows = [reserved_switch_row(index) for index in range(2,len(candidates)+5)]
                rows[0]['M'] = {'boolValue':False}
                key = candidates[0].activity_key
                rows[1].update({'F':literal(key[1]),'L':literal('[MONITOR][%s][%s] old evidence'%key[2:]),'N':literal('New')})
                source = sheet_document('ETH&IB Switch',rows,len(rows)+2); source['sheets'][0]['properties']['sheetId'] = 101
                occupancy = insertion_document('ETH&IB Switch',rows,len(rows)+2); occupancy['sheets'][0]['properties']['sheetId'] = 101
                discovery_plan = prepare_activity_sheet_read(binding,credential,sheet='ETH&IB Switch')
                occupancy_plan = prepare_insertion_sheet_read(binding,credential,sheet='ETH&IB Switch')
                reads = []
                for offset,candidate in enumerate(candidates):
                    index = offset+3
                    exact = exact_row_document('ETH&IB Switch',rows[index-2],index); exact['sheets'][0]['properties']['sheetId'] = 101
                    reads.append({'operation_id':candidate.operation_id,'discovery_plan':discovery_plan,'discovery_response':response(source),
                        'occupancy_plan':occupancy_plan,'occupancy_response':response(occupancy),
                        'row_plan':prepare_sheets_read(binding,credential,mode='row_rectangle',sheet='ETH&IB Switch',first_row=index+1),
                        'row_response':response(exact)})
                history_plan = prepare_history_tail_read(binding,credential)
                history_response = response({'spreadsheetId':binding.spreadsheet_id,'sheets':[{'properties':{'sheetId':105,'title':'Update_History',
                    'sheetType':'GRID','gridProperties':{'rowCount':100,'columnCount':5}},'data':[{'startRow':2,'startColumn':0}]}]})
                with tempfile.TemporaryDirectory(prefix='req7-real-switch-insert-') as directory:
                    global_root = Path(directory).resolve(); state = global_root/'var/lib/http-ztp-container/issue-tracker'
                    state.mkdir(parents=True,mode=0o700); owner_module = load_owner(); enrollment_module = load_enrollment()
                    with tracker_writer(project,self.publication) as writer_token, scoped_fixture(global_root,owner_module), owner_module.spreadsheet_owner(binding) as spreadsheet_token:
                        original = enrollment_module.prepare_enrollment_journal(spreadsheet_token,binding,identity)
                        def compile_switch(**changes):
                            options = dict(local_generation_id=committed.receipt.generation_id,business_reads=tuple(reads),history_plan=history_plan,
                                history_response=history_response,spreadsheet_token=spreadsheet_token,binding=binding,identity=identity,audits=(),occupied_metadata_ids=())
                            if nonallocating_switch_audit_probe:
                                from monitor.issue_tracker_settings_audit_allocation import pending_settings_audits
                                options['audits'] = pending_settings_audits(writer_token)
                                self.assertTrue(options['audits'])
                            options.update(changes)
                            return compiler.freeze_observed_receipted_switch_unit(qualified,self.store,metadata=metadata,
                                expected_template_sha256=self.snapshot.workbook_sha256,writer_token=writer_token,**args,**options)
                        if nonallocating_switch_catalog_probe:
                            from test_cases.test_req7_global_attempt_journal import load as load_global
                            from test_cases.test_req7_nv_reservation import load as load_native
                            from test_cases.test_req7_unit_catalog import load as load_catalog
                            load_global(); native = load_native(); catalog = load_catalog(reset_dependencies=False)
                            self.assertIs(native.ownership, owner_module)
                            self.assertIs(catalog.ownership, owner_module)
                            stem = hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()
                            baseline = {path.name for path in state.iterdir()}
                            with self._assertion_preserving_preparation(native.hold_catalog_nonallocating_preparation(writer_token, spreadsheet_token, binding, identity,
                                    generation_id=committed.receipt.generation_id,
                                    publish_id=committed.receipt.published_sha256, sheet='ETH&IB Switch')) as prepared:
                                self.assertEqual(baseline, {path.name for path in state.iterdir()})
                                self.assertFalse(hasattr(prepared, 'observation'))
                                with self.assertRaises(native.NvReservationHold):
                                    native._catalog_nonallocating_source_observation(prepared, spreadsheet_token, binding, identity,
                                        writer_token=writer_token, generation_id=committed.receipt.generation_id,
                                        publish_id='0' * 64, sheet='ETH&IB Switch')
                                if nonallocating_switch_alias_probe == 'other-live-writer':
                                    foreign_project = global_root / 'another-project'
                                    foreign_project.mkdir(mode=0o700)
                                    foreign_publication = foreign_project / 'publication'
                                    foreign_publication.mkdir(mode=0o700)
                                    initialize_tracker_state(foreign_project, foreign_publication,
                                        initialized_at='2026-09-25T00:00:00Z',
                                        acquisition_id='req7-nonallocating-other-live-writer')
                                    with tracker_writer(foreign_project, foreign_publication) as foreign_writer:
                                        self.assertIsNot(writer_token, foreign_writer)
                                        with self.assertRaises(native.NvReservationHold):
                                            native._catalog_nonallocating_source_observation(prepared, spreadsheet_token, binding, identity,
                                                writer_token=foreign_writer, generation_id=committed.receipt.generation_id,
                                                publish_id=committed.receipt.published_sha256, sheet='ETH&IB Switch')
                                        with mock.patch.object(catalog, '_register_native_pending_c6_unit') as register:
                                            with self.assertRaises(catalog.UnitCatalogHold):
                                                catalog.register_pending_c6_unit(foreign_writer, spreadsheet_token, binding,
                                                    compile_switch(_unit_preparation=prepared), _unit_preparation=prepared)
                                            register.assert_not_called()
                                    self.assertEqual(baseline, {path.name for path in state.iterdir()})
                                unit = compile_switch(_unit_preparation=prepared)
                                body = json.loads(unit.action_preimage)
                                self.assertEqual(['update'] + ['insert'] * (len(candidates) - 1),
                                    [item['action'] for item in body['business']])
                                self.assertEqual(baseline, {path.name for path in state.iterdir()})
                                if nonallocating_switch_alias_probe == 'old-nv-registry':
                                    with self.assertRaises(native.NvReservationHold):
                                        native.register_catalog_nv_unit(prepared, unit)
                                    self.assertEqual(baseline, {path.name for path in state.iterdir()})
                                elif nonallocating_switch_alias_probe == 'old-c6-parameter':
                                    with self.assertRaises(catalog.UnitCatalogHold):
                                        catalog.register_pending_c6_unit(writer_token, spreadsheet_token, binding, unit,
                                            _nv_preparation=prepared)
                                    self.assertEqual(baseline, {path.name for path in state.iterdir()})
                                catalog.register_pending_c6_unit(writer_token, spreadsheet_token, binding, unit,
                                    _unit_preparation=prepared)
                                with catalog.hold_pending_units(spreadsheet_token, binding) as (units, verify):
                                    self.assertEqual((unit,), units); verify()
                                with self.assertRaises(compiler.SendUnitHold): compile_switch(_unit_preparation=prepared)
                            self.assertFalse(native._ACTIVE_CATALOG_PREPARATIONS)
                            self.assertFalse(catalog._IMAGE_BUDGETS)
                            names = {path.name for path in state.iterdir()}
                            self.assertFalse(any(name.endswith('.nv') or name.endswith('.nv-started') for name in names))
                            self.assertFalse(any('.journal' in name or '.GLOBAL' in name for name in names))
                            folder = state / (stem + '.units') / unit.unit_id
                            header = json.loads((folder / 'HEADER').read_bytes())
                            self.assertNotIn('nv_original', header)
                            self.assertIn('project_origin', header)
                            if nonallocating_switch_audit_probe:
                                self.assertTrue(body['audits'])
                                self.assertIn('settings_allocation', header)
                                self.assertEqual(len(candidates) + len(body['audits']), unit.history_rows_expected)
                                audit_directory = state / (stem + '.unit-' + unit.unit_id + '.settings-audit')
                                self.assertTrue((audit_directory / 'INITIALIZED').is_file())
                            self.assertEqual(unit.wire_bytes, (folder / 'WIRE').read_bytes())
                            with self.assertRaises(compiler.SendUnitHold): compile_switch()
                            self.assertEqual(names, {path.name for path in state.iterdir()})
                            self.assertEqual(original_template, self.template.read_bytes())
                            return
                        unit = compile_switch(); action = json.loads(unit.action_preimage)
                        self.assertEqual(committed.receipt.generation_id,action['identity']['generation_id'])
                        self.assertEqual(committed.receipt.published_sha256,action['identity']['publish_id'])
                        nonces = {title:nonce for title,sid,nonce in original.nonces}
                        self.assertEqual(nonces['ETH&IB Switch'],action['target_nonce']); self.assertEqual(nonces['Update_History'],action['history_nonce'])
                        self.assertEqual(['update']+['insert']*(len(candidates)-1),[item['action'] for item in action['business']])
                        updates = [item['updateCells'] for item in json.loads(unit.wire_bytes)['requests'] if 'updateCells' in item]
                        self.assertEqual(set(range(3,len(candidates)+3)),{item['start']['rowIndex'] for item in updates})
                        for item in updates:
                            self.assertEqual(101,item['start']['sheetId']); self.assertNotIn(item['start']['columnIndex'],(0,3,4,6,7,8,12,14,15,16,17,18,19,20))
                        for claim in ({'target_nonce':'c'*64},{'placements':()},{'sheet_id':101},{'preread_sha256':'e'*64},{'business_reads':tuple(reads[:-1])}):
                            with self.assertRaises(compiler.SendUnitHold): compile_switch(**claim)
                        with self.assertRaises(compiler.SendUnitHold): compile_switch(spreadsheet_token=object())
                        changed_identity = replace(identity,sheet_ids=tuple((title,150 if title=='ETH&IB Switch' else sid) for title,sid in identity.sheet_ids))
                        with self.assertRaises(compiler.SendUnitHold): compile_switch(identity=changed_identity)
                        saved = reads[1]['row_response']; drift = json.loads(saved.data)
                        drift['sheets'][0]['data'][0]['rowData'][0]['values'][12] = {'userEnteredValue':literal('operator drift')}
                        reads[1]['row_response'] = response(drift)
                        try:
                            with self.assertRaises(compiler.SendUnitHold): compile_switch()
                        finally: reads[1]['row_response'] = saved
                        real_freeze = compiler.freeze_receipted_prod_source_unit
                        def change_row_during_compilation(*freeze_args,**freeze_kwargs):
                            result = real_freeze(*freeze_args,**freeze_kwargs)
                            reads[1]['row_response'] = response(drift)
                            return result
                        try:
                            with mock.patch.object(compiler,'freeze_receipted_prod_source_unit',side_effect=change_row_during_compilation):
                                with self.assertRaises(compiler.SendUnitHold): compile_switch()
                        finally: reads[1]['row_response'] = saved
                        stem = hashlib.sha256(binding.spreadsheet_id.encode()).hexdigest()
                        blocked = state/(stem+'.journal'); blocked.mkdir(mode=0o700)
                        with self.assertRaises(compiler.SendUnitHold): compile_switch()
                        self.assertEqual([],list(blocked.iterdir()))
                        self.assertEqual({stem+'.lock',stem+'.enrollment',stem+'.journal'},{path.name for path in state.iterdir()})
                self.assertEqual(original_template,self.template.read_bytes())
                self.assertFalse((project/'.tracker/remote-actions').exists()); self.assertFalse((project/'.tracker/remote-attempts').exists())
                return
            if observed_source_probe:
                import monitor.issue_tracker_send_unit as compiler
                from monitor.issue_tracker_sheets_read_plan import prepare_activity_sheet_read, prepare_sheets_read, prepare_history_tail_read
                from monitor.issue_tracker_online_target import OnlineTargetBinding
                from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
                from test_cases.test_req7_activity_discovery import sheet_document, exact_row_document, switch_row, cabling_row, literal
                from test_cases.test_req7_sheets_read_decode import response
                self.assertTrue(hasattr(compiler, 'freeze_observed_receipted_source_updates'), 'protected receipt/source must derive rows from original read images')
                binding = OnlineTargetBinding('synthetic_spreadsheet_id_0001', 'a' * 64, 'b' * 64)
                credential = AuthenticatedToken('synthetic.private-token', time.time() + 3600)
                history_plan = prepare_history_tail_read(binding, credential)
                history_raw = response({'spreadsheetId': binding.spreadsheet_id, 'sheets': [{
                    'properties': {'sheetId': 105, 'title': 'Update_History', 'sheetType': 'GRID',
                        'gridProperties': {'rowCount': 100, 'columnCount': 5}},
                    'data': [{'startRow': 2, 'startColumn': 0}]}]})
                before_generations_observed = tuple(sorted(generation_root.iterdir()))
                for sheet, family, sid in (('ETH&IB Switch', 'switch', 101), ('ETH Cabling', 'eth_cabling', 102), ('IB Cabling', 'ib_cabling', 103)):
                    candidates = tuple(item for item in qualified.candidates if item.activity_key[0] == family)
                    rows = []
                    for index, candidate in enumerate(candidates):
                        key = candidate.activity_key
                        row = switch_row('NV%05d' % (43001 + index)) if family == 'switch' else cabling_row('NV%05d' % (43001 + index))
                        if family == 'switch':
                            row['F'] = literal(key[1]); row['L'] = literal('[MONITOR][%s][%s] old independent evidence' % key[2:])
                        else:
                            for column, value in zip(('K', 'L', 'F'), key[1:]): row[column] = literal(value)
                        rows.append(row)
                    source = sheet_document(sheet, rows, row_count=len(rows) + 4)
                    source['sheets'][0]['properties']['sheetId'] = sid
                    discovery_plan = prepare_activity_sheet_read(binding, credential, sheet=sheet)
                    raw_discovery = response(source)
                    reads = []
                    for index, candidate in enumerate(candidates):
                        exact = exact_row_document(sheet, rows[index], index + 2)
                        exact['sheets'][0]['properties']['sheetId'] = sid
                        reads.append({'operation_id': candidate.operation_id, 'discovery_plan': discovery_plan,
                            'discovery_response': raw_discovery, 'row_plan': prepare_sheets_read(binding, credential,
                                mode='row_rectangle', sheet=sheet, first_row=index + 3), 'row_response': response(exact)})
                    options = dict(local_generation_id=committed.receipt.generation_id, spreadsheet_id=binding.spreadsheet_id,
                        sheet=sheet, sheet_id=sid, history_sheet_id=105, target_nonce='c' * 64, history_nonce='d' * 64,
                        audits=(), occupied_metadata_ids=())
                    with tracker_writer(project, self.publication) as token:
                        def compile_observed(**changes):
                            return compiler.freeze_observed_receipted_source_updates(qualified, self.store, metadata=metadata,
                                expected_template_sha256=self.snapshot.workbook_sha256, writer_token=token, **args,
                                **{**options, 'business_reads': tuple(reads), 'history_plan': history_plan, 'history_response': history_raw, **changes})
                        unit = compile_observed()
                        action = json.loads(unit.action_preimage)
                        self.assertEqual(committed.receipt.generation_id, action['identity']['generation_id'])
                        self.assertEqual(committed.receipt.published_sha256, action['identity']['publish_id'])
                        self.assertNotEqual('e' * 64, action['preread_sha256'])
                        requests = json.loads(unit.wire_bytes)['requests']
                        updates = [item['updateCells'] for item in requests if 'updateCells' in item]
                        self.assertEqual(set(range(2, len(rows) + 2)), {item['start']['rowIndex'] for item in updates})
                        for item in updates:
                            self.assertEqual(sid, item['start']['sheetId'])
                            self.assertEqual('userEnteredValue', item['fields'])
                            self.assertNotEqual(0, item['start']['columnIndex'])
                        with self.assertRaises(compiler.SendUnitHold): compile_observed(preread_sha256='e' * 64)
                        with self.assertRaises(compiler.SendUnitHold): compile_observed(placements=())
                        with self.assertRaises(compiler.SendUnitHold): compile_observed(business_reads=tuple(reads[:-1]))
                        foreign_history = json.loads(history_raw.data)
                        foreign_history['spreadsheetId'] = 'foreign_spreadsheet_id_0002'
                        with self.assertRaises(compiler.SendUnitHold): compile_observed(history_response=response(foreign_history))
                        full_history = json.loads(history_raw.data)
                        full_history['sheets'][0]['properties']['gridProperties']['rowCount'] = 3
                        full_history['sheets'][0]['data'][0]['rowData'] = [{'values': [{'userEnteredValue': literal('occupied original tail')}]}]
                        with self.assertRaises(compiler.SendUnitHold): compile_observed(history_response=response(full_history))
                        original_row = reads[0]['row_response']
                        drift = json.loads(original_row.data)
                        drift['sheets'][0]['data'][0]['rowData'][0]['values'][0] = {'userEnteredValue': literal('NV99999')}
                        reads[0]['row_response'] = response(drift)
                        try:
                            with self.assertRaises(compiler.SendUnitHold): compile_observed()
                        finally: reads[0]['row_response'] = original_row
                        def change_row_during_freeze(*freeze_args, **freeze_kwargs):
                            result = real_freeze(*freeze_args, **freeze_kwargs)
                            reads[0]['row_response'] = response(drift)
                            return result
                        real_freeze = compiler.freeze_receipted_prod_source_unit
                        try:
                            with mock.patch.object(compiler, 'freeze_receipted_prod_source_unit', side_effect=change_row_during_freeze):
                                with self.assertRaises(compiler.SendUnitHold): compile_observed()
                        finally: reads[0]['row_response'] = original_row
                self.assertEqual(before_generations_observed, tuple(sorted(generation_root.iterdir())))
                self.assertEqual(original_template, self.template.read_bytes())
                self.assertFalse((project / '.tracker/remote-actions').exists())
                self.assertFalse((project / '.tracker/remote-attempts').exists())
                return
            if receipted_source_probe:
                import monitor.issue_tracker_send_unit as compiler
                generation_id = committed.receipt.generation_id
                original_publications = tuple(sorted(self.publication.iterdir()))
                original_generations = tuple(sorted(generation_root.iterdir()))
                receipt_path = generation_root / generation_id / 'RECEIPT'
                receipt_bytes = receipt_path.read_bytes()
                publication_path = self.publication / (generation_id + '.xlsx')
                published_bytes = publication_path.read_bytes()
                for sheet, family, sid in (('ETH&IB Switch', 'switch', 101), ('ETH Cabling', 'eth_cabling', 102),
                                           ('IB Cabling', 'ib_cabling', 103)):
                    candidates = tuple(item for item in qualified.candidates if item.activity_key[0] == family)
                    self.assertTrue(candidates)
                    placements = tuple({'operation_id': item.operation_id, 'action': 'update' if family == 'switch' else 'insert',
                        'row_index': index + 2 if family == 'switch' else None, 'observed_values': {'L': {}} if family == 'switch' else None,
                        'reserved_id': None if family == 'switch' else 'NV%05d' % (42001 + index)}
                        for index, item in enumerate(candidates))
                    options = dict(local_generation_id=generation_id,
                        spreadsheet_id='synthetic_spreadsheet_id_0001', sheet=sheet, sheet_id=sid, history_sheet_id=105,
                        target_nonce='c' * 64, history_nonce='d' * 64, preread_sha256='e' * 64,
                        audits=(), occupied_metadata_ids=())
                    with tracker_writer(project, self.publication) as token:
                        def compile_unit(**changes):
                            return compiler.freeze_receipted_prod_source_unit(qualified, self.store, metadata=metadata,
                                expected_template_sha256=self.snapshot.workbook_sha256, placements=placements,
                                writer_token=token, **args, **{**options, **changes})
                        unit = compile_unit()
                        action = json.loads(unit.action_preimage)
                        self.assertEqual(generation_id, action['identity']['generation_id'])
                        self.assertEqual(committed.receipt.published_sha256, action['identity']['publish_id'])
                        self.assertEqual(committed.receipt.manifest_id, action['manifest_id'])
                        with self.assertRaises(compiler.SendUnitHold): compile_unit(publish_id='f' * 64)
                        with self.assertRaises(compiler.SendUnitHold):
                            compile_unit(local_generation_id='gen-00000000000000000002-' + '1' * 32)
                        if family == 'switch':
                            forged = json.loads(receipt_bytes); forged['sequence'] = True
                            receipt_path.write_bytes(json.dumps(forged).encode())
                            bad_receipt = receipt_path.read_bytes()
                            try:
                                with self.assertRaises(compiler.SendUnitHold): compile_unit()
                                self.assertEqual(bad_receipt, receipt_path.read_bytes())
                            finally:
                                receipt_path.write_bytes(receipt_bytes)
                            admission_path = next((project / '.tracker/admissions').iterdir())
                            admission_bytes = admission_path.read_bytes()
                            try:
                                admission_path.write_bytes(b'{}\n')
                                with self.assertRaises(compiler.SendUnitHold): compile_unit()
                                self.assertEqual(b'{}\n', admission_path.read_bytes())
                            finally:
                                admission_path.write_bytes(admission_bytes)
                            real_compile = compiler.freeze_prod_source_unit
                            def change_publication_after_freeze(*freeze_args, **freeze_options):
                                result = real_compile(*freeze_args, **freeze_options)
                                publication_path.write_bytes(b'changed after source unit freeze')
                                return result
                            try:
                                with mock.patch.object(compiler, 'freeze_prod_source_unit', side_effect=change_publication_after_freeze):
                                    with self.assertRaises(compiler.SendUnitHold): compile_unit()
                                self.assertEqual(b'changed after source unit freeze', publication_path.read_bytes())
                            finally:
                                publication_path.write_bytes(published_bytes)
                            preserved_receipt = project / 'preserved-original-receipt'
                            def replace_receipt_inode_after_freeze(*freeze_args, **freeze_options):
                                result = real_compile(*freeze_args, **freeze_options)
                                receipt_path.rename(preserved_receipt)
                                receipt_path.write_bytes(receipt_bytes)
                                receipt_path.chmod(0o600)
                                return result
                            try:
                                with mock.patch.object(compiler, 'freeze_prod_source_unit', side_effect=replace_receipt_inode_after_freeze):
                                    with self.assertRaises(compiler.SendUnitHold): compile_unit()
                                self.assertNotEqual(preserved_receipt.stat().st_ino, receipt_path.stat().st_ino)
                                self.assertEqual(receipt_bytes, receipt_path.read_bytes())
                            finally:
                                if preserved_receipt.exists():
                                    receipt_path.unlink()
                                    preserved_receipt.rename(receipt_path)
                self.assertEqual(original_publications, tuple(sorted(self.publication.iterdir())))
                self.assertEqual(original_generations, tuple(sorted(generation_root.iterdir())))
                self.assertEqual(original_template, self.template.read_bytes())
                self.assertEqual(receipt_bytes, receipt_path.read_bytes())
                self.assertEqual(published_bytes, publication_path.read_bytes())
                self.assertFalse((project / '.tracker/remote-actions').exists())
                self.assertFalse((project / '.tracker/remote-attempts').exists())
                return
            if require_first_manual_admission:
                self.assertTrue((project / ".tracker/admissions").is_dir())
                admission_files = tuple(sorted(
                    (project / ".tracker/admissions").iterdir()))
                self.assertEqual(1, len(admission_files))
                with tracker_writer(project, self.publication) as token:
                    shared = read_auto_local_admission(
                        token, self.store, self.snapshot.workbook_sha256)
                self.assertEqual(committed.receipt.generation_id,
                                 shared["generation_id"])
                self.assertEqual(committed.receipt.published_sha256,
                                 shared["published_sha256"])
                self.assertEqual("manual", shared["lane"])
                self.assertEqual(cycle["cycle_id"], shared["cycle_id"])
                root_template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
                root_template.parent.mkdir(parents=True, exist_ok=True)
                root_template.write_bytes(self.template.read_bytes())
                stage_status_path = (
                    self.root / "monitor/status/issue-tracker-stage-l.status.json"
                )
                before_second_cycle = tuple(sorted(generation_root.iterdir()))
                with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                      mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                      mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                        stage_status_path),
                      mock.patch.object(WORKER, "_current_boot_identity",
                                        return_value=shared["boot_id"])):
                    self.assertIsNone(
                        WORKER._publish_stage_l_local_after_completion(self.store)
                    )
                self.assertEqual(before_second_cycle,
                                 tuple(sorted(generation_root.iterdir())))
                self.assertEqual("not_due", json.loads(
                    stage_status_path.read_bytes())["local"])
                second_identity = build_collection_cycle_identity(
                    str(project), "prod", 2, TOKEN_2,
                )
                second_binding = produce_worker_ib_analysis(
                    second_identity, project_root=project, http_root=self.root,
                    clock=lambda: dt.datetime(2026, 9, 26, 4, 31,
                                              tzinfo=dt.timezone.utc),
                    runner=lambda _argv: self.fail(
                        "transport is supplied by fixture"),
                )
                second_cycle, _ = self._cycle(
                    activity=True, derivation=True,
                    observed_peer="changed-peer", ib_analysis=second_binding,
                    fabric_templates={"ethernet/prod": "tan-leaf",
                                      "nvlink/prod": "border-leaf"},
                )
                self.assertEqual(second_identity["cycle_id"],
                                 second_cycle["cycle_id"])
                later_ns = (shared["monotonic_ns"]
                            + MIN_CONTINUOUS_INTERVAL_MINUTES * 60
                            * 1_000_000_000 + 1)
                if manual_after_manual:
                    second_witness = (
                        shared["policy_sha256"],
                        shared["publish_every_cycles"],
                        shared["boot_id"], later_ns,
                    )
                    with mock.patch.object(WORKER.time, "monotonic_ns",
                                           return_value=later_ns):
                        second_result = commit_qualified_prod_local(
                            self.store, http_root=self.root, project=project,
                            publication=self.publication,
                            template_path=root_template,
                            manual_admission=second_witness,
                        )
                    self.assertIsInstance(second_result, CommittedProdWorkbook)
                    self.assertNotEqual(committed.receipt.generation_id,
                                        second_result.receipt.generation_id)
                    with tracker_writer(project, self.publication) as token:
                        latest = read_auto_local_admission(
                            token, self.store, self.snapshot.workbook_sha256)
                    self.assertEqual("manual", latest["lane"])
                    self.assertEqual(3, latest["publish_every_cycles"])
                    self.assertEqual(second_cycle["cycle_id"], latest["cycle_id"])
                    self.assertEqual(second_result.receipt.generation_id,
                                     latest["generation_id"])
                    self.assertEqual(2, len(tuple(
                        (project / ".tracker/admissions").iterdir())))
                    with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                          mock.patch.object(WORKER, "STATUS_DIR",
                                            stage_status_path.parent),
                          mock.patch.object(WORKER,
                                            "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                            stage_status_path),
                          mock.patch.object(WORKER, "_current_boot_identity",
                                            return_value=shared["boot_id"]),
                          mock.patch.object(WORKER.time, "monotonic_ns",
                                            return_value=later_ns)):
                        self.assertIsNone(
                            WORKER._publish_stage_l_local_after_completion(
                                self.store))
                    self.assertEqual("not_due", json.loads(
                        stage_status_path.read_bytes())["local"])
                    self.assertEqual(2, len(tuple(
                        (project / ".tracker/generations").iterdir())))
                    return
                with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                      mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                      mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                        stage_status_path),
                      mock.patch.object(WORKER, "_current_boot_identity",
                                        return_value=shared["boot_id"]),
                      mock.patch.object(WORKER.time, "monotonic_ns",
                                        return_value=later_ns)):
                    second_result = WORKER._publish_stage_l_local_after_completion(
                        self.store)
                self.assertIsInstance(second_result, CommittedProdWorkbook)
                self.assertNotEqual(committed.receipt.generation_id,
                                    second_result.receipt.generation_id)
                with tracker_writer(project, self.publication) as token:
                    latest = read_auto_local_admission(
                        token, self.store, self.snapshot.workbook_sha256)
                self.assertEqual("automatic", latest["lane"])
                self.assertEqual(second_cycle["cycle_id"], latest["cycle_id"])
                self.assertEqual(second_result.receipt.generation_id,
                                 latest["generation_id"])
                self.assertEqual(2, len(tuple(
                    (project / ".tracker/admissions").iterdir())))
                return
            root_template = self.root / "monitor/Issue_Tracker_Template_v1.xlsx"
            root_template.parent.mkdir(parents=True, exist_ok=True)
            root_template.write_bytes(self.template.read_bytes())
            before_runtime_entry = tuple(sorted(generation_root.iterdir()))
            runtime_noop = commit_qualified_prod_local(
                self.store, http_root=self.root, project=project,
                publication=self.publication, template_path=root_template,
                manual_admission=manual_witness,
            )
            self.assertIsInstance(runtime_noop, ProdWorkbookNoop)
            self.assertEqual("no_change", runtime_noop.status)
            self.assertEqual(before_runtime_entry,
                             tuple(sorted(generation_root.iterdir())))
            stage_status_path = self.root / "monitor/status/issue-tracker-stage-l.status.json"
            with (mock.patch.object(WORKER, "HTTP_ROOT", self.root),
                  mock.patch.object(WORKER, "STATUS_DIR", stage_status_path.parent),
                  mock.patch.object(WORKER, "ISSUE_TRACKER_STAGE_L_STATUS_FILE",
                                    stage_status_path)):
                lane_result = WORKER._publish_stage_l_local_after_completion(self.store)
            if replayed_auto:
                self.assertIsNone(lane_result)
                self.assertEqual("hold", json.loads(stage_status_path.read_bytes())["state"])
                self.assertEqual(before_runtime_entry,
                                 tuple(sorted(generation_root.iterdir())))
                return
            # Direct C6 image replay remains a no-op above; an automatic lane
            # must not treat that prior manual RECEIPT as a new admission.
            self.assertIsNone(lane_result)
            self.assertEqual("hold", json.loads(stage_status_path.read_bytes())["state"])
            self.assertEqual(before_runtime_entry,
                             tuple(sorted(generation_root.iterdir())))
            try:
                self.template.write_bytes(fake_workbook(
                    whitelist_rules=("leaf-z",), reserved_switch_rows=4,
                ))
                skipped_snapshot = read_whitelist_workbook(self.template)
                skipped_args = {**args, "whitelist_snapshot": skipped_snapshot}
                eth_skipped = qualify_prod_stage_l(self.store, **skipped_args)
                self.assertEqual(protected_time, eth_skipped.recorded_at_utc)
                self.assertEqual(
                    (("eth_cabling", ("leaf-a", "swp1", "leaf-z", "swp2"),
                      "leaf-z"),),
                    tuple((skip.source, skip.endpoints, skip.matched_rule)
                          for skip in eth_skipped.whitelist_skips),
                )
                self.assertTrue(all(skip.activity_key is None
                                    and skip.record_id is None
                                    for skip in eth_skipped.whitelist_skips))
                eth_metadata = {
                    **metadata,
                    "template_sha256": skipped_snapshot.workbook_sha256,
                }
                eth_body, eth_digest = freeze_prod_stage_l_manifest(
                    eth_skipped, self.store, metadata=eth_metadata,
                    expected_template_sha256=skipped_snapshot.workbook_sha256,
                    **skipped_args,
                )
                self.assertEqual(hashlib.sha256(eth_body).hexdigest(), eth_digest)
                self.assertEqual([{
                    "source": "eth_cabling",
                    "endpoints": ["leaf-a", "swp1", "leaf-z", "swp2"],
                    "matched_rule": "leaf-z",
                }], json.loads(eth_body)["qualified_source"]["whitelist_skips"])
                self.template.write_bytes(fake_workbook(
                    whitelist_rules=("leaf-a",), reserved_switch_rows=4,
                ))
                switch_snapshot = read_whitelist_workbook(self.template)
                switch_args = {**args, "whitelist_snapshot": switch_snapshot}
                switch_skipped = qualify_prod_stage_l(self.store, **switch_args)
                self.assertEqual(protected_time, switch_skipped.recorded_at_utc)
                self.assertEqual({
                    ("switch", "switch:leaf-a", None, "leaf-a"),
                    ("eth_cabling", None,
                     ("leaf-a", "swp1", "leaf-z", "swp2"), "leaf-a"),
                }, {
                    (skip.source, skip.record_id, skip.endpoints,
                     skip.matched_rule)
                    for skip in switch_skipped.whitelist_skips
                })
                self.assertTrue(all(skip.activity_key is None
                                    for skip in switch_skipped.whitelist_skips))
                with self.assertRaises((StageLConsumerHold, ValueError)):
                    freeze_prod_stage_l_manifest(
                        eth_skipped, self.store, metadata=eth_metadata,
                        expected_template_sha256=skipped_snapshot.workbook_sha256,
                        **skipped_args,
                    )
                switch_metadata = {
                    **metadata,
                    "template_sha256": switch_snapshot.workbook_sha256,
                }
                switch_body, switch_digest = freeze_prod_stage_l_manifest(
                    switch_skipped, self.store, metadata=switch_metadata,
                    expected_template_sha256=switch_snapshot.workbook_sha256,
                    **switch_args,
                )
                self.assertEqual(hashlib.sha256(switch_body).hexdigest(),
                                 switch_digest)
                self.assertEqual({
                    ("eth_cabling", "leaf-a", None),
                    ("switch", "leaf-a", "switch:leaf-a"),
                }, {
                    (item["source"], item["matched_rule"],
                     item.get("record_id"))
                    for item in json.loads(switch_body)["qualified_source"]
                    ["whitelist_skips"]
                })
                self.template.write_bytes(fake_workbook(
                    whitelist_rules=("re:^leaf-a$",), reserved_switch_rows=4,
                ))
                regex_snapshot = read_whitelist_workbook(self.template)
                regex_args = {**args, "whitelist_snapshot": regex_snapshot}
                regex_skipped = qualify_prod_stage_l(self.store, **regex_args)
                self.assertEqual(
                    {(skip.source, skip.record_id, skip.endpoints)
                     for skip in switch_skipped.whitelist_skips},
                    {(skip.source, skip.record_id, skip.endpoints)
                     for skip in regex_skipped.whitelist_skips},
                )
                self.assertEqual({"re:^leaf-a$"},
                                 {skip.matched_rule for skip in
                                  regex_skipped.whitelist_skips})
                with self.assertRaises((StageLConsumerHold, ValueError)):
                    freeze_prod_stage_l_manifest(
                        switch_skipped, self.store, metadata=switch_metadata,
                        expected_template_sha256=switch_snapshot.workbook_sha256,
                        **switch_args,
                    )
            finally:
                self.template.write_bytes(original_template)
            self.template.write_bytes(fake_workbook(
                whitelist_rules=("leaf-z",), reserved_switch_rows=4,
            ))
            with self.assertRaises((StageLConsumerHold, ValueError)):
                freeze_prod_stage_l_manifest(
                    qualified, self.store, metadata=metadata,
                    expected_template_sha256=self.snapshot.workbook_sha256,
                    **args,
                )
            self.template.write_bytes(fake_workbook(reserved_switch_rows=4))
            latest = artifacts["ethernet/prod"]["info"]
            original = latest.read_bytes()
            latest.write_bytes(original + b"late byte drift")
            with self.assertRaises((StageLConsumerHold, ValueError)):
                freeze_prod_stage_l_manifest(
                    qualified, self.store, metadata=metadata,
                    expected_template_sha256=self.snapshot.workbook_sha256,
                    **args,
                )
            latest.write_bytes(original)
            with tracker_writer(project, self.publication) as token:
                set_k(token, new_k=2, actor="operator:fixture",
                      recorded_at="2026-09-25T00:02:00Z",
                      request_id="req7-three-panel-k2", expected_revision=1)
            with self.assertRaises((StageLConsumerHold, ValueError)):
                freeze_prod_stage_l_manifest(
                    qualified, self.store, metadata=metadata,
                    expected_template_sha256=self.snapshot.workbook_sha256,
                    **args,
                )

    def _verify_protected_skip_commit(self, project, args):
        from monitor.issue_tracker_publish_runtime import local_publish_interval
        from monitor.issue_tracker_local_workbook_commit import (
            CommittedProdWorkbook, ProdWorkbookNoop,
            commit_prod_stage_l_workbook,
        )
        from monitor.issue_tracker_manifest import freeze_prod_stage_l_manifest
        from monitor.issue_tracker_stage_l_consumer import qualify_prod_stage_l
        from monitor.issue_tracker_state_owner import tracker_writer

        self.template.write_bytes(fake_workbook(
            whitelist_rules=("leaf-a",), reserved_switch_rows=4,
        ))
        self.snapshot = read_whitelist_workbook(self.template)
        args = {**args, "whitelist_snapshot": self.snapshot}
        qualified = qualify_prod_stage_l(self.store, **args)
        self.assertEqual({"eth_cabling", "switch"},
                         {skip.source for skip in qualified.whitelist_skips})
        metadata = {
            "project_id": str(project), "schema_version": 1,
            "producer_version": "req7-test-producer",
            "template_contract_version": "v1",
            "template_sha256": self.snapshot.workbook_sha256,
        }
        body, manifest_id = freeze_prod_stage_l_manifest(
            qualified, self.store, metadata=metadata,
            expected_template_sha256=self.snapshot.workbook_sha256,
            **args,
        )
        self.assertEqual(hashlib.sha256(body).hexdigest(), manifest_id)
        interval, policy_sha = local_publish_interval(project)
        manual_witness = (policy_sha, interval, "fixture-boot",
                          time.monotonic_ns())
        with tracker_writer(project, self.publication) as token:
            committed = commit_prod_stage_l_workbook(
                token, qualified, self.store, template_path=self.template,
                metadata=metadata,
                expected_template_sha256=self.snapshot.workbook_sha256,
                manual_admission=manual_witness,
                **args,
            )
        self.assertIsInstance(committed, CommittedProdWorkbook)
        self.assertEqual(manifest_id, committed.receipt.manifest_id)
        with zipfile.ZipFile(BytesIO(self.template.read_bytes())) as before, \
             zipfile.ZipFile(BytesIO(committed.prepared.xlsx_bytes)) as after:
            history = after.read("xl/worksheets/sheet6.xml")
            self.assertIn(b"Whitelist Skip", history)
            self.assertIn(manifest_id.encode("ascii"), history)
            self.assertIn(qualified.recorded_at_utc.encode("ascii"), history)
            self.assertIn(b"switch:leaf-a", history)
            self.assertIn(b"leaf-z", history)
            self.assertIn(b"matched_rule=leaf-a", history)
            self.assertEqual(before.read("xl/worksheets/sheet3.xml"),
                             after.read("xl/worksheets/sheet3.xml"))
            self.assertNotIn(b"leaf-a", after.read("xl/worksheets/sheet2.xml"))
        with tracker_writer(project, self.publication) as token:
            no_op = commit_prod_stage_l_workbook(
                token, qualified, self.store, template_path=self.template,
                metadata=metadata,
                expected_template_sha256=self.snapshot.workbook_sha256,
                **args,
            )
        self.assertIsInstance(no_op, ProdWorkbookNoop)
        self.assertEqual("no_change", no_op.status)

    def _verify_two_cycle_latest_local_commit(self, project, args, cycle_ids):
        from monitor.issue_tracker_stage_l_consumer import qualify_prod_stage_l
        from monitor.issue_tracker_manifest import freeze_prod_stage_l_manifest
        from monitor.issue_tracker_local_workbook_commit import (
            CommittedProdWorkbook, commit_prod_stage_l_workbook,
        )
        from monitor.issue_tracker_publish_runtime import local_publish_interval
        from monitor.issue_tracker_state_owner import tracker_writer
        import xml.etree.ElementTree as ET

        qualified = qualify_prod_stage_l(self.store, **args)
        self.assertTrue(qualified.qualified)
        self.assertEqual(cycle_ids, qualified.cycle_ids)
        self.assertEqual(2, self.settings.k)
        self.assertEqual(4, len(qualified.candidates))
        by_key = {item.activity_key: item for item in qualified.candidates}
        self.assertEqual({
            ("eth_cabling", "leaf-a", "swp1", "Mis-wiring"),
            ("ib_cabling", "leaf01", "sw1p1", "Mis-wiring"),
            ("switch", "leaf-a", "fan", "PSU1/FAN1"),
            ("switch", "nvsw01", "asic_temp", "ASIC1"),
        }, set(by_key))
        eth = by_key[("eth_cabling", "leaf-a", "swp1", "Mis-wiring")]
        ib = by_key[("ib_cabling", "leaf01", "sw1p1", "Mis-wiring")]
        self.assertEqual(("leaf-a", "swp1", "leaf-z", "swp2"), eth.expected_endpoints)
        self.assertEqual(("changed-peer", "swp9", "leaf-a", "swp1"), eth.actual_endpoints)
        # Match the literal planned P2P switch port, not the raw vendor ordinal.
        self.assertEqual(("leaf01", "sw1p1", "server01", "mlx5_0"), ib.expected_endpoints)
        self.assertEqual(("leaf01", "sw1p1", "server03", "mlx5_1"), ib.actual_endpoints)
        asic = by_key[("switch", "nvsw01", "asic_temp", "ASIC1")]
        self.assertIn("81", asic.evidence_description)
        self.assertNotIn("75", asic.evidence_description)
        original_template = self.template.read_bytes()
        metadata = {
            "project_id": str(project), "schema_version": 1,
            "producer_version": "req7-test-producer",
            "template_contract_version": "v1",
            "template_sha256": self.snapshot.workbook_sha256,
        }
        before = tuple(sorted(self.publication.iterdir()))
        body, digest = freeze_prod_stage_l_manifest(
            qualified, self.store, metadata=metadata,
            expected_template_sha256=self.snapshot.workbook_sha256, **args,
        )
        self.assertEqual(before, tuple(sorted(self.publication.iterdir())))
        self.assertEqual(hashlib.sha256(body).hexdigest(), digest)
        (project / "01-global.yaml").write_text(
            "schema_version: 2\ncommon:\n  mgmt:\n"
            "    issue-tracker:\n      status: disabled\n", encoding="utf-8",
        )
        interval, policy_sha = local_publish_interval(project)
        witness = (policy_sha, interval, "fixture-boot", time.monotonic_ns())
        with tracker_writer(project, self.publication) as token:
            committed = commit_prod_stage_l_workbook(
                token, qualified, self.store, template_path=self.template,
                metadata=metadata,
                expected_template_sha256=self.snapshot.workbook_sha256,
                manual_admission=witness, **args,
            )
        self.assertIsInstance(committed, CommittedProdWorkbook)
        self.assertEqual(3, committed.prepared.source_family_count)
        self.assertEqual(digest, committed.receipt.manifest_id)
        self.assertEqual(hashlib.sha256(committed.prepared.xlsx_bytes).hexdigest(),
                         committed.receipt.published_sha256)
        generation = project / ".tracker/generations" / committed.generation.generation_id
        self.assertEqual(body, (generation / "MANIFEST").read_bytes())
        receipt = json.loads((generation / "RECEIPT").read_bytes())
        self.assertEqual(digest, receipt["manifest_id"])
        self.assertEqual(committed.receipt.published_sha256, receipt["published_sha256"])
        published_bytes = (self.publication / receipt["published"]).read_bytes()
        self.assertEqual(committed.prepared.xlsx_bytes, published_bytes)
        self.assertEqual(hashlib.sha256(published_bytes).hexdigest(),
                         committed.receipt.published_sha256)
        self.assertEqual(original_template, self.template.read_bytes())
        ns = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}

        def cells(archive, sheet):
            root = ET.fromstring(archive.read("xl/worksheets/" + sheet))
            return {node.attrib["r"]: node for node in root.findall(".//s:c", ns)}

        def text_value(node):
            return "".join(node.itertext())

        with zipfile.ZipFile(BytesIO(original_template)) as template, \
             zipfile.ZipFile(BytesIO(published_bytes)) as published:
            for sheet, expected in (
                ("sheet3.xml", {"M3": "changed-peer", "N3": "swp9",
                                "S3": "leaf-a", "T3": "swp1"}),
                ("sheet4.xml", {"M3": "leaf01", "N3": "sw1p1",
                                "S3": "server03", "T3": "mlx5_1"}),
            ):
                actual_cells = cells(published, sheet)
                for address, expected_value in expected.items():
                    self.assertEqual(expected_value, text_value(actual_cells[address]), address)
            old_switch, new_switch = cells(template, "sheet2.xml"), cells(published, "sheet2.xml")
            for address in ("D3", "E3", "G3", "H3", "I3", "O3", "U3"):
                self.assertEqual(ET.tostring(old_switch[address]),
                                 ET.tostring(new_switch[address]), address)
            for row in range(4, 8):
                for column in "DEGH":
                    address = f"{column}{row}"
                    self.assertEqual(ET.tostring(old_switch[address]),
                                     ET.tostring(new_switch[address]), address)
            asic_rows = [address[1:] for address, node in new_switch.items()
                         if address.startswith("F") and text_value(node) == "nvsw01"]
            self.assertEqual(1, len(asic_rows))
            description = text_value(new_switch["L" + asic_rows[0]])
            self.assertIn("81", description)
            self.assertNotIn("75", description)

    def test_frozen_template_fabric_is_projected_with_strict_type_precedence(self):
        from monitor.issue_tracker_stage_l_consumer import (
            inspect_prod_stage_l_composed_sources,
            project_prod_stage_l_source_candidates,
        )

        self.two_cycles(activity=True, derivation=True,
                        fabric_templates={"ethernet/prod": "tan-leaf",
                                          "nvlink/prod": "border-leaf"})
        cycles = read_completed_cycle_evidence(self.store)
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                f"{cycle.sequence}" * 64, "a" * 64, (),
            ) for cycle in cycles
        }
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            source = inspect_prod_stage_l_composed_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
            projection = project_prod_stage_l_source_candidates(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
        fabrics = {(item.activity_key[1], item.fabric, item.fabric_source)
                   for item in projection.candidates
                   if item.panel == "Switch Status"}
        self.assertEqual({("leaf-a", "Inband", "template"),
                          ("nvsw01", "Compute", "type")}, fabrics)
        self.assertEqual("qualification_not_implemented", projection.reason)
        self.assertEqual(0, projection.hostname_fallback_count)
        self.assertFalse(projection.qualified)
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_source_projection_displays_eth_w1_skip_without_issue_or_permit(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_composed_sources,
            project_prod_stage_l_source_candidates,
            validate_prod_stage_l_source_projection,
        )

        self.template.write_bytes(literal_xlsx(rules=("leaf-z",)))
        self.snapshot = read_whitelist_workbook(self.template)
        self.two_cycles(activity=True, derivation=True)
        cycles = read_completed_cycle_evidence(self.store)
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                f"{cycle.sequence}" * 64, "a" * 64, (),
            ) for cycle in cycles
        }
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            source = inspect_prod_stage_l_composed_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
            projection = project_prod_stage_l_source_candidates(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
        self.assertFalse(projection.qualified)
        self.assertEqual("hold", projection.state)
        self.assertFalse(any(item.panel == "Eth Link Validation"
                             for item in projection.candidates))
        self.assertEqual(1, len(projection.whitelist_skips))
        self.assertEqual(("eth_cabling", ("leaf-a", "swp1", "leaf-z", "swp2")),
                         (projection.whitelist_skips[0].source,
                          projection.whitelist_skips[0].endpoints))
        self.assertEqual("leaf-z", projection.whitelist_skips[0].matched_rule)
        self.template.write_bytes(literal_xlsx(rules=("leaf-a",)))
        changed_snapshot = read_whitelist_workbook(self.template)
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            with self.assertRaisesRegex(
                StageLConsumerHold, "changed|disagree|unsafe",
            ):
                validate_prod_stage_l_source_projection(
                    projection, source, self.store, http_root=self.root,
                    settings=self.settings, whitelist_snapshot=changed_snapshot,
                    whitelist_path=self.template,
                )
            changed_source = inspect_prod_stage_l_composed_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=changed_snapshot,
                whitelist_path=self.template,
            )
            changed = project_prod_stage_l_source_candidates(
                changed_source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=changed_snapshot,
                whitelist_path=self.template,
            )
        self.assertEqual(projection.whitelist_skips[0].endpoints,
                         changed.whitelist_skips[0].endpoints)
        self.assertEqual("leaf-a", changed.whitelist_skips[0].matched_rule)
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_source_projection_reopens_w1_and_latest_completed_source_bytes(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_composed_sources,
            project_prod_stage_l_source_candidates,
            validate_prod_stage_l_source_projection,
        )

        _, _, artifacts = self.two_cycles(activity=True, derivation=True)
        cycles = read_completed_cycle_evidence(self.store)
        row = IbReportLink(
            "Mis-wiring", ("leaf-ib", "1/1", "server01", "mlx5_0"),
            ("server02", "mlx5_1"), "Miswired_Links", 2,
        )
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                f"{cycle.sequence}" * 64, "a" * 64, (row,),
            ) for cycle in cycles
        }
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            source = inspect_prod_stage_l_composed_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
            projection = project_prod_stage_l_source_candidates(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
            self.assertFalse(projection.qualified)
            self.template.write_bytes(literal_xlsx(rules=("leaf-z",)))
            with self.assertRaises(StageLConsumerHold):
                project_prod_stage_l_source_candidates(
                    source, self.store, http_root=self.root,
                    settings=self.settings, whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template,
                )
            with self.assertRaises(StageLConsumerHold):
                validate_prod_stage_l_source_projection(
                    projection, source, self.store, http_root=self.root,
                    settings=self.settings, whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template,
                )
            self.template.write_bytes(literal_xlsx())
            latest = artifacts["ethernet/prod"]["info"]
            latest.write_bytes(latest.read_bytes() + b"late byte drift")
            with self.assertRaises(StageLConsumerHold):
                project_prod_stage_l_source_candidates(
                    source, self.store, http_root=self.root,
                    settings=self.settings, whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template,
                )
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_source_projection_preserves_switch_device_level_w1_record_id(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_composed_sources,
            project_prod_stage_l_source_candidates,
            validate_prod_stage_l_source_projection,
        )

        self.template.write_bytes(literal_xlsx(rules=("leaf-a",)))
        self.snapshot = read_whitelist_workbook(self.template)
        self.two_cycles(activity=True, derivation=True,
                        fabric_templates={"ethernet/prod": "tan-leaf",
                                          "nvlink/prod": "border-leaf"})
        cycles = read_completed_cycle_evidence(self.store)
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                f"{cycle.sequence}" * 64, "a" * 64, (),
            ) for cycle in cycles
        }
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            source = inspect_prod_stage_l_composed_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
            projection = project_prod_stage_l_source_candidates(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
            switch_skips = tuple(skip for skip in projection.whitelist_skips
                                 if skip.source == "switch")
            self.assertEqual(1, len(switch_skips))
            self.assertEqual(("switch:leaf-a", "leaf-a", None),
                             (switch_skips[0].record_id,
                              switch_skips[0].matched_rule,
                              switch_skips[0].endpoints))
            self.assertFalse(projection.qualified)
            self.template.write_bytes(literal_xlsx(rules=("re:^leaf-a$",)))
            changed_snapshot = read_whitelist_workbook(self.template)
            with self.assertRaises(StageLConsumerHold):
                validate_prod_stage_l_source_projection(
                    projection, source, self.store, http_root=self.root,
                    settings=self.settings,
                    whitelist_snapshot=changed_snapshot,
                    whitelist_path=self.template,
                )

    def test_prod_three_source_domains_join_exact_k_without_qualification(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold,
            inspect_prod_stage_l_composed_sources,
            project_prod_stage_l_source_candidates,
            validate_prod_stage_l_composed_sources,
            validate_prod_stage_l_source_projection,
        )

        self.two_cycles(activity=True, derivation=True)
        cycles = read_completed_cycle_evidence(self.store)
        row = IbReportLink(
            "Mis-wiring", ("leaf-ib", "1/1", "server01", "mlx5_0"),
            ("server02", "mlx5_1"), "Miswired_Links", 2,
        )
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                f"{cycle.sequence}" * 64, "a" * 64, (row,),
            ) for cycle in cycles
        }
        # Only the protected IB report decoder is substituted. This tests
        # composition, not true nine-role IB provenance or Stage-L acceptance.
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            source = inspect_prod_stage_l_composed_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
            self.assertEqual(tuple(cycle.cycle_id for cycle in cycles),
                             source.eth_link_source.cycle_ids)
            self.assertEqual(source.switch_ib_source.switch_source.cycle_ids,
                             source.eth_link_source.cycle_ids)
            self.assertEqual("WRONG_PEER",
                             source.eth_link_source.persistent_links[0].status)
            self.assertEqual(("Miswired_Links", "Mis-wiring"),
                             (source.eth_issue_rows[0].source_sheet,
                              source.eth_issue_rows[0].issue_type))
            self.assertFalse(source.eth_issue_rows[0].qualified)
            self.assertEqual((row,), source.switch_ib_source.ib_source.kept_rows)
            self.assertFalse(source.qualified)
            self.assertEqual("hold", source.state)
            self.assertEqual("qualification_not_implemented", source.reason)
            self.assertEqual(source, validate_prod_stage_l_composed_sources(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            ))
            projection = project_prod_stage_l_source_candidates(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
            self.assertFalse(projection.qualified)
            self.assertEqual("hold", projection.state)
            self.assertEqual("fabric_identity_unresolved", projection.reason)
            self.assertEqual({"Switch Status", "Eth Link Validation",
                              "IB Link Validation"},
                             {item.panel for item in projection.candidates})
            eth = [item for item in projection.candidates
                   if item.panel == "Eth Link Validation"]
            self.assertEqual(1, len(eth))
            self.assertEqual(("leaf-a", "swp1", "leaf-z", "swp2"),
                             eth[0].expected_endpoints)
            self.assertEqual(("foreign-z", "swp9", "leaf-a", "swp1"),
                             eth[0].actual_endpoints)
            self.assertEqual(("Miswired_Links", "Mis-wiring"),
                             (eth[0].source_sheet, eth[0].issue_type))
            self.assertEqual(
                "stl-" + hashlib.sha256(
                    b'["eth_cabling","leaf-a","swp1","Mis-wiring"]'
                ).hexdigest(),
                eth[0].operation_id,
            )
            self.assertFalse(any(item.qualified for item in projection.candidates))
            fabrics = {(item.activity_key[1], item.fabric, item.fabric_source)
                       for item in projection.candidates
                       if item.panel == "Switch Status"}
            self.assertIn(("nvsw01", "Compute", "type"), fabrics)
            self.assertIn(("leaf-a", None, None), fabrics)
            self.assertEqual(projection, validate_prod_stage_l_source_projection(
                projection, source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            ))
            with self.assertRaises(StageLConsumerHold):
                validate_prod_stage_l_source_projection(
                    replace(projection, qualified=True), source, self.store,
                    http_root=self.root, settings=self.settings,
                    whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template,
                )
            with self.assertRaises(StageLConsumerHold):
                project_prod_stage_l_source_candidates(
                    replace(source, qualified=True), self.store,
                    http_root=self.root, settings=self.settings,
                    whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template,
                )
            with self.assertRaises(StageLConsumerHold):
                project_prod_stage_l_source_candidates(
                    replace(source, eth_link_source=replace(
                        source.eth_link_source,
                        cycle_ids=("foreign-cycle", *source.eth_link_source.cycle_ids[1:]),
                    )), self.store, http_root=self.root,
                    settings=self.settings, whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template,
                )
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_real_cycles_and_durable_k_combine_switch_families_and_ib_only(self):
        from monitor.issue_tracker_stage_l_consumer import (
            inspect_prod_stage_l_bound_sources,
            validate_prod_stage_l_bound_sources,
        )

        self.two_cycles()
        cycles = read_completed_cycle_evidence(self.store)
        first = IbReportLink(
            "Mis-wiring", ("leaf-ib", "1/1", "server01", "mlx5_0"),
            ("server02", "mlx5_1"), "Miswired_Links", 2,
        )
        latest = IbReportLink(
            "Mis-wiring", first.expected_endpoints,
            ("server03", "mlx5_2"), "Miswired_Links", 3,
        )
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                f"{cycle.sequence}" * 64, "a" * 64,
                (first if index == 0 else latest,),
            ) for index, cycle in enumerate(cycles)
        }
        # This composition seam replaces protected IB report replay only;
        # it cannot be counted as real report-role or Stage-L acceptance.
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            source = inspect_prod_stage_l_bound_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
            self.assertEqual(tuple(cycle.cycle_id for cycle in cycles),
                             source.switch_source.cycle_ids)
            self.assertEqual((latest,), source.ib_source.kept_rows)
            self.assertFalse(source.qualified)
            self.assertEqual("hold", source.state)
            self.assertEqual("qualification_not_implemented", source.reason)
            self.assertEqual(source, validate_prod_stage_l_bound_sources(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            ))
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_real_prod_worker_emitter_cycles_with_unbound_ib_stay_read_only(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_sources,
            require_complete_stage_l_sources,
        )

        first, second, _artifacts = self.two_cycles()
        source = inspect_prod_stage_l_sources(
            self.store, http_root=self.root, settings=self.settings,
            whitelist_snapshot=self.snapshot, whitelist_path=self.template,
        )
        self.assertEqual((first["cycle_id"], second["cycle_id"]), source.cycle_ids)
        self.assertEqual("hold", source.state)
        self.assertEqual("ib_report_not_bound_to_completed_cycle", source.reason)
        self.assertFalse(source.qualified)
        self.assertEqual({"ethernet/prod", "nvlink/prod"},
                         {row.source_slot for row in source.switch_rows})
        with self.assertRaisesRegex(StageLConsumerHold,
                                    "IB report.*completed cycle"):
            require_complete_stage_l_sources(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
        self.assertEqual((), tuple(self.publication.iterdir()))


if __name__ == "__main__":
    unittest.main()
