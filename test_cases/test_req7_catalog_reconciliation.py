"""ALL catalog originals survive fixed four-read reconciliation and append."""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import hashlib
import importlib
import json
import socket
import unittest
from unittest import mock

from test_cases import test_req7_online_reconciliation as fixture
from test_cases.test_req7_global_attempt_journal import original_read_files


class CatalogReconciliationDirectTests(unittest.TestCase):
    def test_manifest_registers_one_primary_and_actual_all_catalog_workflow(self):
        from pathlib import Path
        registry = json.loads((Path(__file__).resolve().parent/'script_test_manifest.json').read_text())
        test = 'test_cases.test_req7_catalog_reconciliation'
        self.assertEqual(['issue-tracker-local'],
            [suite['id'] for suite in registry['test_suites'] if test in suite['tests']])
        self.assertTrue(any('monitor/issue_tracker_remote_history_match.py' in rule['paths']
            and test in rule['tests'] for rule in registry['test_rules']))
        required = {'monitor/issue_tracker_remote_history_match.py', 'monitor/issue_tracker_unit_catalog.py',
            'monitor/issue_tracker_retained_inventory.py', 'monitor/issue_tracker_local_commit.py',
            'monitor/issue_tracker_token_launcher.py', 'monitor/issue_tracker_history_read_launcher.py'}
        self.assertTrue(any(required <= set(item['members']) and test in item['tests']
            for item in registry['workflows']))

    def api(self):
        module = importlib.import_module('monitor.issue_tracker_remote_history_match')
        api = getattr(module, 'reconcile_pending_project_units', None)
        self.assertTrue(callable(api), 'actual catalog must select retained project units, not caller generation')
        return module, api

    def test_unheld_writer_refuses_before_catalog_auth_or_read(self):
        module, api = self.api()
        from monitor import issue_tracker_unit_catalog as catalog
        from monitor import issue_tracker_history_read_launcher as reads
        with mock.patch.object(catalog, '_inspect') as inspect, \
                mock.patch.object(reads, 'OwnedProjectSheetsReadUnit') as read:
            with self.assertRaises(module.RemoteHistoryHold) as caught:
                api(object(), object(), object(), object())
        inspect.assert_not_called(); read.assert_not_called()
        self.assertIsNone(caught.exception.__context__)

    def test_public_all_readers_still_reject_caller_namespace_allowances(self):
        import inspect
        from monitor import issue_tracker_unit_catalog as catalog
        for api in (catalog.hold_pending_units, catalog.hold_pending_project_origins,
                    catalog.hold_pending_project_c6_units):
            self.assertEqual(('token', 'binding'), tuple(inspect.signature(api).parameters))


class DefaultOriginalDispatchDirectTests(unittest.TestCase):
    def api(self):
        from test_cases.test_collection_cycle_persistence import WORKER
        api=getattr(WORKER,'_dispatch_current_project_online_originals',None)
        self.assertTrue(callable(api),'fixed dispatch must remain inside the original live input context')
        return WORKER,api

    def test_fixed_driver_rejects_unissued_and_caller_admission_inputs(self):
        import inspect
        worker,api=self.api()
        from monitor import issue_tracker_remote_history_match as remote
        self.assertEqual(('writer_token','owner_token','binding','authentication','_store','http_root'),
            tuple(inspect.signature(api).parameters))
        with self.assertRaises(remote.RemoteHistoryHold):
            api(object(),object(),object(),None,_store=object(),http_root=object())
        for claims in ({'unit':object()},{'boot_id':'caller-boot'},{'monotonic_ns':1},
                {'allow_send':True},{'verify':lambda:None}):
            with self.subTest(claim=tuple(claims)),self.assertRaises(TypeError):
                api(object(),object(),object(),None,_store=object(),http_root=object(),**claims)

    def exercise(self,*,count=0,budget_kind='DEDICATED_PROJECT_CAPACITY',complete=True,exit_error=None):
        # These synthetic packets prove orchestration only. The separate native
        # workflow must exercise actual C6/issued reads/COUNT/CLAIM/TLS originals.
        from pathlib import Path
        from types import SimpleNamespace as N
        worker,api=self.api()
        from monitor import issue_tracker_remote_history_match as remote
        from monitor import issue_tracker_global_attempt_journal as journal
        from monitor import issue_tracker_mutation_launcher as mutation
        events=[];writer=object();owner=object();binding=object();store=object();unit=object()
        settings=object();source=object();whitelist=N(workbook_sha256='a'*64)
        auth=N(token=object());identity=object();history=object();business=({},)
        responses={kind:object() for kind in ('template_headers','whitelist','metadata')}
        responses['template_identity']=identity
        budget=None if budget_kind is None else N(outcome=budget_kind,inventory_complete=complete)
        def verify():events.append('image-verify')
        def old_guard():self.fail('closed strict business guard must not be revived')
        @contextmanager
        def inputs(*arguments,**options):
            self.assertEqual((writer,owner,binding,None),arguments)
            self.assertEqual({'_store':store,'http_root':Path('/fixed-http')},options)
            events.append('input-enter')
            yield settings,whitelist,responses,(N(unit=unit),source,old_guard,(identity,history,business),verify),auth,budget
            events.append('input-exit')
            if exit_error is not None:raise exit_error
        image=object();completion=object();seen=[]
        @contextmanager
        def lane(*arguments,**options):
            self.assertEqual((owner,binding,unit),arguments);seen.append(options)
            self.assertIs(writer,options['writer_token']);self.assertIs(source,options['qualified_source'])
            self.assertIs(store,options['store']);self.assertIs(settings,options['settings'])
            self.assertIs(whitelist,options['whitelist_snapshot']);self.assertIs(business,options['business_reads'])
            self.assertIs(identity,options['identity_response']);self.assertIs(history,options['history_response'])
            self.assertEqual('a'*64,options['expected_template_sha256'])
            self.assertEqual(Path('/fixed-http/monitor/Issue_Tracker_Template_v1.xlsx'),options['whitelist_path'])
            for kind in ('template_headers','whitelist','metadata'):
                key={'template_headers':'headers_response','whitelist':'whitelist_response','metadata':'metadata_response'}[kind]
                self.assertIs(responses[kind],options[key])
            events.append('lane-enter');yield image;events.append('lane-exit')
        def send(*arguments):
            self.assertEqual((writer,owner,binding,auth.token,unit,image),arguments)
            events.append('send');return completion
        with mock.patch.object(remote,'_hold_current_project_online_original_inputs',side_effect=inputs), \
                mock.patch.object(journal,'inspect_global_unit',return_value=N(attempt_count=count)) as inspected, \
                mock.patch.object(journal,'_hold_continuous_owned_attempt_wire',side_effect=lane) as first, \
                mock.patch.object(journal,'_hold_shared_retry_owned_attempt_wire',side_effect=lane) as retry, \
                mock.patch.object(mutation,'_send_counted_original_once',side_effect=send) as sender, \
                mock.patch.object(worker,'_current_boot_identity',return_value='actual-boot') as boot, \
                mock.patch.object(worker.time,'monotonic_ns',return_value=123456789) as clock:
            refused=budget is None or not complete or budget_kind!='DEDICATED_PROJECT_CAPACITY' or type(count) is not int or not 0<=count<6
            if refused or exit_error is not None:
                with self.assertRaises(type(exit_error) if isinstance(exit_error,(KeyboardInterrupt,SystemExit)) else remote.RemoteHistoryHold):
                    api(writer,owner,binding,None,_store=store,http_root=Path('/fixed-http'))
            else:self.assertIs(completion,api(writer,owner,binding,None,_store=store,http_root=Path('/fixed-http')))
            if refused:
                first.assert_not_called();retry.assert_not_called();sender.assert_not_called()
                boot.assert_not_called();clock.assert_not_called()
                if budget is None or not complete or budget_kind!='DEDICATED_PROJECT_CAPACITY':inspected.assert_not_called()
            else:
                sender.assert_called_once()
                self.assertEqual(['input-enter','image-verify','lane-enter','image-verify','send',
                    'image-verify','lane-exit','image-verify','input-exit'],events)
                if count==0:first.assert_called_once();retry.assert_not_called();boot.assert_not_called();clock.assert_not_called()
                else:
                    retry.assert_called_once();first.assert_not_called();boot.assert_called_once();clock.assert_called_once()
                    self.assertEqual(('actual-boot',123456789),(seen[0]['boot_id'],seen[0]['monotonic_ns']))

    def test_fixed_driver_never_counts_on_missing_stop_or_incomplete_quota(self):
        for kind,complete in ((None,True),('STOP_CAPACITY',True),('VISIBLE_ONLY_UNPROVED',True),('DEDICATED_PROJECT_CAPACITY',False)):
            with self.subTest(kind=kind,complete=complete):self.exercise(budget_kind=kind,complete=complete)

    def test_fixed_driver_uses_actual_first_or_shared_retry_once_and_refuses_exhaustion(self):
        for count in (0,1,5,6,-1,True,'1'):
            with self.subTest(count=count):self.exercise(count=count)

    def test_fixed_driver_waits_for_all_finalizers_and_preserves_operator_interrupt(self):
        for error in (ValueError('owned original cleanup fault'),KeyboardInterrupt(),SystemExit()):
            with self.subTest(error=type(error).__name__):self.exercise(exit_error=error)


class CatalogReconciliationWorkflowTests(unittest.TestCase):
    _Fixture = fixture.OnlineReconciliationWorkflowTests._Fixture
    setUp = fixture.OnlineReconciliationWorkflowTests.setUp
    server = fixture.OnlineReconciliationWorkflowTests.server
    owners = fixture.OnlineReconciliationWorkflowTests.owners
    intercept = fixture.OnlineReconciliationWorkflowTests.intercept
    child_fixture = fixture.OnlineReconciliationWorkflowTests.child_fixture
    certificates = fixture.OnlineReconciliationWorkflowTests.certificates
    read_owned = fixture.OnlineReconciliationWorkflowTests.read_owned
    prepare_owned = fixture.OnlineReconciliationWorkflowTests.prepare_owned
    project_auth = fixture.OnlineReconciliationWorkflowTests.project_auth
    api = CatalogReconciliationDirectTests.api

    def exercise(self, fault=None, *, other_project=False, lazy_auth=False, count_zero=False):
        module, api = self.api()
        from monitor import issue_tracker_unit_catalog as catalog
        from monitor import issue_tracker_history_read_launcher as reads
        from monitor import issue_tracker_spreadsheet_owner as ownership
        from monitor import issue_tracker_global_attempt_journal as globals_
        from monitor import issue_tracker_token_launcher as tokens
        real_owners = self.owners; captured = []; other_receipts = []
        def capture_owners(stack):
            actual = real_owners(stack); captured.append(actual[2]); return actual
        real_prepare = globals_.prepare_global_unit
        def register_then_prepare(owner, binding, unit):
            catalog.register_pending_c6_unit(captured[0], owner, binding, unit)
            if other_project:
                from test_cases.test_req7_send_unit import inputs as send_inputs
                from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
                project = self.root/'other-project'; project.mkdir(mode=0o700)
                publication = project/'publication'; publication.mkdir(mode=0o700)
                catalog.local.create_local_commit_store(project, publication)
                source = stack.enter_context(catalog.local.writer_owner(project, publication))
                arguments = send_inputs()
                arguments.update(spreadsheet_id=binding.spreadsheet_id, sheet_id=101, history_sheet_id=105,
                    target_nonce='a'*64, history_nonce='d'*64)
                generation = catalog.local.begin_generation(source, arguments['manifest'])
                catalog.local.record_intent(source, generation, literal_xlsx(), kind='xlsx')
                receipt = catalog.local.commit(source, generation)
                arguments.update(generation_id=generation.generation_id, publish_id=receipt.published_sha256)
                second = catalog.composer.freeze_send_unit(**arguments)
                catalog.register_pending_c6_unit(source, owner, binding, second)
                real_prepare(owner, binding, second)
                other_receipts.append(project/'.tracker/generations'/generation.generation_id/'RECEIPT')
            return real_prepare(owner, binding, unit)
        with ExitStack() as stack:
            if count_zero:
                # Setup a genuine initialized GLOBAL/History but no attempt.
                # The production reconciliation is never patched or given a
                # caller count; it must inspect that original count-zero state.
                stack.enter_context(mock.patch.object(globals_, 'record_global_attempt_intent'))
            with mock.patch.object(self, 'owners', side_effect=capture_owners), \
                    mock.patch.object(globals_, 'prepare_global_unit', side_effect=register_then_prepare):
                writer, owner, bound, _old_auth, _config, unit, docs = self.prepare_owned(stack, native_generation=True)
            refreshes = []; authentications = []
            if not lazy_auth:
                auth, _credential, _raw = self.project_auth(stack, ownership, owner, bound)
                self.certificates('sheets.googleapis.com')
            else:
                real_refresh = tokens.OwnedProjectTokenRefreshUnit.refresh_once
                def refresh_actual(refresh_unit):
                    refreshes.append((refresh_unit._owner_token is owner, refresh_unit._binding == bound))
                    # The fixture owns only TLS/credentials/DNS/child mapping;
                    # call the same genuine fixed OAuth implementation, not an
                    # issued-object substitute or a caller authentication plan.
                    with mock.patch.object(tokens.OwnedProjectTokenRefreshUnit, 'refresh_once', real_refresh):
                        value, _credential, _raw = self.project_auth(stack, ownership, owner, bound)
                    self.certificates('sheets.googleapis.com')
                    authentications.append(value)
                    return value
                stack.enter_context(mock.patch.object(tokens.OwnedProjectTokenRefreshUnit, 'refresh_once',
                    autospec=True, side_effect=refresh_actual))
            state = self.root/'var/lib/http-ztp-container/issue-tracker'
            stem = hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
            prefix = stem+'.unit-'+unit.unit_id
            origin = state/(prefix+'.project-origin')/'ORIGIN'
            before = original_read_files(self.root); reads_seen = []; replaced = []
            if lazy_auth:
                # Synthetic TLS certificates are regenerated when the owned
                # destination changes. Keep every business/origin/state image,
                # policy and fixed enumeration; certificates are not journals.
                before = {name: raw for name, raw in before.items()
                    if name.startswith(('project/', 'other-project/', 'var/lib/http-ztp-container/'))}
            documents = {kind: deepcopy(doc) for kind, doc in docs.values()}
            if fault == 'missing-fence': documents['metadata']['matchedDeveloperMetadata'].pop()
            actual_read = reads.OwnedProjectSheetsReadUnit.read_once
            def read_actual(reader):
                body = json.dumps(documents[reader._kind], separators=(',', ':')).encode()
                reply = b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
                with self.server(reply, hostname='sheets.googleapis.com', destination='sheets.googleapis.com') as (records, errors), ExitStack() as launched:
                    port = socket.getaddrinfo('sheets.googleapis.com', 443)[0][4][1]
                    calls, children = self.intercept(launched, self.child_fixture(port), writer, owner, bound)
                    value = actual_read(reader)
                reads_seen.append((reader._kind, len(records), len(calls), tuple(type(error).__name__ for error in errors), children[0].returncode))
                if fault == 'other-receipt-rebind' and reader._kind == 'history_tail':
                    path = other_receipts[0]; raw = path.read_bytes(); old = path.stat().st_ino
                    path.rename(self.root/'preserved-other-receipt'); path.write_bytes(raw); path.chmod(0o600)
                    replaced.append((old, path.stat().st_ino))
                return value
            actual_creator = module._hold_created_completion_evidence
            if fault == 'completion-capture-rebind':
                actual_file = catalog._Originals.file
                def capture_then_rebind(held, parent, name, limit):
                    value = actual_file(held, parent, name, limit)
                    marker = state/(prefix+'.completion')/'COMPLETE'
                    if name == 'COMPLETE' and marker.is_file() and not replaced:
                        raw = marker.read_bytes(); old = marker.stat().st_ino
                        marker.rename(self.root/'preserved-capture-complete'); marker.write_bytes(raw); marker.chmod(0o600)
                        replaced.append((old, marker.stat().st_ino))
                    return value
                stack.enter_context(mock.patch.object(catalog._Originals, 'file', autospec=True, side_effect=capture_then_rebind))
            @contextmanager
            def creator_then_fault(*args, **kwargs):
                with actual_creator(*args, **kwargs) as actual:
                    if fault == 'third-name':
                        (state/(stem+'.foreign-name')).write_bytes(b'owned unexpected name')
                    if fault == 'origin-rebind':
                        raw = origin.read_bytes(); old = origin.stat().st_ino
                        origin.rename(self.root/'preserved-origin'); origin.write_bytes(raw); origin.chmod(0o600)
                        replaced.append((old, origin.stat().st_ino))
                    yield actual
            with mock.patch.object(reads.OwnedProjectSheetsReadUnit, 'read_once', autospec=True, side_effect=read_actual), \
                    mock.patch.object(module, '_hold_created_completion_evidence', side_effect=creator_then_fault):
                if fault in ('third-name', 'origin-rebind', 'other-receipt-rebind', 'completion-capture-rebind'):
                    with self.assertRaises(module.RemoteHistoryHold) as caught:
                        if lazy_auth:
                            api(writer, owner, bound)
                        else:
                            api(writer, owner, bound, auth)
                    self.assertIsNone(caught.exception.__context__)
                else:
                    result = api(writer, owner, bound) if lazy_auth else api(writer, owner, bound, auth)
            # Outside every production normalization scope: actual four owned
            # TLS requests, cleanup, original count and persisted safety facts.
            self.assertEqual([] if count_zero else [(kind, 1, 1, (), 0) for kind in
                ('template_identity', 'template_headers', 'metadata', 'history_tail')], reads_seen)
            self.assertEqual([] if not lazy_auth or count_zero else [(True, True)], refreshes)
            # A deliberately invalid shared namespace/origin must itself make
            # high-level inventory inspection HOLD. Inspect the retained raw
            # attempt instead, not a permission from that invalid inventory.
            attempts = sorted((state/(prefix+'.journal')).glob('ATTEMPT-*'))
            self.assertEqual([] if count_zero else ['ATTEMPT-1'], [path.name for path in attempts])
            if count_zero:
                self.assertEqual((), result)
                self.assertTrue(before.items() <= original_read_files(self.root).items())
                self.assertFalse((state/(prefix+'.completion')).exists())
                self.assertFalse((self.root/'project/.tracker'/('REMOTE-APPLIED-'+unit.unit_id)).exists())
                return
            self.assertEqual('UNKNOWN', json.loads(attempts[0].read_bytes())['outcome'])
            old_attempts = {name: raw for name, raw in before.items() if '/ATTEMPT-' in name}
            self.assertTrue(old_attempts)
            self.assertTrue(old_attempts.items() <= original_read_files(self.root).items())
            if fault not in ('third-name', 'origin-rebind', 'other-receipt-rebind', 'completion-capture-rebind'):
                self.assertEqual((1, 'UNKNOWN'), (globals_.inspect_global_unit(owner, bound, unit).attempt_count,
                    globals_.inspect_global_unit(owner, bound, unit).outcome))
            key = self.root/'project/.tracker'/('REMOTE-KEY-HIGH-WATER-'+unit.unit_id)
            applied = self.root/'project/.tracker'/('REMOTE-APPLIED-'+unit.unit_id)
            if fault is None:
                self.assertEqual(1, len(result))
                self.assertEqual(('APPLIED', unit.unit_id, ('switch:0001',)),
                    (result[0].state, result[0].unit_id, result[0].applied_operation_ids))
                self.assertTrue(key.is_file()); self.assertTrue(applied.is_file())
                self.assertTrue((state/(prefix+'.completion')/'COMPLETE').is_file())
                self.assertTrue(before.items() <= original_read_files(self.root).items())
                with mock.patch.object(reads, 'OwnedProjectSheetsReadUnit') as no_new:
                    self.assertEqual(result, api(writer, owner, bound,
                        authentications[0] if lazy_auth else auth))
                no_new.assert_not_called()
            else:
                self.assertFalse(key.exists()); self.assertFalse(applied.exists())
                if fault == 'missing-fence':
                    self.assertEqual(('UNKNOWN',), tuple(item.state for item in result))
                    self.assertEqual(before, original_read_files(self.root))
                elif fault == 'origin-rebind':
                    self.assertEqual(1, len(replaced)); self.assertNotEqual(*replaced[0])
                    self.assertEqual(origin.read_bytes(), (self.root/'preserved-origin').read_bytes())
                elif fault == 'other-receipt-rebind':
                    self.assertEqual(1, len(replaced)); self.assertNotEqual(*replaced[0])
                    self.assertEqual(other_receipts[0].read_bytes(), (self.root/'preserved-other-receipt').read_bytes())
                    self.assertFalse((state/(prefix+'.completion')).exists())
                elif fault == 'completion-capture-rebind':
                    self.assertEqual(1, len(replaced)); self.assertNotEqual(*replaced[0])
                    self.assertEqual((state/(prefix+'.completion')/'COMPLETE').read_bytes(),
                        (self.root/'preserved-capture-complete').read_bytes())
                else:
                    self.assertTrue(before.items() <= original_read_files(self.root).items())

    def test_actual_all_catalog_c6_four_reads_and_creator_append_settle_without_releasing_unknown(self): self.exercise()
    def test_absent_fence_leaves_actual_catalog_unchanged_unknown(self): self.exercise('missing-fence')
    def test_creator_third_shared_name_holds_before_applied(self): self.exercise('third-name')
    def test_original_origin_rebind_during_actual_creator_holds_before_applied(self): self.exercise('origin-rebind')
    def test_actual_foreign_pending_c6_is_held_but_not_selected_or_authenticated(self): self.exercise(other_project=True)
    def test_foreign_pending_receipt_rebind_after_last_read_revokes_all_before_completion(self):
        self.exercise('other-receipt-rebind', other_project=True)
    def test_created_complete_rebound_during_all_receiver_capture_cannot_be_adopted(self):
        self.exercise('completion-capture-rebind')

    def test_actual_catalog_count_zero_default_does_not_authenticate_or_read(self):
        self.exercise(lazy_auth=True, count_zero=True)

    def test_selected_counted_catalog_default_performs_one_actual_oauth_and_four_reads(self):
        self.exercise(lazy_auth=True)


class CatalogProjectAuthenticationHandoffDirectTests(unittest.TestCase):
    def test_default_quota_finalizer_rechecks_issued_reads_and_preserves_interruptions(self):
        from contextlib import ExitStack, contextmanager
        from pathlib import Path
        import tempfile
        from types import SimpleNamespace
        from monitor import issue_tracker_local_commit as local
        from monitor import issue_tracker_stage_l_consumer as source
        from monitor import issue_tracker_cycle_source as cycles
        from monitor import issue_tracker_metadata_reservation as quota
        from monitor import issue_tracker_history_read_launcher as reads
        from monitor import issue_tracker_token_launcher as tokens
        from monitor import issue_tracker_online_target as target
        module=importlib.import_module('monitor.issue_tracker_remote_history_match')
        # Direct orchestration boundary only. Real owners/issued reads/native
        # quota FDs are separately required by the genuine C6/TLS workflow.
        for interrupted in (False,True):
            with self.subTest(interrupted=interrupted),tempfile.TemporaryDirectory() as directory,ExitStack() as patches:
                root=Path(directory).resolve();events=[];strict_live=[False];revoked=[False]
                writer=object();owner=object();binding=object();auth=object();identity=object();metadata=object()
                stop=KeyboardInterrupt('owned quota finalizer interruption')
                row=SimpleNamespace(unit=object(),project_identity=object(),c6_facts=object())
                @contextmanager
                def held(*args,**options):
                    yield lambda:None
                @contextmanager
                def last_owner(*args,**options):
                    yield row
                @contextmanager
                def business_images():
                    yield (identity,None,None),lambda:None
                guard=SimpleNamespace(_hold_original_images=business_images)
                @contextmanager
                def core(*args,**options):
                    strict_live[0]=True
                    try:yield (None,None,{'template_identity':identity,'metadata':metadata},((row,None,guard),),auth)
                    finally:strict_live[0]=False;events.append('strict-closed')
                @contextmanager
                def quota_images(*args,**options):
                    self.assertTrue(strict_live[0]);self.assertEqual((writer,owner,binding,auth),args)
                    self.assertEqual({'identity_response':identity,'metadata_response':metadata},options)
                    events.append('quota-enter')
                    try:yield SimpleNamespace(inventory_complete=True,outcome='DEDICATED_PROJECT_CAPACITY'),lambda:events.append('quota-verify')
                    finally:
                        events.append('quota-closed');revoked[0]=True
                        if interrupted:raise stop
                def issued(*args,**options):
                    events.append('read-after-quota-close' if revoked[0] else 'live-read')
                    if revoked[0]:raise module.RemoteHistoryHold()
                patches.enter_context(mock.patch.object(local,'_owner',return_value=SimpleNamespace(project=root)))
                patches.enter_context(mock.patch.object(module.ownership,'_validated_owner'))
                patches.enter_context(mock.patch.object(cycles,'_hold_current_completed_cycle_replay',held))
                patches.enter_context(mock.patch.object(source,'_hold_original_replay_inputs',held))
                # Synthetic orchestration prerequisites only; genuine ALL-last
                # selection, owners and raw tails remain real workflow duties.
                patches.enter_context(mock.patch.object(module,'_hold_current_project_last_original_owners',last_owner))
                patches.enter_context(mock.patch.object(module.global_journal,'_hold_selected_last_catalog_write_originals',held))
                patches.enter_context(mock.patch.object(module,'_hold_current_project_online_inputs',core))
                patches.enter_context(mock.patch.object(quota,'_hold_owned_project_dedicated_quota_images',quota_images))
                patches.enter_context(mock.patch.object(reads,'require_current_owned_project_read',side_effect=issued))
                patches.enter_context(mock.patch.object(tokens,'require_current_owned_project_token'))
                patches.enter_context(mock.patch.object(target,'inspect_project_online_target'))
                no_count=patches.enter_context(mock.patch.object(module.global_journal,'record_global_attempt_intent'))
                with self.assertRaises(KeyboardInterrupt if interrupted else module.RemoteHistoryHold) as caught:
                    module._consume_current_project_online_original_inputs(writer,owner,binding,None,
                        _store=SimpleNamespace(project_identity=root),http_root=root)
                self.assertLess(events.index('quota-enter'),events.index('strict-closed'))
                self.assertLess(events.index('strict-closed'),events.index('quota-closed'))
                self.assertGreaterEqual(events.count('quota-verify'),3);no_count.assert_not_called()
                if interrupted:self.assertIs(stop,caught.exception);self.assertNotIn('read-after-quota-close',events)
                else:self.assertEqual('read-after-quota-close',events[-1])

    def test_default_consumer_retains_actual_dedicated_quota_before_strict_inputs_close(self):
        import ast
        import inspect
        import textwrap
        module=importlib.import_module('monitor.issue_tracker_remote_history_match')
        # Extraction must keep the old quota acquisition and all its strict
        # overlap assertions, not move acquisition after closed readers.
        wrapper=ast.parse(textwrap.dedent(inspect.getsource(module._consume_current_project_online_original_inputs)))
        delegations=[node for node in ast.walk(wrapper) if isinstance(node,ast.Call)
            and isinstance(node.func,ast.Name) and node.func.id=='_hold_current_project_online_original_inputs']
        self.assertEqual(1,len(delegations),'read-only consumer must use the same fixed live context once')
        api=getattr(module,'_hold_current_project_online_original_inputs',None)
        self.assertTrue(callable(api),'default FIRST/R2 needs a live original context, not a returned closed tuple')
        tree=ast.parse(textwrap.dedent(inspect.getsource(api)))
        calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call)
            and isinstance(node.func,ast.Name) and node.func.id=='_hold_owned_project_dedicated_quota_images']
        self.assertEqual(1,len(calls),'G1 quota originals must overlap the still-live strict acquisition')
        self.assertEqual(('writer_token','owner_token','binding','authentication'),
            tuple(arg.id for arg in calls[0].args))
        self.assertEqual({'identity_response','metadata_response'},set(item.arg for item in calls[0].keywords))
        self.assertTrue(any(isinstance(node,ast.With)
            and any(isinstance(item.context_expr,ast.Call)
                and isinstance(item.context_expr.func,ast.Name)
                and item.context_expr.func.id=='_hold_current_project_online_inputs' for item in node.items)
            and calls[0] in tuple(ast.walk(node)) for node in ast.walk(tree)),
            'closed strict readers cannot be the first acquisition of quota originals')

    def test_continuous_default_input_context_rejects_unissued_and_caller_permissions(self):
        import inspect
        from monitor import issue_tracker_unit_catalog as catalog
        from monitor import issue_tracker_history_read_launcher as reads
        module=importlib.import_module('monitor.issue_tracker_remote_history_match')
        api=getattr(module,'_hold_current_project_online_original_inputs',None)
        self.assertTrue(callable(api),'fixed live context must not return original images after cleanup')
        self.assertEqual(('writer_token','owner_token','binding','authentication','_store','http_root'),
            tuple(inspect.signature(api).parameters))
        with mock.patch.object(catalog,'hold_pending_project_origins') as origins, \
                mock.patch.object(reads,'OwnedProjectSheetsReadUnit') as read:
            with self.assertRaises(module.RemoteHistoryHold):
                with api(object(),object(),object(),None,_store=object(),http_root=object()):
                    self.fail('unissued default context yielded')
            origins.assert_not_called();read.assert_not_called()
        for claims in ({'unit':object()},{'verify':lambda:None},{'capacity_complete':True},{'allow_send':True}):
            with self.subTest(claim=tuple(claims)),self.assertRaises(TypeError):
                api(object(),object(),object(),None,_store=object(),http_root=object(),**claims)

    def _actual_fixed_acquisition_contract(self, module):
        import ast
        import inspect
        import textwrap
        # The old API remains a read-only wrapper. Pin its real single-core
        # delegation independently before inspecting that core's old contract.
        wrapper = ast.parse(textwrap.dedent(inspect.getsource(
            module._prepare_current_project_online_observation))).body[0]
        statements = wrapper.body[1:]
        self.assertEqual(2, len(statements))
        self.assertIsInstance(statements[0], ast.With)
        self.assertEqual(1, len(statements[0].items))
        call = statements[0].items[0].context_expr
        self.assertEqual('_hold_current_project_online_inputs', call.func.id)
        self.assertEqual(('writer_token','owner_token','binding','authentication'),
            tuple(arg.id for arg in call.args))
        self.assertEqual([('_store','_store'),('http_root','http_root')],
            [(item.arg,item.value.id) for item in call.keywords])
        self.assertEqual(['pass'], [ast.unparse(item) for item in statements[0].body])
        self.assertEqual("return 'VISIBLE_ONLY_UNPROVED'", ast.unparse(statements[1]))
        return ast.parse(textwrap.dedent(inspect.getsource(
            module._hold_current_project_online_inputs)))

    def test_fixed_default_consumer_accepts_no_selected_unit_guard_or_permission(self):
        import inspect
        module = importlib.import_module('monitor.issue_tracker_remote_history_match')
        api = getattr(module, '_consume_current_project_online_original_inputs', None)
        self.assertTrue(callable(api), 'default input consumer lacks actual continuous original-image handoff')
        self.assertEqual(('writer_token','owner_token','binding','authentication','_store','http_root'),
            tuple(inspect.signature(api).parameters))
        from monitor import issue_tracker_global_attempt_journal as attempts
        from monitor import issue_tracker_mutation_launcher as mutation
        with mock.patch.object(attempts, '_hold_continuous_owned_attempt_wire') as first, \
                mock.patch.object(attempts, '_hold_shared_retry_owned_attempt_wire') as retry, \
                mock.patch.object(mutation, '_send_counted_original_once') as send:
            with self.assertRaises(module.RemoteHistoryHold):
                api(object(),object(),object(),None,_store=object(),http_root=object())
            first.assert_not_called(); retry.assert_not_called(); send.assert_not_called()

    def test_default_preparation_uses_actual_mixed_settlement_and_permanent_quota_readers(self):
        import ast
        import inspect
        import textwrap
        module = importlib.import_module('monitor.issue_tracker_remote_history_match')
        tree = self._actual_fixed_acquisition_contract(module)
        calls = [node.func for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertIn('_hold_all_project_mixed_settlements',
            [node.attr for node in calls if isinstance(node, ast.Attribute)])
        self.assertIn('_hold_owned_project_mixed_metadata_capacity',
            [node.id for node in calls if isinstance(node, ast.Name)])
        self.assertNotIn('_hold_owned_project_catalog_metadata_capacity',
            [node.id for node in calls if isinstance(node, ast.Name)])
        selected = next(node.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == 'selected' for target in node.targets))
        self.assertTrue(any(isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not)
            and isinstance(node.operand, ast.Attribute) and node.operand.attr == 'settled'
            for node in ast.walk(selected)), 'actual settled originals are not pending preparation candidates')

    def test_preparation_revalidates_each_actual_read_after_original_holders_close(self):
        import ast
        import inspect
        import textwrap
        module=importlib.import_module('monitor.issue_tracker_remote_history_match')
        api=getattr(module,'_hold_current_project_online_inputs',None)
        self.assertTrue(callable(api))
        function=self._actual_fixed_acquisition_contract(module).body[0]
        body=next(node.body for node in function.body if isinstance(node,ast.Try))
        held_index=next(i for i,node in enumerate(body) if isinstance(node,ast.With)
            and any(isinstance(item.context_expr,ast.Call)
                and isinstance(item.context_expr.func,ast.Name)
                and item.context_expr.func.id=='ExitStack' for item in node.items))
        holder=body[held_index]
        read_loop=next(node for node in holder.body if isinstance(node,ast.For)
            and isinstance(node.iter,ast.Tuple))
        self.assertEqual(('template_identity','template_headers','whitelist','metadata'),
            tuple(ast.literal_eval(item) for item in read_loop.iter.elts))
        # The actual original business readers outlive all old source/C6
        # finalizers. Pin their normal close order, then independently check
        # every issued business response before the four original gate reads.
        self.assertEqual('scope.close()',ast.unparse(holder.body[-3]))
        live_business_loop=holder.body[-2]
        self.assertIsInstance(live_business_loop,ast.For)
        self.assertEqual('business_guards',ast.unparse(live_business_loop.iter))
        self.assertEqual(['verify_business()'],
            [ast.unparse(node) for node in live_business_loop.body])
        self.assertEqual('business_scope.close()',ast.unparse(holder.body[-1]))
        final_business_loop=body[held_index+1]
        self.assertIsInstance(final_business_loop,ast.For,
            'actual issued business reads must be rechecked after their last finalizer')
        self.assertEqual('business_guards',ast.unparse(final_business_loop.iter))
        self.assertEqual(['verify_business._verify_issued_only()'],
            [ast.unparse(node) for node in final_business_loop.body])
        final_read_loop=body[held_index+2]
        self.assertIsInstance(final_read_loop,ast.For,
            'actual read deadlines must be rechecked after every original-holder finalizer')
        self.assertEqual('responses.items()',ast.unparse(final_read_loop.iter))
        self.assertEqual(['require_current_owned_project_read'],
            [node.func.id for node in ast.walk(final_read_loop) if isinstance(node,ast.Call)
                and isinstance(node.func,ast.Name)])
        call=final_read_loop.body[0].value
        self.assertEqual(('writer_token','owner_token','binding','response','authentication'),
            tuple(arg.id for arg in call.args))
        self.assertEqual([('read_kind','kind')],[(arg.arg,arg.value.id) for arg in call.keywords])
        self.assertEqual(['require_current_owned_project_token','inspect_project_online_target'],
            [node.value.func.id for node in body[held_index+3:]])

    def test_fixed_internal_handoff_accepts_no_caller_authentication_or_factory(self):
        import inspect
        module=importlib.import_module('monitor.issue_tracker_remote_history_match')
        api=getattr(module,'_reconcile_pending_project_units_and_project_auth',None)
        self.assertTrue(callable(api),'fixed reconciliation lacks actual internal OAuth lifecycle handoff')
        self.assertEqual(('writer_token','owner_token','binding','_store'),tuple(inspect.signature(api).parameters))
        from monitor import issue_tracker_unit_catalog as catalog
        with mock.patch.object(catalog,'_inspect') as inventory:
            with self.assertRaises(module.RemoteHistoryHold): api(object(),object(),object())
            inventory.assert_not_called()

    def test_fixed_next_stage_acquires_source_and_reads_instead_of_accepting_plans(self):
        import inspect
        module=importlib.import_module('monitor.issue_tracker_remote_history_match')
        api=getattr(module,'_prepare_current_project_online_observation',None)
        self.assertTrue(callable(api),'default next stage lacks actual source/read preparation')
        self.assertEqual(('writer_token','owner_token','binding','authentication','_store','http_root'),
            tuple(inspect.signature(api).parameters))
        from monitor import issue_tracker_token_launcher as tokens
        from monitor import issue_tracker_history_read_launcher as reads
        with mock.patch.object(tokens,'OwnedProjectTokenRefreshUnit') as oauth, \
                mock.patch.object(reads,'OwnedProjectSheetsReadUnit') as read:
            with self.assertRaises(module.RemoteHistoryHold):
                api(object(),object(),object(),None,_store=object(),http_root=object())
            oauth.assert_not_called(); read.assert_not_called()


class CatalogMixedPreparationOriginalWorkflowTests(unittest.TestCase):
    def test_actual_settled_current_and_foreign_pending_refuse_before_source_auth_or_reads(self):
        from types import SimpleNamespace
        from test_cases.test_req7_unit_catalog import CatalogAppliedNativeWorkflowTests
        with CatalogAppliedNativeWorkflowTests.completed_and_pending(self, cross_project=True) as (
                case, catalog, remote, _inventory, _old, writer, owner, bound, units):
            from monitor import issue_tracker_cycle_source as source
            from monitor import issue_tracker_token_launcher as tokens
            from monitor import issue_tracker_history_read_launcher as reads
            before = original_read_files(case.root)
            # Deliberately unsupported source store: no current pending unit
            # must dereference it or acquire OAuth. It is NOT a qualified source.
            store = SimpleNamespace(project_identity=str(catalog.local._owner(writer).project))
            with mock.patch.object(source, '_hold_current_completed_cycle_replay',
                    wraps=source._hold_current_completed_cycle_replay) as cycle, \
                    mock.patch.object(tokens, 'OwnedProjectTokenRefreshUnit') as oauth, \
                    mock.patch.object(reads, 'OwnedProjectSheetsReadUnit') as read:
                with self.assertRaises(remote.RemoteHistoryHold):
                    remote._prepare_current_project_online_observation(writer, owner, bound, None,
                        _store=store, http_root=case.root)
            cycle.assert_not_called(); oauth.assert_not_called(); read.assert_not_called()
            self.assertEqual(before, original_read_files(case.root))
            from monitor import issue_tracker_global_attempt_journal as globals_
            self.assertEqual((1, 0), tuple(globals_.inspect_global_unit(owner, bound, unit).attempt_count
                for unit in units))


class CatalogProjectAuthenticationHandoffWorkflowTests(unittest.TestCase):
    _Base=CatalogReconciliationWorkflowTests
    _Fixture=_Base._Fixture
    setUp=_Base.setUp; server=_Base.server; owners=_Base.owners
    intercept=_Base.intercept; child_fixture=_Base.child_fixture
    certificates=_Base.certificates; read_owned=_Base.read_owned
    prepare_owned=_Base.prepare_owned; project_auth=_Base.project_auth
    exercise=_Base.exercise

    def api(self):
        module=importlib.import_module('monitor.issue_tracker_remote_history_match')
        fixed=getattr(module,'_reconcile_pending_project_units_and_project_auth',None)
        self.assertTrue(callable(fixed),'default next stage cannot use a closed read summary as OAuth')
        def run(writer,owner,bound,authentication=None):
            if authentication is not None:
                # The reused fixture separately checks the unchanged legacy
                # read-only API's settled replay. Never pass its caller auth
                # to the new lazy-only handback or count it as a new handoff.
                return module.reconcile_pending_project_units(writer,owner,bound,authentication)
            result,actual=fixed(writer,owner,bound)
            self.handoffs.append((result,actual))
            if result:
                from monitor.issue_tracker_token_launcher import require_current_owned_project_token
                project,digest=require_current_owned_project_token(owner,bound,actual)
                self.assertEqual('synthetic-cloud-project',project)
                self.assertRegex(digest,r'^[0-9a-f]{64}$')
                self.assertFalse(hasattr(actual,'permit'))
            else:
                self.assertIsNone(actual,'no counted unit must still mean no OAuth acquisition')
            return result
        return module,run

    def test_actual_four_read_finalization_returns_original_live_auth_not_read_permission(self):
        self.handoffs=[]; self.exercise(lazy_auth=True)
        self.assertEqual(1,len(self.handoffs))
        result,auth=self.handoffs[0]
        self.assertEqual(('APPLIED',),tuple(row.state for row in result)); self.assertIsNotNone(auth)
        # The helper owners have now closed. A handback is not a persisted or
        # transferable token capability and cannot revive that acquisition.
        from monitor import issue_tracker_token_launcher as tokens
        with self.assertRaises(tokens.TokenLauncherHold):
            tokens.require_current_owned_project_token(object(),object(),auth)

    def test_no_counted_unit_returns_empty_result_without_authenticating(self):
        self.handoffs=[]; self.exercise(lazy_auth=True,count_zero=True)
        self.assertEqual([((),None)],self.handoffs)

    def test_original_c6_failure_does_not_publish_authentication_handoff(self):
        self.handoffs=[]; self.exercise('other-receipt-rebind',other_project=True,lazy_auth=True)
        self.assertEqual([],self.handoffs)
