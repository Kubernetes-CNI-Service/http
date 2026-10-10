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
    def test_default_preparation_uses_actual_mixed_settlement_and_permanent_quota_readers(self):
        import ast
        import inspect
        import textwrap
        module = importlib.import_module('monitor.issue_tracker_remote_history_match')
        tree = ast.parse(textwrap.dedent(inspect.getsource(module._prepare_current_project_online_observation)))
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
        api=getattr(module,'_prepare_current_project_online_observation',None)
        self.assertTrue(callable(api))
        function=ast.parse(textwrap.dedent(inspect.getsource(api))).body[0]
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
        final_read_loop=body[held_index+1]
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
            [node.value.func.id for node in body[held_index+2:]])

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
