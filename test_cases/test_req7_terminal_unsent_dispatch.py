"""Terminal original reconciliation -> local ALL UNSENT disposition; no NEW."""
from contextlib import ExitStack, contextmanager
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_cases import test_req7_online_completion_runtime as runtime_tests


class TerminalUnsentDispatchDirectTests(unittest.TestCase):
    def exercise(self, *, held_stop=False, drift=False, interrupt=False, applied=False,
                 preparation_probe=None, preparation_interrupt=False,
                 preparation_endpoint='_consume_current_project_online_original_inputs',
                 terminal_dispatch=False, delivery_failure=False, attempt_unproved=False):
        from monitor import issue_tracker_local_commit as local
        from monitor import issue_tracker_online_target as target
        from monitor import issue_tracker_spreadsheet_owner as ownership
        from monitor import issue_tracker_remote_history_match as remote
        from monitor import issue_tracker_retained_inventory as inventory
        from monitor import issue_tracker_settings_audit_allocation as delivery
        worker = runtime_tests.persistence.WORKER
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory).resolve()
            store = runtime_tests.cycle(stack, root)
            writer, owner, binding = object(), object(), object()
            authentication = object()
            calls = []; closed = []; reached = []; substituted = []
            result = (remote.RemoteHistoryObservation('UNKNOWN', 1, False, True, True,
                1, 0, 3, 3, 'PRIVATE ACTION', 'PRIVATE WIRE', 'PRIVATE METADATA', 'PRIVATE HISTORY'),)
            if applied:
                result = (remote.AppliedEvidenceObservation('APPLIED', 'original', 1, 'unit', ()),)

            @contextmanager
            def held(label, value):
                yield value
                closed.append(label)

            def reconcile(actual_writer, actual_owner, actual_binding, *, _store):
                self.assertIs(writer, actual_writer); self.assertIs(owner, actual_owner)
                self.assertIs(binding, actual_binding); self.assertIs(store, _store)
                calls.append('reconcile')
                return result

            def append(actual_owner, actual_binding):
                self.assertEqual(['reconcile'], calls)
                self.assertIs(owner, actual_owner); self.assertIs(binding, actual_binding)
                self.assertEqual([], closed)
                self.assertIsNotNone(store.gate._lock_fd)
                calls.append('disposition'); reached.append(True)
                if drift:
                    path = store.completion_path(1); raw = path.read_bytes()
                    old = path.stat().st_ino
                    path.rename(root/'preserved-original-completion')
                    path.write_bytes(raw); path.chmod(0o600)
                    substituted.append((old, path.stat().st_ino))
                if interrupt:
                    raise KeyboardInterrupt('PRIVATE INTERRUPT')
                if held_stop:
                    raise inventory.RetainedInventoryHold()
                return ()

            def prepare(actual_writer, actual_owner, actual_binding, actual_authentication, *, _store, http_root):
                self.assertIs(writer,actual_writer); self.assertIs(owner,actual_owner)
                self.assertIs(binding,actual_binding); self.assertIs(authentication,actual_authentication)
                self.assertIs(store,_store); self.assertEqual(root,http_root)
                self.assertEqual(['reconcile','disposition'],calls)
                self.assertEqual([],closed); self.assertIsNotNone(store.gate._lock_fd)
                if preparation_probe is not None: preparation_probe.append('live-after-unsent')
                if preparation_interrupt: raise KeyboardInterrupt('PRIVATE PREPARATION INTERRUPT')
                raise remote.RemoteHistoryHold()

            def finalize(actual_writer, actual_binding):
                # This direct fixture substitutes owner objects, not native C25
                # authority. Its C25 boundary must likewise be explicit, after
                # sheet exit and before the writer/target originals close.
                self.assertIs(writer, actual_writer); self.assertIs(binding, actual_binding)
                self.assertEqual(['sheet'], closed)
                self.assertIsNotNone(store.gate._lock_fd)
                if delivery_failure: raise ValueError('PRIVATE FINALIZER DETAIL')
                return ()

            stack.enter_context(mock.patch.object(worker, 'STATUS_DIR', root/'monitor/status'))
            stack.enter_context(mock.patch.object(local, 'try_writer_owner',
                side_effect=lambda *args: held('writer', writer)))
            stack.enter_context(mock.patch.object(target, '_hold_current_project_online_target',
                side_effect=lambda *args: held('target', binding)))
            stack.enter_context(mock.patch.object(ownership, 'spreadsheet_owner',
                side_effect=lambda *args: held('sheet', owner)))
            stack.enter_context(mock.patch.object(remote, '_reconcile_pending_project_units', side_effect=reconcile))
            stack.enter_context(mock.patch.object(remote, '_reconcile_pending_project_units_and_project_auth',
                side_effect=lambda *args,**options:(reconcile(*args,**options),authentication)))
            stack.enter_context(mock.patch.object(worker if terminal_dispatch else remote,
                '_dispatch_current_project_online_originals' if terminal_dispatch else preparation_endpoint,
                side_effect=prepare))
            stack.enter_context(mock.patch.object(inventory, '_record_all_project_unsent_dispositions', side_effect=append))
            stack.enter_context(mock.patch.object(delivery, '_finalize_native_completed_settings_delivery', side_effect=finalize))
            api = (worker._dispatch_issue_tracker_online_after_completion if terminal_dispatch
                   else worker._reconcile_issue_tracker_online_after_completion)
            with mock.patch.object(worker.sys, 'stderr', io.StringIO()) as stream:
                if interrupt or preparation_interrupt:
                    with self.assertRaises(KeyboardInterrupt):
                        api(store)
                elif drift or delivery_failure:
                    with self.assertRaises(worker.CollectionCycleHoldError):
                        api(store)
                else:
                    self.assertIs(result, api(store))
            self.assertEqual([True], reached)
            self.assertEqual(['reconcile', 'disposition'], calls)
            if drift:
                self.assertEqual(1, len(substituted))
                self.assertNotEqual(*substituted[0])
            else:
                self.assertEqual([], substituted)
            status = root/'monitor/status/issue-tracker-online.status.json'
            if drift or interrupt or preparation_interrupt or delivery_failure:
                self.assertFalse(status.exists())
            else:
                self.assertEqual(['sheet', 'writer', 'target'], closed)
                view = json.loads(status.read_bytes())
                self.assertEqual('attempt_unproved' if attempt_unproved else
                    'historical_applied' if applied else 'stalled', view['state'])
                self.assertIs(True, view['read_only']); self.assertIs(True, view['mutation_disabled'])
                if not applied:
                    self.assertEqual('Issue Tracker online stalled: UNKNOWN; read-only reconciliation; mutation disabled\n',
                        stream.getvalue())
                if held_stop and applied:
                    self.assertIn('Issue Tracker UNSENT disposition unavailable; mutation disabled', stream.getvalue())
            self.assertNotIn('PRIVATE', stream.getvalue())

    def test_fixed_preparation_follows_unsent_with_identical_live_owner_and_actual_auth_handoff(self):
        observed=[]
        self.exercise(preparation_probe=observed,held_stop=True)
        self.assertEqual(['live-after-unsent'],observed)

    def test_default_worker_enters_fixed_original_consumer_once_not_legacy_preparation(self):
        from monitor import issue_tracker_remote_history_match as remote
        observed=[]
        with mock.patch.object(remote, '_prepare_current_project_online_observation') as legacy:
            self.exercise(preparation_probe=observed, held_stop=True,
                preparation_endpoint='_consume_current_project_online_original_inputs')
        self.assertEqual(['live-after-unsent'], observed,
            'actual default worker must enter the fixed original consumer after ALL UNSENT')
        legacy.assert_not_called()

    def test_preparation_operator_interrupt_is_not_swallowed_or_published(self):
        observed=[]
        self.exercise(preparation_probe=observed,preparation_interrupt=True)
        self.assertEqual(['live-after-unsent'],observed)

    def test_reconciliation_then_local_disposition_use_identical_live_owner_and_binding(self):
        self.exercise()

    def test_disposition_hold_preserves_original_unknown_tuple_and_stalled_status(self):
        self.exercise(held_stop=True)

    def test_disposition_hold_cannot_suppress_original_cycle_rebind(self):
        self.exercise(held_stop=True, drift=True)

    def test_historical_applied_disposition_hold_is_visible_but_not_new_permission(self):
        self.exercise(held_stop=True, applied=True)

    def test_operator_interrupt_is_not_normalized_into_successful_reconciliation(self):
        self.exercise(interrupt=True)

    def test_terminal_dispatch_hold_preserves_actual_unknown_and_all_finalizer_order(self):
        reached=[]
        self.exercise(terminal_dispatch=True,held_stop=True,preparation_probe=reached)
        self.assertEqual(['live-after-unsent'], reached)

    def test_terminal_dispatch_cannot_mask_original_cycle_rebind(self):
        self.exercise(terminal_dispatch=True,held_stop=True,drift=True)

    def test_terminal_dispatch_interrupt_does_not_publish_or_normalize_success(self):
        self.exercise(terminal_dispatch=True,preparation_interrupt=True)

    def test_terminal_dispatch_failed_c25_finalizer_never_publishes_status(self):
        self.exercise(terminal_dispatch=True,delivery_failure=True)

    def test_terminal_original_conflict_or_exhaustion_stops_before_dispatch(self):
        from monitor import issue_tracker_remote_history_match as remote
        worker = runtime_tests.persistence.WORKER
        for state, count, expected in (('CONFLICT', 1, 'conflict'), ('UNKNOWN', 6, 'retry_exhausted')):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                observation = remote.RemoteHistoryObservation(state, count, False, True, True,
                    2, 0, 3, 3, 'PRIVATE ACTION', 'PRIVATE WIRE', 'PRIVATE META', 'PRIVATE HISTORY')
                result = (observation,)
                @contextmanager
                def originals(store):
                    yield dict(result=result, writer=object(), owner=object(), binding=object(),
                        authentication=object(), http_root=Path(directory),
                        disposition_stopped=False, delivery_stopped=False)
                stack.enter_context(mock.patch.object(worker, '_hold_terminal_current_project_online_originals', originals))
                stack.enter_context(mock.patch.object(worker, 'STATUS_DIR', Path(directory)))
                dispatch = stack.enter_context(mock.patch.object(worker, '_dispatch_current_project_online_originals', return_value=None))
                stream = stack.enter_context(mock.patch.object(worker.sys, 'stderr', io.StringIO()))
                self.assertIs(result, worker._dispatch_issue_tracker_online_after_completion(object()))
                dispatch.assert_not_called()
                self.assertEqual(expected, json.loads((Path(directory)/'issue-tracker-online.status.json').read_bytes())['state'])
                self.assertNotIn('PRIVATE', stream.getvalue())

    def test_terminal_applied_prefix_cannot_hide_new_attempt_hold(self):
        # Historical APPLIED is not a statement about the selected new unit.
        # The old read-only entry keeps its historical display independently.
        self.exercise(terminal_dispatch=True, applied=True, attempt_unproved=True)


class TerminalUnsentNativeWorkflowTests(unittest.TestCase):
    """Reuse actual OAuth/four-read workflow, not inherited discovery methods."""
    _Fixture = runtime_tests.OnlineCompletionRuntimeWorkflowTests._Fixture
    setUp = runtime_tests.OnlineCompletionRuntimeWorkflowTests.setUp
    server = runtime_tests.OnlineCompletionRuntimeWorkflowTests.server
    certificates = runtime_tests.OnlineCompletionRuntimeWorkflowTests.certificates
    child_fixture = runtime_tests.OnlineCompletionRuntimeWorkflowTests.child_fixture
    read_owned = runtime_tests.OnlineCompletionRuntimeWorkflowTests.read_owned
    prepare_owned = runtime_tests.OnlineCompletionRuntimeWorkflowTests.prepare_owned
    project_auth = runtime_tests.OnlineCompletionRuntimeWorkflowTests.project_auth
    owners = runtime_tests.OnlineCompletionRuntimeWorkflowTests.owners
    intercept = runtime_tests.OnlineCompletionRuntimeWorkflowTests.intercept
    api = runtime_tests.OnlineCompletionRuntimeWorkflowTests.api
    exercise = runtime_tests.OnlineCompletionRuntimeWorkflowTests.exercise

    def test_actual_default_worker_calls_new_consumer_with_original_auth_and_keeps_unknown(self):
        observed=[]; worker_api=self.api()
        def invoke(store):
            from monitor import issue_tracker_remote_history_match as remote
            from monitor.issue_tracker_token_launcher import require_current_owned_project_token
            from monitor import issue_tracker_global_attempt_journal as attempts
            from monitor import issue_tracker_mutation_launcher as mutation
            actual=remote._consume_current_project_online_original_inputs
            def consume(writer,owner,binding,authentication,*,_store,http_root):
                project,digest=require_current_owned_project_token(owner,binding,authentication)
                self.assertTrue(project); self.assertEqual(64,len(digest))
                self.assertIs(store,_store); self.assertIsNotNone(_store.gate._lock_fd)
                self.assertEqual(self.root,http_root)
                try:
                    actual(writer,owner,binding,authentication,_store=_store,http_root=http_root)
                except remote.RemoteHistoryHold:
                    observed.append('original-auth-live-actual-hold')
                    raise
                self.fail('unproved G1 must not return an admission result')
            with mock.patch.object(remote,'_consume_current_project_online_original_inputs',side_effect=consume) as consumer, \
                    mock.patch.object(remote,'_prepare_current_project_online_observation') as legacy, \
                    mock.patch.object(attempts,'_hold_continuous_owned_attempt_wire') as first, \
                    mock.patch.object(attempts,'_hold_shared_retry_owned_attempt_wire') as retry, \
                    mock.patch.object(attempts,'_hold_counted_original_wire') as claim, \
                    mock.patch.object(mutation,'_send_counted_original_once') as send:
                result=worker_api(store)
                self.assertEqual(1,consumer.call_count)
                legacy.assert_not_called(); first.assert_not_called(); retry.assert_not_called()
                claim.assert_not_called(); send.assert_not_called()
                return result
        with mock.patch.object(self,'api',return_value=invoke):
            self.exercise(missing_fence=True)
        self.assertEqual(['original-auth-live-actual-hold'],observed)

    def test_default_worker_hands_actual_issued_project_auth_to_preparation_inside_real_owners(self):
        observed=[]; worker_api=self.api()
        def invoke(store):
            # The native fixture loads a new actual matcher before invoking
            # the worker. Observe that current module, not a stale prefixture.
            from monitor import issue_tracker_remote_history_match as remote
            from monitor.issue_tracker_token_launcher import require_current_owned_project_token
            actual=remote._consume_current_project_online_original_inputs
            def prepare(writer,owner,binding,authentication,*,_store,http_root):
                project,digest=require_current_owned_project_token(owner,binding,authentication)
                self.assertTrue(project); self.assertEqual(64,len(digest))
                self.assertIsNotNone(_store.gate._lock_fd)
                self.assertEqual(self.root,http_root)
                observed.append('actual-auth-live')
                return actual(writer,owner,binding,authentication,_store=_store,http_root=http_root)
            with mock.patch.object(remote,'_consume_current_project_online_original_inputs',side_effect=prepare):
                return worker_api(store)
        with mock.patch.object(self,'api',return_value=invoke):
            self.exercise(missing_fence=True)
        self.assertEqual(['actual-auth-live'],observed)

    def test_actual_missing_fence_keeps_unknown_and_status_after_unsent_hold(self):
        from monitor import issue_tracker_retained_inventory as inventory
        original = inventory._record_all_project_unsent_dispositions
        called = []; stopped = []
        def append(owner, binding):
            called.append(True)
            try:
                return original(owner, binding)
            except inventory.RetainedInventoryHold:
                stopped.append(True)
                raise
        with mock.patch.object(inventory, '_record_all_project_unsent_dispositions', side_effect=append):
            self.exercise(missing_fence=True)
        self.assertEqual([True], called); self.assertEqual([True], stopped)
        self.assertEqual([], list((self.root/'project/.tracker').glob('REMOTE-UNSENT-*')))

    def test_actual_reconciled_applied_keys_commit_only_covered_older_original(self):
        from monitor import issue_tracker_local_commit as local
        from monitor import issue_tracker_global_attempt_journal as journal
        from monitor import issue_tracker_unit_catalog as catalog
        from monitor import issue_tracker_retained_inventory as inventory
        from monitor.issue_tracker_send_unit import freeze_send_unit
        from test_cases.test_req7_send_unit import inputs
        from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
        begin = local.begin_generation; prepare = journal.prepare_global_unit
        append = inventory._record_all_project_unsent_dispositions
        earlier = []; captured = []; expected = []

        def allocate(writer, manifest):
            old = begin(writer, manifest)
            self.assertEqual(1, old.sequence)
            local.record_intent(writer, old, literal_xlsx(), kind='xlsx')
            receipt = local.commit(writer, old)
            earlier.append((writer, old, receipt))
            return begin(writer, manifest)

        def prepare_both(owner, binding, selected):
            prepare(owner, binding, selected)
            writer, old, receipt = earlier[0]
            arguments = inputs()
            arguments.update(spreadsheet_id=binding.spreadsheet_id, sheet_id=101, history_sheet_id=105,
                target_nonce='a'*64, history_nonce='d'*64, generation_id=old.generation_id,
                publish_id=receipt.published_sha256)
            arguments['business'][0]['observed_values'] = {'L': {'stringValue': 'down'}}
            arguments['audits'] = ({'event_id': 'settings:001',
                'recorded_at_utc': '2026-10-08T10:00:00Z', 'details': 'K=3'},)
            original = freeze_send_unit(**arguments)
            catalog.register_pending_c6_unit(writer, owner, binding, original)
            prepare(owner, binding, original)
            expected.append((original.unit_id, 1, ((('switch', 'node0001', 'down', 'fabric'), 2),)))

        def appended(owner, binding):
            value = append(owner, binding)
            captured.append(value)
            return value

        with mock.patch.object(local, 'begin_generation', side_effect=allocate), \
                mock.patch.object(journal, 'prepare_global_unit', side_effect=prepare_both), \
                mock.patch.object(inventory, '_record_all_project_unsent_dispositions', side_effect=appended):
            self.exercise()
        self.assertEqual([tuple(expected)], captured)
        self.assertEqual(1, len(expected))
        self.assertEqual(3, len(list((self.root/'project/.tracker').glob('REMOTE-UNSENT-*'))))
