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
    def exercise(self, *, held_stop=False, drift=False, interrupt=False, applied=False):
        from monitor import issue_tracker_local_commit as local
        from monitor import issue_tracker_online_target as target
        from monitor import issue_tracker_spreadsheet_owner as ownership
        from monitor import issue_tracker_remote_history_match as remote
        from monitor import issue_tracker_retained_inventory as inventory
        worker = runtime_tests.persistence.WORKER
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory).resolve()
            store = runtime_tests.cycle(stack, root)
            writer, owner, binding = object(), object(), object()
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

            stack.enter_context(mock.patch.object(worker, 'STATUS_DIR', root/'monitor/status'))
            stack.enter_context(mock.patch.object(local, 'try_writer_owner',
                side_effect=lambda *args: held('writer', writer)))
            stack.enter_context(mock.patch.object(target, '_hold_current_project_online_target',
                side_effect=lambda *args: held('target', binding)))
            stack.enter_context(mock.patch.object(ownership, 'spreadsheet_owner',
                side_effect=lambda *args: held('sheet', owner)))
            stack.enter_context(mock.patch.object(remote, '_reconcile_pending_project_units', side_effect=reconcile))
            stack.enter_context(mock.patch.object(inventory, '_record_all_project_unsent_dispositions', side_effect=append))
            with mock.patch.object(worker.sys, 'stderr', io.StringIO()) as stream:
                if interrupt:
                    with self.assertRaises(KeyboardInterrupt):
                        worker._reconcile_issue_tracker_online_after_completion(store)
                elif drift:
                    with self.assertRaises(worker.CollectionCycleHoldError):
                        worker._reconcile_issue_tracker_online_after_completion(store)
                else:
                    self.assertIs(result, worker._reconcile_issue_tracker_online_after_completion(store))
            self.assertEqual([True], reached)
            self.assertEqual(['reconcile', 'disposition'], calls)
            if drift:
                self.assertEqual(1, len(substituted))
                self.assertNotEqual(*substituted[0])
            else:
                self.assertEqual([], substituted)
            status = root/'monitor/status/issue-tracker-online.status.json'
            if drift or interrupt:
                self.assertFalse(status.exists())
            else:
                self.assertEqual(['sheet', 'writer', 'target'], closed)
                view = json.loads(status.read_bytes())
                self.assertEqual('historical_applied' if applied else 'stalled', view['state'])
                self.assertIs(True, view['read_only']); self.assertIs(True, view['mutation_disabled'])
                if not applied:
                    self.assertEqual('Issue Tracker online stalled: UNKNOWN; read-only reconciliation; mutation disabled\n',
                        stream.getvalue())
                if held_stop and applied:
                    self.assertIn('Issue Tracker UNSENT disposition unavailable; mutation disabled', stream.getvalue())
            self.assertNotIn('PRIVATE', stream.getvalue())

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
