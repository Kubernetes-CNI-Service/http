"""Actual FIRST/R2 composition under the terminal worker's original cycle scope."""

import copy
import ast
from contextlib import contextmanager
from contextvars import copy_context
import inspect
import json
import os
from pathlib import Path
import socket
import sys
import textwrap
import unittest
from unittest import mock

from monitor import issue_tracker_cycle_source as source
from test_cases import test_issue_tracker_cycle_source as fixtures


class Req7OnlineCycleScopeDirectTests(unittest.TestCase):
    def test_native_retry_fixture_prepares_transport_before_issuing_attempt_reads(self):
        from test_cases.test_issue_tracker_stage_l_consumer_workflow import ProdStageLConsumerWorkflowTests
        tree = ast.parse(textwrap.dedent(inspect.getsource(
            ProdStageLConsumerWorkflowTests._exercise_real_protected_three_panel_fixture)))
        loops = [node for node in ast.walk(tree) if isinstance(node, ast.For)
                 and isinstance(node.target, ast.Name) and node.target.id == 'count'
                 and isinstance(node.iter, ast.Tuple)
                 and [getattr(item, 'value', None) for item in node.iter.elts] == [1, 2]]
        self.assertEqual(1, len(loops))
        servers = [node for node in ast.walk(loops[0]) if isinstance(node, ast.With)
                   and any(isinstance(item.context_expr, ast.Call)
                       and isinstance(item.context_expr.func, ast.Attribute)
                       and isinstance(item.context_expr.func.value, ast.Name)
                       and item.context_expr.func.value.id == 'native_mutation'
                       and item.context_expr.func.attr == 'server' for item in node.items)]
        self.assertEqual(1, len(servers))
        issued = [node for node in ast.walk(servers[0]) if isinstance(node, ast.Assign)
                  and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                  and node.value.func.id == 'fresh_bundle']
        self.assertEqual(1, len(issued),
            'local TLS fixture preparation must not spend the original attempt read budget')

    def test_manifest_requires_both_original_holders_and_actual_request_workflow(self):
        registry = json.loads((Path(__file__).resolve().parent / 'script_test_manifest.json').read_text())
        module = 'test_cases.test_req7_online_cycle_scope'
        self.assertEqual(['issue-tracker-local'],
            [suite['id'] for suite in registry['test_suites'] if module in suite['tests']])
        for path in ('monitor/issue_tracker_cycle_source.py', 'monitor/issue_tracker_global_attempt_journal.py',
                     'monitor/issue_tracker_stage_l_consumer.py'):
            self.assertTrue(any(path in rule['paths'] and module in rule['tests']
                for rule in registry['test_rules']), path)
        members = {'monitor/issue_tracker_cycle_source.py', 'monitor/switch-collection-worker.py',
            'monitor/issue_tracker_global_attempt_journal.py', 'monitor/issue_tracker_stage_l_consumer.py',
            'monitor/issue_tracker_mutation_launcher.py', 'monitor/issue_tracker_spreadsheet_owner.py',
            'monitor/issue_tracker_admission.py', 'monitor/issue_tracker_local_commit.py',
            'monitor/issue_tracker_local_workbook_commit.py', 'monitor/issue_tracker_nv_reservation.py'}
        self.assertTrue(any(members <= set(flow['members']) and module in flow['tests']
            for flow in registry['workflows']))

    def setUp(self):
        fixture = fixtures.IssueTrackerCycleSourceTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.store = fixture.store
        self.directory = fixture.directory
        fixtures.completed(self.store, fixtures.TOKEN_1)
        self.api = getattr(source, '_hold_current_completed_cycle_replay', None)
        self.assertTrue(callable(self.api), 'private composition must verify the actual already-held store')

    def holder(self, store):
        return self.api(store)

    def test_unheld_composition_pins_and_revokes_the_actual_original_scope(self):
        self.assertIsNone(source._HELD_CYCLE_REPLAY.get())
        with self.holder(self.store) as verify:
            active = source._HELD_CYCLE_REPLAY.get()
            self.assertIs(self.store, active[0])
            self.assertIs(verify, active[1])
            self.assertEqual((1,), tuple(item.sequence for item in source.read_completed_cycle_evidence(self.store)))
        self.assertIsNone(source._HELD_CYCLE_REPLAY.get())

    def test_same_actual_scope_verifies_originals_without_a_second_semantic_replay(self):
        real = self.store._validate_completion_record
        with mock.patch.object(self.store, '_validate_completion_record', wraps=real) as replay:
            with source._hold_completed_cycle_replay(self.store) as original:
                active = source._HELD_CYCLE_REPLAY.get()
                with self.holder(self.store) as verify:
                    self.assertIs(original, verify)
                    self.assertIs(active, source._HELD_CYCLE_REPLAY.get())
                    verify()
                    self.assertEqual((1,), tuple(item.sequence for item in source.read_completed_cycle_evidence(self.store)))
                self.assertIs(active, source._HELD_CYCLE_REPLAY.get())
                self.assertEqual(1, replay.call_count)
            source.read_completed_cycle_evidence(self.store)
            self.assertEqual(2, replay.call_count, 'scope exit must revoke semantic reuse')

    def test_copied_store_and_the_public_nested_holder_are_still_refused(self):
        entered = []
        with source._hold_completed_cycle_replay(self.store):
            active = source._HELD_CYCLE_REPLAY.get()
            with self.assertRaises(source.CycleSourceHoldError):
                with self.holder(copy.copy(self.store)):
                    entered.append('copied store')
            with self.assertRaises(source.CycleSourceHoldError):
                with source._hold_completed_cycle_replay(self.store):
                    entered.append('strict nested holder')
            self.assertIs(active, source._HELD_CYCLE_REPLAY.get())
            active[1]()
        self.assertEqual([], entered, 'neither copied store nor strict nested holder can enter')

    def test_same_byte_original_rebinding_during_borrow_is_not_repaired(self):
        path = self.store.completion_path(1)
        raw = path.read_bytes()
        reached = []; inner_refused = []
        try:
            with source._hold_completed_cycle_replay(self.store):
                try:
                    with self.holder(self.store):
                        reached.append(True)
                        path.rename(Path(self.directory.name) / 'owned-original')
                        path.write_bytes(raw)
                except source.CycleSourceHoldError:
                    inner_refused.append(True)
        except source.CycleSourceHoldError:
            pass
        self.assertEqual([True], reached)
        self.assertEqual([True], inner_refused, 'borrow exit itself must reject before the outer finalizer')
        self.assertEqual(raw, path.read_bytes())

    def test_gate_binding_change_during_borrow_is_refused(self):
        reached = []; inner_refused = []
        original_lane = self.store.gate.lane
        with source._hold_completed_cycle_replay(self.store):
            try:
                with self.holder(self.store):
                    reached.append(True)
                    self.store.gate.lane = 'foreign-lane'
            except source.CycleSourceHoldError:
                inner_refused.append(True)
            finally:
                self.store.gate.lane = original_lane
        self.assertEqual([True], reached)
        self.assertEqual([True], inner_refused, 'borrow exit must reject gate drift independently')

    def test_context_replacement_during_borrow_is_refused_even_if_originals_survive(self):
        reached = []; refused = []; token = None
        with source._hold_completed_cycle_replay(self.store):
            try:
                with self.holder(self.store):
                    token = source._HELD_CYCLE_REPLAY.set(None)
                    reached.append(True)
            except source.CycleSourceHoldError:
                refused.append(True)
            finally:
                if token is not None: source._HELD_CYCLE_REPLAY.reset(token)
        self.assertEqual([True], reached)
        self.assertEqual([True], refused)
        self.assertIsNone(source._HELD_CYCLE_REPLAY.get())

    def test_caller_tuple_and_revoked_original_tuple_never_invoke_a_verifier(self):
        callbacks = []; entered = []
        fabricated = (self.store, lambda: callbacks.append(True), ())
        with source._hold_completed_cycle_replay(self.store):
            revoked = source._HELD_CYCLE_REPLAY.get()
        for active in (fabricated, revoked):
            token = source._HELD_CYCLE_REPLAY.set(active)
            try:
                with self.assertRaises(source.CycleSourceHoldError):
                    with self.holder(self.store): entered.append(True)
            finally:
                source._HELD_CYCLE_REPLAY.reset(token)
        self.assertEqual([], callbacks, 'never execute a caller callback as an original verifier')
        self.assertEqual([], entered, 'revoked and fabricated scopes grant no reuse')

    def test_public_reader_refuses_caller_verifier_before_invoking_it(self):
        callbacks = []
        token = source._HELD_CYCLE_REPLAY.set(
            (self.store, lambda: callbacks.append(True), ('caller evidence',)))
        try:
            with self.assertRaises(source.CycleSourceHoldError):
                source.read_completed_cycle_evidence(self.store)
        finally:
            source._HELD_CYCLE_REPLAY.reset(token)
        self.assertEqual([], callbacks, 'a caller callback is not an original verifier')

    def test_public_reader_refuses_malformed_scope_as_typed_hold(self):
        for active in ((), (self.store,), [self.store, lambda: None, ()]):
            with self.subTest(scope_type=type(active).__name__, fields=len(active)):
                token = source._HELD_CYCLE_REPLAY.set(active)
                try:
                    with self.assertRaises(source.CycleSourceHoldError):
                        source.read_completed_cycle_evidence(self.store)
                finally:
                    source._HELD_CYCLE_REPLAY.reset(token)

    def test_live_scope_for_other_actual_store_does_not_supply_its_result(self):
        other = fixtures.IssueTrackerCycleSourceTests()
        other.setUp()
        self.addCleanup(other.doCleanups)
        with source._hold_completed_cycle_replay(self.store):
            self.assertEqual((), source.read_completed_cycle_evidence(other.store))
            self.assertEqual((1,), tuple(item.sequence for item in
                source.read_completed_cycle_evidence(self.store)))


class Req7OnlineCycleScopeWorkflowTests(unittest.TestCase):
    def test_actual_admitted_private_window_is_live_and_revoked_before_parent_replay(self):
        from monitor import issue_tracker_stage_l_consumer as consumer
        from test_cases.test_issue_tracker_stage_l_consumer_workflow import ProdStageLConsumerWorkflowTests
        fixture = ProdStageLConsumerWorkflowTests(
            'test_shared_retry_after_new_real_cycle_sends_only_the_original_unknown_wire')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        real_qualify = consumer.qualify_prod_stage_l
        real_projection = consumer._require_original_source_projection
        windows = []
        restored = []

        def qualify(store, **arguments):
            if type(store).__name__ == 'OriginalWindow':
                active = source._HELD_CYCLE_REPLAY.get()
                windows.append((store, active, copy_context(),
                    type(active) is tuple and len(active) == 3 and active[0] is store
                    and source._LIVE_CYCLE_REPLAYS.get(id(active)) is active))
            return real_qualify(store, **arguments)

        def projection(original, result):
            parent = source._HELD_CYCLE_REPLAY.get()
            for store, active, copied, _live in windows:
                parent_live = (type(parent) is tuple and len(parent) == 3
                    and parent[0] is fixture.store
                    and source._LIVE_CYCLE_REPLAYS.get(id(parent)) is parent)
                revoked = source._LIVE_CYCLE_REPLAYS.get(id(active)) is not active
                try:
                    copied.run(source.read_completed_cycle_evidence, store)
                except source.CycleSourceHoldError:
                    refused = True
                except Exception:
                    refused = False
                else:
                    refused = False
                restored.append((parent_live, revoked, refused))
            return real_projection(original, result)

        failure = None
        with mock.patch.object(consumer, 'qualify_prod_stage_l', side_effect=qualify), \
                mock.patch.object(consumer, '_require_original_source_projection', side_effect=projection):
            try:
                fixture.test_shared_retry_after_new_real_cycle_sends_only_the_original_unknown_wire()
            except Exception as exc:
                failure = exc
        # Facts are asserted after the production sanitizer has unwound.
        self.assertTrue(windows, 'actual admitted historical C6 must enter native requalification')
        self.assertTrue(all(live for _, _, _, live in windows),
            'only the actual private original window issuer may supply held cycle evidence')
        self.assertTrue(restored, 'original projection must run after restoring the full parent scope')
        self.assertTrue(all(facts == (True, True, True) for facts in restored),
            'private context must be revoked while its actual parent remains live')
        if failure is not None:
            raise failure

    def test_exited_worker_scope_in_copied_context_cannot_hide_next_real_cycle(self):
        fixture = fixtures.IssueTrackerCycleSourceTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        first = fixtures.completed(fixture.store, fixtures.TOKEN_1)
        with source._hold_completed_cycle_replay(fixture.store):
            copied = copy_context()
            self.assertEqual((first['cycle_id'],), tuple(item.cycle_id for item in
                copied.run(source.read_completed_cycle_evidence, fixture.store)))
        second = fixtures.completed(fixture.store, fixtures.TOKEN_2)
        before = {path.name: path.read_bytes() for path in fixture.store.records_dir.iterdir()}
        with self.assertRaises(source.CycleSourceHoldError):
            copied.run(source.read_completed_cycle_evidence, fixture.store)
        self.assertEqual((first['cycle_id'], second['cycle_id']), tuple(item.cycle_id for item in
            source.read_completed_cycle_evidence(fixture.store)))
        self.assertEqual(before, {path.name: path.read_bytes()
            for path in fixture.store.records_dir.iterdir()}, 'read rejection cannot repair originals')

    def exercise(self, method, boundary):
        from test_cases import test_req7_global_attempt_journal as fixtures
        from test_cases.test_issue_tracker_stage_l_consumer_workflow import ProdStageLConsumerWorkflowTests
        fixture = ProdStageLConsumerWorkflowTests(method)
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        real_load = fixtures.load
        reached = []

        def load():
            module = real_load()
            real_scope = getattr(module, boundary)

            @contextmanager
            def scope(*args, **kwargs):
                store = kwargs['store']
                with source._hold_completed_cycle_replay(store) as original:
                    active = source._HELD_CYCLE_REPLAY.get()
                    with real_scope(*args, **kwargs) as image:
                        self.assertIs(active, source._HELD_CYCLE_REPLAY.get())
                        self.assertIs(store, active[0])
                        self.assertIs(original, active[1])
                        body = json.loads(os.pread(image.fd, 1024 * 1024 + 1, 0))
                        reached.append((image.attempt_count,
                            type(body) is dict and set(body) == {'requests', 'includeSpreadsheetInResponse'}
                            and type(body['requests']) is list and bool(body['requests'])
                            and body['includeSpreadsheetInResponse'] is False))
                        yield image
                    original()
            setattr(module, boundary, scope)
            return module

        # Original real source/compiler/C6/CLAIM/encrypted request fixture:
        # only place its existing protected entry inside the actual outer scope.
        with mock.patch.object(fixtures, 'load', side_effect=load):
            getattr(fixture, method)()
        self.assertTrue(reached, 'actual protected count and original request must reach the outer scope')
        self.assertTrue(all(valid for _, valid in reached),
            'counted original FD contains the canonical JSON batch body, not an HTTP envelope')
        return reached

    def test_actual_first_request_under_the_terminal_cycle_original_scope(self):
        reached = self.exercise(
            'test_actual_continuous_count_scope_reaches_one_fixed_native_original_request',
            '_hold_continuous_owned_attempt_wire',
        )
        self.assertEqual({1}, {count for count, _ in reached})

    def test_actual_original_retry_under_the_terminal_cycle_original_scope(self):
        reached = self.exercise(
            'test_shared_retry_held_originals_reach_one_identical_native_request',
            '_hold_shared_retry_owned_attempt_wire',
        )
        self.assertEqual({2}, {count for count, _ in reached})

    def test_actual_retry_reads_are_issued_only_after_the_encrypted_fixture_is_ready(self):
        from test_cases.test_issue_tracker_stage_l_consumer_workflow import ProdStageLConsumerWorkflowTests
        from test_cases.test_req7_mutation_launcher import Req7MutationLauncherWorkflowTests
        from test_cases.test_req7_remote_history_match import Req7OwnedHistoryMatchWorkflowTests
        fixture = ProdStageLConsumerWorkflowTests(
            'test_shared_retry_after_new_real_cycle_sends_only_the_original_unknown_wire')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        real_server = Req7MutationLauncherWorkflowTests.server
        real_read = Req7OwnedHistoryMatchWorkflowTests.read_owned
        ready = []
        issued = []

        @contextmanager
        def server(actual, *args, **kwargs):
            with real_server(actual, *args, **kwargs) as endpoint:
                ready.append(actual)
                try:
                    yield endpoint
                finally:
                    self.assertIs(actual, ready.pop())

        def read(actual, *args, **kwargs):
            caller = sys._getframe(1)
            if caller.f_code.co_name in ('<dictcomp>', '<genexpr>'):
                caller = caller.f_back
            if caller.f_code.co_name == 'fresh_bundle':
                parent = caller.f_back
                mutation = parent.f_locals.get('native_mutation')
                if mutation is not None:
                    self.assertTrue(ready and ready[-1] is mutation,
                        'the real endpoint must be ready before FIRST/R2 issue original reads')
                    self.assertNotEqual(mutation.root, actual.root,
                        'nested read servers must not overwrite the prepared mutation trust root')
                    self.assertNotEqual(mutation.path, actual.path)
                    original_ca = mutation.path.read_bytes()
                    ca_stat = mutation.path.stat()
                    ca_identity = (ca_stat.st_dev, ca_stat.st_ino, ca_stat.st_size,
                                   ca_stat.st_mtime_ns, ca_stat.st_ctime_ns)
                    address = socket.getaddrinfo('sheets.googleapis.com', 443)
                    issued.append(parent.f_locals['count'])
                    result = real_read(actual, *args, **kwargs)
                    self.assertEqual(original_ca, mutation.path.read_bytes(),
                        'actual nested reads must preserve the prepared mutation CA bytes')
                    ca_stat = mutation.path.stat()
                    self.assertEqual(ca_identity, (ca_stat.st_dev, ca_stat.st_ino,
                        ca_stat.st_size, ca_stat.st_mtime_ns, ca_stat.st_ctime_ns))
                    self.assertEqual(address, socket.getaddrinfo('sheets.googleapis.com', 443),
                        'nested read DNS must restore the actual mutation endpoint')
                    return result
            return real_read(actual, *args, **kwargs)

        with mock.patch.object(Req7MutationLauncherWorkflowTests, 'server', server), \
                mock.patch.object(Req7OwnedHistoryMatchWorkflowTests, 'read_owned', read):
            fixture.test_shared_retry_after_new_real_cycle_sends_only_the_original_unknown_wire()
        self.assertEqual({1, 2}, set(issued))
        self.assertGreaterEqual(issued.count(1), 6)
        self.assertGreaterEqual(issued.count(2), 6)
        self.assertEqual([], ready)
