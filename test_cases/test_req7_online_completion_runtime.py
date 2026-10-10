"""Actual terminal cycle -> original C6/catalog -> fixed OAuth/four reads."""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest import mock

from test_cases import test_collection_cycle_persistence as persistence
from test_cases import test_req7_online_reconciliation as native
from test_cases.test_req7_global_attempt_journal import original_read_files


def cycle(stack, root, *, scope='prod', terminal=True):
    worker = persistence.WORKER
    project = root/'project'; project.mkdir(exist_ok=True)
    gate = stack.enter_context(worker.CollectionGate(str(project), scope,
        status_dir=root/'monitor/status', enforce_cooldown=False, lane='collection'))
    store = worker.CollectionCycleStore(gate=gate)
    with mock.patch.object(worker, '_mint_cycle_run_token', return_value=persistence.TOKEN_1):
        identity = store.allocate_start(process_inspector=lambda _binding: 'dead')
    store.publish_launch(identity, pid=4321, boot_id='owned-fixture-boot', process_start_time='9000',
        argv=['collector'], context={'scope': scope}, credential_argv_positions=(), credential_context_names=())
    if terminal: store._publish_crashed_completion(identity)
    return store


class OnlineCompletionRuntimeDirectTests(unittest.TestCase):
    def test_manifest_maps_default_online_original_lane_and_real_collector_flow(self):
        registry = json.loads((Path(__file__).resolve().parent/'script_test_manifest.json').read_text())
        module = 'test_cases.test_req7_online_completion_runtime'
        self.assertEqual(['issue-tracker-local'],
            [suite['id'] for suite in registry['test_suites'] if module in suite['tests']])
        originals = {'monitor/switch-collection-worker.py', 'monitor/issue_tracker_cycle_source.py',
            'monitor/issue_tracker_online_target.py', 'monitor/issue_tracker_credential_shape.py',
            'monitor/issue_tracker_remote_history_match.py'}
        for path in originals:
            self.assertTrue(any(path in rule['paths'] and module in rule['tests']
                for rule in registry['test_rules']), path)
        required = originals | {'monitor/switch_collection_gate.py', 'monitor/collection_v2_emitter.py',
            'ethernet/monitor/cron.sh', 'infiniband/monitor/cron.sh', 'nvlink/monitor/cron.sh',
            'monitor/issue_tracker_local_commit.py', 'monitor/issue_tracker_spreadsheet_owner.py',
            'monitor/issue_tracker_unit_catalog.py', 'monitor/issue_tracker_retained_inventory.py',
            'monitor/issue_tracker_history_read_launcher.py', 'monitor/issue_tracker_token_launcher.py'}
        self.assertTrue(any(required <= set(flow['members']) and module in flow['tests']
            for flow in registry['workflows']))

    def api(self):
        value = getattr(persistence.WORKER, '_reconcile_issue_tracker_online_after_completion', None)
        self.assertTrue(callable(value), 'durable cycle needs fixed online original-only lane')
        return value

    def test_nonstore_rejected_before_writer_or_any_authentication(self):
        api = self.api()
        from monitor import issue_tracker_local_commit as local
        from monitor import issue_tracker_token_launcher as tokens
        with mock.patch.object(local, 'try_writer_owner') as owner, \
                mock.patch.object(tokens, 'OwnedProjectTokenRefreshUnit') as auth:
            with self.assertRaises(persistence.WORKER.CollectionCycleHoldError): api(object())
        owner.assert_not_called(); auth.assert_not_called()

    def test_air_completion_does_not_enter_online_owner_or_auth(self):
        api = self.api()
        from monitor import issue_tracker_local_commit as local
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            store = cycle(stack, Path(directory).resolve(), scope='air')
            with mock.patch.object(local, 'try_writer_owner') as owner:
                self.assertIsNone(api(store))
            owner.assert_not_called()

    def test_incomplete_original_cycle_refuses_before_writer(self):
        api = self.api()
        from monitor import issue_tracker_local_commit as local
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            store = cycle(stack, Path(directory).resolve(), terminal=False)
            with mock.patch.object(local, 'try_writer_owner') as owner:
                with self.assertRaises(persistence.WORKER.CollectionCycleHoldError): api(store)
            owner.assert_not_called()

    def test_changed_store_binding_refuses_before_writer(self):
        api = self.api()
        from monitor import issue_tracker_local_commit as local
        for field in ('project_identity', 'project_key', 'records_dir', 'witness_path', 'source'):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                store = cycle(stack, Path(directory).resolve())
                setattr(store, field, 'foreign')
                with mock.patch.object(local, 'try_writer_owner') as owner:
                    with self.assertRaises(persistence.WORKER.CollectionCycleHoldError): api(store)
                owner.assert_not_called()

    def test_local_not_due_or_error_does_not_skip_online_lane(self):
        worker = persistence.WORKER; calls = []
        for fault in (None, ValueError('synthetic-private-detail')):
            calls.clear()
            with mock.patch.object(worker, '_publish_stage_l_status_after_completion'), \
                    mock.patch.object(worker, '_publish_stage_l_local_after_completion', side_effect=fault), \
                    mock.patch.object(worker, '_reconcile_issue_tracker_online_after_completion',
                        create=True, side_effect=lambda actual: calls.append(actual)), \
                    mock.patch.object(worker.sys, 'stderr', io.StringIO()) as stderr:
                store = object(); worker._publish_issue_tracker_lanes_after_completion(store)
                self.assertNotIn('synthetic-private-detail', stderr.getvalue())
            self.assertEqual([store], calls)

    def test_online_stall_diagnostic_is_fixed_and_cannot_echo_evidence_or_tokens(self):
        worker = persistence.WORKER
        report = getattr(worker, '_report_issue_tracker_online_read_only_result', None)
        self.assertTrue(callable(report), 'unresolved reconciliation needs an explicit no-send diagnostic')
        from monitor.issue_tracker_remote_history_match import RemoteHistoryObservation
        for state, expected in (
            ('UNKNOWN', 'Issue Tracker online stalled: UNKNOWN; read-only reconciliation; mutation disabled'),
            ('CONFLICT', 'Issue Tracker online stopped: CONFLICT; read-only reconciliation; mutation disabled'),
        ):
            with self.subTest(state=state), mock.patch.object(worker.sys, 'stderr', io.StringIO()) as stream:
                observation = RemoteHistoryObservation(state, 1, False, True, True, 1, 0, 3, 3,
                    'PRIVATE ACTION', 'PRIVATE WIRE', 'PRIVATE METADATA', 'PRIVATE HISTORY')
                report((observation,))
                self.assertEqual(expected + '\n', stream.getvalue())

    def test_read_only_report_rejects_caller_shapes_and_never_labels_applied_as_send_permission(self):
        worker = persistence.WORKER
        report = getattr(worker, '_report_issue_tracker_online_read_only_result', None)
        self.assertTrue(callable(report), 'fixed reconciliation result reporter missing')
        from monitor.issue_tracker_remote_history_match import AppliedEvidenceObservation
        for forged in (({'state': 'UNKNOWN'},), ['UNKNOWN'], (object(),)):
            with self.subTest(shape=type(forged).__name__), \
                    mock.patch.object(worker.sys, 'stderr', io.StringIO()) as stream:
                with self.assertRaises(worker.CollectionCycleHoldError): report(forged)
                self.assertEqual('', stream.getvalue())
        with mock.patch.object(worker.sys, 'stderr', io.StringIO()) as stream:
            report(())
            report((AppliedEvidenceObservation('APPLIED', 'original', 1, 'unit', ()),))
            self.assertEqual('', stream.getvalue(), 'historical APPLIED is not current online GO')


class OnlineCompletionRuntimeWorkflowTests(unittest.TestCase):
    _Fixture = native.OnlineReconciliationWorkflowTests._Fixture
    setUp = native.OnlineReconciliationWorkflowTests.setUp
    server = native.OnlineReconciliationWorkflowTests.server
    certificates = native.OnlineReconciliationWorkflowTests.certificates
    child_fixture = native.OnlineReconciliationWorkflowTests.child_fixture
    read_owned = native.OnlineReconciliationWorkflowTests.read_owned
    prepare_owned = native.OnlineReconciliationWorkflowTests.prepare_owned
    project_auth = native.OnlineReconciliationWorkflowTests.project_auth
    intercept = native.OnlineReconciliationWorkflowTests.intercept
    api = OnlineCompletionRuntimeDirectTests.api

    def owners(self, stack):
        from test_cases.test_req7_history_read_launcher import document, TARGET, scoped_fixture
        from monitor import issue_tracker_local_commit as local
        from monitor import issue_tracker_spreadsheet_owner as ownership
        from monitor import issue_tracker_online_target as target
        from monitor import issue_tracker_credential_shape as private
        from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
        import time
        project = self.root/'project'; publication = project/'99-output-monitor'
        publication.mkdir(mode=0o700); local.create_local_commit_store(project, publication)
        config = project/'01-global.yaml'; config.write_text(json.dumps(document(target=TARGET, cycles=3))); config.chmod(0o644)
        credentials = self.root/'var/lib/http-ztp-container/service-account'; credentials.mkdir(parents=True, mode=0o700)
        listing = credentials/'issue-tracker-spreadsheet-whitelist.json'; listing.write_text(json.dumps([TARGET])); listing.chmod(0o600)
        (self.root/'var/lib/http-ztp-container/issue-tracker').mkdir(mode=0o700)
        binding = target.bind_online_target(document(target=TARGET, cycles=3), target.freeze_target_allowlist(listing.read_bytes()))
        for module in (ownership, target, private): stack.enter_context(scoped_fixture(self.root, module))
        writer = self.initial_owners.enter_context(local.writer_owner(project, publication))
        owner = self.initial_owners.enter_context(ownership.spreadsheet_owner(binding))
        self.initial_writer = writer
        return local, ownership, writer, owner, binding, AuthenticatedToken('owned-private-token', time.time()+3600), config

    def exercise(self, fault=None, *, missing_fence=False):
        api = self.api()
        from monitor import issue_tracker_global_attempt_journal as globals_
        from monitor import issue_tracker_unit_catalog as catalog
        from monitor import issue_tracker_local_commit as local
        from monitor import issue_tracker_spreadsheet_owner as ownership
        from monitor import issue_tracker_token_launcher as tokens
        from monitor import issue_tracker_history_read_launcher as reads
        from monitor import issue_tracker_remote_history_match as match
        from monitor import issue_tracker_cycle_source as cycles
        with ExitStack() as stack, ExitStack() as initial:
            self.root = self.root.resolve()
            stack.enter_context(mock.patch.object(persistence.WORKER, 'STATUS_DIR', self.root/'monitor/status'))
            store = cycle(stack, self.root); self.initial_owners = initial
            real_prepare = globals_.prepare_global_unit
            def prepare(owner, binding, unit):
                catalog.register_pending_c6_unit(self.initial_writer, owner, binding, unit)
                return real_prepare(owner, binding, unit)
            with mock.patch.object(globals_, 'prepare_global_unit', side_effect=prepare):
                _writer, _owner, bound, _auth, _config, unit, docs = self.prepare_owned(stack, native_generation=True)
            initial.close()
            self.assertFalse(cycles.read_completed_cycle_evidence(store)[0].qualifying)
            cycle_before = {path.name: (path.stat().st_ino, path.read_bytes()) for path in store.records_dir.iterdir()}
            real_reconcile = match._reconcile_pending_project_units_and_project_auth
            owned = []; oauth = []; facts = []; substituted = []; closing_owners = []
            changed_input = []
            def replace_original(path):
                raw = path.read_bytes(); old = path.stat().st_ino
                path.rename(self.root/'preserved-input'); path.write_bytes(raw)
                path.chmod(0o644 if path.name == '01-global.yaml' else 0o600)
                substituted.append((old, path.stat().st_ino)); changed_input.append(path)
            def reconcile(writer, owner, binding, *args, **kwargs):
                owned.append((writer, owner, binding))
                closing_owners.append((writer, local._owner(writer).project_fd))
                return real_reconcile(writer, owner, binding, *args, **kwargs)
            stack.enter_context(mock.patch.object(match, '_reconcile_pending_project_units_and_project_auth', side_effect=reconcile))
            real_refresh = tokens.OwnedProjectTokenRefreshUnit.refresh_once
            def refresh_actual(refresh_unit):
                writer, owner, binding = owned[-1]
                oauth.append((refresh_unit._owner_token is owner, refresh_unit._binding == bound))
                if fault == 'before-auth':
                    path = store.completion_path(1); raw = path.read_bytes(); old = path.stat().st_ino
                    path.rename(self.root/'preserved-cycle'); path.write_bytes(raw); path.chmod(0o600)
                    substituted.append((old, path.stat().st_ino))
                with mock.patch.object(tokens.OwnedProjectTokenRefreshUnit, 'refresh_once', real_refresh):
                    value, _credential, _raw = self.project_auth(stack, ownership, owner, binding)
                if fault == 'allowlist-after-auth':
                    replace_original(self.root/'var/lib/http-ztp-container/service-account/issue-tracker-spreadsheet-whitelist.json')
                self.certificates('sheets.googleapis.com')
                return value
            stack.enter_context(mock.patch.object(tokens.OwnedProjectTokenRefreshUnit, 'refresh_once', autospec=True, side_effect=refresh_actual))
            real_read = reads.OwnedProjectSheetsReadUnit.read_once
            def read_actual(reader):
                writer, owner, binding = owned[-1]
                doc = deepcopy(dict(docs.values())[reader._kind])
                if missing_fence and reader._kind == 'metadata':
                    entries = doc['matchedDeveloperMetadata']
                    before_count = len(entries)
                    doc['matchedDeveloperMetadata'] = [item for item in entries
                        if item['developerMetadata']['metadataId'] != unit.fence_metadata_id]
                    self.assertEqual(before_count - 1, len(doc['matchedDeveloperMetadata']))
                body = json.dumps(doc, separators=(',', ':')).encode()
                reply = b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body
                with self.server(reply, hostname='sheets.googleapis.com', destination='sheets.googleapis.com') as (records, errors), ExitStack() as launched:
                    port = socket.getaddrinfo('sheets.googleapis.com', 443)[0][4][1]
                    calls, children = self.intercept(launched, self.child_fixture(port), writer, owner, binding)
                    value = real_read(reader)
                facts.append((reader._kind, len(records), len(calls), tuple(type(error).__name__ for error in errors), children[0].returncode))
                if fault == 'last-read' and reader._kind == 'history_tail':
                    path = store.completion_path(1); raw = path.read_bytes(); old = path.stat().st_ino
                    path.rename(self.root/'preserved-cycle'); path.write_bytes(raw); path.chmod(0o600)
                    substituted.append((old, path.stat().st_ino))
                if fault == 'config-last-read' and reader._kind == 'history_tail':
                    replace_original(self.root/'project/01-global.yaml')
                if fault == 'gate-last-read' and reader._kind == 'history_tail':
                    original = store.gate.project; store.gate.project = str(self.root/'foreign')
                    substituted.append((original, store.gate.project))
                return value
            if missing_fence:
                # Prepare the owned OAuth fixture before measuring production
                # side effects; the actual lazy refresh still performs TLS.
                from test_req7_sdk_authentication import fresh_info
                credential = self.root/'var/lib/http-ztp-container/service-account/cre.json'
                self.assertFalse(credential.exists())
                info = fresh_info(); info['project_id'] = 'synthetic-cloud-project'
                credential.write_bytes(json.dumps(info).encode()); credential.chmod(0o600)
            before = {name: raw for name, raw in original_read_files(self.root).items()
                if name.startswith(('project/', 'var/lib/http-ztp-container/'))}
            state = self.root/'var/lib/http-ztp-container/issue-tracker'
            prefix = hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()+'.unit-'+unit.unit_id
            revoked = []
            if fault in ('config-owner-close', 'allowlist-owner-close'):
                real_close = local.os.close
                def close_then_drift(fd):
                    result = real_close(fd)
                    if closing_owners and fd == closing_owners[-1][1] and not substituted:
                        revoked.append(closing_owners[-1][0] not in local._ACTIVE)
                        path = (self.root/'project/01-global.yaml' if fault == 'config-owner-close' else
                            self.root/'var/lib/http-ztp-container/service-account/issue-tracker-spreadsheet-whitelist.json')
                        replace_original(path)
                    return result
                stack.enter_context(mock.patch.object(local.os, 'close', side_effect=close_then_drift))
            if fault == 'creator-header':
                real_write = local._write_new
                def write_then_drift(parent, name, raw):
                    result = real_write(parent, name, raw)
                    folder = state/(prefix+'.completion')
                    if name == 'HEADER' and folder.is_dir() and not substituted:
                        expected = folder.stat(); actual = os.fstat(parent)
                        if (expected.st_dev, expected.st_ino) == (actual.st_dev, actual.st_ino):
                            path = store.completion_path(1); original = path.read_bytes(); old = path.stat().st_ino
                            path.rename(self.root/'preserved-cycle'); path.write_bytes(original); path.chmod(0o600)
                            substituted.append((old, path.stat().st_ino))
                    return result
                stack.enter_context(mock.patch.object(local, '_write_new', side_effect=write_then_drift))
            stack.enter_context(mock.patch.object(reads.OwnedProjectSheetsReadUnit, 'read_once', autospec=True, side_effect=read_actual))
            if fault:
                with self.assertRaises(persistence.WORKER.CollectionCycleHoldError) as caught: api(store)
                self.assertIsNone(caught.exception.__context__)
            else:
                with mock.patch.object(persistence.WORKER.sys, 'stderr', io.StringIO()) as online_stderr:
                    result = api(store)
                diagnostic = online_stderr.getvalue()
            self.assertEqual([(True, True)], oauth)
            self.assertEqual([] if fault in ('before-auth', 'allowlist-after-auth') else [(kind, 1, 1, (), 0) for kind in
                ('template_identity', 'template_headers', 'metadata', 'history_tail')], facts)
            if changed_input:
                before = {name: raw for name, raw in before.items()
                    if name != str(changed_input[0].relative_to(self.root))}
            self.assertTrue(before.items() <= original_read_files(self.root).items())
            attempts = list((state/(prefix+'.journal')).glob('ATTEMPT-*'))
            self.assertEqual(['ATTEMPT-1'], [path.name for path in attempts])
            self.assertEqual('UNKNOWN', json.loads(attempts[0].read_bytes())['outcome'])
            applied = self.root/'project/.tracker'/('REMOTE-APPLIED-'+unit.unit_id)
            if fault:
                self.assertEqual(1, len(substituted)); self.assertNotEqual(*substituted[0])
                if fault in ('config-owner-close', 'allowlist-owner-close'):
                    self.assertEqual([True], revoked)
                    self.assertTrue(applied.is_file())
                    self.assertTrue((state/(prefix+'.completion')/'COMPLETE').is_file())
                elif fault == 'creator-header':
                    self.assertFalse(applied.exists())
                    self.assertTrue((state/(prefix+'.completion')/'HEADER').is_file())
                    self.assertFalse((state/(prefix+'.completion')/'COMPLETE').exists())
                else:
                    self.assertFalse(applied.exists())
                    self.assertFalse((state/(prefix+'.completion')).exists())
                if changed_input:
                    self.assertEqual((self.root/'preserved-input').read_bytes(), changed_input[0].read_bytes())
                elif fault != 'gate-last-read':
                    self.assertEqual((self.root/'preserved-cycle').read_bytes(), store.completion_path(1).read_bytes())
            elif missing_fence:
                self.assertEqual(('UNKNOWN',), tuple(item.state for item in result))
                self.assertFalse(applied.exists())
                self.assertFalse((state/(prefix+'.completion')).exists())
                self.assertFalse((state/(prefix+'.dispatch')).exists())
                self.assertEqual(before, {name: raw for name, raw in original_read_files(self.root).items()
                    if name.startswith(('project/', 'var/lib/http-ztp-container/'))})
                self.assertEqual(cycle_before, {path.name: (path.stat().st_ino, path.read_bytes())
                    for path in store.records_dir.iterdir()})
                self.assertEqual('Issue Tracker online stalled: UNKNOWN; read-only reconciliation; mutation disabled\n', diagnostic)
                visible = json.loads((self.root/'monitor/status/issue-tracker-online.status.json').read_bytes())
                self.assertEqual({'schema_version', 'state', 'updated_at', 'read_only', 'mutation_disabled'}, set(visible))
                self.assertEqual('stalled', visible['state'])
                self.assertIs(True, visible['read_only']); self.assertIs(True, visible['mutation_disabled'])
            else:
                self.assertEqual(('APPLIED',), tuple(item.state for item in result)); self.assertTrue(applied.exists())
                self.assertEqual(cycle_before, {path.name: (path.stat().st_ino, path.read_bytes()) for path in store.records_dir.iterdir()})

    def test_nonqualifying_real_terminal_cycle_still_reconciles_original_counted_unknown(self): self.exercise()
    def test_cycle_original_replaced_at_actual_oauth_revokes_before_any_four_reads(self): self.exercise('before-auth')
    def test_cycle_original_replaced_after_last_actual_read_revokes_before_complete_applied(self): self.exercise('last-read')
    def test_actual_gate_project_drift_after_last_read_revokes_before_completion(self): self.exercise('gate-last-read')
    def test_same_byte_current_policy_rebind_after_last_read_revokes_before_completion(self): self.exercise('config-last-read')
    def test_same_byte_fixed_allowlist_rebind_after_actual_auth_revokes_before_reads(self): self.exercise('allowlist-after-auth')
    def test_actual_creator_header_cycle_drift_refuses_complete_marker_not_only_applied(self): self.exercise('creator-header')
    def test_policy_original_outlives_actual_project_owner_revoke_close(self): self.exercise('config-owner-close')
    def test_allowlist_original_outlives_actual_project_owner_revoke_close(self): self.exercise('allowlist-owner-close')
    def test_actual_missing_fence_four_reads_reports_stall_without_count_claim_or_mutation(self):
        self.exercise(missing_fence=True)


class OnlineCompletionCollectorDispatchWorkflowTests(unittest.TestCase):
    """Real collector dispatch edge, distinct from the native OAuth tests above."""
    def exercise(self, fault=None):
        from test_cases import test_collection_cycle_handoff_workflow as handoff
        marker = 'original_interruptible = worker["run_interruptible"]'
        self.assertEqual(1, handoff.BOOTSTRAP.count(marker))
        observer = '''online_dispatch_facts = []
online_dispatch_fault = FAULT_LITERAL
def observe_completion_lane(phase):
    def observe(store):
        raw = {path.name: path.read_bytes() for path in sorted(Path(store.records_dir).glob("*.json"))}
        finished = json.loads(raw["00000000000000000001.completion.json"])
        online_dispatch_facts.append({"phase": phase, "source": store.source,
            "scope": store.scope, "project": store.project_identity,
            "gate_live": isinstance(store.gate._lock_fd, int) and store.gate._lock_fd >= 0,
            "cycle_id": finished["identity"]["cycle_id"], "outcome": finished["outcome"],
            "sha256": {name: hashlib.sha256(data).hexdigest() for name,data in raw.items()}})
        if phase == online_dispatch_fault: raise ValueError("synthetic-private-lane-detail")
        return None
    return observe
for phase, name in (("status", "_publish_stage_l_status_after_completion"),
    ("local", "_publish_stage_l_local_after_completion"),
    ("online", "_reconcile_issue_tracker_online_after_completion")):
    worker["run_collection_cycle_coordinator"].__globals__[name] = observe_completion_lane(phase)
'''.replace('FAULT_LITERAL', repr(fault))
        field = '"persisted": persisted if action in ("persisted", "sigkill") else None,'
        self.assertEqual(1, handoff.BOOTSTRAP.count(field))
        bootstrap = handoff.BOOTSTRAP.replace(marker, observer+marker).replace(field,
            field+'\n        "online_dispatch_facts": online_dispatch_facts,')
        with tempfile.TemporaryDirectory(prefix='req7-online-collector-edge-') as directory, \
                mock.patch.object(handoff, 'BOOTSTRAP', bootstrap):
            harness = handoff.CollectionCycleHandoffWorkflowTests()
            root = harness.make_layout(directory)
            completed, payload, traces = harness.run_workflow(root, 'prod', action='persisted')
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertIsNotNone(payload, completed.stdout)
            self.assertTrue(payload['returned'])
            records = payload['persisted']['records']; completion = records['00000000000000000001.completion.json']
            self.assertEqual(payload['result'], completion['run_result'])
            self.assertEqual('cycle_completed', completion['outcome'])
            self.assertEqual(['status', 'local', 'online'], [fact['phase'] for fact in payload['online_dispatch_facts']])
            record_root = root/'monitor/status/collection-cycles'/completion['identity']['project_key']/'prod/switch_collection/records'
            expected = {name: hashlib.sha256((record_root/name).read_bytes()).hexdigest() for name in
                ('00000000000000000001.start.json', '00000000000000000001.launch.json', '00000000000000000001.completion.json')}
            for fact in payload['online_dispatch_facts']:
                self.assertEqual(expected, fact['sha256'])
                self.assertEqual(completion['identity']['cycle_id'], fact['cycle_id'])
                self.assertEqual(completion['identity']['project_key'],
                    hashlib.sha256(fact['project'].encode('utf-8')).hexdigest())
                self.assertEqual(('switch_collection', 'prod', True, 'cycle_completed'),
                    (fact['source'], fact['scope'], fact['gate_live'], fact['outcome']))
            self.assertNotIn('synthetic-private-lane-detail', completed.stderr)
            self.assertEqual(3, len(traces))
            self.assertEqual(['accepted']*3, [row['outcome'] for row in payload['result']['outcomes']])

    def test_real_three_cron_completion_dispatches_online_even_local_not_due(self): self.exercise()
    def test_real_three_cron_status_failure_does_not_skip_local_online(self): self.exercise('status')
    def test_real_three_cron_local_failure_does_not_skip_online(self): self.exercise('local')
    def test_real_three_cron_online_failure_keeps_original_durable_completion(self): self.exercise('online')
