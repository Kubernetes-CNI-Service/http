"""Non-authoritative last-observation display: never a send admission."""
from contextlib import ExitStack, contextmanager
import errno
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from test_cases.test_monitor_stack_review import load_module, ROOT
from test_cases.test_collection_cycle_persistence import WORKER
from test_cases.test_issue_tracker_manual_ui import HTML, page

CGI = load_module('req7_online_observation_cgi', ROOT/'monitor/switch-collection-control.cgi')
STAMP = '2026-01-01T00:00:00+00:00'
AUTH = {'CONTROL_REQUIRE_AUTH': '1', 'AUTH_TYPE': 'Basic', 'REMOTE_USER': 'nvis',
    'SCRIPT_NAME': '/monitor/control/switch-collection', 'PATH_INFO': '',
    'REQUEST_METHOD': 'GET', 'QUERY_STRING': 'view=issue_tracker_online'}


def observed(state):
    from monitor.issue_tracker_remote_history_match import RemoteHistoryObservation
    return RemoteHistoryObservation(state, 1, False, True, True, 1, 0, 3, 3,
        'PRIVATE ACTION', 'PRIVATE WIRE', 'PRIVATE METADATA', 'PRIVATE HISTORY')


def snapshot(state):
    return {'schema_version': 1, 'state': state, 'updated_at': STAMP,
        'read_only': True, 'mutation_disabled': True}


def unproved():
    return {'schema_version': 1, 'state': 'unproved', 'updated_at': None,
        'read_only': True, 'mutation_disabled': True}


def browser(payload):
    script = getattr(HTML, '_ISSUE_TRACKER_ONLINE_STATUS_SCRIPT', None)
    if not isinstance(script, str):
        raise AssertionError('default online last-observation script missing')
    node = shutil.which('node')
    if node is None:
        bundled = Path.home()/'.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node'
        if bundled.is_file(): node = str(bundled)
    if node is None: raise AssertionError('online display contract needs local Node')
    fixture = '''
const label = {textContent: ''};
const document = {getElementById: id => id === 'issue-tracker-online-state' ? label : null};
const SWITCH_COLLECTION_URL = '/monitor/control/switch-collection';
const calls = [];
async function fetch(url, options) {
  calls.push({url, options});
  return {ok: true, async json(){return PAYLOAD}};
}
'''.replace('PAYLOAD', json.dumps(payload))
    result = subprocess.run([node, '-e', fixture+script+'''
refreshIssueTrackerOnlineStatus().then(() => {
  console.log(JSON.stringify({text: label.textContent, calls}));
}).catch(error => {console.error(error); process.exitCode = 1});
'''], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
    if result.returncode != 0: raise AssertionError(result.stderr)
    return json.loads(result.stdout)


class OnlineObservationStatusDirectTests(unittest.TestCase):
    def test_fixed_transport_observations_are_read_only_never_remote_complete(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(CGI, 'STATUS_DIR', Path(directory)):
            path = Path(directory)/'issue-tracker-online.status.json'
            for state in ('attempted_unknown', 'attempted_definite_rejection', 'attempt_unproved'):
                value = snapshot(state); path.write_text(json.dumps(value)); path.chmod(0o644)
                self.assertEqual(value, self.reader()())
                for field in ('read_only', 'mutation_disabled'):
                    path.write_text(json.dumps({**value, field: False}))
                    self.assertEqual(unproved(), self.reader()())

    def publisher(self):
        publish = getattr(WORKER, '_publish_issue_tracker_online_observation_status', None)
        self.assertTrue(callable(publish), 'fixed non-authoritative observation publisher missing')
        return publish

    def reader(self):
        read = getattr(CGI, 'issue_tracker_online_status', None)
        self.assertTrue(callable(read), 'protected fixed diagnostic reader missing')
        return read

    def test_typed_states_have_fixed_schema_no_evidence_or_current_send_permission(self):
        from monitor.issue_tracker_remote_history_match import AppliedEvidenceObservation
        publish = self.publisher()
        cases = (((), 'no_counted_units'), ((observed('UNKNOWN'),), 'stalled'),
            ((observed('CONFLICT'),), 'conflict'),
            ((observed('UNKNOWN'), observed('CONFLICT')), 'conflict'),
            ((AppliedEvidenceObservation('APPLIED', 'PRIVATE', 1, 'PRIVATE', ()),), 'historical_applied'))
        for values, expected in cases:
            with self.subTest(expected=expected), mock.patch.object(WORKER, '_write_status_file') as write:
                publish(values)
                write.assert_called_once_with(WORKER.STATUS_DIR/'issue-tracker-online.status.json',
                    '.issue-tracker-online.', expected, schema_version=1,
                    read_only=True, mutation_disabled=True)

    def test_mixed_forged_result_cannot_write_a_partial_snapshot(self):
        publish = self.publisher()
        for values in ([observed('UNKNOWN')], (observed('UNKNOWN'), object()),
                ({'state': 'UNKNOWN'},), (observed('MATCHED_OBSERVATION'),)):
            with self.subTest(shape=type(values).__name__), mock.patch.object(WORKER, '_write_status_file') as write:
                with self.assertRaises(WORKER.CollectionCycleHoldError): publish(values)
                write.assert_not_called()

    def test_missing_malformed_untrusted_or_future_snapshot_is_unproved_not_idle(self):
        read = self.reader()
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(CGI, 'STATUS_DIR', Path(directory)):
            path = Path(directory)/'issue-tracker-online.status.json'
            self.assertEqual(unproved(), read())
            invalid = (b'not-json', b'{}', json.dumps({**snapshot('stalled'), 'token': 'PRIVATE'}).encode(),
                json.dumps({**snapshot('stalled'), 'read_only': False}).encode(),
                json.dumps({**snapshot('stalled'), 'schema_version': True}).encode(),
                json.dumps({**snapshot('stalled'), 'updated_at': '2999-01-01T00:00:00+00:00'}).encode(),
                json.dumps({**snapshot('stalled'), 'updated_at': STAMP[:-6]}).encode(),
                json.dumps(snapshot('GO')).encode(), b'{"state":"stalled","state":"conflict"}',
                b'x'*4097)
            for raw in invalid:
                with self.subTest(raw_size=len(raw)):
                    path.write_bytes(raw); path.chmod(0o644)
                    self.assertEqual(unproved(), read()); self.assertEqual(raw, path.read_bytes())

    def test_valid_old_observation_remains_diagnostic_and_is_not_expired_into_go(self):
        read = self.reader()
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(CGI, 'STATUS_DIR', Path(directory)):
            path = Path(directory)/'issue-tracker-online.status.json'
            for state in ('stalled', 'conflict', 'historical_applied', 'no_counted_units'):
                value = snapshot(state); path.write_text(json.dumps(value)); path.chmod(0o644)
                self.assertEqual(value, read())

    def test_symlink_hardlink_fifo_and_writable_image_are_not_observations(self):
        read = self.reader()
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(CGI, 'STATUS_DIR', Path(directory)):
            root = Path(directory); path = root/'issue-tracker-online.status.json'; foreign = root/'foreign'
            foreign.write_text(json.dumps(snapshot('stalled'))); before = foreign.read_bytes()
            path.symlink_to(foreign); self.assertEqual(unproved(), read()); path.unlink()
            os.link(foreign, path); self.assertEqual(unproved(), read()); path.unlink()
            os.mkfifo(path); self.assertEqual(unproved(), read()); path.unlink()
            path.write_bytes(before); path.chmod(0o666); self.assertEqual(unproved(), read())
            self.assertEqual(before, foreign.read_bytes())

    def test_authentication_still_precedes_online_snapshot_access(self):
        self.reader()
        for override in ({'REMOTE_USER': 'foreign'}, {'CONTROL_REQUIRE_AUTH': '0'}, {'PATH_INFO': '/extra'}):
            with mock.patch.dict(os.environ, {**AUTH, **override}, clear=True), \
                    mock.patch.object(CGI, 'issue_tracker_online_status') as read, \
                    mock.patch.object(CGI, 'process_state') as process, mock.patch.object(CGI, 'respond') as respond:
                CGI.main(); read.assert_not_called(); process.assert_not_called()
                self.assertEqual('403 Forbidden', respond.call_args.args[1])

    def first_stat_fault(self, phase, replace_with_foreign):
        """Actual opened FD, one stat fault, and independently checked cleanup."""
        real_open, real_fstat = os.open, os.fstat
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'issue-tracker-online.status.json').write_text(json.dumps(snapshot('stalled')))
            foreign = root/'foreign'; foreign.write_bytes(b'FOREIGN MUST SURVIVE')
            foreign_fd = real_open(foreign, os.O_RDONLY)
            foreign_identity = real_fstat(foreign_fd)
            opened = {}; faulted = []; survivors = []
            def open_actual(path, flags, **kwargs):
                fd = real_open(path, flags, **kwargs)
                kind = 'image' if str(path) == 'issue-tracker-online.status.json' else 'parent'
                opened[fd] = (kind, real_fstat(fd))
                return fd
            def first_fault(fd):
                if fd in opened and opened[fd][0] == phase and not faulted:
                    faulted.append(fd)
                    if replace_with_foreign: os.dup2(foreign_fd, fd)
                    raise OSError(errno.EIO, 'independent first fstat fault')
                return real_fstat(fd)
            try:
                with mock.patch.object(CGI, 'STATUS_DIR', root), \
                        mock.patch.object(CGI.os, 'open', side_effect=open_actual), \
                        mock.patch.object(CGI.os, 'fstat', side_effect=first_fault):
                    self.assertEqual(unproved(), self.reader()())
                self.assertEqual(1, len(faulted))
                for fd in opened:
                    try: current = real_fstat(fd)
                    except OSError as error:
                        self.assertEqual(errno.EBADF, error.errno)
                    else:
                        survivors.append(fd)
                        self.assertTrue(replace_with_foreign and fd == faulted[0],
                            'reader leaked an actual owned FD after first fstat failed')
                        self.assertEqual((foreign_identity.st_dev, foreign_identity.st_ino),
                            (current.st_dev, current.st_ino))
                self.assertEqual([faulted[0]] if replace_with_foreign else [], survivors)
                self.assertEqual(b'FOREIGN MUST SURVIVE', os.pread(foreign_fd, 100, 0))
                if replace_with_foreign:
                    self.assertEqual(b'FOREIGN MUST SURVIVE', os.pread(faulted[0], 100, 0))
            finally:
                # Only this fixture's opens/dup2 targets; never enumerate unrelated FDs.
                for fd in (*opened, foreign_fd):
                    try: os.close(fd)
                    except OSError as error:
                        if error.errno != errno.EBADF: raise

    def test_first_fstat_failure_closes_actual_owned_parent_and_image(self):
        for phase in ('parent', 'image'):
            with self.subTest(phase=phase): self.first_stat_fault(phase, False)

    def test_first_fstat_failure_does_not_close_rebound_foreign_descriptor(self):
        for phase in ('parent', 'image'):
            with self.subTest(phase=phase): self.first_stat_fault(phase, True)

    def test_default_page_has_only_independent_read_only_label_not_manual_route(self):
        rendered = page()
        self.assertIn('id="issue-tracker-online-state"', rendered)
        self.assertIn('refreshIssueTrackerOnlineStatus();', rendered)
        self.assertNotIn('/monitor/control/issue-tracker', rendered)
        self.assertNotIn('issueTrackerManualPreview(', rendered)


class OnlineObservationStatusWorkflowTests(unittest.TestCase):

    def test_original_enrollment_refusal_reaches_worker_status_and_authenticated_cgi_only_after_cleanup(self):
        from test_cases import test_req7_online_completion_runtime as runtime
        from test_cases.test_req7_sheets_read_decode import identity_response
        from test_cases.test_req7_history_read import response
        import hashlib
        import time
        for fault in ('missing', 'partial', 'cleanup-error', 'cleanup-interrupt'):
            with self.subTest(fault=fault):
                # Reuse the existing registry-binding setup. Its private CA
                # fixture is unused here: no TLS server or client is started.
                fixture = runtime.OnlineCompletionRuntimeWorkflowTests()
                fixture.setUp()
                try:
                    # Capture the canonical registries AFTER the existing
                    # fixture's deliberate support-module reloads, before
                    # issuing any original owner token.
                    from monitor import issue_tracker_enrollment_journal as enrollment
                    from monitor import issue_tracker_local_commit as local
                    from monitor import issue_tracker_spreadsheet_owner as ownership
                    from monitor import issue_tracker_online_target as target
                    from monitor import issue_tracker_token_launcher as tokens
                    from monitor import issue_tracker_history_read_launcher as reads
                    from monitor import issue_tracker_global_attempt_journal as journal
                    from monitor import issue_tracker_mutation_launcher as mutation
                    from monitor import issue_tracker_sheets_read_plan as plans
                    from monitor import issue_tracker_sheets_read_decode as decode
                    from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
                    with tempfile.TemporaryDirectory(prefix='req7-enrollment-status-') as raw, ExitStack() as stack:
                        root = Path(raw).resolve()
                        fixture.root = root
                        initial = stack.enter_context(ExitStack())
                        fixture.initial_owners = initial
                        store = runtime.cycle(stack, root)
                        _local, _ownership, writer, owner, bound, _unused, _config = fixture.owners(stack)
                        original_identity = identity_response()
                        original_identity['spreadsheetId'] = bound.spreadsheet_id
                        parsed_identity = decode.decode_template_identity(
                            plans.prepare_template_identity_read(bound, AuthenticatedToken('fixture-only', time.time()+3600)),
                            response(original_identity))
                        state = root/'var/lib/http-ztp-container/issue-tracker'
                        stem = hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
                        if fault == 'partial':
                            with mock.patch('secrets.token_hex', side_effect=['a'*64, 'b'*64, 'c'*64, 'd'*64]):
                                enrollment.prepare_enrollment_journal(owner, bound, parsed_identity)
                            (state/(stem+'.enrollment')/'INITIALIZED').rename(root/'retained-original-marker')
                        initial.close()
                        before = {str(path.relative_to(state)): (path.stat().st_ino, path.read_bytes())
                                  for path in state.rglob('*') if path.is_file()}
                        old = snapshot('stalled')
                        status = root/'monitor/status/issue-tracker-online.status.json'
                        status.write_text(json.dumps(old)); status.chmod(0o644)
                        closed = []
                        ordinary = RuntimeError('fixture cleanup fault; not an enrollment reason')
                        interrupt = KeyboardInterrupt('fixture cleanup interruption')
                        preset = ValueError('independent preset cause')
                        interrupt.__cause__ = preset
                        actual_writer, actual_sheet = local.try_writer_owner, ownership.spreadsheet_owner
                        actual_target, actual_write = target._hold_current_project_online_target, WORKER._write_status_file

                        @contextmanager
                        def original_role(factory, label, *args, **kwargs):
                            body_error = None
                            try:
                                with factory(*args, **kwargs) as actual:
                                    try:
                                        yield actual
                                    except BaseException as error:
                                        body_error = error
                                        raise
                            except BaseException as error:
                                if error is not body_error:
                                    raise  # A different cleanup failure is never marked completed.
                                closed.append(label)
                                if label == 'sheet' and fault == 'cleanup-error':
                                    raise ordinary
                                if label == 'sheet' and fault == 'cleanup-interrupt':
                                    raise interrupt
                                raise
                            else:
                                closed.append(label)
                                if label == 'sheet' and fault == 'cleanup-error':
                                    raise ordinary
                                if label == 'sheet' and fault == 'cleanup-interrupt':
                                    raise interrupt

                        def write_after_roles(*args, **kwargs):
                            self.assertEqual(['sheet', 'writer', 'target'], closed,
                                             'no known diagnostic before original owner finalizers')
                            return actual_write(*args, **kwargs)

                        stack.enter_context(mock.patch.object(local, 'try_writer_owner',
                            side_effect=lambda *a, **k: original_role(actual_writer, 'writer', *a, **k)))
                        stack.enter_context(mock.patch.object(ownership, 'spreadsheet_owner',
                            side_effect=lambda *a, **k: original_role(actual_sheet, 'sheet', *a, **k)))
                        stack.enter_context(mock.patch.object(target, '_hold_current_project_online_target',
                            side_effect=lambda *a, **k: original_role(actual_target, 'target', *a, **k)))
                        stack.enter_context(mock.patch.object(WORKER, 'STATUS_DIR', root/'monitor/status'))
                        stack.enter_context(mock.patch.object(CGI, 'STATUS_DIR', root/'monitor/status'))
                        stack.enter_context(mock.patch.object(WORKER, 'timestamp', return_value=STAMP))
                        stack.enter_context(mock.patch.object(WORKER, '_write_status_file', side_effect=write_after_roles))
                        # The independent Stage-L lanes are not subjects of this
                        # workflow. The original online dispatcher/owner graph is.
                        stack.enter_context(mock.patch.object(WORKER, '_publish_stage_l_status_after_completion'))
                        stack.enter_context(mock.patch.object(WORKER, '_publish_stage_l_local_after_completion'))
                        blocked = []
                        for module, name in ((enrollment, 'prepare_enrollment_journal'),
                                (tokens, 'OwnedProjectTokenRefreshUnit'), (reads, 'OwnedProjectSheetsReadUnit'),
                                (journal, 'record_global_attempt_intent'), (mutation, '_send_counted_original_once'),
                                (WORKER, '_dispatch_current_project_online_originals')):
                            blocked.append(stack.enter_context(mock.patch.object(
                                module, name, side_effect=AssertionError('read-only precondition must not execute ' + name))))
                        network = stack.enter_context(mock.patch('socket.socket', side_effect=AssertionError('No network')))
                        child = stack.enter_context(mock.patch('subprocess.Popen', side_effect=AssertionError('No child')))
                        stack.enter_context(mock.patch.object(WORKER.sys, 'stderr', io.StringIO()))
                        if fault == 'cleanup-interrupt':
                            with self.assertRaises(KeyboardInterrupt) as caught:
                                WORKER._publish_issue_tracker_lanes_after_completion(store)
                            self.assertIs(interrupt, caught.exception)
                            self.assertIs(preset, caught.exception.__cause__)
                        else:
                            WORKER._publish_issue_tracker_lanes_after_completion(store)
                        for operation in (*blocked, network, child):
                            operation.assert_not_called()
                        after = {str(path.relative_to(state)): (path.stat().st_ino, path.read_bytes())
                                 for path in state.rglob('*') if path.is_file()}
                        self.assertEqual(before, after, 'diagnostics cannot initialize/adopt/repair enrollment')
                        self.assertFalse(list(state.rglob('ATTEMPT-*')))
                        self.assertFalse(list(state.rglob('CLAIM-*')))
                        self.assertFalse(list(state.glob('*.units')))
                        original_status = status.read_bytes()
                        if fault.startswith('cleanup-'):
                            self.assertEqual(old, json.loads(original_status),
                                             'unknown cleanup must not publish a known enrollment reason')
                            continue
                        stack.enter_context(mock.patch.dict(os.environ, AUTH, clear=True))
                        stack.enter_context(mock.patch.object(CGI, 'process_state', return_value=(False, None)))
                        for name in ('collection_status', 'yaml_backup_status', 'continuous_collection_status', 'continuous_backup_status'):
                            stack.enter_context(mock.patch.object(CGI, name, return_value={'state': 'idle'}))
                        stack.enter_context(mock.patch.object(CGI, 'request_action', return_value=None))
                        respond = stack.enter_context(mock.patch.object(CGI, 'respond'))
                        request = stack.enter_context(mock.patch.object(CGI, 'write_request'))
                        CGI.main()
                        respond.assert_called_once(); request.assert_not_called()
                        projected = respond.call_args.args[0]
                        self.assertEqual(original_status, status.read_bytes(), 'authenticated read cannot mutate the snapshot')
                        # Closed schema/type negatives for the two new fixed
                        # states; they do not authorize arbitrary reason text.
                        expected = 'enrollment_missing' if fault == 'missing' else 'enrollment_incomplete'
                        for invalid in ({**snapshot(expected), 'reason': 'PRIVATE'},
                                {**snapshot(expected), 'schema_version': True},
                                {**snapshot(expected), 'read_only': 1},
                                {**snapshot(expected), 'mutation_disabled': False},
                                snapshot({'state': expected}), snapshot(expected + '_PRIVATE')):
                            status.write_text(json.dumps(invalid)); status.chmod(0o644)
                            self.assertEqual(unproved(), CGI.issue_tracker_online_status())
                        self.assertEqual({**snapshot(expected), 'process_alive': False}, projected,
                                         'ENROLLMENT_WORKER_FIXED_STATUS_MISSING')
                finally:
                    fixture.doCleanups()

    def test_fixed_enrollment_browser_labels_are_read_only_not_initialization_or_send_permission(self):
        for state, expected in (
                ('enrollment_missing', 'Issue Tracker enrollment 缺失；仅只读诊断，未自动初始化或修补；自动发送禁用；最后观察：2026-01-01T00:00:00+00:00（非当前准入证明）'),
                ('enrollment_incomplete', 'Issue Tracker enrollment 未完成；仅只读诊断，未自动初始化或修补；自动发送禁用；最后观察：2026-01-01T00:00:00+00:00（非当前准入证明）')):
            with self.subTest(state=state):
                rendered = browser(snapshot(state))
                self.assertEqual(expected, rendered['text'], 'ENROLLMENT_BROWSER_FIXED_LABEL_MISSING')
                self.assertEqual([{'url': '/monitor/control/switch-collection?view=issue_tracker_online',
                    'options': {'method': 'GET', 'credentials': 'same-origin', 'cache': 'no-store'}}],
                    rendered['calls'])
                for invalid in ({**snapshot(state), 'reason': 'PRIVATE'},
                        {**snapshot(state), 'schema_version': True},
                        {**snapshot(state), 'read_only': 1},
                        {**snapshot(state), 'mutation_disabled': False},
                        snapshot([state]), snapshot({'state': state}), snapshot(state + '_PRIVATE')):
                    self.assertEqual('Issue Tracker 在线状态未证明；自动发送禁用，请检查并升级处理',
                        browser(invalid)['text'])

    def test_fixed_transport_browser_labels_cannot_claim_complete_or_permission(self):
        for state, text in (('attempted_unknown', 'UNKNOWN'),
                ('attempted_definite_rejection', '明确拒绝'), ('attempt_unproved', '未证明')):
            with self.subTest(state=state):
                rendered=browser(snapshot(state))
                self.assertIn(text, rendered['text'])
                self.assertIn('不代表', rendered['text']); self.assertIn('发送许可', rendered['text'])
                self.assertNotIn('已完成', rendered['text'])

    def test_terminal_transport_observation_actual_cache_cgi_and_browser_without_permission(self):
        from monitor.issue_tracker_mutation_launcher import CountedMutationCompletion
        from monitor.issue_tracker_remote_history_match import RemoteHistoryHold
        for outcome, count, state, text in (
                ('UNKNOWN', 1, 'attempted_unknown', 'UNKNOWN'),
                ('DEFINITE_REJECTION', 1, 'attempted_definite_rejection', '明确拒绝'),
                ('HOLD', None, 'attempt_unproved', '未证明'),
                ('UNKNOWN', 6, 'retry_exhausted', '6 次已耗尽'),
                ('DEFINITE_REJECTION', 6, 'retry_exhausted', '6 次已耗尽')):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                root=Path(directory); closed=[]; store=object()
                observations=dict(result=(), writer=object(), owner=object(), binding=object(),
                    authentication=object(), http_root=root, disposition_stopped=False, delivery_stopped=False)
                @contextmanager
                def owners(actual):
                    self.assertIs(store, actual)
                    yield observations
                    closed.append('all-original-finalizers')
                actual_write=WORKER._write_status_file
                def write(*args, **kwargs):
                    self.assertEqual(['all-original-finalizers'], closed)
                    return actual_write(*args, **kwargs)
                stack.enter_context(mock.patch.object(WORKER, '_hold_terminal_current_project_online_originals', owners))
                # The status-only fixture supplies fake owners and transport
                # observations, not source/NEW authority. Preserve every
                # original cache/CGI/browser assertion at that boundary.
                stack.enter_context(mock.patch('monitor.issue_tracker_remote_history_match._prepare_next_current_cycle_native_originals',
                    return_value=('EXISTING_PENDING',None,observations['authentication'])))
                dispatch_options = ({'side_effect':RemoteHistoryHold()} if outcome == 'HOLD'
                    else {'return_value':CountedMutationCompletion(count, 401, 'a'*64, None, outcome)})
                stack.enter_context(mock.patch.object(WORKER, '_dispatch_current_project_online_originals',
                    **dispatch_options))
                stack.enter_context(mock.patch.object(WORKER, '_write_status_file', side_effect=write))
                stack.enter_context(mock.patch.object(WORKER, 'STATUS_DIR', root))
                stack.enter_context(mock.patch.object(WORKER, 'timestamp', return_value=STAMP))
                stack.enter_context(mock.patch.object(CGI, 'STATUS_DIR', root))
                diagnostic = stack.enter_context(mock.patch.object(WORKER.sys, 'stderr', io.StringIO()))
                self.assertEqual((), WORKER._dispatch_issue_tracker_online_after_completion(store))
                self.assertEqual('Issue Tracker online attempt unproved; original count/UNKNOWN retained; mutation disabled\n'
                    if outcome == 'HOLD' else '', diagnostic.getvalue())
                original=(root/'issue-tracker-online.status.json').read_bytes()
                stack.enter_context(mock.patch.dict(os.environ, AUTH, clear=True))
                stack.enter_context(mock.patch.object(CGI, 'process_state', return_value=(False, None)))
                for name in ('collection_status', 'yaml_backup_status', 'continuous_collection_status', 'continuous_backup_status'):
                    stack.enter_context(mock.patch.object(CGI, name, return_value={'state':'idle'}))
                stack.enter_context(mock.patch.object(CGI, 'request_action', return_value=None))
                respond=stack.enter_context(mock.patch.object(CGI, 'respond'))
                request=stack.enter_context(mock.patch.object(CGI, 'write_request'))
                CGI.main(); respond.assert_called_once(); request.assert_not_called()
                value=respond.call_args.args[0]
                self.assertEqual({**snapshot(state), 'process_alive':False}, value)
                rendered=browser(value)
                self.assertIn(text, rendered['text'])
                if count == 6:
                    self.assertIn('自动发送禁用', rendered['text']); self.assertIn('升级', rendered['text'])
                else:
                    self.assertIn('不代表', rendered['text']); self.assertIn('发送许可', rendered['text'])
                self.assertNotIn('已完成', rendered['text'])
                self.assertNotIn('PRIVATE', rendered['text'])
                self.assertEqual('GET', rendered['calls'][0]['options']['method'])
                self.assertEqual('no-store', rendered['calls'][0]['options']['cache'])
                self.assertEqual(original, (root/'issue-tracker-online.status.json').read_bytes())

    def test_unscoped_empty_observation_does_not_claim_the_page_project_is_empty(self):
        result = browser(snapshot('no_counted_units'))
        self.assertIn('最近对账未观察到已计数单元', result['text'])
        self.assertNotIn('本项目', result['text'])
        self.assertIn('不代表发送许可', result['text'])

    def test_actual_worker_snapshot_authenticated_cgi_and_generated_browser_display(self):
        publish = getattr(WORKER, '_publish_issue_tracker_online_observation_status', None)
        self.assertTrue(callable(publish), 'actual worker diagnostic publisher missing')
        for observed_state, visible_state in (('UNKNOWN', 'stalled'), ('CONFLICT', 'conflict')):
            with self.subTest(state=observed_state), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                root = Path(directory)
                stack.enter_context(mock.patch.object(WORKER, 'STATUS_DIR', root))
                stack.enter_context(mock.patch.object(WORKER, 'timestamp', return_value=STAMP))
                stack.enter_context(mock.patch.object(CGI, 'STATUS_DIR', root))
                publish((observed(observed_state),))
                original = (root/'issue-tracker-online.status.json').read_bytes()
                stack.enter_context(mock.patch.dict(os.environ, AUTH, clear=True))
                stack.enter_context(mock.patch.object(CGI, 'process_state', return_value=(False, None)))
                for name in ('collection_status', 'yaml_backup_status', 'continuous_collection_status', 'continuous_backup_status'):
                    stack.enter_context(mock.patch.object(CGI, name, return_value={'state': 'idle'}))
                stack.enter_context(mock.patch.object(CGI, 'request_action', return_value=None))
                respond = stack.enter_context(mock.patch.object(CGI, 'respond'))
                write = stack.enter_context(mock.patch.object(CGI, 'write_request'))
                CGI.main(); respond.assert_called_once()
                value = respond.call_args.args[0]
                self.assertEqual({**snapshot(visible_state), 'process_alive': False}, value)
                write.assert_not_called()
                result = browser(value)
                self.assertIn(observed_state, result['text']); self.assertIn('发送禁用', result['text'])
                self.assertIn('升级', result['text']); self.assertNotIn('PRIVATE', result['text'])
                self.assertEqual('/monitor/control/switch-collection?view=issue_tracker_online', result['calls'][0]['url'])
                self.assertEqual('GET', result['calls'][0]['options']['method'])
                self.assertEqual('no-store', result['calls'][0]['options']['cache'])
                self.assertEqual(original, (root/'issue-tracker-online.status.json').read_bytes())

    def test_browser_rejects_permission_labels_bad_shapes_and_private_payloads(self):
        for value in ({**snapshot('GO'), 'token': 'PRIVATE'}, {**snapshot('stalled'), 'token': 'PRIVATE'},
                {**snapshot('stalled'), 'read_only': False},
                {**snapshot('stalled'), 'updated_at': 'PRIVATE'}, {}, None):
            with self.subTest(shape=type(value).__name__):
                result = browser(value)
                self.assertIn('未证明', result['text']); self.assertNotIn('PRIVATE', result['text'])
                self.assertNotIn('GO', result['text'])


class OnlineExhaustionDirectTests(unittest.TestCase):
    def test_sixth_unknown_count_is_explicit_exhaustion_without_new_permission(self):
        from dataclasses import replace
        report = WORKER._report_issue_tracker_online_read_only_result
        publish = WORKER._publish_issue_tracker_online_observation_status
        for count in range(1, 7):
            value = replace(observed('UNKNOWN'), attempt_count=count)
            expected = 'retry_exhausted' if count == 6 else 'stalled'
            with self.subTest(count=count), mock.patch.object(WORKER, '_write_status_file') as write, \
                    mock.patch.object(WORKER.sys, 'stderr', io.StringIO()) as stream:
                report((value,)); publish((value,))
                write.assert_called_once_with(WORKER.STATUS_DIR/'issue-tracker-online.status.json',
                    '.issue-tracker-online.', expected, schema_version=1,
                    read_only=True, mutation_disabled=True)
                diagnostic = stream.getvalue()
                self.assertIn('UNKNOWN', diagnostic); self.assertIn('mutation disabled', diagnostic)
                self.assertNotIn('PRIVATE', diagnostic)
                if count == 6:
                    self.assertEqual('Issue Tracker online stalled: UNKNOWN; retry-exhausted; '
                        'durable total count=6; read-only reconciliation and escalation; '
                        'mutation disabled\n', diagnostic)
                else:
                    self.assertNotIn('retry-exhausted', diagnostic)
        with mock.patch.object(WORKER, '_write_status_file') as write:
            publish((replace(observed('UNKNOWN'), attempt_count=6), observed('CONFLICT')))
            self.assertEqual('conflict', write.call_args.args[2], 'exhaustion never hides CONFLICT')

    def test_unproved_count_cannot_report_or_write_even_after_valid_prefix(self):
        from dataclasses import replace
        for count in (0, 7, True, '6', None):
            values = (observed('UNKNOWN'), replace(observed('UNKNOWN'), attempt_count=count))
            with self.subTest(count=count), mock.patch.object(WORKER, '_write_status_file') as write, \
                    mock.patch.object(WORKER.sys, 'stderr', io.StringIO()) as stream:
                with self.assertRaises(WORKER.CollectionCycleHoldError):
                    WORKER._report_issue_tracker_online_read_only_result(values)
                self.assertEqual('', stream.getvalue(), 'no partial count classification')
                with self.assertRaises(WORKER.CollectionCycleHoldError):
                    WORKER._publish_issue_tracker_online_observation_status(values)
                write.assert_not_called()


class OnlineExhaustionWorkflowTests(unittest.TestCase):
    def setUp(self):
        import sys
        import monitor
        from monitor import issue_tracker_spreadsheet_owner as owner
        from monitor import issue_tracker_global_attempt_journal as counter
        from monitor import issue_tracker_unit_catalog as catalog
        from test_cases.test_req7_unit_catalog import load as load_catalog
        # Refresh this real consumer before any owner is issued. Preserve the
        # current owner/counter objects, not their name/path or copied state.
        self.assertEqual({},owner._ACTIVE)
        self.assertEqual({},catalog.ownership._ACTIVE)
        self.assertEqual({},catalog.local._ACTIVE)
        self.assertIsNone(counter._HELD_COUNT_CLAIM_ORIGINALS.get())
        names=('_LIVE_COUNT_CLAIM_ORIGINALS','_LIVE_COUNT_SOURCE_GRAPHS',
            '_LIVE_COUNT_SOURCE_RAW_TAILS','_LIVE_WIRE_CLAIMS')
        for name in names:self.assertEqual(0,len(getattr(counter,name)))
        module_map=sys.modules;package_map=vars(monitor)
        owner_registry=owner._ACTIVE
        counter_registries=tuple(getattr(counter,name) for name in names)
        actual=load_catalog(reset_dependencies=False)
        self.assertIs(sys.modules,module_map);self.assertIs(vars(monitor),package_map)
        self.assertIs(owner,sys.modules['monitor.issue_tracker_spreadsheet_owner'])
        self.assertIs(owner,monitor.issue_tracker_spreadsheet_owner)
        self.assertIs(counter,sys.modules['monitor.issue_tracker_global_attempt_journal'])
        self.assertIs(counter,monitor.issue_tracker_global_attempt_journal)
        self.assertIs(owner._ACTIVE,owner_registry)
        for name,original in zip(names,counter_registries):
            self.assertIs(getattr(counter,name),original);self.assertEqual(0,len(original))
        self.assertIs(actual,sys.modules['monitor.issue_tracker_unit_catalog'])
        self.assertIs(actual,monitor.issue_tracker_unit_catalog)
        self.assertIs(actual.ownership,owner)

    def test_exhaustion_fixture_refreshes_same_source_catalog_without_replacing_current_registries(self):
        import sys
        import monitor
        from monitor import issue_tracker_spreadsheet_owner as owner0
        from monitor import issue_tracker_global_attempt_journal as counter0
        from monitor import issue_tracker_unit_catalog as catalog0
        from test_cases.test_req7_spreadsheet_owner import load as load_owner
        from test_cases.test_req7_global_attempt_journal import load as load_counter
        # The selected test uses only real imports/loaders. No owner/Count,
        # browser, SDK or child resource is created. Restoration is local to
        # this isolated test process; it cannot repair an active production graph.
        self.assertEqual({},owner0._ACTIVE);self.assertEqual({},catalog0.ownership._ACTIVE)
        self.assertEqual({},catalog0.local._ACTIVE)
        self.assertIsNone(counter0._HELD_COUNT_CLAIM_ORIGINALS.get())
        names=('_LIVE_COUNT_CLAIM_ORIGINALS','_LIVE_COUNT_SOURCE_GRAPHS',
            '_LIVE_COUNT_SOURCE_RAW_TAILS','_LIVE_WIRE_CLAIMS')
        for name in names:self.assertEqual(0,len(getattr(counter0,name)))
        module_map=sys.modules;package_map=vars(monitor)
        modules={name:value for name,value in sys.modules.items()
            if name=='monitor' or name.startswith('monitor.')}
        aliases={name:value for name,value in vars(monitor).items() if name.startswith('issue_tracker_')}
        original_owner_registry=owner0._ACTIVE
        original_counter_registries=tuple(getattr(counter0,name) for name in names)
        primary=cleanup=None;owner1=counter1=None
        try:
            owner1=load_owner();counter1=load_counter()
            self.assertIsNot(owner0,owner1);self.assertIsNot(counter0,counter1)
            self.assertEqual(Path(owner0.__file__).resolve(),Path(owner1.__file__).resolve())
            self.assertIs(catalog0.ownership,owner0)
            self.assertIsNot(catalog0.ownership,owner1)
            live_owner_registry=owner1._ACTIVE
            live_counter_registries=tuple(getattr(counter1,name) for name in names)
            self.setUp()
            from monitor import issue_tracker_unit_catalog as actual
            self.assertIs(actual.ownership,owner1)
            self.assertIs(owner1,sys.modules['monitor.issue_tracker_spreadsheet_owner'])
            self.assertIs(owner1,monitor.issue_tracker_spreadsheet_owner)
            self.assertIs(counter1,sys.modules['monitor.issue_tracker_global_attempt_journal'])
            self.assertIs(counter1,monitor.issue_tracker_global_attempt_journal)
            self.assertIs(sys.modules,module_map);self.assertIs(vars(monitor),package_map)
            self.assertIs(owner1._ACTIVE,live_owner_registry);self.assertEqual({},live_owner_registry)
            for name,original in zip(names,live_counter_registries):
                self.assertIs(getattr(counter1,name),original);self.assertEqual(0,len(original))
            self.assertIsNone(counter1._HELD_COUNT_CLAIM_ORIGINALS.get())
        except BaseException as error:primary=error
        finally:
            try:
                # Never restore a saved map over actual LIVE originals.
                if owner1 is not None:self.assertEqual({},owner1._ACTIVE)
                if counter1 is not None:
                    self.assertIsNone(counter1._HELD_COUNT_CLAIM_ORIGINALS.get())
                    for name in names:self.assertEqual(0,len(getattr(counter1,name)))
                for name in tuple(sys.modules):
                    if name.startswith('monitor.') and name not in modules:del sys.modules[name]
                sys.modules.update(modules)
                for name in tuple(vars(monitor)):
                    if name.startswith('issue_tracker_') and name not in aliases:del vars(monitor)[name]
                vars(monitor).update(aliases)
                self.assertIs(sys.modules,module_map);self.assertIs(vars(monitor),package_map)
                for name,original in modules.items():self.assertIs(sys.modules[name],original)
                for name,original in aliases.items():self.assertIs(vars(monitor)[name],original)
                self.assertIs(owner0._ACTIVE,original_owner_registry);self.assertEqual({},owner0._ACTIVE)
                for name,original in zip(names,original_counter_registries):
                    self.assertIs(getattr(counter0,name),original);self.assertEqual(0,len(original))
            except BaseException as error:cleanup=error
        if primary is not None:
            if cleanup is not None and cleanup is not primary:
                if isinstance(primary,Exception) and not isinstance(cleanup,Exception):raise cleanup from primary
                raise primary from cleanup
            raise primary
        if cleanup is not None:raise cleanup

    def test_exhaustion_workflow_preserves_existing_canonical_owner_and_counter_registries(self):
        import sys
        from monitor import issue_tracker_spreadsheet_owner as owner
        from monitor import issue_tracker_global_attempt_journal as counter
        from monitor import issue_tracker_unit_catalog as catalog
        self.assertIs(catalog.ownership, owner)
        probe = OnlineExhaustionWorkflowTests(
            'test_actual_six_durable_intents_survive_read_only_worker_cgi_browser_diagnostic')
        try:
            probe.test_actual_six_durable_intents_survive_read_only_worker_cgi_browser_diagnostic()
        finally:
            probe.doCleanups()
        self.assertIs(owner, sys.modules['monitor.issue_tracker_spreadsheet_owner'],
            'workflow fixture must not revoke later real scripts by replacing their owner registry')
        self.assertIs(counter, sys.modules['monitor.issue_tracker_global_attempt_journal'])
        self.assertIs(catalog.ownership, owner)

    def test_actual_six_durable_intents_survive_read_only_worker_cgi_browser_diagnostic(self):
        from dataclasses import replace
        from types import SimpleNamespace
        from test_cases import test_req7_global_attempt_journal as originals
        from monitor import issue_tracker_global_attempt_journal as counter
        from monitor import issue_tracker_spreadsheet_owner as owner
        import hashlib
        # Borrow current real registries; another fixture's setUp reloads the
        # canonical modules and would strand already imported real readers.
        temporary = tempfile.TemporaryDirectory(prefix='req7-six-intent-display-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        locks = root/'var/lib/http-ztp-container/issue-tracker'
        locks.mkdir(parents=True, mode=0o700)
        case = SimpleNamespace(root=root, owner=owner, module=counter,
            value=originals.unit(), store=locks/(hashlib.sha256(originals.TARGET.encode()).hexdigest()+'.journal'))
        states = []; seventh_refused = False
        with originals.fixture(case.root), case.owner.spreadsheet_owner(originals.binding()) as token:
            case.module.prepare_global_unit(token, originals.binding(), case.value)
            for _ in range(6):
                states.append(case.module.record_global_attempt_intent(token, originals.binding(), case.value))
            before = originals.original_read_files(case.root)
            try:
                case.module.record_global_attempt_intent(token, originals.binding(), case.value)
            except case.module.GlobalAttemptHold:
                seventh_refused = True
            after = originals.original_read_files(case.root)
            actual = case.module.inspect_global_unit(token, originals.binding(), case.value)
        # Independent assertions stay outside production owner finalizers.
        self.assertEqual([(i, 'UNKNOWN') for i in range(1, 7)],
            [(item.attempt_count, item.outcome) for item in states])
        self.assertTrue(seventh_refused); self.assertEqual(before, after)
        self.assertEqual((6, 'UNKNOWN'), (actual.attempt_count, actual.outcome))
        self.assertEqual({'ATTEMPT-'+str(i) for i in range(1, 7)},
            {path.name for path in case.store.glob('ATTEMPT-*')})
        self.assertFalse(any(path.name.startswith('CLAIM-') for path in case.root.rglob('*')),
            'durable intent count is not proof of any physical wire attempt')
        with ExitStack() as stack:
            status = case.root/'status'; status.mkdir(mode=0o700)
            stack.enter_context(mock.patch.object(WORKER, 'STATUS_DIR', status))
            stack.enter_context(mock.patch.object(WORKER, 'timestamp', return_value=STAMP))
            stack.enter_context(mock.patch.object(CGI, 'STATUS_DIR', status))
            stream = stack.enter_context(mock.patch.object(WORKER.sys, 'stderr', io.StringIO()))
            value = replace(observed('UNKNOWN'), attempt_count=actual.attempt_count)
            WORKER._report_issue_tracker_online_read_only_result((value,))
            WORKER._publish_issue_tracker_online_observation_status((value,))
            stack.enter_context(mock.patch.dict(os.environ, AUTH, clear=True))
            stack.enter_context(mock.patch.object(CGI, 'process_state', return_value=(False, None)))
            respond = stack.enter_context(mock.patch.object(CGI, 'respond'))
            write = stack.enter_context(mock.patch.object(CGI, 'write_request'))
            CGI.main(); respond.assert_called_once(); write.assert_not_called()
            payload = respond.call_args.args[0]
            self.assertEqual({**snapshot('retry_exhausted'), 'process_alive': False}, payload)
            visible = browser(payload)
            for text in ('UNKNOWN', '6', '耗尽', '升级', '发送禁用'):
                self.assertIn(text, visible['text'])
            self.assertNotIn('PRIVATE', visible['text']); self.assertNotIn('GO', visible['text'])
            self.assertIn('retry-exhausted', stream.getvalue())
        self.assertTrue(before.items() <= originals.original_read_files(case.root).items(),
            'observation must not remove/reset/repair immutable original count evidence')
