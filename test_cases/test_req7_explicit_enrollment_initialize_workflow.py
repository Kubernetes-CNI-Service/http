"""Explicit fresh-only enrollment: owned local TLS, never real Cloud.

SOURCE candidate only. Existing journal module is the actual CLI entry even on
the no-op baseline; no missing new implementation symbol is invoked up front.
"""
from contextlib import ExitStack, contextmanager, redirect_stdout, redirect_stderr
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import runpy
import socket
import subprocess
import sys
import unittest
import warnings
from types import SimpleNamespace
from unittest import mock

from test_cases import test_req7_online_completion_runtime as runtime
from test_cases import test_req7_history_read_launcher as read_fixture
from test_cases.test_req7_spreadsheet_owner import scoped_fixture
from test_cases.test_req7_sheets_read_decode import identity_response, header_response, response
from test_cases.test_req7_online_whitelist_read import document as whitelist_document
from test_cases.test_req7_sdk_authentication import fresh_info
from test_cases import test_req7_token_launcher as token_fixture

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'monitor/issue_tracker_enrollment_journal.py'
SUCCESS = 'enrollment initialized; automatic sending remains disabled\n'
REFUSED = 'enrollment initialization refused; evidence retained\n'
NONCES = ('a' * 64, 'b' * 64, 'c' * 64, 'd' * 64)
SHEETS = (('ETH&IB Switch', 101), ('ETH Cabling', 102), ('IB Cabling', 103), ('Update_History', 105))


def wire_reply(document):
    body = json.dumps(document, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    return b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body


def file_images(state):
    return {str(path.relative_to(state)): (path.lstat().st_ino, path.read_bytes())
            for path in state.rglob('*') if path.is_file()}


def tree_images(state):
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    return {str(path.relative_to(state)): (tuple(getattr(path.lstat(), name) for name in fields),
            path.read_bytes() if path.is_file() else None)
            for path in (state, *state.rglob('*'))}


class ExplicitEnrollmentInitializeWorkflowTests(unittest.TestCase):
    _Fixture = runtime.OnlineCompletionRuntimeWorkflowTests._Fixture
    setUp = runtime.OnlineCompletionRuntimeWorkflowTests.setUp
    certificates = runtime.OnlineCompletionRuntimeWorkflowTests.certificates
    server = runtime.OnlineCompletionRuntimeWorkflowTests.server
    owners = runtime.OnlineCompletionRuntimeWorkflowTests.owners

    def invoke(self, project, *, stdout=None):
        output, errors = stdout or io.StringIO(), io.StringIO()
        with mock.patch.object(sys, 'argv', [str(CLI), '--initialize-project', str(project)]), \
                redirect_stdout(output), redirect_stderr(errors):
            try:
                runpy.run_path(str(CLI), run_name='__main__')
            except SystemExit as error:
                status = error.code
            else:
                status = 0
        return status, output.getvalue(), errors.getvalue()

    def project(self, stack):
        self.root = self.root.resolve()
        project = self.root / 'project'
        project.mkdir()
        with ExitStack() as initial:
            self.initial_owners = initial
            local, ownership, writer, owner, bound, _unused, _config = self.owners(stack)
            return project, local, ownership, writer, owner, bound

    def _exercise_actual_initialize(self, fault=None, *, repeat_after_success=False, after_initialize=None):
        from monitor import issue_tracker_enrollment_journal as enrollment
        from monitor import issue_tracker_token_launcher as auth
        from monitor import issue_tracker_history_read_launcher as reads
        from monitor import issue_tracker_online_target as target
        from monitor import issue_tracker_global_attempt_journal as counted
        from monitor import issue_tracker_mutation_launcher as mutation
        with ExitStack() as stack:
            project, local, ownership, _old_writer, _old_owner, bound = self.project(stack)
            state = self.root / 'var/lib/http-ztp-container/issue-tracker'
            stem = hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
            folder = state / (stem + '.enrollment')
            attempt = state / ('enrollment-init-' + stem)
            sdk = importlib.import_module('monitor.issue_tracker_sdk_authentication')
            stack.enter_context(scoped_fixture(self.root, sdk))
            credential = self.root / 'var/lib/http-ztp-container/service-account/cre.json'
            info = fresh_info(); info['project_id'] = 'synthetic-cloud-project'
            credential.write_text(json.dumps(info)); credential.chmod(0o600)
            credential_before = credential.read_bytes()
            identity = identity_response(); identity['spreadsheetId'] = bound.spreadsheet_id
            headers = header_response(); headers['spreadsheetId'] = bound.spreadsheet_id
            whitelist = whitelist_document(()); whitelist['spreadsheetId'] = bound.spreadsheet_id
            whitelist['sheets'][0]['properties']['sheetId'] = 112
            metadata = [{'metadataId': 2001 + index, 'metadataKey': 'http-ztp-enrollment-v1',
                         'metadataValue': NONCES[index], 'visibility': 'DOCUMENT',
                         'location': {'locationType': 'SHEET', 'sheetId': sid}}
                        for index, (_title, sid) in enumerate(SHEETS)]
            written = {'spreadsheetId': bound.spreadsheet_id, 'replies': [
                {'createDeveloperMetadata': {'developerMetadata': item}} for item in metadata]}
            expected_requests = {'requests': [
                {'createDeveloperMetadata': {'developerMetadata': {
                    'metadataKey': 'http-ztp-enrollment-v1', 'metadataValue': NONCES[index],
                    'location': {'sheetId': sid}, 'visibility': 'DOCUMENT'}}}
                for index, (_title, sid) in enumerate(SHEETS)], 'includeSpreadsheetInResponse': False}
            completed = {'matchedDeveloperMetadata': [{'developerMetadata': dict(item)} for item in metadata]}
            prior_metadata = {}
            if fault == 'remote-existing':
                prior_metadata = {'matchedDeveloperMetadata': [{'developerMetadata': {
                    'metadataId': 9001, 'metadataKey': 'independent-existing-key',
                    'metadataValue': 'preserved', 'visibility': 'DOCUMENT',
                    'location': {'locationType': 'SPREADSHEET', 'spreadsheet': True}}}]}
            if fault == 'readback-mismatch':
                completed['matchedDeveloperMetadata'][0]['developerMetadata']['metadataId'] = 9002
            held, closed, emissions, journal_before_write, prepared = {}, [], [], [], []
            finalizer_error = RuntimeError('independent original-target cleanup rejection')
            real_writer, real_sheet = local.try_writer_owner, ownership.spreadsheet_owner
            real_target, real_prepare = target._hold_current_project_online_target, enrollment.prepare_enrollment_journal

            @contextmanager
            def original_owner(factory, label, *args, **kwargs):
                with factory(*args, **kwargs) as actual:
                    held[label] = actual
                    yield actual
                closed.append(label)
                if label == 'target' and fault == 'owner-cleanup':
                    # Inject only AFTER the exact original target context
                    # returned from its real verification and close sequence.
                    raise finalizer_error

            def prepare_original(*args):
                with mock.patch('secrets.token_hex', side_effect=NONCES):
                    result = real_prepare(*args)
                prepared.append(file_images(folder))
                return result

            class Output(io.StringIO):
                def write(buffer, text):
                    if 'enrollment initialized' in text:
                        emissions.append(tuple(closed))
                    return super().write(text)

            stack.enter_context(mock.patch.object(local, 'try_writer_owner',
                side_effect=lambda *a, **k: original_owner(real_writer, 'writer', *a, **k)))
            stack.enter_context(mock.patch.object(ownership, 'spreadsheet_owner',
                side_effect=lambda *a, **k: original_owner(real_sheet, 'sheet', *a, **k)))
            stack.enter_context(mock.patch.object(target, '_hold_current_project_online_target',
                side_effect=lambda *a, **k: original_owner(real_target, 'target', *a, **k)))
            stack.enter_context(mock.patch.object(enrollment, 'prepare_enrollment_journal', side_effect=prepare_original))
            count = stack.enter_context(mock.patch.object(counted, 'record_global_attempt_intent',
                side_effect=AssertionError('enrollment must not create a business COUNT')))
            business = stack.enter_context(mock.patch.object(mutation, '_send_counted_original_once',
                side_effect=AssertionError('enrollment must not enter business mutation launcher')))
            native_popen = subprocess.Popen
            children, servers, stages = [], [], []

            def cleanup_returned_children():
                # Existing native fixture policy, only actual returned objects;
                # no PID scan/adoption, and this fallback is not a normal PASS.
                import signal
                for child in children:
                    if child.poll() is None:
                        self.assertEqual(child.pid, os.getpgid(child.pid))
                        self.assertEqual(child.pid, os.getsid(child.pid))
                        os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=3)
                    for stream in (child.stdin, child.stdout, child.stderr):
                        if stream is not None:
                            stream.close()
            self.addCleanup(cleanup_returned_children)

            def launch(argv, **kwargs):
                self.assertEqual([str(Path(sys.executable).resolve()), '-I', '-B', '-c'], argv[:4])
                self.assertEqual(str(ROOT), argv[5]); self.assertRegex(argv[6], r'^[0-9a-f]{64}$')
                self.assertEqual({'LC_ALL': 'C'}, kwargs['env'])
                self.assertEqual(str(ROOT), kwargs['cwd']); self.assertIs(kwargs['start_new_session'], True)
                self.assertIs(kwargs['close_fds'], True); self.assertIsNone(kwargs.get('shell'))
                self.assertNotIn('owned-project-token', repr(argv))
                self.assertNotIn('owned-project-token', repr(kwargs['env']))
                if argv[4] == auth._PROJECT_CHILD_PROGRAM:
                    self.assertEqual([], stages); stage = 'oauth'
                    reply = wire_reply({'access_token': 'owned-project-token', 'expires_in': 3600})
                    host = 'oauth2.googleapis.com'
                elif argv[4] == reads._TEMPLATE_COHORT_CHILD_PROGRAM:
                    self.assertEqual(['oauth'], stages); stage = 'template4'
                    reply = tuple(wire_reply(item) for item in (identity, headers, whitelist, prior_metadata))
                    host = 'sheets.googleapis.com'
                elif argv[4] == reads._CHILD_PROGRAM:
                    self.assertEqual(['oauth', 'template4', 'initialize4'], stages); stage = 'readback'
                    reply = wire_reply(completed); host = 'sheets.googleapis.com'
                else:
                    # New symbols are inspected only after a real new launcher
                    # has actually requested its child, never on the old no-op.
                    initializer = sys.modules.get('monitor.issue_tracker_enrollment_initialize')
                    self.assertIsNotNone(initializer, 'no unrelated child may initialize metadata')
                    self.assertEqual(initializer._INITIALIZE_CHILD_PROGRAM, argv[4])
                    self.assertEqual(['oauth', 'template4'], stages); stage = 'initialize4'
                    self.assertEqual(11, len(argv))
                    header_fd, nonces_fd, marker_fd, wire_fd = map(int, argv[7:])
                    self.assertEqual({'HEADER', 'NONCES', 'INITIALIZED'}, {p.name for p in folder.iterdir()})
                    self.assertTrue(attempt.is_dir())
                    self.assertEqual([[title, sid, NONCES[index]] for index, (title, sid) in enumerate(SHEETS)],
                                     json.loads(os.pread(nonces_fd, 16385, 0)))
                    self.assertEqual(expected_requests, json.loads(os.pread(wire_fd, 65537, 0)))
                    self.assertEqual(json.loads((folder / 'HEADER').read_bytes()), json.loads(os.pread(header_fd, 16385, 0)))
                    self.assertEqual((folder / 'INITIALIZED').read_bytes(), os.pread(marker_fd, 16385, 0))
                    journal_before_write.append(file_images(folder))
                    self.assertEqual({local._owner(held['writer']).lock_fd,
                        ownership.owner_lock_fd(held['sheet'], bound), header_fd, nonces_fd, marker_fd, wire_fd},
                        set(kwargs['pass_fds']))
                    # Truncate one body byte while retaining the original
                    # declared Content-Length: the real transport sees an
                    # ambiguous write, not a fake decoded UNKNOWN result.
                    reply = wire_reply(written)
                    if fault == 'write-UNKNOWN':
                        reply = reply[:-1]
                    host = 'sheets.googleapis.com'
                stages.append(stage)
                records, errors = stack.enter_context(self.server(reply, hostname=host, destination=host))
                servers.append((stage, records, errors))
                port = socket.getaddrinfo(host, 443)[0][4][1]
                if stage == 'oauth':
                    program = token_fixture.Req7FixedTokenLauncherWorkflowTests.child_fixture(self, port, project_scope=True)
                else:
                    program = read_fixture.Req7HistoryReadLauncherWorkflowTests.child_fixture(self, port)
                    if stage == 'template4':
                        program = program.replace('launcher._history_child(', 'launcher._history_template_cohort_child(')
                    elif stage == 'initialize4':
                        program = program.replace('issue_tracker_history_read_launcher as launcher',
                                                  'issue_tracker_enrollment_initialize as launcher')
                        program = program.replace('launcher._history_child(sys.argv[2])',
                            'launcher._initialize_child(sys.argv[2],int(sys.argv[3]),int(sys.argv[4]),int(sys.argv[5]),int(sys.argv[6]))')
                changed = list(argv); changed[4] = program
                child = native_popen(changed, **kwargs); children.append(child)
                return child

            # Retain the supervisor's native Popen class identity check. Patch
            # only the three launching modules, not shared subprocess itself.
            initializer = importlib.import_module('monitor.issue_tracker_enrollment_initialize')
            process_api = SimpleNamespace(**{name: getattr(subprocess, name) for name in dir(subprocess)})
            process_api.Popen = launch
            for launching in (auth, reads, initializer):
                stack.enter_context(mock.patch.object(launching, 'subprocess', process_api))
            with warnings.catch_warnings(record=True) as runtime_warnings:
                warnings.simplefilter('always', FutureWarning)
                status, stdout, stderr = self.invoke(project, stdout=Output())
            # Old journal module normally returns without an entry; literal
            # behavior FAIL, not missing-helper/import ERROR.
            if fault is None:
                self.assertEqual(SUCCESS, stdout, 'EXPLICIT_ENROLLMENT_REAL_WORKFLOW_NOT_COMPLETED')
                self.assertEqual((0, ''), (status, stderr))
            else:
                self.assertEqual((3, '', REFUSED), (status, stdout, stderr),
                    'EXPLICIT_ENROLLMENT_REMOTE_OR_FINALIZER_FAILURE_NOT_REFUSED')
                self.assertEqual([], emissions, 'no success before complete remote proof and owner cleanup')
            for warning in runtime_warnings:
                self.assertIs(FutureWarning, warning.category)
                self.assertIn('Python version 3.9 past its end of life', str(warning.message))
            if sys.version_info[:2] == (3, 9):
                self.assertTrue(runtime_warnings, 'preserve original fixed runtime warning')
            else:
                self.assertEqual([], runtime_warnings)
            expected_stages = (['oauth', 'template4'] if fault == 'remote-existing'
                               else ['oauth', 'template4', 'initialize4'] if fault == 'write-UNKNOWN'
                               else ['oauth', 'template4', 'initialize4', 'readback'])
            self.assertEqual(expected_stages, stages)
            if fault is None:
                self.assertEqual(1, len(emissions)); self.assertEqual({'writer', 'sheet', 'target'}, set(emissions[0]))
                self.assertEqual(3, len(emissions[0]))
            self.assertEqual(len(expected_stages), len(children))
            for index, child in enumerate(children):
                if fault == 'write-UNKNOWN' and index == 2:
                    self.assertIn(child.returncode, (0, 1), 'real fixed child must be reaped after ambiguous response')
                else:
                    self.assertEqual(0, child.returncode)
            self.assertTrue(all(stream is None or stream.closed for child in children
                                for stream in (child.stdin, child.stdout, child.stderr)))
            self.assertEqual([1, 4] + [1] * (len(expected_stages) - 2),
                             [len(records) for _stage, records, _errors in servers])
            self.assertTrue(all(not errors for _stage, _records, errors in servers))
            if fault == 'remote-existing':
                self.assertEqual([], prepared); self.assertEqual([], journal_before_write)
                self.assertFalse(folder.exists(), 'existing remote metadata cannot create local nonces')
            else:
                initialization_request = servers[2][1][0]
                self.assertEqual(b'POST /v4/spreadsheets/' + bound.spreadsheet_id.encode() + b':batchUpdate HTTP/1.1\r\n',
                                 initialization_request[0])
                self.assertEqual(expected_requests, json.loads(initialization_request[2]))
                self.assertEqual(journal_before_write, [file_images(folder)])
                self.assertEqual(1, len(prepared))
                self.assertEqual({'HEADER', 'NONCES', 'INITIALIZED'}, {p.name for p in folder.iterdir()})
                self.assertTrue(attempt.is_dir(), 'ambiguous/failed attempts retain independent evidence')
                if fault == 'readback-mismatch':
                    self.assertEqual(2001, written['replies'][0]['createDeveloperMetadata']['developerMetadata']['metadataId'])
                    self.assertEqual(9002, completed['matchedDeveloperMetadata'][0]['developerMetadata']['metadataId'])
                    self.assertEqual('a' * 64, completed['matchedDeveloperMetadata'][0]['developerMetadata']['metadataValue'])
                if fault == 'owner-cleanup':
                    self.assertIn('target', closed, 'failure injected after original target close return')
            self.assertEqual(credential_before, credential.read_bytes())
            count.assert_not_called(); business.assert_not_called()
            self.assertFalse(list(state.rglob('ATTEMPT-*'))); self.assertFalse(list(state.rglob('CLAIM-*')))
            self.assertFalse(list(state.glob('*.units')))
            if repeat_after_success:
                self.assertIsNone(fault)
                before_repeat = tree_images(state)
                before_counts = (len(children), tuple(stages), len(prepared))
                with mock.patch.object(subprocess, 'Popen',
                        side_effect=AssertionError('completed enrollment must not reauthenticate or rewrite')) as second_child:
                    repeated = self.invoke(project)
                second_child.assert_not_called()
                self.assertEqual((3, '', REFUSED), repeated,
                    'EXPLICIT_ENROLLMENT_COMPLETED_EVIDENCE_WAS_REUSED')
                self.assertEqual(before_repeat, tree_images(state))
                self.assertEqual(before_counts, (len(children), tuple(stages), len(prepared)))

            if after_initialize is not None:
                after_initialize(project, state, bound, real_writer, real_sheet, real_target)

    def _assert_initialized_worker_gate(self, project, state, bound,
            original_writer, original_sheet, original_target, *, expected_new_entries):
        from monitor import issue_tracker_remote_history_match as remote
        from monitor import issue_tracker_enrollment_initialize as initialize
        from monitor import issue_tracker_enrollment_journal as enrollment
        from monitor import issue_tracker_local_commit as local
        from monitor import issue_tracker_spreadsheet_owner as ownership
        from monitor import issue_tracker_online_target as target
        from monitor import issue_tracker_token_launcher as auth
        from monitor import issue_tracker_global_attempt_journal as counted
        from monitor import issue_tracker_mutation_launcher as mutation
        worker = runtime.persistence.WORKER
        before = tree_images(state)
        with ExitStack() as controls:
            store = runtime.cycle(controls, self.root)
            # Normal second use must not get another fixture cleanup fault.
            controls.enter_context(mock.patch.object(local, 'try_writer_owner', original_writer))
            controls.enter_context(mock.patch.object(ownership, 'spreadsheet_owner', original_sheet))
            controls.enter_context(mock.patch.object(target, '_hold_current_project_online_target', original_target))
            controls.enter_context(mock.patch.object(worker, 'STATUS_DIR', self.root / 'monitor/status'))
            controls.enter_context(mock.patch.object(worker, '_publish_stage_l_status_after_completion'))
            controls.enter_context(mock.patch.object(worker, '_publish_stage_l_local_after_completion'))
            controls.enter_context(mock.patch.object(worker.sys, 'stderr', io.StringIO()))
            gate_returns = []
            original_gate = remote._observe_original_first_catalog_absence
            def observe_gate(*args, **kwargs):
                observed = original_gate(*args, **kwargs)
                gate_returns.append(observed)
                return observed
            controls.enter_context(mock.patch.object(remote, '_observe_original_first_catalog_absence',
                side_effect=observe_gate))
            original_new = remote._prepare_current_cycle_native_unit
            new_entry = controls.enter_context(mock.patch.object(remote, '_prepare_current_cycle_native_unit',
                wraps=original_new))
            manual = controls.enter_context(mock.patch.object(initialize, 'initialize_current_project',
                side_effect=AssertionError('normal worker cannot repeat manual initialization')))
            prepare = controls.enter_context(mock.patch.object(enrollment, 'prepare_enrollment_journal',
                side_effect=AssertionError('normal worker cannot repair original nonces')))
            authentication = controls.enter_context(mock.patch.object(auth, 'OwnedProjectTokenRefreshUnit',
                side_effect=AssertionError('this fixture has no C6/online authority for OAuth')))
            # Existing fixture module-local process facade, NOT the shared
            # native subprocess class checked by the actual supervisor.
            child = controls.enter_context(mock.patch.object(initialize.subprocess, 'Popen',
                side_effect=AssertionError('no additional child authorized by initialization DATA')))
            network = controls.enter_context(mock.patch('socket.socket',
                side_effect=AssertionError('no network authority from initialization completion alone')))
            count = controls.enter_context(mock.patch.object(counted, 'record_global_attempt_intent',
                side_effect=AssertionError('initialization does not grant a business COUNT')))
            business = controls.enter_context(mock.patch.object(mutation, '_send_counted_original_once',
                side_effect=AssertionError('initialization does not grant business send authority')))
            worker._publish_issue_tracker_lanes_after_completion(store)
            self.assertEqual(expected_new_entries, new_entry.call_count,
                'INITIALIZATION_COMPLETION_GATE_DID_NOT_MATCH_REAL_WORKER_NEW_BOUNDARY')
            if expected_new_entries:
                self.assertTrue(gate_returns)
                self.assertTrue(all(value is True for value in gate_returns),
                    'only the original complete initialization precondition may pass')
            else:
                self.assertEqual([], gate_returns,
                    'unproved initialization must not return the first-catalog absence precondition')
            for operation in (manual, prepare, authentication, child, network, count, business):
                operation.assert_not_called()
        self.assertEqual(before, tree_images(state), 'normal worker must not repair or consume initialization evidence')

    def _require_original_completion_record(self, state, bound):
        stem = hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
        attempt = state / ('enrollment-init-' + stem)
        complete = attempt / 'COMPLETED'
        self.assertTrue(complete.is_file(), 'MANUAL_SUCCESS_REQUIRES_FINAL_BOUND_COMPLETION_RECORD')
        record = json.loads(complete.read_bytes())
        self.assertIs(type(record), dict)
        self.assertEqual(1, record.get('schema_version'))
        self.assertEqual('INITIALIZATION_COMPLETED', record.get('outcome'))
        self.assertEqual(bound.spreadsheet_id, record.get('spreadsheet_id'))
        self.assertIs(False, record.get('automatic_sending_enabled'))
        self.assertEqual({'HEADER', 'NONCES', 'INITIALIZED'},
            {path.name for path in (state / (stem + '.enrollment')).iterdir()})
        return complete

    def test_real_tls_completed_initialization_unlocks_only_the_normal_worker_initialization_gate(self):
        def after(project, state, bound, *owners):
            self._require_original_completion_record(state, bound)
            self._assert_initialized_worker_gate(project, state, bound, *owners, expected_new_entries=1)
        self._exercise_actual_initialize(after_initialize=after)

    def test_real_owner_cleanup_unknown_blocks_next_normal_worker_before_new_or_authentication(self):
        def after(project, state, bound, *owners):
            stem = hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
            attempt = state / ('enrollment-init-' + stem)
            self.assertTrue((attempt / 'OBSERVED-DATA').is_file(),
                'readback DATA is present before the failing owner finalizer, not a completion permit')
            self.assertFalse((attempt / 'COMPLETED').exists(),
                'OWNER_CLEANUP_UNKNOWN_CANNOT_PUBLISH_COMPLETION')
            self._assert_initialized_worker_gate(project, state, bound, *owners, expected_new_entries=0)
        self._exercise_actual_initialize('owner-cleanup', after_initialize=after)

    def test_real_tls_completion_record_lost_is_retained_and_blocks_next_worker(self):
        def after(project, state, bound, *owners):
            complete = self._require_original_completion_record(state, bound)
            raw, inode = complete.read_bytes(), complete.stat().st_ino
            preserved = self.root / 'preserved-completion-record'
            complete.rename(preserved)
            self.assertFalse(complete.exists())
            self._assert_initialized_worker_gate(project, state, bound, *owners, expected_new_entries=0)
            self.assertEqual((raw, inode), (preserved.read_bytes(), preserved.stat().st_ino))
        self._exercise_actual_initialize(after_initialize=after)

    def test_real_tls_completion_record_tamper_is_not_repaired_or_accepted(self):
        def after(project, state, bound, *owners):
            complete = self._require_original_completion_record(state, bound)
            raw, inode = complete.read_bytes(), complete.stat().st_ino
            preserved = self.root / 'preserved-untampered-completion'
            complete.rename(preserved)
            complete.write_bytes(b'{}\n'); complete.chmod(0o600)
            self._assert_initialized_worker_gate(project, state, bound, *owners, expected_new_entries=0)
            self.assertEqual((raw, inode), (preserved.read_bytes(), preserved.stat().st_ino))
            self.assertEqual(b'{}\n', complete.read_bytes())
        self._exercise_actual_initialize(after_initialize=after)

    def test_real_tls_completion_binding_rejects_same_bytes_replacement_of_original_nonces(self):
        def after(project, state, bound, *owners):
            complete = self._require_original_completion_record(state, bound)
            completion_before = (complete.read_bytes(), complete.stat().st_ino)
            stem = hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
            nonces = state / (stem + '.enrollment') / 'NONCES'
            raw, original_inode = nonces.read_bytes(), nonces.stat().st_ino
            preserved = self.root / 'preserved-completed-original-nonces'
            nonces.rename(preserved)
            nonces.write_bytes(raw); nonces.chmod(0o600)
            self.assertNotEqual(original_inode, nonces.stat().st_ino)
            self._assert_initialized_worker_gate(project, state, bound, *owners, expected_new_entries=0)
            self.assertEqual((raw, original_inode), (preserved.read_bytes(), preserved.stat().st_ino))
            self.assertEqual(completion_before, (complete.read_bytes(), complete.stat().st_ino))
            self.assertEqual(raw, nonces.read_bytes())
        self._exercise_actual_initialize(after_initialize=after)

    def test_existing_real_business_catalog_cannot_bypass_unknown_manual_initialization_gate(self):
        from test_cases import test_req7_unit_catalog as catalog_fixture
        with catalog_fixture.CatalogAppliedNativeWorkflowTests.completed_and_pending(
                self, project_origins=True) as (case, _catalog, remote, _inventory,
                _old_api, writer, owner, bound, _originals):
            state = case.root / 'var/lib/http-ztp-container/issue-tracker'
            stem = hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
            self.assertTrue((state / (stem + '.units')).is_dir(),
                'exercise the actual existing-business path, not empty first-catalog absence')
            attempt = state / ('enrollment-init-' + stem)
            attempt.mkdir(mode=0o700)
            witness = attempt / 'PRESERVED'
            witness.write_bytes(b'UNKNOWN independent initialization; no final completion\n')
            witness.chmod(0o600)
            before = tree_images(state)
            with self.assertRaises(remote.RemoteHistoryHold,
                    msg='EXISTING_BUSINESS_CATALOG_BYPASSED_UNKNOWN_INITIALIZATION'):
                remote._current_cycle_native_new_pending(writer, owner, bound)
            self.assertEqual(before, tree_images(state))

    def test_real_pending_c6_catalog_unknown_initialization_blocks_both_normal_worker_entries(self):
        # Real C6 + pending catalog, no APPLIED/remote-success substitute.
        # Complements, never replaces, the original APPLIED+pending TLS case.
        from test_cases.test_req7_send_unit import inputs as send_inputs
        from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx
        from monitor import issue_tracker_enrollment_journal as enrollment
        from monitor import issue_tracker_sheets_read_plan as plans
        from monitor import issue_tracker_sheets_read_decode as decode
        from monitor import issue_tracker_online_target as target
        from monitor import issue_tracker_unit_catalog as catalog
        from monitor import issue_tracker_send_unit as composer
        from monitor import issue_tracker_global_attempt_journal as journal
        from monitor import issue_tracker_remote_history_match as remote
        from monitor import issue_tracker_token_launcher as authentication
        from monitor import issue_tracker_mutation_launcher as mutation
        from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
        import time
        with ExitStack() as controls:
            project, local, ownership, _old_writer, _old_owner, bound = self.project(controls)
            state = self.root / 'var/lib/http-ztp-container/issue-tracker'
            stem = hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
            refusals = []
            with local.try_writer_owner(project, project / '99-output-monitor') as writer:
                with target._hold_current_project_online_target(writer) as actual:
                    with ownership.spreadsheet_owner(actual) as owner:
                        document = identity_response(); document['spreadsheetId'] = actual.spreadsheet_id
                        identity = decode.decode_template_identity(plans.prepare_template_identity_read(
                            actual, AuthenticatedToken('local-format-only', time.time() + 3600)), response(document))
                        with mock.patch('secrets.token_hex', side_effect=NONCES):
                            enrollment.prepare_enrollment_journal(owner, actual, identity)
                        arguments = send_inputs()
                        arguments.update(spreadsheet_id=actual.spreadsheet_id, sheet_id=101,
                            history_sheet_id=105, target_nonce=NONCES[0], history_nonce=NONCES[3])
                        generation = local.begin_generation(writer, arguments['manifest'])
                        local.record_intent(writer, generation, literal_xlsx(), kind='xlsx')
                        receipt = local.commit(writer, generation)
                        arguments.update(generation_id=generation.generation_id,
                            publish_id=receipt.published_sha256)
                        unit = composer.freeze_send_unit(**arguments)
                        catalog.register_pending_c6_unit(writer, owner, actual, unit)
                        journal.prepare_global_unit(owner, actual, unit)
                        before_count = journal.inspect_global_unit(owner, actual, unit).attempt_count
                        attempt = state / ('enrollment-init-' + stem); attempt.mkdir(mode=0o700)
                        witness = attempt / 'PRESERVED'
                        witness.write_bytes(b'UNKNOWN initialization; retain existing pending C6\n')
                        witness.chmod(0o600)
                        before = tree_images(state)
                        with mock.patch.object(authentication, 'OwnedProjectTokenRefreshUnit',
                                side_effect=AssertionError('UNKNOWN must stop before OAuth')) as auth, \
                                mock.patch.object(journal, 'record_global_attempt_intent',
                                side_effect=AssertionError('UNKNOWN cannot create COUNT')) as count, \
                                mock.patch.object(mutation, '_send_counted_original_once',
                                side_effect=AssertionError('UNKNOWN cannot send')) as send, \
                                mock.patch.object(subprocess, 'Popen',
                                side_effect=AssertionError('UNKNOWN cannot launch')) as child, \
                                mock.patch.object(socket, 'socket',
                                side_effect=AssertionError('UNKNOWN cannot connect')) as network:
                            for entry in (remote._current_cycle_native_new_pending,
                                          remote._reconcile_pending_project_units_with_authentication):
                                try:
                                    entry(writer, owner, actual)
                                except remote.RemoteHistoryHold:
                                    refusals.append(True)
                                else:
                                    refusals.append(False)
                        after_count = journal.inspect_global_unit(owner, actual, unit).attempt_count
            # Independent assertions outside original owner normalization.
            self.assertEqual([True, True], refusals)
            self.assertTrue((state / (stem + '.units')).is_dir())
            self.assertEqual((0, 0), (before_count, after_count))
            self.assertEqual(before, tree_images(state))
            for operation in (auth, count, send, child, network): operation.assert_not_called()

    def test_explicit_fresh_initialization_orders_real_local_journal_before_one_tls_batch_and_readback(self):
        self._exercise_actual_initialize()

    def test_existing_remote_metadata_refuses_before_local_nonces_or_initialization_write(self):
        self._exercise_actual_initialize('remote-existing')

    def test_unknown_initialization_write_retains_local_originals_without_retry_or_success(self):
        self._exercise_actual_initialize('write-UNKNOWN')

    def test_matching_nonce_with_mismatched_readback_metadata_id_is_not_initialization(self):
        self._exercise_actual_initialize('readback-mismatch')

    def test_final_owner_cleanup_failure_after_real_readback_cannot_report_success(self):
        self._exercise_actual_initialize('owner-cleanup')

    def test_completed_initialization_is_not_repeated_or_reauthenticated(self):
        self._exercise_actual_initialize(repeat_after_success=True)

    def test_default_worker_missing_enrollment_never_calls_manual_initializer(self):
        from monitor import issue_tracker_enrollment_initialize as initialize
        from monitor import issue_tracker_enrollment_journal as enrollment
        from monitor import issue_tracker_token_launcher as auth
        worker = runtime.persistence.WORKER
        with ExitStack() as stack:
            _project, _local, _ownership, _writer, _owner, bound = self.project(stack)
            store = runtime.cycle(stack, self.root)
            state = self.root / 'var/lib/http-ztp-container/issue-tracker'
            before = tree_images(state)
            stem = hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
            stack.enter_context(mock.patch.object(worker, 'STATUS_DIR', self.root / 'monitor/status'))
            stack.enter_context(mock.patch.object(worker, 'timestamp', return_value='2026-01-01T00:00:00+00:00'))
            stack.enter_context(mock.patch.object(worker, '_publish_stage_l_status_after_completion'))
            stack.enter_context(mock.patch.object(worker, '_publish_stage_l_local_after_completion'))
            manual = stack.enter_context(mock.patch.object(initialize, 'initialize_current_project',
                side_effect=AssertionError('ordinary worker must never initialize enrollment')))
            prepare = stack.enter_context(mock.patch.object(enrollment, 'prepare_enrollment_journal',
                side_effect=AssertionError('ordinary worker must never prepare enrollment')))
            authentication = stack.enter_context(mock.patch.object(auth, 'OwnedProjectTokenRefreshUnit',
                side_effect=AssertionError('missing enrollment diagnostic cannot authenticate')))
            child = stack.enter_context(mock.patch.object(subprocess, 'Popen',
                side_effect=AssertionError('ordinary missing-enrollment worker cannot spawn')))
            network = stack.enter_context(mock.patch('socket.socket', side_effect=AssertionError('no network')))
            stack.enter_context(mock.patch.object(worker.sys, 'stderr', io.StringIO()))
            worker._publish_issue_tracker_lanes_after_completion(store)
            for operation in (manual, prepare, authentication, child, network):
                operation.assert_not_called()
            self.assertEqual({'schema_version': 1, 'state': 'enrollment_missing',
                'updated_at': '2026-01-01T00:00:00+00:00', 'read_only': True, 'mutation_disabled': True},
                json.loads((self.root / 'monitor/status/issue-tracker-online.status.json').read_bytes()))
            self.assertEqual(before, tree_images(state))
            self.assertFalse((state / ('enrollment-init-' + stem)).exists())

    def test_partial_lost_or_unknown_local_evidence_is_preserved_before_any_oauth_or_repair(self):
        from monitor import issue_tracker_enrollment_journal as enrollment
        from monitor import issue_tracker_sheets_read_plan as plans
        from monitor import issue_tracker_sheets_read_decode as decode
        for fault in ('partial', 'lost', 'UNKNOWN'):
            with self.subTest(fault=fault), ExitStack() as stack:
                if fault != 'partial':
                    self.setUp(); stack.callback(self.doCleanups)
                project, _local, _ownership, _writer, _owner, bound = self.project(stack)
                state = self.root / 'var/lib/http-ztp-container/issue-tracker'
                stem = hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
                if fault == 'partial':
                    from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
                    import time
                    with _ownership.spreadsheet_owner(bound) as owner:
                        document = identity_response(); document['spreadsheetId'] = bound.spreadsheet_id
                        identity = decode.decode_template_identity(plans.prepare_template_identity_read(
                            bound, AuthenticatedToken('fixture-only', time.time() + 3600)), response(document))
                        with mock.patch('secrets.token_hex', side_effect=NONCES):
                            enrollment.prepare_enrollment_journal(owner, bound, identity)
                    (state / (stem + '.enrollment') / 'INITIALIZED').rename(self.root / 'preserved-partial-marker')
                elif fault == 'lost':
                    witness = state / (stem + '.units-started')
                    witness.write_bytes(b'original lost-enrollment catalog witness\n'); witness.chmod(0o600)
                else:
                    attempt = state / ('enrollment-init-' + stem); attempt.mkdir(mode=0o700)
                    witness = attempt / 'PRESERVED'
                    witness.write_bytes(b'UNKNOWN initialization attempt; never adopt or retry\n'); witness.chmod(0o600)
                before = tree_images(state)
                with mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('no authentication or write child')) as child, \
                        mock.patch('socket.socket', side_effect=AssertionError('no network')) as network, \
                        mock.patch.object(enrollment, 'prepare_enrollment_journal',
                            side_effect=AssertionError('no initialization repair/adoption')) as prepare:
                    status, stdout, stderr = self.invoke(project)
                child.assert_not_called(); network.assert_not_called(); prepare.assert_not_called()
                self.assertEqual(before, tree_images(state))
                self.assertEqual((3, '', REFUSED), (status, stdout, stderr),
                    'EXPLICIT_ENROLLMENT_UNSAFE_EVIDENCE_NOT_REFUSED')


# Fixed DATA scopes, not a completion marker schema or send permission.
_DATA_GRAPH_LEAVES = (
    ('attempt', 'INTENT'),
    ('attempt', 'PREFLIGHT-template_identity'),
    ('attempt', 'PREFLIGHT-template_headers'),
    ('attempt', 'PREFLIGHT-whitelist'),
    ('attempt', 'PREFLIGHT-metadata'),
    ('attempt', 'WIRE'),
    ('attempt', 'RESPONSE'),
    ('attempt', 'RESPONSE-STATUS'),
    ('attempt', 'READBACK'),
    ('attempt', 'OBSERVED-DATA'),
    ('journal', 'HEADER'),
    ('journal', 'NONCES'),
    ('journal', 'INITIALIZED'),
)


class InitializationDataGraphWorkflowTests(unittest.TestCase):
    def test_real_tls_data_graph_rejects_readback_replacement_without_completion(self):
        # Use the normal canonical fixture even when this appended candidate is
        # loaded from a private SOURCE path. Do not execute its copied old tests.
        from test_cases import test_req7_explicit_enrollment_initialize_workflow as canonical
        fixture = canonical.ExplicitEnrollmentInitializeWorkflowTests(methodName='runTest')
        def cleanup_original_fixture():
            self.assertTrue(fixture.doCleanups(),
                            'AUTHENTIC_TLS_ORIGINAL_FIXTURE_CLEANUP_INCOMPLETE')
        self.addCleanup(cleanup_original_fixture)
        fixture.setUp()
        observed = []

        def after_initialize(project, state, bound, real_writer, real_sheet, real_target):
            from monitor import issue_tracker_unit_catalog as catalog
            from monitor import issue_tracker_enrollment_initialize as initialize
            from monitor import issue_tracker_spreadsheet_owner as ownership
            from monitor import issue_tracker_token_launcher as tokens
            from monitor import issue_tracker_global_attempt_journal as counted
            from monitor import issue_tracker_mutation_launcher as mutation

            def stat9(info):
                return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                        info.st_gid, info.st_nlink, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns)

            facts = {}
            stem = hashlib.sha256(bound.spreadsheet_id.encode()).hexdigest()
            attempt = state / ('enrollment-init-' + stem)
            nonce = state / (stem + '.enrollment')
            retained = fixture.root / 'retained-original-readback'
            readback = attempt / 'READBACK'
            # The real TLS helper has already completed all its original
            # journal-before-request/readback/child-reap assertions and closed
            # its manual owners. No new remote operation is allowed here.
            with mock.patch.object(tokens, 'OwnedProjectTokenRefreshUnit',
                    side_effect=AssertionError('DATA graph cannot authenticate')) as extra_auth, \
                 mock.patch.object(counted, 'record_global_attempt_intent',
                    side_effect=AssertionError('DATA graph cannot COUNT')) as extra_count, \
                 mock.patch.object(mutation, '_send_counted_original_once',
                    side_effect=AssertionError('DATA graph cannot send')) as extra_send:
                with real_writer(project, project / '99-output-monitor') as writer:
                    with real_target(writer) as actual_binding:
                        with real_sheet(actual_binding) as sheet:
                            facts['binding_equal'] = actual_binding == bound
                            sheet_owner = ownership._validated_owner(sheet, actual_binding)
                            parent = sheet_owner.directories[-1][0]  # Borrowed, never closed here.
                            graph = catalog._Originals()
                            primary = None
                            try:
                                attempt_fd = graph.directory(parent, 'enrollment-init-' + stem)
                                nonce_fd = graph.directory(parent, stem + '.enrollment')
                                directories = {'attempt': attempt_fd, 'journal': nonce_fd}
                                scopes = {attempt_fd: 'attempt', nonce_fd: 'journal'}
                                for scope, leaf in _DATA_GRAPH_LEAVES:
                                    graph.file(directories[scope], leaf, 2 * 1024 * 1024)

                                def snapshot():
                                    return {
                                        (scopes[parent_fd], leaf): {
                                            'fd': fd, 'captured_stat9': identity,
                                            'stat9': stat9(os.fstat(fd)),
                                            'sha256': hashlib.sha256(
                                                os.pread(fd, len(raw) + 1, 0)).hexdigest(),
                                            'captured_sha256': hashlib.sha256(raw).hexdigest(),
                                        }
                                        for parent_fd, leaf, fd, identity, raw in graph.files
                                    }

                                facts['verify_globals_original'] = (
                                    catalog._Originals.verify.__globals__ is catalog.__dict__)
                                facts['first_verify_result'] = graph.verify()
                                facts['verified_before'] = True
                                facts['before'] = snapshot()
                                facts['attempt_before'] = set(os.listdir(attempt_fd))
                                facts['journal_before'] = set(os.listdir(nonce_fd))
                                facts['retained_did_not_exist'] = not retained.exists()

                                readback.rename(retained)
                                with readback.open('xb') as replacement:
                                    os.fchmod(replacement.fileno(), 0o600)
                                    replacement.write(b'{}\n')
                                facts['after'] = snapshot()
                                facts['attempt_after'] = set(os.listdir(attempt_fd))
                                facts['journal_after'] = set(os.listdir(nonce_fd))
                                facts['replacement_inode'] = readback.stat().st_ino
                                facts['replacement_bytes'] = readback.read_bytes()
                                facts['retained_inode'] = retained.stat().st_ino
                                facts['retained_bytes'] = retained.read_bytes()
                                original_readback = next(row[4] for row in graph.files
                                    if row[0] == attempt_fd and row[1] == 'READBACK')
                                facts['original_readback_bytes'] = original_readback
                                facts['refusal'] = None
                                facts['verify_frame_original'] = False
                                try:
                                    graph.verify()
                                except catalog.UnitCatalogHold as error:
                                    facts['refusal'] = type(error)
                                    trace = error.__traceback__
                                    while trace is not None:
                                        facts['verify_frame_original'] |= (
                                            trace.tb_frame.f_code is catalog._Originals.verify.__code__
                                            and trace.tb_frame.f_globals is catalog.__dict__)
                                        trace = trace.tb_next
                                # Verification checks directory identity before
                                # file rows. This HOLD does not prove that the
                                # later file-FD branch ran or all 13 revalidated.
                            except BaseException as error:
                                primary = error
                            finally:
                                primary = initialize._close_initialization_images(
                                    graph, None, None, primary)
                            if primary is not None:
                                raise primary
                            facts['graph_close_returned'] = True
                facts['owners_returned'] = True
                facts['additional_calls'] = (extra_auth.call_count,
                    extra_count.call_count, extra_send.call_count)
            facts['no_completion_markers'] = not any(
                (attempt / name).exists() for name in ('.COMPLETED-STAGED', 'COMPLETED'))
            observed.append((facts, catalog.UnitCatalogHold))

        fixture._exercise_actual_initialize('data-only-without-final-completion',
                                           after_initialize=after_initialize)
        # Independent assertions stay outside all actual owner contexts;
        # owner normalization cannot turn an assertion failure into HOLD.
        self.assertEqual(len(observed), 1)
        facts, expected_hold = observed[0]
        self.assertIs(facts['binding_equal'], True)
        self.assertIs(facts['verify_globals_original'], True)
        self.assertIs(facts['verified_before'], True)
        self.assertIsNone(facts['first_verify_result'])
        self.assertIs(facts['retained_did_not_exist'], True)
        self.assertEqual(set(facts['before']), set(_DATA_GRAPH_LEAVES))
        self.assertEqual(set(facts['after']), set(_DATA_GRAPH_LEAVES))
        for leaf in _DATA_GRAPH_LEAVES:
            with self.subTest(original=leaf):
                before, after = facts['before'][leaf], facts['after'][leaf]
                self.assertEqual(before['fd'], after['fd'])
                self.assertEqual(before['stat9'], before['captured_stat9'])
                self.assertEqual(before['stat9'][:2], after['stat9'][:2])
                self.assertEqual(before['sha256'], before['captured_sha256'])
                self.assertEqual(before['sha256'], after['sha256'])
                if leaf != ('attempt', 'READBACK'):
                    self.assertEqual(before['stat9'], after['stat9'])
        self.assertEqual(facts['attempt_before'], {name for scope, name in _DATA_GRAPH_LEAVES if scope == 'attempt'})
        self.assertEqual(facts['attempt_after'], facts['attempt_before'])
        self.assertEqual(facts['journal_before'], {'HEADER', 'NONCES', 'INITIALIZED'})
        self.assertEqual(facts['journal_after'], facts['journal_before'])
        original_inode = facts['before'][('attempt', 'READBACK')]['stat9'][1]
        self.assertEqual(facts['retained_inode'], original_inode)
        self.assertEqual(facts['retained_bytes'], facts['original_readback_bytes'])
        self.assertNotEqual(facts['replacement_inode'], original_inode)
        self.assertEqual(facts['replacement_bytes'], b'{}\n')
        self.assertIs(facts['refusal'], expected_hold,
                      'REAL_DATA_GRAPH_MUST_REFUSE_READBACK_ORIGINAL_REPLACEMENT')
        self.assertIs(facts['verify_frame_original'], True)
        self.assertIs(facts['graph_close_returned'], True)
        self.assertIs(facts['owners_returned'], True)
        self.assertIs(facts['no_completion_markers'], True)
        self.assertEqual(facts['additional_calls'], (0, 0, 0))
