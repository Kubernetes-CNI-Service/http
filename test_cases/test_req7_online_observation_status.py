"""Non-authoritative last-observation display: never a send admission."""
from contextlib import ExitStack
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
