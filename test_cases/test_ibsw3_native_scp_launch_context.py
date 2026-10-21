"""NOT RUN: DIRECT native-original envelope DATA, not executor launch authority.

The existing carrier is imported unchanged. Its target SDK/query/MemorySFTP IO
is synthetic. A real wrapper call supplies the already consumed native leaf;
this test deliberately calls original stage APIs and the proposed builder there.
The executor does not call the builder. No probe/SSH/launch/dispatch/ACK is run.
"""
import dis
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from test_cases import scp_native_source_preflight_fixture as FIXTURE
from test_cases import test_ibsw3_scp_source_cli_prompt_binding as CLI


SECRET = 'DIRECT-LAUNCH-CONTEXT-SOURCE-ONLY-72c1'
ORIGINALS = ('request.json', 'step.sh', 'step-binding.json', 'runner.sh', 'runner-binding.json')
COMPANION = 'scp-source-request.json'
PACKAGE_BYTES = b'SYNTHETIC-NOT-FIRMWARE'
PACKAGE_SHA = hashlib.sha256(PACKAGE_BYTES).hexdigest()
RETAINED_DIRECT_TREES = []


class _DirectStop(FIXTURE.driver.SharedUpgradeHold):
    """Test control: stop at the original call seam, not a production success."""


class NativeScpLaunchContextDirectTests(unittest.TestCase):
    def capability(self):
        method = getattr(FIXTURE.driver._PreparedRunScope, '_native_scp_launch_context', None)
        self.assertTrue(callable(method),
            'MISSING_NATIVE_SCP_LAUNCH_CONTEXT_CAPABILITY; original graph/export NOT_REACHED')
        self.assertEqual(('self', 'leaf', 'component', 'package_index'),
                         tuple(inspect.signature(method).parameters))
        self.assertIs(method.__globals__, FIXTURE.driver.__dict__)
        return method

    def exercise(self, method, fault=None):
        scope_type = FIXTURE.driver._PreparedRunScope
        wrapper = scope_type._preflight_native_scp_source
        getter = scope_type._native_scp_source
        execute = FIXTURE.executor._execute_component_once
        provider = importlib.import_module('ibsw_upgrade_scp')
        real_read, real_fstat = os.read, os.fstat
        real_sync, real_close = os.fsync, os.close
        stop = _DirectStop('DIRECT envelope test stops before original probe body')
        state = dict(actions=0, action_error=None, invoke_error=None, getters=[], chunks=[],
                     capture_sync=[], capture_close=[], capture_active=False,
                     builder_returned=False, builder_error=None, result=None)
        root = Path(tempfile.mkdtemp(prefix='ibsw-native-context-direct-')).resolve()
        state['root'] = root
        trust = root / 'scp-source-known_hosts'
        trust.write_bytes(CLI.known_line(17)); trust.chmod(0o600)
        package = root / 'packages/image/nvos-amd64-25.03.1010.bin'
        state['package'] = package
        self.assertIsNone(sys.getprofile()); self.assertIsNone(sys.gettrace())
        self.assertIsNone(getattr(threading, 'getprofile', lambda: None)())
        self.assertIsNone(getattr(threading, 'gettrace', lambda: None)())

        def key(row):
            return row.st_dev, row.st_ino, stat.S_IFMT(row.st_mode)

        def reading(fd, count):
            value = real_read(fd, count)
            try:
                named = package.lstat()
            except FileNotFoundError:
                return value
            if key(real_fstat(fd)) == key(named):
                state['chunks'].append(value)  # Real IO result; never substitutes bytes.
            return value

        def syncing(fd):
            value = real_sync(fd)
            if state['capture_active']:
                state['capture_sync'].append(key(real_fstat(fd)))
            return value

        def closing(fd):
            original = key(real_fstat(fd)) if state['capture_active'] else None
            value = real_close(fd)
            if original is not None:
                state['capture_close'].append(original)  # Only actual normal close return.
            return value

        def normal(frame):
            return frame.f_lasti >= 0 and dis.opname[frame.f_code.co_code[frame.f_lasti]] in (
                'RETURN_VALUE', 'RETURN_CONST')

        def observe(frame, event, argument):
            if (frame.f_code is getter.__code__ and frame.f_globals is getter.__globals__
                    and event == 'return' and normal(frame)):
                caller = frame.f_back
                state['getters'].append((frame.f_locals['self'], frame.f_locals['leaf'], argument,
                    caller.f_code is execute.__code__, caller.f_globals is execute.__globals__))

        def direct(frame):
            child, leaf = frame.f_locals['self'], frame.f_locals['leaf']
            component, index = frame.f_locals['component'], frame.f_locals['package_index']
            transport, deadline = frame.f_locals['transport'], frame.f_locals['deadline']
            parent = child._native_parent
            state.update(child=child, parent=parent, leaf=leaf, owner=parent._package_source_owner,
                         component=component, index=index,
                         controls=(type(child) is scope_type, type(parent) is scope_type,
                             type(leaf) is FIXTURE.driver._ReadonlyQueryInputs, leaf.scope is child,
                             leaf._original_selection[0] is child,
                             leaf._native_observation_consumed is True,
                             child._package_source_parent is parent,
                             child._package_source_owner is parent._package_source_owner,
                             child._package_source_selection is parent._package_source_selection,
                             child in parent._package_source_borrowers,
                             child._native_schedule_started, parent._native_schedule_started,
                             frame.f_back.f_code is execute.__code__,
                             frame.f_back.f_globals is execute.__globals__))
            # Explicit DIRECT getter call on the original registered graph.
            # Not readiness relabeling and not proof the executor calls builder.
            source = child._native_scp_source(leaf, component, index)
            state['source_same'] = source is parent._scp_source
            data, _records = FIXTURE.executor._component_query(leaf, transport, component, deadline)
            uid_raw = FIXTURE.executor._complete_query(leaf, transport, FIXTURE.executor._UID_COMMAND, deadline)
            if not (uid_raw[1:] == (b'', 0, True) and uid_raw[0].endswith(b'\n')
                    and uid_raw[0][:-1].isdigit()):
                raise RuntimeError('DIRECT fixture did not obtain original numeric UID query')
            uid = int(uid_raw[0])
            sftp = None
            try:
                with child._request_namespace_lease():
                    child._prepare_requested_step_locked(leaf.node.hostname, component, index)
                    child._request_prepared_step_locked(leaf.node.hostname, component, index)
                    # Original uploader generates its own nonce and performs all
                    # original same-handle checks against existing MemorySFTP IO.
                    sftp = FIXTURE.executor._fixed_sdk().SFTPClient.from_transport(transport)
                    sftp.get_channel().settimeout(FIXTURE.observer._remaining(deadline))
                    remote = FIXTURE.executor._upload_original_script(leaf, data, sftp, uid, deadline)
                    child._prepare_owned_runner_data_locked(leaf, component, index, remote_script=remote)
                    sftp.close(); sftp = None
                    stage, binding, _args = child._owned_runner_stage(leaf, component, index)
                    held = {name: child._hold(stage, name) for name in ORIGINALS}
                    state['originals_before'] = {name: (obj, obj.fd, obj.payload) for name, obj in held.items()}
                    state['stage_key'] = key(real_fstat(stage.fd))
                    state['capture_active'] = True
                    try:
                        capture = child._capture_scp_request_content_locked(leaf, component, index)
                    finally:
                        state['capture_active'] = False
                    state['capture_none'] = capture is None
                    companion = child._hold(stage, COMPANION)
                    state['companion_key'] = key(real_fstat(companion.fd))
                    state['original_objects'] = tuple(held.values()) + (companion,)
                    state['public_before'] = {name: held[name].payload for name in ORIGINALS}
                    state['public_before'][COMPANION] = companion.payload
                    state['expected_public'] = dict(host='198.51.100.44', user='source_test', port=2222,
                        host_keys=CLI.known_line(17).decode('ascii'), timeout_seconds=600,
                        paths={str(package): len(PACKAGE_BYTES)},
                        content_binding=dict(version=1,
                            binding_sha256=hashlib.sha256(held['step-binding.json'].payload).hexdigest(),
                            request_id=json.loads(held['request.json'].payload)['request_id'],
                            request_sha256=hashlib.sha256(held['request.json'].payload).hexdigest(),
                            companion_sha256=hashlib.sha256(companion.payload).hexdigest(),
                            packages={str(package): dict(size=len(PACKAGE_BYTES), sha256=PACKAGE_SHA)}))
                    state['companion_document'] = json.loads(companion.payload)
                    state['five_same_after_capture'] = all(
                        child._hold(stage, name) is obj and obj.fd == fd and obj.payload == payload
                        for name, (obj, fd, payload) in state['originals_before'].items())
                    if fault == 'companion_replaced':
                        retained = root / 'retained-original-companion'
                        (stage.path / COMPANION).rename(retained)
                        replacement = stage.path / COMPANION
                        replacement.write_bytes(b'{}\n'); replacement.chmod(0o600)
                        state['retained_original_same'] = (
                            key(retained.lstat()) == state['companion_key']
                            and retained.read_bytes() == companion.payload)
                    elif fault == 'owner_slot':
                        # A foreign sentinel is not a package owner/capability.
                        child._package_source_owner = object()
                    if fault != 'lease_missing':
                        try:
                            raw = method(child, leaf, component, index)
                        except BaseException as error:
                            state['builder_error'] = error
                        else:
                            state['raw'] = raw; state['builder_returned'] = True
                    state['public_after'] = {name: obj.payload for name, obj in held.items()}
                    state['public_after'][COMPANION] = companion.payload
                    state['no_dispatch_ack'] = not any(
                        (stage.path / name).exists() for name in ('component-dispatch.json', 'download-ack'))
            finally:
                if sftp is not None:
                    sftp.close()  # Only this original known fixture handle; no FD rescue.
            if fault == 'lease_missing':
                state['lease_absent'] = child._active_request_lease is None
                try:
                    raw = method(child, leaf, component, index)
                except BaseException as error:
                    state['builder_error'] = error
                else:
                    state['raw'] = raw; state['builder_returned'] = True

        def trace(frame, event, argument):
            if (event == 'call' and frame.f_code is wrapper.__code__
                    and frame.f_globals is wrapper.__globals__):
                state['actions'] += 1
                if state['actions'] == 1:
                    try:
                        direct(frame)
                    except BaseException as error:
                        state['action_error'] = error
                raise stop  # Deliberately never enter original probe body.
            return None

        try:
            sys.setprofile(observe); threading.setprofile(observe)
            sys.settrace(trace); threading.settrace(trace)
            with patch.object(sys, 'stdin', CLI.UnitTTY()), \
                 patch.object(FIXTURE.app.getpass, 'getpass', return_value=SECRET), \
                 patch.object(os, 'read', reading), patch.object(os, 'fsync', syncing), \
                 patch.object(os, 'close', closing):
                try:
                    state['result'] = FIXTURE.ThreeComponentWorkflowTests().invoke(
                        root, selection=('--os-only',), controlled_grace=True)
                except BaseException as error:
                    state['invoke_error'] = error
        finally:
            threading.settrace(None); sys.settrace(None)
            threading.setprofile(None); sys.setprofile(None)
        # Do not recursively delete an uncertain owner/evidence tree. A failed
        # assertion or negative case is retained, not closed/retried by FD number.
        RETAINED_DIRECT_TREES.append(str(root))
        return state

    def assert_graph(self, state, *, allow_group_tail=False):
        if state['action_error'] is not None:
            if not (allow_group_tail and state['action_error'] is
                    state.get('parent')._package_source_lifecycle_failure):
                raise RuntimeError('DIRECT fixture/stage/teardown failed before complete oracle') from state['action_error']
        self.assertEqual(1, state['actions'])
        self.assertTrue(all(state['controls']), 'actual native parent/borrow/leaf/executor identity')
        self.assertEqual(('os', 1), (state['component'], state['index']))
        self.assertTrue(state['source_same'])
        self.assertTrue(any(child is state['child'] and leaf is state['leaf'] and
            source is state['parent']._scp_source and caller_code and caller_globals
            for child, leaf, source, caller_code, caller_globals in state['getters']),
            'original pre-session executor getter completed normally')
        self.assertTrue(state['capture_none']); self.assertTrue(state['five_same_after_capture'])
        self.assertIn(state['companion_key'], state['capture_sync'], 'actual original file fsync returned')
        self.assertIn(state['stage_key'], state['capture_sync'], 'actual original directory fsync returned')
        self.assertIn(state['companion_key'], state['capture_close'], 'actual original writer close returned')
        companion = state['companion_document']
        self.assertEqual((2, 'SCP_REQUEST_CONTENT_DATA_ONLY', 'NOT_EXECUTED', 'UNKNOWN', 'scp'),
            (companion['schema_version'], companion['state'], companion['execution_state'],
             companion['activation_state'], companion['declared_method']))
        self.assertTrue(companion['packages'] == state['expected_public']['content_binding']['packages'])
        self.assertEqual(companion['request_id'], state['expected_public']['content_binding']['request_id'])
        self.assertEqual([PACKAGE_BYTES, b''], state['chunks'], 'one original hash pass; builder never rehashes')
        self.assertTrue(all(SECRET.encode() not in raw for raw in state['public_before'].values()))
        self.assertIsNone(sys.getprofile()); self.assertIsNone(sys.gettrace())

    def test_native_originals_export_only_bounded_private_envelope_data(self):
        state = self.exercise(self.capability())
        self.assert_graph(state)
        self.assertIsNone(state['invoke_error'], 'healthy direct graph must complete real owner teardown')
        self.assertIsNone(state['builder_error']); self.assertTrue(state['builder_returned'])
        raw = state['raw']
        self.assertIs(type(raw), bytes); self.assertLessEqual(len(raw), 65536)
        self.assertTrue(raw.endswith(b'\n')); self.assertEqual(1, raw.count(b'\n'))
        document = json.loads(raw)
        self.assertIs(type(document), dict)
        self.assertEqual(set(state['expected_public']) | {'password'}, set(document))
        self.assertTrue(document['password'] == SECRET, 'same source secret only in returned private bytes')
        public = {name: value for name, value in document.items() if name != 'password'}
        self.assertTrue(public == state['expected_public'], 'independent fixed public envelope mismatch')
        self.assertTrue(state['public_before'] == state['public_after'], 'no persisted request/runner/companion change')
        self.assertTrue(state['no_dispatch_ack'])
        self.assertTrue(state['child'].closed); self.assertTrue(state['parent'].closed)
        self.assertEqual([], state['child'].cleanup_issues); self.assertEqual([], state['parent'].cleanup_issues)
        self.assertTrue(all(obj.fd is None for obj in state['original_objects']))
        self.assertTrue(state['owner']._closed)
        self.assertIsNone(state['parent']._package_source_lifecycle_failure)
        code, report, error, calls, installs = state['result']
        self.assertNotEqual(0, code); self.assertEqual([], installs)
        self.assertTrue(SECRET not in error and SECRET not in repr(report))
        shutil.rmtree(state['root'])  # Only after all original healthy teardown facts.
        RETAINED_DIRECT_TREES.remove(str(state['root']))

    def test_missing_lease_or_changed_companion_or_owner_never_exports_and_poison_group(self):
        method = self.capability()
        for fault in ('lease_missing', 'companion_replaced', 'owner_slot'):
            with self.subTest(fault=fault):
                state = self.exercise(method, fault)
                # Sticky verification can also reject the original lease tail.
                # That tail is not substituted for the builder's own refusal.
                if state['action_error'] is not None and state['builder_error'] is None:
                    raise RuntimeError('negative DIRECT fixture failed before builder refusal') from state['action_error']
                self.assert_graph(state, allow_group_tail=True)
                self.assertFalse(state['builder_returned'], 'no envelope before lease/original owner admission')
                self.assertIsInstance(state['builder_error'], FIXTURE.driver.SharedUpgradeHold)
                self.assertIsInstance(state['parent']._package_source_lifecycle_failure,
                                      FIXTURE.driver.SharedUpgradeHold)
                if fault == 'lease_missing': self.assertTrue(state['lease_absent'])
                if fault == 'companion_replaced': self.assertTrue(state['retained_original_same'])
                self.assertTrue(all(SECRET.encode() not in raw for raw in state['public_before'].values()))
                # Retain unknown source-group/FD/evidence state. No rescue,
                # source refresh, retry, fake owner adoption or automatic repair.


if __name__ == '__main__':
    unittest.main()
