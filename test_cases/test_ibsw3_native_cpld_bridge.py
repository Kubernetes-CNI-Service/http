"""UNRUN real native CPLD bridge workflow with precisely lowered executable IO.

No production result, dispatch, verifier, owner or manager ACK is mocked.
All uncertain roots remain for the root driver; each whole runs in its own
original-handle supervised child via the existing fixed isolation pattern.
"""
import base64
import dis
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_cases import scp_native_cpld_bridge_fixture as FIXTURE
from test_cases import native_cpld_physical_io as IO
from test_cases import scp_native_cpld_bridge_isolation as ISOLATION
from test_cases import test_ibsw3_scp_source_cli_prompt_binding as CLI

SECRET = 'secret-value'
RETAINED_TREES = []
BURN = 'FUI1_BURN_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme'
REFRESH = 'FUI1_REFRESH_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme'
ORIGINALS = ('request.json', 'step.sh', 'step-binding.json', 'runner.sh',
             'runner-binding.json', 'scp-source-request.json')


class NativeCpldBridgeWorkflowTests(unittest.TestCase):
    def exercise(self, fault=None):
        root = Path(tempfile.mkdtemp(prefix='native-cpld-bridge-owned-', dir='/private/tmp')).resolve()
        RETAINED_TREES.append(str(root))
        switch = root / 'switch'; switch.mkdir(mode=0o700)
        trust = root / 'scp-source-known_hosts'
        trust.write_bytes(CLI.known_line(17)); trust.chmod(0o600)
        provider = importlib.import_module('ibsw_upgrade_scp')
        scope = FIXTURE.driver._PreparedRunScope
        r = SimpleNamespace(root=root, switch=switch, channels=[], remotes=[], factories=[],
            freezes=[], requests=[], captures=[], contexts=[], dispatches=[], bound=[],
            manager=[], signed_probes=[], fault_fired=False, fixture_error=None,
            invoke_error=None, fault_error=None, original_rows=None,
            same_inode=False, poison_rejections=None, live_close_verifications=[])

        class RemoteBridge:
            def __init__(self): self.switch = switch
            def remote(self, memory):
                value = IO.PhysicalSwitchSFTP(switch, memory)
                r.remotes.append(value); return value
            def open_channel(self, **kwargs):
                value = IO.ActualFixedPythonChannel(root, root / ('channel-%d.json' % len(r.channels)))
                r.channels.append(value); return value
            def query(self, leaf, transport, command, deadline):
                raise AssertionError('secret launcher must use its fixed stdin role, not generic _read_channel')

        watched = {
            'close': scope.close,
            'factory': provider.source_from_known_hosts,
            'freeze': scope.freeze_scp_package_sources,
            'request': scope._request_prepared_step_locked,
            'capture': scope._capture_scp_request_content_locked,
            'context': scope._native_scp_launch_context,
            'preflight': scope._preflight_native_scp_source,
            'execute': FIXTURE.executor._execute_component_once,
            'bound': FIXTURE.executor._bound_component_postcondition_inputs,
            'manager': FIXTURE.executor._probe_component_exit_once,
        }

        def normal(frame):
            return frame.f_lasti >= 0 and dis.opname[frame.f_code.co_code[frame.f_lasti]] in (
                'RETURN_VALUE', 'RETURN_CONST')

        def graph(child, leaf, component, index):
            stage = child.run_directory / leaf.node.hostname / FIXTURE.driver.declared_step_key(
                child.policy, component, index)
            held = {name: child.files[(str(stage), name)] for name in ORIGINALS}
            return stage, held

        def observe(frame, event, value):
            if (event == 'call' and r.fault_fired and r.contexts
                    and frame.f_code is watched['close'].__code__
                    and frame.f_globals is watched['close'].__globals__):
                owner = frame.f_locals['self']
                child, _leaf, parent, _stage, _held, _raw = r.contexts[0]
                if ((owner is child or owner is parent) and owner.closed is False
                        and not any(row[0] is owner for row in r.live_close_verifications)):
                    # Passive observation at the ACTUAL original close entry,
                    # while this exact owner is still live. No test assertion
                    # or replacement verify result may affect production exit.
                    failure = None
                    marker = parent._package_source_lifecycle_failure
                    before_closed = owner.closed
                    try:
                        owner.verify()
                    except BaseException as error:
                        failure = error
                    r.live_close_verifications.append((owner, failure, marker,
                        before_closed, owner.closed, parent._package_source_lifecycle_failure))
            selected = next((name for name, function in watched.items()
                if frame.f_code is function.__code__ and frame.f_globals is function.__globals__), None)
            if selected is None or event != 'return' or not normal(frame): return
            local = frame.f_locals
            if selected == 'factory' and value is not None: r.factories.append(value)
            elif selected == 'freeze' and value is not None: r.freezes.append((local['self'], value))
            elif selected == 'request': r.requests.append((local['self'], local['node'], local['component']))
            elif selected == 'capture': r.captures.append(local['self'])
            elif selected == 'preflight': r.signed_probes.append(local['self'])
            elif selected == 'execute' and value is not None:
                r.dispatches.append((local['leaf'], value))
            elif selected == 'bound':
                r.bound.append((local['leaf'], local['dispatch'], value))
            elif selected == 'manager' and type(value) is dict:
                r.manager.append(value)
            elif selected == 'context' and type(value) is bytes:
                child, leaf = local['self'], local['leaf']
                component, index = local['component'], local['package_index']
                parent = child._native_parent
                stage, held = graph(child, leaf, component, index)
                r.contexts.append((child, leaf, parent, stage, held, value))
                if r.original_rows is None:
                    r.original_rows = {name: (obj, obj.payload, obj.fd) for name, obj in held.items()}
                if fault == 'companion_same_inode_rewrite_after_context' and not r.fault_fired:
                    p = stage / 'scp-source-request.json'; before = p.lstat()
                    try:
                        # Owned same-inode mutation, no unlink/adoption, no
                        # replacement verify result or fabricated authorization.
                        with p.open('r+b') as stream:
                            stream.seek(0); stream.write(b'X'); stream.flush()
                        after = p.lstat()
                        r.same_inode = (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
                        r.fault_fired = True
                    except BaseException as error: r.fault_error = error

        self.assertIsNone(sys.getprofile()); self.assertIsNone(sys.gettrace())
        self.assertIsNone(getattr(threading, 'getprofile', lambda: None)())
        self.assertIsNone(getattr(threading, 'gettrace', lambda: None)())
        try:
            sys.setprofile(observe); threading.setprofile(observe)
            with patch.object(sys, 'stdin', CLI.UnitTTY()), \
                 patch.object(FIXTURE.app.getpass, 'getpass', return_value=SECRET):
                try:
                    r.result = FIXTURE.ThreeComponentWorkflowTests().invoke(root,
                        selection=('--cpld-only',), old_os=False, controlled_grace=True,
                        bridge=RemoteBridge())
                except BaseException as error: r.invoke_error = error
        finally:
            threading.setprofile(None); sys.setprofile(None)
        r.public_records = []
        for channel in r.channels:
            if channel.record.is_file(): r.public_records.append(json.loads(channel.record.read_bytes()))
        r.scp_records = []
        r.nv_records = []
        for name, destination in (('scp.bridge.trace', r.scp_records), ('nv.bridge.trace', r.nv_records)):
            for path in switch.rglob(name):
                destination.extend(json.loads(line) for line in path.read_text().splitlines())
        return r

    def healthy(self, r):
        self.assertIsNone(r.fault_error)
        self.assertIsNone(r.invoke_error, 'fixture/owner failure is not dispatch success')
        self.assertEqual(2, len(r.factories), 'real source before/after hidden prompt')
        self.assertEqual(1, len(r.freezes))
        self.assertTrue(r.signed_probes, 'actual source preflight must complete')
        self.assertTrue(r.dispatches,
            'MISSING_NATIVE_SCP_DISPATCH_CAPABILITY after actual source preflight; manager NOT_REACHED')
        self.assertEqual(1, len(r.dispatches))
        leaf, dispatch = r.dispatches[0]
        self.assertEqual(('cpld', 'DISPATCHED_UNKNOWN'), (dispatch.component, dispatch.state))
        self.assertTrue(r.contexts)
        child, original_leaf, parent, stage, held, raw = r.contexts[0]
        self.assertIs(leaf, original_leaf)
        self.assertIs(child._native_parent, parent)
        self.assertIs(child._package_source_owner, parent._package_source_owner)
        document = json.loads((stage / 'component-dispatch.json').read_bytes())
        self.assertEqual('SCP_STDIN_OWNED_RUNNER_V2', document['launch_kind'])
        self.assertEqual(hashlib.sha256(held['request.json'].payload).hexdigest(), document['request_sha256'])
        self.assertEqual(hashlib.sha256(held['scp-source-request.json'].payload).hexdigest(),
                         document['scp_companion_sha256'])
        self.assertTrue(r.bound, 'real original manager consumer must return normally')
        for bound_leaf, actual_dispatch, values in r.bound:
            self.assertIs(bound_leaf, leaf); self.assertIs(actual_dispatch, dispatch)
            self.assertIs(values[0], child)
            self.assertEqual(stage, values[1].path)
            self.assertEqual(document, values[3])
            for name, (original, payload, _fd) in r.original_rows.items():
                self.assertIs(child.files[(str(stage), name)], original)
                self.assertIs(held[name], original)
                self.assertEqual(payload, original.payload)
        self.assertTrue(any(value.get('child_exit_code') == 93 for value in r.manager))
        self.assertEqual([93], [code for record in r.public_records for code in record['codes']])
        self.assertTrue(all(not record['unknown'] for record in r.public_records))
        self.assertEqual(['source_test@198.51.100.44:' + str(r.root / 'packages/firmware' / BURN),
                          'source_test@198.51.100.44:' + str(r.root / 'packages/firmware' / REFRESH)], r.scp_records)
        self.assertEqual([['action', 'fetch', 'platform', 'firmware', 'CPLD1',
            'file://' + str(r.switch / BURN)]], r.nv_records)
        code, report, error, calls, installs = r.result
        self.assertNotEqual(0, code); self.assertEqual([], installs)
        self.assertFalse(any(command.startswith(('nv config patch ', 'nv config apply', 'nv config save'))
                             for _name, command in calls))
        self.assertEqual('UNKNOWN', report['targets'][0]['state'])
        self.assertFalse(list(r.switch.rglob('download-ack')))
        self.assertTrue(all(channel.process is not None and channel.process.poll() is not None
                            and not channel.unknown for channel in r.channels))
        self.assertTrue(all(channel.close_calls == 1 for channel in r.channels))
        self.assertTrue(child.closed and parent.closed)
        self.assertEqual([], child.cleanup_issues); self.assertEqual([], parent.cleanup_issues)
        self.assertTrue(all(obj.fd is None for obj in held.values()))
        self.secrecy(r)

    def secrecy(self, r):
        if r.invoke_error is None:
            self.assertNotIn(SECRET, r.result[2]); self.assertNotIn(SECRET, repr(r.result[1]))
        for p in r.root.rglob('*'):
            if p.is_file(): self.assertNotIn(SECRET.encode(), p.read_bytes())
        self.assertFalse(list(r.root.rglob('.ibsw-scp-*')))

    @ISOLATION.isolated_whole
    def test_native_cpld_dispatch_retains_originals_and_manager_reads_real_exit_93(self):
        self.healthy(self.exercise())

    @ISOLATION.isolated_whole
    def test_companion_drift_after_context_prevents_secret_send_and_dispatch(self):
        self.healthy(self.exercise())
        r = self.exercise('companion_same_inode_rewrite_after_context')
        self.assertIsNone(r.fault_error)
        self.assertTrue(r.fault_fired); self.assertTrue(r.same_inode)
        self.assertTrue(r.contexts)
        self.assertEqual([], r.dispatches)
        self.assertEqual([], r.scp_records); self.assertEqual([], r.nv_records)
        # Source-probe sends are allowed and must not be mistaken for the new
        # launch secret. A six-argv command is the fixed execution launcher.
        launch_channels = [channel for channel in r.channels
            if len(__import__('shlex').split(channel.command or '')) == 6]
        self.assertTrue(all(channel.send_calls == 0 for channel in launch_channels),
                        'actual remote exec may precede the final original-source send gate')
        self.assertEqual([], [code for record in r.public_records for code in record['codes']],
                         'no owned runner Popen after companion drift')
        child, leaf, parent, stage, held, raw = r.contexts[0]
        self.assertIsInstance(parent._package_source_lifecycle_failure, FIXTURE.driver.SharedUpgradeHold)
        for owner in (parent, child):
            observed = [row for row in r.live_close_verifications if row[0] is owner]
            self.assertEqual(1, len(observed), 'one live original close-entry rejection per owner')
            original_owner, error, marker, before_closed, after_closed, after_marker = observed[0]
            self.assertIs(original_owner, owner)
            self.assertIs(before_closed, False); self.assertIs(after_closed, False)
            self.assertIsInstance(error, FIXTURE.driver.SharedUpgradeHold)
            self.assertIs(error, parent._package_source_lifecycle_failure)
            self.assertIs(marker, parent._package_source_lifecycle_failure)
            self.assertIs(after_marker, marker)
            self.assertTrue(owner.closed, 'original close still ran after the passive live check')
        self.assertTrue((stage / 'request.json').is_file())
        self.assertFalse((stage / 'component-dispatch.json').exists())
        self.assertFalse(list(r.switch.rglob('download-ack')))
        self.assertEqual(1, len(r.freezes), 'no refreeze/re-hash retry')
        self.assertEqual(2, len(r.factories), 'no source refresh/retry')
        if r.invoke_error is None:
            self.assertNotEqual(0, r.result[0]); self.assertEqual([], r.result[4])
        else:
            self.assertIsInstance(r.invoke_error, FIXTURE.driver.SharedUpgradeHold)
        self.secrecy(r)


if __name__ == '__main__': unittest.main()
