"""UNRUN: real native entry/session/source probe, target SDK IO simulated.

Only LocalProbeChannel's private SSH executable seam runs locally. No real
SSH, installer, source permission, request, dispatch or ACK is supplied.
"""
import base64
import dis
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
from types import CodeType, SimpleNamespace
import unittest
from unittest.mock import patch

from test_cases import scp_native_source_preflight_fixture as FIXTURE
from test_cases import test_ibsw3_scp_source_cli_prompt_binding as CLI
from test_cases import test_ibsw3_scp_source_probe_channel as PROTOCOL

SOURCE_SECRET = 'SOURCE-PREFLIGHT-UNIT-ONLY-9e7d'
TARGET_SECRET = 'SYNTHETIC'


class NativeScpSourcePreflightWorkflowTests(unittest.TestCase):
    def capability(self):
        wrapper = getattr(FIXTURE.driver._PreparedRunScope, '_preflight_native_scp_source', None)
        self.assertTrue(callable(wrapper),
            'MISSING_NATIVE_SOURCE_PREFLIGHT_CAPABILITY; signed session/probe/stdin=NOT_REACHED')
        self.assertEqual(('self', 'leaf', 'component', 'package_index', 'transport', 'deadline'),
                         tuple(inspect.signature(wrapper).parameters))
        return wrapper

    def exercise(self, wrapper, drift=False):
        provider = importlib.import_module('ibsw_upgrade_scp')
        scope_type = FIXTURE.driver._PreparedRunScope
        factory, bind = provider.source_from_known_hosts, scope_type._bind_scp_source
        getter, freeze = scope_type._native_scp_source, scope_type.freeze_scp_package_sources
        probe = provider._probe_source_channel
        single = FIXTURE.observer._signed_session_single.__wrapped__
        outer = FIXTURE.observer._signed_session.__wrapped__
        execute = FIXTURE.executor._execute_component_once
        leaf_verify, source_verify = FIXTURE.driver._ReadonlyQueryInputs.verify, provider.ScpSource.verify
        authority_entries = tuple(getattr(scope_type, name) for name in (
            '_prepare_requested_step_locked', '_request_prepared_step_locked',
            '_publish_requested_step_locked', '_write_os_dispatch_data_locked'))
        factory_codes = [c for c in FIXTURE.ThreeComponentWorkflowTests.invoke.__code__.co_consts
                         if type(c) is CodeType and c.co_name == 'transport_factory']
        self.assertEqual(1, len(factory_codes), 'one unchanged nested test-owned SDK factory')
        sdk_factory_code = factory_codes[0]
        state = dict(factory_calls=[], sources=[], binds=[], freezes=[], channels=[], wrappers=[],
                     probes=[], getter_returns=[], sdk=[], environment_clean=[], source_tail=0, leaf_tail=0,
                     authority_calls=[])
        active_sessions, active_outer, active_wrappers, traced = {}, {}, {}, {}
        missing = object()
        self.assertIsNone(sys.getprofile()); self.assertIsNone(sys.gettrace())
        # threading.getprofile()/gettrace() are 3.10+; on 3.9 they are read from the hooks threading.setprofile()/settrace() store.
        self.assertIsNone(getattr(threading, 'getprofile', lambda: threading._profile_hook)())
        self.assertIsNone(getattr(threading, 'gettrace', lambda: threading._trace_hook)())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            trust = root / 'scp-source-known_hosts'
            trust.write_bytes(CLI.known_line(17)); trust.chmod(0o600)
            state['trust_before'] = (trust.lstat().st_ino, trust.read_bytes())
            ssh, events = root / 'private-ssh-stub', root / 'public-probe-events'
            # This synthetic fixture contains only a credential digest, not
            # source plaintext. It validates exact public endpoint/pin/options.
            ssh.write_text('#!/usr/bin/python3\nimport hashlib,os,stat,sys\nfrom pathlib import Path\n'
                'a=sys.argv[1:]\n'
                'if a[:2]!=["-F","/dev/null"] or a[-4:]!=["-p","2222","source_test@198.51.100.44","/bin/true"]: raise SystemExit(91)\n'
                'for flag in ("StrictHostKeyChecking=yes","GlobalKnownHostsFile=/dev/null","UpdateHostKeys=no","IdentitiesOnly=yes","ConnectionAttempts=1","NumberOfPasswordPrompts=1","PreferredAuthentications=publickey,password"):\n'
                ' if flag not in a: raise SystemExit(92)\n'
                'pins=[v.split("=",1)[1] for v in a if v.startswith("UserKnownHostsFile=")]\n'
                'if len(pins)!=1: raise SystemExit(93)\n'
                'p=Path(pins[0])\n'
                'if p.read_bytes()!='+repr(CLI.known_line(17))+' or stat.S_IMODE(p.stat().st_mode)!=0o600: raise SystemExit(94)\n'
                'sys.stdout.write("Password: ");sys.stdout.flush()\n'
                'value=sys.stdin.readline().rstrip("\\n")\n'
                'if hashlib.sha256(value.encode()).hexdigest()!='+repr(hashlib.sha256(SOURCE_SECRET.encode()).hexdigest())+': raise SystemExit(95)\n'
                'if any(value in item for item in a) or any(value in item for item in os.environ.values()): raise SystemExit(96)\n'
                'Path('+repr(str(events))+').write_text("SSH_CURRENT_PIN_AND_STDIN\\n")\n'
                'print(value)\n')
            ssh.chmod(0o700)

            class Channel(PROTOCOL.LocalProbeChannel):
                def __init__(self):
                    super().__init__(root, ssh)
                    self.events = []; self.command = None; self.trust_mutated = False
                def exec_command(self, command):
                    self.command = command; self.events.append('exec')
                    super().exec_command(command)  # Actual generated Python/helper child.
                    if drift:
                        trust.write_bytes(CLI.known_line(34))
                        self.trust_mutated = True
                def send(self, value):
                    self.events.append('send'); return super().send(value)
                def shutdown_write(self):
                    self.events.append('shutdown'); return super().shutdown_write()
                def recv_exit_status(self):
                    value = super().recv_exit_status(); self.events.append('status'); return value
                def close(self):
                    self.events.append('close'); return super().close()

            def normal_return(frame):
                return (frame.f_lasti >= 0 and dis.opname[frame.f_code.co_code[frame.f_lasti]]
                        in ('RETURN_VALUE', 'RETURN_CONST'))

            def observe(frame, event, argument):
                code, namespace = frame.f_code, frame.f_globals
                if event == 'call' and any(code is f.__code__ and namespace is f.__globals__ for f in authority_entries):
                    state['authority_calls'].append(code.co_name)
                elif code is sdk_factory_code and namespace is FIXTURE.ThreeComponentWorkflowTests.invoke.__globals__:
                    if event == 'return' and normal_return(frame) and type(argument) is SimpleNamespace:
                        transport = argument
                        state['sdk'].append(transport)
                        def open_session(*, timeout):
                            channel = Channel()
                            channel.original_transport, channel.open_timeout = transport, timeout
                            state['channels'].append(channel)
                            return channel
                        # Only the original test-owned SDK instance's channel IO
                        # seam. Its factory/auth/identity/close remain unchanged.
                        transport.open_session = open_session
                elif code is factory.__code__ and namespace is factory.__globals__:
                    if event == 'call': state['factory_calls'].append(bool(state['channels']))
                    elif event == 'return' and argument is not None: state['sources'].append(argument)
                elif code is bind.__code__ and namespace is bind.__globals__:
                    if event == 'return' and normal_return(frame):
                        state['binds'].append((frame.f_locals['self'], frame.f_locals['source']))
                elif code is freeze.__code__ and namespace is freeze.__globals__:
                    if event == 'return' and argument is not None:
                        state['freezes'].append((frame.f_locals['self'], argument))
                elif code is getter.__code__ and namespace is getter.__globals__:
                    if event == 'return' and normal_return(frame): state['getter_returns'].append(argument)
                elif ((code is single.__code__ and namespace is single.__globals__)
                      or (code is outer.__code__ and namespace is outer.__globals__)):
                    selected = active_sessions if code is single.__code__ else active_outer
                    if event == 'call':
                        for key in [k for k, v in selected.items() if v['frame'] == id(frame)]:
                            del selected[key]
                    elif event == 'return' and type(argument) is tuple and len(argument) == 5:
                        selected[id(argument[0])] = dict(frame=id(frame), leaf=frame.f_locals['leaf'],
                            transport=argument[0], deadline=argument[1], identity=argument[2],
                            authentication=argument[3], fingerprint=argument[4],
                            entered=frame.f_locals.get('operation_entered'))
                elif (code is PROTOCOL.LocalProbeChannel.exec_command.__code__
                      and namespace is PROTOCOL.LocalProbeChannel.exec_command.__globals__
                      and event == 'return' and normal_return(frame)):
                    environment = frame.f_locals['environment']
                    state['environment_clean'].append(not any(SOURCE_SECRET in value for value in environment.values()))
                elif state['channels'] and state['channels'][-1].close_calls:
                    if (code is source_verify.__code__ and namespace is source_verify.__globals__
                            and event == 'call' and state['binds']
                            and frame.f_locals.get('self') is state['binds'][0][1]): state['source_tail'] += 1
                    elif (code is leaf_verify.__code__ and namespace is leaf_verify.__globals__
                          and event == 'call' and state['wrappers']
                          and frame.f_locals.get('self') is state['wrappers'][0]['leaf']): state['leaf_tail'] += 1

            def trace(frame, event, argument):
                code, namespace = frame.f_code, frame.f_globals
                is_wrapper = code is wrapper.__code__ and namespace is wrapper.__globals__
                is_probe = code is probe.__code__ and namespace is probe.__globals__
                if not is_wrapper and not is_probe: return None
                tid = threading.get_ident()
                if event == 'call':
                    if is_wrapper:
                        child, leaf = frame.f_locals['self'], frame.f_locals['leaf']
                        transport = frame.f_locals['transport']; parent = child._native_parent
                        caller = frame.f_back
                        row = dict(child=child, leaf=leaf, parent=parent, transport=transport,
                            deadline=frame.f_locals['deadline'], component=frame.f_locals['component'],
                            index=frame.f_locals['package_index'], session=active_sessions.get(id(transport)),
                            outer=active_outer.get(id(transport)),
                            controls=(type(child) is scope_type, type(parent) is scope_type,
                                type(leaf) is FIXTURE.driver._ReadonlyQueryInputs, leaf.scope is child,
                                leaf._original_selection[0] is child, child._package_source_parent is parent,
                                child._package_source_owner is parent._package_source_owner,
                                child._package_source_selection is parent._package_source_selection,
                                child in parent._package_source_borrowers,
                                caller.f_code is execute.__code__, caller.f_globals is execute.__globals__),
                            returned=missing, normal=None, errors=[])
                        state['wrappers'].append(row); active_wrappers[tid] = row
                    else:
                        caller = frame.f_back
                        row = dict(leaf=frame.f_locals['leaf'], source=frame.f_locals['source'],
                            transport=frame.f_locals['transport'], wrapper=active_wrappers.get(tid),
                            direct=(caller.f_code is wrapper.__code__, caller.f_globals is wrapper.__globals__),
                            returned=missing, normal=None, errors=[])
                        state['probes'].append(row)
                    traced[id(frame)] = row
                elif event == 'exception': traced[id(frame)]['errors'].append(argument[1])
                elif event == 'return':
                    traced[id(frame)]['returned'] = argument
                    traced[id(frame)]['normal'] = normal_return(frame)
                    if is_wrapper: active_wrappers.pop(tid, None)
                return trace

            try:
                sys.setprofile(observe); threading.setprofile(observe)
                sys.settrace(trace); threading.settrace(trace)
                with patch.object(sys, 'stdin', CLI.UnitTTY()), \
                     patch.object(FIXTURE.app.getpass, 'getpass', return_value=SOURCE_SECRET):
                    state['result'] = FIXTURE.ThreeComponentWorkflowTests().invoke(
                        root, selection=('--os-only',), controlled_grace=True,
                        prewrite_query_timeout='nv show system version')
            finally:
                threading.settrace(None); sys.settrace(None)
                threading.setprofile(None); sys.setprofile(None)
                for channel in state['channels']: channel.cleanup_owned()
            state['trust_after'] = (trust.lstat().st_ino, trust.read_bytes())
            state['ssh_events'] = events.read_text() if events.exists() else None
            state['leftover_helpers'] = [p.name for p in root.glob('.ibsw-scp-*')]
        return state

    def assert_real_probe_chain(self, state):
        self.assertEqual([False, False], state['factory_calls'], 'no source factory refresh after open')
        self.assertEqual(2, len(state['sources'])); self.assertEqual(1, len(state['binds']))
        parent, source = state['binds'][0]
        self.assertIs(source, state['sources'][1])
        self.assertEqual(1, len(state['wrappers'])); self.assertEqual(1, len(state['probes']))
        self.assertEqual(1, len(state['channels']))
        row, probe, channel = state['wrappers'][0], state['probes'][0], state['channels'][0]
        self.assertTrue(all(row['controls'])); self.assertIs(parent, row['parent'])
        self.assertEqual(('os', 1), (row['component'], row['index']))
        self.assertTrue(any(p is parent and owner is row['child']._package_source_owner for p, owner in state['freezes']))
        self.assertTrue(any(value is source for value in state['getter_returns']))
        self.assertTrue(all(probe['direct'])); self.assertIs(row, probe['wrapper'])
        self.assertIs(source, probe['source']); self.assertIs(row['leaf'], probe['leaf'])
        self.assertIs(row['transport'], probe['transport']); self.assertIs(row['transport'], channel.original_transport)
        signed = row['session']; self.assertIsNotNone(signed, 'real signed session is suspended at its authenticated yield')
        self.assertIsNotNone(row['outer'], 'real original _signed_session must also remain suspended')
        self.assertIs(row['leaf'], row['outer']['leaf']); self.assertIs(row['transport'], row['outer']['transport'])
        self.assertTrue(signed['entered']); self.assertIs(row['leaf'], signed['leaf'])
        self.assertIs(row['transport'], signed['transport']); self.assertEqual('publickey', signed['authentication'])
        expected_pin = 'SHA256:' + base64.b64encode(hashlib.sha256(FIXTURE.trust.WIRE).digest()).rstrip(b'=').decode()
        self.assertEqual(expected_pin, signed['fingerprint'])
        self.assertEqual((row['leaf'].node.hostname+'\n'+row['leaf'].node.mac+'\n').encode(), signed['identity'][0])
        self.assertEqual((b'', 0, True), signed['identity'][1:])
        self.assertGreater(channel.open_timeout, 0)
        self.assertEqual(1, channel.close_calls); self.assertIsNotNone(channel.process.returncode)
        self.assertTrue(all(handle.closed for handle in (channel.process.stdin, channel.process.stdout, channel.process.stderr)))
        self.assertGreaterEqual(state['source_tail'], 1); self.assertGreaterEqual(state['leaf_tail'], 1)
        self.assertEqual([True], state['environment_clean'])
        self.assertNotIn(SOURCE_SECRET, channel.command)
        self.assertFalse(any(SOURCE_SECRET in value for value in channel.process.args))
        code, report, error, calls, installs = state['result']
        self.assertNotEqual(0, code, 'probe None is not native backend permission')
        self.assertEqual([], installs)
        self.assertEqual([], state['authority_calls'], 'no original request/publish/OS dispatch entry')
        self.assertNotIn(SOURCE_SECRET, error + repr(report))
        self.assertEqual([], state['leftover_helpers'])

    def test_real_native_session_sends_only_source_secret_to_actual_probe_helper_then_holds(self):
        state = self.exercise(self.capability())
        self.assert_real_probe_chain(state)
        wrapper, probe, channel = state['wrappers'][0], state['probes'][0], state['channels'][0]
        for row in (wrapper, probe):
            self.assertTrue(row['normal']); self.assertIsNone(row['returned']); self.assertEqual([], row['errors'])
        self.assertEqual('SSH_CURRENT_PIN_AND_STDIN\n', state['ssh_events'])
        self.assertEqual(0, channel.process.returncode)
        self.assertGreater(channel.send_calls, 1)
        self.assertLess(channel.events.index('exec'), channel.events.index('send'))
        self.assertLess(channel.events.index('send'), channel.events.index('shutdown'))
        self.assertLess(channel.events.index('shutdown'), channel.events.index('status'))
        self.assertLess(channel.events.index('status'), channel.events.index('close'))
        context = json.loads(bytes(channel.sent))
        self.assertEqual({'host', 'user', 'port', 'host_keys', 'password', 'paths', 'timeout_seconds'}, set(context))
        self.assertEqual(('198.51.100.44', 'source_test', 2222), (context['host'], context['user'], context['port']))
        self.assertEqual(CLI.known_line(17), context['host_keys'].encode())
        self.assertTrue(context['password'] == SOURCE_SECRET)
        self.assertNotIn(TARGET_SECRET.encode(), bytes(channel.sent))
        self.assertEqual({}, context['paths']); self.assertGreater(context['timeout_seconds'], 0)
        self.assertLessEqual(context['timeout_seconds'], 20)
        self.assertEqual(state['trust_before'], state['trust_after'])

    def test_trust_changes_after_actual_exec_before_first_send_is_shared_sticky_without_refresh(self):
        state = self.exercise(self.capability(), drift=True)
        self.assert_real_probe_chain(state)
        channel = state['channels'][0]
        self.assertTrue(channel.trust_mutated)
        self.assertEqual(0, channel.send_calls); self.assertEqual(b'', bytes(channel.sent))
        self.assertEqual(['exec', 'close'], channel.events)
        self.assertIsNone(state['ssh_events'], 'no source authentication child before current trust check')
        self.assertEqual(state['trust_before'][0], state['trust_after'][0])
        self.assertEqual(CLI.known_line(17), state['trust_before'][1])
        self.assertEqual(CLI.known_line(34), state['trust_after'][1])
        for row in (state['probes'][0], state['wrappers'][0]):
            self.assertFalse(row['normal']); self.assertIsNone(row['returned'])
            self.assertTrue(any(isinstance(error, FIXTURE.driver.SharedUpgradeHold) for error in row['errors']))
        self.assertIsInstance(state['binds'][0][0]._package_source_lifecycle_failure, FIXTURE.driver.SharedUpgradeHold)
