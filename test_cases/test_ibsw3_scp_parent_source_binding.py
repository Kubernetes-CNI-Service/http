"""UNRUN: actual entry -> native borrower -> source getter, still backend HOLD.

Target IO/getpass are the existing explicit fixture seams. No test invokes the
new bind/getter, constructs a bound source, or substitutes a verifier/result.
"""
import dis
import importlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from test_cases import scp_source_cli_fixture as FIXTURE
from test_cases import test_ibsw3_scp_source_cli_prompt_binding as CLI


class ScpParentSourceBindingTests(unittest.TestCase):
    def capabilities(self):
        scope = FIXTURE.driver._PreparedRunScope
        for name in ('_bind_scp_source', '_native_scp_source'):
            self.assertTrue(callable(getattr(scope, name, None)),
                'MISSING_PARENT_SOURCE_BINDING_CAPABILITY; native getter/probe/dispatch=NOT_REACHED: ' + name)
        return scope._bind_scp_source, scope._native_scp_source

    def exercise(self, bind, getter, fault=None):
        provider = importlib.import_module('ibsw_upgrade_scp')
        factory = provider.source_from_known_hosts
        api = FIXTURE.driver._fixed_scp_source_api
        scope_type = FIXTURE.driver._PreparedRunScope
        freeze = scope_type.freeze_scp_package_sources
        package_factory = provider.package_content_owner
        begin = FIXTURE.pipeline.NativeAdapter.begin
        execute = FIXTURE.executor._execute_component_once
        # The new fixed preflight boundary is also a legitimate direct
        # consumer. Keep recording every getter; never hide unknown callers.
        preflight = getattr(scope_type, '_preflight_native_scp_source', None)
        state = dict(factory_calls=[], factory_returns=[], apis=[], binds=[], getters=[],
                     freezes=[], package_factories=0, chunks=[], read_errors=[], fault=None)
        active = {}
        real_read, real_fstat = os.read, os.fstat
        self.assertIsNone(sys.getprofile())
        # threading.getprofile()/gettrace() are 3.10+; on 3.9 they are read from the hooks threading.setprofile()/settrace() store.
        self.assertIsNone(getattr(threading, 'getprofile', lambda: threading._profile_hook)())
        self.assertIsNone(sys.gettrace())
        self.assertIsNone(getattr(threading, 'gettrace', lambda: threading._trace_hook)())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            trust = root / 'scp-source-known_hosts'
            trust.write_bytes(CLI.known_line(17))
            trust.chmod(0o600)
            package = root / 'packages/image/nvos-amd64-25.03.1010.bin'
            missing = object()
            restore = []

            def normal_return(frame):
                return (frame.f_lasti >= 0 and dis.opname[frame.f_code.co_code[frame.f_lasti]]
                        in ('RETURN_VALUE', 'RETURN_CONST'))

            def observe(frame, event, argument):
                code, namespace = frame.f_code, frame.f_globals
                tid = threading.get_ident()
                if code is factory.__code__ and namespace is factory.__globals__:
                    if event == 'call': state['factory_calls'].append(state['fault'] is not None)
                    elif event == 'return' and argument is not None:
                        state['factory_returns'].append(argument)
                elif (code is api.__code__ and namespace is api.__globals__
                      and event == 'return' and type(argument) is tuple):
                    state['apis'].append(argument)
                elif code is begin.__code__ and namespace is begin.__globals__:
                    if event == 'call': active[tid] = frame.f_locals['self']
                    elif event == 'return': active.pop(tid, None)
                elif code is freeze.__code__ and namespace is freeze.__globals__:
                    if event == 'call':
                        info = package.lstat()
                        state['package_key'] = (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
                    elif event == 'return' and argument is not None:
                        state['freezes'].append((frame.f_locals['self'], argument))
                elif (code is package_factory.__code__ and namespace is package_factory.__globals__
                      and event == 'call'):
                    state['package_factories'] += 1
                elif (code is bind.__code__ and namespace is bind.__globals__
                      and event == 'return' and normal_return(frame)):
                    parent, source, joint = (frame.f_locals[name] for name in ('self', 'source', 'api'))
                    row = dict(parent=parent, source=source, joint=joint,
                               slot_same=getattr(parent, '_scp_source', None) is source)
                    state['binds'].append(row)
                    # Only the first confirmed normal bind return is the fault
                    # seam. No test calls a production getter/validator here.
                    if fault is not None and state['fault'] is None:
                        if fault == 'parent_slot':
                            old = getattr(parent, '_scp_source', missing)
                            restore.append(('slot', parent, old))
                            replacement = state['factory_returns'][0]
                            parent._scp_source = replacement
                            state['fault'] = dict(kind=fault, replacement=replacement,
                                                  source=source, parent=parent)
                        elif fault == 'host_field':
                            old = source.host
                            restore.append(('host', source, old))
                            object.__setattr__(source, 'host', '203.0.113.99')
                            state['fault'] = dict(kind=fault, source=source, parent=parent)

            def trace(frame, event, argument):
                if frame.f_code is not getter.__code__ or frame.f_globals is not getter.__globals__:
                    return None
                if event == 'call':
                    child, leaf = frame.f_locals['self'], frame.f_locals['leaf']
                    parent = getattr(child, '_native_parent', None)
                    caller = frame.f_back
                    row = dict(child=child, leaf=leaf, parent=parent,
                        component=frame.f_locals['component'], index=frame.f_locals['package_index'],
                        adapter=active.get(threading.get_ident()), owner=child._package_source_owner,
                        slot=getattr(parent, '_scp_source', None), host=getattr(getattr(parent, '_scp_source', None), 'host', None),
                        controls=(type(child) is scope_type, type(parent) is scope_type,
                            type(leaf) is FIXTURE.driver._ReadonlyQueryInputs, leaf.scope is child,
                            leaf._original_selection[0] is child,
                            child._package_source_parent is parent,
                            child._package_source_owner is parent._package_source_owner,
                            child._package_source_selection is parent._package_source_selection,
                            child in parent._package_source_borrowers,
                            parent._native_schedule_started, child._native_schedule_started,
                            ((caller.f_code is execute.__code__ and caller.f_globals is execute.__globals__)
                             or (preflight is not None and caller.f_code is preflight.__code__
                                 and caller.f_globals is preflight.__globals__))),
                        returned=missing, normal_return=None, exceptions=[])
                    state['getters'].append(row)
                    frame_rows[id(frame)] = row
                elif event == 'exception':
                    frame_rows[id(frame)]['exceptions'].append(argument[1])
                elif event == 'return':
                    frame_rows[id(frame)]['returned'] = argument
                    frame_rows[id(frame)]['normal_return'] = normal_return(frame)
                return trace

            def reading(fd, count):
                data = real_read(fd, count)  # Never substitutes an IO result.
                if state.get('package_key') is not None:
                    try:
                        info = real_fstat(fd)
                    except OSError as error:
                        state['read_errors'].append(type(error).__name__)
                    else:
                        if (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)) == state['package_key']:
                            state['chunks'].append(data)
                return data

            frame_rows = {}
            try:
                sys.setprofile(observe); threading.setprofile(observe)
                sys.settrace(trace); threading.settrace(trace)
                with patch.object(sys, 'stdin', CLI.UnitTTY()), \
                     patch.object(FIXTURE.app.getpass, 'getpass', return_value=CLI.SECRET), \
                     patch.object(os, 'read', reading):
                    state['result'] = FIXTURE.ThreeComponentWorkflowTests().invoke(
                        root, selection=('--os-only',), controlled_grace=True)
            finally:
                threading.settrace(None); sys.settrace(None)
                threading.setprofile(None); sys.setprofile(None)
                # Restore only explicit test-owned memory faults, after the
                # actual flow/owner cleanup returned. Never clear group poison,
                # repair evidence, retry a native action or manipulate an FD.
                for kind, target, original in reversed(restore):
                    if kind == 'slot':
                        if original is missing: delattr(target, '_scp_source')
                        else: target._scp_source = original
                    else: object.__setattr__(target, 'host', original)
        return state

    def assert_real_chain(self, state):
        self.assertEqual(1, len(state['binds']), 'one actual parent binding; no refresh')
        self.assertEqual(2, len(state['factory_calls']))
        self.assertEqual(2, len(state['factory_returns']))
        bound = state['binds'][0]
        self.assertTrue(bound['slot_same'])
        self.assertIs(bound['source'], state['factory_returns'][1])
        self.assertEqual(19, len(bound['joint']))
        self.assertTrue(any(bound['joint'] is joint for joint in state['apis']))
        self.assertTrue(state['getters'], 'NOT_REACHED: real executor source consumer')
        self.assertEqual(1, state['package_factories'])
        for row in state['getters']:
            self.assertTrue(all(row['controls']), 'original leaf/borrow/owner/executor chain')
            self.assertIs(row['parent'], bound['parent'])
            self.assertIsNot(row['child'], row['parent'])
            self.assertIsNotNone(row['adapter'])
            self.assertIs(row['adapter'].parent, row['parent'])
            self.assertTrue(any(parent is row['parent'] and owner is row['owner']
                                for parent, owner in state['freezes']))
            self.assertEqual(('os', 1), (row['component'], row['index']))
        code, report, error, calls, installs = state['result']
        self.assertEqual([], installs, 'binding/getter is not secret wire or installation')
        self.assertNotEqual(0, code, 'the real SCP backend remains HOLD')
        self.assertNotIn(CLI.SECRET, error + repr(report))
        self.assertIsNone(sys.getprofile()); self.assertIsNone(sys.gettrace())

    def test_actual_parent_bind_and_native_executor_get_same_original_without_rehash(self):
        bind, getter = self.capabilities()
        state = self.exercise(bind, getter)
        self.assert_real_chain(state)
        source = state['binds'][0]['source']
        for row in state['getters']:
            self.assertIs(source, row['slot'])
            self.assertIs(source, row['returned'])
            self.assertTrue(row['normal_return'])
            self.assertEqual([], row['exceptions'])
        self.assertEqual([], state['read_errors'])
        self.assertEqual([b'SYNTHETIC-NOT-FIRMWARE', b''], state['chunks'],
                         'one original needed-package digest pass, no getter rehash')

    def test_post_bind_same_class_slot_or_field_drift_is_shared_sticky_before_backend(self):
        bind, getter = self.capabilities()
        for fault in ('parent_slot', 'host_field'):
            with self.subTest(fault=fault):
                state = self.exercise(bind, getter, fault)
                self.assert_real_chain(state)
                self.assertIsNotNone(state['fault'], 'NOT_REACHED: normal bind-return fault seam')
                self.assertEqual([False, False], state['factory_calls'], 'no factory refresh after fault')
                bound = state['binds'][0]
                if fault == 'parent_slot':
                    self.assertIs(state['fault']['replacement'], state['factory_returns'][0])
                    self.assertIsNot(state['fault']['replacement'], bound['source'])
                for row in state['getters']:
                    if fault == 'parent_slot': self.assertIs(row['slot'], state['factory_returns'][0])
                    else:
                        self.assertIs(row['slot'], bound['source'])
                        self.assertEqual('203.0.113.99', row['host'])
                    self.assertIsNone(row['returned'])
                    self.assertFalse(row['normal_return'], 'caught HOLD plus normal return is not refusal')
                    self.assertTrue(any(isinstance(error, FIXTURE.driver.SharedUpgradeHold)
                                        for error in row['exceptions']),
                                    'getter itself must raise shared HOLD, not just later backend refusal')
                self.assertIsInstance(bound['parent']._package_source_lifecycle_failure,
                                      FIXTURE.driver.SharedUpgradeHold, 'original group stays poisoned')
