"""UNRUN capability SOURCE; not a legal SCP download/dispatch/ACK proof.

Baseline must fail at the explicit CLI capability assertion, before graph IO.
The copied fixture submits real --method scp to real main; no HTTP relabeling.
"""
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from test_cases import scp_source_cli_fixture as SCP
from test_cases import test_ibsw3_scp_source_cli_prompt_binding as CLI
from test_cases import test_ibsw225_three_component_workflow as HTTP


class NativeScpCliBorrowCapabilityTests(unittest.TestCase):
    def require_natural_scp_cli(self):
        argv = ('--project', '/SYNTHETIC-CLI-ONLY/project', '--os-only',
                '--method', 'scp', '--package-dir', '/SYNTHETIC-CLI-ONLY/packages',
                '--known-hosts', '/SYNTHETIC-CLI-ONLY/known_hosts',
                '--upgrade', '--yes')
        try:
            parsed = SCP.app._parse_cli(argv)
        except SCP.app._InspectionHold:
            self.fail('MISSING_NATIVE_SCP_CLI_CAPABILITY; '
                      'factory/parent/NativeAdapter/dispatch/ACK=NOT_REACHED')
        self.assertEqual('scp', parsed.method)
        self.assertIn('--os-only', parsed.prepare_args)
        self.assertEqual('scp', parsed.prepare_args[parsed.prepare_args.index('--method') + 1])
        self.assertNotIn('--known-hosts', parsed.prepare_args)
        return parsed

    def test_natural_cli_explicit_scp_is_not_relabelled_as_http(self):
        self.require_natural_scp_cli()

    def test_natural_main_retains_factory_parent_and_native_adapter_borrow(self):
        # This preliminary call is only a fail-explicit capability guard; the
        # actual workflow below creates its own real project and calls main.
        self.require_natural_scp_cli()
        self.assertIsNone(sys.getprofile(), 'refuse an existing interpreter profiler')
        # threading.getprofile()/gettrace() are 3.10+; on 3.9 they are read from the hooks threading.setprofile()/settrace() store.
        self.assertIsNone(getattr(threading, 'getprofile', lambda: threading._profile_hook)(), 'refuse an existing thread profiler')
        scope_type = SCP.driver._PreparedRunScope
        freeze = scope_type.freeze_scp_package_sources
        # Optional fixed native API: do not mask the earlier natural CLI FAIL.
        fork = getattr(scope_type, 'fork_native_component_scope', None)
        begin = SCP.pipeline.NativeAdapter.begin
        active = {}
        freezes, borrows = [], []

        def observe(frame, event, argument):
            # Passive exact code+globals witness, never substitutes a factory,
            # verifier, next_step, result or production callback.
            code, globals_ = frame.f_code, frame.f_globals
            tid = threading.get_ident()
            if code is begin.__code__ and globals_ is begin.__globals__:
                if event == 'call':
                    active[tid] = frame.f_locals['self']
                elif event == 'return':
                    active.pop(tid, None)
            elif (code is freeze.__code__ and globals_ is freeze.__globals__
                  and event == 'return' and argument is not None):
                freezes.append((frame.f_locals['self'], argument))
            elif (fork is not None and code is fork.__code__ and globals_ is fork.__globals__
                  and event == 'return' and type(argument) is scope_type
                  and tid in active):
                parent = frame.f_locals['self']
                borrows.append((active[tid], parent, argument,
                                getattr(argument, '_native_parent', None),
                                getattr(argument, '_package_source_parent', None),
                                parent._package_source_owner,
                                argument._package_source_owner,
                                parent._native_schedule_started,
                                argument._native_schedule_started,
                                argument in parent._package_source_borrowers))

        fixture = SCP.ThreeComponentWorkflowTests()
        try:
            sys.setprofile(observe)
            threading.setprofile(observe)
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve()
                trust = root/'scp-source-known_hosts'
                trust.write_bytes(CLI.known_line(17))
                trust.chmod(0o600)
                # UNIT credential input only; no factory/verifier substitute.
                with patch.object(sys, 'stdin', CLI.UnitTTY()), \
                     patch.object(SCP.app.getpass, 'getpass',
                                  return_value=CLI.SECRET) as prompt:
                    code, report, err, calls, installs = fixture.invoke(
                        root, selection=('--os-only',), controlled_grace=True)
                self.assertEqual(1, prompt.call_count)
        finally:
            threading.setprofile(None)
            sys.setprofile(None)
        self.assertTrue(freezes, 'NOT_REACHED: original SCP factory/parent freeze')
        self.assertTrue(borrows, 'NOT_REACHED: NativeAdapter.begin fixed '
                        'fork_native_component_scope original-parent borrow')
        for (adapter, parent, child, native_parent, source_parent, owner, child_owner,
             parent_native, child_native, registered_borrow) in borrows:
            self.assertIs(parent, adapter.parent)
            self.assertIs(parent, native_parent)
            self.assertTrue(parent_native)
            self.assertTrue(child_native)
            self.assertTrue(registered_borrow)
            self.assertIs(parent, source_parent)
            self.assertIsNotNone(owner)
            self.assertIs(owner, child_owner)
            self.assertTrue(any(p is parent and o is owner for p, o in freezes))
            self.assertIsNot(parent, child)
        # This slice supplies only UNIT credential input, no SCP wire or launch implementation.
        # Reaching real borrow must not be confused with native completion.
        self.assertEqual([], installs, 'borrow capability is not SCP launch authority')
        self.assertNotEqual(0, code, 'this no-wire fixture must not report upgrade success')

    def test_existing_http_entry_still_uses_actual_normal_workflow(self):
        fixture = HTTP.ThreeComponentWorkflowTests()
        with tempfile.TemporaryDirectory() as raw:
            code, report, err, calls, installs = fixture.invoke(
                Path(raw).resolve(), selection=('--os-only',), controlled_grace=True)
        self.assertEqual(0, code, err)
        self.assertEqual(['os'], [row[1] for row in installs])
