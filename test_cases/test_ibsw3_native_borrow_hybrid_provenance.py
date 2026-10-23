"""Independent real native child fault injection; no fabricated source authority.

Same three subcases test one native/readiness mutual-exclusion boundary.
Real main and NativeAdapter must first produce the original native child.
No network/device: existing fixture IO substitutes; no launch wire or ACK.
"""
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from test_cases import scp_source_cli_fixture as SCP
from test_cases import test_ibsw3_scp_source_cli_prompt_binding as CLI


class NativeBorrowHybridProvenanceTests(unittest.TestCase):
    def test_real_native_child_cannot_fall_back_to_readiness_provenance(self):
        scope_type = SCP.driver._PreparedRunScope
        fork = getattr(scope_type, 'fork_native_component_scope', None)
        self.assertIsNotNone(fork, 'CAPABILITY_NOT_REACHED: no real native fork')
        self.assertIsNone(sys.getprofile())
        # threading.getprofile()/gettrace() are 3.10+; on 3.9 they are read from the hooks threading.setprofile()/settrace() store.
        self.assertIsNone(getattr(threading, 'getprofile', lambda: threading._profile_hook)())
        for fault in ('readiness_fields_only', 'wrong_native_component', 'wrong_native_indices'):
            with self.subTest(fault=fault):
                seen = []
                sentinel = object()

                def observe(frame, event, argument):
                    if (event != 'return' or frame.f_code is not fork.__code__
                            or frame.f_globals is not fork.__globals__
                            or type(argument) is not scope_type):
                        return
                    child, parent = argument, frame.f_locals['self']
                    # A real unmodified child must already satisfy the original
                    # verifier. Do not turn early failure into a rejection PASS.
                    child._verify_package_source_owner()
                    control = (child._native_parent is parent,
                               child._package_source_parent is parent,
                               child._package_source_owner is parent._package_source_owner,
                               child in parent._package_source_borrowers,
                               child._native_schedule_started,
                               parent._native_schedule_started)
                    names = ('_readiness_parent', '_readiness_node',
                             '_native_component', '_native_package_indices')
                    old = {name: getattr(child, name, sentinel) for name in names}
                    outcome = None
                    try:
                        child._readiness_parent = parent
                        child._readiness_node = child._native_node
                        if fault == 'wrong_native_component':
                            child._native_component = 'NOT-A-SELECTED-COMPONENT'
                        elif fault == 'wrong_native_indices':
                            child._native_package_indices = (-123,)
                        try:
                            child._verify_package_source_owner()
                        except SCP.driver.SharedUpgradeHold as exc:
                            outcome = exc
                    finally:
                        # Restore only the explicit test fault; never repair a
                        # real owner failure, descriptor, record or poison.
                        for name, value in old.items():
                            if value is sentinel:
                                if hasattr(child, name):
                                    delattr(child, name)
                            else:
                                setattr(child, name, value)
                    seen.append((control, outcome))

                try:
                    sys.setprofile(observe)
                    threading.setprofile(observe)
                    with tempfile.TemporaryDirectory() as raw:
                        root = Path(raw).resolve()
                        trust = root/'scp-source-known_hosts'
                        trust.write_bytes(CLI.known_line(17))
                        trust.chmod(0o600)
                        # UNIT credential input only; factory and verification
                        # remain the real source fixture's production calls.
                        with patch.object(sys, 'stdin', CLI.UnitTTY()), \
                             patch.object(SCP.app.getpass, 'getpass',
                                          return_value=CLI.SECRET) as prompt:
                            code, report, err, calls, installs = SCP.ThreeComponentWorkflowTests().invoke(
                                root, selection=('--os-only',), controlled_grace=True)
                        self.assertEqual(1, prompt.call_count)
                finally:
                    threading.setprofile(None)
                    sys.setprofile(None)
                self.assertTrue(seen, 'NOT_REACHED: no original native child')
                for control, outcome in seen:
                    self.assertTrue(all(control), 'fault must start from real healthy native borrow')
                    self.assertIsInstance(outcome, SCP.driver.SharedUpgradeHold,
                                          'native-marked child accepted hybrid readiness fallback')
                self.assertEqual([], installs, 'no-wire hybrid probe must not install')
                self.assertNotEqual(0, code, 'no-wire native workflow must stay HOLD')

