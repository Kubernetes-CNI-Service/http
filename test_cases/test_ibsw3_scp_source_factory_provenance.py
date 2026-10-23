"""SOURCE ONLY: one fixed-provider dependency-fault contract, not SCP wire.

The original entry/project/readiness and real factory run in the existing
simulated-target fixture. No completion, source verifier or dispatch is mocked
by this test. Only the factory namespace dependency is deliberately replaced.
"""
import base64
from functools import wraps
import importlib
from pathlib import Path
import struct
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from test_cases import scp_source_cli_fixture as FIXTURE


class UnitSourceTTY:
    def isatty(self):
        return True

    def readline(self, *args):
        raise AssertionError('fixed source argv requires no address/user prompt')


class ScpSourceFactoryProvenanceTests(unittest.TestCase):
    def test_real_entry_refuses_same_named_delegate_factory_before_source_freeze(self):
        provider = importlib.import_module('ibsw_upgrade_scp')
        factory = provider.source_from_known_hosts
        source_class = provider.ScpSource
        configure = FIXTURE.app._configure_scp_source
        freeze = FIXTURE.driver._PreparedRunScope.freeze_scp_package_sources
        self.assertIs(factory.__globals__, vars(provider))
        self.assertIs(provider.source_from_known_hosts, factory)
        self.assertIsNone(sys.getprofile())
        # threading.getprofile()/gettrace() are 3.10+; on 3.9 they are read from the hooks threading.setprofile()/settrace() store.
        self.assertIsNone(getattr(threading, 'getprofile', lambda: threading._profile_hook)())
        secret = 'secret-value'
        counts = {'foreign_factory': 0, 'freeze': 0}
        genuine_returns = []
        configured = []

        # The wrapper borrows the genuine name/module/doc, but remains a
        # different function/code/globals object. It does not invent a source.
        @wraps(factory)
        def foreign_same_named_factory(*args, **kwargs):
            counts['foreign_factory'] += 1
            result = factory(*args, **kwargs)
            genuine_returns.append(result)
            return result

        self.assertEqual(factory.__name__, foreign_same_named_factory.__name__)
        self.assertEqual(factory.__module__, foreign_same_named_factory.__module__)
        self.assertIsNot(factory, foreign_same_named_factory)
        self.assertIsNot(factory.__code__, foreign_same_named_factory.__code__)
        self.assertIsNot(factory.__globals__, foreign_same_named_factory.__globals__)

        def observe(frame, event, argument):
            if (frame.f_code is configure.__code__
                    and frame.f_globals is configure.__globals__
                    and event == 'return' and argument is not None):
                configured.append(argument)
            elif (frame.f_code is freeze.__code__
                    and frame.f_globals is freeze.__globals__ and event == 'call'):
                counts['freeze'] += 1

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            kind = b'ssh-ed25519'
            wire = (struct.pack('>I', len(kind)) + kind
                    + struct.pack('>I', 32) + bytes((17,)) * 32)
            trust_bytes = (b'[198.51.100.44]:2222 ssh-ed25519 '
                           + base64.b64encode(wire) + b'\n')
            trust = root / 'scp-source-known_hosts'
            trust.write_bytes(trust_bytes)
            trust.chmod(0o600)

            # Real healthy factory/verification prerequisite, before the fault.
            # This is public synthetic trust, not an actual key or permit.
            healthy = factory('198.51.100.44', 'source_test', 2222, trust, '')
            self.assertIs(type(healthy), source_class)
            self.assertEqual(trust_bytes, healthy.host_keys)
            healthy.verify()

            try:
                sys.setprofile(observe)
                threading.setprofile(observe)
                with patch.object(provider, 'source_from_known_hosts', foreign_same_named_factory), \
                     patch.object(sys, 'stdin', UnitSourceTTY()), \
                     patch.object(FIXTURE.app.getpass, 'getpass', return_value=secret):
                    self.assertIs(provider.source_from_known_hosts, foreign_same_named_factory)
                    code, report, errors, calls, installs = (
                        FIXTURE.ThreeComponentWorkflowTests().invoke(
                            root, selection=('--os-only',), controlled_grace=True))
                    installed_slot = provider.source_from_known_hosts
            finally:
                threading.setprofile(None)
                sys.setprofile(None)

            # Independent fixed-provider policy. An eventual backend HOLD is
            # insufficient if a foreign factory has already been executed.
            self.assertIs(installed_slot, foreign_same_named_factory)
            self.assertIs(provider.source_from_known_hosts, factory)
            self.assertIsNone(sys.getprofile())
            self.assertIsNone(getattr(threading, 'getprofile', lambda: threading._profile_hook)())
            self.assertEqual(0, counts['foreign_factory'],
                             'FOREIGN_SOURCE_FACTORY_MUST_BE_REFUSED_BEFORE_CALL')
            self.assertEqual([], configured,
                             'a real DTO returned by a foreign wrapper is not original provenance')
            self.assertEqual(0, counts['freeze'],
                             'source provenance refusal must precede package freeze')
            self.assertEqual([], installs)
            self.assertNotEqual(0, code)
            self.assertEqual(trust_bytes, trust.read_bytes())
            healthy.verify()
            self.assertTrue(all(type(value) is source_class for value in genuine_returns))
