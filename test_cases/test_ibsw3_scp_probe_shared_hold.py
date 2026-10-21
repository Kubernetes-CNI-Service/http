"""UNRUN protocol UNIT: genuine source drift remains a shared batch HOLD.

Synthetic leaf/channel are not native ownership or preflight authority. The
source factory and its original known_hosts verification are never replaced.
"""
import contextlib
import importlib
import io
from pathlib import Path
import tempfile
import time
import unittest

from test_cases import test_ibsw3_scp_source_binding as SOURCE
from test_cases import test_ibsw3_scp_source_probe_channel as PROTOCOL


class BoundaryChannel(PROTOCOL.UnitChannel):
    def __init__(self, case, trust):
        super().__init__()
        self.case, self.trust = case, trust
        self.changed = False
        self.shutdown_calls = 0

    def exec_command(self, command):
        super().exec_command(command)
        if self.case == 'source_drift':
            original = self.trust.read_bytes()
            changed = original.replace(b'192.0.2.254', b'192.0.2.253')
            if original == changed:
                raise AssertionError('literal synthetic endpoint must exist')
            self.trust.write_bytes(changed)
            self.changed = True

    def send(self, value):
        if self.case == 'send_zero':
            self.send_calls += 1
            return 0
        if self.case == 'partial_io' and self.send_calls:
            self.send_calls += 1
            raise OSError('SYNTHETIC_ONLY private send error')
        return super().send(value)

    def shutdown_write(self):
        self.shutdown_calls += 1
        if self.case == 'shutdown_failure':
            raise OSError('SYNTHETIC_ONLY private shutdown error')
        return super().shutdown_write()


class ScpProbeSharedHoldTests(unittest.TestCase):
    def test_original_source_drift_before_secret_send_remains_shared_hold(self):
        module = SOURCE.ScpSourceBindingTests().module()
        function = getattr(module, '_probe_source_channel', None)
        self.assertTrue(callable(function), 'fixed probe capability required')
        contract = importlib.import_module('ibsw_upgrade_contract')
        for case in ('source_drift', 'send_zero', 'partial_io', 'shutdown_failure', 'healthy'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as raw:
                trust, source = SOURCE.ScpSourceBindingTests().source(Path(raw).resolve(), module)
                original_keys, original_identity = source.host_keys, source._identity
                channel = BoundaryChannel(case, trust)
                leaf = PROTOCOL.UnitLeaf(channel)
                transport = PROTOCOL.UnitTransport(channel)
                failure = None
                result = object()
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    try:
                        result = function(leaf, transport, time.monotonic()+5, source)
                    except BaseException as caught:
                        failure = caught
                self.assertEqual(1, transport.opens, 'never reopen/retry a source probe')
                self.assertEqual(1, channel.close_calls, 'one actual acquired channel close')
                self.assertEqual(original_keys, source.host_keys, 'no fresh trust adoption')
                self.assertEqual(original_identity, source._identity)
                if case == 'source_drift':
                    self.assertTrue(channel.changed, 'fault must occur after actual exec')
                    self.assertEqual(0, channel.send_calls, 'zero secret bytes after trust drift')
                    self.assertEqual(b'', bytes(channel.sent))
                    self.assertEqual(0, channel.shutdown_calls)
                    self.assertIsInstance(failure, contract.SharedUpgradeHold,
                        'source drift is whole-batch shared HOLD, not ordinary per-device ScpHold')
                    self.assertIn('SCP_SOURCE_CHANGED', str(failure))
                    self.assertIsInstance(failure.__cause__, module.ScpHold)
                elif case == 'healthy':
                    self.assertIsNone(failure)
                    self.assertIsNone(result, 'only protocol DATA completion, never a native grant')
                    self.assertGreater(channel.send_calls, 1)
                    self.assertEqual(1, channel.shutdown_calls)
                else:
                    self.assertIsInstance(failure, module.ScpHold)
                    self.assertEqual('SCP_SECRET_CHANNEL_FAILED', failure.reason_code)
                    if case == 'send_zero':
                        self.assertEqual(1, channel.send_calls)
                        self.assertEqual(b'', bytes(channel.sent))
                    if case == 'partial_io':
                        self.assertEqual(2, channel.send_calls)
                        self.assertEqual(3, len(channel.sent))
                    self.assertEqual(1 if case == 'shutdown_failure' else 0,
                                     channel.shutdown_calls)
                self.assertNotIn('SYNTHETIC_ONLY', stdout.getvalue()+stderr.getvalue())
                if failure is not None:
                    self.assertNotIn('SYNTHETIC_ONLY', str(failure))
