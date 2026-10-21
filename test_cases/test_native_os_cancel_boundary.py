"""SOURCE ONLY fixture UNIT: explicit test-owner cancellation, NOT native proof."""
import threading
import unittest
from test_cases import scp_native_os_manager_fixture as FLOW


class MarkerOwnerCancellationUnitTests(unittest.TestCase):
    def controller(self):
        kind = getattr(FLOW, '_MarkerWaitCancellation', None)
        self.assertTrue(callable(kind), 'fixture-only completed-manager cancellation controller required')
        return kind()

    def test_only_completed_missing_marker_false_requests_once_and_idle_delivers(self):
        gate = self.controller()
        original_stop = threading.Event()
        calls, clock = [], [100.0]
        def original_idle(seconds):
            calls.append(seconds); clock[0] += seconds
        def controlled_idle(seconds):
            gate.before_idle()
            return original_idle(seconds)
        self.assertIsNone(controlled_idle(2.5))
        self.assertEqual([2.5], calls)
        self.assertEqual(102.5, clock[0])
        self.assertFalse(original_stop.is_set())
        gate.after_manager_return(fault='missing_content', original_stop=original_stop,
                                 value=False, normal_return=True, ack_absent=True)
        self.assertTrue(original_stop.is_set())
        self.assertEqual(1, gate.requests)
        self.assertFalse(gate.delivered, 'profile completion must not throw/cancel original result')
        first = gate.error
        self.assertIsInstance(first, FLOW.SharedUpgradeHold)
        self.assertEqual('TestOwnerCancellation', type(first).__name__)
        gate.after_manager_return(fault='missing_content', original_stop=original_stop,
                                 value=False, normal_return=True, ack_absent=True)
        self.assertEqual(1, gate.requests)
        with self.assertRaises(type(first)) as caught:
            controlled_idle(10.0)
        self.assertIs(first, caught.exception)
        self.assertTrue(gate.delivered)
        self.assertEqual([2.5], calls, 'original idle is not called after the explicit test cancellation')
        self.assertEqual(102.5, clock[0])
        with self.assertRaises(type(first)) as repeated:
            gate.before_idle()
        self.assertIs(first, repeated.exception)

    def test_wrong_marker_exception_or_ack_never_arms_and_pending_ni_is_preserved(self):
        for fault, value, normal, absent in (
                ('wrong_content', False, True, True),
                ('record_file_sync', False, True, True),
                ('missing_content', None, False, True),
                ('missing_content', False, True, False),
                ('missing_content', None, True, True),
                ('missing_content', True, True, True)):
            with self.subTest(fault=fault, normal=normal, value=value, absent=absent):
                gate = self.controller(); stop = threading.Event()
                gate.after_manager_return(fault=fault, original_stop=stop,
                                         value=value, normal_return=normal, ack_absent=absent)
                self.assertFalse(stop.is_set())
                self.assertEqual(0, gate.requests)
                self.assertIsNone(gate.before_idle())
                self.assertFalse(gate.delivered)
        gate = self.controller(); stop = threading.Event()
        gate.after_manager_return(fault='missing_content', original_stop=stop,
                                 value=False, normal_return=True, ack_absent=True)
        primary = KeyboardInterrupt('literal owner UNIT interrupt')
        cause = RuntimeError('literal already attached cause')
        primary.__cause__ = cause
        caught_primary = None
        try:
            raise primary
        except BaseException as caught:
            caught_primary = caught
            self.assertIsNone(gate.before_idle(), 'test cancellation cannot replace an active body exception')
            self.assertFalse(gate.delivered)
        self.assertIs(primary, caught_primary)
        self.assertIs(cause, primary.__cause__)
        self.assertEqual(1, gate.requests)
