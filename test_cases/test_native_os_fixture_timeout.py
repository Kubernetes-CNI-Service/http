"""Literal SDK timeout compatibility, no producer import/channel/process/FD grant."""
import math
import unittest
from unittest.mock import patch
from test_cases import native_os_dual_channel as dual
from test_cases.native_os_physical_bridge import NativeChannel


class NativeOsFixtureTimeoutTests(unittest.TestCase):
    def test_sdk_120_second_timeout_is_accepted_without_extending_original_owner(self):
        channel=NativeChannel(object())
        channel.settimeout(120.0)
        self.assertEqual(120.0,channel.timeout)
        self.assertIsNone(channel.inner)
        wire=object.__new__(dual._Channel)
        wire.deadline=150.0
        with patch.object(dual.time,'monotonic',return_value=100.0):
            wire.settimeout(120.0)
        self.assertEqual(150.0,wire.deadline,'existing owner absolute deadline must not renew')
        with patch.object(dual.time,'monotonic',return_value=100.0):
            wire.settimeout(10.0)
        self.assertEqual(110.0,wire.deadline,'a smaller SDK timeout may shorten the original deadline')

    def test_nonfinite_nonpositive_or_foreign_timeout_is_refused(self):
        channel=NativeChannel(object())
        wire=object.__new__(dual._Channel)
        wire.deadline=150.0
        for value in (float('nan'),math.inf,-math.inf,0,-1,True,None,'120'):
            for target in (channel,wire):
                with self.subTest(value=repr(value),target=type(target).__name__),self.assertRaises(ValueError):
                    target.settimeout(value)
        self.assertIsNone(channel.timeout)
        self.assertEqual(150.0,wire.deadline)


if __name__=='__main__': unittest.main()
