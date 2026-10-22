"""Independent caller/DTO refusal, actual providers never replaced."""
from contextlib import contextmanager
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest import mock


def entry(test):
    from monitor import issue_tracker_publish_runtime as runtime
    function = getattr(runtime, '_hold_current_cable_sdk_credential_prerequisite', None)
    test.assertTrue(callable(function), 'MISSING_ACTUAL_HELD_SOURCE_SDK_CREDENTIAL_CONSTRUCTION')
    return runtime, function


@contextmanager
def observe_providers():
    # Actual imported functions and objects; never stub construction/verification.
    from google.oauth2 import service_account, credentials
    from google.auth.crypt import rsa, _cryptography_rsa
    watched = {fn.__code__ for fn in (
        service_account.Credentials.__init__, credentials.Credentials.__init__,
        rsa.RSASigner.__init__, _cryptography_rsa.RSASigner.__init__,
    )}
    sa_init = service_account.Credentials.__init__
    from_info = service_account.Credentials.from_service_account_info.__func__
    events = {'constructors': [], 'credentials': [], 'from_info': 0}
    previous = sys.getprofile()
    def observe(frame, event, value):
        if previous is not None:
            previous(frame, event, value)
        if event == 'call' and frame.f_code in watched:
            events['constructors'].append(frame.f_code)
        if (event == 'call' and frame.f_code is from_info.__code__
                and frame.f_globals is from_info.__globals__):
            events['from_info'] += 1
        if (event == 'return' and frame.f_code is sa_init.__code__
                and frame.f_globals is sa_init.__globals__):
            events['credentials'].append(frame.f_locals['self'])
    sys.setprofile(observe)
    try:
        yield events
    finally:
        sys.setprofile(previous)


class CredentialCallerRefusalTests(unittest.TestCase):
    def test_arbitrary_caller_cannot_construct_credential_or_send(self):
        runtime, function = entry(self)
        with observe_providers() as events:
            with mock.patch.object(socket, 'socket', side_effect=AssertionError('NETWORK_FORBIDDEN')) as network:
                with mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('TRANSPORT_CHILD_FORBIDDEN')) as children:
                    entered = False
                    refusal = None
                    try:
                        with function(object(), http_root=Path('/private/tmp')):
                            entered = True
                    except runtime.CableSourceHold as error:
                        refusal = error
                    # Assertions OUTSIDE product guards: a late Hold cannot
                    # turn an already-yielded scope into pre-yield refusal.
                    self.assertFalse(entered, 'ARBITRARY_CALLER_ADMITTED')
                    self.assertIsNotNone(refusal, 'ARBITRARY_CALLER_NOT_REFUSED')
                    self.assertEqual((0, 0), (network.call_count, children.call_count))
            self.assertEqual([], events['constructors'])
            self.assertEqual([], events['credentials'])
            self.assertEqual(0, events['from_info'])


if __name__ == '__main__':
    unittest.main(verbosity=2)

