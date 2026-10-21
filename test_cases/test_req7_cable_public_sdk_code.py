"""Independent finite public-code prerequisite UNIT; never SDK/send authority.

Imports real installed public providers only. No key, token, SDK constructor,
Cloud request, private account file or controlled native-success flag is used.
The expected wrapper limits and SA defaults are literal independent oracles.
"""
from contextlib import contextmanager
import importlib
import sys
import types
import unittest


class CablePublicSdkCodeTests(unittest.TestCase):
    def entry(self):
        from monitor import issue_tracker_publish_runtime as runtime
        entry = getattr(runtime, '_hold_cable_public_sdk_code', None)
        self.assertTrue(callable(entry), 'MISSING_FIXED_PUBLIC_SDK_CODE_PREREQUISITE')
        return runtime, entry

    @contextmanager
    def observed_no_constructors(self):
        # Code-only observation, not replacement or qualification of providers.
        from google.oauth2 import credentials, service_account
        from google.auth.crypt import rsa, _cryptography_rsa
        watched = {
            service_account.Credentials.__init__.__code__,
            credentials.Credentials.__init__.__code__,
            rsa.RSASigner.__init__.__code__,
            _cryptography_rsa.RSASigner.__init__.__code__,
        }
        calls = []
        previous = sys.getprofile()
        def observe(frame, event, value):
            if previous is not None:
                previous(frame, event, value)
            if event == 'call' and frame.f_code in watched:
                calls.append((frame.f_code.co_name, frame.f_code.co_filename))
        sys.setprofile(observe)
        try:
            yield calls
        finally:
            sys.setprofile(previous)

    def health(self, entry):
        with self.observed_no_constructors() as constructors:
            with entry() as proof:
                self.assertEqual('NO_SEND', proof.outcome)
                proof.verify()
                proof.verify()
                for name in ('credential', 'credential_raw', 'token', 'writer_token',
                             'sheet_token', 'fd', 'sdk', 'transport', 'service'):
                    self.assertFalse(hasattr(proof, name), 'CODE_ONLY_EXPORTS_' + name)
            self.assertEqual([], constructors, 'CODE_PREREQUISITE_CONSTRUCTED_CREDENTIAL_OR_SIGNER')
        return proof

    def test_actual_public_producers_qualify_without_credential_construction_and_revoke(self):
        runtime, entry = self.entry()
        proof = self.health(entry)
        with self.assertRaises(runtime.CableSourceHold):
            proof.verify()

    def test_initial_same_code_wrapper_with_wrong_fixed_closure_is_not_adopted(self):
        runtime, entry = self.entry()
        # Healthy real providers before either independent corruption.
        self.health(entry)
        module = importlib.import_module('googleapiclient.discovery')
        original = module.build
        names = original.__code__.co_freevars
        self.assertEqual(('max_positional_args', 'wrapped'), names)
        self.assertEqual(2, original.__closure__[0].cell_contents)
        self.assertIs(original.__wrapped__, original.__closure__[1].cell_contents)
        def cell(value):
            return (lambda: value).__closure__[0]
        # Actual original wrapper bytecode/globals/name and real wrapped body;
        # only its pre-existing semantic closure has changed 2 -> 3.
        changed = types.FunctionType(original.__code__, original.__globals__,
            original.__name__, original.__defaults__,
            (cell(3), original.__closure__[1]))
        changed.__dict__.update(original.__dict__)
        changed.__kwdefaults__ = original.__kwdefaults__
        module.build = changed
        try:
            with self.assertRaises(runtime.CableSourceHold):
                with entry() as proof:
                    proof.verify()
        finally:
            module.build = original
        self.health(entry)

    def test_initial_modified_service_account_default_is_not_snapshot_authority(self):
        runtime, entry = self.entry()
        self.health(entry)
        from google.oauth2 import service_account
        function = service_account.Credentials.__init__
        original = function.__defaults__
        expected = (None, None, None, None, None, None, False, 'googleapis.com', None)
        self.assertEqual(expected, original)
        # Does not instantiate a credential. Bytecode/name/globals stay real;
        # pre-existing semantic default must still match the held source.
        function.__defaults__ = (None, None, None, None, None, None, True,
                                 'googleapis.com', None)
        try:
            with self.assertRaises(runtime.CableSourceHold):
                with entry() as proof:
                    proof.verify()
        finally:
            function.__defaults__ = original
        self.health(entry)


if __name__ == '__main__':
    unittest.main(verbosity=2)
