"""Canonical owned-CA close contracts; synthetic ownership, no real system CA/online."""
from contextlib import ExitStack
import errno
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'monitor/issue_tracker_tls_inputs.py'
BODY = b'Owned CA reader literal bytes; not a certificate or a trust assertion.\n'


class CaCloseContractTests(unittest.TestCase):
    def run_owned_reader(self, *, body_interrupt=None, first_close_interrupt=None):
        spec = importlib.util.spec_from_file_location('req7_owned_ca_cleanup_candidate', SOURCE)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        root = Path(tempfile.mkdtemp(prefix='req7-ca-close-owned-', dir='/private/tmp'))
        leaf = root / 'etc/ssl/certs/ca-certificates.crt'
        leaf.parent.mkdir(parents=True)
        # These are test fixture data, not a source/credential permission.
        leaf.write_bytes(BODY)
        leaf.chmod(0o644)
        real_open, real_close = os.open, os.close
        real_fstat, real_stat, real_read = os.fstat, os.stat, os.read
        opened, names, attempts, reads = [], [], [], []
        caught = result = None

        def metadata(info):
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                      'st_size', 'st_atime', 'st_mtime', 'st_ctime',
                      'st_atime_ns', 'st_mtime_ns', 'st_ctime_ns')
            value = SimpleNamespace(**{name: getattr(info, name) for name in fields})
            value.st_uid = 0  # Only synthetic ownership; actual inode/mode/times stay.
            return value

        def opening(name, flags, *args, **kwargs):
            if name == '/':
                self.assertFalse(opened)
                actual = root
            else:
                self.assertIn(kwargs.get('dir_fd'), opened)
                self.assertIn(name, ('etc', 'ssl', 'certs', 'ca-certificates.crt'))
                actual = name
            fd = real_open(actual, flags, *args, **kwargs)
            opened.append(fd)
            names.append(name)
            return fd

        def reading(fd, count):
            self.assertEqual(opened[-1], fd)
            value = real_read(fd, count)
            reads.append(value)
            if body_interrupt is not None:
                raise body_interrupt
            return value

        def closing(fd):
            self.assertIn(fd, opened)
            attempts.append(fd)
            real_close(fd)  # Genuine close happens before the injected error.
            if len(attempts) == 1 and first_close_interrupt is not None:
                raise first_close_interrupt
            if len(attempts) == 2 and first_close_interrupt is not None:
                raise OSError(errno.EIO, 'owned delegated-close tail')

        first_result_closed = []
        try:
            with ExitStack() as stack:
                for target, value in (
                    ('os.geteuid', lambda: 0), ('os.open', opening),
                    ('os.fstat', lambda fd: metadata(real_fstat(fd))),
                    ('os.stat', lambda *a, **k: metadata(real_stat(*a, **k))),
                    ('os.read', reading), ('os.close', closing),
                ):
                    stack.enter_context(mock.patch(target, side_effect=value))
                try:
                    result = module._fixed_ca()
                except BaseException as error:
                    caught = error
            # FIRST-result facts precede fixture cleanup. No later reuse can repair them.
            for fd in opened:
                try:
                    real_fstat(fd)
                except OSError as error:
                    self.assertEqual(errno.EBADF, error.errno)
                    first_result_closed.append(True)
                else:
                    first_result_closed.append(False)
            facts = dict(root=str(root), names=names, opened=opened, attempts=attempts[:],
                         first_result_closed=first_result_closed[:], reads_match=reads == [BODY],
                         result_present=result is not None, error_type=type(caught).__name__ if caught else None,
                         system_ca_read=False, synthetic_uid=True, no_tls_or_network=True)
            print('OWNED_CA_FIRST_RESULT=' + json.dumps(facts, sort_keys=True), flush=True)
            return result, caught, facts
        finally:
            # Only the exact descriptors obtained by this fixture; never scan any FDs.
            for fd in opened:
                try:
                    real_fstat(fd)
                except OSError:
                    continue
                real_close(fd)

    def assert_health(self):
        result, error, facts = self.run_owned_reader()
        self.assertIsNone(error)
        self.assertEqual(BODY, result[0])
        self.assertEqual(['/', 'etc', 'ssl', 'certs', 'ca-certificates.crt'], facts['names'])
        self.assertEqual(list(reversed(facts['opened'])), facts['attempts'])
        self.assertEqual([True] * 5, facts['first_result_closed'])
        self.assertTrue(facts['reads_match'])

    def test_delegated_close_interruption_keeps_identity_and_closes_every_known_fd(self):
        self.assert_health()
        interruption = KeyboardInterrupt('owned first close interruption')
        cause = ValueError('owned original cause')
        interruption.__cause__ = cause
        result, error, facts = self.run_owned_reader(first_close_interrupt=interruption)
        self.assertIsNone(result)
        self.assertIs(error, interruption)
        self.assertIs(error.__cause__, cause)
        self.assertEqual(list(reversed(facts['opened'])), facts['attempts'],
                         'CA_CLOSE_INTERRUPTION_SKIPPED_REMAINING_KNOWN_FDS')
        self.assertEqual([True] * 5, facts['first_result_closed'])
        self.assertTrue(facts['reads_match'])

    def test_read_interruption_wins_over_later_close_interruptions_and_all_fds_close(self):
        self.assert_health()
        interruption = KeyboardInterrupt('owned delegated read interruption')
        cause = ValueError('owned original read cause')
        interruption.__cause__ = cause
        result, error, facts = self.run_owned_reader(body_interrupt=interruption,
            first_close_interrupt=SystemExit('owned first cleanup interruption'))
        self.assertIsNone(result)
        self.assertIs(error, interruption, 'CA_CLEANUP_REPLACED_ORIGINAL_READ_INTERRUPTION')
        self.assertIs(error.__cause__, cause)
        self.assertEqual(list(reversed(facts['opened'])), facts['attempts'])
        self.assertEqual([True] * 5, facts['first_result_closed'])
        self.assertTrue(facts['reads_match'])



class TokenWireCaCloseWorkflowTests(unittest.TestCase):
    def setUp(self):
        from test_cases import test_req7_tls_inputs as fixtures
        self._fixtures = fixtures
        fixtures.Req7TlsInputsDirectTests.setUp(self)

    def test_actual_token_wire_unit_preserves_ca_interruption_closes_all_and_never_connects_or_reuses(self):
        from monitor.issue_tracker_sdk_authentication import TokenWireRequest
        # Load real production shape modules before observing just this CA acquisition.
        from monitor.issue_tracker_sheets_read_plan import PreparedSheetsMutation
        from monitor.issue_tracker_enrollment_protocol import PreparedEnrollmentMutation
        import ssl
        wire = TokenWireRequest('https://oauth2.googleapis.com/token', 'POST',
                                b'owned-ca-cleanup-workflow',
                                (('Content-Type', 'application/x-www-form-urlencoded'),))
        prepared = self.module.prepare_token_request(wire)
        self.assertEqual(('oauth2.googleapis.com', '/token', 'POST', b'owned-ca-cleanup-workflow'),
                         (prepared.host, prepared.path, prepared.method, prepared.body))
        self.assertEqual(Path(self._fixtures.MODULE).resolve(), Path(self.module.__file__).resolve())
        with self._fixtures.Req7TlsInputsDirectTests.fixture(self):
            context, identity = self.module.controlled_tls_context()
        self.assertIs(type(context), ssl.SSLContext)
        self.assertTrue(context.check_hostname)
        self.assertEqual(ssl.CERT_REQUIRED, context.verify_mode)
        self.assertEqual(1, context.cert_store_stats()['x509_ca'])
        self.assertEqual('/etc/ssl/certs/ca-certificates.crt', identity.path)

        real_close, real_fstat = os.close, os.fstat
        opened, attempted = [], []
        interruption = KeyboardInterrupt('owned CA token-unit close interruption')
        cause = ValueError('owned CA workflow original cause')
        interruption.__cause__ = cause
        unit = self.module.NativeTokenHttpsUnit()
        caught = None
        def cleanup_known():
            for fd in opened:
                try: real_fstat(fd)
                except OSError: continue
                real_close(fd)
        self.addCleanup(cleanup_known)
        with self._fixtures.Req7TlsInputsDirectTests.fixture(self):
            fixture_open = os.open
            def opening(*args, **kwargs):
                fd = fixture_open(*args, **kwargs)
                opened.append(fd)
                return fd
            def closing(fd):
                self.assertIn(fd, opened)
                attempted.append(fd)
                real_close(fd)
                if len(attempted) == 1: raise interruption
                if len(attempted) == 2: raise OSError(errno.EIO, 'owned tail close')
            with mock.patch('os.open', side_effect=opening), mock.patch('os.close', side_effect=closing), \
                    mock.patch('http.client.HTTPSConnection', side_effect=AssertionError('CA failure must precede connection')) as connect:
                try: unit.send_once(wire)
                except BaseException as error: caught = error
                connections = connect.call_count
        closed = []
        for fd in opened:
            try: real_fstat(fd)
            except OSError as error:
                self.assertEqual(errno.EBADF, error.errno)
                closed.append(True)
            else: closed.append(False)
        print('CA_TOKEN_UNIT_FIRST_RESULT=' + json.dumps(dict(opened=opened, attempted=attempted,
            first_result_closed=closed, connections=connections,
            error_type=type(caught).__name__ if caught else None,
            cause_identity=(caught is interruption and caught.__cause__ is cause)), sort_keys=True), flush=True)
        self.assertIs(caught, interruption)
        self.assertIs(caught.__cause__, cause)
        self.assertEqual(5, len(opened))
        self.assertEqual(list(reversed(opened)), attempted,
                         'TOKEN_UNIT_CA_INTERRUPTION_SKIPPED_KNOWN_CLOSES')
        self.assertEqual([True] * 5, closed)
        self.assertEqual(0, connections)
        with mock.patch.object(self.module, 'controlled_tls_context') as ca, \
                mock.patch('http.client.HTTPSConnection') as connect:
            with self.assertRaises(self.module.TlsInputHold): unit.send_once(wire)
            ca.assert_not_called()
            connect.assert_not_called()
