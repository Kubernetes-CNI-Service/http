"""Independent current-FD EX helper contracts; no stage or writer authority."""
from contextlib import contextmanager
import errno
import fcntl
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from tools import deployment_lock as locks


ROOT = Path(__file__).resolve().parents[1]


CURRENT_FD_EX = (
    b'pos:\t0\n'
    b'flags:\t0100002\n'
    b'mnt_id:\t12\n'
    b'ino:\t17\n'
    b'lock:\t1: FLOCK  ADVISORY  WRITE 123 08:01:17 0 EOF\n'
)


def nine(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


@contextmanager
def owned_exclusive_fixture(test):
    root = Path(tempfile.mkdtemp(
        prefix='public-current-ex-', dir=os.environ.get('R22_TEST_PRIVATE_ROOT'),
    )).resolve()
    descriptor = locks.acquire_lock_descriptor(root, exclusive=True, create=True)
    path = root / '.deployment.lock'
    first = nine(path.lstat())
    test.assertTrue(stat.S_ISREG(first[2]))
    test.assertEqual(1, first[5])
    test.assertEqual(first, nine(os.fstat(descriptor)))
    test.assertEqual(b'', path.read_bytes())
    try:
        yield root, path, descriptor, first
    finally:
        try:
            test.assertEqual(first, nine(path.lstat()))
            test.assertEqual(first, nine(os.fstat(descriptor)))
            test.assertEqual(b'', path.read_bytes())
        finally:
            locks.release_lock_descriptor(descriptor)
            print('CURRENT_EX_PUBLIC_FIXTURE_RETAINED=' + str(root), flush=True)


class CurrentExclusiveDeploymentLockTests(unittest.TestCase):
    def setUp(self):
        expected = ROOT / "tools/deployment_lock.py"
        self.assertEqual(expected, Path(locks.__file__))
        self.assertTrue(stat.S_ISREG(expected.lstat().st_mode))

    def test_literal_current_fd_whole_file_write_row_is_accepted(self):
        parser = locks._require_current_fdinfo_exclusive
        metadata = SimpleNamespace(st_dev=os.makedev(8, 1), st_ino=17)
        self.assertIsNone(parser(CURRENT_FD_EX, metadata))
        # The originating PID is not an ownership oracle; preserve the old
        # parser's literal signed PID acceptance for current-FD kernel rows.
        self.assertIsNone(parser(CURRENT_FD_EX.replace(b'WRITE 123 ', b'WRITE -1 '), metadata))

    def test_literal_malformed_or_nonexclusive_fdinfo_frames_are_rejected(self):
        parser = locks._require_current_fdinfo_exclusive
        metadata = SimpleNamespace(st_dev=os.makedev(8, 1), st_ino=17)
        cases = (
            ('empty', b''),
            ('not-bytes', 'PUBLIC_NOT_BYTES'),
            ('missing-newline', CURRENT_FD_EX[:-1]),
            ('CR', CURRENT_FD_EX.replace(b'pos:\t0\n', b'pos:\t0\r\n')),
            ('NUL', CURRENT_FD_EX + b'\0'),
            ('non-ASCII', CURRENT_FD_EX + b'\xff\n'),
            ('SH-read', CURRENT_FD_EX.replace(b'WRITE', b'READ')),
            ('POSIX-not-FLOCK', CURRENT_FD_EX.replace(b'FLOCK', b'POSIX')),
            ('non-advisory', CURRENT_FD_EX.replace(b'ADVISORY', b'MANDATORY')),
            ('wrong-device', CURRENT_FD_EX.replace(b'08:01:17', b'08:02:17')),
            ('wrong-lock-inode', CURRENT_FD_EX.replace(b'08:01:17', b'08:01:18')),
            ('wrong-header-inode', CURRENT_FD_EX.replace(b'ino:\t17', b'ino:\t18')),
            ('not-whole-file', CURRENT_FD_EX.replace(b'17 0 EOF', b'17 1 EOF')),
            ('finite-end', CURRENT_FD_EX.replace(b'17 0 EOF', b'17 0 10')),
            ('missing-lock', b'pos:\t0\nflags:\t0100002\nmnt_id:\t12\nino:\t17\n'),
            ('duplicate-lock', CURRENT_FD_EX + b'lock:\t2: FLOCK ADVISORY WRITE 123 08:01:17 0 EOF\n'),
            ('duplicate-header', b'pos:\t0\n' + CURRENT_FD_EX),
            ('unknown-header', b'PUBLIC:\t0\n' + CURRENT_FD_EX),
            ('missing-header', CURRENT_FD_EX.replace(b'mnt_id:\t12\n', b'')),
            ('oversize', b'X' * (65536 + 1)),
        )
        for label, frame in cases:
            with self.subTest(label=label):
                with self.assertRaises(locks.DeploymentLockError):
                    parser(frame, metadata)

    def test_actual_original_EX_descriptor_is_accepted_without_mutation(self):
        require = locks.require_current_exclusive_lock_descriptor
        with owned_exclusive_fixture(self) as (root, path, descriptor, first):
            self.assertIsNone(require(path, descriptor))
            self.assertEqual(first, nine(os.fstat(descriptor)))
            self.assertEqual(first, nine(path.lstat()))

    def test_actual_SH_downgrade_is_rejected_before_any_EX_conversion(self):
        require = locks.require_current_exclusive_lock_descriptor
        with owned_exclusive_fixture(self) as (root, path, descriptor, first):
            self.assertIsNone(require(path, descriptor))
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
            probe = None
            try:
                with self.assertRaises(locks.DeploymentLockError):
                    require(path, descriptor)
                # Independent real SH must still succeed. A helper which
                # accidentally upgrades the original SH before rejection fails.
                probe = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
                self.assertEqual(first, nine(os.fstat(probe)))
                fcntl.flock(probe, fcntl.LOCK_SH | fcntl.LOCK_NB)
            finally:
                if probe is not None:
                    try:
                        fcntl.flock(probe, fcntl.LOCK_UN)
                    finally:
                        os.close(probe)
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertIsNone(require(path, descriptor))

    def test_actual_independent_same_inode_unflocked_FD_cannot_borrow_EX(self):
        require = locks.require_current_exclusive_lock_descriptor
        with owned_exclusive_fixture(self) as (root, path, descriptor, first):
            self.assertIsNone(require(path, descriptor))
            independent = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                self.assertNotEqual(descriptor, independent)
                self.assertEqual(first, nine(os.fstat(independent)))
                with self.assertRaises(locks.DeploymentLockError):
                    require(path, independent)
                self.assertEqual(first, nine(os.fstat(independent)))
                self.assertIsNone(require(path, descriptor))
            finally:
                os.close(independent)

    def test_actual_closed_independent_FD_is_rejected_without_closing_owner(self):
        require = locks.require_current_exclusive_lock_descriptor
        with owned_exclusive_fixture(self) as (root, path, descriptor, first):
            self.assertIsNone(require(path, descriptor))
            closed = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.assertNotEqual(descriptor, closed)
            self.assertEqual(first, nine(os.fstat(closed)))
            os.close(closed)
            with self.assertRaises(OSError) as prerequisite:
                os.fstat(closed)
            self.assertEqual(errno.EBADF, prerequisite.exception.errno)
            # This stale integer is never closed again, even if the helper's
            # own file open happens to reuse its numeric descriptor.
            with self.assertRaises(locks.DeploymentLockError):
                require(path, closed)
            self.assertEqual(first, nine(os.fstat(descriptor)))
            self.assertIsNone(require(path, descriptor))



class CurrentExclusiveDeploymentLockStrengthenedTests(unittest.TestCase):
    """Collect guard and independent kernel-witness results before asserting."""

    def setUp(self):
        self.assertEqual(ROOT / 'tools/deployment_lock.py', Path(locks.__file__))

    @staticmethod
    def _guard_observation(call):
        result = {'returned': False, 'value': None, 'error': None}
        try:
            result['value'] = call()
            result['returned'] = True
        except Exception as exc:
            result['error'] = exc
        return result

    @staticmethod
    def _shared_witness(path, real_flock):
        result = {'acquired': False, 'error': None, 'close_error': None}
        descriptor = None
        try:
            descriptor = os.open(
                path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            real_flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
            result['acquired'] = True
        except Exception as exc:
            result['error'] = exc
        finally:
            if descriptor is not None:
                # Closing this sole-owned witness also releases any SH lock.
                to_close, descriptor = descriptor, None
                try:
                    os.close(to_close)
                except Exception as exc:
                    result['close_error'] = exc
        return result

    def _report_pair(self, label, guard, witness):
        import json
        def error(value):
            if value is None:
                return None
            return {'type': type(value).__name__, 'message': str(value),
                    'errno': getattr(value, 'errno', None)}
        print('CURRENT_OFD_STRENGTHENED_OBSERVATION=' + json.dumps({
            'label': label, 'guard_returned': guard['returned'],
            'guard_value_is_none': guard['value'] is None,
            'guard_error': error(guard['error']),
            'witness_acquired': witness['acquired'],
            'witness_error': error(witness['error']),
            'witness_close_error': error(witness['close_error']),
        }, sort_keys=True), flush=True)

    def _check_pair(self, label, guard, witness, *, accepted):
        # Both real operations have already completed. Separate subtests make
        # a bad guard result unable to suppress the witness assertion.
        with self.subTest(label=label, observation='guard'):
            if accepted:
                self.assertIsNone(guard['error'])
                self.assertTrue(guard['returned'])
                self.assertIsNone(guard['value'])
            else:
                self.assertFalse(guard['returned'])
                self.assertIs(type(guard['error']), locks.DeploymentLockError)
                self.assertIn('deployment lock', str(guard['error']))
        with self.subTest(label=label, observation='SH-witness'):
            self.assertIsNone(witness['close_error'])
            if accepted:
                self.assertFalse(witness['acquired'])
                self.assertIsInstance(witness['error'], BlockingIOError)
                self.assertIn(witness['error'].errno,
                              (errno.EAGAIN, errno.EWOULDBLOCK))
            else:
                self.assertTrue(witness['acquired'])
                self.assertIsNone(witness['error'])

    @staticmethod
    def _close_owned_descriptors(descriptors):
        import sys
        active_primary = sys.exc_info()[1]
        errors = []
        for descriptor in descriptors:
            if descriptor is None:
                continue
            try:
                os.close(descriptor)
            except Exception as exc:
                errors.append(exc)
                print('CURRENT_OFD_OWNED_CLOSE_ERROR=' + type(exc).__name__, flush=True)
        if active_primary is None and errors:
            raise errors[0]

    @contextmanager
    def _public_EX_fixture(self):
        root = Path(tempfile.mkdtemp(
            prefix='public-current-ofd-strengthened-',
            dir=os.environ.get('R22_TEST_PRIVATE_ROOT'),
        )).resolve()
        path = root / '.deployment.lock'
        path.write_bytes(b'PUBLIC current OFD rendezvous\n')
        caller = locks.acquire_lock_descriptor(root, exclusive=True, create=True)
        first = nine(path.lstat())
        primary = None
        try:
            self.assertEqual(first, nine(os.fstat(caller)))
            self.assertTrue(stat.S_ISREG(first[2]))
            self.assertEqual(1, first[5])
            yield root, path, caller, first
        except BaseException as exc:
            primary = exc
            raise
        finally:
            # Sole close through the original constructor's release function;
            # a cleanup error never replaces an already active body exception.
            try:
                locks.release_lock_descriptor(caller)
            except Exception as exc:
                print('CURRENT_OFD_FIXTURE_CLEANUP_ERROR=' + type(exc).__name__,
                      flush=True)
                if primary is None:
                    raise
            finally:
                print('CURRENT_OFD_PUBLIC_FIXTURE_RETAINED=' + str(root), flush=True)

    def test_real_EX_dup_and_same_PID_independent_OFD_have_distinct_authority(self):
        real_flock = fcntl.flock
        with self._public_EX_fixture() as (_root, path, owner, first):
            duplicate = os.dup(owner)
            independent = None
            try:
                independent = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
                observations = []
                for label, candidate in (('original', owner), ('dup', duplicate)):
                    guard = self._guard_observation(
                        lambda: locks.require_current_exclusive_lock_descriptor(
                            path, candidate,
                        ),
                    )
                    witness = self._shared_witness(path, real_flock)
                    self._report_pair(label, guard, witness)
                    observations.append((label, guard, witness))
                foreign_guard = self._guard_observation(
                    lambda: locks.require_current_exclusive_lock_descriptor(
                        path, independent,
                    ),
                )
                # Only the genuine owner is explicitly released. Do not unlock
                # or close the rejected independent candidate before witnessing.
                real_flock(owner, fcntl.LOCK_UN)
                foreign_witness = self._shared_witness(path, real_flock)
                self._report_pair('same-PID-independent-OFD',
                                  foreign_guard, foreign_witness)
                for label, guard, witness in observations:
                    self._check_pair(label, guard, witness, accepted=True)
                self._check_pair('same-PID-independent-OFD',
                                 foreign_guard, foreign_witness, accepted=False)
                self.assertNotEqual(owner, independent)
                for descriptor in (owner, duplicate, independent):
                    self.assertEqual(first, nine(os.fstat(descriptor)))
                self.assertEqual(first, nine(path.lstat()))
                self.assertEqual(b'PUBLIC current OFD rendezvous\n', path.read_bytes())
            finally:
                self._close_owned_descriptors((independent, duplicate))

    def test_same_PID_foreign_EX_release_during_real_probe_does_not_promote_unlocked_caller(self):
        from unittest import mock
        from contextlib import ExitStack
        host = locks.platform.system().casefold()
        self.assertIn(host, ('darwin', 'linux'), 'unsupported fixture platform')
        for use_duplicate in (False, True):
            with self.subTest(caller='dup' if use_duplicate else 'original'):
                with self._public_EX_fixture() as (_root, path, owner, first):
                    duplicate = os.dup(owner)
                    foreign = None
                    real_flock = fcntl.flock
                    caller = duplicate if use_duplicate else owner
                    try:
                        foreign = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
                        positive = self._guard_observation(
                            lambda: locks.require_current_exclusive_lock_descriptor(
                                path, caller,
                            ),
                        )
                        positive_witness = self._shared_witness(path, real_flock)
                        self._report_pair('race-positive', positive, positive_witness)
                        # A failed genuine-EX control is a fixture/prerequisite
                        # failure, not evidence about the following race.
                        self._check_pair('race-positive', positive,
                                         positive_witness, accepted=True)
                        if (not positive['returned'] or positive['value'] is not None
                                or positive['error'] is not None
                                or not isinstance(positive_witness['error'], BlockingIOError)
                                or positive_witness['acquired']
                                or positive_witness['close_error'] is not None):
                            self.fail('PUBLIC_EX_POSITIVE_PREREQUISITE_FAILED')
                        real_flock(owner, fcntl.LOCK_UN)
                        real_flock(foreign, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        events = []
                        frames = []
                        original_reader = locks._read_current_lock_fdinfo

                        def probe_then_release(descriptor, operation):
                            try:
                                return real_flock(descriptor, operation)
                            except BlockingIOError:
                                if (not events and descriptor not in (owner, duplicate, foreign)
                                        and operation == (fcntl.LOCK_SH | fcntl.LOCK_NB)):
                                    metadata = os.fstat(descriptor)
                                    if (metadata.st_dev, metadata.st_ino) == first[:2]:
                                        events.append('real-SH-blocked')
                                        real_flock(foreign, fcntl.LOCK_UN)
                                        events.append('foreign-EX-released')
                                raise

                        def read_current_then_release(descriptor):
                            frame = original_reader(descriptor)
                            frames.append((descriptor, frame))
                            if descriptor == caller and not events:
                                events.append('real-current-FD-read')
                                real_flock(foreign, fcntl.LOCK_UN)
                                events.append('foreign-EX-released')
                            return frame

                        with ExitStack() as stack:
                            if host == 'linux':
                                stack.enter_context(mock.patch.object(
                                    locks, '_read_current_lock_fdinfo',
                                    side_effect=read_current_then_release,
                                ))
                            else:
                                stack.enter_context(mock.patch.object(
                                    locks.fcntl, 'flock', side_effect=probe_then_release,
                                ))
                            guard = self._guard_observation(
                                lambda: locks.require_current_exclusive_lock_descriptor(
                                    path, caller,
                                ),
                            )
                        # This happens before assertions and without changing
                        # caller lock state, closing caller, or releasing it.
                        witness = self._shared_witness(path, real_flock)
                        self._report_pair('same-PID-release-race', guard, witness)
                        self._check_pair('same-PID-release-race',
                                         guard, witness, accepted=False)
                        expected_event = ('real-current-FD-read' if host == 'linux'
                                          else 'real-SH-blocked')
                        self.assertEqual([expected_event, 'foreign-EX-released'], events)
                        if host == 'linux':
                            self.assertGreaterEqual(len(frames), 1)
                            self.assertEqual(caller, frames[0][0])
                            self.assertIsInstance(frames[0][1], bytes)
                            self.assertNotIn(b'lock:', frames[0][1])
                        else:
                            self.assertEqual([], frames)
                        for descriptor in (owner, duplicate, foreign):
                            self.assertEqual(first, nine(os.fstat(descriptor)))
                        self.assertEqual(first, nine(path.lstat()))
                        self.assertEqual(b'PUBLIC current OFD rendezvous\n', path.read_bytes())
                    finally:
                        self._close_owned_descriptors((foreign, duplicate))

if __name__ == "__main__":
    unittest.main()
