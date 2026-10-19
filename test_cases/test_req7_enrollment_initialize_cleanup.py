"""Initializer-only strict close controls; no enrollment or network execution.

Before the private capability exists these are explicit CAPABILITY assertion
failures, not product-behavior RED. After it exists, every FD belongs to this
test's private temporary tree and every injected close error is post-real-close.
"""
from contextlib import contextmanager
import errno
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from monitor import issue_tracker_enrollment_initialize as initialize

RAW_OPEN, RAW_CLOSE, RAW_FSTAT = os.open, os.close, os.fstat
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid',
          'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')


def identity(info):
    return tuple(getattr(info, name) for name in FIELDS)


class FixtureUnknown(KeyboardInterrupt):
    """Stop the suite; never infer ownership or clean an unconfirmed tree."""


class EnrollmentInitializeStrictCloseDirectTests(unittest.TestCase):
    def api(self, name):
        value = getattr(initialize, name, None)
        self.assertTrue(callable(value), 'INITIALIZER_STRICT_CLOSE_CAPABILITY_NOT_INSTALLED: ' + name)
        return value

    @contextmanager
    def originals(self):
        temporary = tempfile.TemporaryDirectory(prefix='req7-init-close-originals-')
        root = Path(temporary.name).resolve()
        records, pending = [], []
        unknown = False

        def opened(path, *, directory=False):
            nonlocal unknown
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            if directory:
                flags |= os.O_DIRECTORY
            fd = RAW_OPEN(path, flags)
            pending.append(fd)
            try:
                captured = identity(RAW_FSTAT(fd))
            except BaseException as error:
                unknown = True
                temporary._finalizer.detach()
                raise FixtureUnknown('fixture acquisition identity unknown; tree retained') from error
            records.append((fd, captured)); pending.remove(fd)
            return fd, captured

        try:
            parent, parent_identity = opened(root, directory=True)
            directories = []
            files = []
            for label in ('directory1', 'directory2'):
                path = root / label; path.mkdir(mode=0o700)
                fd, captured = opened(path, directory=True)
                directories.append((parent, label, fd, captured, ()))
            for label in ('file1', 'file2'):
                path = root / label; path.write_bytes(label.encode('ascii')); path.chmod(0o600)
                fd, captured = opened(path)
                files.append((parent, label, fd, captured, label.encode('ascii')))
            graph = SimpleNamespace(files=files, directories=directories)
            labels = {row[2]: row[1] for row in files + directories}
            labels[parent] = 'parent'
            yield graph, parent, parent_identity, labels
        finally:
            if pending or unknown:
                temporary._finalizer.detach()
            else:
                for fd, captured in reversed(records):
                    try:
                        actual = identity(RAW_FSTAT(fd))
                    except OSError as error:
                        if error.errno == errno.EBADF:
                            continue
                        temporary._finalizer.detach()
                        raise FixtureUnknown('fixture remaining original identity unknown; tree retained') from error
                    if actual[:2] != captured[:2]:
                        temporary._finalizer.detach()
                        raise FixtureUnknown('fixture original slot rebound; foreign slot and tree retained')
                    try:
                        RAW_CLOSE(fd)
                        try:
                            RAW_FSTAT(fd)
                        except OSError as closed_error:
                            if closed_error.errno != errno.EBADF:
                                raise
                        else:
                            raise FixtureUnknown('fixture close returned without EBADF; tree retained')
                    except BaseException as error:
                        temporary._finalizer.detach()
                        raise FixtureUnknown('fixture original close unconfirmed; tree retained') from error
                temporary.cleanup()

    def os_facade(self, **changes):
        values = {name: getattr(os, name) for name in dir(os)}
        values.update(changes)
        return SimpleNamespace(**values)

    def assert_closed(self, fd):
        with self.assertRaises(OSError) as caught:
            RAW_FSTAT(fd)
        self.assertEqual(errno.EBADF, caught.exception.errno)

    def test_normal_all_originals_close_in_reverse_file_directory_parent_order(self):
        close_all = self.api('_close_initialization_images')
        with self.originals() as (graph, parent, parent_identity, labels):
            calls = []
            def closing(fd):
                calls.append(labels[fd]); RAW_CLOSE(fd); self.assert_closed(fd)
            with mock.patch.object(initialize, 'os', self.os_facade(close=closing)):
                self.assertIsNone(close_all(graph, parent, parent_identity, None))
            self.assertEqual(['file2', 'file1', 'directory2', 'directory1', 'parent'], calls)
            for fd in labels:
                self.assert_closed(fd)

    def test_post_real_close_ordinary_error_is_not_swallowed(self):
        close_one = self.api('_initializer_close_original')
        with self.originals() as (graph, _parent, _parent_identity, _labels):
            fd, captured = graph.files[0][2:4]
            failure = OSError(errno.EIO, 'independent post-real-close error')
            calls = []
            def closing(actual):
                calls.append(actual); RAW_CLOSE(actual); self.assert_closed(actual)
                raise failure
            with mock.patch.object(initialize, 'os', self.os_facade(close=closing)):
                with self.assertRaises(OSError) as caught:
                    close_one(fd, captured)
            self.assertIs(failure, caught.exception)
            self.assertEqual([fd], calls); self.assert_closed(fd)
        close_all = self.api('_close_initialization_images')
        with self.originals() as (graph, parent, parent_identity, labels):
            failure = OSError(errno.EIO, 'literal aggregate ordinary cleanup error')
            calls = []
            def closing(fd):
                label = labels[fd]; calls.append(label)
                RAW_CLOSE(fd); self.assert_closed(fd)
                if label == 'file2': raise failure
            with mock.patch.object(initialize, 'os', self.os_facade(close=closing)):
                selected = close_all(graph, parent, parent_identity, None)
            self.assertIs(failure, selected)
            self.assertEqual(['file2', 'file1', 'directory2', 'directory1', 'parent'], calls)
            for fd in labels: self.assert_closed(fd)

    def test_unknown_original_stat_is_hold_without_close_or_new_adoption(self):
        close_one = self.api('_initializer_close_original')
        with self.originals() as (graph, _parent, _parent_identity, _labels):
            fd, captured = graph.files[0][2:4]
            failure = OSError(errno.EIO, 'independent original identity failure')
            def stat(actual):
                self.assertEqual(fd, actual)
                raise failure
            with mock.patch.object(initialize, 'os', self.os_facade(fstat=stat, close=mock.Mock())) as facade:
                with self.assertRaises((OSError, initialize.EnrollmentInitializeHold)):
                    close_one(fd, captured)
                facade.close.assert_not_called()
            self.assertEqual(captured, identity(RAW_FSTAT(fd)))

    def test_mismatching_foreign_slot_is_hold_and_never_closed(self):
        close_one = self.api('_initializer_close_original')
        with self.originals() as (graph, _parent, _parent_identity, _labels):
            expected = graph.files[0][3]
            foreign, foreign_identity = graph.files[1][2:4]
            self.assertNotEqual(expected[:2], foreign_identity[:2])
            with mock.patch.object(initialize, 'os', self.os_facade(close=mock.Mock())) as facade:
                with self.assertRaises(initialize.EnrollmentInitializeHold):
                    close_one(foreign, expected)
                facade.close.assert_not_called()
            self.assertEqual(foreign_identity, identity(RAW_FSTAT(foreign)))
            self.assertEqual(b'file2', os.pread(foreign, 10, 0))

    def test_body_interrupt_and_preset_cause_win_without_skipping_remaining_originals(self):
        close_all = self.api('_close_initialization_images')
        for kind in (KeyboardInterrupt, SystemExit):
            with self.subTest(body=kind.__name__), self.originals() as (graph, parent, parent_identity, labels):
                body = kind('literal body interrupt'); body_cause = ValueError('literal preset body cause')
                body.__cause__ = body_cause
                tail = KeyboardInterrupt('literal cleanup interrupt')
                tail_cause = ValueError('literal preset cleanup cause'); tail.__cause__ = tail_cause
                ordinary = OSError(errno.EIO, 'literal ordinary cleanup error')
                calls = []
                def closing(fd):
                    label = labels[fd]; calls.append(label)
                    RAW_CLOSE(fd); self.assert_closed(fd)
                    if label == 'file2': raise ordinary
                    if label == 'file1': raise tail
                with mock.patch.object(initialize, 'os', self.os_facade(close=closing)):
                    selected = close_all(graph, parent, parent_identity, body)
                self.assertIs(body, selected); self.assertIs(body_cause, selected.__cause__)
                self.assertIs(tail_cause, tail.__cause__)
                self.assertEqual(['file2', 'file1', 'directory2', 'directory1', 'parent'], calls)
                for fd in labels: self.assert_closed(fd)

    def test_first_cleanup_interrupt_and_preset_cause_win_over_ordinary_and_later_interrupt(self):
        close_all = self.api('_close_initialization_images')
        for kind in (KeyboardInterrupt, SystemExit):
            with self.subTest(first=kind.__name__), self.originals() as (graph, parent, parent_identity, labels):
                first = kind('literal first cleanup interrupt')
                preset = ValueError('literal preset first cleanup cause'); first.__cause__ = preset
                later = SystemExit('literal later cleanup interrupt')
                ordinary = OSError(errno.EIO, 'literal first ordinary cleanup error')
                calls = []
                def closing(fd):
                    label = labels[fd]; calls.append(label)
                    RAW_CLOSE(fd); self.assert_closed(fd)
                    if label == 'file2': raise ordinary
                    if label == 'file1': raise first
                    if label == 'directory2': raise later
                with mock.patch.object(initialize, 'os', self.os_facade(close=closing)):
                    selected = close_all(graph, parent, parent_identity, None)
                self.assertIs(first, selected); self.assertIs(preset, selected.__cause__)
                self.assertEqual(['file2', 'file1', 'directory2', 'directory1', 'parent'], calls)
                for fd in labels: self.assert_closed(fd)


class EnrollmentInitializeParentFolderCloseTests(unittest.TestCase):
    @contextmanager
    def original_folder_case(self, body=None, tail=None):
        from monitor import issue_tracker_local_commit as local
        from monitor import issue_tracker_enrollment_journal as enrollment
        from monitor import issue_tracker_spreadsheet_owner as ownership
        from monitor import issue_tracker_online_target as target
        from monitor import issue_tracker_token_launcher as auth
        temporary = tempfile.TemporaryDirectory(prefix='req7-init-parent-close-')
        root = Path(temporary.name).resolve()
        records, pending, acquired, closed = [], [], [], []
        unknown = [False]

        def register(fd):
            pending.append(fd)
            try:
                captured = identity(RAW_FSTAT(fd))
            except BaseException as error:
                unknown[0] = True
                temporary._finalizer.detach()
                raise FixtureUnknown('parent fixture acquisition identity unknown; tree retained') from error
            records.append((fd, captured)); pending.remove(fd)
            return fd

        def prove_closed(fd):
            try:
                RAW_FSTAT(fd)
            except OSError as error:
                if error.errno == errno.EBADF:
                    return
                unknown[0] = True
                raise FixtureUnknown('parent fixture post-close identity unknown') from error
            unknown[0] = True
            raise FixtureUnknown('parent fixture close returned without EBADF')

        try:
            folder = root / 'journal'; folder.mkdir(mode=0o700)
            for name in ('HEADER', 'NONCES', 'INITIALIZED'):
                path = folder / name; path.write_bytes(name.encode('ascii')); path.chmod(0o600)
            parent = register(RAW_OPEN(root, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_DIRECTORY))
            borrowed = tuple(register(RAW_OPEN(folder / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC))
                             for name in ('HEADER', 'NONCES', 'INITIALIZED'))
            project = SimpleNamespace(lock_fd=parent)
            writer, owner, binding, journal = (object() for _ in range(4))
            authentication = SimpleNamespace(token=object())
            original_identity = SimpleNamespace(sheet_ids=(('literal-sheet', 101),))
            rebuilt = SimpleNamespace(sheet_ids=original_identity.sheet_ids)
            images, prepared = ('literal-full-images',), object()
            original_directory = local._directory
            stat_calls = []

            def directory(actual_parent, name):
                self.assertEqual(parent, actual_parent); self.assertEqual('journal', name)
                fd = original_directory(actual_parent, name)
                register(fd); acquired.append(fd)
                return fd

            def stat(path, *, dir_fd=None, follow_symlinks=True):
                self.assertEqual(1, len(acquired))
                self.assertEqual(acquired[0], dir_fd); self.assertIs(False, follow_symlinks)
                self.assertIn(path, ('HEADER', 'NONCES', 'INITIALIZED'))
                stat_calls.append(path)
                if body is not None:
                    raise body
                return os.stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

            def closing(fd):
                self.assertEqual(acquired, [fd])
                captured = next(row[1] for row in records if row[0] == fd)
                try:
                    current = identity(RAW_FSTAT(fd))
                except BaseException as error:
                    unknown[0] = True
                    raise FixtureUnknown('parent fixture pre-close identity unknown') from error
                if current[:2] != captured[:2]:
                    unknown[0] = True
                    raise FixtureUnknown('parent fixture slot rebound; do not close foreign slot')
                try:
                    RAW_CLOSE(fd)
                except BaseException as error:
                    unknown[0] = True
                    raise FixtureUnknown('parent fixture close unconfirmed') from error
                prove_closed(fd); closed.append(fd)
                if tail is not None:
                    raise tail

            facade = EnrollmentInitializeStrictCloseDirectTests.os_facade(self, stat=stat, close=closing)
            with mock.patch.object(local, '_owner', return_value=project), \
                 mock.patch.object(ownership, 'owner_lock_fd', return_value=parent), \
                 mock.patch.object(auth, 'require_current_owned_project_token', return_value=None), \
                 mock.patch.object(target, 'inspect_project_online_target', return_value=binding), \
                 mock.patch.object(enrollment, 'inspect_enrollment_journal', return_value=journal), \
                 mock.patch.object(enrollment, '_inputs', return_value=(owner, parent, 'journal', None)), \
                 mock.patch.object(initialize, '_originals', return_value=(images, rebuilt, journal, prepared)), \
                 mock.patch.object(local, '_directory', side_effect=directory), \
                 mock.patch.object(initialize, 'os', facade):
                def invoke():
                    return initialize._parent_originals(writer, owner, binding, authentication,
                        original_identity, journal, (*borrowed, parent))
                yield invoke, (project, parent, images, prepared), stat_calls, acquired, closed
            self.assertEqual(1, len(acquired)); self.assertEqual(acquired, closed)
            prove_closed(acquired[0])
            # Only the acquired temporary folder is owned by the callee.
            # The three borrowed originals and parent remain open for caller cleanup.
            for fd, captured in records[:-1]:
                self.assertEqual(captured, identity(RAW_FSTAT(fd)))
        finally:
            if pending or unknown[0]:
                temporary._finalizer.detach()
            else:
                for fd, captured in reversed(records):
                    try:
                        current = identity(RAW_FSTAT(fd))
                    except OSError as error:
                        if error.errno == errno.EBADF:
                            continue
                        temporary._finalizer.detach()
                        raise FixtureUnknown('parent fixture final stat unknown; tree retained') from error
                    if current[:2] != captured[:2]:
                        temporary._finalizer.detach()
                        raise FixtureUnknown('parent fixture final slot rebound; tree retained')
                    try:
                        RAW_CLOSE(fd); prove_closed(fd)
                    except BaseException as error:
                        temporary._finalizer.detach()
                        raise FixtureUnknown('parent fixture final close unknown; tree retained') from error
                temporary.cleanup()

    def test_parent_folder_normal_checks_return_original_tuple_and_close_only_own_folder(self):
        with self.original_folder_case() as (invoke, expected, stat_calls, acquired, closed):
            result = invoke()
            self.assertIs(expected[0], result[0]); self.assertEqual(expected[1], result[1])
            self.assertIs(expected[2], result[2]); self.assertIs(expected[3], result[3])
            self.assertEqual(['HEADER', 'NONCES', 'INITIALIZED'], stat_calls)
            self.assertEqual(acquired, closed)

    def test_parent_folder_body_interrupt_and_preset_cause_win_post_close_tails(self):
        for body_type in (KeyboardInterrupt, SystemExit):
            for tail_type in (OSError, KeyboardInterrupt):
                with self.subTest(body=body_type.__name__, tail=tail_type.__name__):
                    body = body_type('literal parent-original body interrupt')
                    preset = ValueError('literal parent-original preset cause'); body.__cause__ = preset
                    tail = (OSError(errno.EIO, 'literal post-real-close ordinary tail') if tail_type is OSError
                            else KeyboardInterrupt('literal second cleanup interrupt'))
                    tail_preset = ValueError('literal second cleanup preset cause'); tail.__cause__ = tail_preset
                    with self.original_folder_case(body, tail) as (invoke, _expected, stat_calls, acquired, closed):
                        try:
                            invoke()
                        except FixtureUnknown:
                            raise
                        except BaseException as observed:
                            self.assertIs(body, observed, 'PARENT_ORIGINALS_BODY_INTERRUPT_REPLACED_BY_FOLDER_CLOSE')
                            self.assertIs(preset, observed.__cause__)
                            self.assertIs(tail_preset, tail.__cause__)
                        else:
                            self.fail('parent originals must propagate the body interrupt')
                        self.assertEqual(['HEADER'], stat_calls)
                        self.assertEqual(acquired, closed)

    def test_parent_folder_successful_body_does_not_swallow_ordinary_close_error(self):
        failure = OSError(errno.EIO, 'literal successful-body post-close EIO')
        with self.original_folder_case(tail=failure) as (invoke, _expected, stat_calls, acquired, closed):
            with self.assertRaises(OSError) as caught:
                invoke()
            self.assertIs(failure, caught.exception)
            self.assertEqual(['HEADER', 'NONCES', 'INITIALIZED'], stat_calls)
            self.assertEqual(acquired, closed)
