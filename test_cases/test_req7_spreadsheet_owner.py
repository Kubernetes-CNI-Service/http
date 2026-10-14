"""Actual local flock/fd workflows with synthetic root metadata, no root writes."""
from contextlib import ExitStack, contextmanager
from dataclasses import replace
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

if len(sys.argv) > 1 and sys.argv[1] in ('--owned-contender', '--owned-crash-parent'):
    sys.path.insert(0, sys.argv[3])
    sys.path.insert(0, str(Path(sys.argv[3]) / 'tools'))
import test_cases
ROOT = Path(test_cases.__file__).resolve().parents[1]
SOURCE = Path(__file__).resolve().parents[1] / 'monitor/issue_tracker_spreadsheet_owner.py'
TARGET = 'synthetic_spreadsheet_id_0001'


def load():
    if not SOURCE.is_file(): raise AssertionError('spreadsheet-wide persistent OS owner missing')
    spec = importlib.util.spec_from_file_location('monitor.issue_tracker_spreadsheet_owner', SOURCE)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    import monitor
    monitor.issue_tracker_spreadsheet_owner = module
    return module


def binding(target=TARGET):
    from monitor.issue_tracker_online_target import OnlineTargetBinding
    return OnlineTargetBinding(target, 'a' * 64, 'b' * 64)


@contextmanager
def fixture(root, fault=None):
    # The only path redirection is this test fixture; the shipped API has no
    # path, UID, TTL, repair or lock override argument. Native flock is real.
    real_open, real_fstat, real_stat = os.open, os.fstat, os.stat
    def metadata(value):
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_atime_ns', 'st_mtime_ns', 'st_ctime_ns')
        result = SimpleNamespace(**{name: getattr(value, name) for name in fields})
        result.st_uid = 0
        if fault == 'uid': result.st_uid = 501
        return result
    def opening(name, flags, *args, **kwargs):
        return real_open(root if name == '/' else name, flags, *args, **kwargs)
    with ExitStack() as stack:
        stack.enter_context(mock.patch('os.geteuid', return_value=0))
        stack.enter_context(mock.patch('os.getuid', return_value=0))
        stack.enter_context(mock.patch('os.open', side_effect=opening))
        stack.enter_context(mock.patch('os.fstat', side_effect=lambda fd: metadata(real_fstat(fd))))
        stack.enter_context(mock.patch('os.stat', side_effect=lambda *a, **k: metadata(real_stat(*a, **k))))
        yield


@contextmanager
def scoped_fixture(root, module):
    """Synthetic root metadata ONLY at the ownership module's OS boundary.

    C6/source/workbook modules keep their actual OS identities and absolute
    paths. Native flock/FD/fsync remain real; this fixture grants no root or
    real-environment proof and does not mutate the shared os module.
    """
    facade = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
    def metadata(value):
        # Keep every original field access, in its original order. Explicit
        # copying avoids the repeated dictionary/getattr loop in this scoped
        # fixture without caching native metadata or omitting an OS check.
        result = SimpleNamespace(st_dev=value.st_dev, st_ino=value.st_ino,
            st_mode=value.st_mode, st_uid=value.st_uid, st_gid=value.st_gid,
            st_nlink=value.st_nlink, st_size=value.st_size,
            st_mtime_ns=value.st_mtime_ns, st_ctime_ns=value.st_ctime_ns)
        result.st_uid = 0
        return result
    facade.geteuid = lambda: 0
    facade.open = lambda name, flags, *args, **kwargs: os.open(root if name == '/' else name, flags, *args, **kwargs)
    facade.fstat = lambda fd: metadata(os.fstat(fd))
    facade.stat = lambda *args, **kwargs: metadata(os.stat(*args, **kwargs))
    with mock.patch.object(module, 'os', facade): yield


class Req7SpreadsheetOwnerTests(unittest.TestCase):
    def test_global_root_metadata_fixture_preserves_native_atime_for_fault_restoration(self):
        # Independent native stat is the expectation, before synthetic root
        # metadata is installed. The fixture cannot invent or omit timestamps
        # needed by an actual owned-file fault/restoration operation.
        path=self.root/'owned-atime-source';path.write_bytes(b'literal native timestamp source\n')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            # Native open may advance atime. Capture the independent original
            # after that real acquisition, not a stale pre-open timestamp.
            original=os.fstat(fd)
            with fixture(self.root):
                named=os.stat(path,follow_symlinks=False);held=os.fstat(fd)
                self.assertTrue(hasattr(named,'st_atime_ns'),'synthetic named metadata must keep native access timestamp')
                self.assertTrue(hasattr(held,'st_atime_ns'),'synthetic held metadata must keep native access timestamp')
                self.assertEqual(original.st_atime_ns,named.st_atime_ns)
                self.assertEqual(original.st_atime_ns,held.st_atime_ns)
                self.assertEqual((original.st_ino,original.st_mtime_ns,original.st_ctime_ns),
                    (held.st_ino,held.st_mtime_ns,held.st_ctime_ns))
                self.assertEqual(0,named.st_uid)
        finally:os.close(fd)

    def setUp(self):
        self.module = load(); self.temp = tempfile.TemporaryDirectory(prefix='req7-sheet-owner-')
        self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name).resolve()
        self.locks = self.root / 'var/lib/http-ztp-container/issue-tracker'
        self.locks.mkdir(parents=True, mode=0o700); self.locks.chmod(0o700)
        self.name = hashlib.sha256(TARGET.encode('ascii')).hexdigest() + '.lock'

    def test_exact_spreadsheet_identity_not_project_policy_or_sheet_controls_exclusion(self):
        with fixture(self.root), self.module.spreadsheet_owner(binding()) as token:
            fd = self.module.owner_lock_fd(token, binding())
            self.assertIs(type(fd), int); self.assertFalse(os.get_inheritable(fd))
            self.assertEqual([self.name], os.listdir(self.locks))
            self.assertEqual(b'', (self.locks / self.name).read_bytes())
            self.assertEqual(0o600, (self.locks / self.name).stat().st_mode & 0o777)
            different_project = replace(binding(), policy_sha256='c' * 64, allowlist_sha256='d' * 64)
            with self.assertRaises(self.module.SpreadsheetOwnerHold):
                with self.module.spreadsheet_owner(different_project): self.fail('same spreadsheet acquired twice')
            with self.module.spreadsheet_owner(binding(TARGET + '_other')) as other:
                self.assertNotEqual(fd, self.module.owner_lock_fd(other, binding(TARGET + '_other')))
            with self.assertRaises(self.module.SpreadsheetOwnerHold): self.module.owner_lock_fd(token, different_project)
        with self.assertRaises(self.module.SpreadsheetOwnerHold): self.module.owner_lock_fd(token, binding())

    def test_scoped_synthetic_root_fixture_keeps_shared_os_and_native_identity_unchanged(self):
        real_uid, real_euid, actual_stat = os.getuid(), os.geteuid(), self.root.stat()
        with scoped_fixture(self.root, self.module), self.module.spreadsheet_owner(binding()) as token:
            self.assertEqual(real_uid, os.getuid()); self.assertEqual(real_euid, os.geteuid())
            self.assertEqual(actual_stat.st_uid, self.root.stat().st_uid)
            fd = self.module.owner_lock_fd(token,binding())
            self.assertEqual(real_uid, os.fstat(fd).st_uid)
            self.assertIsNot(self.module.os, os)
            with self.assertRaises(self.module.SpreadsheetOwnerHold):
                with self.module.spreadsheet_owner(binding()): self.fail('native flock exclusion bypassed')
        self.assertIs(self.module.os, os)

    def test_scoped_root_metadata_copies_every_literal_native_field_and_only_overrides_uid(self):
        """Equivalence control for fixture cost, not root/real-environment proof."""
        literal = SimpleNamespace(st_dev=11, st_ino=12, st_mode=0o100600,
            st_uid=501, st_gid=20, st_nlink=1, st_size=655,
            st_mtime_ns=111111, st_ctime_ns=222222)
        expected = {'st_dev':11, 'st_ino':12, 'st_mode':0o100600,
            'st_uid':0, 'st_gid':20, 'st_nlink':1, 'st_size':655,
            'st_mtime_ns':111111, 'st_ctime_ns':222222}
        with mock.patch.object(os, 'fstat', return_value=literal) as original:
            with scoped_fixture(self.root, self.module):
                observed = self.module.os.fstat(12345)
            original.assert_called_once_with(12345)
        self.assertEqual(expected, vars(observed))
        self.assertEqual(501, literal.st_uid)
        self.assertIs(self.module.os, os)

    def test_fixed_root_missing_or_nonroot_never_creates_repairs_or_uses_environment_override(self):
        with mock.patch('os.geteuid', return_value=501), mock.patch('os.open') as opening:
            with self.assertRaises(self.module.SpreadsheetOwnerHold):
                with self.module.spreadsheet_owner(binding()): pass
        opening.assert_not_called()
        self.locks.rmdir()
        with mock.patch.dict(os.environ, {'REQ7_LOCK_ROOT': str(self.root), 'TMPDIR': str(self.root)}), fixture(self.root):
            with self.assertRaises(self.module.SpreadsheetOwnerHold):
                with self.module.spreadsheet_owner(binding()): pass
        self.assertFalse(self.locks.exists()); self.assertEqual([], os.listdir(self.locks.parent))

    def test_binding_wrong_type_scalar_digest_or_target_refuses_before_filesystem(self):
        for bad in (None, object(), replace(binding(), spreadsheet_id='../escape'),
                    replace(binding(), spreadsheet_id='x' * 4097), replace(binding(), policy_sha256='?'),
                    replace(binding(), allowlist_sha256=True)):
            with self.subTest(bad_type=type(bad).__name__), fixture(self.root), mock.patch('os.open') as opening:
                with self.assertRaises(self.module.SpreadsheetOwnerHold):
                    with self.module.spreadsheet_owner(bad): pass
                opening.assert_not_called()
        self.assertEqual([], os.listdir(self.locks))

    def test_symlink_hardlink_nonempty_nonprivate_or_foreign_lock_is_preserved_and_denied(self):
        for fault in ('symlink', 'hardlink', 'bytes', 'mode', 'uid'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix='req7-unsafe-lock-') as path:
                root = Path(path).resolve(); locks = root / 'var/lib/http-ztp-container/issue-tracker'
                locks.mkdir(parents=True, mode=0o700); lock = locks / self.name
                saved = root / 'preserved'; saved.write_bytes(b''); saved.chmod(0o600)
                if fault == 'symlink': lock.symlink_to(saved)
                elif fault == 'hardlink': os.link(saved, lock)
                else: lock.write_bytes(b'foreign' if fault == 'bytes' else b''); lock.chmod(0o644 if fault == 'mode' else 0o600)
                with fixture(root, 'uid' if fault == 'uid' else None), self.assertRaises(self.module.SpreadsheetOwnerHold) as caught:
                    with self.module.spreadsheet_owner(binding()): pass
                self.assertEqual('req7_spreadsheet_owner_denied', str(caught.exception))
                self.assertIsNone(caught.exception.__context__)
                self.assertTrue(lock.exists()); self.assertEqual(b'', saved.read_bytes())
                if fault == 'bytes': self.assertEqual(b'foreign', lock.read_bytes())

    def test_fresh_checks_reject_lock_or_ancestor_displacement_and_preserve_original(self):
        for fault in ('lock', 'ancestor', 'mode'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix='req7-displaced-lock-') as path:
                root = Path(path).resolve(); locks = root / 'var/lib/http-ztp-container/issue-tracker'
                locks.mkdir(parents=True, mode=0o700)
                with fixture(root), self.module.spreadsheet_owner(binding()) as token:
                    original = os.fstat(self.module.owner_lock_fd(token, binding())).st_ino
                    if fault == 'lock':
                        (locks / self.name).rename(locks / 'preserved'); (locks / self.name).write_bytes(b''); (locks / self.name).chmod(0o600)
                    elif fault == 'ancestor':
                        locks.rename(locks.with_name('preserved')); locks.mkdir(mode=0o700)
                    else: (locks / self.name).chmod(0o644)
                    with self.assertRaises(self.module.SpreadsheetOwnerHold): self.module.owner_lock_fd(token, binding())
                    preserved = locks / ('preserved' if fault == 'lock' else self.name)
                    if fault == 'ancestor': preserved = locks.with_name('preserved') / self.name
                    self.assertEqual(original, preserved.stat().st_ino)

    def test_mtime_age_never_authorizes_takeover_or_unlink_and_same_inode_is_reused(self):
        with fixture(self.root), self.module.spreadsheet_owner(binding()) as token:
            inode = os.fstat(self.module.owner_lock_fd(token, binding())).st_ino
            os.utime(self.locks / self.name, (1, 1))
            fd = os.open(self.locks / self.name, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError): fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally: os.close(fd)
        with fixture(self.root), self.module.spreadsheet_owner(binding()) as token:
            self.assertEqual(inode, os.fstat(self.module.owner_lock_fd(token, binding())).st_ino)

    def test_acquisition_interruption_closes_every_owned_descriptor_without_unlock_or_removal(self):
        actual_open = os.open; descriptors = []
        def opening(*args, **kwargs):
            fd = actual_open(*args, **kwargs); descriptors.append(fd); return fd
        try:
            with mock.patch('os.open', side_effect=opening), fixture(self.root), mock.patch('os.fsync', side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    with self.module.spreadsheet_owner(binding()): self.fail('interrupted acquisition issued a token')
            self.assertEqual(6, len(descriptors))
            leaked = []
            for fd in descriptors:
                try: os.fstat(fd); leaked.append(fd)
                except OSError: pass
            self.assertEqual([], leaked, 'interrupted acquisition retained owned descriptors/kernel lock')
            self.assertTrue((self.locks / self.name).is_file())
            self.assertEqual({}, self.module._ACTIVE)
        finally:
            # Diagnostic cleanup touches ONLY descriptors opened above in this
            # interrupted fixture; no external PID or lock-file deletion.
            for fd in descriptors:
                try: os.close(fd)
                except OSError: pass

    def test_revocation_precedes_close_no_explicit_unlock_and_forked_token_cannot_be_used(self):
        actual_close = os.close; seen = []; actual_flock = fcntl.flock
        fd = None
        def closing(value):
            if value == fd:
                with self.assertRaises(self.module.SpreadsheetOwnerHold): self.module.owner_lock_fd(token, binding())
                seen.append(value)
            actual_close(value)
        def flocking(value, operation):
            self.assertNotEqual(fcntl.LOCK_UN, operation)
            return actual_flock(value, operation)
        with fixture(self.root), mock.patch('os.close', side_effect=closing), mock.patch('fcntl.flock', side_effect=flocking):
            with self.module.spreadsheet_owner(binding()) as token:
                fd = self.module.owner_lock_fd(token, binding())
                with mock.patch('os.getpid', return_value=-1), self.assertRaises(self.module.SpreadsheetOwnerHold):
                    self.module.owner_lock_fd(token, binding())
                self.assertFalse(hasattr(token, 'permit'))
        self.assertEqual([fd], seen)

    def test_manifest_real_workflow_not_run_card_and_manual_preserve_non_send_scope(self):
        manifest = json.loads((ROOT / 'test_cases/script_test_manifest.json').read_text())
        source = 'monitor/issue_tracker_spreadsheet_owner.py'; test = 'test_cases.test_req7_spreadsheet_owner'
        self.assertEqual(source, manifest['scripts'].get(source))
        self.assertTrue(any(source in rule['paths'] and test in rule['tests'] for rule in manifest['test_rules']))
        self.assertTrue(any({source, 'monitor/issue_tracker_send_intent.py', 'monitor/issue_tracker_local_commit.py'} <= set(rule['members'])
                            and test in rule['tests'] for rule in manifest['workflows']))
        card = (ROOT / 'test_cases/REAL_ENVIRONMENT.md').read_text()
        start = card.index('## TC-REAL-REQ7-SPREADSHEET-OWNER-001'); end = card.find('\n## ', start + 1)
        card = card[start:] if end < 0 else card[start:end]
        for required in ('NOT RUN / REAL_ENV REQUIRED', '前置条件', '证据', '清理', '父', '跨项目', '不删除'):
            self.assertIn(required, card)
        spec = importlib.util.spec_from_file_location('req7_sheet_owner_manual', ROOT / 'tools/update-user-manual.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        profile = module.script_profile(ROOT, source)
        for field, value in (('environment', '未安装'), ('scenario', '跨项目'), ('success', '不授予'), ('success', '整个 REQ7')):
            self.assertIn(value, profile[field])


class Req7SpreadsheetOwnerWorkflowTests(unittest.TestCase):
    setUp = Req7SpreadsheetOwnerTests.setUp
    def test_two_real_project_journals_contend_on_one_spreadsheet_not_their_c6_roots(self):
        from monitor.issue_tracker_local_commit import create_local_commit_store, writer_owner
        from monitor.issue_tracker_send_intent import prepare_send_intent, record_compiled_attempt_intent
        from monitor.issue_tracker_send_unit import freeze_send_unit
        from test_cases.test_req7_send_unit import inputs
        projects = []
        for name in ('project-a', 'project-b'):
            project = self.root / name; project.mkdir(mode=0o700); pub = project / 'publication'; pub.mkdir(mode=0o700)
            create_local_commit_store(project, pub); projects.append((project, pub))
        with writer_owner(*projects[0]) as local_a, writer_owner(*projects[1]) as local_b:
            with ExitStack() as owners:
                with fixture(self.root):
                    global_a = owners.enter_context(self.module.spreadsheet_owner(binding()))
                    self.module.owner_lock_fd(global_a, binding())
                # Synthetic global-root checks must not redirect the separate
                # real C-6 project ancestry walker or change its owner policy.
                unit = freeze_send_unit(**inputs()); prepare_send_intent(local_a, unit)
                self.assertEqual(1, record_compiled_attempt_intent(local_a, unit).attempt_count)
                with fixture(self.root), self.assertRaises(self.module.SpreadsheetOwnerHold):
                    with self.module.spreadsheet_owner(replace(binding(), policy_sha256='f' * 64)):
                        prepare_send_intent(local_b, unit)
                self.assertFalse((projects[1][0] / '.tracker/remote-actions').exists())
        self.assertTrue((projects[0][0] / '.tracker/remote-attempts' / unit.unit_id / 'ATTEMPT-1').is_file())

    def test_independent_cold_process_cannot_acquire_live_owner_and_reuses_persistent_inode_after_exit(self):
        command = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--owned-contender', str(self.root), str(ROOT)]
        with fixture(self.root), self.module.spreadsheet_owner(binding()) as token:
            inode = os.fstat(self.module.owner_lock_fd(token, binding())).st_ino
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            self.assertEqual(3, result.returncode, result.stderr); self.assertEqual(b'denied\n', result.stdout)
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr); self.assertEqual(b'owned\n', result.stdout)
        self.assertEqual(inode, (self.locks / self.name).stat().st_ino)

    def test_parent_exit_preserves_actual_inherited_kernel_lock_until_owned_child_is_reaped(self):
        child = None
        try:
            with fixture(self.root), self.module.spreadsheet_owner(binding()) as token:
                fd = self.module.owner_lock_fd(token, binding())
                code = "import os,sys; os.fstat(int(sys.argv[1])); os.write(1,b'held\\n'); sys.stdin.buffer.read(1)"
                child = subprocess.Popen([sys.executable, '-I', '-B', '-c', code, str(fd)],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    close_fds=True, pass_fds=(fd,), start_new_session=True)
                import selectors
                with selectors.DefaultSelector() as ready:
                    ready.register(child.stdout, selectors.EVENT_READ)
                    self.assertTrue(ready.select(5), 'owned inherited-lock child failed readiness')
                self.assertEqual(b'held\n', child.stdout.readline())
            # Production must close, not LOCK_UN: unlocking a shared open-file
            # description here would silently release the child's lock too.
            with fixture(self.root), self.assertRaises(self.module.SpreadsheetOwnerHold):
                with self.module.spreadsheet_owner(binding()): self.fail('inherited live lock was released')
            child.stdin.close(); child.wait(timeout=5)
            self.assertEqual(0, child.returncode); self.assertEqual(b'', child.stderr.read())
            with fixture(self.root), self.module.spreadsheet_owner(binding()) as fresh:
                self.assertIs(type(self.module.owner_lock_fd(fresh, binding())), int)
        finally:
            if child is not None:
                if child.stdin and not child.stdin.closed: child.stdin.close()
                child.wait(timeout=5)
                for stream in (child.stdout, child.stderr): stream.close()

    def test_real_parent_process_death_does_not_release_its_live_orphan_child_lock(self):
        import selectors
        import time
        read_fd, release_fd = os.pipe(); parent = None
        try:
            parent = subprocess.Popen([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                '--owned-crash-parent', str(self.root), str(ROOT), str(read_fd)], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, pass_fds=(read_fd,), start_new_session=True)
            os.close(read_fd); read_fd = None
            data = bytearray(); deadline = time.monotonic() + 5
            with selectors.DefaultSelector() as ready:
                ready.register(parent.stdout, selectors.EVENT_READ)
                while data.count(b'\n') < 2:
                    remaining = deadline - time.monotonic(); self.assertGreater(remaining, 0, 'owned parent/orphan readiness missing')
                    self.assertTrue(ready.select(remaining), 'owned parent/orphan readiness expired')
                    chunk = os.read(parent.stdout.fileno(), 1024); self.assertTrue(chunk); data.extend(chunk)
            self.assertEqual({b'parent-exiting', b'orphan-held'}, set(bytes(data).splitlines()))
            parent.wait(timeout=5); self.assertEqual(0, parent.returncode)
            with fixture(self.root), self.assertRaises(self.module.SpreadsheetOwnerHold):
                with self.module.spreadsheet_owner(binding()): self.fail('parent death released live orphan lock')
            os.close(release_fd); release_fd = None  # EOF releases only this owned child.
            stdout, stderr = parent.communicate(timeout=5)
            self.assertEqual(b'', stdout); self.assertEqual(b'', stderr)
            with fixture(self.root), self.module.spreadsheet_owner(binding()) as token:
                self.assertIs(type(self.module.owner_lock_fd(token, binding())), int)
        finally:
            for fd in (read_fd, release_fd):
                if fd is not None: os.close(fd)
            if parent is not None:
                parent.communicate(timeout=5)
                for stream in (parent.stdout, parent.stderr): stream.close()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--owned-crash-parent':
        owner = load(); control = int(sys.argv[4])
        with fixture(Path(sys.argv[2])), owner.spreadsheet_owner(binding()) as token:
            fd = owner.owner_lock_fd(token, binding())
            code = "import os,sys; os.fstat(int(sys.argv[1])); os.write(1,b'orphan-held\\n'); os.read(int(sys.argv[2]),1)"
            subprocess.Popen([sys.executable, '-I', '-B', '-c', code, str(fd), str(control)],
                stdin=subprocess.DEVNULL, close_fds=True, pass_fds=(fd, control), start_new_session=True)
            os.write(1, b'parent-exiting\n')
            os._exit(0)  # Test-owned abrupt death, no context finally/unlock.
    if len(sys.argv) > 1 and sys.argv[1] == '--owned-contender':
        owner = load()
        try:
            with fixture(Path(sys.argv[2])), owner.spreadsheet_owner(binding()):
                os.write(1, b'owned\n')
        except owner.SpreadsheetOwnerHold:
            os.write(1, b'denied\n'); raise SystemExit(3)
    else: unittest.main()
