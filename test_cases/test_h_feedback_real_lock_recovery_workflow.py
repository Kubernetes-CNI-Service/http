"""Private filesystem workflow; no real processes, devices, or service actions."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import errno
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load_feedback():
    spec = importlib.util.spec_from_file_location(
        'h_real_lock_feedback', ROOT / 'ztp/optimize/feedback.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def version(path):
    info = path.lstat()
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            path.read_bytes())


def independently_busy(path):
    descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        else:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            return False
    finally:
        os.close(descriptor)


class FeedbackRealLockRecoveryWorkflowTests(unittest.TestCase):
    def exercise(self, *, invalid_pid):
        feedback = load_feedback()
        lock_module = sys.modules[feedback.deployment_lock.__module__]
        finish_module = sys.modules[lock_module.assert_writer_allowed.__module__]
        runtime = sys.modules[feedback.stop_native_ztp_monitors.__module__]
        real_acquire = lock_module.acquire_lock_descriptor
        real_revalidate = feedback._revalidate_sample_plan
        real_recover = feedback.recover_global_writeback_state
        events, acquired, signals, recovery_fds = [], [], [], []
        stop_results, stop_errors = [], []
        with tempfile.TemporaryDirectory(prefix='h-feedback-owned-') as temporary:
            workspace = Path(temporary) / 'http'
            workspace.mkdir()
            (workspace / 'ztp/optimize').mkdir(parents=True)
            proc = Path(temporary) / 'proc'
            proc.mkdir()
            finish = Path(temporary) / 'finished-state'
            authority = workspace / '01-global.yaml'
            authority.write_bytes(b'common: {}\n')
            state = workspace / '99-output-ztp/optimize/.feedback-global-writeback-state.json'
            state.parent.mkdir(parents=True)
            state.write_text(json.dumps({
                'authority_path': str(authority.absolute()),
                'expected_after_sha256': hashlib.sha256(b'common: {}\n').hexdigest(),
                'published': True, 'schema': 1,
                'timestamp': '2026-10-20T00:00:00Z',
            }, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
            state.chmod(0o600)
            pid = workspace / 'DAY0-Prepare/project/99-output-ztp/ztp-monitor.pid'
            if invalid_pid:
                pid.parent.mkdir(parents=True)
                pid.write_bytes(b'not-a-pid\n')
                pid_before = version(pid)
            state_before, authority_before = version(state), version(authority)
            lock_path = workspace / '.deployment.lock'
            lock_path.write_bytes(b'')

            def acquire(*args, **kwargs):
                fd = real_acquire(*args, **kwargs)
                status = os.fstat(fd)
                acquired.append((fd, status.st_dev, status.st_ino))
                events.append('lock-acquired')
                return fd

            def revalidate(plan):
                events.append(('revalidate', independently_busy(lock_path)))
                return real_revalidate(plan)

            def signal_forbidden(*args):
                signals.append(args)
                raise AssertionError('real or synthetic signal attempts forbidden')

            def stop(root):
                events.append(('runtime-stop', independently_busy(lock_path), version(state) == state_before))
                try:
                    result = runtime.stop_native_ztp_monitors(
                        root, proc_root=proc, kill=signal_forbidden)
                except Exception as exc:
                    codes = []
                    traceback = exc.__traceback__
                    while traceback is not None:
                        codes.append(traceback.tb_frame.f_code)
                        traceback = traceback.tb_next
                    stop_errors.append((type(exc), tuple(codes)))
                    raise
                stop_results.append(result)
                return result

            def recover(*args, **kwargs):
                fd = kwargs['held_lock_fd']
                status = os.fstat(fd)
                recovery_fds.append((fd, status.st_dev, status.st_ino))
                events.append(('recovery', independently_busy(lock_path)))
                result = real_recover(*args, **kwargs)
                events.append(('recovery-result', result))
                return result

            output, errors = io.StringIO(), io.StringIO()
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(feedback, '__file__', str(workspace / 'ztp/optimize/feedback.py')))
                stack.enter_context(mock.patch.object(finish_module, 'FINISH_STATE_ROOT', finish))
                stack.enter_context(mock.patch.dict(os.environ))
                os.environ.pop('HTTP_DEPLOYMENT_LOCK_FD', None)
                stack.enter_context(mock.patch.object(lock_module, 'acquire_lock_descriptor', acquire))
                stack.enter_context(mock.patch.object(feedback, '_revalidate_sample_plan', revalidate))
                stack.enter_context(mock.patch.object(feedback, 'stop_native_ztp_monitors', stop))
                stack.enter_context(mock.patch.object(feedback, 'recover_global_writeback_state', recover))
                stack.enter_context(redirect_stdout(output))
                stack.enter_context(redirect_stderr(errors))
                argv = ['--recover-global-writeback-state', '--global-config', str(authority)]
                if invalid_pid:
                    with self.assertRaises(SystemExit) as raised:
                        feedback.main(argv)
                    self.assertEqual(2, raised.exception.code)
                else:
                    self.assertEqual(0, feedback.main(argv))

            # Assertions remain outside production exception handlers and owners.
            self.assertEqual([], signals)
            self.assertEqual(1, len(acquired))
            fd, device, inode = acquired[0]
            self.assertEqual((device, inode), (lock_path.stat().st_dev, lock_path.stat().st_ino))
            with self.assertRaises(OSError) as closed:
                os.fstat(fd)
            self.assertEqual(errno.EBADF, closed.exception.errno)
            self.assertFalse(independently_busy(lock_path))
            self.assertEqual(authority_before, version(authority))
            self.assertFalse(finish.exists())
            self.assertEqual([], list(proc.iterdir()))
            if invalid_pid:
                self.assertEqual(['lock-acquired', ('revalidate', True),
                                  ('runtime-stop', True, True)], events)
                self.assertEqual([], recovery_fds)
                self.assertEqual([], stop_results)
                self.assertEqual(1, len(stop_errors))
                self.assertIs(runtime.RuntimeContractError, stop_errors[0][0])
                self.assertIn(runtime._native_monitor_pid_files.__code__, stop_errors[0][1])
                self.assertEqual(state_before, version(state))
                self.assertEqual(pid_before, version(pid))
                self.assertNotIn('[RECOVER]', output.getvalue())
                self.assertNotIn('Traceback', errors.getvalue())
            else:
                self.assertEqual(['lock-acquired', ('revalidate', True),
                                  ('runtime-stop', True, True), ('recovery', True),
                                  ('recovery-result', True)], events)
                self.assertEqual(acquired, recovery_fds)
                self.assertEqual([()], stop_results)
                self.assertEqual([], stop_errors)
                self.assertFalse(state.exists())
                self.assertIn('[RECOVER] validated published state cleared', output.getvalue())
                self.assertEqual('', errors.getvalue())

    def test_real_lock_real_stop_then_real_private_recovery(self):
        self.exercise(invalid_pid=False)

    def test_invalid_private_pid_prevents_recovery_and_releases_real_lock(self):
        self.exercise(invalid_pid=True)
