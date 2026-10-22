import copy
import errno
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

REAL_POPEN = subprocess.Popen


class ReadOS:
    def __init__(self, original, fd):
        self.original, self.fd, self.raw = original, fd, bytearray()

    def __getattr__(self, name):
        return getattr(self.original, name)

    def read(self, fd, size):
        result = self.original.read(fd, size)
        if fd == self.fd:
            self.raw.extend(result)
        return result


def gone(process):
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return True
    return False


def run_case(module, mode, *, wait60=False, exhaust=False, slow=False, closefault=False):
    child = Path(__file__).with_name('live_read_v2_literal_child.py')
    if not child.is_file():
        child = Path(__file__).with_name('live_read_v2_literal_child.py.SOURCE.txt')
    started = time.clock_gettime(time.CLOCK_MONOTONIC)
    process = REAL_POPEN([sys.executable, '-B', str(child), 'a' * 64, mode],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         start_new_session=True, close_fds=True, pass_fds=(),
                         env={'LC_ALL': 'C', 'HOME': os.path.expanduser('~')})
    original_os, original_copy, original_close = module.os, module.copy, module._close_stream
    streams = (process.stdin, process.stdout, process.stderr)
    fds = [stream.fileno() for stream in streams]
    close_calls = []
    first_ni = KeyboardInterrupt('synthetic-first-close')
    ni_cause = RuntimeError('synthetic-independent-cause')
    first_ni.__cause__ = ni_cause
    def close_observed(stream):
        close_calls.append(stream)
        original_close(stream)
        if closefault and stream is streams[0]:
            raise first_ni
        if closefault and stream is streams[1]:
            raise OSError(errno.EIO, 'synthetic-later-close')
    module._close_stream = close_observed
    view = ReadOS(original_os, process.stdout.fileno())
    module.os = view
    class SlowCopy:
        @staticmethod
        def deepcopy(value):
            result = copy.deepcopy(value)
            # Real delay after real copy; pump must close while caller waits.
            while time.clock_gettime(time.CLOCK_MONOTONIC) < started + 29.15:
                time.sleep(0.01)
            return result
    if slow:
        module.copy = SlowCopy
    session = None
    data = later = None
    first_error = close_error = None
    observations = []
    try:
        session = module.adopt_owned_read_session(process, started_monotonic=started, nonce='a' * 64)
        try:
            data = session.read_once()
            if wait60:
                # Getter must not renew original sixty. Actual wall-clock run.
                deadline = time.clock_gettime(time.CLOCK_MONOTONIC) + 61.0
                while time.clock_gettime(time.CLOCK_MONOTONIC) < deadline:
                    try:
                        later = session.current_ready()
                    except BaseException as error:
                        first_error = error
                        break
                    time.sleep(0.5)
            elif exhaust:
                for _ in range(1024):
                    later = session.current_ready()
            else:
                later = session.current_ready()
                try:
                    session.read_once()
                except module.SessionHold:
                    observations.append('repeat-refused')
        except BaseException as error:
            first_error = error
        try:
            session.close()
        except BaseException as error:
            close_error = error
        # FIRST result before any fixture fallback; original objects only.
        ebadf = []
        for fd in fds:
            try:
                os.fstat(fd)
            except OSError as error:
                ebadf.append(error.errno == errno.EBADF)
            else:
                ebadf.append(False)
        first = dict(elapsed=time.clock_gettime(time.CLOCK_MONOTONIC) - started,
                     returncode=process.poll(), groupgone=gone(process),
                     closed=[stream.closed for stream in streams], ebadf=ebadf)
    finally:
        module.os, module.copy, module._close_stream = original_os, original_copy, original_close
        if process.poll() is None:
            process.kill()  # Retained own handle only; not product evidence.
            process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
    frames = [json.loads(line) for line in bytes(view.raw).splitlines() if line]
    return dict(data=data, later=later, error=first_error, close_error=close_error,
                first=first, frames=frames, observations=observations,
                close_calls=[streams.index(stream) for stream in close_calls],
                ni=first_ni, ni_cause=ni_cause)


class FixedReadV2WorkflowTests(unittest.TestCase):
    def test_real_owned_child_capacity_original_clocks_failures_and_cleanup(self):
        spec = importlib.util.find_spec('monitor.issue_tracker_read_live_session_v2')
        self.assertIsNotNone(spec, 'MISSING_FIXED_READ_V2_SESSION')
        module = importlib.import_module('monitor.issue_tracker_read_live_session_v2')
        expected = {'unicode': '界' * 690000, 'literal': ['A', 7, None, True]}
        healthy = run_case(module, 'delayed-check')
        self.assertEqual(healthy['data'], expected)
        self.assertEqual(healthy['later'], expected)
        self.assertIsNone(healthy['error'])
        self.assertIsNone(healthy['close_error'])
        self.assertEqual(healthy['observations'], ['repeat-refused'])
        self.assertEqual(healthy['first']['closed'], [True, True, True])
        self.assertEqual(healthy['first']['ebadf'], [True, True, True])
        self.assertEqual(healthy['close_calls'], [0, 1, 2])
        self.assertEqual(healthy['first']['returncode'], 0)
        self.assertTrue(healthy['first']['groupgone'])
        self.assertEqual([f['event'] for f in healthy['frames']], ['READY', 'LIVE', 'CLOSED'])
        self.assertEqual(set(healthy['frames'][1]), {'v', 'nonce', 'event', 'serial', 'digest'})
        self.assertEqual(healthy['frames'][1]['serial'], 1)
        self.assertEqual(healthy['frames'][0]['expires_at'] - healthy['frames'][0]['ready_at'], 60.0)
        for mode in ('wrong-serial', 'wrong-digest', 'stderr-over', 'future', 'expired', 'ready-extra', 'closed-extra'):
            result = run_case(module, mode)
            with self.subTest(mode=mode):
                self.assertTrue(isinstance(result['error'], module.SessionHold) or
                                isinstance(result['close_error'], module.SessionHold))
                self.assertTrue(result['first']['groupgone'])
                self.assertIsNotNone(result['first']['returncode'])
                self.assertEqual(result['first']['closed'], [True, True, True])
        exhausted = run_case(module, 'good', exhaust=True)
        self.assertIsInstance(exhausted['error'], module.SessionHold)
        self.assertEqual(sum(f['event'] == 'READY' for f in exhausted['frames']), 1)
        self.assertLess(sum(f['event'] == 'LIVE' for f in exhausted['frames']), 1024)
        self.assertTrue(exhausted['first']['groupgone'])
        self.assertEqual(exhausted['first']['closed'], [True, True, True])
        slow = run_case(module, 'good', slow=True)
        self.assertIsNone(slow['data'])
        self.assertIsInstance(slow['error'], module.SessionHold)
        self.assertLess(slow['first']['elapsed'], 30.0)
        self.assertTrue(slow['first']['groupgone'])
        self.assertEqual(slow['first']['closed'], [True, True, True])
        silent = run_case(module, 'silent')
        self.assertIsNone(silent['data'])
        self.assertIsInstance(silent['error'], module.SessionHold)
        self.assertGreater(silent['first']['elapsed'], 27.5)
        self.assertLess(silent['first']['elapsed'], 30.0)
        self.assertTrue(silent['first']['groupgone'])
        self.assertEqual(silent['first']['closed'], [True, True, True])
        fault = run_case(module, 'good', closefault=True)
        self.assertEqual(fault['data'], expected)
        self.assertIs(fault['close_error'], fault['ni'])
        self.assertIs(fault['close_error'].__cause__, fault['ni_cause'])
        self.assertEqual(fault['close_calls'], [0, 1, 2])
        self.assertEqual(fault['first']['ebadf'], [True, True, True])
        self.assertTrue(fault['first']['groupgone'])
        live = run_case(module, 'good', wait60=True)
        self.assertEqual(live['data'], expected)
        self.assertIsInstance(live['error'], module.SessionHold)
        ready = live['frames'][0]
        self.assertGreaterEqual(live['first']['elapsed'], 59.5)
        self.assertLess(live['first']['elapsed'], 63.0)
        self.assertEqual(ready['expires_at'] - ready['ready_at'], 60.0)
        self.assertEqual(sum(f['event'] == 'READY' for f in live['frames']), 1)
        self.assertTrue(live['first']['groupgone'])
        self.assertEqual(live['first']['closed'], [True, True, True])
