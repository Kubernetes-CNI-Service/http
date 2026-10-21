"""NOTRUN event-clock direct only; generated private NV stub, never real NV/SSH."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

from test_cases import native_os_stub_sources


class NativeOsEventClockDirectTests(unittest.TestCase):
    def test_real_generated_private_nv_event_is_between_parent_kernel_raw_samples(self):
        self.assertTrue(callable(getattr(time, 'clock_gettime_ns', None)),
                        'explicit kernel event clock is a test-platform precondition')
        self.assertTrue(hasattr(time, 'CLOCK_MONOTONIC_RAW'),
                        'kernel RAW clock required; no wall-clock or implicit-clock fallback')
        raw_clock = time.CLOCK_MONOTONIC_RAW
        temporary = tempfile.mkdtemp(prefix='native-os-event-clock-', dir='/private/tmp')
        root = Path(temporary).resolve()
        print('IBSW_NATIVE_OS_EVENT_CLOCK_OWNED_ROOT=' + str(root), flush=True)
        remote = root / '.ibsw-event-clock-witness'
        remote.mkdir(mode=0o700)
        executable = root / 'private-nv'
        # Only this exact generated local fixture executable is launched.
        # SSH/SCP generated entries are never written or executed here.
        executable.write_bytes(native_os_stub_sources.executable_sources()['private-nv'])
        executable.chmod(0o700)
        environment = dict(PATH='/usr/bin:/bin', LC_ALL='C',
                           HOME=str(root), TMPDIR=str(remote),
                           PYTHONDONTWRITEBYTECODE='1')
        expected = ['action', 'fetch', 'system', 'image', 'file:///synthetic/image.bin']
        before = time.clock_gettime_ns(raw_clock)
        outcome = subprocess.run([str(executable), *expected], cwd=root,
            env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=5, check=False)
        after = time.clock_gettime_ns(raw_clock)
        self.assertEqual(93, outcome.returncode, 'fixed private first-fetch refusal, not installation')
        self.assertEqual(b'', outcome.stdout)
        self.assertEqual(b'', outcome.stderr)
        payload = (remote / 'nv.os.trace').read_bytes()
        self.assertTrue(payload.endswith(b'\n'))
        self.assertEqual(1, payload.count(b'\n'))
        event = json.loads(payload)
        self.assertEqual({'argv', 'time_ns'}, set(event))
        self.assertEqual(expected, event['argv'])
        self.assertIs(type(event['time_ns']), int)
        self.assertGreaterEqual(after, before)
        self.assertGreaterEqual(event['time_ns'], before,
            'actual shebang interpreter event must share the explicit kernel RAW epoch')
        self.assertLessEqual(event['time_ns'], after,
            'actual child event must precede parent completion sample')
