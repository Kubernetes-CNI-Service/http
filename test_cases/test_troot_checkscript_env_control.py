"""RV31-92 carrier control: observe the real helper, never start its child."""
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_cases import test_ibsw_v2_device_scripts as scripts


class CheckScriptOwnedRootControlTests(unittest.TestCase):
    def observe_root(self, name):
        # Expected authority comes from the independent runner input, not from
        # the helper's returned env or the source being tested.
        root = Path(os.environ['HTTP_TEST_OWNED_ROOT'])
        self.assertTrue(root.is_absolute())
        self.assertEqual(root, root.resolve())
        self.assertEqual(os.geteuid(), root.stat().st_uid)
        self.assertEqual(0o700, root.stat().st_mode & 0o777)
        fixture = SimpleNamespace(bin=root / 'public-bin', sysroot=root / 'public-sysroot')
        observed = []

        def inspect(argv, **kwargs):
            observed.append(dict(kwargs['env']))
            self.assertEqual(['/bin/bash', '-s', '--', 'ladder'], argv)
            self.assertEqual(str(root), kwargs['env'].get(name))
            self.assertEqual(str(fixture.sysroot), kwargs['env']['IBSW_SYSROOT'])
            self.assertEqual(str(fixture.bin) + ':/usr/bin:/bin', kwargs['env']['PATH'])
            self.assertEqual('C', kwargs['env']['LC_ALL'])
            self.assertEqual(60, kwargs['timeout'])
            self.assertTrue(kwargs['capture_output'])
            return subprocess.CompletedProcess(argv, 0, b'CONTROL_NOT_EXECUTED', b'')

        with patch.object(scripts.subprocess, 'run', side_effect=inspect) as called, \
                patch.object(scripts.subprocess, 'Popen', side_effect=AssertionError('FORBIDDEN_REAL_CHILD')) as child:
            result = scripts.CheckScriptTest.run_check(fixture, 'ladder')
            called.assert_called_once()
            child.assert_not_called()
        self.assertEqual(1, len(observed))
        self.assertEqual(b'CONTROL_NOT_EXECUTED', result.stdout)

    def test_tmpdir_is_the_explicit_owned_root_before_child(self):
        self.observe_root('TMPDIR')

    def test_http_test_root_is_the_same_explicit_root_before_child(self):
        self.observe_root('HTTP_TEST_OWNED_ROOT')
