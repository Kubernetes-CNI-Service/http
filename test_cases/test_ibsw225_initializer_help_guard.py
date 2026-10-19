"""Independent sole-help versus mixed-help guard contract, private inode only."""
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"

class InitializerHelpGuardTests(unittest.TestCase):
    def initial(self):
        name = "_ibsw_initial_help_contract"
        self.assertNotIn(name, sys.modules)
        spec = importlib.util.spec_from_file_location(name, INITIAL)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        self.addCleanup(lambda: sys.modules.pop(name, None))
        spec.loader.exec_module(module)
        return module

    def test_mixed_help_requires_real_private_guard_and_busy_does_not_print_help(self):
        initial = self.initial()
        for option in ("--help", "-h", "--he"):
            with self.subTest(option=option), tempfile.TemporaryDirectory(prefix="ibsw-mixed-help-") as raw:
                lock = Path(raw) / "private-runtime.lock"
                with mock.patch.object(initial, "_RUNTIME_GUARD_PATH", lock), \
                     mock.patch.object(initial, "main", side_effect=AssertionError("Busy mixed help must not enter main")) as body, \
                     mock.patch.object(sys, "argv", [str(INITIAL), option, "--apply"]), \
                     mock.patch.object(sys, "stdout", io.StringIO()) as out, \
                     mock.patch.object(sys, "stderr", io.StringIO()) as err:
                    with initial._runtime_instance_guard():
                        try:
                            result = initial._guarded_main()
                        except SystemExit as exc:
                            result = exc.code
                        self.assertEqual(result, 75)
                        self.assertEqual(out.getvalue(), "")
                        self.assertIn("ALREADY_RUNNING", err.getvalue())
                        body.assert_not_called()

    def test_only_sole_explicit_help_bypasses_guard(self):
        initial = self.initial()
        for option in ("--help", "-h"):
            with self.subTest(option=option), \
                 mock.patch.object(initial, "_runtime_instance_guard", side_effect=AssertionError("Sole help must not acquire")) as guard, \
                 mock.patch.object(sys, "argv", [str(INITIAL), option]), \
                 mock.patch.object(sys, "stdout", io.StringIO()) as out:
                with self.assertRaises(SystemExit) as stopped:
                    initial._guarded_main()
                self.assertEqual(stopped.exception.code, 0)
                self.assertIn("usage:", out.getvalue())
                guard.assert_not_called()

    def test_unknown_and_unsupported_version_reject_before_guard_or_report(self):
        initial = self.initial()
        for option in ("--unknown-test-option", "--version"):
            with self.subTest(option=option), \
                 mock.patch.object(initial, "_runtime_instance_guard", side_effect=AssertionError("Invalid argv must not acquire")) as guard, \
                 mock.patch.object(sys, "argv", [str(INITIAL), option]), \
                 mock.patch.object(sys, "stderr", io.StringIO()):
                with self.assertRaises(SystemExit) as stopped:
                    initial._guarded_main()
                self.assertEqual(stopped.exception.code, 2)
                self.assertIsNone(initial.REPORT_HANDLE)
                guard.assert_not_called()
