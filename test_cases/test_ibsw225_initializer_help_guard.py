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

    def test_unknown_option_rejects_before_guard_or_report(self):
        # v3.1.3 guide WP-2 / table 6-1 row 7 (O4): only the --version half of the former
        # test_unknown_and_unsupported_version_reject_before_guard_or_report changed; that
        # half is test_version_prints_repository_revision_without_guard_or_report below.
        # The unknown-option half keeps its original assertions unchanged.
        initial = self.initial()
        for option in ("--unknown-test-option",):
            with self.subTest(option=option), \
                 mock.patch.object(initial, "_runtime_instance_guard", side_effect=AssertionError("Invalid argv must not acquire")) as guard, \
                 mock.patch.object(sys, "argv", [str(INITIAL), option]), \
                 mock.patch.object(sys, "stderr", io.StringIO()):
                with self.assertRaises(SystemExit) as stopped:
                    initial._guarded_main()
                self.assertEqual(stopped.exception.code, 2)
                self.assertIsNone(initial.REPORT_HANDLE)
                guard.assert_not_called()

    def test_retired_auto_and_credentials_file_are_unknown_before_guard_or_report(self):
        # Owner 2026-11-02 (requirements :557): retire the initial-setup --auto mode; R-012
        # design :589 (--auto retired); v3.1.3 guide O3: both options are deleted, so argparse
        # rejects them as unknown arguments (exit 2) before the runtime guard, main or a report.
        initial = self.initial()
        retired = (
            ("--auto",),
            ("--credentials-file", "PUBLIC-retired-credentials.env"),
            ("--auto", "--apply", "--yes", "--credentials-file", "PUBLIC-retired-credentials.env"),
        )
        for argv in retired:
            with self.subTest(argv=argv), \
                 mock.patch.object(initial, "_runtime_instance_guard", side_effect=AssertionError("Retired option must not acquire")) as guard, \
                 mock.patch.object(initial, "main", side_effect=AssertionError("Retired option must not enter main")) as body, \
                 mock.patch.object(sys, "argv", [str(INITIAL), *argv]), \
                 mock.patch.object(sys, "stdout", io.StringIO()), \
                 mock.patch.object(sys, "stderr", io.StringIO()) as err:
                with self.assertRaises(SystemExit) as stopped:
                    initial._guarded_main()
                self.assertEqual(stopped.exception.code, 2)
                self.assertIn("unrecognized arguments", err.getvalue())
                self.assertIsNone(initial.REPORT_HANDLE)
                guard.assert_not_called()
                body.assert_not_called()

    def test_help_names_repository_entry_not_desktop_copy(self):
        # Owner 2026-11-06 (development plan :314): rename v15 to initial-setup.py and develop
        # it in the repository; the merged file is the repository entry, not a desktop review copy
        # (v3.1.3 guide WP-2 "先写的测试").
        initial = self.initial()
        with mock.patch.object(initial, "_runtime_instance_guard", side_effect=AssertionError("Sole help must not acquire")), \
             mock.patch.object(sys, "argv", [str(INITIAL), "--help"]), \
             mock.patch.object(sys, "stdout", io.StringIO()) as out:
            with self.assertRaises(SystemExit) as stopped:
                initial._guarded_main()
        self.assertEqual(stopped.exception.code, 0)
        text = out.getvalue()
        self.assertIn("usage:", text)
        self.assertNotIn("desktop review copy", text.casefold())
        self.assertNotIn("reserved", text.casefold())

    def test_version_prints_repository_revision_without_guard_or_report(self):
        # v3.1.3 guide WP-2 and table 6-1 row 7 (O4, adopt v15): --version prints the
        # repository revision string (guide: "http-v3.1.<n>", written into the file) and exits 0
        # without the runtime guard or a report.
        initial = self.initial()
        with mock.patch.object(initial, "_runtime_instance_guard", side_effect=AssertionError("--version must not acquire")) as guard, \
             mock.patch.object(sys, "argv", [str(INITIAL), "--version"]), \
             mock.patch.object(sys, "stdout", io.StringIO()) as out, \
             mock.patch.object(sys, "stderr", io.StringIO()) as err:
            with self.assertRaises(SystemExit) as stopped:
                initial._guarded_main()
        self.assertEqual(stopped.exception.code, 0)
        printed = (out.getvalue() + err.getvalue()).strip()
        self.assertRegex(printed, r"\Ahttp-v3\.1\.[0-9]+\Z")
        self.assertNotIn("desktop", printed.casefold())
        self.assertIsNone(initial.REPORT_HANDLE)
        guard.assert_not_called()
