"""Independent report-finally direct contracts, not real-main or kernel proof."""
import importlib.util
import io
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"

class StandaloneReportFinallyDirectTests(unittest.TestCase):
    def load_initial(self):
        name = "_ibsw_initializer_report_finally_direct"
        self.assertNotIn(name, sys.modules)
        spec = importlib.util.spec_from_file_location(name, INITIAL)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        self.addCleanup(lambda: sys.modules.pop(name, None))
        spec.loader.exec_module(module)
        return module

    def test_success_closes_actual_report_stream_and_preserves_return_code(self):
        initial = self.load_initial()
        report = io.StringIO()
        initial.REPORT_HANDLE = report
        with mock.patch.object(initial, "main", return_value=7) as algorithm:
            self.assertEqual(initial._standalone_main_with_report_cleanup(), 7)
        algorithm.assert_called_once_with()
        self.assertTrue(report.closed)

    def test_setup_error_writes_both_diagnostics_then_closes_actual_report(self):
        initial = self.load_initial()
        events = []
        class Report(io.StringIO):
            def close(self):
                events.append(("before_close", self.getvalue()))
                return super().close()
        report = Report()
        initial.REPORT_HANDLE = report
        error = initial.SetupError("literal input rejection")
        with mock.patch.object(initial, "main", side_effect=error), mock.patch.object(sys, "stderr", io.StringIO()) as stderr:
            self.assertEqual(initial._standalone_main_with_report_cleanup(), 2)
            self.assertEqual(stderr.getvalue(), "ERROR: literal input rejection\n")
        self.assertEqual(events, [("before_close", "ERROR: literal input rejection\n")])
        self.assertTrue(report.closed)

    def test_nonordinary_primary_or_cleanup_keeps_exact_exception_identity(self):
        for primary_factory, cleanup_factory, expected in (
            (KeyboardInterrupt, ValueError, "primary"),
            (SystemExit, RuntimeError, "primary"),
            (ValueError, KeyboardInterrupt, "cleanup"),
            (ValueError, SystemExit, "cleanup"),
            (ValueError, RuntimeError, "primary"),
        ):
            with self.subTest(primary=primary_factory.__name__, cleanup=cleanup_factory.__name__):
                initial = self.load_initial()
                primary = primary_factory("original primary")
                cleanup = cleanup_factory("original cleanup")
                calls = []
                class Report:
                    def close(self):
                        calls.append("close")
                        raise cleanup
                initial.REPORT_HANDLE = Report()
                with mock.patch.object(initial, "main", side_effect=primary):
                    try:
                        initial._standalone_main_with_report_cleanup()
                    except BaseException as caught:
                        self.assertIs(caught, primary if expected == "primary" else cleanup)
                    else:
                        self.fail("Original exception must remain observable")
                self.assertEqual(calls, ["close"])
                # Each subcase releases only its own real module registration.
                self.assertIs(sys.modules.pop(initial.__name__), initial)
