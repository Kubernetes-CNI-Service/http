"""Real managed initializer failure/cleanup under the outer host guard.

Uses existing public synthetic REQ10B inputs; blank project public-key
placeholders intentionally cause the real cycle's complete-profile rejection
AFTER pending is published. No main/cycle/guard/results are substituted.
"""
import importlib
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from test_cases.module_loader import load_script
from test_cases import test_req10b_services_keys_workflow as req10b_fixtures

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"

class ManagedInitialOuterGuardWorkflowTests(unittest.TestCase):
    def test_real_pending_failure_report_and_deployment_cleanup_remain_guarded(self):
        authority = load_script("ibsw_true_managed_outer_guard", ROOT / "ztp/config_sync_authority.py")
        guard = importlib.import_module("tools.ib_bringup_runtime_guard")
        deployment = importlib.import_module("tools.deployment_lock")
        real_begin = authority.begin_method
        real_cycle_close = authority.ManagedInitialMethodCycle.close
        real_release = deployment.release_lock_descriptor
        previous_profile = sys.getprofile()
        self.assertIsNone(previous_profile, "Cannot replace an unrelated profiling owner")
        previous_module = sys.modules.get("_http_managed_initial_setup")
        previous_argv = sys.argv
        events, cycle_objects, real_main_globals, reports = [], [], [], []
        with tempfile.TemporaryDirectory(prefix="ibsw-managed-real-cleanup-", dir="/private/tmp") as raw:
            base = Path(raw).resolve()
            project = base / "project"
            root, tool, global_file, csv_path, p2p, pubdir, cache, _, _ = (
                req10b_fixtures.Req10BServicesKeysWorkflowTests().fixture(str(project)))
            csv_path.write_text(
                "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,config_method\n"
                "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,,initial-setup\n"
                "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,,\n", encoding="utf-8")
            # Actual empty placeholders bypass ssh-keygen without forging a key.
            (pubdir / "laptop.pub").write_text("", encoding="ascii")
            (pubdir / "mgmt-server.pub").write_text("", encoding="ascii")
            home = base / "home"
            home.mkdir(mode=0o700)
            report_path = project / "out/report.log"
            lock_path = base / "private-runtime.lock"
            storage = project / "99-output-ztp/configuration-methods"

            def host_busy():
                try:
                    with guard._runtime_instance_guard():
                        return False
                except guard._InstanceGuardError as exc:
                    return exc.code == "ALREADY_RUNNING"

            def begin_and_observe(*args, **kwargs):
                ticket = real_begin(*args, **kwargs)
                current = authority.read_method_current(storage, "EXAMPLE-IB01")
                self.assertEqual((current["generation"], current["state"], current["veto"]),
                                 (1, "pending", True))
                self.assertEqual(current, ticket)
                events.append(("real_pending_published", host_busy()))
                return ticket

            def close_real_cycle(cycle):
                cycle_objects.append(cycle)
                events.append(("cycle_close_before", host_busy()))
                result = real_cycle_close(cycle)
                events.append(("cycle_close_after", host_busy()))
                return result

            def release_real_deployment(descriptor):
                events.append(("deployment_release_before", host_busy()))
                result = real_release(descriptor)
                events.append(("deployment_release_after", host_busy()))
                return result

            def observe_original_main_and_report(frame, event, argument):
                # Fixed real main Code/globals, and the actual TextIOWrapper's
                # built-in close events only. No profile callback grants IO.
                if event == "call" and frame.f_code.co_filename == str(INITIAL) and frame.f_code.co_name == "main":
                    function = frame.f_globals.get("main")
                    if function is not None and function.__code__ is frame.f_code and function.__globals__ is frame.f_globals:
                        real_main_globals.append(frame.f_globals)
                        cycle_objects.append(frame.f_locals.get("method_cycle"))
                        events.append(("real_main_enter", host_busy()))
                if event in ("c_call", "c_return") and real_main_globals:
                    report = real_main_globals[0].get("REPORT_HANDLE")
                    if report is not None and getattr(argument, "__self__", None) is report and getattr(argument, "__name__", None) == "close":
                        reports.append(report)
                        phase = "report_close_before" if event == "c_call" else "report_close_after"
                        events.append((phase, host_busy()))
                return observe_original_main_and_report

            argv = ["--project", str(project), "--", "--ib-csv", str(csv_path),
                    "--p2p", str(p2p), "--target-cache", str(cache),
                    "--report", str(report_path), "--snapshot-dir", str(project / "snapshots"),
                    "--apply", "--yes", "--execution-mode", "management"]
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.object(authority, "_HTTP_ROOT", base), \
                 mock.patch.object(guard, "_RUNTIME_GUARD_PATH", lock_path), \
                 mock.patch.object(Path, "home", return_value=home), \
                 mock.patch.dict("os.environ", {"NVOS_INITIAL_PASSWORD": "PRIVATE_SYNTHETIC_ONLY"}, clear=True), \
                 mock.patch.object(authority, "begin_method", side_effect=begin_and_observe), \
                 mock.patch.object(authority.ManagedInitialMethodCycle, "close", close_real_cycle), \
                 mock.patch.object(deployment, "release_lock_descriptor", side_effect=release_real_deployment), \
                 mock.patch.object(socket, "socket", side_effect=AssertionError("No network")) as network, \
                 mock.patch.object(subprocess, "Popen", side_effect=AssertionError("No child")) as child, \
                 mock.patch.object(threading.Thread, "start", side_effect=AssertionError("No worker")) as worker, \
                 mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
                try:
                    sys.setprofile(observe_original_main_and_report)
                    code = authority.managed_initial_main(argv)
                finally:
                    sys.setprofile(previous_profile)
                self.assertEqual(code, 2)
                self.assertEqual(err.getvalue(), "managed initial-setup rejected: AuthorityError\n")
                self.assertEqual(len(real_main_globals), 1)
                self.assertEqual(len(cycle_objects), 3)  # actual main object + two actual close calls
                self.assertIs(cycle_objects[0], cycle_objects[1])
                self.assertIs(cycle_objects[1], cycle_objects[2])
                self.assertIsInstance(cycle_objects[0], authority.ManagedInitialMethodCycle)
                self.assertEqual([name for name, _ in events], [
                    "real_main_enter", "real_pending_published",
                    "cycle_close_before", "cycle_close_after",
                    "cycle_close_before", "cycle_close_after",
                    "report_close_before", "report_close_after",
                    "deployment_release_before", "deployment_release_after"])
                self.assertTrue(all(held for _, held in events))
                self.assertEqual(len(reports), 2)
                self.assertIs(reports[0], reports[1])
                self.assertIs(type(reports[0]), io.TextIOWrapper)
                self.assertTrue(reports[0].closed)
                current = authority.read_method_current(storage, "EXAMPLE-IB01")
                self.assertEqual((current["generation"], current["state"], current["veto"]),
                                 (1, "failed", True))
                self.assertIsNone(authority.read_method_receipt(storage, "EXAMPLE-IB01"))
                self.assertEqual(json.loads(cache.read_text())["public_keys"], [])
                self.assertIn("Execution location: management server", report_path.read_text())
                self.assertNotIn("PRIVATE_SYNTHETIC_ONLY", out.getvalue() + err.getvalue() + report_path.read_text())
                self.assertIs(sys.argv, previous_argv)
                self.assertIs(sys.modules.get("_http_managed_initial_setup"), previous_module)
                with guard._runtime_instance_guard():
                    pass  # reacquisition succeeds only after all real cleanup
                network.assert_not_called()
                child.assert_not_called()
                worker.assert_not_called()
        self.assertIs(sys.getprofile(), previous_profile)
