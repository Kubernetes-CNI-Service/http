"""Real managed initializer success and failure cleanup under the outer guard.

Uses existing public synthetic REQ10B inputs; blank project public-key
placeholders intentionally cause the real cycle's complete-profile rejection
AFTER pending is published. No main/cycle/guard/results are substituted.
Success uses real local synthetic keys and explicitly simulated device IO;
it is not proof of a real device installation.
"""
from contextlib import ExitStack, redirect_stdout, redirect_stderr
import base64
import hashlib
import importlib
import io
import json
import os
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

_MANAGED_SUCCESS_STATE = (
    "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
    "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
    "nv set system hostname EXAMPLE-IB01\n"
    "nv set system dns server 203.0.113.53\n"
    "nv set system ntp server ntp.ubuntu.com\n"
    "nv set system ntp server time.ib.example.test\n"
    "nv set system date-time timezone Asia/Taipei\n"
)

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

    def test_real_managed_success_receipt_and_cleanup_remain_guarded(self):
        authority = load_script("ibsw_managed_success", ROOT / "ztp/config_sync_authority.py")
        guard = importlib.import_module("tools.ib_bringup_runtime_guard")
        deployment = importlib.import_module("tools.deployment_lock")
        real_run, real_popen, real_init = subprocess.run, subprocess.Popen, authority.ManagedInitialMethodCycle.__init__
        real_begin, real_finish = authority.begin_method, authority.finish_method
        real_close, real_release = authority.ManagedInitialMethodCycle.close, deployment.release_lock_descriptor
        previous_profile, previous_argv = sys.getprofile(), sys.argv
        previous_module = sys.modules.get("_http_managed_initial_setup")
        self.assertIsNone(previous_profile)
        events, crypto, transports, cycles, main_globals, reports = [], [], [], [], [], []
        with tempfile.TemporaryDirectory(prefix="ibsw-managed-success-", dir="/private/tmp") as raw, ExitStack() as patches:
            base = Path(raw).resolve()
            project = base / "project"
            _, tool, _, csv_path, p2p, pubdir, cache, laptop, _ = req10b_fixtures.Req10BServicesKeysWorkflowTests().fixture(str(project))
            csv_path.write_text(
                "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,config_method\n"
                "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,,initial-setup\n"
                "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,,\n", encoding="utf-8")
            home = base / "home"
            (home / ".ssh").mkdir(parents=True, mode=0o700)
            private = home / ".ssh/id_ed25519"
            self.assertFalse(private.exists())
            # Exactly one owned local key generation, never a user key.
            generated = real_run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private)],
                                 stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5, check=False,
                                 env={"PATH": "/usr/bin:/bin", "HOME": str(home)})
            self.assertEqual(generated.returncode, 0)
            crypto.append("generate")
            management = private.with_suffix(".pub").read_text().strip()
            (pubdir / "mgmt-server.pub").write_text(management + "\n", encoding="ascii")
            expected_lines = [laptop.strip(), management]
            wire = ("__HTTP_INITIAL_METHOD_V1_IDENTITY_BEGIN__\nEXAMPLE-IB01\n02:00:00:00:00:01\n"
                    "__HTTP_INITIAL_METHOD_V1_IDENTITY_END__\n__HTTP_INITIAL_METHOD_V1_CONFIG_BEGIN__\n" + _MANAGED_SUCCESS_STATE +
                    "__HTTP_INITIAL_METHOD_V1_CONFIG_END__=0\n__HTTP_INITIAL_METHOD_V1_KEYS_BEGIN__\n" +
                    "\n".join(expected_lines) + "\n__HTTP_INITIAL_METHOD_V1_KEYS_END__=0\n")
            storage = project / "99-output-ztp/configuration-methods"
            report_path = project / "out/report.log"

            def held(name):
                with self.assertRaises(guard._InstanceGuardError) as caught:
                    with guard._runtime_instance_guard():
                        self.fail("outer guard was released")
                self.assertEqual(caught.exception.code, "ALREADY_RUNNING")
                events.append(name)

            def local_or_simulated_transport(argv, **kwargs):
                argv = list(argv)
                if argv[:2] == ["ssh", "-i"]:
                    self.assertEqual(argv[2], str(private))
                    self.assertEqual(argv[-2:], ["admin@203.0.113.2", "true"])
                    self.assertIn("PasswordAuthentication=no", argv)
                    held("simulated_possession_transport")
                    transports.append("possession")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                self.assertIn(argv[0], ("ssh-keygen", "/usr/bin/ssh-keygen"))
                if argv[1:] == ["-y", "-f", str(private)]:
                    self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
                    crypto.append("derive")
                    return real_run(["/usr/bin/ssh-keygen", *argv[1:]], **{**kwargs, "timeout": 5})
                self.assertEqual(argv[1:], ["-l", "-E", "sha256", "-f", "/dev/stdin"])
                line = kwargs["input"].strip()
                self.assertIn(line, expected_lines)
                public = pubdir / ("laptop.pub" if line == expected_lines[0] else "mgmt-server.pub")
                self.assertEqual(public.read_text().strip(), line)
                crypto.append("fingerprint:" + public.name)
                self.assertEqual(kwargs["input"], line + "\n")
                self.assertEqual(kwargs["timeout"], 10)
                return real_run(argv, **kwargs)  # Exact original argv/input/timeout.

            def local_crypto_child(argv, *args, **kwargs):
                # subprocess.run's real context/wait/pipe cleanup remains intact.
                self.assertEqual(argv[0], "/usr/bin/ssh-keygen")
                self.assertIn(tuple(argv[1:]), (("-y", "-f", str(private)),
                    ("-l", "-E", "sha256", "-f", "/dev/stdin")))
                return real_popen(argv, *args, **kwargs)

            def bind_actual_cycle(cycle, *args, **kwargs):
                real_init(cycle, *args, **kwargs)
                cycles.append(cycle)
                initial = cycle.initial
                ethernet = {
                    ("hostname",): "EXAMPLE-JUMP01\n",
                    ("nv", "show", "interface"): "Interface Admin Oper\nswp7 up up\n",
                    ("ip", "-d", "link", "show"): "7: swp7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9216\n",
                    ("bridge", "fdb", "show"): "02:00:00:00:00:01 dev swp7 vlan 1 master bridge\n",
                    ("ip", "neighbor"): "fe80::1 dev swp7 lladdr 02:00:00:00:00:01 REACHABLE\n",
                    ("ifquery", "swp7"): "",
                }
                def eth_transport(*args, **kwargs):
                    command = tuple(args[3])
                    self.assertIn(command, ethernet)
                    transports.append(command)
                    return ethernet[command]
                def ib_transport(*args, **kwargs):
                    command = list(args[7])
                    if command == ["nv", "config", "show", "-o", "commands"]:
                        transports.append("config")
                        return initial.SessionResult(_MANAGED_SUCCESS_STATE, 0)
                    self.assertEqual(command[:4], ["sh", "-c", initial._KEY_INSTALL_SCRIPT, "--"])
                    self.assertEqual(len(command), 5)
                    self.assertEqual(base64.b64decode(command[4]).decode(), "\n".join(expected_lines) + "\n")
                    transports.append("install_keys")
                    return initial.SessionResult("", 0)
                def observation_transport(command, timeout, *, pass_fds=()):
                    self.assertEqual(len(pass_fds), 1)
                    self.assertEqual(command[2], "/dev/fd/" + str(pass_fds[0]))
                    self.assertEqual(os.fstat(pass_fds[0]).st_ino, private.stat().st_ino)
                    self.assertEqual(command[-2], "admin@203.0.113.2")
                    held("real_observer_transport")
                    transports.append("observation")
                    return subprocess.CompletedProcess(command, 0, wire, "")
                for name, callback in (("run_on_ethernet", eth_transport), ("run_on_ib", ib_transport),
                                       ("_run_initial_observation", observation_transport)):
                    patches.enter_context(mock.patch.object(initial, name, side_effect=callback))
                patches.enter_context(mock.patch.object(initial, "interactive_run", side_effect=AssertionError("No interactive device transport")))

            def begin(*args, **kwargs):
                result = real_begin(*args, **kwargs)
                self.assertEqual((result["state"], result["veto"]), ("pending", True))
                held("pending")
                return result
            def finish(*args, **kwargs):
                held("finish_before")
                result = real_finish(*args, **kwargs)
                held("finish_after")
                return result
            def close(cycle):
                held("cycle_close_before")
                result = real_close(cycle)
                held("cycle_close_after")
                return result
            def release(fd):
                held("deployment_before")
                result = real_release(fd)
                held("deployment_after")
                return result
            def observe(frame, event, argument):
                if event == "call" and frame.f_code.co_filename == str(ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py") and frame.f_code.co_name == "main":
                    self.assertIs(frame.f_globals["main"].__code__, frame.f_code)
                    main_globals.append(frame.f_globals)
                    self.assertIs(frame.f_locals["method_cycle"], cycles[0])
                    held("main")
                if event in ("c_call", "c_return") and main_globals:
                    report = main_globals[0].get("REPORT_HANDLE")
                    if report is not None and getattr(argument, "__self__", None) is report and getattr(argument, "__name__", None) == "close":
                        reports.append(report)
                        held("report_before" if event == "c_call" else "report_after")

            for target, name, replacement in ((authority, "_HTTP_ROOT", base), (guard, "_RUNTIME_GUARD_PATH", base / "private-runtime.lock"),
                    (authority.ManagedInitialMethodCycle, "__init__", bind_actual_cycle), (authority, "begin_method", begin),
                    (authority, "finish_method", finish), (authority.ManagedInitialMethodCycle, "close", close),
                    (deployment, "release_lock_descriptor", release), (subprocess, "run", local_or_simulated_transport),
                    (subprocess, "Popen", local_crypto_child)):
                patches.enter_context(mock.patch.object(target, name, replacement))
            patches.enter_context(mock.patch.object(Path, "home", return_value=home))
            patches.enter_context(mock.patch.dict(os.environ, {"PATH": "/usr/bin:/bin", "HOME": str(home), "NVOS_INITIAL_PASSWORD": "SYNTHETIC_ONLY"}, clear=True))
            patches.enter_context(mock.patch.object(socket, "socket", side_effect=AssertionError("No network")))
            patches.enter_context(mock.patch.object(threading.Thread, "start", side_effect=AssertionError("No worker")))
            out, err = io.StringIO(), io.StringIO()
            argv = ["--project", str(project), "--", "--ib-csv", str(csv_path), "--p2p", str(p2p),
                    "--target-cache", str(cache), "--report", str(report_path), "--snapshot-dir", str(project / "snapshots"),
                    "--apply", "--yes", "--execution-mode", "management", "--ethernet-password", "SYNTHETIC_ONLY"]
            with redirect_stdout(out), redirect_stderr(err):
                try:
                    sys.setprofile(observe)
                    code = authority.managed_initial_main(argv)
                finally:
                    sys.setprofile(previous_profile)
            self.assertEqual(code, 0, out.getvalue() + err.getvalue())
            self.assertEqual(err.getvalue(), "")
            self.assertEqual(len(main_globals), 1)
            self.assertEqual(crypto, ["generate", "fingerprint:laptop.pub", "fingerprint:mgmt-server.pub", "derive"])
            self.assertEqual(events.count("pending"), 1)
            self.assertEqual(events.count("cycle_close_before"), 2)
            self.assertEqual(events[-4:], ["report_before", "report_after", "deployment_before", "deployment_after"])
            self.assertEqual(len(reports), 2)
            self.assertIs(reports[0], reports[1])
            self.assertTrue(reports[0].closed)
            current = authority.read_method_current(storage, "EXAMPLE-IB01")
            receipt = authority.read_method_receipt(storage, "EXAMPLE-IB01")
            self.assertEqual((current["generation"], current["state"], current["veto"]), (1, "success", False))
            self.assertEqual((receipt["hostname"], receipt["config_method"], receipt["state"], receipt["config_verified"], receipt["batch_identity_verified"]),
                             ("EXAMPLE-IB01", "initial-setup", "success", True, True))
            self.assertEqual(receipt["source_receipt_sha256"], hashlib.sha256(wire.encode()).hexdigest())
            self.assertEqual(receipt["live_state_sha256"], hashlib.sha256(_MANAGED_SUCCESS_STATE.encode()).hexdigest())
            expected_input = {
                "schema_version": 1, "type": "ib", "config_method": "initial-setup", "hostname": "EXAMPLE-IB01",
                "eth0": "203.0.113.2/24", "eth0_gateway": "203.0.113.1", "eth1": "", "eth1_gateway": "",
                "eth0_mac": "02:00:00:00:00:01", "dns": ["203.0.113.53"],
                "ntp": ["ntp.ubuntu.com", "time.ib.example.test"], "timezone": "Asia/Taipei",
                "key_fingerprints": sorted({req10b_fixtures.fingerprint(line) for line in expected_lines}),
            }
            self.assertEqual(receipt["input_sha256"], hashlib.sha256(json.dumps(
                expected_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest())
            self.assertEqual(cycles[0].finished, {"example-ib01"})
            self.assertIn("install_keys", transports)
            self.assertIn("observation", transports)
            self.assertNotIn("SYNTHETIC_ONLY", out.getvalue() + err.getvalue() + report_path.read_text())
            self.assertIs(sys.argv, previous_argv)
            self.assertIs(sys.modules.get("_http_managed_initial_setup"), previous_module)
            with guard._runtime_instance_guard():
                pass
        self.assertIs(sys.getprofile(), previous_profile)
