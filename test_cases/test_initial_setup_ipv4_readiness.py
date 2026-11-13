"""WP-3 independent IPv4 readiness policy/probe contracts, guide r504 :630-683.

Synthetic targets, a fake readiness clock and substituted SSH results only.
No native/KAT, devices, process creation, real SSH, user credentials or key files.
"""
from __future__ import annotations

from contextlib import ExitStack
import errno
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
MARKER = "ab" * 16


def load_app(name="wp3_ipv4_readiness"):
    return load_script(name, INITIAL)


def target(app):
    ib = app.Device("EXAMPLE-IB01", "ib", "192.0.2.10", "192.0.2.10/24",
                    "192.0.2.1", "02:00:00:00:00:10", "", "")
    jump = app.Device("EXAMPLE-JUMP01", "eth_jump", "198.51.100.10", "", "", "", "", "")
    return app.Target(ib, jump, "swp1", "eth0")


def credential(role):
    return "-".join(("PUBLIC", "WP3", role, "71!"))


def success(app):
    return app.SessionResult("__HTTP_IB_BEGIN_" + MARKER + "__\n"
                             "__HTTP_IB_END_" + MARKER + "__=0\n", 0)


def strict_policy(app, directory):
    path = Path(directory) / "01-global.yaml"
    setting = "$" + "6$PUBLICsalt$" + "A" * 86
    path.write_text("schema_version: 2\nswitches:\n- ib:\n    system:\n"
                    "      aaa:\n        user:\n          admin:\n            pass" + "word: "
                    + setting + "\n", encoding="utf-8")
    return app.ProjectPasswordPolicy(path, "admin", target_password=credential("target"), interactive=False)


class Ipv4ReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = load_app()

    def api(self):
        self.assertTrue(callable(getattr(self.app, "ReadinessPolicy", None)), "r504 readiness policy is required")
        self.assertTrue(callable(getattr(self.app, "wait_until_ready", None)), "r504 independent wait is required")

    def verify(self, **kwargs):
        return self.app.verify_ipv4_login(target(self.app), "oob", "cumulus", credential("outer"),
                                          "admin", 2, ib_password=credential("current"), **kwargs)

    def test_default_policy_is_15_10_9(self):
        self.api()
        waits, probes = [], []
        def probe():
            probes.append(len(probes) + 1)
            return "RETRY", "connection refused"
        with self.assertRaisesRegex(self.app.SetupError, "9 attempts"):
            self.app.wait_until_ready(probe, self.app.ReadinessPolicy(), label="EXAMPLE-IB01", sleep=waits.append)
        self.assertEqual([15] + [10] * 8, waits)
        self.assertEqual(list(range(1, 10)), probes)

    def test_device_ready_after_60s_passes_within_attempts_4_to_6(self):
        self.api()
        for cost, expected in ((0, 6), (10, 4)):
            with self.subTest(cost=cost):
                clock, probes, waits = [0], [], []
                def sleep(seconds):
                    waits.append(seconds)
                    clock[0] += seconds
                def probe():
                    probes.append(clock[0])
                    ready = clock[0] >= 60
                    clock[0] += cost
                    return ("READY", None) if ready else ("RETRY", "not ready")
                self.app.wait_until_ready(probe, self.app.ReadinessPolicy(), label="EXAMPLE-IB01", sleep=sleep)
                self.assertEqual(expected, len(probes))
                self.assertEqual([15] + [10] * (expected - 1), waits)

    def test_no_network_write_means_no_first_delay(self):
        self.api()
        events = []
        def probe():
            events.append("probe")
            return "READY", None
        self.app.wait_until_ready(probe, self.app.ReadinessPolicy(first_delay=0),
                                  label="EXAMPLE-IB01", sleep=lambda seconds: events.append(seconds))
        self.assertEqual(["probe"], events)

    def test_fatal_result_keeps_original_failure_identity(self):
        self.api()
        failure = self.app.SshFailure(self.app.SshFailureKind.TARGET_HOST_KEY_CHANGED,
                                      "inner", "192.0.2.10", "EXAMPLE-JUMP01")
        probe, waits = mock.Mock(return_value=("FATAL", failure)), []
        with self.assertRaises(self.app.SshFailure) as caught:
            self.app.wait_until_ready(probe, self.app.ReadinessPolicy(), label="EXAMPLE-IB01", sleep=waits.append)
        self.assertIs(failure, caught.exception)
        probe.assert_called_once_with()
        self.assertEqual([15], waits)

    def test_timeout_message_says_still_converging(self):
        self.api()
        with self.assertRaisesRegex(self.app.SetupError, "可能还在收敛"):
            self.app.wait_until_ready(lambda: ("RETRY", "not ready"), self.app.ReadinessPolicy(),
                                      label="EXAMPLE-IB01", sleep=lambda _: None)

    def test_each_probe_checks_master_only_after_its_wait(self):
        events = []
        replies = iter((self.app.SessionResult("Connection refused", 255), success(self.app)))
        with mock.patch.object(self.app.time, "sleep", side_effect=lambda seconds: events.append(("sleep", seconds))), \
                mock.patch.object(self.app.os, "urandom", return_value=bytes.fromhex(MARKER)), \
                mock.patch.object(self.app, "_jump_control_path_for",
                                  side_effect=lambda *args, **kwargs: events.append(("master", None))), \
                mock.patch.object(self.app, "interactive_run",
                                  side_effect=lambda *args: (events.append(("probe", None)), next(replies))[1]):
            self.verify()
        self.assertEqual([("sleep", 15), ("master", None), ("probe", None),
                          ("sleep", 10), ("master", None), ("probe", None)], events)

    def test_existing_fatal_signals_never_retry(self):
        for output in ("Permission denied (password).", "Password has expired", "command not found",
                       "Host key verification failed."):
            with self.subTest(output=output), mock.patch.object(self.app.time, "sleep"), \
                    mock.patch.object(self.app, "interactive_run", return_value=self.app.SessionResult(output, 255)) as run:
                with self.assertRaises(self.app.SetupError):
                    self.verify()
                run.assert_called_once()

    def test_program_control_and_interruptions_keep_identity(self):
        faults = (self.app.SetupError("PUBLIC-fatal"), self.app.IBAuthenticationError("PUBLIC-auth"),
                  RuntimeError("PUBLIC-program"), self.app.ProjectInputChanged("PUBLIC-input"),
                  self.app.BatchStopped("PUBLIC-stop"), KeyboardInterrupt())
        for fault in faults:
            with self.subTest(kind=type(fault).__name__), mock.patch.object(self.app.time, "sleep"), \
                    mock.patch.object(self.app, "interactive_run", side_effect=fault) as run:
                observed = None
                try:
                    self.verify()
                except BaseException as caught:
                    observed = caught
                self.assertIs(fault, observed, "existing fatal/control/program/interrupt keeps exact identity")
                run.assert_called_once()

    def test_outer_master_failure_still_stops_once_for_existing_gate(self):
        failure = self.app.SshFailure(self.app.SshFailureKind.JUMP_UNREACHABLE,
                                      "outer", "198.51.100.10", "EXAMPLE-JUMP01")
        with mock.patch.object(self.app.time, "sleep") as sleep, \
                mock.patch.object(self.app, "_jump_control_path_for", side_effect=failure) as check, \
                mock.patch.object(self.app, "interactive_run") as run:
            with self.assertRaises(self.app.SshFailure) as caught:
                self.verify()
        self.assertIs(failure, caught.exception)
        self.assertEqual("OOB_JUMP_UNREACHABLE", caught.exception.failure_kind)
        check.assert_called_once()
        run.assert_not_called()
        sleep.assert_called_once_with(15)

    def test_strict_outer_transport_failure_keeps_existing_gate_category(self):
        with tempfile.TemporaryDirectory(prefix="wp3-outer-") as directory, ExitStack() as stack:
            stack.enter_context(mock.patch.object(self.app, "verify_password_hash", return_value=True))
            policy = strict_policy(self.app, directory)
            sleep = stack.enter_context(mock.patch.object(self.app.time, "sleep"))
            run = stack.enter_context(mock.patch.object(self.app, "interactive_run", return_value=self.app.SessionResult(
                "ssh: connect to host 198.51.100.10 port 22: Connection refused", 255)))
            with self.assertRaises(self.app.SetupError) as caught:
                self.app.verify_ipv4_login(target(self.app), "oob", "cumulus", credential("outer"), "admin", 2,
                                           _ib_current_password=credential("current"), _password_policy=policy)
        self.assertEqual(("management IB operation failed; device state is UNKNOWN",), caught.exception.args)
        self.assertEqual("OOB_JUMP_UNREACHABLE", caught.exception.failure_kind)
        self.assertEqual(("outer", "198.51.100.10"),
                         (caught.exception.ssh_failure.hop, caught.exception.ssh_failure.address))
        run.assert_called_once()
        sleep.assert_called_once_with(15)

    def test_strict_ordinary_io_preserves_only_old_safe_facts(self):
        with tempfile.TemporaryDirectory(prefix="wp3-io-") as directory, ExitStack() as stack:
            stack.enter_context(mock.patch.object(self.app, "verify_password_hash", return_value=True))
            policy = strict_policy(self.app, directory)
            fault = OSError(errno.EACCES, "PUBLIC-IO-value")
            fault.cleanup_uncertain = True
            stack.enter_context(mock.patch.object(self.app.time, "sleep"))
            run = stack.enter_context(mock.patch.object(self.app, "interactive_run", side_effect=fault))
            with self.assertRaises(self.app.SetupError) as caught:
                self.app.verify_ipv4_login(target(self.app), "oob", "cumulus", credential("outer"), "admin", 2,
                                           _ib_current_password=credential("current"), _password_policy=policy)
            error = caught.exception
            self.assertEqual(("management IB operation failed; device state is UNKNOWN",), error.args)
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            self.assertEqual({"cleanup_uncertain": True, "io_errno": errno.EACCES}, vars(error))
            run.assert_called_once()

    def test_real_caller_first_delay_depends_only_on_successful_network_stage(self):
        self.api()
        app = self.app
        for needs_network, apply in ((False, True), (True, True), (False, False)):
            with self.subTest(needs_network=needs_network, apply=apply), ExitStack() as stack:
                state = app.DeviceState((), (), (), (), "EXAMPLE-IB01", "")
                device = target(app)
                task = app.PreparedIBTask(device, app.Neighbor("fe80::10", "swp1", "02:00:00:00:00:10"),
                                          credential("outer"), False)
                args = SimpleNamespace(eth_user="cumulus", ib_user="admin", connect_timeout=2,
                                       apply=apply, force=False, execution_mode="management")
                current = app.SessionResult("PUBLIC-state", 0)
                stack.enter_context(mock.patch.object(app, "inspect_ib_device",
                                                      return_value=(current, credential("current"), True)))
                stack.enter_context(mock.patch.object(app, "parse_nvue_state", return_value=state))
                stack.enter_context(mock.patch.object(app, "base_stage_needed", side_effect=[False, needs_network]))
                # Initial does run in both cases: it must not itself select first_delay=15.
                stack.enter_context(mock.patch.object(app, "run_initial_stage", return_value=("PUBLIC-state", True)))
                stack.enter_context(mock.patch.object(app, "_management_network_commands", return_value=[]))
                stack.enter_context(mock.patch.object(app, "_require_empty_pending"))
                write = stack.enter_context(mock.patch.object(app, "_stage_ib_command", return_value=current))
                stack.enter_context(mock.patch.object(app, "verify_state"))
                stack.enter_context(mock.patch.object(app, "_verify_management_network_state"))
                verify = stack.enter_context(mock.patch.object(app, "verify_ipv4_login"))
                stack.enter_context(mock.patch.object(app, "run_service_stage", return_value=(True, True)))
                stack.enter_context(mock.patch.object(app, "run_key_stage", return_value=True))
                stack.enter_context(mock.patch.object(app, "run_management_direct_checks", return_value=[]))
                result = app.execute_ib_task(task, args, None, credential("initial"), None, [], None)
                if apply:
                    verify.assert_called_once()
                    selected = verify.call_args.kwargs.get("readiness_policy")
                    self.assertIs(type(selected), app.ReadinessPolicy)
                    self.assertEqual(15 if needs_network else 0, selected.first_delay)
                    self.assertEqual((10, 9), (selected.interval, selected.attempts))
                else:
                    verify.assert_not_called()
                    self.assertEqual("NOT_REQUESTED", result["stage_status"]["ipv4_readiness"])
                self.assertEqual(3 if needs_network and apply else 0, write.call_count)


if __name__ == "__main__":
    unittest.main()
