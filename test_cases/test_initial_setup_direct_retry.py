"""Direct: bounded IPv4 readiness and direct read-only SSH retry in initial-setup (v3.1.3 WP-7).

What: verify_ipv4_login (3 probes, 10 s before each, no retry on authentication, host-key or
password-change evidence), verify_management_direct_ssh / run_management_direct_checks (the
management server reaches the IB directly, eth0 first and eth1 only as a fallback, identity is
checked) and readonly_direct_ssh_retry with verify_management_key_possession (3 read-only
attempts, 3 s apart, only for transient network failures; the original diagnostics are kept).

Expectation sources (not derived from the implementation):
- R-011 I24 (需求文档.md:1228, moved from 待确认问题.md:161 on 2026-11-08; TEST tracker
  参考/TEST问题跟踪/user-test-issue-tracker.md:4121): direct SSH retries a short network failure
  at most 3 times per address and keeps the original diagnostic.  I24 is v15-implemented
  behaviour, adopted as this release's test expectation under the owner's 11-06 ruling to take
  v15 as the base (开发计划.md:314; v3.1.3 guide O13 :266, 需求文档.md:1233); it is not an owner
  confirmation of I24.
- The v15 delivered tests 参考/initial-setup-v15/initial-setup-test-cases/
  test_desktop_initial_setup.py::IPv4ReadinessRetryTests (:513-588),
  ::ManagementServerDirectSSHTests (:591-727) and ::DirectReadonlyRetryTests (:730-903); the file
  is bound by HANDOFF-SHA256SUMS:27.  Their assertions are kept.  Table 6-1 row 9 (guide :752):
  the 10 s wait and the 3 attempts are adopted from v15.

Fixture rewrites (public audit, guide :835): synthetic host names (example-ib…, example-oob-leaf…),
documentation addresses only, credentials assembled at run time.  verify_ipv4_login is called on
its non-management-server branch with the selected IB credential as ``ib_password`` and a
different OOB credential (06 WP6-a6), exactly as the v15 tests did.  time.sleep is patched in every
test that reaches verify_ipv4_login or readonly_direct_ssh_retry (guide :173).  No real SSH,
ssh-keygen or device I/O happens: interactive_run and subprocess.run are replaced.
"""
from __future__ import annotations

import contextlib
from dataclasses import replace
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
app = load_script("initial_setup_v15_direct_retry", INITIAL)

MARKER = "ab" * 16


def secret(label: str) -> str:
    # Assembled at run time so no credential literal appears in the source (public audit).
    return "-".join(("PUBLIC", "wp7", label, "Zq7"))


IB_CREDENTIAL = secret("ib-target")
OOB_CREDENTIAL = secret("oob")


def target():
    ib = app.Device("example-ib001", "ib", "192.0.2.10", "192.0.2.10/24",
                    "192.0.2.1", "02:00:00:00:00:10", "", "")
    eth = app.Device("example-oob-leaf01", "eth_jump", "198.51.100.10", "", "", "", "", "")
    return app.Target(ib, eth, "swp1", "eth0")


class DirectRetryTests(unittest.TestCase):
    # -- helpers (v15 IPv4ReadinessRetryTests.verify/success) --------------------------------------
    def ipv4_verify(self):
        app.verify_ipv4_login(target(), "oob", "cumulus", OOB_CREDENTIAL, "admin", 10,
                              ib_password=IB_CREDENTIAL)

    def ipv4_success(self):
        return app.SessionResult("__HTTP_IB_BEGIN_" + MARKER + "__\n"
                                 "__HTTP_IB_END_" + MARKER + "__=0\n", 0)

    # -- helpers (v15 ManagementServerDirectSSHTests.output/dual_target) --------------------------
    def direct_output(self, hostname="example-ib001"):
        config = ("nv set interface eth0 ipv4 address 192.0.2.10/24\n"
                  "nv set interface eth0-1 ipv4 gateway 192.0.2.1\n"
                  "nv set system hostname " + hostname + "\n")
        return "__HTTP_IB_BEGIN_" + MARKER + "__\n" + config + "__HTTP_IB_END_" + MARKER + "__=0\n"

    def dual_target(self):
        original = target()
        device = app.Device("example-ib001", "ib", "192.0.2.10", "192.0.2.10/24",
                            "192.0.2.1", "02:00:00:00:00:10", "192.0.2.11/24", "192.0.2.1")
        return app.Target(device, original.ethernet, "swp1", "eth0")

    # -- helpers (v15 DirectReadonlyRetryTests.success/verify/key_probe) ---------------------------
    def direct_success(self):
        return app.SessionResult(self.direct_output(), 0)

    def direct_verify(self, timeout=10):
        return app.verify_management_direct_ssh(target().ib, "eth0", "admin", IB_CREDENTIAL, timeout)

    def key_probe(self, replies, *, fingerprint="SHA256:fixture"):
        with tempfile.TemporaryDirectory() as directory:
            private_key = Path(directory) / "id_ed25519"
            private_key.write_text("synthetic fixture")
            with patch.object(app, "_public_key_fingerprint", return_value=fingerprint), \
                 patch.object(app.subprocess, "run",
                              side_effect=[subprocess.CompletedProcess([], 0, "fixture", "")] + replies) as run, \
                 patch.object(app.time, "sleep") as wait:
                try:
                    app.verify_management_key_possession(target(), "admin", {"fingerprint": "SHA256:fixture"},
                                                         private_key, 10)
                except app.SetupError as exc:
                    error = str(exc)
                else:
                    error = ""
        return error, run.call_count, [call.args for call in wait.call_args_list]

    # =============================================================================================
    # IPv4 readiness via the OOB jump (v15 IPv4ReadinessRetryTests)
    # =============================================================================================

    # v15 IPv4ReadinessRetryTests.test_first_success_waits_ten_seconds_and_stops (test_desktop_initial_setup.py:523)
    def test_first_success_waits_ten_seconds_and_stops(self):
        with patch.object(app.time, "sleep") as sleep, \
             patch.object(app.os, "urandom", return_value=bytes.fromhex(MARKER)), \
             patch.object(app, "interactive_run", return_value=self.ipv4_success()) as run:
            self.ipv4_verify()
        self.assertEqual([c.args for c in sleep.call_args_list], [(10,)])
        self.assertEqual(run.call_count, 1)
        self.assertNotIn("nv config apply", str(run.call_args.args[0]))
        self.assertNotIn("nv config save", str(run.call_args.args[0]))

    # v15 IPv4ReadinessRetryTests.test_third_attempt_can_succeed_after_network_convergence (test_desktop_initial_setup.py:533)
    def test_third_attempt_can_succeed_after_network_convergence(self):
        failure = app.SessionResult("ssh: connect to host 192.0.2.10 port 22: Connection refused\n", 255)
        with patch.object(app.time, "sleep") as sleep, \
             patch.object(app.os, "urandom", return_value=bytes.fromhex(MARKER)), \
             patch.object(app, "interactive_run", side_effect=[failure, failure, self.ipv4_success()]) as run:
            self.ipv4_verify()
        self.assertEqual([c.args for c in sleep.call_args_list], [(10,), (10,), (10,)])
        self.assertEqual(run.call_count, 3)

    # v15 IPv4ReadinessRetryTests.test_all_attempts_fail_without_fourth_wait_or_attempt (test_desktop_initial_setup.py:542)
    def test_all_attempts_fail_without_fourth_wait_or_attempt(self):
        failure = app.SessionResult("ssh: connect: Network is unreachable\n", 255)
        with patch.object(app.time, "sleep") as sleep, \
             patch.object(app, "interactive_run", return_value=failure) as run:
            with self.assertRaisesRegex(app.SetupError, "after 3 attempts"):
                self.ipv4_verify()
        self.assertEqual([c.args for c in sleep.call_args_list], [(10,), (10,), (10,)])
        self.assertEqual(run.call_count, 3)

    # v15 IPv4ReadinessRetryTests.test_explicit_authentication_or_host_key_failure_is_not_retried (test_desktop_initial_setup.py:551)
    def test_explicit_authentication_or_host_key_failure_is_not_retried(self):
        for output in ("admin@192.0.2.10: Permission denied (password).\n",
                       "Host key verification failed.\n"):
            with self.subTest(output=output), patch.object(app.time, "sleep") as sleep, \
                 patch.object(app, "interactive_run", return_value=app.SessionResult(output, 255)) as run:
                with self.assertRaises(app.SetupError):
                    self.ipv4_verify()
            self.assertEqual(run.call_count, 1)
            self.assertEqual(sleep.call_count, 1)

    # v15 IPv4ReadinessRetryTests.test_expired_password_is_not_changed_or_retried (test_desktop_initial_setup.py:561)
    def test_expired_password_is_not_changed_or_retried(self):
        failure = app.SessionResult("Password has expired\n", 1, password_change_required=True)
        with patch.object(app.time, "sleep"), \
             patch.object(app, "interactive_run", return_value=failure) as run:
            with self.assertRaises(app.SetupError):
                self.ipv4_verify()
        self.assertEqual(run.call_count, 1)
        self.assertFalse(run.call_args.args[1].allow_password_change)

    # v15 IPv4ReadinessRetryTests.test_transport_timeout_can_retry_but_other_safety_errors_cannot (test_desktop_initial_setup.py:570)
    def test_transport_timeout_can_retry_but_other_safety_errors_cannot(self):
        with patch.object(app.time, "sleep"), \
             patch.object(app.os, "urandom", return_value=bytes.fromhex(MARKER)), \
             patch.object(app, "interactive_run", side_effect=[
                 app.SetupError("SSH/PAM session timed out; device state may be unknown"),
                 self.ipv4_success()]) as run:
            self.ipv4_verify()
        self.assertEqual(run.call_count, 2)
        with patch.object(app.time, "sleep"), \
             patch.object(app, "interactive_run",
                          side_effect=app.SetupError("SSH output exceeded the safety limit")) as run:
            with self.assertRaises(app.SetupError):
                self.ipv4_verify()
        self.assertEqual(run.call_count, 1)

    # v15 IPv4ReadinessRetryTests.test_no_success_assumed_without_complete_command_frame (test_desktop_initial_setup.py:584)
    def test_no_success_assumed_without_complete_command_frame(self):
        with patch.object(app.time, "sleep"), \
             patch.object(app, "interactive_run", return_value=app.SessionResult("Welcome to NVOS\n", 0)):
            with self.assertRaises(app.SetupError):
                self.ipv4_verify()

    # =============================================================================================
    # Management server -> IB direct SSH (v15 ManagementServerDirectSSHTests)
    # =============================================================================================

    # v15 ManagementServerDirectSSHTests.test_probe_uses_direct_ip_and_no_jump_or_password_in_argv (test_desktop_initial_setup.py:599)
    def test_probe_uses_direct_ip_and_no_jump_or_password_in_argv(self):
        with patch.object(app.os, "urandom", return_value=bytes.fromhex(MARKER)), \
             patch.object(app, "interactive_run", return_value=app.SessionResult(self.direct_output(), 0)) as run:
            app.verify_management_direct_ssh(target().ib, "eth0", "admin", IB_CREDENTIAL, 10)
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], "ssh")
        self.assertIn("admin@192.0.2.10", argv)
        self.assertIn("ProxyCommand=none", argv)
        self.assertIn("ProxyJump=none", argv)
        self.assertIn("ConnectTimeout=3", argv)
        self.assertNotIn("198.51.100.10", str(argv))
        self.assertNotIn(IB_CREDENTIAL, str(argv))
        self.assertFalse(run.call_args.args[1].allow_password_change)

    # v15 ManagementServerDirectSSHTests.test_wrong_device_at_the_ip_is_not_upgrade_access_ready (test_desktop_initial_setup.py:613)
    def test_wrong_device_at_the_ip_is_not_upgrade_access_ready(self):
        with patch.object(app.os, "urandom", return_value=bytes.fromhex(MARKER)), \
             patch.object(app, "interactive_run",
                          return_value=app.SessionResult(self.direct_output("example-other-switch"), 0)):
            with self.assertRaises(app.SetupError):
                app.verify_management_direct_ssh(target().ib, "eth0", "admin", IB_CREDENTIAL, 10)

    # v15 ManagementServerDirectSSHTests.test_authentication_or_forced_password_change_is_not_success (test_desktop_initial_setup.py:619)
    def test_authentication_or_forced_password_change_is_not_success(self):
        for result in (app.SessionResult("Permission denied (password).\n", 255),
                       app.SessionResult("Password has expired\n", 1, password_change_required=True)):
            with self.subTest(result=result), patch.object(app, "interactive_run", return_value=result):
                with self.assertRaises(app.SetupError):
                    app.verify_management_direct_ssh(target().ib, "eth0", "admin", IB_CREDENTIAL, 10)

    # v15 ManagementServerDirectSSHTests.test_eth0_success_does_not_probe_eth1 (test_desktop_initial_setup.py:632)
    def test_eth0_success_does_not_probe_eth1(self):
        t = self.dual_target()
        with patch.object(app, "verify_management_direct_ssh", return_value=None) as probe:
            rows = app.run_management_direct_checks([t], {"example-ib001": IB_CREDENTIAL}, "admin", 10,
                                                    on_management_server=True)
        self.assertEqual(probe.call_count, 1)
        self.assertEqual(probe.call_args.args[1], "eth0")
        self.assertEqual([(r["interface"], r["ip"], r["status"]) for r in rows],
                         [("eth0", "192.0.2.10", "PASS"), ("eth1", "192.0.2.11", "NOT_NEEDED")])
        self.assertNotIn(IB_CREDENTIAL, repr(rows))

    # v15 ManagementServerDirectSSHTests.test_summary_hides_not_needed_without_changing_readiness_counts (test_desktop_initial_setup.py:643)
    def test_summary_hides_not_needed_without_changing_readiness_counts(self):
        rows = [
            {"hostname": "example-ib001", "interface": "eth0", "ip": "192.0.2.10",
             "status": "PASS", "detail": "verified"},
            {"hostname": "example-ib001", "interface": "eth1", "ip": "192.0.2.11",
             "status": "NOT_NEEDED", "detail": "eth0 passed; fallback not needed"},
        ]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            app.log_management_direct_summary(rows)
        self.assertIn("eth0 192.0.2.10", output.getvalue())
        self.assertNotIn("NOT_NEEDED", output.getvalue())
        self.assertNotIn("192.0.2.11", output.getvalue())
        self.assertEqual(app.summarize_management_direct_checks(rows),
                         {"ready": 1, "failed": 0, "not_tested": 0, "fallback": 0})

    # v15 ManagementServerDirectSSHTests.test_summary_hides_untested_interfaces_but_keeps_device_count (test_desktop_initial_setup.py:659)
    def test_summary_hides_untested_interfaces_but_keeps_device_count(self):
        rows = [
            {"hostname": "example-ib064", "interface": "eth0", "ip": "192.0.2.127",
             "status": "NOT_TESTED", "detail": "base configuration not verified"},
            {"hostname": "example-ib064", "interface": "eth1", "ip": "192.0.2.128",
             "status": "NOT_TESTED", "detail": "base configuration not verified"},
            {"hostname": "example-ib001", "interface": "eth0", "ip": "192.0.2.10",
             "status": "PASS", "detail": "verified"},
        ]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            app.log_management_direct_summary(rows)
        self.assertNotIn("NOT_TESTED", output.getvalue())
        self.assertNotIn("example-ib064", output.getvalue())
        self.assertIn("example-ib001 eth0 192.0.2.10: PASS", output.getvalue())
        self.assertEqual(app.summarize_management_direct_checks(rows),
                         {"ready": 1, "failed": 0, "not_tested": 1, "fallback": 0})

    # v15 ManagementServerDirectSSHTests.test_summary_does_not_hide_failed_eth0_or_successful_eth1_fallback (test_desktop_initial_setup.py:677)
    def test_summary_does_not_hide_failed_eth0_or_successful_eth1_fallback(self):
        rows = [
            {"hostname": "example-ib001", "interface": "eth0", "ip": "192.0.2.10",
             "status": "FAIL", "detail": "connection timed out"},
            {"hostname": "example-ib001", "interface": "eth1", "ip": "192.0.2.11",
             "status": "PASS", "detail": "verified"},
        ]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            app.log_management_direct_summary(rows)
        self.assertIn("eth0 192.0.2.10: FAIL", output.getvalue())
        self.assertIn("eth1 192.0.2.11: PASS", output.getvalue())

    # v15 ManagementServerDirectSSHTests.test_eth0_failure_falls_back_to_eth1_and_counts_as_access_ready (test_desktop_initial_setup.py:690)
    def test_eth0_failure_falls_back_to_eth1_and_counts_as_access_ready(self):
        with patch.object(app, "verify_management_direct_ssh", side_effect=[
                app.SetupError("connection timed out"), None]) as probe:
            rows = app.run_management_direct_checks([self.dual_target()], {"example-ib001": IB_CREDENTIAL},
                                                    "admin", 10, on_management_server=True)
        self.assertEqual([call.args[1] for call in probe.call_args_list], ["eth0", "eth1"])
        self.assertEqual([row["status"] for row in rows], ["FAIL", "PASS"])
        self.assertEqual(app.summarize_management_direct_checks(rows),
                         {"ready": 1, "failed": 0, "not_tested": 0, "fallback": 1})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            app.log_management_direct_summary(rows)
        self.assertIn("eth1 192.0.2.11", output.getvalue())

    # v15 ManagementServerDirectSSHTests.test_both_interfaces_failing_is_one_unreachable_device (test_desktop_initial_setup.py:704)
    def test_both_interfaces_failing_is_one_unreachable_device(self):
        with patch.object(app, "verify_management_direct_ssh", side_effect=app.SetupError("unreachable")) as probe:
            rows = app.run_management_direct_checks([self.dual_target()], {"example-ib001": IB_CREDENTIAL},
                                                    "admin", 10, on_management_server=True)
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(app.summarize_management_direct_checks(rows),
                         {"ready": 0, "failed": 1, "not_tested": 0, "fallback": 0})

    # v15 ManagementServerDirectSSHTests.test_no_eth1_address_means_no_fallback_probe (test_desktop_initial_setup.py:712)
    def test_no_eth1_address_means_no_fallback_probe(self):
        with patch.object(app, "verify_management_direct_ssh", side_effect=app.SetupError("unreachable")) as probe:
            rows = app.run_management_direct_checks([target()], {"example-ib001": IB_CREDENTIAL},
                                                    "admin", 10, on_management_server=True)
        self.assertEqual(probe.call_count, 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "FAIL")

    # v15 ManagementServerDirectSSHTests.test_unverified_or_non_management_execution_is_explicitly_not_tested (test_desktop_initial_setup.py:720)
    def test_unverified_or_non_management_execution_is_explicitly_not_tested(self):
        for credentials, is_management in (({}, True), ({"example-ib001": IB_CREDENTIAL}, False)):
            with self.subTest(is_management=is_management), \
                 patch.object(app, "verify_management_direct_ssh") as probe:
                rows = app.run_management_direct_checks([target()], credentials, "admin", 10,
                                                        on_management_server=is_management)
            probe.assert_not_called()
            self.assertEqual(rows[0]["status"], "NOT_TESTED")

    # =============================================================================================
    # Read-only direct retry (v15 DirectReadonlyRetryTests)
    # =============================================================================================

    # v15 DirectReadonlyRetryTests.test_first_success_uses_three_second_connect_timeout_and_no_sleep (test_desktop_initial_setup.py:737)
    def test_first_success_uses_three_second_connect_timeout_and_no_sleep(self):
        with patch.object(app.os, "urandom", return_value=bytes.fromhex(MARKER)), \
             patch.object(app, "interactive_run", return_value=self.direct_success()) as run, \
             patch.object(app.time, "sleep") as wait:
            self.direct_verify()
        self.assertEqual(run.call_count, 1)
        self.assertIn("ConnectTimeout=3", run.call_args.args[0])
        self.assertIn("ConnectionAttempts=1", run.call_args.args[0])
        wait.assert_not_called()

    # v15 DirectReadonlyRetryTests.test_third_success_retries_only_reads_and_counts_each_attempt (test_desktop_initial_setup.py:747)
    def test_third_success_retries_only_reads_and_counts_each_attempt(self):
        failures = [app.SessionResult("ssh: connect to host 192.0.2.10 port 22: No route to host\n", 255),
                    app.SessionResult("ssh: connect to host 192.0.2.10 port 22: Connection timed out\n", 255)]
        with patch.object(app.os, "urandom", return_value=bytes.fromhex(MARKER)), \
             patch.object(app, "interactive_run", side_effect=failures + [self.direct_success()]) as run, \
             patch.object(app.time, "sleep") as wait, patch.object(app, "record_metric") as metric:
            self.direct_verify()
        self.assertEqual(run.call_count, 3)
        self.assertEqual([call.args for call in wait.call_args_list], [(3,), (3,)])
        self.assertEqual(sum(call.args == ("direct_ssh_attempts",) for call in metric.call_args_list), 3)
        for call in run.call_args_list:
            self.assertIn("nv config show -o commands", call.args[0][-1])
            self.assertNotIn("nv config apply", call.args[0][-1])
            self.assertFalse(call.args[1].allow_password_change)
            self.assertNotIn(IB_CREDENTIAL, str(call.args[0]))

    # v15 DirectReadonlyRetryTests.test_all_network_failures_stop_after_three_with_real_detail (test_desktop_initial_setup.py:763)
    def test_all_network_failures_stop_after_three_with_real_detail(self):
        failure = app.SessionResult("ssh: connect to host 192.0.2.10 port 22: No route to host\n", 255)
        with patch.object(app, "interactive_run", return_value=failure) as run, \
             patch.object(app.time, "sleep") as wait:
            with self.assertRaisesRegex(app.SetupError, r"3 attempts.*No route to host"):
                self.direct_verify()
        self.assertEqual(run.call_count, 3)
        self.assertEqual(wait.call_count, 2)

    # v15 DirectReadonlyRetryTests.test_authentication_hostkey_expiry_and_unclassified_failures_do_not_retry (test_desktop_initial_setup.py:771)
    def test_authentication_hostkey_expiry_and_unclassified_failures_do_not_retry(self):
        for text in ("Permission denied (password).", "Host key verification failed.",
                     "REMOTE HOST IDENTIFICATION HAS CHANGED!", "WARNING: Your password has expired.",
                     "No matching host key type found.", "unexpected remote failure",
                     "Permission denied (password).\nssh: connect: Connection timed out"):
            with self.subTest(text=text), \
                 patch.object(app, "interactive_run", return_value=app.SessionResult(text, 255)) as run, \
                 patch.object(app.time, "sleep") as wait:
                with self.assertRaises(app.SetupError):
                    self.direct_verify()
                self.assertEqual(run.call_count, 1)
                wait.assert_not_called()

    # v15 DirectReadonlyRetryTests.test_missing_frame_or_wrong_identity_is_not_retried (test_desktop_initial_setup.py:783)
    def test_missing_frame_or_wrong_identity_is_not_retried(self):
        for result in (app.SessionResult("NVOS banner only", 0),
                       app.SessionResult(self.direct_output("example-wrong-device"), 0)):
            with self.subTest(output=result.output), \
                 patch.object(app.os, "urandom", return_value=bytes.fromhex(MARKER)), \
                 patch.object(app, "interactive_run", return_value=result) as run, \
                 patch.object(app.time, "sleep") as wait:
                with self.assertRaises(app.SetupError):
                    self.direct_verify()
                self.assertEqual(run.call_count, 1)
                wait.assert_not_called()

    # v15 DirectReadonlyRetryTests.test_bounded_session_timeout_can_retry_without_password_rotation (test_desktop_initial_setup.py:794)
    def test_bounded_session_timeout_can_retry_without_password_rotation(self):
        with patch.object(app.os, "urandom", return_value=bytes.fromhex(MARKER)), \
             patch.object(app, "interactive_run", side_effect=[
                 app.SetupError("SSH/PAM session timed out; device state may be unknown"),
                 self.direct_success()]) as run, \
             patch.object(app.time, "sleep") as wait:
            self.direct_verify()
        self.assertEqual(run.call_count, 2)
        self.assertEqual([call.args for call in wait.call_args_list], [(3,)])

    # v15 DirectReadonlyRetryTests.test_shorter_explicit_connect_timeout_is_preserved (test_desktop_initial_setup.py:802)
    def test_shorter_explicit_connect_timeout_is_preserved(self):
        with patch.object(app.os, "urandom", return_value=bytes.fromhex(MARKER)), \
             patch.object(app, "interactive_run", return_value=self.direct_success()) as run:
            self.direct_verify(1)
        self.assertIn("ConnectTimeout=1", run.call_args.args[0])

    # v15 DirectReadonlyRetryTests.test_eth1_fallback_starts_only_after_three_failed_eth0_reads (test_desktop_initial_setup.py:808)
    def test_eth1_fallback_starts_only_after_three_failed_eth0_reads(self):
        original = target()
        t = app.Target(replace(original.ib, eth1_prefix="192.0.2.11/24", eth1_gateway="192.0.2.1"),
                       original.ethernet, original.ethernet_port, original.ib_port_alias)
        calls = []

        def transport(argv, responder, timeout):
            calls.append(argv)
            if "admin@192.0.2.10" in argv:
                return app.SessionResult("ssh: connect to host 192.0.2.10 port 22: No route to host", 255)
            return app.SessionResult(self.direct_output().replace(
                "nv set system hostname",
                "nv set interface eth1 ipv4 address 192.0.2.11/24\nnv set system hostname"), 0)
        with patch.object(app.os, "urandom", return_value=bytes.fromhex(MARKER)), \
             patch.object(app, "interactive_run", side_effect=transport), \
             patch.object(app.time, "sleep") as wait:
            rows = app.run_management_direct_checks([t], {"example-ib001": IB_CREDENTIAL}, "admin", 10,
                                                    on_management_server=True)
        self.assertEqual(len(calls), 4)
        self.assertEqual([row["status"] for row in rows], ["FAIL", "PASS"])
        self.assertEqual(app.summarize_management_direct_checks(rows),
                         {"ready": 1, "failed": 0, "not_tested": 0, "fallback": 1})
        self.assertEqual([call.args for call in wait.call_args_list], [(3,), (3,)])

    # v15 DirectReadonlyRetryTests.test_key_probe_retries_connections_without_reinstalling_key (test_desktop_initial_setup.py:830)
    def test_key_probe_retries_connections_without_reinstalling_key(self):
        with tempfile.TemporaryDirectory() as directory:
            private_key = Path(directory) / "id_ed25519"
            private_key.write_text("synthetic test fixture; never used by real ssh")
            entry = {"name": "mgmt-server.pub", "fingerprint": "SHA256:fixture"}
            replies = [subprocess.CompletedProcess([], 0, "synthetic public key\n", ""),
                       subprocess.CompletedProcess(
                           [], 255, "", "ssh: connect to host 192.0.2.10 port 22: No route to host\n"),
                       subprocess.CompletedProcess([], 0, "", "")]
            with patch.object(app, "key_install_command", return_value=["test-install"]), \
                 patch.object(app, "run_on_ib",
                              return_value=app.SessionResult("IBSW_PUBLIC_KEYS_UPDATED\n", 0)) as install, \
                 patch.object(app, "_public_key_fingerprint", return_value="SHA256:fixture"), \
                 patch.object(app.subprocess, "run", side_effect=replies) as run, \
                 patch.object(app.time, "sleep") as wait, patch.object(app, "record_metric") as metric:
                app.run_key_stage(target(), app.Neighbor("fe80::10", "vlan1000", target().ib.eth0_mac),
                                  "cumulus", OOB_CREDENTIAL, "admin", 10, [entry], local=False, apply=True,
                                  authorized=True, management_private_key=private_key,
                                  ib_password=IB_CREDENTIAL)
            install.assert_called_once()
            self.assertEqual(run.call_count, 3)
            self.assertEqual([call.args for call in wait.call_args_list], [(3,)])
            probes = [call.args[0] for call in run.call_args_list if call.args[0][0] == "ssh"]
            self.assertEqual(len(probes), 2)
            for argv in probes:
                self.assertIn("ConnectTimeout=3", argv)
                self.assertIn("ConnectionAttempts=1", argv)
                self.assertIn("ProxyCommand=none", argv)
                self.assertIn("ProxyJump=none", argv)
                self.assertIn("ControlMaster=no", argv)
                self.assertIn("PreferredAuthentications=publickey", argv)
            self.assertEqual(sum(c.args == ("public_key_ssh_attempts",) for c in metric.call_args_list), 2)

    # v15 DirectReadonlyRetryTests.test_key_probe_exhaustion_preserves_stderr_and_three_attempt_count (test_desktop_initial_setup.py:875)
    def test_key_probe_exhaustion_preserves_stderr_and_three_attempt_count(self):
        failure = subprocess.CompletedProcess([], 255, "", "ssh: connect to host 192.0.2.10 port 22: No route to host")
        error, calls, waits = self.key_probe([failure] * 3)
        self.assertIn("No route to host", error)
        self.assertIn("3 attempts", error)
        self.assertEqual(calls, 4)
        self.assertEqual(waits, [(3,), (3,)])

    # v15 DirectReadonlyRetryTests.test_key_authentication_and_hostkey_failures_do_not_retry (test_desktop_initial_setup.py:883)
    def test_key_authentication_and_hostkey_failures_do_not_retry(self):
        for text in ("Permission denied (publickey).", "Host key verification failed.",
                     "REMOTE HOST IDENTIFICATION HAS CHANGED!", "Load key: invalid format",
                     "No matching key exchange method found."):
            with self.subTest(text=text):
                error, calls, waits = self.key_probe([subprocess.CompletedProcess([], 255, "", text)])
                self.assertIn(text, error)
                self.assertEqual(calls, 2)
                self.assertEqual(waits, [])

    # v15 DirectReadonlyRetryTests.test_local_key_mismatch_does_not_attempt_ssh_or_retry (test_desktop_initial_setup.py:893)
    def test_local_key_mismatch_does_not_attempt_ssh_or_retry(self):
        error, calls, waits = self.key_probe([], fingerprint="SHA256:different")
        self.assertIn("does not match", error)
        self.assertEqual(calls, 1)
        self.assertEqual(waits, [])

    # v15 DirectReadonlyRetryTests.test_key_readonly_session_timeout_can_recover (test_desktop_initial_setup.py:899)
    def test_key_readonly_session_timeout_can_recover(self):
        error, calls, waits = self.key_probe([subprocess.TimeoutExpired(["ssh"], 15),
                                              subprocess.CompletedProcess([], 0, "", "")])
        self.assertEqual(error, "")
        self.assertEqual(calls, 3)
        self.assertEqual(waits, [(3,)])


if __name__ == "__main__":
    unittest.main()
