"""Direct: initial-setup's operator output — compact console vs full report, the seven-module
English Summary with mutually exclusive outcome categories, SUCCESS/INCOMPLETE/FAILED, per-stage
and SSH-access counts, worker progress lines, public-key stage visibility and key receipts.

Expectation sources: the v15 delivered tests initial-setup-test-cases/test_desktop_initial_setup.py
::ModularOutputTests (:1782), ::SummaryOperatorContractTests (:1952), ::ClassifiedSummaryTests
(:2082), ::PublicKeyStageVisibilityTests (:906) (file bytes bound by HANDOFF-SHA256SUMS:27) and
initial-setup-test-cases/test_initial_setup_log_review.py::ProgressAndSummaryDirectTests (:169)
(bound by HANDOFF-SHA256SUMS:29); v15 CURRENT-CONTRACT.md:21 (summary fields) and :67 (FAILED only
for a script/shared-flow failure, INCOMPLETE for remaining device work).  Gaps that no DEV test
pins (guide table 7-1 :818 "缺的补"), ported with their v15 origin marked:
test_initial_setup_log_review.py::KeyReceiptDirectTests (:120; receipt -> content action, metric
and category) and ::AuthorizedKeyTaskWorkflowTests (:262).  Expectations are not derived from the
merged implementation.

Not moved (v3.1.3 guide WP-7): ProgressAndSummaryDirectTests
.test_manifest_maps_current_entry_and_real_generated_program_scenarios pins the v15 delivery
package itself (its handoff manifest and the v14 file name).  Of
.test_version_query_needs_no_inputs_and_creates_no_run_artifacts only the v14 version string is
not moved: the merged entry's --version string is pinned by test_ibsw225_initializer_help_guard
(guide table 6-1 row 7, :750); the no-input / no-artifact half is ported here.
KeyReceiptDirectTests.test_missing_duplicate_or_unknown_receipt_cannot_claim_install_verified is
covered more strictly by test_initial_setup_key_receipt_consumer (DEV exact receipt match,
06 D1a2-03, guide :818).

Fixture rewrites (public audit, guide :835): synthetic host names, documentation addresses,
02:00:00 MACs, credentials assembled at run time, SSH public keys generated at run time.  Two
tests start real local worker processes, both through run_local_pool (17 tasks, two workers); the
one-task run_prepared_tasks calls stay in the inline slot.  The version test calls main() in
process with only --version, which exits in parse_args() before any input is read.
PerRunReportNameTests (v3.1.3 guide WP-10, :1078-1084) runs main() in process on a temporary
project and working directory (management mode, OOB access replaced, HOME temporary): without
--report every run writes its own report in the same directory, and its devices-* directory
carries the report's timestamp; an explicit --report is written verbatim.  Expectation sources:
开发计划.md :314 「每次运行用单独的文件名（目录不变）」 and O12 (guide :265, :1071); not derived from
the implementation.  No test reaches a device, and the generated key shell runs against a
temporary HOME.
"""

from __future__ import annotations

import base64
import contextlib
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_cases.module_loader import load_script
from test_cases.initial_setup_jump_fixture import legacy_jump_sessions_factory

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
app = load_script("initial_setup_v15_summary_output", INITIAL)


def secret(label: str) -> str:
    return "-".join(("PUBLIC", "wp7", label, "Zq7"))


PASSWORD = secret("target")
OOB_PASSWORD = secret("oob")
INITIAL_PASSWORD = secret("initial")
CONFIG = "nv set system hostname nvos\n"
REPORT = Path("synthetic-report.log")


def target():
    ib = app.Device("example-ib001", "ib", "192.0.2.10", "192.0.2.10/24",
                    "192.0.2.1", "02:00:00:00:00:10", "", "")
    eth = app.Device("example-oob-leaf01", "eth_jump", "198.51.100.10", "", "", "", "", "")
    return app.Target(ib, eth, "swp1", "eth0")


def public(number):
    algorithm = b"ssh-ed25519"
    blob = struct.pack(">I", len(algorithm)) + algorithm + struct.pack(">I", 32) + bytes([number]) * 32
    return "ssh-ed25519 " + base64.b64encode(blob).decode() + " fixture-" + str(number)


def success(task):
    """v15 WorkerProcessLifecycleTests.success (test_desktop_initial_setup.py:1181)."""
    return {"hostname": task.target.ib.hostname, "outcome": "CONFIGURED", "reason": "",
            "direct_rows": [], "batch_error": ""}


def run_local_pool(simulated, *, count=17, apply=False, yes=False, timeout=20):
    """v15 WorkerProcessLifecycleTests.run_local_pool (test_desktop_initial_setup.py:1185):
    the real scheduler and worker processes; execute_ib_task is replaced, so no device IO."""
    original = target()
    tasks = [app.PreparedIBTask(app.Target(replace(original.ib, hostname=f"example-ib{number:03d}"),
                                           original.ethernet, "swp1", "eth0"),
                                app.Neighbor("fe80::10", "vlan1000", original.ib.eth0_mac, "oob"), "", False)
             for number in range(1, count + 1)]
    messages = []
    with tempfile.TemporaryDirectory() as directory:
        args = SimpleNamespace(max_workers=16, task_timeout=timeout,
                               report=Path(directory) / "report.log", apply=apply, yes=yes)
        with patch.object(app, "execute_ib_task", simulated), \
             patch.object(app, "interactive_run", side_effect=AssertionError("Real device IO forbidden")), \
             patch.object(app, "log", lambda message="": messages.append(message)):
            result = app.run_prepared_tasks(tasks, args, None, INITIAL_PASSWORD, None, [], None)
        logs = [path.read_text() for path in Path(result["log_dir"]).glob("*.log")]
    return result, messages, logs


def install_keys(home, lines):
    """v15 KeyShellWorkflowTests.install (test_initial_setup_log_review.py:29): run the real
    generated key-install shell against a private test HOME; no ssh or network tool."""
    entries = [dict(name="key" + str(i) + ".pub", line=line, fingerprint=app._public_key_fingerprint(line))
               for i, line in enumerate(lines)]
    argv = app.key_install_command(entries)
    script = argv[2].replace('"${HOME:-}"', shlex.quote(str(home))).replace(
        '"$HOME"', shlex.quote(str(home))).replace('"$HOME/.ssh"', shlex.quote(str(home / ".ssh")))
    if "$HOME" in script:
        raise AssertionError("remote HOME expansion left unbound")
    return subprocess.run([argv[0], "-c", script, *argv[3:]], capture_output=True, text=True,
                          timeout=5, cwd=home, check=False,
                          env={"HOME": str(home), "PATH": os.defpath, "LC_ALL": "C", "LANG": "C"})


class SummaryOutputTests(unittest.TestCase):
    def summary(self, records, direct_rows=(), *, fatal=""):
        targets = [app.Target(replace(target().ib, hostname=name), target().ethernet,
                              "swp" + str(index + 1), "eth0") for index, name in enumerate(records)]
        output = []
        with patch.object(app, "log", lambda message="": output.append(message)):
            result = app.print_initial_setup_summary("synthetic", SimpleNamespace(apply=True,
                report=REPORT), targets, len(targets), {}, records, list(direct_rows), 1, fatal)
        return result, "\n".join(output)

    # ---- v15 ModularOutputTests ---------------------------------------------------------------
    # v15 ModularOutputTests.test_detail_is_report_only_in_compact_mode (test_desktop_initial_setup.py:1783)
    def test_detail_is_report_only_in_compact_mode(self):
        report, console = io.StringIO(), io.StringIO()
        with patch.object(app, "REPORT_HANDLE", report), patch.object(app, "_CONSOLE_VERBOSE", False), \
             contextlib.redirect_stdout(console):
            app.report_detail("full diagnostic command output")
            app.log("one progress line")
        self.assertEqual(console.getvalue(), "one progress line\n")
        self.assertEqual(report.getvalue(), "full diagnostic command output\none progress line\n")

    # v15 ModularOutputTests.test_verbose_keeps_detail_on_terminal_and_in_report (test_desktop_initial_setup.py:1792)
    def test_verbose_keeps_detail_on_terminal_and_in_report(self):
        report, console = io.StringIO(), io.StringIO()
        with patch.object(app, "REPORT_HANDLE", report), patch.object(app, "_CONSOLE_VERBOSE", True), \
             contextlib.redirect_stdout(console):
            app.report_detail("full diagnostic command output")
        self.assertEqual(console.getvalue(), report.getvalue())
        self.assertIn("full diagnostic command output", console.getvalue())

    # v15 ModularOutputTests.test_compact_workers_keep_full_private_logs_but_print_one_completion_each (test_desktop_initial_setup.py:1800)
    def test_compact_workers_keep_full_private_logs_but_print_one_completion_each(self):
        def simulated(task, *args, **kwargs):
            app.log("SYNTHETIC DETAIL for " + task.target.ib.hostname)
            app.task_phase("synthetic phase")
            return success(task)
        with patch.object(app, "_CONSOLE_VERBOSE", False):
            result, messages, logs = run_local_pool(simulated)
        output = "\n".join(messages)
        self.assertEqual(len(result["records"]), 17)
        self.assertNotIn("SYNTHETIC DETAIL", output)
        self.assertNotIn("DEVICE LOG BEGIN", output)
        self.assertNotIn("[PHASE", output)
        self.assertEqual(sum(line.startswith("[DONE ") for line in messages), 17)
        self.assertEqual(sum("SYNTHETIC DETAIL" in body for body in logs), 17)

    # v15 ModularOutputTests.test_summary_has_seven_ordered_modules_without_operation_counters (test_desktop_initial_setup.py:1825)
    def test_summary_has_seven_ordered_modules_without_operation_counters(self):
        result, output = self.summary({"example-ib001": {"hostname": "example-ib001", "outcome": "SKIPPED",
            "category": "SKIPPED_LINK_DOWN", "port": "swp1", "reason": "Oper Status DOWN"}})
        self.assertEqual(result, "INCOMPLETE")
        headings = ("01 OVERVIEW", "02 OOB SNAPSHOTS", "03 IB SWITCHES OUTCOMES", "04 CONFIGURATION STAGES",
                    "05 SSH ACCESS", "06 ATTENTION REQUIRED", "07 EVIDENCE & NEXT ACTIONS")
        positions = [output.index(heading) for heading in headings]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("OPERATION COUNTERS", output)
        self.assertNotIn("Workers:", output)
        self.assertIn("SKIPPED_LINK_DOWN: 1", output)
        self.assertIn("TOTAL: 1", output)

    # v15 ModularOutputTests.test_idempotent_key_install_is_not_reported_as_base_configuration (test_desktop_initial_setup.py:1838)
    def test_idempotent_key_install_is_not_reported_as_base_configuration(self):
        records = {
            "example-ib001": {"outcome": "ALREADY_CONFIGURED", "writes_attempted": True,
                "metrics": {"public_key_install_attempts": 1}, "stage_status": {"day0": "ALREADY_PRESENT", "services": "SKIPPED", "public_keys": "COMPLETED"}},
            "example-ib002": {"outcome": "CONFIGURED", "writes_attempted": True,
                "metrics": {"nvue_write_commands": 9, "public_key_install_attempts": 1},
                "stage_status": {"day0": "VERIFIED", "services": "VERIFIED", "public_keys": "COMPLETED"}},
        }
        _, output = self.summary(records)
        self.assertIn("CHECKED_EXISTING_KEY_INSTALL_COMPLETED: 1", output)
        self.assertNotIn("CHECKED_EXISTING_KEYS_REFRESHED: 1", output,
                         "legacy records without a change receipt cannot prove content was refreshed")
        self.assertIn("CHECKED_AND_CONFIGURED: 1", output)
        self.assertIn("Network: ALREADY_PRESENT=1, VERIFIED=1", output)
        self.assertIn("idempotent", output.lower())

    # v15 ModularOutputTests.test_summary_separates_key_install_completion_from_retried_network_verification (test_desktop_initial_setup.py:1854)
    def test_summary_separates_key_install_completion_from_retried_network_verification(self):
        records = {
            "example-ib001": {"outcome": "FAILED", "writes_attempted": True,
                "failure_kind": "DIRECT_SSH_NETWORK", "failed_stage": "public_keys",
                "reason": "No route to host after 3 attempts",
                "metrics": {"public_key_install_attempts": 1, "public_key_install_completed": 1,
                            "public_key_ssh_attempts": 3},
                "stage_status": {"day0": "ALREADY_PRESENT", "public_keys": "FAILED"}},
            "example-ib002": {"outcome": "ALREADY_CONFIGURED", "writes_attempted": True,
                "metrics": {"public_key_install_attempts": 1, "public_key_install_completed": 1,
                            "public_key_ssh_attempts": 2, "public_key_ssh_verified": 1},
                "stage_status": {"day0": "ALREADY_PRESENT", "public_keys": "COMPLETED"}},
        }
        result, output = self.summary(records)
        self.assertEqual(result, "INCOMPLETE")
        self.assertIn("FAILED_DIRECT_SSH_NETWORK: 1", output)
        self.assertIn("Key install command completed: 2 device(s)", output)
        self.assertIn("Management-key SSH verification: verified=1 failed/unverified=1 not-attempted=0", output)
        self.assertNotIn("FAILED_AFTER_WRITE_UNVERIFIED: 1", output)

    # v15 ModularOutputTests.test_failed_transit_readiness_with_direct_success_remains_failed_not_upgrade_ready (test_desktop_initial_setup.py:1874)
    def test_failed_transit_readiness_with_direct_success_remains_failed_not_upgrade_ready(self):
        records = {"example-ib001": {"outcome": "FAILED", "writes_attempted": True,
            "reason": "IPv4 via OOB timed out", "port": "swp1", "failed_stage": "ipv4_readiness",
            "metrics": {"ib_ssh_attempts": 3, "nvue_write_commands": 9},
            "stage_status": {"day0": "VERIFIED", "ipv4_readiness": "FAILED", "services": "NOT_REACHED", "public_keys": "NOT_REACHED"}}}
        rows = [{"hostname": "example-ib001", "interface": "eth0", "ip": "192.0.2.10", "status": "PASS", "detail": "verified"}]
        result, output = self.summary(records, rows)
        self.assertEqual(result, "INCOMPLETE")
        self.assertIn("FAILED_OOB_IPV4_READINESS: 1", output)
        self.assertIn("Network: VERIFIED=1", output)
        self.assertIn("OOB IPv4 readiness failed but ZTP-server direct SSH passed: 1", output)
        self.assertIn("Setup complete + direct SSH verified: 0/1", output)
        self.assertIn("example-ib001", output)
        self.assertIn("ipv4_readiness", output)

    # v15 ModularOutputTests.test_summary_order_does_not_depend_on_worker_completion_order (test_desktop_initial_setup.py:1889)
    def test_summary_order_does_not_depend_on_worker_completion_order(self):
        records = {name: {"hostname": name, "outcome": "FAILED", "reason": name + " diagnostic"}
                   for name in ("example-ib003", "example-ib001", "example-ib002")}
        _, output = self.summary(records)
        attention = output.split("06 ATTENTION REQUIRED", 1)[1].split("07 EVIDENCE & NEXT ACTIONS", 1)[0]
        self.assertLess(attention.index("example-ib001"), attention.index("example-ib002"))
        self.assertLess(attention.index("example-ib002"), attention.index("example-ib003"))

    # v15 ModularOutputTests.test_direct_summary_never_emits_one_unbounded_ready_line (test_desktop_initial_setup.py:1897)
    def test_direct_summary_never_emits_one_unbounded_ready_line(self):
        rows = [{"hostname": f"example-ib{i:03d}", "interface": "eth0", "ip": f"192.0.2.{i}",
                 "status": "PASS", "detail": "verified"} for i in range(1, 65)]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            app.log_management_direct_summary(rows)
        self.assertTrue(all(len(line) <= 200 for line in output.getvalue().splitlines()))

    # v15 ModularOutputTests.test_readiness_error_does_not_overwrite_verified_day0_stage (test_desktop_initial_setup.py:1905)
    def test_readiness_error_does_not_overwrite_verified_day0_stage(self):
        t = target()
        task = app.PreparedIBTask(t, app.Neighbor("fe80::10", "vlan1000", t.ib.eth0_mac, "oob"), "", False)
        args = SimpleNamespace(eth_user="cumulus", ib_user="admin", connect_timeout=5,
                               apply=True, force=False, execution_mode="management")
        state = app.SessionResult(CONFIG, 0)
        rows = [{"hostname": t.ib.hostname, "interface": "eth0", "ip": t.ib.login_ip,
                 "status": "PASS", "detail": "synthetic direct success"}]
        identity_calls = []
        identities = []
        real_identity = app._check_ib_identity

        def check_identity(*positional, **keywords):
            actual = real_identity(*positional, **keywords)
            identities.append(actual)
            return actual

        def read_stage(*positional, **keywords):
            self.assertEqual((t, task.neighbor, "cumulus", "", "admin", PASSWORD, 5),
                             positional[:-1])
            identity_calls.append(tuple(positional[-1]))
            if positional[-1] == ["nv", "show", "system", "ztp"]:
                self.assertEqual({"local": False, "strict": False, "policy": None,
                                  "_ib_read_context": None}, keywords)
                return app.SessionResult("service disabled\nstate disabled\nstatus success\n", 0)
            self.assertEqual(["ip", "addr", "show", "eth0"], positional[-1])
            self.assertEqual({"local": False, "strict": False, "policy": None}, keywords)
            return app.SessionResult(
                "2: eth0: <UP> mtu 1500\n"
                "    link/ether 02:00:00:00:00:10\n"
                "    inet 192.0.2.10/24 scope global eth0\n", 0)

        with patch.object(app, "log"), patch.object(app.time, "sleep"), \
             patch.object(app, "interactive_run", side_effect=AssertionError("real transport forbidden")), \
             patch.object(app, "_stage_ib_command", side_effect=read_stage), \
             patch.object(app, "_check_ib_identity", side_effect=check_identity), \
             patch.object(app, "inspect_ib_device", return_value=(state, PASSWORD, True)), \
             patch.object(app, "run_initial_stage", return_value=(state.output, True)), \
             patch.object(app, "parse_nvue_state",
                          return_value=app.DeviceState((), (), (), (), t.ib.hostname, state.output)), \
             patch.object(app, "base_stage_needed", return_value=False), \
             patch.object(app, "verify_state"), \
             patch.object(app, "verify_ipv4_login", side_effect=app.SetupError("synthetic OOB IPv4 timeout")) as readiness, \
             patch.object(app, "run_management_direct_checks", return_value=rows), \
             patch.object(app, "run_service_stage") as services, \
             patch.object(app, "run_key_stage") as keys:
            record = app.execute_ib_task(task, args, None, "admin", None, [], None, True)
        self.assertEqual([("ip", "addr", "show", "eth0"), ("nv", "show", "system", "ztp")],
                         identity_calls)
        self.assertTrue(record["ztp"]["read"])
        self.assertEqual("disabled", record["ztp"]["service"])
        self.assertEqual(1, len(identities))
        self.assertIs(identities[0]["ok"], True)
        self.assertEqual("02:00:00:00:00:10", identities[0]["observed"]["mac"])
        readiness.assert_called_once()
        self.assertEqual(record["outcome"], "FAILED")
        self.assertEqual(record["stage_status"]["day0"], "ALREADY_PRESENT")
        self.assertEqual(record["stage_status"]["ipv4_readiness"], "FAILED")
        self.assertEqual(record["failed_stage"], "ipv4_readiness")
        self.assertEqual(record["direct_rows"][0]["status"], "PASS")
        services.assert_not_called()
        keys.assert_not_called()

    # v15 ModularOutputTests.test_latest_log_count_pattern_is_four_base_changes_169_key_refreshes_19_skips (test_desktop_initial_setup.py:1932)
    def test_latest_log_count_pattern_is_four_base_changes_169_key_refreshes_19_skips(self):
        records, rows = {}, []
        for index in range(192):
            name = f"example-ib{index + 1:03d}"
            if index < 173:
                changed = index < 4
                records[name] = {"outcome": "CONFIGURED" if changed else "ALREADY_CONFIGURED",
                    "writes_attempted": True, "metrics": {"nvue_write_commands": 19 if changed else 0,
                    "public_key_install_attempts": 1}, "stage_status": {"day0": "VERIFIED" if changed else "ALREADY_PRESENT"}}
                rows.append({"hostname": name, "interface": "eth0", "status": "PASS", "ip": "192.0.2.10", "detail": "synthetic"})
            else:
                records[name] = {"outcome": "SKIPPED", "category": "SKIPPED_LINK_DOWN" if index < 188 else "SKIPPED_MAC_MISMATCH"}
        facts = app.initial_setup_facts(records, rows)
        self.assertEqual(facts["categories"], {"CHECKED_AND_CONFIGURED": 4, "CHECKED_EXISTING_KEY_INSTALL_COMPLETED": 169,
                                              "SKIPPED_LINK_DOWN": 15, "SKIPPED_MAC_MISMATCH": 4})
        self.assertEqual(sum(facts["categories"].values()), 192)
        self.assertEqual(facts["stages"]["day0"], {"VERIFIED": 4, "ALREADY_PRESENT": 169, "NOT_REACHED": 19})
        self.assertEqual(facts["setup_and_direct_ssh_verified"], 173)

    # ---- v15 SummaryOperatorContractTests ------------------------------------------------------
    # v15 SummaryOperatorContractTests.test_all_required_setup_and_direct_checks_pass_is_success (test_desktop_initial_setup.py:1956)
    def test_all_required_setup_and_direct_checks_pass_is_success(self):
        records = {"example-ib001": {"outcome": "ALREADY_CONFIGURED", "stage_status": {
            "authentication": "VERIFIED", "day0": "ALREADY_PRESENT", "direct_ssh": "VERIFIED"}}}
        rows = [{"hostname": "example-ib001", "interface": "eth0", "ip": "192.0.2.10", "status": "PASS"}]
        result, output = self.summary(records, rows)
        self.assertEqual(result, "SUCCESS")
        self.assertIn("Result: SUCCESS", output)
        self.assertIn("All attached IB switches completed setup and direct SSH passed", output)
        self.assertNotIn("No prerequisite blocks or IB failures", output)

    # v15 SummaryOperatorContractTests.test_script_failure_is_failed_not_device_incomplete (test_desktop_initial_setup.py:1966)
    def test_script_failure_is_failed_not_device_incomplete(self):
        for records, fatal in (({"example-ib001": {"outcome": "NOT_ATTEMPTED"}}, "shared inputs changed"),
                               ({"example-ib001": {"outcome": "FAILED", "script_error": True,
                                                   "reason": "worker crashed"}}, "")):
            with self.subTest(fatal=fatal):
                result, output = self.summary(records, fatal=fatal)
                self.assertEqual(result, "FAILED")
                self.assertIn("Result: FAILED", output)

    # v15 SummaryOperatorContractTests.test_per_device_failure_is_incomplete_with_problem_preserved (test_desktop_initial_setup.py:1975)
    def test_per_device_failure_is_incomplete_with_problem_preserved(self):
        result, output = self.summary({"example-ib001": {"outcome": "FAILED", "failed_stage": "services",
            "reason": "NTP readback mismatch", "stage_status": {"services": "FAILED"}}})
        self.assertEqual(result, "INCOMPLETE")
        self.assertIn("FAILED_CHECK_OR_LOGIN: 1", output)
        self.assertIn("services", output)
        attention = output.split("06 ATTENTION REQUIRED")[1].split("07 EVIDENCE")[0]
        self.assertIn("[FAILED_SERVICES_CONFIGURATION]", attention)

    # v15 SummaryOperatorContractTests.test_missing_direct_validation_never_becomes_success (test_desktop_initial_setup.py:1984)
    def test_missing_direct_validation_never_becomes_success(self):
        result, output = self.summary({"example-ib001": {"outcome": "ALREADY_CONFIGURED"}})
        self.assertEqual(result, "INCOMPLETE")
        self.assertIn("DIRECT_SSH_NOT_TESTED", output)
        self.assertIn("example-ib001", output.split("06 ATTENTION REQUIRED")[1])

    # v15 SummaryOperatorContractTests.test_configuration_stages_follow_actual_pipeline_and_ssh_checks_are_separate (test_desktop_initial_setup.py:1990)
    def test_configuration_stages_follow_actual_pipeline_and_ssh_checks_are_separate(self):
        records = {"example-ib001": {"outcome": "ALREADY_CONFIGURED", "stage_status": {
            "initial": "VERIFIED", "day0": "ALREADY_PRESENT", "services": "SKIPPED",
            "public_keys": "COMPLETED", "authentication": "VERIFIED", "ipv4_readiness": "VERIFIED"},
            "metrics": {"public_key_install_completed": 1, "public_key_ssh_verified": 1,
                        "public_key_ssh_attempts": 2}}}
        _, output = self.summary(records)
        stages = output.split("04 CONFIGURATION STAGES", 1)[1].split("05 SSH ACCESS", 1)[0]
        labels = ("1. Initial:", "2. Network:", "3. Infra Services:", "4. Public Keys:")
        self.assertEqual([stages.index(value) for value in labels], sorted(stages.index(value) for value in labels))
        self.assertNotIn("Authentication:", stages)
        self.assertNotIn("IPv4 readiness via OOB:", stages)
        ssh = output.split("05 SSH ACCESS", 1)[1].split("06 ATTENTION REQUIRED", 1)[0]
        self.assertIn("IB IPv6 SSH via OOB: VERIFIED=1", ssh)
        self.assertIn("IB IPv4 SSH via OOB: VERIFIED=1", ssh)
        self.assertIn("Management-key SSH verification: verified=1 failed/unverified=0 not-attempted=0", ssh)

    # v15 SummaryOperatorContractTests.test_network_and_infra_labels_preserve_existing_structured_stage_keys (test_desktop_initial_setup.py:2007)
    def test_network_and_infra_labels_preserve_existing_structured_stage_keys(self):
        records = {"example-ib001": {"outcome": "ALREADY_CONFIGURED", "stage_status": {
            "day0": "ALREADY_PRESENT", "services": "SKIPPED"}}}
        _, output = self.summary(records)
        self.assertIn("2. Network: ALREADY_PRESENT=1", output)
        self.assertIn("3. Infra Services: SKIPPED=1", output)
        self.assertNotIn("Day-0", output)
        self.assertNotIn("3. Services:", output)
        facts = app.initial_setup_facts(records, [])
        self.assertEqual(facts["stages"]["day0"], {"ALREADY_PRESENT": 1})
        self.assertEqual(facts["stages"]["services"], {"SKIPPED": 1})
        self.assertNotIn("network", facts["stages"])
        self.assertNotIn("infra_services", facts["stages"])

    # v15 SummaryOperatorContractTests.test_attention_groups_all_devices_and_next_actions_match_each_group (test_desktop_initial_setup.py:2021)
    def test_attention_groups_all_devices_and_next_actions_match_each_group(self):
        records = {
            "example-ib001": {"outcome": "SKIPPED", "category": "SKIPPED_LINK_DOWN", "port": "swp1"},
            "example-ib002": {"outcome": "SKIPPED", "category": "SKIPPED_LINK_DOWN", "port": "swp2"},
            "example-ib003": {"outcome": "SKIPPED", "category": "SKIPPED_MAC_MISMATCH", "port": "swp3"},
        }
        _, output = self.summary(records)
        attention = output.split("06 ATTENTION REQUIRED", 1)[1].split("07 EVIDENCE", 1)[0]
        self.assertEqual(attention.count("[SKIPPED_LINK_DOWN]"), 1)
        self.assertIn("[SKIPPED_LINK_DOWN] 2 device(s)", attention)
        self.assertIn("[SKIPPED_MAC_MISMATCH] 1 device(s)", attention)
        self.assertLess(attention.index("example-ib002"), attention.index("[SKIPPED_MAC_MISMATCH]"))
        actions = output.split("07 EVIDENCE & NEXT ACTIONS", 1)[1]
        self.assertIn("[SKIPPED_LINK_DOWN]", actions)
        self.assertIn("[SKIPPED_MAC_MISMATCH]", actions)
        self.assertIn("cabling", actions)
        self.assertIn("CSV", actions)

    # v15 SummaryOperatorContractTests.test_direct_only_failure_is_in_attention_and_json_even_when_setup_completed (test_desktop_initial_setup.py:2039)
    def test_direct_only_failure_is_in_attention_and_json_even_when_setup_completed(self):
        records = {"example-ib001": {"outcome": "ALREADY_CONFIGURED", "stage_status": {"direct_ssh": "FAILED"}}}
        rows = [{"hostname": "example-ib001", "interface": "eth0", "ip": "192.0.2.10", "status": "FAIL",
                 "detail": "direct SSH network failed after 3 attempts: No route to host"}]
        result, output = self.summary(records, rows)
        self.assertEqual(result, "INCOMPLETE")
        attention = output.split("06 ATTENTION REQUIRED", 1)[1].split("07 EVIDENCE", 1)[0]
        self.assertIn("[FAILED_DIRECT_SSH_NETWORK] 1 device(s)", attention)
        self.assertIn("example-ib001", attention)
        facts = app.initial_setup_facts(records, rows)
        self.assertEqual(facts["attention"][0]["category"], "FAILED_DIRECT_SSH_NETWORK")
        self.assertEqual(facts["attention"][0]["devices"][0]["hostname"], "example-ib001")
        self.assertIn("TCP/22", facts["attention"][0]["guidance"])

    # v15 SummaryOperatorContractTests.test_current_192_device_pattern_groups_11_network_failures_without_claiming_key_install_failure (test_desktop_initial_setup.py:2053)
    def test_current_192_device_pattern_groups_11_network_failures_without_claiming_key_install_failure(self):
        records, rows = {}, []
        for index in range(192):
            name = f"example-ib{index + 1:03d}"
            if index < 173:
                failed = index < 11
                records[name] = {"hostname": name, "outcome": "FAILED" if failed else "ALREADY_CONFIGURED",
                    "failure_kind": "DIRECT_SSH_NETWORK" if failed else "",
                    "writes_attempted": True,
                    "metrics": {"public_key_install_attempts": 1, "public_key_install_completed": 1,
                        "public_key_ssh_attempts": 3 if failed else 1, "public_key_ssh_verified": 0 if failed else 1},
                    "stage_status": {"day0": "ALREADY_PRESENT", "public_keys": "FAILED" if failed else "COMPLETED"}}
                rows.append({"hostname": name, "interface": "eth0", "ip": f"192.0.2.{index + 1}",
                             "status": "FAIL" if failed else "PASS", "detail": "synthetic network failure"})
            else:
                records[name] = {"hostname": name, "outcome": "SKIPPED", "category":
                                 "SKIPPED_LINK_DOWN" if index < 188 else "SKIPPED_MAC_MISMATCH"}
        result, output = self.summary(records, rows)
        self.assertEqual(result, "INCOMPLETE")
        self.assertIn("Key install command completed: 173 device(s)", output)
        self.assertIn("Management-key SSH verification: verified=162 failed/unverified=11 not-attempted=19", output)
        attention = output.split("06 ATTENTION REQUIRED")[1].split("07 EVIDENCE")[0]
        self.assertIn("[FAILED_DIRECT_SSH_NETWORK] 11 device(s)", attention)
        self.assertIn("[SKIPPED_LINK_DOWN] 15 device(s)", attention)
        self.assertIn("[SKIPPED_MAC_MISMATCH] 4 device(s)", attention)
        self.assertNotIn("Workers:", output)
        self.assertNotIn("OPERATION COUNTERS", output)

    # ---- v15 ClassifiedSummaryTests ------------------------------------------------------------
    # v15 ClassifiedSummaryTests.test_all_blocked_example_is_incomplete_with_zero_ib_attempts_or_writes (test_desktop_initial_setup.py:2083)
    def test_all_blocked_example_is_incomplete_with_zero_ib_attempts_or_writes(self):
        targets, records, failures = [], {}, {}
        for index, (number, count, down) in enumerate(((9, 48, True), (10, 20, True),
                                                       (11, 32, False), (13, 4, False))):
            oob = replace(target().ethernet, hostname=f"example-oob-leaf{number:03d}",
                          login_ip=f"198.51.100.{index + 10}")
            if not down:
                failures[oob.hostname] = "No route to host"
            for port in range(1, count + 1):
                hostname = f"example-ib{len(targets) + 1:03d}"
                item = app.Target(replace(target().ib, hostname=hostname), oob, f"swp{port}", "eth0")
                targets.append(item)
                records[hostname] = {"hostname": hostname, "oob": oob.hostname, "outcome": "SKIPPED",
                    "category": "SKIPPED_LINK_DOWN" if down else "SKIPPED_OOB_UNREACHABLE",
                    "port": f"swp{port}", "metrics": {}, "stage_status": {}}
        messages = []
        args = SimpleNamespace(apply=False, report=REPORT)
        with patch.object(app, "log", lambda message="": messages.append(message)):
            result = app.print_initial_setup_summary("synthetic-project", args, targets, 104,
                                                     failures, records, [], 0)
        output = "\n".join(messages)
        self.assertEqual(result, "INCOMPLETE")
        self.assertIn("OOB snapshots: 4 total, 2 collected, 2 failed", output)
        self.assertIn("SKIPPED_LINK_DOWN: 68", output)
        self.assertIn("SKIPPED_OOB_UNREACHABLE: 36", output)
        self.assertIn("TOTAL: 104", output)
        self.assertIn("swp1-48", output)
        self.assertIn("No IB switch login was attempted", output)
        self.assertIn("current IB configuration remains unknown", output)
        self.assertTrue(all(not row.get("writes_attempted", False) for row in records.values()))
        self.assertIn("Network: NOT_REACHED", output)

    # v15 ClassifiedSummaryTests.test_existing_checked_applied_and_partial_failure_are_exclusive (test_desktop_initial_setup.py:2114)
    def test_existing_checked_applied_and_partial_failure_are_exclusive(self):
        targets, records = [], {}
        for number, (outcome, writes) in enumerate((("ALREADY_CONFIGURED", False),
                                                    ("CONFIGURED", True), ("FAILED", True)), 1):
            item = app.Target(replace(target().ib, hostname=f"example-ib{number:03d}"),
                              target().ethernet, f"swp{number}", "eth0")
            targets.append(item)
            records[item.ib.hostname] = {"outcome": outcome, "writes_attempted": writes,
                                         "metrics": {"nvue_write_commands": 2 if writes else 0}}
        messages = []
        with patch.object(app, "log", lambda message="": messages.append(message)):
            result = app.print_initial_setup_summary("synthetic", SimpleNamespace(apply=True,
                report=REPORT), targets, 3, {}, records, [], 1)
        output = "\n".join(messages)
        self.assertEqual(result, "INCOMPLETE")
        for category in ("CHECKED_EXISTING_CONFIGURATION", "CHECKED_AND_CONFIGURED", "FAILED_AFTER_WRITE_UNVERIFIED"):
            self.assertIn(category + ": 1", output)
        self.assertIn("TOTAL: 3", output)

    # v15 ClassifiedSummaryTests.test_mac_mismatch_is_skipped_before_ib_ssh (test_desktop_initial_setup.py:2133)
    def test_mac_mismatch_is_skipped_before_ib_ssh(self):
        t = target()
        records, outcomes = {}, {}
        links = "1: swp1: <UP> mtu 1500 state UP\n2: swp2: <UP> mtu 1500 state UP\n"
        fdb = "02:00:00:00:00:10 dev swp2 master bridge dynamic\n"
        vlans = "port vlan-id\nswp1 1 PVID Egress Untagged\nswp2 1 PVID Egress Untagged\n"
        with patch.object(app, "interface_status_line", return_value="swp1 up up"), \
             patch.object(app, "interface_oper_status", return_value="up"), \
             patch.object(app, "interface_vrf", side_effect=AssertionError("Unexpected VRF probe")), \
             patch.object(app, "run_on_ib", side_effect=AssertionError("Real device IO forbidden")) as ssh, \
             patch.object(app, "run_on_ethernet", side_effect=AssertionError("Real device IO forbidden")), \
             patch.object(app, "interactive_run", side_effect=AssertionError("Real device IO forbidden")), \
             patch.object(subprocess, "run", side_effect=AssertionError("Real subprocess forbidden")), \
             patch.object(app, "REPORT_HANDLE", None), patch.object(app, "log") as output:
            ready = app.prepare_ready_ib_tasks([t], SimpleNamespace(), {"example-oob-leaf01": ""}, set(),
                {"example-oob-leaf01": "interfaces"}, {"example-oob-leaf01": (links, fdb, vlans)},
                {}, outcomes, records)
            result = app.print_initial_setup_summary("fixture", SimpleNamespace(apply=False,
                report=REPORT), [t], 1, {}, records, [], 0)
        self.assertEqual(ready, [])
        self.assertEqual(outcomes, {"example-ib001": "SKIPPED"})
        self.assertEqual(records["example-ib001"]["category"], "SKIPPED_CABLE_CHECK_FAILED")
        self.assertEqual(records["example-ib001"]["cable_check"], {
            "hostname": "example-ib001", "mac": "02:00:00:00:00:10",
            "link_local": "fe80::ff:fe00:10", "expected": ("example-oob-leaf01", "swp1"),
            "actual": (("example-oob-leaf01", "swp2"),), "verdict": "ELSEWHERE",
            "extra_macs": (), "login_interface": "swp1", "after_ping": False,
            "ping_ok": None, "ignored": False,
        })
        self.assertFalse(records["example-ib001"]["writes_attempted"])
        for key in ("identity", "mac_mismatch", "backup"):
            self.assertNotIn(key, records["example-ib001"])
        text = "\n".join(call.args[0] for call in output.call_args_list)
        self.assertEqual("INCOMPLETE", result)
        self.assertIn("Result: INCOMPLETE", text)
        outcomes_text = text.split("03 IB SWITCHES OUTCOMES", 1)[1].split("04 CONFIGURATION STAGES", 1)[0]
        self.assertIn("SKIPPED_CABLE_CHECK_FAILED: 1", outcomes_text)
        self.assertIn("TOTAL: 1", outcomes_text)
        self.assertIn('Cable: expected="example-oob-leaf01:swp1" actual=["example-oob-leaf01:swp2"] '
                      'verdict=ELSEWHERE after_ping=no ping_ok=unknown ignored=no', outcomes_text)
        ssh.assert_not_called()

    # v15 ClassifiedSummaryTests.test_redaction_handles_quotes_before_json_serialization (test_desktop_initial_setup.py:2152)
    def test_redaction_handles_quotes_before_json_serialization(self):
        value = 'private"' + secret("redact") + "\\value"
        self.assertEqual(app.redact_data({"reason": "failed with " + value}, [value]),
                         {"reason": "failed with [REDACTED]"})

    # ---- v15 PublicKeyStageVisibilityTests ------------------------------------------------------
    def stage(self, keys):
        t = target()
        n = app.Neighbor("fe80::10", "vlan1000", t.ib.eth0_mac, "oob")
        return app.run_key_stage(t, n, "cumulus", OOB_PASSWORD, "admin", 5, keys,
                                 local=False, apply=True, authorized=True, ib_password=PASSWORD)

    # v15 PublicKeyStageVisibilityTests.test_no_keys_is_an_explicit_skip_not_a_successful_install (test_desktop_initial_setup.py:913)
    def test_no_keys_is_an_explicit_skip_not_a_successful_install(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.object(app, "run_on_ib") as run:
            self.stage([])
        run.assert_not_called()
        self.assertIn("Stage 4: IB public-key installation", output.getvalue())
        self.assertIn("Public keys SKIP", output.getvalue())
        self.assertNotIn("KEYS WRITE OK", output.getvalue())

    # v15 PublicKeyStageVisibilityTests.test_install_is_only_reported_after_the_remote_write_completes (test_desktop_initial_setup.py:922)
    def test_install_is_only_reported_after_the_remote_write_completes(self):
        entry = {"name": "laptop.pub", "fingerprint": "SHA256:test-fixture"}
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
             patch.object(app, "key_install_command", return_value=["test-install"]), \
             patch.object(app, "run_on_ib", return_value=app.SessionResult("IBSW_PUBLIC_KEYS_UPDATED\n", 0)) as run:
            self.stage([entry])
        run.assert_called_once()
        self.assertLess(output.getvalue().index("PLAN INSTALL"), output.getvalue().index("KEYS WRITE OK"))
        self.assertIn("laptop.pub", output.getvalue())

    # v15 PublicKeyStageVisibilityTests.test_failed_write_never_prints_write_success (test_desktop_initial_setup.py:933)
    def test_failed_write_never_prints_write_success(self):
        entry = {"name": "laptop.pub", "fingerprint": "SHA256:test-fixture"}
        output = io.StringIO()
        with contextlib.redirect_stdout(output), \
             patch.object(app, "key_install_command", return_value=["test-install"]), \
             patch.object(app, "run_on_ib", side_effect=app.SetupError("remote write failed")):
            with self.assertRaises(app.SetupError):
                self.stage([entry])
        self.assertNotIn("KEYS WRITE OK", output.getvalue())

    # ---- v15 ProgressAndSummaryDirectTests (test_initial_setup_log_review.py) ------------------
    # v15 ProgressAndSummaryDirectTests.test_tail_progress_lists_remaining_host_phase_and_elapsed_without_secrets (test_initial_setup_log_review.py:200)
    def test_tail_progress_lists_remaining_host_phase_and_elapsed_without_secrets(self):
        job = dict(task=SimpleNamespace(target=target()), phase="Infra Services", started_at=10., phase_at=50.)
        with patch.object(app, "log") as log:
            app.print_worker_progress({1: job}, 0, 176, 177, now=100., secrets=(secret("tail"),))
        text = "\n".join(call.args[0] for call in log.call_args_list)
        self.assertIn("running=1 queued=0 completed=176/177", text)
        self.assertIn("example-ib001", text)
        self.assertIn("Infra Services", text)
        self.assertIn("elapsed=90s", text)
        self.assertIn("phase-elapsed=50s", text)

    # v15 ProgressAndSummaryDirectTests.test_many_active_tasks_have_one_phase_count_line_instead_of_long_host_lists (test_initial_setup_log_review.py:211)
    def test_many_active_tasks_have_one_phase_count_line_instead_of_long_host_lists(self):
        hidden = secret("phase")
        jobs = {number: dict(task=SimpleNamespace(target=target()), phase="Infra Services " + hidden)
                for number in range(12)}
        with patch.object(app, "log") as log:
            app.print_worker_progress(jobs, 165, 0, 177, now=100., secrets=(hidden,))
        text = "\n".join(call.args[0] for call in log.call_args_list)
        self.assertEqual(log.call_count, 2)
        self.assertIn("=12", text)
        self.assertNotIn(hidden, text)
        self.assertNotIn("[WAIT]", text)

    # v15 ProgressAndSummaryDirectTests.test_fallback_is_separately_counted_as_candidate_and_verified_login (test_initial_setup_log_review.py:222)
    def test_fallback_is_separately_counted_as_candidate_and_verified_login(self):
        records = {"example-ib001": dict(outcome="ALREADY_CONFIGURED", neighbor=dict(address_source="FDB_EUI64_CANDIDATE"),
                                         stage_status=dict(authentication="VERIFIED"))}
        rows = [dict(hostname="example-ib001", interface="eth0", ip="192.0.2.10", status="PASS")]
        _, output = self.summary(records, rows)
        self.assertIn("FDB-derived IPv6 candidates: 1; authenticated=1; not-verified=0", output)

    # v15 ProgressAndSummaryDirectTests.test_missing_inventory_mac_is_disclosed_without_faking_or_filling_it (test_initial_setup_log_review.py:229)
    def test_missing_inventory_mac_is_disclosed_without_faking_or_filling_it(self):
        t = target()
        t = replace(t, ib=replace(t.ib, eth0_mac=""))
        for apply in (False, True):
            with self.subTest(apply=apply):
                records = {"example-ib001": {
                    "hostname": "example-ib001", "outcome": "SKIPPED",
                    "category": "SKIPPED_INPUT_INCOMPLETE", "writes_attempted": False,
                    "reason": "eth0_mac=: MAC is missing or invalid", "metrics": {}, "stage_status": {},
                    "input_issues": [{"hostname": "example-ib001", "field": "eth0_mac", "value": "",
                                      "problem": "MAC is missing or invalid", "blocking": True}],
                }}
                with patch.object(app, "run_on_ib", side_effect=AssertionError("Real device IO forbidden")) as ssh, \
                     patch.object(app, "run_on_ethernet", side_effect=AssertionError("Real device IO forbidden")), \
                     patch.object(app, "interactive_run", side_effect=AssertionError("Real device IO forbidden")), \
                     patch.object(subprocess, "run", side_effect=AssertionError("Real subprocess forbidden")), \
                     patch.object(app, "REPORT_HANDLE", None), patch.object(app, "log") as log:
                    result = app.print_initial_setup_summary("fixture", SimpleNamespace(apply=apply, report=REPORT),
                                                            [t], 1, {}, records, [], 1)
                text = "\n".join(c.args[0] for c in log.call_args_list)
                self.assertEqual("INCOMPLETE", result)
                self.assertIn("Result: INCOMPLETE", text)
                outcomes_text = text.split("03 IB SWITCHES OUTCOMES", 1)[1].split("04 CONFIGURATION STAGES", 1)[0]
                self.assertIn("SKIPPED_INPUT_INCOMPLETE: 1", outcomes_text)
                self.assertIn("TOTAL: 1", outcomes_text)
                self.assertNotIn("Completed:", outcomes_text)
                self.assertNotIn("CHECKED_EXISTING_CONFIGURATION", outcomes_text)
                self.assertNotIn("CHECKED_AND_CONFIGURED", outcomes_text)
                self.assertIn('Input issue: field="eth0_mac" value="" problem="MAC is missing or invalid"', outcomes_text)
                attention_text = text.split("06 ATTENTION REQUIRED", 1)[1].split("07 EVIDENCE & NEXT ACTIONS", 1)[0]
                self.assertIn("[SKIPPED_INPUT_INCOMPLETE] 1 device(s)", attention_text)
                self.assertIn("example-ib001", attention_text)
                self.assertNotIn("    Identity:", text)
                self.assertNotIn("    Backup:", text)
                for key in ("identity", "cable_check", "backup"):
                    self.assertNotIn(key, records["example-ib001"])
                self.assertFalse(records["example-ib001"]["writes_attempted"])
                self.assertNotIn("CSV eth0 MAC unavailable: 1", text)
                self.assertNotIn("not checked against inventory MAC", text)
                self.assertNotIn("Inventory: supply the real CSV eth0 MAC before MAC-required upgrade preflight", text)
                self.assertEqual(t.ib.eth0_mac, "")
                ssh.assert_not_called()

    # v15 ProgressAndSummaryDirectTests.test_synthetic_192_case_preserves_three_network_changes_and_fifteen_prerequisite_skips (test_initial_setup_log_review.py:240)
    def test_synthetic_192_case_preserves_three_network_changes_and_fifteen_prerequisite_skips(self):
        records, rows = {}, []
        for number in range(192):
            name = f"example-ib{number:03d}"
            if number < 177:
                changed = number < 3
                records[name] = dict(hostname=name, outcome="CONFIGURED" if changed else "ALREADY_CONFIGURED",
                    writes_attempted=True, metrics=dict(nvue_write_commands=9 if changed else 0,
                        public_key_install_attempts=1, public_key_install_completed=1, public_key_content_unchanged=1),
                    stage_status=dict(authentication="VERIFIED", day0="VERIFIED" if changed else "ALREADY_PRESENT",
                        services="VERIFIED" if changed else "ALREADY_PRESENT", public_keys="COMPLETED"))
                rows.append(dict(hostname=name, interface="eth0", ip="192.0.2.10", status="PASS"))
            else:
                records[name] = dict(hostname=name, outcome="SKIPPED", category="SKIPPED_LINK_DOWN"
                                     if number < 188 else "SKIPPED_MAC_MISMATCH")
        facts = app.initial_setup_facts(records, rows)
        self.assertEqual(facts["categories"], dict(CHECKED_AND_CONFIGURED=3, CHECKED_EXISTING_KEYS_VERIFIED=174,
                                                   SKIPPED_LINK_DOWN=11, SKIPPED_MAC_MISMATCH=4))
        self.assertEqual(facts["setup_and_direct_ssh_verified"], 177)
        self.assertEqual(sum(facts["categories"].values()), 192)

    # v15 ProgressAndSummaryDirectTests.test_version_query_needs_no_inputs_and_creates_no_run_artifacts
    # (test_initial_setup_log_review.py:192); v15 RUNBOOK.md:31 (the operator runs --version first).
    # Ported only the part DEV does not pin: the query needs no project input in an empty working
    # directory, exits 0 and leaves no run artifact there.  The v14 version string is not ported:
    # guide table 6-1 row 7 (:750) adopts the repository revision string, pinned by
    # test_ibsw225_initializer_help_guard (which checks neither the empty directory nor artifacts).
    # In-process main(), never the runtime guard or a __main__ subprocess (guide :835).
    def test_version_query_needs_no_inputs_and_creates_no_run_artifacts(self):
        previous = os.getcwd()
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(app.sys, "argv", [str(INITIAL), "--version"]), \
                patch.object(app, "REPORT_HANDLE", None), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            os.chdir(folder)
            try:
                with self.assertRaises(SystemExit) as stopped:
                    app.main()
                left = sorted(path.name for path in Path(folder).iterdir())
            finally:
                os.chdir(previous)
        self.assertEqual(stopped.exception.code, 0, err.getvalue())
        self.assertEqual(len((out.getvalue() + err.getvalue()).strip().splitlines()), 1)
        self.assertEqual("http-v3.1.5\n", out.getvalue())
        self.assertEqual("", err.getvalue())
        self.assertEqual(left, [])

    # ---- log-review gaps (table 7-1 :818): KeyReceiptDirectTests ------------------------------
    def invoke_receipt(self, receipt):
        details = {}
        key = dict(name="laptop.pub", line=public(2), fingerprint=app._public_key_fingerprint(public(2)))
        t = target()
        n = app.Neighbor("fe80::10", "vlan1000", t.ib.eth0_mac, "oob")
        with patch.object(app, "run_on_ib", return_value=app.SessionResult(receipt, 0)), \
             patch.object(app, "record_metric") as metric, contextlib.redirect_stdout(io.StringIO()):
            result = app.run_key_stage(t, n, "cumulus", OOB_PASSWORD, "admin", 5, [key],
                                       local=False, apply=True, authorized=True, ib_password=PASSWORD,
                                       details=details)
        return result, details, [c.args[0] for c in metric.call_args_list]

    # v15 KeyReceiptDirectTests.test_unchanged_key_content_is_not_reported_as_refreshed (test_initial_setup_log_review.py:130)
    def test_unchanged_key_content_is_not_reported_as_refreshed(self):
        # The canonical receipt with its trailing newline: DEV's exact match accepts it (guide :818).
        _, details, metrics = self.invoke_receipt("IBSW_PUBLIC_KEYS_UNCHANGED\n")
        self.assertEqual(details["content_action"], "UNCHANGED")
        self.assertIn("public_key_content_unchanged", metrics)
        row = dict(outcome="ALREADY_CONFIGURED", writes_attempted=True,
                   metrics=dict(public_key_install_attempts=1, public_key_install_completed=1,
                                public_key_content_unchanged=1))
        self.assertEqual(app.record_category(row), "CHECKED_EXISTING_KEYS_VERIFIED")

    # v15 KeyReceiptDirectTests.test_updated_key_receipt_records_actual_content_change (test_initial_setup_log_review.py:138)
    def test_updated_key_receipt_records_actual_content_change(self):
        _, details, metrics = self.invoke_receipt("IBSW_PUBLIC_KEYS_UPDATED\n")
        self.assertEqual(details["content_action"], "UPDATED")
        self.assertIn("public_key_content_updated", metrics)

    # ---- log-review gaps (table 7-1 :818): AuthorizedKeyTaskWorkflowTests ----------------------
    # v15 AuthorizedKeyTaskWorkflowTests.test_real_worker_ipc_reports_live_tail_phase_only_from_parent (test_initial_setup_log_review.py:263)
    def test_real_worker_ipc_reports_live_tail_phase_only_from_parent(self):
        def task_run(task, *args, **kwargs):
            app.task_phase("waiting for " + INITIAL_PASSWORD + " network")
            time.sleep(.025)
            return success(task)
        with patch.object(app, "_PROGRESS_HEARTBEAT_SECONDS", 0):
            result, messages, _ = run_local_pool(task_run)
        text = "\n".join(messages)
        self.assertFalse(result["fatal"])
        self.assertIn("[PROGRESS]", text)
        self.assertIn("[WAIT]", text)
        self.assertIn("network", text)
        self.assertNotIn(INITIAL_PASSWORD, text)
        self.assertTrue(all("elapsed_seconds" in row and "last_phase" in row for row in result["records"].values()))

    # v15 AuthorizedKeyTaskWorkflowTests.test_real_task_and_coordinator_run_twice_then_report_unchanged_content_without_network_replay (test_initial_setup_log_review.py:279)
    def test_real_task_and_coordinator_run_twice_then_report_unchanged_content_without_network_replay(self):
        from test_cases.native_cpld_physical_io import owned_test_root

        t = target()
        n = app.Neighbor("fe80::10", "vlan1000", t.ib.eth0_mac, "oob")
        task = app.PreparedIBTask(t, n, OOB_PASSWORD, False)
        current = "\n".join(shlex.join(c) for c in app.desired_commands(t.ib) if c[:2] == ["nv", "set"]) + "\n"
        current += "\n".join(shlex.join(c) for c in app.initial_configuration_commands()[:2]) + "\n"
        current += ("nv set system dns server 192.0.2.53\nnv set system ntp server 192.0.2.123 state enabled\n"
                    "nv set system date-time timezone Etc/UTC\n")
        keys = [dict(name="key" + str(i) + ".pub", line=public(i), fingerprint=app._public_key_fingerprint(public(i)))
                for i in (2, 3)]
        services = dict(dns=["192.0.2.53"], ntp=["192.0.2.123"], timezone="Etc/UTC")
        # These PUBLIC inputs do not come from the product's argv builder or
        # formatter. The source constant below is only an exact effect gate.
        public_lines = [public(2), public(3)]
        public_bytes = ("\n".join(public_lines) + "\n").encode("utf-8")
        public_payload = base64.b64encode(public_bytes).decode("ascii")
        key_command = ["sh", "-c", app._KEY_INSTALL_SCRIPT, "--", public_payload]
        addr_reply = ("2: eth0: <UP> mtu 1500 state UP\n"
                      "    link/ether 02:00:00:00:00:10 brd ff:ff:ff:ff:ff:ff\n"
                      "    inet 192.0.2.10/24 scope global eth0\n")
        previous_config = app._TASK_IB_CONFIG
        self.assertIsNone(app._JUMP_SESSIONS, "ordinary prepared-task carrier has no borrowed master")
        self.assertIsNone(app._WORKER_CONNECTION, "one original task uses the real inline coordinator")
        with tempfile.TemporaryDirectory(dir=owned_test_root()) as folder:
            home = Path(folder) / "remote"
            home.mkdir()
            args = SimpleNamespace(apply=True, yes=True, force=False, max_workers=16, task_timeout=20,
                                   eth_user="cumulus", ib_user="admin", connect_timeout=5,
                                   execution_mode="management", report=Path(folder) / "report.log")
            calls, shell_results, external_errors = [], [], []
            safe_path = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "
            outer_header = ["ssh", "-tt", "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=10",
                "-o", "ServerAliveCountMax=2", "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",
                "-o", "ControlMaster=no", "-o", "ControlPath=none", "cumulus@198.51.100.10"]
            inner_header = ["ip", "vrf", "exec", "oob", "ssh", "-6", "-tt", "-o", "ConnectTimeout=5",
                "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR", "-o", "ControlMaster=no",
                "-o", "ControlPath=none", "-o", "NumberOfPasswordPrompts=1", "-B", "vlan1000", "admin@fe80::10"]

            def denied(*values, **kwargs):
                error = RuntimeError("FIXTURE HOLD: outside the finite M3 PUBLIC IO boundary")
                external_errors.append(error)
                raise error

            def remote(argv, responder, timeout, **kwargs):
                self.assertIs(type(argv), list)
                self.assertTrue(all(type(word) is str for word in argv))
                self.assertEqual(outer_header, argv[:-1], "exact ordinary outer SSH carrier only")
                self.assertEqual(60, timeout)
                self.assertEqual({}, kwargs)
                self.assertIs(type(responder), app.NestedResponder)
                self.assertIsNone(responder._phase, "no fabricated private phase")
                self.assertEqual(OOB_PASSWORD, responder.ethernet_password)
                self.assertEqual(secret("ib"), responder.ib_default_password)
                self.assertEqual("admin@fe80::10", responder.ib_destination)
                self.assertIs(False, responder.allow_password_change)
                self.assertIsNone(responder.ib_new_password)
                carrier = shlex.split(argv[-1])
                self.assertEqual(3, len(carrier))
                self.assertEqual(["sh", "-c"], carrier[:2])
                self.assertEqual(shlex.join(carrier), argv[-1])
                self.assertTrue(carrier[2].startswith(safe_path))
                inner_text = carrier[2][len(safe_path):]
                inner = shlex.split(inner_text)
                self.assertEqual(shlex.join(inner), inner_text)
                self.assertEqual(inner_header, inner[:-1], "exact nested endpoint/options/interface")
                framed = shlex.split(inner[-1])
                self.assertEqual(3, len(framed))
                self.assertEqual(["sh", "-c"], framed[:2])
                self.assertEqual(shlex.join(framed), inner[-1])
                markers = re.findall(r"__HTTP_IB_BEGIN_([0-9a-f]{32})__", framed[2])
                self.assertEqual(1, len(markers))
                marker = markers[0]
                self.assertEqual([marker], re.findall(r"__HTTP_IB_END_([0-9a-f]{32})__", framed[2]))
                prefix = 'printf "\\n__HTTP_IB_BEGIN_' + marker + '__\\n"; '
                suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + marker
                          + '__=%s\\n" "$task_rc"; exit "$task_rc"')
                self.assertTrue(framed[2].startswith(prefix) and framed[2].endswith(suffix))
                command_text = framed[2][len(prefix):-len(suffix)]
                command = shlex.split(command_text)
                self.assertEqual(shlex.join(command), command_text, "one canonical typed command")
                calls.append(command)
                code = 0
                if command == ["ip", "addr", "show", "eth0"]:
                    body = addr_reply
                elif command == ["nv", "show", "system", "ztp"]:
                    body = "service disabled\nstate disabled\n"
                elif command == ["nv", "config", "show", "-o", "commands"]:
                    body = current
                elif command == key_command:
                    self.assertEqual(5, len(command))
                    self.assertEqual(public_bytes, base64.b64decode(command[4], validate=True))
                    # Observe permission already obtained by REAL run_on_ib.
                    # The model never grants a permit or changes these facts.
                    coordinator = app._ACTIVE_COORDINATOR
                    self.assertIsNotNone(coordinator)
                    self.assertIs(t, coordinator.current_target)
                    self.assertIs(True, coordinator.authorized)
                    self.assertIs(True, coordinator.writes_attempted)
                    self.assertEqual(1, coordinator.metrics.get("public_key_install_attempts"))
                    result = install_keys(home, [public(2), public(3)])
                    shell_results.append(result)
                    body, code = result.stdout, result.returncode
                else:
                    # In particular: backup/deferred/rc/any other sh-c is
                    # NEVER treated as the key program or executed locally.
                    return denied()
                return app.SessionResult("__HTTP_IB_BEGIN_" + marker + "__\n" + body
                                         + "__HTTP_IB_END_" + marker + "__=" + str(code) + "\n", code)

            def observed_remote(*values, **kwargs):
                try:
                    return remote(*values, **kwargs)
                except BaseException as error:
                    external_errors.append(error)
                    raise

            with patch.object(app, "inspect_ib_device",
                              return_value=(app.SessionResult(current, 0), secret("ib"), True)), \
                 patch.object(app, "interactive_run", new=observed_remote), \
                 patch.object(app, "subprocess", SimpleNamespace(run=denied, Popen=denied,
                     TimeoutExpired=subprocess.TimeoutExpired, SubprocessError=subprocess.SubprocessError)), \
                 patch.object(app, "verify_ipv4_login"), \
                 patch.object(app, "run_management_direct_checks", return_value=[dict(
                     hostname=t.ib.hostname, interface="eth0", ip=t.ib.login_ip, status="PASS")]), \
                 contextlib.redirect_stdout(io.StringIO()):
                first = app.run_prepared_tasks([task], args, None, "admin", services, keys, None)
                if external_errors:
                    raise external_errors[0]  # an adapter/HOLD is never a business result
                second = app.run_prepared_tasks([task], args, None, "admin", services, keys, None)
                if external_errors:
                    raise external_errors[0]
            one = first["records"]["example-ib001"]
            two = second["records"]["example-ib001"]
            self.assertEqual(app.record_category(one), "CHECKED_EXISTING_KEYS_REFRESHED")
            self.assertEqual(app.record_category(two), "CHECKED_EXISTING_KEYS_VERIFIED")
            self.assertEqual(one["public_key_update"]["content_action"], "UPDATED")
            self.assertEqual(two["public_key_update"]["content_action"], "UNCHANGED")
            self.assertEqual(two["stage_status"]["services"], "ALREADY_PRESENT")
            for record in (one, two):
                self.assertIsNone(record["cable_check"], "no prepare/FDB means unmeasured, not MATCH")
                self.assertNotIn("csv_fdb_mac_check", record)
                self.assertIsNone(record["backup"], "key-only is not an NVUE write or a backup proof")
                self.assertEqual(0, record["metrics"].get("nvue_write_commands", 0))
                self.assertEqual(0, record["metrics"].get("config_backup_attempts", 0))
                self.assertEqual(1, record["metrics"].get("public_key_install_attempts"))
            self.assertEqual([0, 0], [result.returncode for result in shell_results])
            self.assertEqual(["IBSW_PUBLIC_KEYS_UPDATED\n", "IBSW_PUBLIC_KEYS_UNCHANGED\n"],
                             [result.stdout for result in shell_results])
            self.assertEqual((1, 1), (first["workers"], second["workers"]))
            self.assertEqual(Path(folder), Path(first["log_dir"]).parent)
            self.assertEqual(Path(folder), Path(second["log_dir"]).parent)
            self.assertIsNone(app._ACTIVE_COORDINATOR)
            self.assertIsNone(app._TASK_DEADLINE)
            self.assertIsNone(app._TASK_LOG_BUFFER)
            self.assertIs(previous_config, app._TASK_IB_CONFIG)
            self.assertEqual((home / ".ssh/authorized_keys").read_text().splitlines(), [public(2), public(3)])
            self.assertFalse(any(c[:2] == ["nv", "set"] for c in calls))
            self.assertEqual(json.loads(Path(two["log"]).with_suffix(".json").read_text())["public_key_update"],
                             two["public_key_update"])


class PerRunReportNameTests(unittest.TestCase):
    """O12 (guide :265, :1071): without --report the report is
    xdr-initial-setup-logs/initial-setup-report-<YYYYmmdd-HHMMSS>.log under the current directory,
    with -<pid> added when that name is taken; its path is printed first; the devices-* evidence
    directory starts with the same timestamp; an explicit --report is written as given."""

    STAMPED = re.compile(r"initial-setup-report-(\d{8}-\d{6})(?:-(\d+))?\.log")

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.cwd, self.home, project = self.root / "cwd", self.root / "home", self.root / "project"
        for path in (self.cwd, self.home, project):
            path.mkdir()
        (project / "ib.csv").write_text(
            "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw\n"
            "example-ib001,ib,192.0.2.10,24,192.0.2.1,02:00:00:00:00:10,,,\n"
            "example-oob-leaf01,eth_jump,198.51.100.10,,,,,,\n", encoding="utf-8")
        (project / "02-devices_config.csv").write_text(
            "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw\n"
            "example-ib001,ib,192.0.2.10,24,192.0.2.1,02:00:00:00:00:10,,,\n"
            "example-oob-leaf01,eth,198.51.100.10,,,,,,\n", encoding="utf-8")
        (project / "p2p.dot").write_text('"example-ib001":"eth0" -- "example-oob-leaf01":"swp1"\n',
                                         encoding="utf-8")
        # Inputs and the cache and snapshots stay in the project, so the working directory's
        # xdr-initial-setup-logs/ holds only what the report rule writes there.
        self.options = ["--project-dir", str(project), "--ib-csv", str(project / "ib.csv"),
                        "--p2p", str(project / "p2p.dot"), "--target-cache", str(project / "tasks.json"),
                        "--snapshot-dir", str(project / "snapshots"), "--execution-mode", "management"]
        self.logs = self.cwd / "xdr-initial-setup-logs"

    def run_main(self, *options):
        """The real main() from self.cwd.  Management mode needs no host-name lookup; the OOB Leaf
        accepts the public key and then fails its snapshot, so no IB login is ever attempted."""
        blocked = AssertionError("no external command or device session in this test")
        previous = os.getcwd()
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(app.sys, "argv", [str(INITIAL), *self.options, *options]))
            for name, value in (("REPORT_HANDLE", None), ("_CONSOLE_VERBOSE", False),
                                ("_CREDENTIALS_FD_MODE", False)):
                stack.enter_context(patch.object(app, name, value))
            stack.enter_context(patch.dict(os.environ, {"HOME": str(self.home)}))
            stack.enter_context(patch.object(Path, "home", return_value=self.home))
            for name in ("run", "Popen"):
                stack.enter_context(patch.object(app.subprocess, name, side_effect=blocked))
            stack.enter_context(patch.object(app, "interactive_run", side_effect=blocked))
            stack.enter_context(patch.object(app, "probe_ethernet_key", return_value="key"))
            stack.enter_context(patch.object(app, "_new_jump_sessions", legacy_jump_sessions_factory(app)))
            stack.enter_context(patch.object(app, "run_on_ethernet",
                                             side_effect=app.SetupError("synthetic OOB Leaf unreachable")))
            stack.enter_context(patch.object(app.time, "sleep", return_value=None))
            output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            os.chdir(self.cwd)
            try:
                code = app.main()
            finally:
                os.chdir(previous)
                if app.REPORT_HANDLE is not None:
                    app.REPORT_HANDLE.close()
        return code, output.getvalue()

    def reports(self):
        return sorted(self.logs.glob("initial-setup-report*.log"))

    # 开发计划.md :314 「每次运行用单独的文件名（目录不变）」; O12 (guide :265, :1071): the name format,
    # -<pid> on a clash, the report path printed first.
    def test_default_report_name_is_unique_per_run_in_same_directory(self):
        code, _ = self.run_main("--plan")
        self.assertEqual(0, code)
        self.assertEqual(1, len(self.reports()))
        first = self.reports()[0]
        first_bytes = first.read_bytes()
        code, _ = self.run_main("--plan")
        self.assertEqual(0, code)
        reports = self.reports()
        self.assertEqual(2, len(reports), "dev plan :314: a second run writes its own report file")
        second = next(path for path in reports if path != first)
        self.assertEqual(first.parent, second.parent, "dev plan :314: the directory does not change")
        self.assertEqual(first_bytes, first.read_bytes(), "the first run's report is left as it was")
        stamps = []
        for report in (first, second):
            self.assertRegex(report.name, self.STAMPED, "O12: initial-setup-report-<YYYYmmdd-HHMMSS>.log")
            self.assertEqual("Report: " + str(report), report.read_text(encoding="utf-8").splitlines()[0],
                             "O12: the report path is printed first")
            stamps.append(self.STAMPED.fullmatch(report.name).groups())
        if stamps[0][0] == stamps[1][0]:
            self.assertEqual(str(os.getpid()), stamps[1][1], "O12: the same second adds -<pid>")

    # 开发计划.md :314 only changes the default; O12 「显式 --report 照用户给的路径写」: the given
    # path is written even when that file exists, and no default report appears.
    def test_explicit_report_path_is_used_verbatim(self):
        explicit = self.root / "chosen" / "my-run.log"
        explicit.parent.mkdir()
        explicit.write_text("previous run\n", encoding="utf-8")
        code, output = self.run_main("--plan", "--report", str(explicit))
        self.assertEqual(0, code)
        self.assertEqual([explicit], sorted(explicit.parent.iterdir()))
        self.assertEqual("Report: " + str(explicit), explicit.read_text(encoding="utf-8").splitlines()[0])
        self.assertIn("Report: " + str(explicit), output)
        self.assertEqual([], self.reports())

    # O12 (guide :265, :1071): 「devices-* 目录用同一个时间戳做前缀」; the directory sits beside the
    # report (v15 run_prepared_tasks :4393-4395, guide :1065).
    def test_devices_dir_shares_the_report_timestamp(self):
        self.run_main()
        reports = self.reports()
        self.assertEqual(1, len(reports))
        self.assertRegex(reports[0].name, self.STAMPED, "O12: the default report name carries the timestamp")
        stamp = self.STAMPED.fullmatch(reports[0].name).group(1)
        devices = [path for path in self.logs.iterdir() if path.name.startswith("devices-")]
        self.assertEqual(1, len(devices))
        self.assertTrue((devices[0] / "summary.json").is_file(), "fixture: the run reached the summary")
        self.assertTrue(devices[0].name.startswith("devices-" + stamp),
                        f"O12: {devices[0].name} starts with devices-{stamp}")


if __name__ == "__main__":
    unittest.main()


class FinalDeviceFactsTests(unittest.TestCase):
    """WP5/r660:824–865, K4/K5 and the independently frozen9759d2a9 design.

    Pure final-summary consumers only.  The original877-line module is an exact
    byte prefix; Root selects this class, not the older process/shell test classes.
    Every displayed expected line below is a PUBLIC literal fixed before source
    implementation, not the formatter's output or a SUT-generated serialization.
    """

    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)

        def forbidden(*args, **kwargs):
            raise AssertionError("pure final-facts test attempted external action")

        # Replace only this loaded app's reference, not shared subprocess attrs.
        self.stack.enter_context(patch.object(app, "subprocess", SimpleNamespace(
            run=forbidden, Popen=forbidden,
            TimeoutExpired=subprocess.TimeoutExpired,
            SubprocessError=subprocess.SubprocessError)))
        for name in ("interactive_run", "run_on_ib", "run_on_ethernet",
                     "execute_ib_task", "run_prepared_tasks", "verify_password_hash",
                     "obtain_write_permit", "_import_tools"):
            self.stack.enter_context(patch.object(app, name, side_effect=forbidden))
        for name in ("_WORKER_CONNECTION", "_TASK_LOG_BUFFER"):
            self.stack.enter_context(patch.object(app, name, None))
        self.stack.enter_context(patch.object(app, "_CONSOLE_VERBOSE", False))

    def _record(self, hostname, **facts):
        record = {
            "hostname": hostname, "oob": None, "port": "",
            "outcome": "ALREADY_CONFIGURED", "writes_attempted": False,
            "failure_kind": None, "metrics": {"ib_ssh_attempts": 1},
            "stage_status": {"authentication": "VERIFIED", "day0": "ALREADY_PRESENT",
                             "direct_ssh": "VERIFIED"},
        }
        record.update(facts)
        return record

    def _pass(self, hostname):
        return {"hostname": hostname, "interface": "eth0", "ip": "192.0.2.10",
                "status": "PASS", "detail": "PUBLIC completed final access"}

    def _render(self, records, rows=(), *, apply=False):
        import copy

        # All old structural defaults are supplied.  Immutability here protects
        # facts/records, not a new ban on old missing-structural-field enrichment.
        before, rows_before = copy.deepcopy(records), copy.deepcopy(rows)
        targets = [app.Target(app.Device(name, "ib", "192.0.2.10", "192.0.2.10/24",
                                        "192.0.2.1", "02:00:00:00:00:10", "", ""),
                              None, "", "eth0") for name in records]
        console, report = io.StringIO(), io.StringIO()
        with patch.object(app, "REPORT_HANDLE", report), contextlib.redirect_stdout(console):
            status = app.print_initial_setup_summary(
                "PUBLIC-final-facts", SimpleNamespace(apply=apply,
                    report=Path("/PUBLIC-display-only/final-facts.log")),
                targets, len(targets), {}, records, list(rows), 1)
        self.assertEqual(before, records, "final formatter mutated input records/facts")
        self.assertEqual(rows_before, rows, "final formatter mutated direct-access facts")
        return status, console.getvalue(), report.getvalue()

    def _assert_fact_lines(self, console, report, total, expected):
        # Exact entire post-TOTAL body: unknown extra lines are not filtered out.
        for channel, text in (("console", console), ("report", report)):
            with self.subTest(channel=channel):
                anchor = "  TOTAL: " + str(total) + "\n"
                self.assertEqual(1, text.count(anchor))
                after = text.split(anchor, 1)[1]
                self.assertIn("\n+-- 04 CONFIGURATION STAGES", after)
                body = after.split("\n+-- 04 CONFIGURATION STAGES", 1)[0]
                self.assertEqual(expected, body.strip("\n").splitlines())
                headings = ("01 OVERVIEW", "02 OOB SNAPSHOTS", "03 IB SWITCHES OUTCOMES",
                            "04 CONFIGURATION STAGES", "05 SSH ACCESS",
                            "06 ATTENTION REQUIRED", "07 EVIDENCE & NEXT ACTIONS")
                positions = [text.index(heading) for heading in headings]
                self.assertEqual(sorted(positions), positions)
                self.assertEqual(7, len(re.findall(r"(?m)^\+-- \d\d ", text)))
                self.assertNotRegex(text, r"(?m)^\+-- 08 ")

    def test_final_cable_facts_keep_physical_position_verdict_and_three_ping_states(self):
        cases = (
            ("ELSEWHERE", False, False, None,
             "    Cable: expected=\"example-leaf01:swp7\" actual=[\"example-leaf02:swp9\"] verdict=ELSEWHERE after_ping=no ping_ok=unknown ignored=no"),
            ("ELSEWHERE", True, False, None,
             "    Cable: expected=\"example-leaf01:swp7\" actual=[\"example-leaf02:swp9\"] verdict=ELSEWHERE after_ping=no ping_ok=unknown ignored=yes"),
            ("NOT_LEARNED", False, True, True,
             "    Cable: expected=\"example-leaf01:swp7\" actual=[] verdict=NOT_LEARNED unlearned=yes after_ping=yes ping_ok=yes ignored=no"),
            ("NOT_LEARNED", False, True, False,
             "    Cable: expected=\"example-leaf01:swp7\" actual=[] verdict=NOT_LEARNED unlearned=yes after_ping=yes ping_ok=no ignored=no"),
            ("NOT_LEARNED", False, True, None,
             "    Cable: expected=\"example-leaf01:swp7\" actual=[] verdict=NOT_LEARNED unlearned=yes after_ping=yes ping_ok=unknown ignored=no"),
        )
        for apply in (False, True):
            for verdict, ignored, after_ping, ping_ok, expected in cases:
                with self.subTest(apply=apply, verdict=verdict, ignored=ignored, ping_ok=ping_ok):
                    cable = {
                        "hostname": "example-ib001", "mac": "02:00:00:00:00:10",
                        "link_local": "fe80::ff:fe00:10",
                        "expected": ["example-leaf01", "swp7"], "verdict": verdict,
                        "actual": [["example-leaf02", "swp9"]] if verdict == "ELSEWHERE" else [],
                        "extra_macs": [], "login_interface": "vlan1000",
                        "after_ping": after_ping, "ping_ok": ping_ok, "ignored": ignored,
                    }
                    record = self._record("example-ib001", cable_check=cable,
                        oob="example-spine01", port="swp49", jump={
                            "hostname": "example-spine01", "login_ip": "198.51.100.10",
                            "type": "eth_jump", "interface": "vlan1000", "vrf": "default",
                            "access_vlan": "1000", "selection_reason": "PUBLIC-cascade"})
                    if not ignored:
                        record.update(outcome="SKIPPED", category="SKIPPED_CABLE_CHECK_FAILED",
                                      stage_status={})
                    status, console, report = self._render({"example-ib001": record},
                        [self._pass("example-ib001")] if ignored else [], apply=apply)
                    self.assertEqual("SUCCESS" if ignored else "INCOMPLETE", status)
                    self._assert_fact_lines(console, report, 1,
                        ["  Device facts: example-ib001", expected])
                    self.assertEqual(verdict, record["cable_check"]["verdict"])
                    for text in (console, report):
                        self.assertNotIn('expected="example-spine01:swp49"', text)
                        self.assertNotIn("verdict=MATCH", text)

    def test_final_identity_facts_preserve_both_sides_and_do_not_invent_ipv4_verification(self):
        mismatch = {
            "ok": False, "via_ipv4": True,
            "expected": {"mac": "02:00:00:00:00:10", "ipv4": "192.0.2.10/24",
                         "gateway": "192.0.2.1"},
            "observed": {"mac": "02:00:00:00:00:99", "ipv4": ["192.0.2.99/24"],
                         "gateways": ["192.0.2.254"]},
            "mismatches": [
                {"field": "mac", "expected": "02:00:00:00:00:10", "observed": "02:00:00:00:00:99"},
                {"field": "ipv4", "expected": "192.0.2.10/24", "observed": "192.0.2.99/24"},
                {"field": "gateway", "expected": "192.0.2.1", "observed": "192.0.2.254"}],
        }
        link_local = {
            "ok": True, "via_ipv4": False,
            "expected": {"mac": "02:00:00:00:00:10", "ipv4": None, "gateway": None},
            "observed": {"mac": "02:00:00:00:00:10", "ipv4": [], "gateways": []},
            "mismatches": [],
        }
        cases = (
            (mismatch, "INCOMPLETE", [
                "    Identity: ok=no via_ipv4=yes mac_expected=\"02:00:00:00:00:10\" mac_observed=\"02:00:00:00:00:99\" ipv4_expected=\"192.0.2.10/24\" ipv4_observed=[\"192.0.2.99/24\"] gateway_expected=\"192.0.2.1\" gateways_observed=[\"192.0.2.254\"]"]),
            (link_local, "SUCCESS", [
                "    Identity: ok=yes via_ipv4=no mac_expected=\"02:00:00:00:00:10\" mac_observed=\"02:00:00:00:00:10\""]),
            (None, "INCOMPLETE", []),
            ({}, "INCOMPLETE", []),
        )
        for apply in (False, True):
            for identity, wanted_status, lines in cases:
                with self.subTest(apply=apply, identity=identity):
                    record = self._record("example-ib001", identity=identity, backup=None)
                    if wanted_status == "INCOMPLETE":
                        record.update(outcome="FAILED", category="FAILED_IDENTITY_MISMATCH",
                                      stage_status={})
                    status, console, report = self._render({"example-ib001": record},
                        [self._pass("example-ib001")] if wanted_status == "SUCCESS" else [], apply=apply)
                    self.assertEqual(wanted_status, status)
                    self._assert_fact_lines(console, report, 1,
                        ["  Device facts: example-ib001", *lines])
                    for text in (console, report):
                        self.assertNotIn("    Backup:", text)
                        if identity is not mismatch:
                            self.assertNotIn("ipv4_expected=", text)
                            self.assertNotIn("gateways_observed=", text)

    def test_successful_direct_device_keeps_hint_route_and_actual_backup_in_final_panel(self):
        for apply in (False, True):
            with self.subTest(apply=apply):
                healthy = self._record("example-ib002", jump=None, neighbor=None, cable_check=None,
                    route={"hostname": "example-ib002", "path": "direct", "reason": "NO_MGMT_LINK",
                           "jump": None, "port": None, "same_subnet": None},
                    input_issues=[], eth1_hints=[{
                        "hostname": "example-ib002", "field": "eth1_mac", "value": "",
                        "problem": "only one management MAC was supplied", "blocking": False}],
                    identity=None, backup={"path": "/home/admin/current_20261117-172746.yaml",
                                           "bytes": 321} if apply else None,
                    opaque_debug="PUBLIC-UNLISTED-RAW-MUST-NOT-PRINT")
                if apply:
                    healthy.update(outcome="CONFIGURED", writes_attempted=True,
                                   metrics={"ib_ssh_attempts": 1, "nvue_write_commands": 9})
                status, console, report = self._render({"example-ib002": healthy},
                    [self._pass("example-ib002")], apply=apply)
                self.assertEqual("SUCCESS", status,
                                 "nonblocking eth1 hint cannot change final success")
                expected = ["  Device facts: example-ib002",
                    "    Route: path=\"direct\" reason=\"NO_MGMT_LINK\" same_subnet=null",
                    "    eth1 hint: field=\"eth1_mac\" value=\"\" problem=\"only one management MAC was supplied\""]
                if apply:
                    expected.append("    Backup: path=\"/home/admin/current_20261117-172746.yaml\" bytes=321")
                self._assert_fact_lines(console, report, 1, expected)
                self.assertEqual([], app.initial_setup_attention(
                    {"example-ib002": healthy}, [self._pass("example-ib002")]))
                for text in (console, report):
                    self.assertNotIn("PUBLIC-UNLISTED-RAW-MUST-NOT-PRINT", text)
                    self.assertNotIn("None:", text)
                    self.assertNotIn("vrf=", text)
                    self.assertNotIn("    Cable:", text)
                    self.assertNotIn("    Identity:", text)
                blocked = self._record("example-ib001", outcome="SKIPPED",
                    category="SKIPPED_INPUT_INCOMPLETE", stage_status={}, input_issues=[{
                        "hostname": "example-ib001", "field": "eth0_gw", "value": "not-a-gateway",
                        "problem": "gateway is not a valid IPv4 address", "blocking": True}])
                status, console, report = self._render(
                    {"example-ib002": healthy, "example-ib001": blocked},
                    [self._pass("example-ib002")], apply=apply)
                self.assertEqual("INCOMPLETE", status)
                self._assert_fact_lines(console, report, 2, [
                    "  Device facts: example-ib001",
                    "    Input issue: field=\"eth0_gw\" value=\"not-a-gateway\" problem=\"gateway is not a valid IPv4 address\"",
                    *expected])
                self.assertIn("SKIPPED_INPUT_INCOMPLETE: 1", console)

                # FF01: independently frozen before formatter implementation.
                # Input has actual LF and one backslash; expected raw literals
                # have JSON escapes on one physical ASCII line, not SUT/json.dumps.
                escaped_value = 'PUBLIC-"q"\\path\n中文'
                escaped_problem = '公开 "bad"\\note\nsecond'
                escaped_records = {
                    "example-ib001": self._record("example-ib001", outcome="SKIPPED",
                        category="SKIPPED_INPUT_INCOMPLETE", stage_status={}, input_issues=[{
                            "hostname": "example-ib001", "field": "eth0_gw", "value": escaped_value,
                            "problem": escaped_problem, "blocking": True}]),
                    "example-ib002": dict(healthy, eth1_hints=[{
                        "hostname": "example-ib002", "field": "eth1_mac", "value": escaped_value,
                        "problem": escaped_problem, "blocking": False}]),
                }
                escaped_expected = [
                    "  Device facts: example-ib001",
                    r'    Input issue: field="eth0_gw" value="PUBLIC-\"q\"\\path\n\u4e2d\u6587" problem="\u516c\u5f00 \"bad\"\\note\nsecond"',
                    "  Device facts: example-ib002",
                    "    Route: path=\"direct\" reason=\"NO_MGMT_LINK\" same_subnet=null",
                    r'    eth1 hint: field="eth1_mac" value="PUBLIC-\"q\"\\path\n\u4e2d\u6587" problem="\u516c\u5f00 \"bad\"\\note\nsecond"',
                ]
                if apply:
                    escaped_expected.append("    Backup: path=\"/home/admin/current_20261117-172746.yaml\" bytes=321")
                status, console, report = self._render(escaped_records,
                    [self._pass("example-ib002")], apply=apply)
                self.assertEqual("INCOMPLETE", status)
                self._assert_fact_lines(console, report, 2, escaped_expected)

    def test_final_facts_keep_legacy_missing_metadata_inputs_immutable_and_seven_panels(self):
        records = {
            "example-ib003": self._record("example-ib003"),
            "example-ib002": self._record("example-ib002", outcome="FAILED",
                failure_kind="DIRECT_LOGIN_NETWORK", category="CHECKED_AND_CONFIGURED"),
            "example-ib001": self._record("example-ib001", outcome="FAILED",
                failure_kind="DIRECT_SSH_NETWORK", category="CHECKED_AND_CONFIGURED"),
        }
        for apply in (False, True):
            with self.subTest(apply=apply):
                status, console, report = self._render(records,
                    [self._pass("example-ib003")], apply=apply)
                self.assertEqual("INCOMPLETE", status)
                self._assert_fact_lines(console, report, 3, [
                    "  Device facts: example-ib001", "  Device facts: example-ib002",
                    "  Device facts: example-ib003"])
                self.assertEqual({"FAILED_DIRECT_SSH_NETWORK": 1,
                                  "FAILED_DIRECT_LOGIN_NETWORK": 1,
                                  "CHECKED_EXISTING_CONFIGURATION": 1},
                                 app.initial_setup_facts(records,
                                     [self._pass("example-ib003")])["categories"])
                for text in (console, report):
                    self.assertIn("FAILED_DIRECT_SSH_NETWORK: 1", text)
                    self.assertIn("FAILED_DIRECT_LOGIN_NETWORK: 1", text)
                    self.assertNotIn("CHECKED_AND_CONFIGURED: 2", text)
                    self.assertNotIn("    Identity:", text)
                    self.assertNotIn("    Backup:", text)
                    self.assertNotIn("    Route:", text)

    def test_csv_eui64_source_is_separate_from_legacy_nd_fdb_and_null_direct(self):
        records = {
            "example-ib001": self._record("example-ib001", neighbor={
                "ipv6": "fe80::10", "interface": "vlan1000", "vrf": "default",
                "mac": "02:00:00:00:00:10", "address_source": "ND"}),
            "example-ib002": self._record("example-ib002", neighbor={
                "ipv6": "fe80::20", "interface": "vlan1000", "vrf": "default",
                "mac": "02:00:00:00:00:20", "address_source": "FDB_EUI64_CANDIDATE"}),
            "example-ib003": self._record("example-ib003", neighbor={
                "ipv6": "fe80::ff:fe00:30", "interface": "vlan1000", "vrf": "default",
                "mac": "02:00:00:00:00:30", "address_source": "CSV_EUI64"}),
            "example-ib004": self._record("example-ib004", outcome="NOT_ATTEMPTED",
                stage_status={}, neighbor={"ipv6": "fe80::ff:fe00:40", "interface": "vlan1000",
                    "vrf": "default", "mac": "02:00:00:00:00:40", "address_source": "CSV_EUI64"}),
            "example-ib005": self._record("example-ib005", jump=None, neighbor=None,
                route={"hostname": "example-ib005", "path": "direct", "reason": "NO_MGMT_LINK",
                       "jump": None, "port": None, "same_subnet": None}),
        }
        rows = [self._pass(name) for name in (
            "example-ib001", "example-ib002", "example-ib003", "example-ib005")]
        facts = app.initial_setup_facts(records, rows)
        self.assertEqual({"ND": 1, "FDB_EUI64_CANDIDATE": 1, "CSV_EUI64": 2},
                         facts["ipv6_address_sources"])
        self.assertEqual({"candidates": 1, "authenticated": 1, "not_verified": 0},
                         facts["ipv6_fallback"], "legacy FDB statistic is not renamed CSV")
        self.assertIn("ipv6_csv_eui64", facts, "missing distinct current CSV source statistic")
        self.assertEqual({"candidates": 2, "authenticated": 1, "not_verified": 1},
                         facts["ipv6_csv_eui64"])
        for apply in (False, True):
            with self.subTest(apply=apply):
                status, console, report = self._render(records, rows, apply=apply)
                self.assertEqual("INCOMPLETE", status, "unattempted candidate remains incomplete")
                self._assert_fact_lines(console, report, 5, [
                    "  Device facts: example-ib001", "  Device facts: example-ib002",
                    "  Device facts: example-ib003", "  Device facts: example-ib004",
                    "  Device facts: example-ib005",
                    "    Route: path=\"direct\" reason=\"NO_MGMT_LINK\" same_subnet=null"])
                for text in (console, report):
                    self.assertIn("CSV-derived IPv6 candidates: 2; authenticated=1; not-verified=1", text)
                    self.assertIn("FDB-derived IPv6 candidates: 1; authenticated=1; not-verified=0", text)
                    self.assertNotIn("FDB-derived IPv6 candidates: 3", text)

    def test_replace_display_defaults_do_not_modify_caller_records(self):
        import copy

        selected_target = target()
        name = selected_target.ib.hostname
        omitted = "example-ib002"
        targets = [selected_target, replace(selected_target,
                   ib=replace(selected_target.ib, hostname=omitted))]
        record = self._record(name, needs_change=False)
        records = {name: record}
        selection = {name: {"file": "PUBLIC-example.yaml"}}
        before = copy.deepcopy((records, selection))
        args = SimpleNamespace(apply=False, config_mode="replace", _replace_selected=selection,
                               report=Path("/PUBLIC-display-only/replace.log"))
        with patch.object(app, "log"), \
             patch.object(app, "initial_setup_facts", wraps=app.initial_setup_facts) as facts:
            app.print_initial_setup_summary("PUBLIC-replace", args, targets, 2, {},
                                            records, [], 1)
        self.assertEqual(before, (records, selection), "formatter changed caller data")
        self.assertIs(record, records[name])
        projected = facts.call_args.args[0]
        self.assertEqual({"file": "PUBLIC-example.yaml"}, projected[name]["replace"])
        self.assertEqual("replace", projected[name]["config_mode"])
        self.assertIs(projected[name]["needs_change"], True)
        self.assertEqual("NOT_ATTEMPTED", projected[omitted]["outcome"])
