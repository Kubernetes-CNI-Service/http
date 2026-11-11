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
process with only --version, which exits in parse_args() before any input is read; no other test
reaches main().  No test reaches a device, and the generated key shell runs against a temporary
HOME.
"""

from __future__ import annotations

import base64
import contextlib
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_cases.module_loader import load_script

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
        with patch.object(app, "log"), patch.object(app.time, "sleep"), \
             patch.object(app, "inspect_ib_device", return_value=(state, PASSWORD, True)), \
             patch.object(app, "run_initial_stage", return_value=(state, True)), \
             patch.object(app, "parse_nvue_state", return_value=SimpleNamespace(hostname=t.ib.hostname, eth0_addresses=(), eth1_addresses=())), \
             patch.object(app, "base_stage_needed", return_value=False), \
             patch.object(app, "verify_state"), \
             patch.object(app, "verify_ipv4_login", side_effect=app.SetupError("synthetic OOB IPv4 timeout")), \
             patch.object(app, "run_management_direct_checks", return_value=rows), \
             patch.object(app, "run_service_stage") as services, \
             patch.object(app, "run_key_stage") as keys:
            record = app.execute_ib_task(task, args, None, "admin", None, [], None, True)
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
        with patch.object(app, "interface_status_line", return_value="swp1 up up"), \
             patch.object(app, "interface_oper_status", return_value="up"), \
             patch.object(app, "fdb_port_for_interface", return_value="swp1"), \
             patch.object(app, "neighbor_for_port", return_value=app.Neighbor("fe80::10", "vlan1000", "02:00:00:00:00:99")), \
             patch.object(app, "run_on_ib") as ssh, patch.object(app, "log") as output:
            ready = app.prepare_ready_ib_tasks([t], SimpleNamespace(), {"example-oob-leaf01": ""}, set(),
                {"example-oob-leaf01": "interfaces"}, {"example-oob-leaf01": ("links", "fdb", "neighbors")},
                {}, outcomes, records)
        self.assertEqual(ready, [])
        self.assertEqual(outcomes, {"example-ib001": "SKIPPED"})
        self.assertEqual(records["example-ib001"]["category"], "SKIPPED_MAC_MISMATCH")
        self.assertEqual(records["example-ib001"]["mac_mismatch"],
                         {"expected": "02:00:00:00:00:10", "observed": "02:00:00:00:00:99"})
        text = "\n".join(call.args[0] for call in output.call_args_list)
        self.assertIn("expected=02:00:00:00:00:10 observed=02:00:00:00:00:99", text)
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
        records = {"example-ib001": dict(hostname="example-ib001", outcome="ALREADY_CONFIGURED")}
        with patch.object(app, "log") as log:
            app.print_initial_setup_summary("fixture", SimpleNamespace(apply=True, report=REPORT),
                                            [t], 1, {}, records, [], 1)
        text = "\n".join(c.args[0] for c in log.call_args_list)
        self.assertIn("CSV eth0 MAC unavailable: 1", text)
        self.assertIn("not checked against inventory MAC", text)
        self.assertEqual(t.ib.eth0_mac, "")

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
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder) / "remote"
            home.mkdir()
            args = SimpleNamespace(apply=True, yes=True, force=False, max_workers=16, task_timeout=20,
                                   eth_user="cumulus", ib_user="admin", connect_timeout=5,
                                   execution_mode="management", report=Path(folder) / "report.log")
            calls = []

            def remote(*values, **kwargs):
                command = values[7]
                calls.append(command)
                app.record_metric("ib_ssh_attempts")
                if command[:2] == ["sh", "-c"]:
                    app.obtain_write_permit("public_key")
                    result = install_keys(home, [public(2), public(3)])
                    if result.returncode:
                        raise app.SetupError("synthetic remote shell failed")
                    return app.SessionResult(result.stdout, 0)
                return app.SessionResult("service disabled\n" if command == ["nv", "show", "system", "ztp"] else "", 0)
            with patch.object(app, "inspect_ib_device",
                              return_value=(app.SessionResult(current, 0), secret("ib"), True)), \
                 patch.object(app, "run_on_ib", remote), patch.object(app, "verify_ipv4_login"), \
                 patch.object(app.time, "sleep"), \
                 patch.object(app, "run_management_direct_checks", return_value=[dict(
                     hostname=t.ib.hostname, interface="eth0", ip=t.ib.login_ip, status="PASS")]), \
                 contextlib.redirect_stdout(io.StringIO()):
                first = app.run_prepared_tasks([task], args, None, "admin", services, keys, None)
                second = app.run_prepared_tasks([task], args, None, "admin", services, keys, None)
            one = first["records"]["example-ib001"]
            two = second["records"]["example-ib001"]
            self.assertEqual(app.record_category(one), "CHECKED_EXISTING_KEYS_REFRESHED")
            self.assertEqual(app.record_category(two), "CHECKED_EXISTING_KEYS_VERIFIED")
            self.assertEqual(one["public_key_update"]["content_action"], "UPDATED")
            self.assertEqual(two["public_key_update"]["content_action"], "UNCHANGED")
            self.assertEqual(two["stage_status"]["services"], "ALREADY_PRESENT")
            self.assertEqual(two["csv_fdb_mac_check"]["status"], "MATCH")
            self.assertEqual((home / ".ssh/authorized_keys").read_text().splitlines(), [public(2), public(3)])
            self.assertFalse(any(c[:2] == ["nv", "set"] for c in calls))
            self.assertEqual(json.loads(Path(two["log"]).with_suffix(".json").read_text())["public_key_update"],
                             two["public_key_update"])


if __name__ == "__main__":
    unittest.main()
