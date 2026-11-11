"""Direct: initial-setup's global worker queue, real worker processes and per-device isolation.

What: the worker count rule min(16, ceil(N/16)) with --max-workers only lowering it, input
authority pins, the initial OOB interleave without worker affinity, real forked workers (peak 16
for 257 tasks, no duplicate dispatch, parent-only prompts, authorization, write permits, crash,
deadline and shared-input stop without replay) and, through the real main(), that one IB device's
failure leaves the other devices eligible while a changed project global stops the batch.

Expectation sources (not derived from the implementation):
- R-011 I21 (需求文档.md, section "R-011 initial-setup", table row I21; moved there from
  待确认问题.md on 2026-11-08).  I21 is v15-implemented behaviour, adopted as this release's
  test-expectation source under the owner's 11-06 ruling to take v15 as the base (开发计划.md:314;
  v3.1.3 guide O13 :266; the 采用依据 bullet of the same R-011 section); it is not an owner
  confirmation of I21.
- 参考/initial-setup-v15/CURRENT-CONTRACT.md:64-65 (workers=min(16,ceil(ready/16)), zero ready
  starts no worker, --max-workers only lowers the cap, one worker runs one IB's whole pipeline,
  the global queue is not bound to an OOB).
- Guide table 6-1 row 1 (:744: a failed device stops only itself, the run is INCOMPLETE) and
  row 11 (:754: exit codes 0 SUCCESS, 1 FAILED, 2 INCOMPLETE).
- The v15 delivered tests test_desktop_initial_setup.py::GlobalWorkerSchedulerTests (:1077),
  ::WorkerProcessLifecycleTests (:1171) and ::BatchDeviceIsolationTests (:2158); the file's
  sha256 is bound by 参考/initial-setup-v15/HANDOFF-SHA256SUMS:27.

Fixture rewrites (public audit, guide :835): synthetic host names (example-ib…, example-oob-…),
documentation IPv4 only, 02:00:00 MACs, credentials assembled at run time, a synthetic global
hash with the native hash backend replaced by ProjectPasswordPolicy.matches.  The batch runs the
real main() with HOME in a temporary directory and a real CSV/P2P/target cache (a management run
with a project global takes the merged strict path, whose cache/profile admission cannot accept a
patched load_target_cache); the fake IB side answers the pending-diff read empty (T15, guide
:2301) and reads back the CSV values after the Network writes.
"""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
app = load_script("initial_setup_v15_worker_queue", INITIAL)

JUMP = "example-oob-leaf01"
WRITE_PREFIXES = ("nv set ", "nv unset ", "nv config apply", "nv config save")


def secret(label: str) -> str:
    # Assembled at run time so no credential literal appears in the source (public audit).
    return "-".join(("PUBLIC", "wp7", label, "Zq7"))


PASSWORD = secret("ib-target")
FACTORY = secret("factory")
OOB = secret("oob")
GLOBAL_HASH = "$" + "6$PUBLICsalt$" + "A" * 86
OTHER_HASH = "$" + "6$PUBLICsalt$" + "B" * 86
CONFIG = "nv set system hostname nvos\n"


def target():
    ib = app.Device("example-ib001", "ib", "192.0.2.10", "192.0.2.10/24",
                    "192.0.2.1", "02:00:00:00:00:10", "", "")
    eth = app.Device(JUMP, "eth_jump", "198.51.100.10", "", "", "", "", "")
    return app.Target(ib, eth, "swp1", "eth0")


def global_text(hash_value: str = GLOBAL_HASH) -> str:
    return ("schema_version: 2\ncommon:\n  switch:\n    system:\n"
            "      config:\n        auto-save:\n          state: enabled\n"
            "switches:\n- ib:\n    system:\n      aaa:\n        user:\n"
            "          admin:\n            password: {}\n").format(json.dumps(hash_value))


def success(task):
    return {"hostname": task.target.ib.hostname, "outcome": "CONFIGURED", "reason": "",
            "direct_rows": [], "batch_error": ""}


def lifecycle_tasks(count):
    original = target()
    return [app.PreparedIBTask(app.Target(replace(original.ib, hostname=f"example-ib{number:03d}"),
                                          original.ethernet, "swp1", "eth0"),
                               app.Neighbor("fe80::10", "vlan1000", original.ib.eth0_mac, "oob"), "", False)
            for number in range(1, count + 1)]


def run_local_pool(simulated, *, count=17, apply=False, yes=False, timeout=20, policy=None,
                   authority=None):
    """v15 WorkerProcessLifecycleTests.run_local_pool: real run_prepared_tasks, no device IO."""
    messages = []
    with tempfile.TemporaryDirectory() as directory:
        args = SimpleNamespace(max_workers=16, task_timeout=timeout,
                               report=Path(directory) / "report.log", apply=apply, yes=yes)
        with patch.object(app, "execute_ib_task", simulated), \
                patch.object(app, "interactive_run", side_effect=AssertionError("Real device IO forbidden")), \
                patch.object(app, "log", lambda message="": messages.append(message)):
            result = app.run_prepared_tasks(lifecycle_tasks(count), args, policy,
                                            FACTORY, None, [], None, authority=authority)
        logs = [path.read_text() for path in Path(result["log_dir"]).glob("*.log")]
    return result, messages, logs


class WorkerQueueTests(unittest.TestCase):
    # -- v15 GlobalWorkerSchedulerTests --------------------------------------------------------------
    # v15 GlobalWorkerSchedulerTests.test_worker_count_is_ceil_n_over_16_and_never_over_16
    # (test_desktop_initial_setup.py:1078); CURRENT-CONTRACT.md:64.
    def test_worker_count_is_ceil_n_over_16_and_never_over_16(self):
        for count, expected in ((0, 0), (1, 1), (16, 1), (17, 2),
                                (32, 2), (33, 3), (256, 16), (257, 16), (4096, 16)):
            with self.subTest(count=count):
                self.assertEqual(app.automatic_worker_count(count), expected)
        self.assertEqual(app.automatic_worker_count(100, 2), 2)
        for cap in (0, 17):
            with self.assertRaises(app.SetupError):
                app.automatic_worker_count(100, cap)

    # v15 GlobalWorkerSchedulerTests.test_input_authority_detects_content_and_link_target_changes
    # (test_desktop_initial_setup.py:1088).
    def test_input_authority_detects_content_and_link_target_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.csv"
            source.write_text("original\n")
            authority = app.RuntimeInputAuthority([source])
            authority.assert_unchanged()
            source.write_text("modified\n")
            with self.assertRaises(app.ProjectInputChanged):
                authority.assert_unchanged()
            other = Path(directory) / "other.csv"
            other.write_text("modified\n")
            link = Path(directory) / "input-link.csv"
            link.symlink_to(source)
            linked = app.RuntimeInputAuthority([link])
            link.unlink()
            link.symlink_to(other)
            with self.assertRaises(app.ProjectInputChanged):
                linked.assert_unchanged()

    # v15 GlobalWorkerSchedulerTests.test_initial_queue_spreads_oobs_but_workers_have_no_affinity
    # (test_desktop_initial_setup.py:1107); CURRENT-CONTRACT.md:65 (global queue, no OOB binding).
    def test_initial_queue_spreads_oobs_but_workers_have_no_affinity(self):
        tasks = []
        for number, group in enumerate(("a", "a", "a", "b", "c"), 1):
            original = target()
            tasks.append(app.PreparedIBTask(app.Target(
                replace(original.ib, hostname=f"example-ib{number:03d}"),
                replace(original.ethernet, hostname="example-oob-" + group), "swp1", "eth0"),
                app.Neighbor("fe80::10", "vlan1000", original.ib.eth0_mac), "", False))
        self.assertEqual([item.target.ib.hostname for item in app.interleave_oob_tasks(tasks)],
                         ["example-ib001", "example-ib004", "example-ib005", "example-ib002", "example-ib003"])

    # v15 GlobalWorkerSchedulerTests.test_verbose_real_workers_share_global_queue_and_parent_prints_whole_logs
    # (test_desktop_initial_setup.py:1118).  The logged worker line carries the secret value (the
    # redaction is by value; v15 prefixed it with a label).
    def test_verbose_real_workers_share_global_queue_and_parent_prints_whole_logs(self):
        context = app.multiprocessing.get_context("fork")
        active, peak = context.Value("i", 0), context.Value("i", 0)
        lock = context.Lock()
        tasks = []
        for number in range(33):
            original = target()
            device = replace(original.ib, hostname=f"example-ib{number + 1:03d}")
            oob = replace(original.ethernet,
                          hostname="example-oob-small" if number < 2 else "example-oob-large")
            tasks.append(app.PreparedIBTask(app.Target(device, oob, "swp1", "eth0"),
                         app.Neighbor("fe80::10", "vlan1000", device.eth0_mac, "oob"), "", False))

        def simulated(task, *args, **kwargs):
            with lock:
                active.value += 1
                peak.value = max(peak.value, active.value)
            try:
                name = task.target.ib.hostname
                app.log("BEGIN " + name)
                app.log("Synthetic credential " + PASSWORD)
                time.sleep(0.03)
                app.log("END " + name)
                return {"hostname": name, "outcome": "FAILED" if name == "example-ib017" else "CONFIGURED",
                        "reason": "synthetic failure" if name == "example-ib017" else "",
                        "direct_rows": [], "writes_attempted": False, "batch_error": ""}
            finally:
                with lock:
                    active.value -= 1

        messages = []
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(max_workers=16, task_timeout=30, verbose=True,
                                   report=Path(directory) / "report.log", apply=False, yes=False)
            with patch.object(app, "execute_ib_task", simulated), \
                    patch.object(app, "log", lambda message="": messages.append(message)):
                result = app.run_prepared_tasks(tasks, args, None, PASSWORD, None, [], None)
            self.assertEqual(len(result["outcomes"]), 33)
            self.assertEqual(list(result["outcomes"].values()).count("FAILED"), 1)
            self.assertEqual(list(result["outcomes"].values()).count("CONFIGURED"), 32)
            self.assertGreater(peak.value, 1)
            self.assertLessEqual(peak.value, 3)
            output = "\n".join(messages)
            self.assertNotIn(PASSWORD, output)
            blocks = [line for line in messages if line.startswith("BEGIN ") or line.startswith("END ")]
            self.assertEqual(len(blocks), 66)
            for index in range(0, len(blocks), 2):
                self.assertEqual(blocks[index][len("BEGIN "):], blocks[index + 1][len("END "):])
            logs = list(Path(directory).glob("devices-*/*.log"))
            self.assertEqual(len(logs), 33)
            self.assertTrue(all(PASSWORD not in path.read_text() for path in logs))

    # -- v15 WorkerProcessLifecycleTests (real local worker/IPC; execute_ib_task is replaced) -------
    # v15 WorkerProcessLifecycleTests.test_actual_peak_is_sixteen_for_257_tasks_with_no_duplicate_dispatch
    # (test_desktop_initial_setup.py:1199); CURRENT-CONTRACT.md:64 (hard cap 16).
    def test_actual_peak_is_sixteen_for_257_tasks_with_no_duplicate_dispatch(self):
        context = app.multiprocessing.get_context("fork")
        active, peak = context.Value("i", 0), context.Value("i", 0)
        hits = context.Array("i", 257)
        lock, released = context.Lock(), context.Event()

        def simulated(task, *args, **kwargs):
            index = int(task.target.ib.hostname[-3:]) - 1
            with lock:
                active.value += 1
                hits[index] += 1
                peak.value = max(peak.value, active.value)
                if active.value == 16:
                    released.set()
            try:
                if not released.wait(8):
                    raise AssertionError("Expected all 16 worker slots to run concurrently")
                time.sleep(0.01)
                return success(task)
            finally:
                with lock:
                    active.value -= 1
        result, _, _ = run_local_pool(simulated, count=257, timeout=30)
        self.assertEqual(result["workers"], 16)
        self.assertEqual(peak.value, 16)
        self.assertEqual(list(hits), [1] * 257)
        self.assertEqual(set(result["outcomes"].values()), {"CONFIGURED"})
        self.assertEqual(len(result["outcomes"]), 257)

    # v15 WorkerProcessLifecycleTests.test_parent_prompts_once_for_batch_authorization_and_twice_for_target_password
    # (test_desktop_initial_setup.py:1227).  Only the native hash backend is replaced
    # (ProjectPasswordPolicy.matches compares with the run-time value; the global hash is synthetic).
    def test_parent_prompts_once_for_batch_authorization_and_twice_for_target_password(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "01-global.yaml"
            path.write_text(global_text())
            policy = app.ProjectPasswordPolicy(path, "admin")

            def simulated(task, *args, **kwargs):
                value = app.worker_request("target-password")
                app.log("Synthetic credential " + value)
                app.confirm_first_device_change(task.target, "synthetic write, no real device IO")
                app.obtain_write_permit("nvue")
                return success(task)
            with patch.object(app.getpass, "getpass", return_value=PASSWORD) as prompt, \
                    patch.object(app.ProjectPasswordPolicy, "matches", side_effect=lambda value: value == PASSWORD), \
                    patch.object(app, "_ask_first_device_change", return_value=True) as authorize:
                result, messages, logs = run_local_pool(simulated, apply=True, policy=policy)
        self.assertEqual(prompt.call_count, 2)
        self.assertEqual(authorize.call_count, 1)
        self.assertEqual(set(result["outcomes"].values()), {"CONFIGURED"})
        self.assertTrue(all(record["writes_attempted"] for record in result["records"].values()))
        self.assertEqual(sum(record["metrics"]["nvue_write_commands"] for record in result["records"].values()), 17)
        self.assertNotIn(PASSWORD, "\n".join(messages + logs))

    # v15 WorkerProcessLifecycleTests.test_readonly_worker_cannot_obtain_any_write_permit
    # (test_desktop_initial_setup.py:1248).
    def test_readonly_worker_cannot_obtain_any_write_permit(self):
        def simulated(task, *args, **kwargs):
            app.obtain_write_permit("nvue")
            raise AssertionError("No write permit should be returned")
        result, _, _ = run_local_pool(simulated)
        self.assertEqual(list(result["outcomes"].values()).count("FAILED"), 17)
        self.assertTrue(all(not record["writes_attempted"] for record in result["records"].values()))
        self.assertEqual(sum(record["metrics"].get("nvue_write_commands", 0)
                             for record in result["records"].values()), 0)

    # v15 WorkerProcessLifecycleTests.test_refused_authorization_stops_dispatch_without_write
    # (test_desktop_initial_setup.py:1258).
    def test_refused_authorization_stops_dispatch_without_write(self):
        def simulated(task, *args, **kwargs):
            try:
                app.confirm_first_device_change(task.target, "synthetic authorization request")
            except app.BatchStopped:
                return {"outcome": "NOT_ATTEMPTED", "direct_rows": [], "batch_error": ""}
            raise AssertionError("User refused authorization")
        with patch.object(app, "_ask_first_device_change", return_value=False) as authorize:
            result, _, _ = run_local_pool(simulated, apply=True)
        self.assertEqual(authorize.call_count, 1)
        self.assertIn("not authorized", result["fatal"])
        self.assertEqual(set(result["outcomes"].values()), {"NOT_ATTEMPTED"})
        self.assertTrue(all(not record["writes_attempted"] for record in result["records"].values()))

    # v15 WorkerProcessLifecycleTests.test_worker_crash_is_not_replayed_and_other_tasks_continue
    # (test_desktop_initial_setup.py:1272).
    def test_worker_crash_is_not_replayed_and_other_tasks_continue(self):
        context = app.multiprocessing.get_context("fork")
        hits = context.Array("i", 17)

        def simulated(task, *args, **kwargs):
            index = int(task.target.ib.hostname[-3:]) - 1
            with hits.get_lock():
                hits[index] += 1
            if index == 1:
                app.log("Evidence received before synthetic worker crash")
                os._exit(9)
            return success(task)
        result, _, logs = run_local_pool(simulated)
        self.assertEqual(list(hits), [1] * 17)
        self.assertEqual(result["outcomes"]["example-ib002"], "FAILED")
        self.assertEqual(list(result["outcomes"].values()).count("CONFIGURED"), 16)
        self.assertEqual(result["fatal"], "")
        self.assertIn("exit=9", result["records"]["example-ib002"]["reason"])
        self.assertIn("Evidence received before synthetic worker crash", "\n".join(logs))

    # v15 WorkerProcessLifecycleTests.test_task_timeout_is_not_replayed_and_does_not_stop_other_devices
    # (test_desktop_initial_setup.py:1291).
    def test_task_timeout_is_not_replayed_and_does_not_stop_other_devices(self):
        context = app.multiprocessing.get_context("fork")
        hits = context.Array("i", 17)

        def simulated(task, *args, **kwargs):
            index = int(task.target.ib.hostname[-3:]) - 1
            with hits.get_lock():
                hits[index] += 1
            if index == 0:
                app.log("Synthetic task started before timeout")
                time.sleep(5)
            return success(task)
        result, _, logs = run_local_pool(simulated, timeout=0.25)
        self.assertEqual(list(hits), [1] * 17)
        self.assertEqual(result["outcomes"]["example-ib001"], "FAILED")
        self.assertIn("deadline exceeded", result["records"]["example-ib001"]["reason"])
        self.assertEqual(list(result["outcomes"].values()).count("CONFIGURED"), 16)
        self.assertEqual(result["fatal"], "")
        self.assertIn("Synthetic task started before timeout", "\n".join(logs))

    # v15 WorkerProcessLifecycleTests.test_shared_input_change_blocks_new_writes_and_remaining_dispatch
    # (test_desktop_initial_setup.py:1310).
    def test_shared_input_change_blocks_new_writes_and_remaining_dispatch(self):
        context = app.multiprocessing.get_context("fork")
        changed = context.Event()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "inventory.csv"
            source.write_text("original\n")
            authority = app.RuntimeInputAuthority([source])

            def simulated(task, *args, **kwargs):
                if task.target.ib.hostname == "example-ib001":
                    source.write_text("changed\n")
                    changed.set()
                else:
                    changed.wait(2)
                app.obtain_write_permit("nvue")
                raise AssertionError("Changed shared input must block write permission")
            result, _, _ = run_local_pool(simulated, apply=True, yes=True, authority=authority)
        self.assertIn("input bytes changed", result["fatal"])
        self.assertGreaterEqual(list(result["outcomes"].values()).count("NOT_ATTEMPTED"), 15)
        self.assertTrue(all(not record["writes_attempted"] for record in result["records"].values()))

    # v15 WorkerProcessLifecycleTests.test_crash_after_write_permit_retains_partial_write_evidence_without_replay
    # (test_desktop_initial_setup.py:1330).
    def test_crash_after_write_permit_retains_partial_write_evidence_without_replay(self):
        def simulated(task, *args, **kwargs):
            if task.target.ib.hostname == "example-ib002":
                app.obtain_write_permit("nvue")
                app.log("Synthetic permitted write may be partial")
                os._exit(11)
            return success(task)
        result, _, logs = run_local_pool(simulated, apply=True, yes=True)
        record = result["records"]["example-ib002"]
        self.assertEqual(record["outcome"], "FAILED")
        self.assertTrue(record["writes_attempted"])
        self.assertEqual(record["metrics"]["nvue_write_commands"], 1)
        self.assertEqual(list(result["outcomes"].values()).count("CONFIGURED"), 16)
        self.assertIn("Synthetic permitted write may be partial", "\n".join(logs))

    # -- v15 BatchDeviceIsolationTests (the real main(); every device/SSH boundary is fake) --------
    def run_batch(self, failure_stage, failure_type=None):
        failure_type = failure_type or app.SetupError
        names = [f"example-ib{number:03d}" for number in (1, 2, 3)]
        inspected, base_calls, key_calls, messages = [], [], [], []
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            root = Path(directory)
            global_path = root / "01-global.yaml"
            global_path.write_text(global_text())
            # A real CSV/P2P: the strict cache/profile admission needs the real target cache.
            rows = ["hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac"]
            rows += [f"{name},ib,192.0.2.{number + 9},24,192.0.2.1,02:00:00:00:00:{number + 15:02x}"
                     for number, name in enumerate(names, 1)]
            rows.append(f"{JUMP},eth_jump,198.51.100.10,,,")
            csv_path = root / "ib.csv"
            csv_path.write_text("\n".join(rows) + "\n")
            p2p_path = root / "p2p.dot"
            p2p_path.write_text("".join(f'"{name}":"eth0" -- "{JUMP}":"swp{number}"\n'
                                        for number, name in enumerate(names, 1)))
            # O6 (guide :259): the neutral service defaults are one local infra-neutral.conf, under
            # --project-dir the project's infiniband/bringup/xdr-initial-setup/ one (WP-8 table 8-1, :923).
            neutral = root / "infiniband/bringup/xdr-initial-setup/infra-neutral.conf"
            neutral.parent.mkdir(parents=True, exist_ok=True)
            neutral.write_text("DNS=192.0.2.53\nNTP=192.0.2.123\nTIMEZONE=Etc/UTC\n")
            home = root / "home"
            home.mkdir()
            argv = [str(INITIAL), "--project-dir", str(root), "--ib-csv", str(csv_path),
                    "--p2p", str(p2p_path), "--target-cache", str(root / "targets.json"),
                    "--report", str(root / "report.log"),
                    "--snapshot-dir", str(root / "snapshots"),
                    "--execution-mode", "management", "--apply", "--yes", "--verbose"]
            stack.enter_context(patch.object(sys, "argv", argv))
            stack.enter_context(patch.object(app, "REPORT_HANDLE", None))
            stack.enter_context(patch.dict(os.environ, {"HOME": str(home)}))
            stack.enter_context(patch.object(Path, "home", return_value=home))
            stack.enter_context(patch.object(app.time, "sleep", return_value=None))
            stack.enter_context(patch.object(app.subprocess, "run",
                                             side_effect=AssertionError("external commands forbidden")))
            # The strict helper verifies the project target; only the native hash backend and the
            # interactive target prompt are replaced (as the v15 spine workflow test does).
            stack.enter_context(patch.object(app.ProjectPasswordPolicy, "password", return_value=PASSWORD))
            stack.enter_context(patch.object(app.ProjectPasswordPolicy, "matches",
                                             side_effect=lambda value: value == PASSWORD))

            def fail_at(stage, device):
                if device.ib.hostname == "example-ib002" and failure_stage == stage:
                    raise failure_type("synthetic device-local failure")

            def inspect(device, *args, **kwargs):
                inspected.append(device.ib.hostname)
                fail_at("inspect", device)
                if failure_stage == "global" and device.ib.hostname == "example-ib002":
                    global_path.write_text(global_text(OTHER_HASH))
                return app.SessionResult(CONFIG, 0), PASSWORD, True

            def initialize(device, *args, **kwargs):
                fail_at("initial", device)
                # The v15 run_initial_stage returns (readback text, authorized).
                return CONFIG, True

            def run_command(device, *args, **kwargs):
                command = args[6]
                text = shlex.join(command)
                if text.startswith(WRITE_PREFIXES):
                    # Only Network writes count as base calls; the pending-diff and readback reads
                    # that the merged stage adds (T15 :2301, _verify_management_network_state) do not.
                    base_calls.append(device.ib.hostname)
                    fail_at("base", device)
                    return app.SessionResult("", 0)
                if command == ["nv", "config", "diff", "-o", "commands"]:
                    return app.SessionResult("", 0)
                if command == ["nv", "config", "show", "-o", "commands"]:
                    return app.SessionResult("".join(shlex.join(item) + "\n" for item in
                                                     app.desired_commands(device.ib)
                                                     if item[:2] == ["nv", "set"]), 0)
                raise AssertionError("unexpected IB command " + text)

            def services(device, *args, **kwargs):
                fail_at("services", device)
                return True, False

            def keys(device, *args, **kwargs):
                key_calls.append(device.ib.hostname)
                fail_at("keys", device)
                return True

            boundaries = {
                "log": lambda message="": messages.append(message),
                "resolve_initial_ib_password": lambda *a, **k: "admin",
                "local_ethernet_keys": lambda *a, **k: set(),
                "prompt_ethernet_passwords": lambda *a, **k: {JUMP: OOB},
                "collect_ethernet_interfaces": lambda *a, **k: (JUMP, "interfaces"),
                "collect_ethernet_network_tables": lambda *a, **k: ("links", "fdb", "neighbors"),
                "save_ethernet_snapshot": lambda *a, **k: root / "snapshot.json",
                "interface_status_line": lambda *a, **k: "swp1 up up",
                "interface_oper_status": lambda *a, **k: "up",
                "fdb_port_for_interface": lambda links, port: port,
                "neighbor_for_port": lambda *a, **k: app.Neighbor("fe80::10", "vlan1000", "02:00:00:00:00:10"),
                "verify_fdb_eth0_mac": lambda *a, **k: None,
                "interface_vrf": lambda *a, **k: "oob",
                "inspect_ib_device": inspect,
                "run_initial_stage": initialize,
                "base_stage_needed": lambda *a, **k: True,
                "run_on_ib": run_command,
                "verify_state": lambda *a, **k: None,
                "verify_ipv4_login": lambda device, *a, **k: fail_at("readiness", device),
                "run_service_stage": services,
                "run_key_stage": keys,
                "run_management_direct_checks": lambda *a, **k: [],
            }
            for name, replacement in boundaries.items():
                stack.enter_context(patch.object(app, name, replacement))
            strict = stack.enter_context(patch.object(app, "_run_authorized_ib_command",
                                                      wraps=app._run_authorized_ib_command))
            try:
                result = app.main()
            finally:
                if app.REPORT_HANDLE is not None:
                    app.REPORT_HANDLE.close()
            if base_calls:
                # Fixture check, not a v15 expectation: the management run with the project global
                # sent its Network writes through the merged strict helper.
                self.assertGreater(strict.call_count, 0)
        return result, inspected, base_calls, key_calls, "\n".join(messages)

    # v15 BatchDeviceIsolationTests.test_middle_device_failure_does_not_stop_other_devices
    # (test_desktop_initial_setup.py:2253); guide table 6-1 row 1 (:744) and row 11 (:754).
    def test_middle_device_failure_does_not_stop_other_devices(self):
        for stage, failure in (
            ("inspect", app.IBPasswordChangeUncertain),
            ("initial", app.IBConfigurationStageUncertain),
            ("base", app.SetupError),
            ("readiness", app.SetupError),
            ("services", app.IBConfigurationStageUncertain),
            ("keys", app.SetupError),
        ):
            with self.subTest(stage=stage):
                code, inspected, base, keys, output = self.run_batch(stage, failure)
                self.assertEqual(code, 2)  # device failure is INCOMPLETE, never SUCCESS
                self.assertEqual(inspected, ["example-ib001", "example-ib002", "example-ib003"])
                self.assertIn("example-ib003", base)
                self.assertIn("example-ib003", keys)
                if stage != "keys":
                    self.assertNotIn("example-ib002", keys)
                self.assertIn("configured=2", output)
                self.assertIn("failed=1", output)
                self.assertIn("not-attempted=0", output)

    # v15 BatchDeviceIsolationTests.test_changed_global_still_blocks_remaining_device_writes
    # (test_desktop_initial_setup.py:2274); CURRENT-CONTRACT.md:60 (shared-input errors stop the
    # common flow).
    def test_changed_global_still_blocks_remaining_device_writes(self):
        code, inspected, base, keys, output = self.run_batch("global")
        self.assertEqual(code, 1)
        self.assertEqual(inspected, ["example-ib001", "example-ib002"])
        self.assertNotIn("example-ib002", base)
        self.assertEqual(keys, ["example-ib001"])
        self.assertIn("not-attempted=1", output)
        self.assertIn("BATCH STOP", output)

    # -- v3.1.3 WP-11: R-011 TEST-tracker acceptance gap (guide :1124, :1126) ----------------------
    # I21 (TEST tracker 参考/TEST问题跟踪/user-test-issue-tracker.md:3714 "重复任务拒绝"): the same IB
    # (host names compared case-insensitively) queued twice is refused before any task starts.
    # v15 run_prepared_tasks :4398-4400 (参考/initial-setup-v15/initial-setup-20261019-v15_oob-spine.py).
    def test_r011_i21_duplicate_ib_task_is_refused_before_any_task_starts(self):
        tasks = lifecycle_tasks(2)
        first = tasks[0]
        tasks.append(app.PreparedIBTask(
            app.Target(replace(first.target.ib, hostname="EXAMPLE-IB001"), first.target.ethernet,
                       "swp2", "eth0"), first.neighbor, "", False))
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(app, "execute_ib_task",
                             side_effect=AssertionError("no task may start")) as execute, \
                patch.object(app, "log", lambda message="": None):
            args = SimpleNamespace(max_workers=16, task_timeout=20, report=Path(directory) / "report.log",
                                   apply=False, yes=False)
            with self.assertRaisesRegex(app.SetupError, "duplicate IB tasks"):
                app.run_prepared_tasks(tasks, args, None, FACTORY, None, [], None)
        execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
