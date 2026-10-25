"""Managed initial-setup contract after the TEST->DEV merge (2026-10-25).

Expected values come from the agreed merge contract, not from the implementation:
  * I18: with a present project global, the new IB password must match the global's
    target hash; a managed run whose global has no target hash fails closed and
    writes nothing to the device.
  * Q1/Q2: a managed run whose own-session completion proof fails is not
    summarized as COMPLETED and keeps DEV's exit contract (1 for a failed target).
  * Q3: managed method authority and --auto are refused together at entry, before
    the auto watch can be armed or any output exists.
  * D-2/H22: only the exact argv ["--_verify-password"] reaches the private password
    worker; it never enters the runtime guard or the operational entry.
The strict-path cases use the REQ10B PUBLIC device adapter and the reviewed
external KAT (FIXTURE HOLD when absent), as TEST d876330 does.
"""
from __future__ import annotations

import ast
from contextlib import ExitStack
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.module_loader import load_script
from test_cases import test_req10b_services_keys_workflow as req10b

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
AUTHORITY = ROOT / "ztp/config_sync_authority.py"
MANAGED_CSV = (
    "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,config_method\n"
    "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,,initial-setup\n"
    "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,,\n"
)
CONFIGURED_STATE = (
    "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
    "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
    "nv set system hostname EXAMPLE-IB01\n"
    "nv set system dns server 203.0.113.53\n"
    "nv set system ntp server ntp.ubuntu.com\n"
    "nv set system ntp server time.ib.example.test\n"
    "nv set system date-time timezone Asia/Taipei\n"
)
READ_ONLY = (req10b.STRICT_READ, req10b.STRICT_DIFF)


class ManagedInitialMergeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.initial = load_script("managed_merge_contract_initial", INITIAL)
        cls.authority = load_script("managed_merge_contract_authority", AUTHORITY)

    def helper(self):
        helper = req10b.Req10BServicesKeysWorkflowTests()
        helper.initial = self.initial
        return helper

    def managed_project(self, directory: str, *, strict: bool):
        helper = self.helper()
        values = helper.strict_fixture(directory) if strict else helper.fixture(directory)
        root, tool, global_path, ib_csv, p2p, _, cache, _, _ = values
        root = root.resolve()
        ib_csv = ib_csv.resolve()
        ib_csv.write_text(MANAGED_CSV, encoding="utf-8")
        private = root / ".ssh/id_ed25519"
        private.parent.mkdir(mode=0o700)
        private.write_text("fixture identity; never a real key")
        private.chmod(0o600)
        return helper, root, tool.resolve(), global_path, ib_csv, p2p.resolve(), cache.parent.resolve() / cache.name

    def device_io(self, stack, calls, *, observe=None):
        neighbor = self.initial.Neighbor("fe80::1", "swp7", "02:00:00:00:00:01")
        stack.enter_context(mock.patch.dict(os.environ, {"NVOS_INITIAL_PASSWORD": "fixture"}))
        for name, value in (("local_ethernet_keys", set()),
                            ("prompt_ethernet_passwords", {"example-jump01": "fixture"}),
                            ("collect_ethernet_interfaces", ("EXAMPLE-JUMP01", "table")),
                            ("collect_ethernet_network_tables", ("links", "fdb", "neighbors")),
                            ("save_ethernet_snapshot", Path("/nonexistent/snapshot")),
                            ("interface_status_line", "swp7 up"), ("interface_oper_status", "up"),
                            ("fdb_port_for_interface", "swp7"), ("neighbor_for_port", neighbor),
                            ("interface_vrf", "default")):
            stack.enter_context(mock.patch.object(self.initial, name, return_value=value))

        def device(*args, **kwargs):
            command = tuple(args[7])
            calls.append((command, kwargs.get("_phase_operation")))
            if (len(command) == 5 and command[:2] == ("sh", "-c")
                    and command[2] == self.initial._KEY_INSTALL_SCRIPT and command[3] == "--"):
                return self.initial.SessionResult("IBSW_PUBLIC_KEYS_UPDATED\n", 0)
            if command == req10b.STRICT_DIFF:
                return self.initial.SessionResult("", 0)
            return self.initial.SessionResult(CONFIGURED_STATE, 0)

        stack.enter_context(mock.patch.object(self.initial, "run_on_ib", side_effect=device))
        stack.enter_context(mock.patch.object(self.initial, "verify_management_key_possession"))
        if observe is not None:
            stack.enter_context(mock.patch.object(
                self.initial, "observe_managed_initial_configuration", side_effect=observe))

    def test_i18_managed_global_without_target_hash_fails_closed_without_device_writes(self):
        with tempfile.TemporaryDirectory(prefix="managed-i18-") as directory:
            helper, root, tool, _, ib_csv, p2p, cache = self.managed_project(directory, strict=False)
            cycle = self.authority.ManagedInitialMethodCycle(root, self.initial)
            calls, phases = [], []

            def phase(*args, **kwargs):
                phases.append(kwargs.get("_phase_operation"))
                raise AssertionError("no IB phase may run without the project's target hash")

            with ExitStack() as stack:
                self.device_io(stack, calls)
                stack.enter_context(mock.patch.object(self.initial, "_execute_ib_phase", side_effect=phase))
                stack.enter_context(mock.patch.object(
                    self.initial, "interactive_run", side_effect=AssertionError("no device transport")))
                try:
                    result = helper.run_initial(tool, ib_csv, p2p, cache, "--apply", "--yes",
                                                "--execution-mode", "management", method_cycle=cycle)
                except self.initial.SetupError:
                    result = "SetupError"
                finally:
                    cycle.close()
            self.assertNotEqual(0, result, "a global without the target hash must fail closed")
            self.assertEqual([], [entry for entry in calls if entry[0] not in READ_ONLY or entry[1] is not None],
                             "no device write and no password phase may happen")
            self.assertEqual([], [operation for operation in phases if operation != "auth-probe-readonly"])
            storage = root / "99-output-ztp/configuration-methods"
            self.assertIsNone(self.authority.read_method_receipt(storage, "EXAMPLE-IB01"))
            current = self.authority.read_method_current(storage, "EXAMPLE-IB01")
            self.assertTrue(current is None or current["state"] != "success")

    def test_q2_failed_completion_is_not_completed_and_keeps_dev_exit_code(self):
        with tempfile.TemporaryDirectory(prefix="managed-q2-") as directory:
            helper, root, tool, global_path, ib_csv, p2p, cache = self.managed_project(directory, strict=True)
            cycle = self.authority.ManagedInitialMethodCycle(root, self.initial)
            calls, observed = [], []

            def unverified(target, user, key, timeout, services, keys):
                observed.append(target.ib.hostname)
                return {"schema_version": 1, "hostname": target.ib.hostname, "batch_identity_verified": True,
                        "config_verified": False, "interface": "eth0", "transport_ip": "", "mac_plain": "",
                        "live_state_sha256": "", "input_sha256": "", "observation_sha256": "",
                        "reason": "initial-current-configuration-not-verified"}

            with ExitStack() as stack:
                self.device_io(stack, calls, observe=unverified)
                witness = stack.enter_context(req10b.strict_management_boundary(
                    self, self.initial, kat=req10b.strict_kat(self.initial)))
                try:
                    result = helper.run_initial(tool, ib_csv, p2p, cache, "--apply", "--yes",
                                                "--execution-mode", "management", method_cycle=cycle)
                finally:
                    cycle.close()
            req10b.assert_strict_management_path(self, witness, global_path=global_path,
                                                 devices=("EXAMPLE-IB01",))
            self.assertEqual(["EXAMPLE-IB01"], observed, "completion proof must be requested once")
            self.assertEqual(1, result, "DEV contract: a failed managed target exits 1")
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("managed current initial-setup configuration was not verified", report)
            self.assertIn("COMPLETED=0", report)
            self.assertNotIn("EXAMPLE-IB01 via EXAMPLE-JUMP01: COMPLETED", report)
            storage = root / "99-output-ztp/configuration-methods"
            self.assertIsNone(self.authority.read_method_receipt(storage, "EXAMPLE-IB01"))
            self.assertEqual("failed", self.authority.read_method_current(storage, "EXAMPLE-IB01")["state"])

    def test_q3_managed_authority_with_auto_is_refused_before_watch_or_output(self):
        with tempfile.TemporaryDirectory(prefix="managed-q3-") as directory:
            helper, root, tool, _, ib_csv, p2p, cache = self.managed_project(directory, strict=False)
            cycle = self.authority.ManagedInitialMethodCycle(root, self.initial)
            before = sorted(str(path.relative_to(root)) for path in root.rglob("*"))
            calls = []
            touched = {name: mock.MagicMock(side_effect=AssertionError(name)) for name in (
                "_pause_auto_watch", "_install_auto_watch", "read_auto_credentials",
                "_write_auto_credentials", "resolve_initial_ib_password")}
            with ExitStack() as stack:
                self.device_io(stack, calls)
                for name, recorder in touched.items():
                    stack.enter_context(mock.patch.object(self.initial, name, recorder))
                admit = stack.enter_context(mock.patch.object(cycle, "admit_paths", wraps=cycle.admit_paths))
                with self.assertRaises(self.initial.SetupError) as caught:
                    # A credentials file keeps the ordinary --auto path past its tty gate, so
                    # only an entry refusal can stop it before credentials or watch work.
                    helper.run_initial(tool, ib_csv, p2p, cache, "--auto", "--execution-mode", "management",
                                       "--credentials-file", str(root / "never-read-auto.env"),
                                       method_cycle=cycle)
                cycle.close()
            self.assertIn("--auto", str(caught.exception))
            self.assertIn("managed", str(caught.exception))
            self.assertEqual({name: 0 for name in touched}, {name: m.call_count for name, m in touched.items()})
            self.assertEqual(0, admit.call_count, "refusal precedes admission and every output")
            self.assertEqual([], calls)
            self.assertEqual(before, sorted(str(path.relative_to(root)) for path in root.rglob("*")))

    def main_block(self):
        tree = ast.parse(INITIAL.read_text(encoding="utf-8"))
        blocks = [node for node in tree.body if isinstance(node, ast.If)
                  and isinstance(node.test, ast.Compare) and isinstance(node.test.left, ast.Name)
                  and node.test.left.id == "__name__"]
        self.assertEqual(1, len(blocks))
        return blocks[0]

    def test_h22_only_exact_verify_argv_reaches_worker_without_guard(self):
        block = self.main_block()
        code = compile(ast.Module(body=block.body, type_ignores=[]), str(INITIAL), "exec")
        cases = {
            ("--_verify-password",): ["worker"],
            (): ["guarded"],
            ("--_verify-password", "--apply"): ["guarded"],
            ("--apply", "--_verify-password"): ["guarded"],
            ("--_verify-password", ""): ["guarded"],
            ("--_verify-password", "--_verify-password"): ["guarded"],
            ("--_verify-password=",): ["guarded"],
        }
        for argv, expected in cases.items():
            with self.subTest(argv=argv):
                calls = []
                namespace = {
                    "sys": SimpleNamespace(argv=[str(INITIAL), *argv]),
                    "_password_hash_worker": lambda: calls.append("worker") or 0,
                    "_guarded_main": lambda: calls.append("guarded") or 0,
                    "_runtime_instance_guard": lambda: calls.append("guard"),
                    "main": lambda **kwargs: calls.append("main"),
                }
                with self.assertRaises(SystemExit):
                    exec(code, namespace)
                self.assertEqual(expected, calls)
        # The worker branch names nothing but the worker: no guard, entry, input or report.
        worker_branch = block.body[0]
        names = {node.id for node in ast.walk(worker_branch) if isinstance(node, ast.Name)}
        self.assertEqual({"sys", "SystemExit", "_password_hash_worker"}, names)

    def test_h22_real_worker_dispatch_and_extra_argument_refusal(self):
        with tempfile.TemporaryDirectory(prefix="managed-verify-argv-") as directory:
            work = Path(directory)
            env = {"PATH": os.defpath, "LC_ALL": "C", "LANG": "C"}
            worker = subprocess.run([sys.executable, "-I", "-S", "-B", str(INITIAL), "--_verify-password"],
                                    input=b"", capture_output=True, timeout=60, cwd=work, env=env, check=False)
            self.assertEqual((2, b'{"status":"error"}\n', b""), (worker.returncode, worker.stdout, worker.stderr),
                             "exact argv runs only the private worker protocol")
            refused = subprocess.run([sys.executable, "-I", "-S", "-B", str(INITIAL), "--_verify-password", "--apply"],
                                     input=b"", capture_output=True, timeout=60, cwd=work, env=env, check=False)
            self.assertEqual(2, refused.returncode)
            self.assertNotIn(b'"status"', refused.stdout)
            self.assertIn(b"usage:", refused.stderr)
            self.assertEqual([], list(work.iterdir()), "neither path may create reports or inputs")


if __name__ == "__main__":
    unittest.main()
