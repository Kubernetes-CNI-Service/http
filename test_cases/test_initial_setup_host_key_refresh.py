"""WP4 entry loading only; WP5 adds jump mutation and selector contracts here."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from test_cases.module_loader import load_script
from test_cases import test_initial_setup_ipv4_readiness as readiness
from test_cases import test_login_path as hostkeys

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"


class HostKeyRefreshEntryTests(unittest.TestCase):
    def test_login_path_loaded_every_run_before_inputs_or_devices(self):
        # r508 :737: check, plan, P1 and apply all load at entry; no late worker surprise.
        app = load_script("wp4_required_login_path", INITIAL)
        for options in ((), ("--plan",), ("--generate-json",), ("--apply", "--yes")):
            with self.subTest(options=options), ExitStack() as stack:
                calls = []
                def require(name):
                    calls.append(name)
                    raise app.SetupError("tools.login_path is missing: PUBLIC required entry")
                stack.enter_context(mock.patch.object(app, "_import_tools", side_effect=require))
                stack.enter_context(mock.patch.object(sys, "argv", [str(INITIAL), *options]))
                stack.enter_context(mock.patch.object(app, "REPORT_HANDLE", None))
                read = stack.enter_context(mock.patch.object(app, "discover_input_file",
                                                            side_effect=app.SetupError("PUBLIC late input")))
                err = stack.enter_context(redirect_stderr(io.StringIO()))
                stack.enter_context(redirect_stdout(io.StringIO()))
                self.assertEqual(2, app._standalone_main_with_report_cleanup())
                self.assertEqual(["tools.login_path"], calls)
                read.assert_not_called()
                self.assertIn("tools.login_path is missing", err.getvalue())

    def test_leaf_missing_each_required_file_names_it_before_device_contact(self):
        # r508 :738: all three real Leaf files, not a dummy loader success.
        modules = ("login_path", "hostname_ranges", "device_identity")
        for missing in modules:
            with self.subTest(missing=missing), tempfile.TemporaryDirectory(prefix="wp4-leaf-") as directory, ExitStack() as stack:
                leaf = Path(directory).resolve()
                script = leaf / "initial-setup.py"
                shutil.copyfile(INITIAL, script)
                (leaf / "tools").mkdir()
                for name in modules:
                    if name != missing:
                        shutil.copyfile(ROOT / "tools" / (name + ".py"), leaf / "tools" / (name + ".py"))
                # Package objects from the repository must not impersonate this fresh Leaf.
                stack.enter_context(mock.patch.dict(sys.modules))
                for name in list(sys.modules):
                    if name == "tools" or name.startswith("tools."):
                        del sys.modules[name]
                stack.enter_context(mock.patch.object(sys, "path", [str(leaf), *sys.path]))
                app = load_script("wp4_missing_leaf_" + missing, script)
                stack.enter_context(mock.patch.object(sys, "argv", [str(script), "--plan"]))
                stack.enter_context(mock.patch.object(app, "REPORT_HANDLE", None))
                read = stack.enter_context(mock.patch.object(app, "discover_input_file",
                                                            side_effect=app.SetupError("PUBLIC late input")))
                err = stack.enter_context(redirect_stderr(io.StringIO()))
                stack.enter_context(redirect_stdout(io.StringIO()))
                self.assertEqual(2, app._standalone_main_with_report_cleanup())
                self.assertIn(str(leaf / "tools" / (missing + ".py")), err.getvalue())
                read.assert_not_called()


class HostKeyRefreshTests(unittest.TestCase):
    """r508 WP5 independent contracts; no actual SSH/native/private inputs."""
    @classmethod
    def setUpClass(cls):
        cls.app = load_script("wp5_host_key_refresh", INITIAL)

    def task(self, **changes):
        app = self.app
        target = readiness.target(app)
        target = replace(target, **{k: v for k, v in changes.items() if k in ("ib", "ethernet")})
        return app.PreparedIBTask(target, app.Neighbor("fe80::10", "vlan1000", target.ib.eth0_mac),
                                  readiness.credential("outer"), changes.get("local", False))

    def change(self, **changes):
        from tools import login_path
        value = login_path.parse_host_key_change(hostkeys.warning(), location="jump", jump="EXAMPLE-JUMP01")
        return replace(value, **changes)

    def api(self, name):
        value = getattr(self.app, name, None)
        self.assertTrue(callable(value), "r508 WP5 requires " + name)
        return value

    @staticmethod
    def lookup():
        return ("# Host 192.0.2.10 found: line 7\n256 ED25519 " + hostkeys.FINGERPRINT + "\n"
                "# Host 192.0.2.10 found: line 9\n2048 RSA " + hostkeys.FINGERPRINT + "\n")

    def test_jump_readonly_table_accepts_keygen_lookup_only(self):
        # r508 WP5 item1/K8: exact fixed path, legal original address, no -R route.
        command = ["ssh-keygen", "-l", "-F", "192.0.2.10", "-f", hostkeys.KNOWN_HOSTS]
        try:
            result = self.app.ethernet_command_argv(command)
        except self.app.SetupError:
            self.fail("approved readonly keygen lookup is missing")
        self.assertEqual(command, result)
        for address in ("fe80::10%vlan1000", "192.0.2.10"):
            self.assertEqual(address, self.app.ethernet_command_argv(command[:3] + [address] + command[4:])[3])
        bad = (["ssh-keygen", "-f", hostkeys.KNOWN_HOSTS, "-R", "192.0.2.10"],
               command + ["extra"], command[:5] + ["/etc/ssh/ssh_known_hosts"],
               command[:3] + ["example-ib01"] + command[4:],
               command[:3] + ["fe80::10"] + command[4:])
        for argv in bad:
            with self.subTest(argv=argv), self.assertRaises(self.app.SetupError):
                self.app.ethernet_command_argv(argv)
        self.assertEqual(["ifquery", "vlan1000"], self.app.ethernet_command_argv(["ifquery", "vlan1000"]))
        self.assertEqual(["ip", "-j", "address", "show"], self.app.ethernet_command_argv(["ip", "-j", "address", "show"]))

    def test_ib_reader_allowlist_is_exactly_three_public_files(self):
        # r508 WP5 item4: no generic cat or secret/extra path.
        for kind in ("rsa", "ecdsa", "ed25519"):
            command = ["cat", "/etc/ssh/ssh_host_" + kind + "_key.pub"]
            try:
                actual = self.app.ib_command_argv(command)
            except self.app.SetupError:
                self.fail("approved fixed IB public-key read is missing: " + kind)
            self.assertEqual(command, actual)
        for argv in (["cat", "/etc/ssh/ssh_host_rsa_key"], ["cat", "/etc/passwd"],
                     ["cat", "/etc/ssh/ssh_host_dsa_key.pub"],
                     ["cat", "/etc/ssh/ssh_host_rsa_key.pub", "/etc/ssh/ssh_host_ecdsa_key.pub"]):
            with self.subTest(argv=argv), self.assertRaises(self.app.SetupError):
                self.app.ib_command_argv(argv)

    def test_closed_delete_uses_fixed_argv_original_address_and_honest_receipt(self):
        remove = self.api("remove_jump_known_hosts_entries")
        app = self.app
        output = "# Host 192.0.2.10 found: line 7\n# Host 192.0.2.10 found: line 9\nOriginal contents retained as " + hostkeys.KNOWN_HOSTS + ".old\n"
        with mock.patch.object(app, "_jump_control_path_for", return_value="PUBLIC-control"), \
                mock.patch.object(app, "run_on_ethernet", return_value=self.lookup()) as lookup, \
                mock.patch.object(app, "outer_ssh_command", return_value=["PUBLIC-outer"]) as outer, \
                mock.patch.object(app, "interactive_run", return_value=app.SessionResult(output, 0)) as run, \
                mock.patch.object(app, "ethernet_command_argv", side_effect=AssertionError("write cannot use readonly table")):
            receipt = remove(self.task(), self.change(), eth_user="cumulus", apply=True, timeout=2)
        self.assertEqual(["ssh-keygen", "-f", hostkeys.KNOWN_HOSTS, "-R", "192.0.2.10"], outer.call_args.args[2])
        self.assertEqual("PUBLIC-control", outer.call_args.kwargs["control_path"])
        self.assertTrue(outer.call_args.kwargs["tty"])
        self.assertEqual(["PUBLIC-outer"], run.call_args.args[0])
        self.assertTrue(receipt.old_file)
        self.assertEqual(["ssh-keygen", "-l", "-F", "192.0.2.10", "-f", hostkeys.KNOWN_HOSTS], lookup.call_args.args[3])
        self.assertEqual((7, 9), receipt.lines)
        self.assertEqual((None,) * 4, (receipt.inode_before, receipt.inode_after, receipt.mode_before, receipt.mode_after))

    def test_delete_gate_checks_ib_type_jump_path_account_address_apply(self):
        remove = self.api("remove_jump_known_hosts_entries")
        normal = self.task()
        variants = ((self.task(ib=replace(normal.target.ib, dev_type="eth")), self.change(), "cumulus", True),
                    (normal, self.change(known_hosts_path="/etc/ssh/ssh_known_hosts"), "cumulus", True),
                    (normal, self.change(), "other", True), (normal, self.change(), "cumulus", False),
                    (normal, self.change(address="192.0.2.99"), "cumulus", True),
                    (normal, self.change(jump="EXAMPLE-OTHER"), "cumulus", True),
                    (normal, self.change(address="fe80::10%wrong"), "cumulus", True),
                    (normal, self.change(address="fe80::10"), "cumulus", True))
        with mock.patch.object(self.app, "interactive_run", side_effect=AssertionError("gate allowed a write")) as run, \
                mock.patch.object(self.app, "run_on_ethernet", side_effect=AssertionError("gate allowed a read")):
            for task, change, user, apply in variants:
                with self.subTest(address=change.address, user=user, apply=apply), self.assertRaises(self.app.SetupError):
                    remove(task, change, eth_user=user, apply=apply, timeout=2)
            run.assert_not_called()

    def test_delete_nonzero_does_not_claim_success_or_retry(self):
        remove = self.api("remove_jump_known_hosts_entries")
        with mock.patch.object(self.app, "_jump_control_path_for", return_value=None), \
                mock.patch.object(self.app, "run_on_ethernet", return_value=self.lookup()), \
                mock.patch.object(self.app, "interactive_run", return_value=self.app.SessionResult("PUBLIC refused", 1)) as run:
            with self.assertRaises(self.app.SetupError):
                remove(self.task(), self.change(), eth_user="cumulus", apply=True, timeout=2)
        run.assert_called_once()

    def test_stale_lines_and_bad_warning_facts_fail_before_writer(self):
        remove = self.api("remove_jump_known_hosts_entries")
        for change in (self.change(lines=(8,)), self.change(lines=()),
                       self.change(new_fingerprint="missing")):
            with self.subTest(lines=change.lines), \
                    mock.patch.object(self.app, "run_on_ethernet", return_value=self.lookup()), \
                    mock.patch.object(self.app, "interactive_run", side_effect=AssertionError("stale fact reached writer")) as run:
                with self.assertRaises(self.app.SetupError):
                    remove(self.task(), change, eth_user="cumulus", apply=True, timeout=2)
                run.assert_not_called()

    def test_all_transit_types_and_scoped_original_address_are_bound(self):
        remove = self.api("remove_jump_known_hosts_entries")
        normal = self.task()
        change = self.change(address="FE80::10%vlan1000")
        for kind in ("eth", "eth_spx", "spx", "ethernet", "eth_jump"):
            task = self.task(ethernet=replace(normal.target.ethernet, dev_type=kind))
            with self.subTest(kind=kind), mock.patch.object(self.app, "run_on_ethernet", return_value=self.lookup()), \
                    mock.patch.object(self.app, "_jump_control_path_for", return_value=None), \
                    mock.patch.object(self.app, "outer_ssh_command", return_value=["PUBLIC-outer"]) as outer, \
                    mock.patch.object(self.app, "interactive_run", return_value=self.app.SessionResult("", 0)):
                receipt = remove(task, change, eth_user="cumulus", apply=True, timeout=2)
                self.assertEqual("FE80::10%vlan1000", outer.call_args.args[2][-1])
                self.assertFalse(receipt.old_file, "no backup output means no invented .old fact")

    def test_host_key_ipc_keeps_existing_outer_failure_category(self):
        self.api("remove_jump_known_hosts_entries")
        app, task = self.app, self.task()
        parent = app.RuntimeCoordinator(SimpleNamespace(apply=True, yes=True, eth_user="cumulus", connect_timeout=2),
            None, readiness.credential("initial"), [task], SimpleNamespace(assert_unchanged=lambda: None))
        failure = app.SshFailure(app.SshFailureKind.JUMP_UNREACHABLE, "outer", "198.51.100.10", "EXAMPLE-JUMP01")
        with mock.patch.object(app, "remove_jump_known_hosts_entries", side_effect=failure), \
                mock.patch.object(app, "interactive_run", side_effect=AssertionError("unexpected real transport")):
            reply = parent.request("host-key-remove", self.change(), task.target)
        connection = SimpleNamespace(send=mock.Mock(), recv=lambda: ("ok", reply))
        with mock.patch.object(app, "_WORKER_CONNECTION", connection):
            with self.assertRaises(app.SshFailure) as caught:
                app.worker_request("host-key-remove", self.change())
        self.assertEqual(("OOB_JUMP_UNREACHABLE", "outer", "198.51.100.10", "EXAMPLE-JUMP01"),
            (caught.exception.failure_kind, caught.exception.hop, caught.exception.address, caught.exception.jump))

    def test_parent_first_change_refusal_blocks_actual_closed_writer(self):
        app, task = self.app, self.task()
        parent = app.RuntimeCoordinator(SimpleNamespace(apply=True, yes=False, eth_user="cumulus", connect_timeout=2),
            None, readiness.credential("initial"), [task], SimpleNamespace(assert_unchanged=lambda: None))
        with mock.patch.object(app, "_ask_first_device_change", return_value=False) as authorize, \
                mock.patch.object(app, "run_on_ethernet", return_value=self.lookup()), \
                mock.patch.object(app, "_jump_control_path_for", return_value=None), \
                mock.patch.object(app, "interactive_run", return_value=app.SessionResult("", 0)) as run:
            with self.assertRaises(app.BatchStopped):
                parent.request("host-key-remove", self.change(), task.target)
            authorize.assert_called_once()
            run.assert_not_called()
            self.assertFalse(parent.writes_attempted)

    def test_parent_authorizes_immediately_before_actual_closed_writer(self):
        app, task = self.app, self.task()
        events = []
        parent = app.RuntimeCoordinator(SimpleNamespace(apply=True, yes=False, eth_user="cumulus", connect_timeout=2),
            None, readiness.credential("initial"), [task], SimpleNamespace(assert_unchanged=lambda: None))
        with mock.patch.object(app, "_ask_first_device_change", side_effect=lambda *_: events.append("authorize") or True), \
                mock.patch.object(app, "run_on_ethernet", side_effect=lambda *_args, **_kwargs: events.append("lookup") or self.lookup()), \
                mock.patch.object(app, "_jump_control_path_for", return_value=None), \
                mock.patch.object(app, "interactive_run", side_effect=lambda *_args, **_kwargs: events.append("write") or app.SessionResult("", 0)):
            parent.request("host-key-remove", self.change(), task.target)
        self.assertEqual(["lookup", "authorize", "write"], events)
        self.assertTrue(parent.writes_attempted)

    def test_parent_final_authority_control_errors_keep_original_identity(self):
        app, task = self.app, self.task()
        for error in (app.ProjectInputChanged("PUBLIC input changed"), app.BatchStopped("PUBLIC stopped")):
            authority = SimpleNamespace(assert_unchanged=mock.Mock(side_effect=[None, error]))
            parent = app.RuntimeCoordinator(SimpleNamespace(apply=True, yes=True, eth_user="cumulus", connect_timeout=2),
                None, readiness.credential("initial"), [task], authority)
            with self.subTest(kind=type(error).__name__), \
                    mock.patch.object(app, "run_on_ethernet", return_value=self.lookup()), \
                    mock.patch.object(app, "_jump_control_path_for", return_value=None), \
                    mock.patch.object(app, "interactive_run", side_effect=AssertionError("cancelled writer ran")) as run:
                with self.assertRaises(app.SetupError) as caught:
                    parent.request("host-key-remove", self.change(), task.target)
                self.assertIs(error, caught.exception, "control errors may not become generic host-key errors")
                self.assertFalse(parent.writes_attempted)
                run.assert_not_called()

    def test_host_key_worker_controls_use_original_status_protocol(self):
        app = self.app
        for status, expected in (("project-changed", app.ProjectInputChanged), ("stopped", app.BatchStopped)):
            connection = SimpleNamespace(send=mock.Mock(), recv=lambda: (status, "PUBLIC control"))
            with self.subTest(status=status), mock.patch.object(app, "_WORKER_CONNECTION", connection):
                with self.assertRaises(expected):
                    app.worker_request("host-key-remove", self.change())

    def test_readonly_two_classes_do_not_write_or_reprobe(self):
        refresh = self.api("refresh_ib_host_key")
        app, task = self.app, self.task()
        for fingerprint, expected in ((hostkeys.FINGERPRINT, "HOST_KEY_REFRESH_PENDING"),
                                      (None, "TARGET_HOST_KEY_CHANGED"),
                                      ("SHA256:" + "B" * 43, "TARGET_HOST_KEY_CHANGED")):
            records = []
            with self.subTest(expected=expected), mock.patch.object(app, "run_on_ethernet", return_value=self.lookup()), \
                    mock.patch.object(app, "interactive_run", side_effect=AssertionError("readonly attempted a write")), \
                    mock.patch.object(app.JumpKnownHostsEditor, "remove", side_effect=AssertionError("readonly removed")), \
                    mock.patch.object(app, "_ACTIVE_COORDINATOR", None):
                retry = mock.Mock(side_effect=AssertionError("readonly retry"))
                with self.assertRaises(app.SshFailure) as caught:
                    refresh(self.change(), task, eth_user="cumulus", timeout=2, apply=False,
                        read_device_fingerprint=lambda _: fingerprint, retry=retry,
                        operator_forced=True, host_key_records=records)
                self.assertEqual(expected, caught.exception.failure_kind)
                retry.assert_not_called()
                if expected == "HOST_KEY_REFRESH_PENDING":
                    self.assertEqual("refresh-pending", records[0].result)
                    self.assertIsNone(records[0].removal)
                else:
                    self.assertEqual([], records)

    def test_local_leaf_requires_actual_uid_user_not_environment_name(self):
        refresh = self.api("refresh_ib_host_key")
        task = self.task(local=True)
        change = self.change(location="local", jump=None, known_hosts_path="/PUBLIC/.ssh/known_hosts")
        with mock.patch.object(self.app.pwd, "getpwuid", return_value=SimpleNamespace(pw_name="other")), \
                mock.patch.dict(os.environ, {"USER": "cumulus", "LOGNAME": "cumulus"}), \
                mock.patch.object(self.app, "interactive_run", side_effect=AssertionError("wrong local user wrote")):
            with self.assertRaises(self.app.SshFailure):
                refresh(change, task, eth_user="cumulus", timeout=2, apply=True,
                    read_device_fingerprint=None, retry=lambda: None, operator_forced=True, host_key_records=[])

    def test_selector_uses_all_csv_ib_and_never_all_keyword(self):
        resolve = self.api("resolve_host_key_refresh_selector")
        task = self.task()
        devices = {"example-ib01": task.target.ib,
                   "example-ib02": replace(task.target.ib, hostname="EXAMPLE-IB02", login_ip="192.0.2.20")}
        devices["example-jump01"] = task.target.ethernet
        self.assertEqual(frozenset(("example-ib01", "example-ib02")), resolve("example-ib[01-02]", devices))
        self.assertEqual(frozenset(), resolve(None, devices))
        for value in ("all", "EXAMPLE-JUMP01", "example-ib03", "example-ib01,,example-ib02"):
            with self.subTest(value=value), self.assertRaises(self.app.SetupError):
                resolve(value, devices)

    def test_parser_keeps_unscoped_linklocal_refused(self):
        self.assertIsNone(hostkeys.parser_module(self).parse_host_key_change(hostkeys.warning("fe80::10")))

    def test_local_leaf_linklocal_change_keeps_real_scoped_fact_and_raw_refusal_safe(self):
        app, task = self.app, self.task(local=True)
        for address in ("fe80::10%vlan1000", "fe80::10"):
            with self.subTest(address=address), \
                    mock.patch.object(app, "interactive_run", return_value=app.SessionResult(hostkeys.warning(address), 255)) as run:
                with self.assertRaises(app.SetupError) as caught:
                    app.run_on_ib(task.target, task.neighbor, "cumulus", readiness.credential("outer"),
                        "admin", readiness.credential("current"), 2, ["nv", "config", "show", "-o", "commands"],
                        local=True, password_only=True)
                self.assertEqual("TARGET_HOST_KEY_CHANGED", caught.exception.failure_kind)
                self.assertNotIn("@@@@", str(caught.exception))
                change = getattr(caught.exception, "host_key_change", None)
                if "%" in address:
                    self.assertEqual((address, "local", None), (change.address, change.location, change.jump))
                else:
                    self.assertIsNone(change)
                run.assert_called_once()

    def test_authenticated_reader_uses_current_role_and_unique_fingerprint(self):
        reader_factory = self.api("ib_host_key_reader")
        app = self.app
        from tools import login_path
        # Valid public ed25519 blob; fingerprint expectation is independent fixed bytes.
        import base64, hashlib
        blob = (11).to_bytes(4, "big") + b"ssh-ed25519" + (32).to_bytes(4, "big") + bytes(range(32))
        line = "ssh-ed25519 " + base64.b64encode(blob).decode()
        expected = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        policy = SimpleNamespace(assert_unchanged=mock.Mock())
        with mock.patch.object(app, "run_on_ib", return_value=app.SessionResult(line + "\n", 0)) as run:
            reader = reader_factory(self.task(), "cumulus", "admin", readiness.credential("current"), 2, policy=policy)
            self.assertEqual(expected, reader("ED25519"))
            args, kw = run.call_args
            self.assertEqual(readiness.credential("current"), args[5])
            self.assertEqual(["cat", "/etc/ssh/ssh_host_ed25519_key.pub"], args[7])
            self.assertTrue(kw["password_only"])
            self.assertNotIn("_phase_operation", kw)
        policy.assert_unchanged.assert_called()

    def test_readonly_pending_mapping_has_no_vrf_advice(self):
        self.assertEqual("CHECKED_HOST_KEY_REFRESH_PENDING",
                         self.app.record_category({"outcome": "CHECK_ONLY", "failure_kind": "HOST_KEY_REFRESH_PENDING"}))
        self.assertNotIn("VRF", self.app.attention_guidance("FAILED_TARGET_HOST_KEY_CHANGED"))
        self.assertIn("--apply", self.app.attention_guidance("CHECKED_HOST_KEY_REFRESH_PENDING"))

    def test_coordinator_binds_task_and_freshly_reads_before_each_delete(self):
        self.api("remove_jump_known_hosts_entries")
        app, task = self.app, self.task()
        args = SimpleNamespace(apply=True, yes=True, eth_user="cumulus", connect_timeout=2)
        authority = SimpleNamespace(assert_unchanged=mock.Mock())
        parent = app.RuntimeCoordinator(args, None, readiness.credential("initial"), [task], authority)
        def closed_write(*args, **kwargs):
            kwargs["before_write"]()
            return "PUBLIC-receipt"
        with mock.patch.object(app, "remove_jump_known_hosts_entries", side_effect=closed_write) as remove, \
                mock.patch.object(app, "run_on_ethernet", side_effect=AssertionError("unexpected real read")), \
                mock.patch.object(app, "interactive_run", side_effect=AssertionError("unexpected real transport")):
            reply = parent.request("host-key-remove", self.change(), task.target)
            self.assertEqual("PUBLIC-receipt", reply)
            self.assertIs(task, remove.call_args.args[0])
            authority.assert_unchanged.assert_called()
            self.assertTrue(parent.writes_attempted)
            with self.assertRaises(app.SetupError):
                parent.request("host-key-remove", self.change(), replace(task.target, ib=replace(task.target.ib, hostname="EXAMPLE-OTHER")))
            with self.assertRaises(app.SetupError):
                parent.request("host-key-remove", self.change(), replace(task.target, ib=replace(task.target.ib, login_ip="192.0.2.99")))
            remove.assert_called_once()


if __name__ == "__main__":
    unittest.main()
