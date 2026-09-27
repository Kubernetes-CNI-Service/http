#!/usr/bin/env python3
"""Direct contracts for ``eth_jump`` admission and closed jump transport."""

from __future__ import annotations

import ast
import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path
import re
import shlex
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
INITIAL_SETUP = (
    ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    old = sys.modules.get(name)
    sys.path.insert(0, str(path.parent))
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
        if old is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = old
    return module


class EthJumpTransportContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module("eth_jump_transport_contract", INITIAL_SETUP)

    def ethernet(self):
        return self.module.Device(
            "EXAMPLE-JUMP01", "eth_jump", "192.0.2.10", "192.0.2.10",
            "", "", "", "",
        )

    def test_eth_jump_is_admitted_as_transit_and_resolves_p2p(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            devices_path = root / "devices.csv"
            devices_path.write_text(
                "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,"
                "eth1_ip,netmask,eth1_gw\n"
                "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,,,,\n"
                "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,\n"
                "EXAMPLE-OOB01,eth,192.0.2.11,,,,,,\n",
                encoding="utf-8",
            )
            ib_devices, transit_devices = self.module.load_devices(devices_path)

            self.assertIn(
                "example-jump01", transit_devices,
                "type=eth_jump must be admitted as an initial-setup transit device",
            )
            self.assertNotIn(
                "example-jump01", ib_devices,
                "type=eth_jump is transit-only and must never become an IB target",
            )
            targets = self.module.build_targets(
                [self.module.Link("EXAMPLE-IB01", "eth0", "EXAMPLE-JUMP01", "7")],
                ib_devices,
                transit_devices,
            )
            self.assertEqual("EXAMPLE-JUMP01", targets[0].ethernet.hostname)

    def test_local_transport_executes_typed_argv_without_shell_carrier(self):
        command = ["nv", "config", "show"]
        argv = self.module.outer_ssh_command(
            self.ethernet(), "admin", command, 10, local=True,
        )
        self.assertEqual(
            command,
            argv,
            "local jump transport must execute the typed argv directly, never sh -c",
        )
        self.assertNotEqual(["sh", "-c"], argv[:2])

    def test_typed_argv_independently_enforces_the_complete_shape_contract(self):
        original = ["custom-command", "argument with spaces"]
        copied = self.module.typed_argv(original, label="test command")
        self.assertEqual(original, copied)
        self.assertIsNot(
            original, copied,
            "typed_argv must return a defensive list copy",
        )

        invalid = (
            [],
            (),
            ("custom-command",),
            "custom-command",
            b"custom-command",
            {"custom-command": True},
            ["custom-command", ""],
            ["custom-command", 1],
            ["custom-command", True],
            ["custom-command", b"argument"],
            ["custom-command", "nul\x00carrier"],
            ["custom-command", "lf\ncarrier"],
            ["custom-command", "cr\rcarrier"],
            ["custom-command", "tab\tcarrier"],
            ["custom-command", "escape\x1bcarrier"],
            ["custom-command", "delete\x7fcarrier"],
            ["custom-command", "c1-next-line\x85carrier"],
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(
                self.module.SetupError,
            ):
                self.module.typed_argv(value, label="test command")

    def test_allowed_read_command_is_joined_once_at_remote_boundary(self):
        command = ["nv", "config", "show"]
        completed = self.module.SessionResult("snapshot", 0)
        with mock.patch.object(
            self.module, "interactive_run", return_value=completed,
        ) as runner:
            output = self.module.run_on_ethernet(
                self.ethernet(), "admin", "secret", command, 10,
            )

        self.assertEqual("snapshot", output)
        dispatched = runner.call_args.args[0]
        self.assertEqual(
            shlex.join(command),
            dispatched[-1],
            "typed argv must be shell-quoted exactly once at the remote SSH boundary",
        )

    def test_write_capable_nv_prefix_is_rejected_before_dispatch(self):
        command = ["nv", "config", "apply"]
        with mock.patch.object(self.module, "interactive_run") as runner:
            with self.assertRaises(
                self.module.SetupError,
                msg="closed jump transport must reject nv config writes",
            ):
                self.module.run_on_ethernet(
                    self.ethernet(), "admin", "secret", command, 10,
                )
        runner.assert_not_called()

    def test_scalar_injection_copy_and_wrong_identity_are_blocked_pre_dispatch(self):
        blocked = (
            "nv show interface; nv set system hostname owned",
            ["scp", "sw-info.sh", "admin@192.0.2.10:/tmp/sw-info.sh"],
            ["nv", "config", "show;", "nv", "config", "apply"],
        )
        with mock.patch.object(self.module, "interactive_run") as runner:
            for command in blocked:
                with self.subTest(command=command), self.assertRaises(
                    self.module.SetupError,
                ):
                    self.module.run_on_ethernet(
                        self.ethernet(), "admin", "secret", command, 10,
                    )

            wrong_identity = self.module.Device(
                "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
                "203.0.113.1", "", "", "",
            )
            with self.assertRaisesRegex(
                self.module.SetupError, "not a supported Ethernet transit device",
            ):
                self.module.run_on_ethernet(
                    wrong_identity, "admin", "secret", ["hostname"], 10,
                )
        runner.assert_not_called()

    def test_desired_nvos_vectors_are_closed_and_independently_enforced(self):
        device = self.module.Device(
            "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
            "203.0.113.1", "", "203.0.114.2/24", "203.0.114.1",
        )
        commands = self.module.desired_commands(device)
        self.assertTrue(commands)
        for command in commands:
            self.assertEqual(command, self.module.ib_command_argv(command))
        for blocked in (
            ["scp", "sw-info.sh", "/tmp/sw-info.sh"],
            ["sh", "-c", "nv config show"],
            ["nv", "config", "replace"],
            ["nv", "config", "show;", "nv", "config", "apply"],
        ):
            with self.subTest(blocked=blocked), self.assertRaises(
                self.module.SetupError,
            ):
                self.module.ib_command_argv(blocked)

    def test_public_key_shell_boundary_rejects_mutated_program_and_payload(self):
        installer = self.module._KEY_INSTALL_SCRIPT
        for blocked in (
            ["sh", "-c", installer + "; true", "--", "YWJj"],
            ["sh", "-c", installer, "--", "YWJj;true"],
            ["sh", "-c", installer, "--", "YWJj\ntrue"],
            ["sh", "-c", installer, "-c", "YWJj"],
        ):
            with self.subTest(blocked=blocked), self.assertRaises(
                self.module.SetupError,
            ):
                self.module.ib_command_argv(blocked)

    def test_ethernet_collectors_dispatch_typed_argv(self):
        observed: list[object] = []

        def collector_output(_ethernet, _user, _password, command, _timeout, **_kwargs):
            observed.append(command)
            if not isinstance(command, (list, tuple)):
                return (
                    "__XDR_HOSTNAME__\nEXAMPLE-JUMP01\n"
                    "__XDR_NV_INTERFACES__\ninterface-data\n"
                )
            return {
                ("hostname",): "EXAMPLE-JUMP01\n",
                ("nv", "show", "interface"): "interface-data\n",
                ("ip", "-d", "link", "show"): "link-data\n",
                ("bridge", "fdb", "show"): "fdb-data\n",
                ("ip", "neighbor"): "neighbor-data\n",
                ("ifquery", "vlan100"): "vrf blue\n",
            }[tuple(command)]

        with mock.patch.object(
            self.module, "run_on_ethernet", side_effect=collector_output,
        ):
            self.module.collect_ethernet_interfaces(
                self.ethernet(), "admin", "secret", 10,
            )
            self.module.collect_ethernet_network_tables(
                self.ethernet(), "admin", "secret", 10,
            )
            self.module.interface_vrf(
                self.ethernet(), "admin", "secret", "vlan100", 10,
            )
        self.assertTrue(observed)
        for remote_argv in observed:
            self.assertIsInstance(
                remote_argv,
                (list, tuple),
                "each collector dispatch must pass typed argv to run_on_ethernet",
            )
            self.assertTrue(all(type(item) is str for item in remote_argv))

    def test_interface_vrf_defaults_only_for_semantic_no_output(self):
        with mock.patch.object(
            self.module, "interactive_run",
            return_value=self.module.SessionResult("", 1),
        ):
            self.assertEqual(
                "default",
                self.module.interface_vrf(
                    self.ethernet(), "admin", "secret", "vlan100", 10,
                    local=True,
                ),
                "ifquery exit 1 with empty output is semantic stanza absence",
            )

        failures = (
            self.module.SessionResult("Permission denied", 255),
            self.module.SessionResult("ifquery failed", 1),
        )
        for failure in failures:
            with self.subTest(result=failure), mock.patch.object(
                self.module, "interactive_run", return_value=failure,
            ), self.assertRaisesRegex(self.module.SetupError, "Ethernet SSH failed"):
                self.module.interface_vrf(
                    self.ethernet(), "admin", "secret", "vlan100", 10,
                    local=True,
                )

        timeout = self.module.SetupError("command timed out after 10s")
        with mock.patch.object(
            self.module, "interactive_run", side_effect=timeout,
        ), self.assertRaisesRegex(self.module.SetupError, re.escape(str(timeout))):
            self.module.interface_vrf(
                self.ethernet(), "admin", "secret", "vlan100", 10,
                local=True,
            )

        with mock.patch.object(self.module, "interactive_run") as runner, \
                self.assertRaisesRegex(self.module.SetupError, "allowlist"):
            self.module.interface_vrf(
                self.ethernet(), "admin", "secret", "vlan100/evil", 10,
                local=True,
            )
        runner.assert_not_called()

    def test_exit_one_empty_is_downgraded_only_for_ifquery(self):
        empty_exit_one = self.module.SessionResult("", 1)
        with mock.patch.object(
            self.module, "interactive_run", return_value=empty_exit_one,
        ):
            self.assertEqual(
                "",
                self.module.run_on_ethernet(
                    self.ethernet(), "admin", "secret",
                    ["ifquery", "vlan100"], 10, local=True,
                ),
                "only ifquery exit 1 with empty output denotes stanza absence",
            )

        other_allowlisted_commands = (
            ["hostname"],
            ["nv", "show", "interface"],
            ["nv", "config", "show"],
            ["ip", "-d", "link", "show"],
            ["bridge", "fdb", "show"],
            ["ip", "neighbor"],
        )
        for command in other_allowlisted_commands:
            with self.subTest(command=command), mock.patch.object(
                self.module, "interactive_run", return_value=empty_exit_one,
            ), self.assertRaisesRegex(
                self.module.SetupError, "Ethernet SSH failed",
            ):
                self.module.run_on_ethernet(
                    self.ethernet(), "admin", "secret", command, 10,
                    local=True,
                )

    def test_nested_jump_dispatch_preserves_typed_argv(self):
        ib = self.module.Device(
            "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
            "203.0.113.1", "", "", "",
        )
        target = self.module.Target(ib, self.ethernet(), "swp7", "eth0")
        neighbor = self.module.Neighbor("fe80::1", "swp7", "02:11:22:33:44:55")
        command = ["nv", "config", "show"]
        with mock.patch.object(
            self.module, "outer_ssh_command", return_value=["sentinel"],
        ) as outer:
            try:
                self.module.nested_ssh_command(
                    target, neighbor, "admin", "admin", 10, command,
                )
            except TypeError as exc:
                self.fail(
                    "nested_ssh_command must accept typed IB argv without scalar "
                    f"coercion: {exc}"
                )
        remote_argv = outer.call_args.args[2]
        self.assertIsInstance(
            remote_argv,
            (list, tuple),
            "nested jump command must remain typed until outer SSH serialization",
        )

    def test_nested_jump_dispatch_binds_target_and_transit_identities(self):
        valid_ib = self.module.Device(
            "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
            "203.0.113.1", "", "", "",
        )
        wrong_ib = self.module.Device(
            "EXAMPLE-NVL01", "nvl", "203.0.113.3", "203.0.113.3/24",
            "203.0.113.1", "", "", "",
        )
        wrong_transit = self.module.Device(
            "EXAMPLE-SERVER01", "server", "192.0.2.20", "192.0.2.20",
            "", "", "", "",
        )
        neighbor = self.module.Neighbor("fe80::1", "swp7", "02:11:22:33:44:55")
        with mock.patch.object(self.module, "outer_ssh_command") as outer:
            for target in (
                self.module.Target(wrong_ib, self.ethernet(), "swp7", "eth0"),
                self.module.Target(valid_ib, wrong_transit, "swp7", "eth0"),
            ):
                with self.subTest(target=target), self.assertRaises(
                    self.module.SetupError,
                ):
                    self.module.nested_ssh_command(
                        target, neighbor, "admin", "admin", 10,
                        ["nv", "config", "show"],
                    )
        outer.assert_not_called()

    def test_ipv4_verification_dispatches_typed_argv(self):
        ib = self.module.Device(
            "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
            "203.0.113.1", "", "", "",
        )
        target = self.module.Target(ib, self.ethernet(), "swp7", "eth0")
        completed = self.module.SessionResult("", 0)
        with mock.patch.object(
            self.module, "outer_ssh_command", return_value=["sentinel"],
        ) as outer, mock.patch.object(
            self.module, "interactive_run", return_value=completed,
        ):
            self.module.verify_ipv4_login(
                target, "default", "admin", "secret", "admin", 10,
            )
        remote_argv = outer.call_args.args[2]
        self.assertIsInstance(
            remote_argv,
            (list, tuple),
            "verify_ipv4_login must pass typed argv to outer_ssh_command",
        )

    def test_ipv4_verification_reuses_closed_nvos_enforcer(self):
        valid_ib = self.module.Device(
            "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
            "203.0.113.1", "", "", "",
        )
        completed = self.module.SessionResult("", 0)
        valid_target = self.module.Target(valid_ib, self.ethernet(), "swp7", "eth0")
        with mock.patch.object(
            self.module, "ib_command_argv", wraps=self.module.ib_command_argv,
        ) as enforcer, mock.patch.object(
            self.module, "outer_ssh_command", return_value=["sentinel"],
        ), mock.patch.object(
            self.module, "interactive_run", return_value=completed,
        ):
            self.module.verify_ipv4_login(
                valid_target, "default", "admin", "secret", "admin", 10,
            )
        enforcer.assert_called_once_with(["true"])

    def test_ipv4_verification_binds_target_and_transit_identities(self):
        valid_ib = self.module.Device(
            "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
            "203.0.113.1", "", "", "",
        )
        completed = self.module.SessionResult("", 0)
        wrong_ib = self.module.Device(
            "EXAMPLE-NVL01", "nvl", "203.0.113.3", "203.0.113.3/24",
            "203.0.113.1", "", "", "",
        )
        wrong_transit = self.module.Device(
            "EXAMPLE-SERVER01", "server", "192.0.2.20", "192.0.2.20",
            "", "", "", "",
        )
        for target in (
            self.module.Target(wrong_ib, self.ethernet(), "swp7", "eth0"),
            self.module.Target(valid_ib, wrong_transit, "swp7", "eth0"),
        ):
            with self.subTest(target=target), mock.patch.object(
                self.module, "outer_ssh_command",
            ) as outer, mock.patch.object(
                self.module, "interactive_run", return_value=completed,
            ) as runner, self.assertRaises(self.module.SetupError):
                self.module.verify_ipv4_login(
                    target, "default", "admin", "secret", "admin", 10,
                )
            outer.assert_not_called()
            runner.assert_not_called()

    def test_neighbor_boundary_rejects_semantic_carriers_before_credentials(self):
        ib = self.module.Device(
            "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
            "203.0.113.1", "", "", "",
        )
        target = self.module.Target(ib, self.ethernet(), "swp7", "eth0")
        invalid_neighbors = (
            self.module.Neighbor(
                "fe80::1", "swp7\nssh attacker", "02:11:22:33:44:55", "default",
            ),
            self.module.Neighbor(
                "fe80::1", "swp7", "02:11:22:33:44:55", "blue\nssh attacker",
            ),
            self.module.Neighbor(
                "2001:db8::1", "swp7", "02:11:22:33:44:55", "default",
            ),
            self.module.Neighbor(
                "192.0.2.99", "swp7", "02:11:22:33:44:55", "default",
            ),
        )
        for neighbor in invalid_neighbors:
            with self.subTest(neighbor=neighbor), mock.patch.object(
                self.module, "NestedResponder",
            ) as responder, mock.patch.object(
                self.module, "interactive_run",
            ) as runner, self.assertRaises(self.module.SetupError):
                self.module.run_on_ib(
                    target, neighbor, "admin", "ethernet-secret", "admin",
                    "ib-secret", 10, ["nv", "config", "show"], local=True,
                )
            responder.assert_not_called()
            runner.assert_not_called()

    def test_auto_key_installer_rejects_transit_and_non_management_key_before_ssh(self):
        oob = self.module.Device(
            "EXAMPLE-OOB01", "eth", "192.0.2.11", "192.0.2.11",
            "", "", "", "",
        )
        invalid = (
            (self.ethernet(), {"name": "mgmt-server.pub"}),
            (oob, {"name": "laptop.pub"}),
        )
        for device, entry in invalid:
            with self.subTest(device=device.dev_type, key=entry["name"]), \
                    mock.patch.object(self.module, "outer_ssh_command") as outer, \
                    mock.patch.object(self.module, "interactive_run") as interactive, \
                    self.assertRaises(self.module.SetupError):
                self.module.install_oob_management_key(
                    device, "cumulus", "secret", entry, 10,
                )
            outer.assert_not_called()
            interactive.assert_not_called()

    def test_closed_jump_dispatch_caller_sets_are_complete(self):
        tree = ast.parse(INITIAL_SETUP.read_text(encoding="utf-8"))
        callers: dict[str, set[str]] = {
            "outer_ssh_command": set(),
            "interactive_run": set(),
            "ib_command_argv": set(),
        }
        for function in (
            node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
                if isinstance(call.func, ast.Name) and call.func.id in callers:
                    callers[call.func.id].add(function.name)

        self.assertEqual(
            {"run_on_ethernet", "nested_ssh_command", "verify_ipv4_login",
             "install_oob_management_key"},
            callers["outer_ssh_command"],
        )
        self.assertEqual(
            {"run_on_ethernet", "run_on_ib", "verify_ipv4_login",
             "install_oob_management_key"},
            callers["interactive_run"],
        )
        self.assertEqual(
            {
                "nested_ssh_command", "verify_ipv4_login", "_service_profile",
                "desired_service_commands", "key_install_command",
                "_validate_cache_profile",
            },
            callers["ib_command_argv"],
            "every NVOS dispatch boundary must reuse the closed typed enforcer",
        )


if __name__ == "__main__":
    unittest.main()
