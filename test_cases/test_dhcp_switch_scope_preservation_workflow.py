#!/usr/bin/env python3
"""Real 11-load to DHCP workflow for switch-scoped host ownership."""

from __future__ import annotations

import importlib.util
import csv
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock
import yaml

from test_cases.test_dhcp_switch_scope_preservation import (
    DHCP,
    FAMILY_HOST,
    ScopedDhcpFixture,
)


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    sys.path[:0] = [str(path.parent), str(ROOT / "tools"), str(ROOT)]
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.path[:3]
        if previous is not None:
            sys.modules[name] = previous
    return module


LOAD = load_module(
    "dhcp_switch_scope_workflow_load",
    ROOT / "DAY0-Prepare/11-load.py",
)


class DhcpSwitchScopeWorkflowTests(unittest.TestCase):
    def _v2_validated_generation(self, fixture, status, *, invalid=None):
        from test_cases.test_dhcp_optional_contract import global_document
        document = global_document(status)
        document["common"]["mgmt"]["ztp"]["status"] = "disabled"
        fixture.global_file.write_text(yaml.safe_dump(document))
        lines = fixture.devices_file.read_text().splitlines()
        fixture.devices_file.write_text(lines[0] + ",lo_ip,bgp_asn,bgp_ports,bond_ports,bond_type,bond_mac,peerlink_ports,vrl\n" +
                                       "\n".join(line + ",NA,NA,NA,NA,NA,NA,NA,NA" for line in lines[1:]) + "\n")
        project = fixture.global_file.parent
        subnet = project / "02-dhcp-subnet_config.csv"
        subnet.write_bytes(fixture.subnet_file.read_bytes())
        if invalid == "missing":
            subnet.unlink()
        elif invalid == "symlink":
            subnet.unlink()
            subnet.symlink_to(fixture.subnet_file.name)
        elif invalid is not None:
            subnet.write_bytes({"zero": b"", "whitespace": b" \n\t", "badheader": b"wrong\nvalue\n",
                               "header-only": fixture.subnet_file.read_bytes().splitlines(keepends=True)[0]}[invalid])
        p2p = project / "p2p.xlsx"
        p2p.write_bytes(b"unrelated workbook selection is stubbed")
        args = SimpleNamespace(switch_scope="all", deployment_scope="prod", p2p_file=None,
                               no_upgrade=True, mini=None, ssh_dir=None, dry_run=True)
        commands = []
        def boundary(command, **kwargs):
            commands.append(command)
            if command[1] == "c1-generate_dhcp.py":
                fixture.execute([command[1], *command[2:]])
        with ExitStack() as stack:
            for name, value in (("find_placeholder_password_sections", ()),
                                ("select_p2p", p2p), ("project_air_topology_policy", None),
                                ("project_mini_air_devices", (None, None)), ("prepare_pubkeys", ()),
                                ("validate_shared_artifact_receipts", None)):
                stack.enter_context(mock.patch.object(LOAD, name, return_value=value))
            stack.enter_context(mock.patch.object(LOAD, "ZTP_DIR", fixture.root / "ztp"))
            stack.enter_context(mock.patch.object(LOAD, "run", side_effect=boundary))
            stack.enter_context(mock.patch.object(LOAD, "newest_directory", return_value=fixture.root / "generated"))
            inputs, _ = LOAD.validate_inputs(project, args, allow_management_key_generation=False,
                                             host_role="workstation")
            self.assertEqual(2, inputs.settings.schema_version)
            self.assertFalse(inputs.settings.ztp_enabled)
            LOAD.generate_configs(inputs.device_types, install_dhcp=False,
                                  dhcp_enabled=inputs.settings.dhcp_enabled, deployment_scope="prod",
                                  source_identities=inputs.source_identities)
        return commands

    def test_v2_validation_to_generation_enabled_and_disabled_five_outputs(self):
        for status in ("enabled", "disabled"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as name:
                fixture = ScopedDhcpFixture(Path(name))
                before = fixture.snapshot()
                commands = self._v2_validated_generation(fixture, status)
                self.assertEqual(int(status == "enabled"), sum(c[1] == "c1-generate_dhcp.py" for c in commands))
                self.assertTrue(any(c[1] == "90-c2-generate_configs.py" for c in commands))
                if status == "disabled":
                    self.assertEqual(before, fixture.snapshot())
                else:
                    for path in fixture.outputs.values():
                        self.assertGreater(path.stat().st_size, 0)
                    self.assertNotEqual(before, fixture.snapshot())

    def test_v2_invalid_subnet_stops_before_generation_and_preserves_old_outputs(self):
        for status in ("enabled", "disabled"):
            cases = ["missing", "zero", "whitespace", "badheader", "symlink"]
            if status == "enabled":
                cases.append("header-only")
            for invalid in cases:
                with self.subTest(status=status, invalid=invalid), tempfile.TemporaryDirectory() as name:
                    fixture = ScopedDhcpFixture(Path(name))
                    before = fixture.snapshot()
                    parent = fixture.root / "old-parent.json"
                    parent.write_bytes(b'{"release_id":"previous-healthy-release"}\n')
                    parent_before = (parent.read_bytes(), parent.stat().st_ino, parent.stat().st_mtime_ns)
                    with mock.patch.object(LOAD, "generate_configs", wraps=LOAD.generate_configs) as generate, \
                            mock.patch.object(LOAD, "stop_other_ztp_monitors") as stop, \
                            mock.patch.object(LOAD, "publish_current_release") as publish:
                        with self.assertRaisesRegex(LOAD.LoadError, "项目输入检查失败"):
                            self._v2_validated_generation(fixture, status, invalid=invalid)
                        generate.assert_not_called()
                        stop.assert_not_called()
                        publish.assert_not_called()
                    self.assertEqual(before, fixture.snapshot())
                    self.assertEqual(parent_before,
                                     (parent.read_bytes(), parent.stat().st_ino, parent.stat().st_mtime_ns))

    def test_source_and_derived_mid_generation_edits_fail_closed(self):
        for tamper in ("source", "derived"):
            with self.subTest(tamper=tamper), tempfile.TemporaryDirectory() as name:
                fixture = ScopedDhcpFixture(Path(name))
                fixture.add_air_inventory()
                fixture.air_file.write_text('{"nodes": {}}')
                before = hashlib.sha256(fixture.devices_file.read_bytes()).hexdigest()
                def run_real_boundary(command, **_kwargs):
                    if command[1] == "c1-generate_dhcp.py":
                        fixture.execute([command[1], *command[2:]])
                    elif command[1] == "90-c2-generate_configs.py" and "--csv" in command:
                        victim = (fixture.devices_file if tamper == "source" else
                                  Path(command[command.index("--csv") + 1]))
                        with victim.open("a") as stream:
                            stream.write("\n")
                with mock.patch.object(LOAD, "ZTP_DIR", fixture.root / "ztp"), \
                        mock.patch.object(LOAD, "run", side_effect=run_real_boundary), \
                        mock.patch.object(LOAD, "newest_directory", return_value=fixture.root / "generated"), \
                        self.assertRaisesRegex(LOAD.LoadError, "inventory changed during generation"):
                    LOAD.generate_configs(frozenset({"eth"}), install_dhcp=False,
                        source_identities={"devices": before})

    def test_new_load_accepts_new_snapshot_but_stale_snapshot_is_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = ScopedDhcpFixture(Path(name))
            fixture.air_file.write_text('{"nodes": {}}')
            old_hash = hashlib.sha256(fixture.devices_file.read_bytes()).hexdigest()
            with fixture.devices_file.open("a") as stream:
                stream.write("\n")
            new_hash = hashlib.sha256(fixture.devices_file.read_bytes()).hexdigest()
            def run_real_boundary(command, **_kwargs):
                if command[1] == "c1-generate_dhcp.py":
                    fixture.execute([command[1], *command[2:]])
            with mock.patch.object(LOAD, "ZTP_DIR", fixture.root / "ztp"), \
                    mock.patch.object(LOAD, "run", side_effect=run_real_boundary), \
                    mock.patch.object(LOAD, "newest_directory", return_value=fixture.root / "generated"):
                with self.assertRaisesRegex(LOAD.LoadError, "customer inventory changed before generation"):
                    LOAD.generate_configs(frozenset({"eth"}), install_dhcp=False,
                        source_identities={"devices": old_hash})
                result = LOAD.generate_configs(frozenset({"eth"}), install_dhcp=False,
                    source_identities={"devices": new_hash})
                self.assertIsInstance(result, LOAD.DerivedInventory)

    def test_load_to_real_c1_rejects_redirected_private_output_before_downstream(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = ScopedDhcpFixture(Path(name))
            fixture.air_file.write_text('{"nodes": {}}')
            source, outputs = fixture.devices_file.read_bytes(), fixture.snapshot()
            destination = fixture.root / "unexpected-live-output.csv"
            commands = []
            def boundary(command, **_kwargs):
                commands.append(command[1])
                if command[1] == "c1-generate_dhcp.py":
                    argv = [command[1], *command[2:]]
                    argv[argv.index("--inventory-output") + 1] = str(destination)
                    fixture.execute(argv)
            with mock.patch.object(LOAD, "ZTP_DIR", fixture.root / "ztp"), \
                    mock.patch.object(LOAD, "run", side_effect=boundary), \
                    self.assertRaisesRegex(ValueError, "private inventory"):
                LOAD.generate_configs(frozenset({"eth"}), install_dhcp=False,
                    source_identities={"devices": hashlib.sha256(source).hexdigest()})
            self.assertFalse(destination.exists())
            self.assertNotIn("90-c2-generate_configs.py", commands)
            self.assertEqual(source, fixture.devices_file.read_bytes())
            self.assertEqual(outputs, fixture.snapshot())

    def test_explicit_air_without_mini_preserves_source_and_uses_derived_inventory(self):
        self._assert_539_old_air_rows_become_81_private_rows("air")

    def test_default_all_with_air_preserves_source_and_uses_derived_inventory(self):
        self._assert_539_old_air_rows_become_81_private_rows("all")

    def _assert_539_old_air_rows_become_81_private_rows(self, deployment_scope):
        for dhcp_enabled in (True, False):
            with self.subTest(dhcp_enabled=dhcp_enabled), tempfile.TemporaryDirectory() as name:
                fixture = ScopedDhcpFixture(Path(name))
                header = fixture.devices_file.read_text().splitlines()[0]
                rows = []
                nodes = {}
                for index in range(1, 82):
                    hostname = f"EXAMPLE-Leaf{index:03}"
                    rows.append(f"{hostname},eth,leaf,192.0.2.{index},24,192.0.2.254,02:00:01:00:00:{index:02x},NA,NA,NA,NA")
                    nodes["AIR-" + hostname] = {
                        "os": "cumulus-vx", "management_interfaces": {"eth0": {
                            "ip": f"192.0.2.{index + 100}",
                            "mac": f"02:00:02:00:00:{index:02x}"}}}
                for index in range(539):
                    rows.append(f"AIR-OLD-{index},air,leaf,192.0.2.90,24,192.0.2.254,02:00:03:00:{index//256:02x}:{index%256:02x},NA,NA,NA,NA")
                fixture.devices_file.write_text(header + "\n" + "\n".join(rows) + "\n")
                fixture.air_file.write_text(json.dumps({"nodes": nodes}))
                before = fixture.devices_file.read_bytes()
                before_stat = fixture.devices_file.stat()
                output_before = fixture.snapshot()
                consumers = []
                def run_real_boundary(command, **_kwargs):
                    if command[1] == "c1-generate_dhcp.py":
                        fixture.execute([command[1], *command[2:]])
                    elif command[1] in {"90-c2-generate_configs.py", "d-hostname2mac.py"}:
                        self.assertIn("--csv", command)
                        path = Path(command[command.index("--csv") + 1])
                        with path.open() as stream:
                            records = list(csv.DictReader(stream))
                        self.assertEqual(81, sum(row["type"] == "air" for row in records))
                        self.assertEqual(81, sum(row["type"] == "eth" for row in records))
                        self.assertFalse(any(row["hostname"].startswith("AIR-OLD-") for row in records))
                        consumers.append(path)
                with mock.patch.object(LOAD, "ZTP_DIR", fixture.root / "ztp"), \
                        mock.patch.object(LOAD, "run", side_effect=run_real_boundary), \
                        mock.patch.object(LOAD, "newest_directory", return_value=fixture.root / "generated"):
                    result = LOAD.generate_configs(frozenset({"eth"}), install_dhcp=False,
                        dhcp_enabled=dhcp_enabled, deployment_scope=deployment_scope,
                        source_identities={"devices": hashlib.sha256(before).hexdigest()})
                self.assertEqual([result.path, result.path], consumers)
                self.assertEqual(before, fixture.devices_file.read_bytes())
                self.assertEqual((before_stat.st_ino, before_stat.st_mtime_ns),
                    (fixture.devices_file.stat().st_ino, fixture.devices_file.stat().st_mtime_ns))
                if not dhcp_enabled:
                    self.assertEqual(output_before, fixture.snapshot())

    def test_load_generation_never_rewrites_validated_customer_inventory(self):
        """A smaller AIR topology must not rewrite the frozen customer CSV."""
        with tempfile.TemporaryDirectory() as name:
            fixture = ScopedDhcpFixture(Path(name))
            fixture.add_air_inventory()
            fixture.air_file.write_text('{"nodes": {}}', encoding="utf-8")
            before = fixture.devices_file.read_bytes()
            before_stat = fixture.devices_file.stat()

            def run_real_boundary(command, **_kwargs):
                if len(command) >= 2 and command[1] == "c1-generate_dhcp.py":
                    fixture.execute(["c1-generate_dhcp.py", *command[2:]])

            with mock.patch.object(LOAD, "ZTP_DIR", fixture.root / "ztp"), \
                    mock.patch.object(LOAD, "run", side_effect=run_real_boundary), \
                    mock.patch.object(LOAD, "newest_directory",
                                      return_value=fixture.root / "generated"):
                LOAD.generate_configs(
                    frozenset({"eth"}), install_dhcp=False, dry_run=False,
                )
            self.assertEqual(before, fixture.devices_file.read_bytes())
            self.assertEqual(before_stat.st_ino, fixture.devices_file.stat().st_ino)

    def test_ib_only_with_air_json_does_not_remove_customer_air_rows(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = ScopedDhcpFixture(Path(name))
            fixture.add_air_inventory()
            fixture.air_file.write_text('{"nodes": {}}', encoding="utf-8")
            before = fixture.devices_file.read_bytes()
            def run_real_boundary(command, **_kwargs):
                if command[1] == "c1-generate_dhcp.py":
                    fixture.execute(["c1-generate_dhcp.py", *command[2:]])
            with mock.patch.object(LOAD, "ZTP_DIR", fixture.root / "ztp"), \
                    mock.patch.object(LOAD, "run", side_effect=run_real_boundary), \
                    mock.patch.object(LOAD, "newest_directory", return_value=fixture.root / "generated"):
                LOAD.generate_configs(frozenset({"ib"}), install_dhcp=False,
                                      dry_run=False, switch_scope="ib")
            self.assertEqual(before, fixture.devices_file.read_bytes())

    def _run_load_generation(
        self,
        fixture: ScopedDhcpFixture,
        *,
        selected: str,
        manifest_failure: BaseException | None = None,
    ) -> list[list[str]]:
        commands: list[list[str]] = []

        def run_real_boundary(command, **_kwargs):
            command = [str(item) for item in command]
            commands.append(command)
            if len(command) >= 2 and command[1] == "c1-generate_dhcp.py":
                fixture.execute(
                    ["c1-generate_dhcp.py", *command[2:]],
                    manifest_failure=manifest_failure,
                )

        with mock.patch.object(
            LOAD, "ZTP_DIR", fixture.root / "ztp",
        ), mock.patch.object(
            LOAD, "run", side_effect=run_real_boundary,
        ), mock.patch.object(
            LOAD, "newest_directory",
            return_value=fixture.root / "fixture-generated-release",
        ):
            LOAD.generate_configs(
                frozenset({"eth", "ib", "nvl"}),
                install_dhcp=False,
                dry_run=False,
                deployment_scope="prod",
                switch_scope=selected,
            )
        return commands

    def test_real_load_forwards_scope_and_preserves_other_family_hosts(self):
        for selected in ("ib", "nvl"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as name:
                fixture = ScopedDhcpFixture(Path(name))
                before = fixture.snapshot()
                commands = self._run_load_generation(
                    fixture, selected=selected,
                )

                dhcp_commands = [
                    item for item in commands
                    if len(item) >= 2 and item[1] == "c1-generate_dhcp.py"
                ]
                self.assertEqual(1, len(dhcp_commands), commands)
                command = dhcp_commands[0]
                self.assertEqual(1, command.count("--switch"), command)
                self.assertEqual(selected, command[command.index("--switch") + 1])
                self.assertIn(FAMILY_HOST[selected], fixture.outputs[selected].read_text())
                for family in ("eth", "ib", "nvl"):
                    if family != selected:
                        self.assertEqual(
                            before[family][0], fixture.outputs[family].read_bytes(),
                            f"load --switch {selected} mutated {family}",
                        )

    def test_real_load_propagates_generation_failure_without_partial_outputs(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = ScopedDhcpFixture(Path(name))
            before = fixture.snapshot()
            with self.assertRaisesRegex(OSError, "workflow manifest failure"):
                self._run_load_generation(
                    fixture,
                    selected="ib",
                    manifest_failure=OSError("injected workflow manifest failure"),
                )

            for label, path in fixture.outputs.items():
                self.assertEqual(before[label][0], path.read_bytes(), label)


if __name__ == "__main__":
    unittest.main()
