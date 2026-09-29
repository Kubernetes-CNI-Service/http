#!/usr/bin/env python3
"""Real DAY0 load -> DHCP-generator contract for optional generation."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path
import shlex
import tempfile
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest import mock

from test_cases.test_dhcp_optional_contract import DHCP, LOAD, SETUP, global_document
from test_cases.test_dhcp_switch_scope_preservation import ScopedDhcpFixture
from test_cases import test_load_release_transaction as release_fixture
from test_cases.module_loader import load_script
import yaml

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = load_script("optional_empty_subnet_runtime", ROOT / "tools/ztp_service_runtime.py")
ACTIVATE = load_script("optional_empty_subnet_docker", ROOT / "infra/docker/activate.py")


class DhcpOptionalWorkflowTests(unittest.TestCase):
    def test_ib_load_to_setup_preserves_mixed_v2_inventory_without_eth_vrr(self):
        with tempfile.TemporaryDirectory() as name:
            project = Path(name)
            document = global_document("disabled")
            document["common"]["mgmt"]["ztp"]["status"] = "disabled"
            eth = next(item["eth"] for item in document["switches"] if "eth" in item)
            eth.pop("vrr")
            global_path = project / "01-global.yaml"
            global_path.write_text(yaml.safe_dump(document), encoding="utf-8")
            header = [
                "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw",
                "eth0_mac", "eth1_ip", "netmask", "eth1_gw", "eth1_mac", "lo_ip",
                "bgp_asn", "bgp_ports", "bond_ports", "bond_type", "bond_mac",
                "peerlink_ports", "vrl",
            ]
            with (project / "02-devices_config.csv").open(
                "w", newline="", encoding="utf-8",
            ) as stream:
                csv.writer(stream).writerows([
                    header,
                    ["ib01", "ib", "", "192.0.2.10", "24", "192.0.2.1"] + [""] * 13,
                    ["leaf01", "eth", "", "192.0.2.11", "24", "192.0.2.1"] + [""] * 13,
                ])
            (project / "02-dhcp-subnet_config.csv").write_bytes(b"")

            settings = LOAD.load_global(global_path, switch_scope="ib")
            self.assertEqual(2, settings.schema_version)
            with mock.patch.multiple(
                SETUP, _SWITCH_SCOPE="ib", _CSV_DIR=None, _P2P_SOURCE=None,
                _DRY_RUN=True, _FORCE=False, _STRICT=False,
                IMAGE_DIR=str(project / "image"),
            ), redirect_stdout(io.StringIO()):
                self.assertTrue(SETUP._validate_project(str(project)))
            with mock.patch.multiple(
                SETUP, _SWITCH_SCOPE="all", _CSV_DIR=None, _P2P_SOURCE=None,
                _DRY_RUN=True, _FORCE=False, _STRICT=False,
                IMAGE_DIR=str(project / "image"),
            ), redirect_stdout(io.StringIO()) as output:
                self.assertFalse(SETUP._validate_project(str(project)))
            self.assertIn("switches.eth.vrr", output.getvalue())
            self.assertNotIn("schema 1", output.getvalue())

    def test_ib_load_input_transaction_keeps_empty_subnet_source_hash(self):
        with tempfile.TemporaryDirectory() as name:
            project = Path(name)
            global_file = project / "01-global.yaml"
            document = global_document("disabled")
            document["common"]["mgmt"]["ztp"]["status"] = "disabled"
            global_file.write_text(yaml.safe_dump(document), encoding="utf-8")
            (project / "02-devices_config.csv").write_text("fixture\n", encoding="utf-8")
            subnet = project / "02-dhcp-subnet_config.csv"
            subnet.write_bytes(b"")
            p2p = project / "real P2P_v1.0.xlsx"
            p2p.write_bytes(b"fixture")
            args = SimpleNamespace(
                switch_scope="ib", deployment_scope="all", p2p_file=None,
                no_upgrade=True, mini=None, ssh_dir=None, dry_run=True,
            )
            with mock.patch.object(LOAD, "find_placeholder_password_sections", return_value=()), \
                    mock.patch.object(LOAD, "load_device_types", return_value=frozenset({"ib"})), \
                    mock.patch.object(LOAD, "select_p2p", return_value=p2p), \
                    mock.patch.object(LOAD, "project_air_topology_policy", return_value=None), \
                    mock.patch.object(LOAD, "project_mini_air_devices", return_value=(None, None)), \
                    mock.patch.object(LOAD, "prepare_pubkeys", return_value=()), \
                    mock.patch.object(LOAD, "validate_shared_artifact_receipts"), \
                    redirect_stdout(io.StringIO()):
                inputs, images = LOAD.validate_inputs(
                    project, args, allow_management_key_generation=False,
                    host_role="workstation",
                )
            self.assertEqual({}, images)
            self.assertEqual(frozenset({"ib"}), inputs.device_types)
            self.assertEqual(hashlib.sha256(b"").hexdigest(),
                             inputs.source_identities["subnet"])

    def test_ib_empty_subnet_passes_setup_load_and_both_runtime_planners(self):
        with tempfile.TemporaryDirectory() as name:
            project = Path(name) / "project"
            project.mkdir()
            global_file = project / "01-global.yaml"
            document = global_document("disabled")
            document["common"]["mgmt"]["ztp"]["status"] = "disabled"
            global_file.write_text(yaml.safe_dump(document), encoding="utf-8")
            subnet = project / "02-dhcp-subnet_config.csv"
            subnet.write_bytes(b"")
            settings = LOAD.load_global(global_file, switch_scope="ib")
            setup_output = io.StringIO()
            with mock.patch.object(SETUP, "_validate_eth_csv", return_value=([], [])), \
                    mock.patch.object(SETUP, "_validate_global_yaml", return_value=([], [])), \
                    redirect_stdout(setup_output):
                old_scope = SETUP._SWITCH_SCOPE
                SETUP._SWITCH_SCOPE = "ib"
                try:
                    self.assertTrue(SETUP._validate_project(str(project)), setup_output.getvalue())
                finally:
                    SETUP._SWITCH_SCOPE = old_scope
            settings = LOAD.apply_subnet_service_ips(settings, subnet)
            LOAD.validate_subnet_file(subnet, settings)
            inputs = SimpleNamespace(settings=settings, subnet_file=subnet)
            native = LOAD.plan_local_dhcp_runtime(
                inputs, link_snapshot=[], address_snapshot=[], environment={},
            )
            self.assertEqual((), native.listener_names)
            self.assertEqual((), native.endpoint_ips)
            docker_settings = SimpleNamespace(project_dir=project, subnet_csv=subnet,
                                              http_root=ROOT,
                                              project_name="project", scope="all",
                                              switch_scope="ib", mini=False,
                                              allowlist=(), relay_ingress=())
            with mock.patch.object(ACTIVATE, "validate_project_mount"), \
                    mock.patch.object(ACTIVATE, "capture_stable_network_snapshot", return_value=([], [])), \
                    mock.patch.object(ACTIVATE, "_load_runtime_module", return_value=RUNTIME):
                docker, _, _, _ = ACTIVATE.build_runtime_plan(docker_settings)
            self.assertEqual((), docker.listener_names)
            self.assertEqual(hashlib.sha256(b"").hexdigest(),
                             ACTIVATE.sha256_path(subnet, allow_empty=True))
            self.assertEqual((), docker.endpoint_ips)
            self.assertEqual(
                hashlib.sha256(b"").hexdigest(),
                ACTIVATE.runtime_plan_payload(docker_settings, docker, [], [])["subnet_sha256"],
            )

            docker_settings.relay_ingress = ("eth0",)
            links = [{"ifindex": 7, "ifname": "eth0", "link_type": "ether",
                      "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                      "operstate": "UP"}]
            addresses = [{"ifindex": 7, "ifname": "eth0", "addr_info": [
                {"family": "inet", "local": "192.0.2.10", "prefixlen": 24,
                 "scope": "global"}]}]
            with mock.patch.object(ACTIVATE, "validate_project_mount"), \
                    mock.patch.object(ACTIVATE, "capture_stable_network_snapshot", return_value=(links, addresses)), \
                    mock.patch.object(ACTIVATE, "_load_runtime_module", return_value=RUNTIME), \
                    self.assertRaisesRegex(ACTIVATE.ActivationError, "no DHCP networks"):
                ACTIVATE.build_runtime_plan(docker_settings)

            docker_settings.relay_ingress = ()
            for service in ("dhcp-server", "ztp"):
                with self.subTest(enabled=service):
                    changed = global_document("disabled")
                    changed["common"]["mgmt"]["ztp"]["status"] = "disabled"
                    changed["common"]["mgmt"][service]["status"] = "enabled"
                    global_file.write_text(yaml.safe_dump(changed), encoding="utf-8")
                    with mock.patch.object(ACTIVATE, "validate_project_mount"), \
                            mock.patch.object(ACTIVATE, "capture_stable_network_snapshot", return_value=([], [])), \
                            mock.patch.object(ACTIVATE, "_load_runtime_module", return_value=RUNTIME), \
                            self.assertRaises(ACTIVATE.ActivationError):
                        ACTIVATE.build_runtime_plan(docker_settings)
                    with mock.patch.object(SETUP, "_validate_eth_csv", return_value=([], [])), \
                            mock.patch.object(SETUP, "_validate_global_yaml", return_value=([], [])), \
                            redirect_stdout(io.StringIO()):
                        self.assertFalse(SETUP._validate_project(str(project)))

    def test_generator_native_handoff_is_accepted_by_real_linux_load_parser(self):
        guidance = DHCP._production_handoff_text()
        command = next(
            line.removeprefix("[NEXT] Native/systemd：")
            for line in guidance.splitlines()
            if line.startswith("[NEXT] Native/systemd：")
        )
        words = shlex.split(command)
        self.assertEqual(
            ["sudo", "python3", "DAY0-Prepare/11-load.py"], words[:3],
        )
        parsed = LOAD.parse_args(words[3:])
        self.assertEqual("DAY0-Prepare/<project>", str(parsed.project))
        self.assertEqual(
            "management-server", LOAD.resolve_host_role(parsed.host_role, "linux"),
        )
        missing_role = [
            word for word in words[3:]
            if word != "--host-role=management-server"
        ]
        with self.assertRaisesRegex(LOAD.LoadError, "Linux requires explicit --host-role"):
            LOAD.resolve_host_role(LOAD.parse_args(missing_role).host_role, "linux")

    _PARENT_BASIS_KEYS = (
        "project", "deployment_scope", "switch_scope", "inputs",
        "input_sources", "dhcp_status", "components", "inventory",
    )

    def _assert_v2_mode_bound_release(self, parent, mode):
        # This key list is an independent contract, not copied from the load
        # implementation.  Removing dhcp_status from its digest must red here.
        self.assertEqual(2, parent["schema_version"])
        self.assertEqual(mode, parent["dhcp_status"])
        basis = {key: parent[key] for key in self._PARENT_BASIS_KEYS}
        expected_id = hashlib.sha256(json.dumps(
            basis, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()[:20]
        self.assertEqual(expected_id, parent["release_id"])

    def _legacy_v1_parent(self, parent):
        legacy = dict(parent)
        legacy["schema_version"] = 1
        legacy.pop("dhcp_status", None)
        basis = {
            key: legacy[key] for key in self._PARENT_BASIS_KEYS
            if key != "dhcp_status"
        }
        legacy["release_id"] = hashlib.sha256(json.dumps(
            basis, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()[:20]
        return legacy

    @staticmethod
    def _disabled_inputs(fixture):
        return release_fixture.LOAD.replace(
            fixture.inputs,
            settings=release_fixture.LOAD.replace(
                fixture.inputs.settings, dhcp_enabled=False,
            ),
        )

    @staticmethod
    def _fresh_project_without_dhcp_release():
        fixture = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match"
        )
        fixture.setUp()
        dhcp_dir = fixture.ztp / "config/isc-dhcp-server"
        for name in (
            "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
            "dhcpd_nvl.hosts", "dhcp-release-manifest.json",
        ):
            (dhcp_dir / name).unlink()
        return fixture

    def _generate(
        self, fixture: ScopedDhcpFixture, *, enabled: bool,
        gate_override: bool | None = None,
    ):
        commands: list[list[str]] = []

        def run_real_dhcp_boundary(command, **_kwargs):
            argv = [str(item) for item in command]
            commands.append(argv)
            if len(argv) > 1 and argv[1] == "c1-generate_dhcp.py":
                fixture.execute(["c1-generate_dhcp.py", *argv[2:]])

        with mock.patch.object(LOAD, "ZTP_DIR", fixture.root / "ztp"), \
                mock.patch.object(LOAD, "run", side_effect=run_real_dhcp_boundary), \
                mock.patch.object(
                    LOAD, "_device_types_after_dhcp", return_value=frozenset({"ib"}),
                ) as after_dhcp, \
                mock.patch.object(
                    LOAD, "newest_directory", return_value=fixture.root / "generated-ib",
                ):
            LOAD.generate_configs(
                frozenset({"ib"}), install_dhcp=enabled,
                dhcp_enabled=enabled if gate_override is None else gate_override,
                deployment_scope="all", switch_scope="all", dry_run=False,
            )
        return commands, after_dhcp.call_count

    @staticmethod
    def _dhcp_generator_calls(commands):
        return sum(
            len(command) > 1 and command[1] == "c1-generate_dhcp.py"
            for command in commands
        )

    def test_disabled_preserves_all_five_real_outputs_and_continues_other_generation(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = ScopedDhcpFixture(Path(name))
            # The isolated fixture models the regular-file targets behind the
            # live project's links into 99-output-dhcp, not symlink metadata.
            before = fixture.snapshot()
            commands, after_dhcp_calls = self._generate(fixture, enabled=False)
            self.assertEqual(0, sum(
                len(command) > 1 and command[1] == "c1-generate_dhcp.py"
                for command in commands
            ))
            self.assertEqual(before, fixture.snapshot())
            self.assertEqual({"conf", "eth", "ib", "nvl", "manifest"}, set(before))
            # A branch-specific continuation witness: skipping the entire load
            # would leave the same five bytes but must fail this assertion.
            self.assertEqual(1, after_dhcp_calls)
            self.assertTrue(any(
                len(command) > 1 and command[1] == "90-c2-generate_configs.py"
                and "ib" in command for command in commands
            ), commands)

    def test_enabled_still_runs_real_generator_and_replaces_all_five_outputs(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = ScopedDhcpFixture(Path(name))
            before = fixture.snapshot()
            commands, after_dhcp_calls = self._generate(fixture, enabled=True)
            self.assertEqual(1, sum(
                len(command) > 1 and command[1] == "c1-generate_dhcp.py"
                for command in commands
            ))
            self.assertEqual(1, after_dhcp_calls)
            after = fixture.snapshot()
            self.assertEqual({"conf", "eth", "ib", "nvl", "manifest"}, set(after))
            for label in before:
                with self.subTest(output=label):
                    self.assertNotEqual(before[label][0], after[label][0])
                    self.assertNotEqual(before[label][1][1], after[label][1][1])

    def test_standalone_generator_remains_callable_after_disabled_load_skip(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = ScopedDhcpFixture(Path(name))
            before = fixture.snapshot()
            commands, continuation = self._generate(fixture, enabled=False)
            self.assertEqual(0, self._dhcp_generator_calls(commands))
            self.assertEqual(1, continuation)
            self.assertEqual(before, fixture.snapshot())
            # Optionality belongs to the load orchestrator. An independently
            # invoked generator must still publish a complete five-file set.
            fixture.execute(["c1-generate_dhcp.py", "-y"])
            after = fixture.snapshot()
            self.assertEqual(set(before), set(after))
            self.assertEqual({"conf", "eth", "ib", "nvl", "manifest"}, set(after))
            for label in before:
                with self.subTest(output=label):
                    self.assertNotEqual(before[label][0], after[label][0])
                    self.assertNotEqual(before[label][1][1], after[label][1][1])

    def test_inverted_load_gate_mutant_is_visible_in_both_modes(self):
        # The one-bit call-site mutant `dhcp_enabled=not enabled` must differ
        # from both independently asserted real branches, not only change a
        # text predicate while leaving artifact assertions unreached.
        with tempfile.TemporaryDirectory() as name:
            fixture = ScopedDhcpFixture(Path(name))
            before = fixture.snapshot()
            actual, _ = self._generate(fixture, enabled=False)
            self.assertEqual(0, self._dhcp_generator_calls(actual))
            self.assertEqual(before, fixture.snapshot())
            inverted, _ = self._generate(
                fixture, enabled=False, gate_override=True,
            )
            self.assertEqual(1, self._dhcp_generator_calls(inverted))
            self.assertNotEqual(before, fixture.snapshot())
        with tempfile.TemporaryDirectory() as name:
            fixture = ScopedDhcpFixture(Path(name))
            before = fixture.snapshot()
            actual, _ = self._generate(fixture, enabled=True)
            self.assertEqual(1, self._dhcp_generator_calls(actual))
            self.assertNotEqual(before, fixture.snapshot())
        with tempfile.TemporaryDirectory() as name:
            fixture = ScopedDhcpFixture(Path(name))
            before = fixture.snapshot()
            inverted, _ = self._generate(
                fixture, enabled=True, gate_override=False,
            )
            self.assertEqual(0, self._dhcp_generator_calls(inverted))
            self.assertEqual(before, fixture.snapshot())

    def test_disabled_fresh_project_can_validate_parent_without_dhcp_artifacts(self):
        fixture = self._fresh_project_without_dhcp_release()
        try:
            disabled = self._disabled_inputs(fixture)
            parent = release_fixture.LOAD.validate_and_publish_release(
                fixture.project, disabled, publish=False,
            )
            self.assertEqual("passed", parent["validation"])
            self.assertEqual("demo", parent["project"])
            self._assert_v2_mode_bound_release(parent, "disabled")
            self.assertNotIn("dhcp", parent["components"])
            self.assertEqual(
                "cumulus-release", parent["components"]["cumulus"]["release_id"],
            )
            self.assertFalse(any(
                (fixture.ztp / "config/isc-dhcp-server" / name).exists()
                for name in (
                    "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
                    "dhcpd_nvl.hosts", "dhcp-release-manifest.json",
                )
            ))
        finally:
            fixture.tearDown()

    def test_disabled_existing_stale_dhcp_receipt_is_not_current_evidence(self):
        fixture = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match"
        )
        fixture.setUp()
        try:
            dhcp_dir = fixture.ztp / "config/isc-dhcp-server"
            manifest_path = dhcp_dir / "dhcp-release-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["outputs"]["dhcpd.conf"]["sha256"] = "0" * 64
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            names = (
                "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
                "dhcpd_nvl.hosts", "dhcp-release-manifest.json",
            )
            before = {
                name: (
                    (dhcp_dir / name).read_bytes(),
                    (dhcp_dir / name).stat().st_ino,
                    (dhcp_dir / name).stat().st_mtime_ns,
                ) for name in names
            }
            parent = release_fixture.LOAD.validate_and_publish_release(
                fixture.project, self._disabled_inputs(fixture), publish=False,
            )
            self._assert_v2_mode_bound_release(parent, "disabled")
            self.assertNotIn("dhcp", parent["components"])
            self.assertEqual("cumulus-release", parent["components"]["cumulus"]["release_id"])
            self.assertEqual(before, {
                name: (
                    (dhcp_dir / name).read_bytes(),
                    (dhcp_dir / name).stat().st_ino,
                    (dhcp_dir / name).stat().st_mtime_ns,
                ) for name in names
            })
        finally:
            fixture.tearDown()

    def test_enabled_existing_valid_receipt_still_binds_dhcp_component(self):
        fixture = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match"
        )
        fixture.setUp()
        try:
            parent = release_fixture.LOAD.validate_and_publish_release(
                fixture.project, fixture.inputs, publish=False,
            )
            self._assert_v2_mode_bound_release(parent, "enabled")
            self.assertEqual("dhcp-release", parent["components"]["dhcp"]["release_id"])
        finally:
            fixture.tearDown()

    def test_enabled_parent_rejects_each_of_four_changed_dhcp_output_hashes(self):
        for name in (
            "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
        ):
            with self.subTest(output=name):
                fixture = release_fixture.ReleaseTransactionTests(
                    "test_writes_parent_release_after_all_components_match"
                )
                fixture.setUp()
                try:
                    output = fixture.ztp / "config/isc-dhcp-server" / name
                    output.write_bytes(output.read_bytes() + b"unexpected-change\n")
                    with self.assertRaisesRegex(
                        release_fixture.LOAD.LoadError,
                        "DHCP release 输出 hash 漂移：" + name.replace(".", r"\."),
                    ):
                        release_fixture.LOAD.validate_and_publish_release(
                            fixture.project, fixture.inputs, publish=False,
                        )
                finally:
                    fixture.tearDown()

    def test_enabled_present_but_wrong_manifest_hash_reaches_child_guard(self):
        fixture = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match"
        )
        fixture.setUp()
        try:
            manifest_path = (
                fixture.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json"
            )
            self.assertTrue(manifest_path.is_file())
            valid = release_fixture.LOAD.validate_and_publish_release(
                fixture.project, fixture.inputs, publish=False,
            )
            self._assert_v2_mode_bound_release(valid, "enabled")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["outputs"]["dhcpd.conf"]["sha256"] = "0" * 64
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertGreater(manifest_path.stat().st_size, 0)
            with self.assertRaisesRegex(
                release_fixture.LOAD.LoadError,
                r"DHCP release 输出 hash 漂移：dhcpd\.conf",
            ):
                release_fixture.LOAD.validate_and_publish_release(
                    fixture.project, fixture.inputs, publish=False,
                )
        finally:
            fixture.tearDown()

    def test_v1_legacy_enabled_parent_keeps_strict_dhcp_binding(self):
        fixture = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match"
        )
        fixture.setUp()
        try:
            parent = release_fixture.LOAD.validate_and_publish_release(
                fixture.project, fixture.inputs,
            )
            # Construct the legacy v1 record independently from the frozen v1
            # basis: no status field, but DHCP must remain a required child.
            legacy = self._legacy_v1_parent(parent)
            parent_path = fixture.project / "99-output-ztp/current-release.json"
            parent_path.write_text(json.dumps(legacy), encoding="utf-8")
            device = {
                "hostname": "leaf01", "type": "eth", "mac_plain": "020000000001",
                "identity_macs": {"eth0": "020000000001"},
            }
            with mock.patch.object(
                release_fixture.MANUAL, "DHCP_RELEASE_MANIFEST",
                fixture.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json",
            ):
                binding = release_fixture.MANUAL.validate_parent_release_binding(
                    fixture.project, device,
                )
                self.assertEqual(legacy["release_id"], binding["parent_release_id"])
                legacy["dhcp_status"] = "disabled"  # fake mode on a v1 receipt
                parent_path.write_text(json.dumps(legacy), encoding="utf-8")
                with self.assertRaisesRegex(
                    release_fixture.MANUAL.ManualZtpError,
                    r"dhcp_status|legacy|旧版|模式",
                ):
                    release_fixture.MANUAL.validate_parent_release_binding(
                        fixture.project, device,
                    )
        finally:
            fixture.tearDown()

    def test_v1_legacy_parent_without_dhcp_component_is_rejected_even_with_valid_id(self):
        fixture = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match"
        )
        fixture.setUp()
        try:
            parent = release_fixture.LOAD.validate_and_publish_release(
                fixture.project, fixture.inputs,
            )
            legacy = self._legacy_v1_parent(parent)
            legacy["components"] = dict(legacy["components"])
            legacy["components"].pop("dhcp")
            legacy = self._legacy_v1_parent(legacy)
            parent_path = fixture.project / "99-output-ztp/current-release.json"
            parent_path.write_text(json.dumps(legacy), encoding="utf-8")
            device = {
                "hostname": "leaf01", "type": "eth", "mac_plain": "020000000001",
                "identity_macs": {"eth0": "020000000001"},
            }
            with mock.patch.object(
                release_fixture.MANUAL, "DHCP_RELEASE_MANIFEST",
                fixture.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json",
            ), self.assertRaisesRegex(
                release_fixture.MANUAL.ManualZtpError, "DHCP 子 release",
            ):
                release_fixture.MANUAL.validate_parent_release_binding(
                    fixture.project, device,
                )
        finally:
            fixture.tearDown()

    def test_enabled_fresh_project_still_rejects_missing_dhcp_manifest(self):
        fixture = self._fresh_project_without_dhcp_release()
        try:
            with self.assertRaisesRegex(
                release_fixture.LOAD.LoadError, "DHCP release manifest",
            ):
                release_fixture.LOAD.validate_and_publish_release(
                    fixture.project, fixture.inputs, publish=False,
                )
        finally:
            fixture.tearDown()


if __name__ == "__main__":
    unittest.main()
