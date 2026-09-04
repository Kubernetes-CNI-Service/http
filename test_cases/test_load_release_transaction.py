"""Unified release validation, DHCP installation, and rollback transactions."""

from __future__ import annotations

import csv
from contextlib import ExitStack
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "day0_load", ROOT / "DAY0-Prepare/11-load.py"
)
LOAD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
import sys
sys.modules[SPEC.name] = LOAD
SPEC.loader.exec_module(LOAD)

MANUAL_SPEC = importlib.util.spec_from_file_location(
    "manual_ztp_release_contract", ROOT / "ztp/manual-ztp.py"
)
MANUAL = importlib.util.module_from_spec(MANUAL_SPEC)
assert MANUAL_SPEC.loader is not None
sys.modules[MANUAL_SPEC.name] = MANUAL
MANUAL_SPEC.loader.exec_module(MANUAL)

DHCP_SPEC = importlib.util.spec_from_file_location(
    "dhcp_release_contract", ROOT / "ztp/config/isc-dhcp-server/c1-generate_dhcp.py"
)
DHCP = importlib.util.module_from_spec(DHCP_SPEC)
assert DHCP_SPEC.loader is not None
sys.modules[DHCP_SPEC.name] = DHCP
DHCP_SPEC.loader.exec_module(DHCP)

TOPOLOGY_SPEC = importlib.util.spec_from_file_location(
    "air_topology_release_contract",
    ROOT / "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
)
TOPOLOGY = importlib.util.module_from_spec(TOPOLOGY_SPEC)
assert TOPOLOGY_SPEC.loader is not None
sys.modules[TOPOLOGY_SPEC.name] = TOPOLOGY
TOPOLOGY_SPEC.loader.exec_module(TOPOLOGY)

SETUP_SPEC = importlib.util.spec_from_file_location(
    "day0_setup_release_contract", ROOT / "DAY0-Prepare/01-a-setup.py"
)
SETUP = importlib.util.module_from_spec(SETUP_SPEC)
assert SETUP_SPEC.loader is not None
sys.modules[SETUP_SPEC.name] = SETUP
SETUP_SPEC.loader.exec_module(SETUP)

UNSETUP_SPEC = importlib.util.spec_from_file_location(
    "day0_unsetup_release_contract", ROOT / "DAY0-Prepare/02-unsetup.py"
)
UNSETUP = importlib.util.module_from_spec(UNSETUP_SPEC)
assert UNSETUP_SPEC.loader is not None
sys.modules[UNSETUP_SPEC.name] = UNSETUP
UNSETUP_SPEC.loader.exec_module(UNSETUP)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReleaseTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.project = self.root / "DAY0-Prepare/demo"
        self.project.mkdir(parents=True)
        self.ztp = self.root / "ztp"
        dhcp_dir = self.ztp / "config/isc-dhcp-server"
        dhcp_dir.mkdir(parents=True)
        cumulus_release = self.project / "99-output-eth/20260830_120000_combine"
        cumulus_release.mkdir(parents=True)
        (self.project / "99-output-eth/latest").symlink_to(cumulus_release.name)
        (self.ztp / "config/cumulus").mkdir(parents=True)
        (self.ztp / "config/cumulus/latest_yaml").symlink_to(
            self.project / "99-output-eth/latest"
        )

        self.global_file = self.project / "01-global.yaml"
        self.subnet_file = self.project / "02-dhcp-subnet_config.csv"
        self.p2p_file = self.project / "p2p.xlsx"
        for path, content in (
            (self.global_file, "schema_version: 1\n"),
            (self.subnet_file, "shared_network,subnet\nnet,192.0.2.0\n"),
            (self.p2p_file, "test\n"),
        ):
            path.write_text(content, encoding="utf-8")
        self.devices_file = self.project / "02-devices_config.csv"
        with self.devices_file.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow([
                "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw",
                "eth0_mac", "eth1_ip", "netmask", "eth1_gw", "eth1_mac",
            ])
            writer.writerow([
                "leaf01", "eth", "leaf", "192.0.2.10", "24", "192.0.2.1",
                "02:00:00:00:00:01", "", "", "", "",
            ])

        outputs = {}
        for name in (
            "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
        ):
            path = dhcp_dir / name
            path.write_text(f"{name}\n", encoding="utf-8")
            outputs[name] = {"sha256": sha256(path)}
        (dhcp_dir / "dhcp-release-manifest.json").write_text(json.dumps({
            "schema_version": 1,
            "release_id": "dhcp-release",
            "outputs": outputs,
            "devices": [{
                "hostname": "leaf01", "type": "eth", "interface": "eth0",
                "mac": "02:00:00:00:00:01", "identity_state": "identified",
            }],
        }), encoding="utf-8")
        (cumulus_release / "leaf01.yaml").write_text("set: {}\n", encoding="utf-8")
        (cumulus_release / "020000000001.yaml").symlink_to("leaf01.yaml")
        (cumulus_release / "default.yaml").write_text("- set: {}\n", encoding="utf-8")
        (cumulus_release / ".published-complete").write_text(
            "complete\n", encoding="utf-8"
        )
        (cumulus_release / "release-manifest.json").write_text(json.dumps({
            "schema_version": 1,
            "release_id": "cumulus-release",
            "effective_default": "default.yaml",
            "effective_default_sha256": sha256(cumulus_release / "default.yaml"),
            "devices": [{
                "hostname": "leaf01", "type": "eth",
                "macs": ["02:00:00:00:00:01"], "identity_state": "managed",
                "config": "leaf01.yaml",
                "config_sha256": sha256(cumulus_release / "leaf01.yaml"),
            }],
        }), encoding="utf-8")
        self.old_ztp_dir = LOAD.ZTP_DIR
        LOAD.ZTP_DIR = self.ztp
        settings = LOAD.GlobalSettings(
            dhcp_enabled=True, dhcp_package="isc-dhcp-server",
            http_enabled=True, http_package="apache2", http_root=self.root,
            ztp_enabled=True, ztp_prefix="/ztp", ztp_ips={}, versions={},
        )
        self.inputs = LOAD.ProjectInputs(
            global_file=self.global_file, devices_file=self.devices_file,
            subnet_file=self.subnet_file, p2p_file=self.p2p_file,
            device_types=frozenset({"eth"}), pubkeys=(), settings=settings,
        )

    def tearDown(self) -> None:
        LOAD.ZTP_DIR = self.old_ztp_dir
        self.temporary.cleanup()

    def _exercise_main_transaction_failure(self, failure: BaseException):
        args = SimpleNamespace(
            skip_doca=False, download_doca=False, dry_run=False,
            project=str(self.project), no_upgrade=True, p2p_file=None,
            skip_infra=True, skip_generate=False, start_services=False,
            start_ztp_monitor=False, ztp_monitor_scope="auto",
            ztp_monitor_interval=30,
        )
        candidate = LOAD.prepare_current_release(
            self.project,
            {"schema_version": 1, "release_id": "failure-candidate"},
        )
        quiesce = mock.Mock()
        restore_links = mock.Mock()
        restore_prefix = mock.Mock()
        release_lock = mock.Mock()
        caught = None
        result = None
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(LOAD, "parse_args", return_value=args))
            stack.enter_context(mock.patch.object(LOAD, "acquire_deployment_lock", return_value=91))
            stack.enter_context(mock.patch.object(LOAD, "release_deployment_lock", release_lock))
            stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Linux"))
            stack.enter_context(mock.patch.object(LOAD, "supports_local_ztp_services", return_value=True))
            stack.enter_context(mock.patch.object(LOAD, "resolve_project", return_value=self.project))
            stack.enter_context(mock.patch.object(LOAD, "initialize_from_template"))
            stack.enter_context(mock.patch.object(LOAD, "validate_inputs", return_value=(self.inputs, {})))
            stack.enter_context(mock.patch.object(LOAD, "validate_management_host", return_value=True))
            stack.enter_context(mock.patch.object(LOAD, "quiesce_services", quiesce))
            stack.enter_context(mock.patch.object(LOAD, "activate_project"))
            stack.enter_context(mock.patch.object(LOAD, "render_ztp_runtime"))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_ztp_prefix_publication",
                return_value=mock.sentinel.prefix_snapshot,
            ))
            stack.enter_context(mock.patch.object(LOAD, "configure_ztp_prefix_publication"))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_release_links",
                return_value={self.project / "99-output-eth/latest": "old-release"},
            ))
            stack.enter_context(mock.patch.object(LOAD, "generate_configs"))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_and_publish_release",
                return_value={"schema_version": 1, "release_id": "failure-candidate"},
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "prepare_current_release", return_value=candidate,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "mount_and_test_dhcp", side_effect=failure,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "restore_release_links", restore_links,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "restore_ztp_prefix_publication", restore_prefix,
            ))
            try:
                result = LOAD.main([])
            except BaseException as exc:  # Assert propagation after cleanup below.
                caught = exc
        return (
            result, caught, candidate, quiesce, restore_links,
            restore_prefix, release_lock,
        )

    def test_writes_parent_release_after_all_components_match(self) -> None:
        result = LOAD.validate_and_publish_release(self.project, self.inputs)
        self.assertEqual(result["validation"], "passed")
        self.assertEqual(set(result["components"]), {"dhcp", "cumulus"})
        current = self.project / "99-output-ztp/current-release.json"
        self.assertEqual(json.loads(current.read_text())["release_id"], result["release_id"])

    def test_rejects_stale_cumulus_latest(self) -> None:
        manifest = self.project / (
            "99-output-eth/20260830_120000_combine/release-manifest.json"
        )
        data = json.loads(manifest.read_text())
        data["devices"][0]["hostname"] = "old-leaf"
        manifest.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(LOAD.LoadError, "设备清单漂移"):
            LOAD.validate_and_publish_release(self.project, self.inputs)

    def test_parent_release_rejects_aliased_manifest_and_marker(self) -> None:
        release = self.project / "99-output-eth/20260830_120000_combine"
        manifest = release / "release-manifest.json"
        manifest_copy = self.root / "manifest-copy.json"
        manifest_copy.write_bytes(manifest.read_bytes())
        manifest.unlink()
        manifest.symlink_to(manifest_copy)
        with self.assertRaisesRegex(LOAD.LoadError, "非符号链接"):
            LOAD.validate_and_publish_release(self.project, self.inputs)

        manifest.unlink()
        manifest.write_bytes(manifest_copy.read_bytes())
        marker = release / ".published-complete"
        os.link(marker, self.root / "marker-second-name")
        with self.assertRaisesRegex(LOAD.LoadError, "单硬链接"):
            LOAD.validate_and_publish_release(self.project, self.inputs)

    def test_rejects_dhcp_output_modified_after_manifest(self) -> None:
        (self.ztp / "config/isc-dhcp-server/dhcpd.conf").write_text(
            "modified\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(LOAD.LoadError, "输出 hash 漂移"):
            LOAD.validate_and_publish_release(self.project, self.inputs)

    def test_parent_rejects_tampered_child_yaml_or_effective_default(self) -> None:
        release = self.project / "99-output-eth/20260830_120000_combine"
        (release / "leaf01.yaml").write_text("set:\n  changed: true\n", encoding="utf-8")
        with self.assertRaisesRegex(LOAD.LoadError, "专属 YAML hash 漂移"):
            LOAD.validate_and_publish_release(self.project, self.inputs)

        (release / "leaf01.yaml").write_text("set: {}\n", encoding="utf-8")
        (release / "default.yaml").write_text(
            "- set:\n    changed: true\n", encoding="utf-8",
        )
        with self.assertRaisesRegex(LOAD.LoadError, "effective default hash 漂移"):
            LOAD.validate_and_publish_release(self.project, self.inputs)

    def test_parent_rejects_missing_wrong_or_extra_mac_yaml_links(self) -> None:
        release = self.project / "99-output-eth/20260830_120000_combine"
        link = release / "020000000001.yaml"

        link.unlink()
        with self.assertRaisesRegex(LOAD.LoadError, "MAC YAML 链接缺失"):
            LOAD.validate_and_publish_release(self.project, self.inputs)

        link.symlink_to("default.yaml")
        with self.assertRaisesRegex(LOAD.LoadError, "MAC YAML 链接目标错误"):
            LOAD.validate_and_publish_release(self.project, self.inputs)

        link.unlink()
        link.symlink_to("leaf01.yaml")
        (release / "020000000099.yaml").symlink_to("leaf01.yaml")
        with self.assertRaisesRegex(LOAD.LoadError, "链接集合漂移"):
            LOAD.validate_and_publish_release(self.project, self.inputs)

        (release / "020000000099.yaml").unlink()
        (release / "020000000099.yaml").write_text("set: {}\n", encoding="utf-8")
        with self.assertRaisesRegex(LOAD.LoadError, "MAC YAML 入口不是软链接"):
            LOAD.validate_and_publish_release(self.project, self.inputs)

    def test_non_dry_skip_generate_is_rejected_before_any_mutation(self) -> None:
        output = mock.mock_open()
        with mock.patch.object(LOAD, "acquire_deployment_lock") as lock, \
                mock.patch.object(LOAD, "quiesce_services") as quiesce, \
                mock.patch.object(LOAD, "activate_project") as activate, \
                mock.patch("builtins.print", output):
            result = LOAD.main([str(self.project), "--skip-generate"])
        self.assertEqual(1, result)
        lock.assert_not_called()
        quiesce.assert_not_called()
        activate.assert_not_called()
        rendered = "\n".join(
            " ".join(str(part) for part in call.args)
            for call in output.mock_calls if call.args
        )
        self.assertIn("--skip-generate 已禁止用于实际 load", rendered)

    def test_air_only_json_identity_is_part_of_parent_release(self) -> None:
        air_json = self.ztp / "config/isc-dhcp-server/p2p-air.json"
        air_json.write_text(json.dumps({
            "content": {"nodes": {
                "AIR-FW01": {
                    "os": "cumulus-vx",
                    "management_interfaces": {
                        "eth0": {"mac_address": "02:00:00:00:00:aa"},
                    },
                },
            }},
        }), encoding="utf-8")
        dhcp_manifest = self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json"
        dhcp = json.loads(dhcp_manifest.read_text())
        dhcp["devices"].append({
            "hostname": "AIR-FW01", "type": "air", "interface": "eth0",
            "mac": "02:00:00:00:00:aa", "identity_state": "identified",
        })
        dhcp_manifest.write_text(json.dumps(dhcp), encoding="utf-8")

        release = self.project / "99-output-eth/20260830_120000_combine/release-manifest.json"
        cumulus = json.loads(release.read_text())
        air_yaml = release.parent / "AIR-FW01.yaml"
        air_yaml.write_text(
            "- set:\n    system:\n      hostname: AIR-FW01\n", encoding="utf-8",
        )
        (release.parent / "0200000000aa.yaml").symlink_to("AIR-FW01.yaml")
        cumulus["devices"].append({
            "hostname": "AIR-FW01", "environment": "air",
            "profile": "baseline", "macs": ["02:00:00:00:00:aa"],
            "identity_state": "managed", "config": "AIR-FW01.yaml",
            "config_sha256": sha256(air_yaml),
        })
        release.write_text(json.dumps(cumulus), encoding="utf-8")

        result = LOAD.validate_and_publish_release(self.project, self.inputs)
        identities = {item["hostname"]: item for item in result["inventory"]}
        self.assertEqual(identities["AIR-FW01"]["identity_source"], "air_json")
        self.assertEqual(identities["AIR-FW01"]["eth0_mac"], "02:00:00:00:00:aa")

    def test_manual_preflight_binds_parent_to_the_exact_current_child(self) -> None:
        parent = LOAD.validate_and_publish_release(self.project, self.inputs)
        device = {
            "hostname": "leaf01", "type": "eth",
            "mac_plain": "020000000001",
            "identity_macs": {"eth0": "020000000001"},
        }
        with mock.patch.object(
            MANUAL, "DHCP_RELEASE_MANIFEST",
            self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json",
        ):
            binding = MANUAL.validate_parent_release_binding(self.project, device)
            self.assertEqual(parent["release_id"], binding["parent_release_id"])
            self.assertEqual("cumulus-release", binding["child_release_id"])

            # Even a no-content re-publication changes the parent file hash,
            # so an old GUI preview cannot be confirmed across load runs.
            parent_path = self.project / "99-output-ztp/current-release.json"
            republished = json.loads(parent_path.read_text(encoding="utf-8"))
            republished["generated_at"] = "2026-08-30T13:00:00+00:00"
            parent_path.write_text(json.dumps(republished), encoding="utf-8")
            rebound = MANUAL.validate_parent_release_binding(self.project, device)
            self.assertNotEqual(binding["binding_sha256"], rebound["binding_sha256"])

            old_release = self.project / "99-output-eth/20260830_120000_combine"
            other_release = self.project / "99-output-eth/20260830_130000_combine"
            shutil.copytree(old_release, other_release)
            latest = self.project / "99-output-eth/latest"
            latest.unlink()
            latest.symlink_to(other_release.name)
            with self.assertRaisesRegex(MANUAL.ManualZtpError, "不属于同一代"):
                MANUAL.validate_parent_release_binding(self.project, device)

    def test_manual_preflight_rejects_inputs_changed_after_parent_commit(self) -> None:
        LOAD.validate_and_publish_release(self.project, self.inputs)
        self.p2p_file.write_text("changed after load\n", encoding="utf-8")
        device = {
            "hostname": "leaf01", "type": "eth",
            "mac_plain": "020000000001",
            "identity_macs": {"eth0": "020000000001"},
        }
        with mock.patch.object(
            MANUAL, "DHCP_RELEASE_MANIFEST",
            self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json",
        ), self.assertRaisesRegex(MANUAL.ManualZtpError, "p2p.xlsx 已变化"):
            MANUAL.validate_parent_release_binding(self.project, device)

    def test_manual_preflight_binds_optional_air_policy_from_parent_release(self) -> None:
        policy = self.project / "03-air-topology-policy.json"
        policy.write_text("{}\n", encoding="utf-8")
        inputs = LOAD.replace(self.inputs, air_topology_policy=policy)
        LOAD.validate_and_publish_release(self.project, inputs)
        device = {
            "hostname": "leaf01", "type": "eth",
            "mac_plain": "020000000001",
            "identity_macs": {"eth0": "020000000001"},
        }
        with mock.patch.object(
            MANUAL, "DHCP_RELEASE_MANIFEST",
            self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json",
        ):
            MANUAL.validate_parent_release_binding(self.project, device)
            policy.write_text('{"changed": true}\n', encoding="utf-8")
            with self.assertRaisesRegex(MANUAL.ManualZtpError, "AIR.*已变化"):
                MANUAL.validate_parent_release_binding(self.project, device)
            policy.unlink()
            with self.assertRaisesRegex(MANUAL.ManualZtpError, "AIR.*无法读取"):
                MANUAL.validate_parent_release_binding(self.project, device)

    def test_manual_preflight_rejects_aliased_child_release_controls(self) -> None:
        LOAD.validate_and_publish_release(self.project, self.inputs)
        release = self.project / "99-output-eth/20260830_120000_combine"
        manifest = release / "release-manifest.json"
        outside = self.root / "outside-release-manifest.json"
        outside.write_bytes(manifest.read_bytes())
        manifest.unlink()
        manifest.symlink_to(outside)
        device = {
            "hostname": "leaf01", "type": "eth",
            "mac_plain": "020000000001",
            "identity_macs": {"eth0": "020000000001"},
        }
        with mock.patch.object(
            MANUAL, "DHCP_RELEASE_MANIFEST",
            self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json",
        ), self.assertRaisesRegex(MANUAL.ManualZtpError, "非符号链接"):
            MANUAL.validate_parent_release_binding(self.project, device)

    def test_manual_preflight_rejects_child_yaml_or_dhcp_output_drift(self) -> None:
        LOAD.validate_and_publish_release(self.project, self.inputs)
        device = {
            "hostname": "leaf01", "type": "eth",
            "mac_plain": "020000000001",
            "identity_macs": {"eth0": "020000000001"},
        }
        dhcp_manifest = self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json"
        with mock.patch.object(MANUAL, "DHCP_RELEASE_MANIFEST", dhcp_manifest):
            yaml_path = self.project / (
                "99-output-eth/20260830_120000_combine/leaf01.yaml"
            )
            yaml_path.write_text("set:\n  changed: true\n", encoding="utf-8")
            with self.assertRaisesRegex(MANUAL.ManualZtpError, "专属 YAML.*未绑定"):
                MANUAL.validate_parent_release_binding(self.project, device)

            yaml_path.write_text("set: {}\n", encoding="utf-8")
            dhcp_conf = dhcp_manifest.parent / "dhcpd.conf"
            dhcp_conf.write_text("out-of-band edit\n", encoding="utf-8")
            with self.assertRaisesRegex(MANUAL.ManualZtpError, "dhcpd.conf.*hash 不一致"):
                MANUAL.validate_parent_release_binding(self.project, device)

    def test_preflight_fingerprint_contains_parent_binding_and_rechecks_it(self) -> None:
        parent = LOAD.validate_and_publish_release(self.project, self.inputs)
        device = {
            "hostname": "leaf01", "type": "eth", "ip": "192.0.2.10",
            "mac_plain": "020000000001",
            "identity_macs": {"eth0": "020000000001"},
        }
        client = mock.Mock()
        client.args.command_timeout = 10
        client.run.return_value = SimpleNamespace(
            returncode=0, stdout="set: {}\n", stderr="",
        )
        dhcp_manifest = self.ztp / "config/isc-dhcp-server/dhcp-release-manifest.json"
        with tempfile.TemporaryDirectory() as evidence_dir, mock.patch.object(
            MANUAL, "DHCP_RELEASE_MANIFEST", dhcp_manifest,
        ), mock.patch.object(
            MANUAL, "connect_and_verify", return_value=("192.0.2.10", "eth0"),
        ):
            evidence = MANUAL.preflight_one(
                client, self.project, device, Path(evidence_dir),
            )
            self.assertEqual(parent["release_id"], evidence["parent_release_id"])
            self.assertNotEqual(
                evidence["expected_sha256"], evidence["expected_yaml_sha256"],
            )
            current = self.project / "99-output-ztp/current-release.json"
            changed = json.loads(current.read_text(encoding="utf-8"))
            changed["generated_at"] = "2026-08-30T14:00:00+00:00"
            current.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(MANUAL.ManualZtpError, "绑定文件已变化"):
                MANUAL.verify_prepared_release_binding(evidence)

    def test_global_deployment_lock_excludes_load_and_manual_operations(self) -> None:
        lock_path = self.root / ".deployment.lock"
        with mock.patch.object(LOAD, "DEPLOYMENT_LOCK", lock_path), mock.patch.object(
            MANUAL, "DEPLOYMENT_LOCK", lock_path,
        ):
            load_lock = LOAD.acquire_deployment_lock(exclusive=True)
            try:
                with self.assertRaisesRegex(MANUAL.ManualZtpError, "load 正在切换"):
                    MANUAL.acquire_deployment_lock()
            finally:
                LOAD.release_deployment_lock(load_lock)

            manual_lock = MANUAL.acquire_deployment_lock()
            try:
                with self.assertRaisesRegex(LOAD.LoadError, "另一个 load"):
                    LOAD.acquire_deployment_lock(exclusive=True)
            finally:
                MANUAL.release_deployment_lock(manual_lock)

    def test_parent_publish_failure_rolls_back_installed_dhcp_files(self) -> None:
        source_dir = self.root / "generated-dhcp"
        destination_dir = self.root / "etc-dhcp"
        source_dir.mkdir()
        destination_dir.mkdir()
        mappings = {}
        for name in (
            "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
        ):
            source = source_dir / name
            destination = destination_dir / name
            source.write_text(f"new:{name}\n", encoding="utf-8")
            destination.write_text(f"old:{name}\n", encoding="utf-8")
            mappings[source] = destination
        # Keep the staged include-rewrite path exercised.
        (source_dir / "dhcpd.conf").write_text(
            "\n".join(
                f'include "/etc/dhcp/{name}";'
                for name in ("dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts")
            ) + "\n",
            encoding="utf-8",
        )
        candidate = LOAD.prepare_current_release(
            self.project,
            {"schema_version": 1, "release_id": "candidate", "validation": "passed"},
        )

        def fake_run(command, **_kwargs):
            operation = command[0]
            if operation == "dhcpd":
                return
            if operation == "install":
                if "-d" in command:
                    mode = int(command[command.index("-m") + 1], 8)
                    for item in command[command.index("--") + 1:]:
                        Path(item).mkdir(parents=True, exist_ok=True)
                        Path(item).chmod(mode)
                    return
                shutil.copy2(command[-2], command[-1])
                return
            if operation == "cp":
                shutil.copy2(command[-2], command[-1])
                return
            raise AssertionError(command)

        def fake_subprocess_run(command, **_kwargs):
            if command[0] == "rm":
                target = Path(command[-1])
                if "-rf" in command:
                    shutil.rmtree(target, ignore_errors=True)
                else:
                    target.unlink(missing_ok=True)
            elif command[0] == "cp":
                shutil.copy2(command[-2], command[-1])
            elif command[0] == "rmdir":
                Path(command[-1]).rmdir()
            else:
                raise AssertionError(command)
            return SimpleNamespace(returncode=0)

        try:
            with mock.patch.object(LOAD, "dhcp_file_mappings", return_value=mappings), \
                    mock.patch.object(LOAD, "sudo_command", side_effect=lambda *args: list(args)), \
                    mock.patch.object(LOAD, "run", side_effect=fake_run), \
                    mock.patch.object(LOAD.subprocess, "run", side_effect=fake_subprocess_run), \
                    mock.patch.object(
                        LOAD, "commit_prepared_release",
                        side_effect=OSError("injected parent replace failure"),
                    ):
                with self.assertRaisesRegex(OSError, "injected parent replace failure"):
                    LOAD.mount_and_test_dhcp(parent_candidate=candidate)
            for destination in mappings.values():
                self.assertEqual(
                    f"old:{destination.name}\n", destination.read_text(encoding="utf-8")
                )
            self.assertFalse(candidate.committed)
            self.assertFalse(candidate.destination.exists())
        finally:
            LOAD.discard_prepared_release(candidate)

    def test_dhcp_preflight_uses_apparmor_readable_unpublished_staging(self) -> None:
        source_dir = self.root / "permission-source-dhcp"
        destination_dir = self.root / "etc-dhcp-permission-contract"
        source_dir.mkdir()
        destination_dir.mkdir()
        names = (
            "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
        )
        mappings = {}
        for name in names:
            source = source_dir / name
            destination = destination_dir / name
            source.write_text(f"new:{name}\n", encoding="utf-8")
            destination.write_text(f"old:{name}\n", encoding="utf-8")
            mappings[source] = destination
        (source_dir / "dhcpd.conf").write_text(
            "\n".join(
                f'include "/etc/dhcp/{name}";'
                for name in names[1:]
            ) + "\n",
            encoding="utf-8",
        )

        syntax_checks = []

        def fake_run(command, **_kwargs):
            operation = command[0]
            if operation == "install":
                mode = int(command[command.index("-m") + 1], 8)
                if "-d" in command:
                    for item in command[command.index("--") + 1:]:
                        path = Path(item)
                        path.mkdir(parents=True, exist_ok=True)
                        path.chmod(mode)
                    return
                source = Path(command[-2])
                destination = Path(command[-1])
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
                destination.chmod(mode)
                return
            if operation == "cp":
                shutil.copy2(command[-2], command[-1])
                return
            if operation != "dhcpd":
                raise AssertionError(command)

            syntax_checks.append(command)
            config = Path(command[-1])
            if len(syntax_checks) == 1:
                staged_dir = config.parent
                transaction_dir = staged_dir.parent
                self.assertEqual(destination_dir, transaction_dir.parent)
                self.assertTrue(transaction_dir.name.startswith(
                    ".load-dhcp-transaction-"
                ))
                self.assertEqual(0o755, transaction_dir.stat().st_mode & 0o777)
                self.assertEqual(0o755, staged_dir.stat().st_mode & 0o777)
                self.assertEqual(0o644, config.stat().st_mode & 0o777)
                text = config.read_text(encoding="utf-8")
                for name in names[1:]:
                    staged_host = staged_dir / name
                    self.assertEqual(0o644, staged_host.stat().st_mode & 0o777)
                    self.assertIn(f'include "{staged_host}";', text)
                    self.assertNotIn(f'include "/etc/dhcp/{name}";', text)
                for destination in mappings.values():
                    self.assertEqual(
                        f"old:{destination.name}\n",
                        destination.read_text(encoding="utf-8"),
                    )
            else:
                self.assertEqual(Path("/etc/dhcp/dhcpd.conf"), config)
                for destination in mappings.values():
                    self.assertTrue(
                        destination.read_text(encoding="utf-8").startswith("new:")
                        or destination.name == "dhcpd.conf"
                    )

        with mock.patch.object(LOAD, "dhcp_file_mappings", return_value=mappings), \
                mock.patch.object(LOAD, "sudo_command", side_effect=lambda *args: list(args)), \
                mock.patch.object(LOAD, "run", side_effect=fake_run):
            LOAD.mount_and_test_dhcp()

        self.assertEqual(2, len(syntax_checks))
        self.assertEqual([], list(destination_dir.glob(".load-dhcp-transaction-*")))

    def test_dhcp_staging_rewrite_requires_each_canonical_include_once(self) -> None:
        names = ("dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts")
        original = "\n".join(
            f'include "/etc/dhcp/{name}";' for name in names
        ) + "\n"
        staged = self.root / "etc/dhcp/.load-dhcp-transaction-test/staged"
        rewritten = LOAD._rewrite_dhcp_staging_includes(original, staged)
        for name in names:
            self.assertIn(f'include "{staged / name}";', rewritten)
            self.assertNotIn(f'include "/etc/dhcp/{name}";', rewritten)

        with self.assertRaisesRegex(LOAD.LoadError, "必须且只能包含一次"):
            LOAD._rewrite_dhcp_staging_includes(
                original.replace(f'include "/etc/dhcp/{names[0]}";\n', ""),
                staged,
            )
        with self.assertRaisesRegex(LOAD.LoadError, "必须且只能包含一次"):
            LOAD._rewrite_dhcp_staging_includes(
                original + f'include "/etc/dhcp/{names[1]}";\n', staged,
            )

    def test_subnet_gate_rejects_router_inside_dynamic_range(self) -> None:
        subnet = self.root / "router-in-range.csv"
        subnet.write_text(
            "shared_network,subnet,netmask,range_start,range_end,routers,"
            "ztp_service_ip,cumulus_profile,nvos_ztp\n"
            "net,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.110,198.51.100.10,oob,no\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(LOAD.LoadError, "routers=.*落入动态 range"):
            LOAD.validate_subnet_file(subnet, self.inputs.settings)

    def test_subnet_gate_rejects_in_subnet_service_ip_inside_dynamic_range(self) -> None:
        subnet = self.root / "service-in-range.csv"
        subnet.write_text(
            "shared_network,subnet,netmask,range_start,range_end,routers,"
            "ztp_service_ip,cumulus_profile,nvos_ztp\n"
            "net,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.110,oob,no\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(LOAD.LoadError, "service_ip=.*落入动态 range"):
            LOAD.validate_subnet_file(subnet, self.inputs.settings)

    def test_custom_ztp_prefix_publication_is_idempotent_and_cleans_on_default(self) -> None:
        root = self.root / "http-prefix"
        ztp_dir = root / "ztp"
        marker = root / ".ztp-prefix-publication.json"
        ztp_dir.mkdir(parents=True)
        custom = LOAD.replace(
            self.inputs.settings,
            http_root=root,
            ztp_prefix="/day0/ztp",
        )
        builtin = LOAD.replace(custom, ztp_prefix="/ztp")
        with mock.patch.object(LOAD, "HTTP_ROOT", root), mock.patch.object(
            LOAD, "ZTP_DIR", ztp_dir,
        ), mock.patch.object(LOAD, "ZTP_PREFIX_MARKER", marker):
            destination = LOAD.configure_ztp_prefix_publication(custom)
            self.assertTrue(destination.is_symlink())
            self.assertEqual(ztp_dir.resolve(), destination.resolve())
            marker_before = marker.read_bytes()

            # A repeated load preserves the same link and marker content.
            self.assertEqual(
                destination,
                LOAD.configure_ztp_prefix_publication(custom),
            )
            self.assertEqual(marker_before, marker.read_bytes())

            # Returning to the built-in /ztp path removes only the link that
            # this loader recorded; the real ZTP directory remains untouched.
            self.assertEqual(
                ztp_dir,
                LOAD.configure_ztp_prefix_publication(builtin),
            )
            self.assertFalse(destination.exists())
            self.assertFalse(destination.is_symlink())
            self.assertFalse(marker.exists())
            self.assertTrue(ztp_dir.is_dir())

    def test_custom_ztp_prefix_publication_rejects_existing_path_conflict(self) -> None:
        root = self.root / "http-prefix-conflict"
        ztp_dir = root / "ztp"
        marker = root / ".ztp-prefix-publication.json"
        ztp_dir.mkdir(parents=True)
        destination = root / "day0/ztp"
        destination.mkdir(parents=True)
        settings = LOAD.replace(
            self.inputs.settings,
            http_root=root,
            ztp_prefix="/day0/ztp",
        )
        with mock.patch.object(LOAD, "HTTP_ROOT", root), mock.patch.object(
            LOAD, "ZTP_DIR", ztp_dir,
        ), mock.patch.object(LOAD, "ZTP_PREFIX_MARKER", marker):
            with self.assertRaisesRegex(LOAD.LoadError, "发布路径已被占用"):
                LOAD.configure_ztp_prefix_publication(settings)
        self.assertTrue(destination.is_dir())
        self.assertFalse(marker.exists())

    def test_custom_prefix_rejects_untracked_same_target_symlink(self) -> None:
        root = self.root / "http-prefix-untracked"
        ztp_dir = root / "ztp"
        marker = root / ".ztp-prefix-publication.json"
        ztp_dir.mkdir(parents=True)
        destination = root / "day0/ztp"
        destination.parent.mkdir(parents=True)
        destination.symlink_to(Path("../ztp"))
        settings = LOAD.replace(
            self.inputs.settings, http_root=root, ztp_prefix="/day0/ztp",
        )
        with mock.patch.object(LOAD, "HTTP_ROOT", root), mock.patch.object(
            LOAD, "ZTP_DIR", ztp_dir,
        ), mock.patch.object(LOAD, "ZTP_PREFIX_MARKER", marker):
            with self.assertRaisesRegex(LOAD.LoadError, "ownership marker"):
                LOAD.configure_ztp_prefix_publication(settings)
        self.assertTrue(destination.is_symlink())
        self.assertEqual(ztp_dir.resolve(), destination.resolve())
        self.assertFalse(marker.exists())

    def test_custom_prefix_rejects_broken_or_drifted_marker(self) -> None:
        root = self.root / "http-prefix-marker"
        ztp_dir = root / "ztp"
        marker = root / ".ztp-prefix-publication.json"
        ztp_dir.mkdir(parents=True)
        settings = LOAD.replace(
            self.inputs.settings, http_root=root, ztp_prefix="/day0/ztp",
        )
        with mock.patch.object(LOAD, "HTTP_ROOT", root), mock.patch.object(
            LOAD, "ZTP_DIR", ztp_dir,
        ), mock.patch.object(LOAD, "ZTP_PREFIX_MARKER", marker):
            marker.symlink_to("missing-marker.json")
            with self.assertRaisesRegex(LOAD.LoadError, "不是普通文件"):
                LOAD.configure_ztp_prefix_publication(settings)
            marker.unlink()

            destination = LOAD.configure_ztp_prefix_publication(settings)
            valid = json.loads(marker.read_text(encoding="utf-8"))
            drifted_path = dict(valid, path=str(root / "other"))
            marker.write_text(json.dumps(drifted_path), encoding="utf-8")
            with self.assertRaisesRegex(LOAD.LoadError, "prefix/path"):
                LOAD.configure_ztp_prefix_publication(settings)

            drifted_target = dict(valid, target=str(root / "other-target"))
            marker.write_text(json.dumps(drifted_target), encoding="utf-8")
            with self.assertRaisesRegex(LOAD.LoadError, "target"):
                LOAD.configure_ztp_prefix_publication(settings)

        self.assertTrue(destination.is_symlink())

    def test_prefix_snapshot_restores_old_link_after_precommit_failure(self) -> None:
        root = self.root / "http-prefix-rollback"
        ztp_dir = root / "ztp"
        marker = root / ".ztp-prefix-publication.json"
        ztp_dir.mkdir(parents=True)
        old = LOAD.replace(
            self.inputs.settings, http_root=root, ztp_prefix="/legacy/ztp",
        )
        new = LOAD.replace(old, ztp_prefix="/day0/ztp")
        with mock.patch.object(LOAD, "HTTP_ROOT", root), mock.patch.object(
            LOAD, "ZTP_DIR", ztp_dir,
        ), mock.patch.object(LOAD, "ZTP_PREFIX_MARKER", marker):
            old_path = LOAD.configure_ztp_prefix_publication(old)
            marker_before = marker.read_bytes()
            snapshot = LOAD.snapshot_ztp_prefix_publication(new)
            new_path = LOAD.configure_ztp_prefix_publication(new)
            self.assertFalse(old_path.is_symlink())
            self.assertTrue(new_path.is_symlink())

            # This is the same rollback invoked by main's catch block whenever
            # generation/DHCP/parent publication fails before parent commit.
            LOAD.restore_ztp_prefix_publication(snapshot)

            self.assertTrue(old_path.is_symlink())
            self.assertEqual(ztp_dir.resolve(), old_path.resolve())
            self.assertFalse(new_path.is_symlink())
            self.assertEqual(marker_before, marker.read_bytes())

    def test_prefix_rejects_percent_encoded_path_segments(self) -> None:
        with self.assertRaisesRegex(LOAD.LoadError, "安全绝对 URL path"):
            LOAD._validate_ztp_prefix("/safe/%2e%2e/ztp")
        global_yaml = self.root / "encoded-prefix.yaml"
        global_yaml.write_text(
            "common:\n  mgmt:\n    ztp:\n      ztp_url_prefix: /safe/%2f/ztp\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(MANUAL.ManualZtpError, "安全绝对 URL path"):
            MANUAL.global_ztp_url_prefix(global_yaml)

    def test_off_link_endpoint_has_no_binding_but_still_requires_exact_local_ip(self) -> None:
        subnet = self.root / "off-link-service.csv"
        subnet.write_text(
            "shared_network,subnet,netmask,range_start,range_end,routers,"
            "ztp_service_ip,cumulus_profile,nvos_ztp\n"
            "clients,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,198.51.100.10,oob,no\n",
            encoding="utf-8",
        )
        settings = LOAD.replace(
            self.inputs.settings,
            ztp_ips={"prod_oob": ("198.51.100.10",)},
        )
        inputs = LOAD.replace(
            self.inputs, subnet_file=subnet, settings=settings,
        )
        self.assertEqual((), LOAD.service_ip_bindings(inputs))
        self.assertEqual(
            ["198.51.100.10"],
            LOAD.missing_service_ip_addresses(settings.service_ips, {}),
        )
        # Routed endpoints have no CIDR inferred from the client subnet. The
        # exact address may use any real local prefix and must not be skipped.
        assignments = {"198.51.100.10": {("eth9", 30)}}
        self.assertEqual(
            [],
            LOAD.missing_service_ip_addresses(settings.service_ips, assignments),
        )

        noninteractive = mock.Mock()
        noninteractive.isatty.return_value = False
        with mock.patch.object(
            LOAD, "_local_ipv4_assignments", return_value={},
        ), mock.patch.object(LOAD.sys, "stdin", noninteractive):
            with self.assertRaisesRegex(LOAD.LoadError, "非交互模式"):
                LOAD.ensure_ztp_url_network_ready(inputs)

    def test_prepare_infra_explicitly_defers_service_activation(self) -> None:
        with mock.patch.object(LOAD, "run") as run_command, mock.patch.object(
            LOAD, "select_http_ip", return_value="192.0.2.1",
        ):
            LOAD.prepare_infra(self.inputs, skip_doca=True)
        commands = [call.args[0] for call in run_command.call_args_list]
        setup = next(
            command for command in commands
            if any(str(item).endswith("infra-setup.sh") for item in command)
        )
        self.assertIn("--mgmt", setup)
        self.assertIn("--defer-services", setup)
        self.assertIn("--install-apache", setup)
        self.assertIn("--install-dhcp", setup)

    def test_service_start_failure_restores_entry_enabled_and_active_state(self) -> None:
        states = {
            "apache2": LOAD.ServiceRuntimeState(enabled=True, active=False),
            "isc-dhcp-server": LOAD.ServiceRuntimeState(enabled=False, active=True),
        }
        events = []
        restart_failed = False

        def fake_run(command, **_kwargs):
            nonlocal restart_failed
            normalized = command[-3:]
            events.append(tuple(normalized))
            if normalized == ["systemctl", "restart", "isc-dhcp-server"] and not restart_failed:
                restart_failed = True
                raise LOAD.LoadError("injected DHCP restart failure")

        with mock.patch.object(
            LOAD, "ensure_ztp_url_network_ready", side_effect=lambda *_a, **_k: events.append("gate"),
        ), mock.patch.object(
            LOAD, "snapshot_service_states",
            side_effect=lambda *_a, **_k: (events.append("snapshot") or states),
        ), mock.patch.object(LOAD, "run", side_effect=fake_run), mock.patch.object(
            LOAD, "verify_http_publication",
        ):
            with self.assertRaisesRegex(LOAD.LoadError, "injected DHCP restart failure"):
                LOAD.start_services(self.inputs, {})

        self.assertEqual(events[:2], ["gate", "snapshot"])
        self.assertIn(("systemctl", "stop", "apache2"), events)
        self.assertIn(("systemctl", "stop", "isc-dhcp-server"), events)
        self.assertIn(("systemctl", "enable", "apache2"), events)
        self.assertIn(("systemctl", "disable", "isc-dhcp-server"), events)
        self.assertIn(("systemctl", "start", "isc-dhcp-server"), events)

    def test_main_value_error_rolls_back_links_parent_temp_and_services(self) -> None:
        result, caught, candidate, quiesce, restore, restore_prefix, release_lock = (
            self._exercise_main_transaction_failure(ValueError("injected value error"))
        )
        self.assertEqual(result, 1)
        self.assertIsNone(caught)
        self.assertFalse(candidate.temporary.exists())
        restore.assert_called_once()
        restore_prefix.assert_called_once_with(mock.sentinel.prefix_snapshot)
        self.assertEqual(quiesce.call_count, 2)
        release_lock.assert_called_once_with(91)

    def test_main_keyboard_interrupt_cleans_up_then_propagates(self) -> None:
        result, caught, candidate, quiesce, restore, restore_prefix, release_lock = (
            self._exercise_main_transaction_failure(KeyboardInterrupt())
        )
        self.assertIsNone(result)
        self.assertIsInstance(caught, KeyboardInterrupt)
        self.assertFalse(candidate.temporary.exists())
        restore.assert_called_once()
        restore_prefix.assert_called_once_with(mock.sentinel.prefix_snapshot)
        self.assertEqual(quiesce.call_count, 2)
        release_lock.assert_called_once_with(91)

    def test_generate_configs_passes_global_eth_version_to_air_topology(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            LOAD, "ZTP_DIR", Path(directory),
        ), mock.patch.object(LOAD, "run") as runner:
            LOAD.generate_configs(
                frozenset({"eth"}), install_dhcp=False, dry_run=True,
                eth_version="5.18",
            )

        self.assertEqual(
            [
                sys.executable, "b-xlsx_to_dot.py", "-y",
                "--os-version", "5.18",
            ],
            runner.call_args_list[0].args[0],
        )

    def test_global_eth_version_reaches_oobofoob_air_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            global_file = root / "01-global.yaml"
            global_file.write_text(
                "schema_version: 2\n"
                "common:\n"
                "  mgmt:\n"
                "    dhcp-server: {status: enabled, package: isc-dhcp-server}\n"
                "    http: {status: enabled, package: apache2, http_root: /srv/http}\n"
                "    ztp: {status: enabled, ztp_url_prefix: /ztp}\n"
                "  switch:\n"
                "    system:\n"
                "      dns: {}\n"
                "      ntp: {}\n"
                "      date-time: {}\n"
                "switches:\n"
                "  - eth:\n"
                "      version: '5.18'\n"
                "      vrr: {base_mac: '02:00:5e:01:00:00'}\n",
                encoding="utf-8",
            )
            settings = LOAD.load_global(global_file)
            lldpq = root / "source-lldpq.dot"
            lldpq.write_text(
                'graph synthetic {\n'
                '"example-oobofoob-leaf10":"swp1" -- '
                '"example-oob-core01":"swp1"\n'
                '}\n',
                encoding="utf-8",
            )
            air_dot = root / "air.dot"
            air_json = root / "air.json"

            def run_and_materialize_air(command, **_kwargs):
                if len(command) < 2 or command[1] != "b-xlsx_to_dot.py":
                    return
                version = command[command.index("--os-version") + 1]
                patterns = {"Eth-SW": ["example-*"]}
                order = ["Eth-SW"]
                TOPOLOGY.generate_air_dot(
                    lldpq, air_dot, patterns, order,
                    os_version=version,
                    template_file=TOPOLOGY.AIR_JSON_TEMPLATE,
                )
                TOPOLOGY.generate_air_json(
                    air_dot, air_json, TOPOLOGY.AIR_JSON_TEMPLATE,
                    lldpq_file=lldpq,
                )

            with mock.patch.object(
                LOAD, "ZTP_DIR", root / "ztp",
            ), mock.patch.object(
                LOAD, "run", side_effect=run_and_materialize_air,
            ) as runner:
                LOAD.generate_configs(
                    frozenset({"eth"}), install_dhcp=False, dry_run=True,
                    eth_version=settings.versions["eth"],
                )

            self.assertEqual(
                "5.18",
                runner.call_args_list[0].args[0][
                    runner.call_args_list[0].args[0].index("--os-version") + 1
                ],
            )
            nodes = json.loads(
                air_json.read_text(encoding="utf-8")
            )["content"]["nodes"]
            self.assertEqual(
                {"cumulus-vx-5.18"},
                {node["os"] for node in nodes.values()},
            )

    def test_load_dhcp_workflow_uses_most_specific_air_production_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ztp = root / "ztp"
            dhcp_dir = ztp / "config/isc-dhcp-server"
            dhcp_dir.mkdir(parents=True)
            global_file = dhcp_dir / "01-global.yaml"
            global_file.write_text(
                "common:\n"
                "  mgmt:\n"
                "    ztp:\n"
                "      ztp_url_prefix: /ztp\n",
                encoding="utf-8",
            )
            devices_file = dhcp_dir / "02-devices_config.csv"
            devices_file.write_text(
                "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,"
                "eth1_ip,netmask,eth1_gw,eth1_mac\n"
                "oob-pod3-leaf03,eth,leaf,192.0.2.10,24,192.0.2.1,"
                "02:00:00:00:00:10,,,,\n"
                "oobofoob-pod3-leaf03,eth,leaf,192.0.2.11,24,192.0.2.1,"
                "02:00:00:00:00:11,,,,\n"
                "border01,eth,leaf,192.0.2.12,24,192.0.2.1,"
                "02:00:00:00:00:12,,,,\n",
                encoding="utf-8",
            )
            subnet_file = dhcp_dir / "02-subnet_config.csv"
            subnet_file.write_text(
                "shared_network,subnet,netmask,range_start,range_end,routers,"
                "ztp_service_ip,cumulus_profile,nvos_ztp\n"
                "oob,192.0.2.0,255.255.255.0,192.0.2.200,192.0.2.220,"
                "192.0.2.1,192.0.2.2,oob,no\n",
                encoding="utf-8",
            )
            air_json = dhcp_dir / "p2p-air.json"
            air_json.write_text(json.dumps({
                "content": {"nodes": {
                    "AIR-example-site-oobofoob-pod3-leaf03": {
                        "os": "cumulus-vx-5.18",
                        "management_interfaces": {
                            "eth0": {"mac_address": "02:00:00:00:01:11"},
                        },
                    },
                    "AIR-evilborder01": {
                        "os": "cumulus-vx-5.18",
                        "management_interfaces": {
                            "eth0": {"mac_address": "02:00:00:00:01:12"},
                        },
                    },
                }},
            }), encoding="utf-8")
            manifest = dhcp_dir / "dhcp-release-manifest.json"

            def run_real_dhcp(command, **_kwargs):
                if len(command) < 2 or command[1] != "c1-generate_dhcp.py":
                    return
                with mock.patch.object(
                    sys, "argv", ["c1-generate_dhcp.py", "-y"],
                ):
                    DHCP.main()

            with mock.patch.object(
                LOAD, "ZTP_DIR", ztp,
            ), mock.patch.object(
                LOAD, "run", side_effect=run_real_dhcp,
            ), mock.patch.multiple(
                DHCP,
                SCRIPT_DIR=str(dhcp_dir),
                OUTPUT_ETH=str(dhcp_dir / "dhcpd_eth.hosts"),
                OUTPUT_IB=str(dhcp_dir / "dhcpd_ib.hosts"),
                OUTPUT_NVL=str(dhcp_dir / "dhcpd_nvl.hosts"),
                OUTPUT_CONF=str(dhcp_dir / "dhcpd.conf"),
                OUTPUT_MANIFEST=str(manifest),
                SUBNET_CSV=str(subnet_file),
                GLOBAL_YAML=str(global_file),
                P2P_AIR_JSON=str(air_json),
                DEVICES_CSV=str(devices_file),
                _AUTO_YES=False,
            ):
                LOAD.generate_configs(
                    frozenset({"eth"}), install_dhcp=False, dry_run=True,
                )

            devices = json.loads(
                manifest.read_text(encoding="utf-8")
            )["devices"]
            production_hostnames = [
                "oob-pod3-leaf03", "oobofoob-pod3-leaf03", "border01",
            ]
            self.assertTrue(SETUP._is_matching_production_air_pair(
                "oobofoob-pod3-leaf03", "eth",
                "AIR-example-site-oobofoob-pod3-leaf03", "air",
                production_hostnames,
            ))
            self.assertFalse(SETUP._is_matching_production_air_pair(
                "oob-pod3-leaf03", "eth",
                "AIR-example-site-oobofoob-pod3-leaf03", "air",
                production_hostnames,
            ))
            self.assertFalse(SETUP._is_matching_production_air_pair(
                "border01", "eth", "AIR-evilborder01", "air",
                production_hostnames,
            ))
            air_device = next(
                item for item in devices
                if item["hostname"] == "AIR-example-site-oobofoob-pod3-leaf03"
            )
            self.assertEqual("192.0.2.11", air_device["planned_ip"])
            self.assertEqual("fixed", air_device["dhcp_assignment"])
            boundary_device = next(
                item for item in devices
                if item["hostname"] == "AIR-evilborder01"
            )
            self.assertIsNone(boundary_device["planned_ip"])
            self.assertIsNone(boundary_device["fixed_address"])
            self.assertEqual("dynamic_known", boundary_device["dhcp_assignment"])

    def test_generate_configs_passes_project_air_topology_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            LOAD, "ZTP_DIR", Path(directory),
        ), mock.patch.object(LOAD, "run") as runner:
            policy = Path(directory) / "03-air-topology-policy.json"
            policy.write_text("{}\n", encoding="utf-8")
            LOAD.generate_configs(
                frozenset({"eth"}), install_dhcp=False, dry_run=True,
                eth_version="5.18", air_topology_policy=policy,
            )

        self.assertEqual(
            [
                sys.executable, "b-xlsx_to_dot.py", "-y",
                "--os-version", "5.18",
                "--air-link-policy", str(policy),
            ],
            runner.call_args_list[0].args[0],
        )

    def test_project_air_topology_policy_uses_fixed_optional_filename(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            self.assertIsNone(LOAD.project_air_topology_policy(project))
            policy = project / "03-air-topology-policy.json"
            policy.write_text("{}\n", encoding="utf-8")
            self.assertEqual(policy, LOAD.project_air_topology_policy(project))
            policy.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(LOAD.LoadError, "大小为 0"):
                LOAD.project_air_topology_policy(project)

    def test_macos_preparation_does_not_publish_runtime_ztp_prefix(self) -> None:
        """Remote Linux HTTP paths are declarative input on a macOS workstation."""
        args = SimpleNamespace(
            skip_doca=False, download_doca=False, dry_run=False,
            project=str(self.project), no_upgrade=True, p2p_file=None,
            skip_infra=True, skip_generate=False, start_services=False,
            start_ztp_monitor=False, ztp_monitor_scope="auto",
            ztp_monitor_interval=30,
        )
        remote_settings = LOAD.replace(
            self.inputs.settings,
            http_root=Path("/var/www/html"),
            ztp_prefix="/day0/project-ztp",
            versions={"eth": "5.18"},
        )
        air_policy = self.project / "03-air-topology-policy.json"
        remote_inputs = LOAD.replace(
            self.inputs,
            settings=remote_settings,
            air_topology_policy=air_policy,
        )
        configure_prefix = mock.Mock()
        snapshot_prefix = mock.Mock()
        render_runtime = mock.Mock()
        generate_configs = mock.Mock()
        validate_host = mock.Mock(side_effect=AssertionError(
            "macOS preparation must not validate Linux service endpoints"
        ))
        release_lock = mock.Mock()

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(LOAD, "parse_args", return_value=args))
            stack.enter_context(mock.patch.object(
                LOAD, "acquire_deployment_lock", return_value=73,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "release_deployment_lock", release_lock,
            ))
            stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Darwin"))
            stack.enter_context(mock.patch.object(
                LOAD, "supports_local_ztp_services", return_value=False,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "resolve_project", return_value=self.project,
            ))
            stack.enter_context(mock.patch.object(LOAD, "initialize_from_template"))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_inputs", return_value=(remote_inputs, {}),
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_management_host", validate_host,
            ))
            stack.enter_context(mock.patch.object(LOAD, "quiesce_services"))
            stack.enter_context(mock.patch.object(LOAD, "activate_project"))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_ztp_prefix_publication", snapshot_prefix,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "configure_ztp_prefix_publication", configure_prefix,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "render_ztp_runtime", render_runtime,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_release_links", return_value={},
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "generate_configs", generate_configs,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_and_publish_release", return_value=None,
            ))

            result = LOAD.main([])

        self.assertEqual(0, result)
        validate_host.assert_not_called()
        snapshot_prefix.assert_not_called()
        configure_prefix.assert_not_called()
        render_runtime.assert_called_once()
        generate_configs.assert_called_once_with(
            remote_inputs.device_types,
            install_dhcp=False,
            dry_run=False,
            schema_version=remote_inputs.settings.schema_version,
            eth_version="5.18",
            air_topology_policy=air_policy,
        )
        release_lock.assert_called_once_with(73)

    def test_linux_without_local_service_does_not_publish_runtime_ztp_prefix(self) -> None:
        """A Linux artifact builder without service endpoints must not publish aliases."""
        args = SimpleNamespace(
            skip_doca=False, download_doca=False, dry_run=False,
            project=str(self.project), no_upgrade=True, p2p_file=None,
            skip_infra=True, skip_generate=False, start_services=False,
            start_ztp_monitor=False, ztp_monitor_scope="auto",
            ztp_monitor_interval=30,
        )
        remote_settings = LOAD.replace(
            self.inputs.settings,
            http_root=Path("/var/www/html"),
            ztp_prefix="/day0/project-ztp",
        )
        remote_inputs = LOAD.replace(self.inputs, settings=remote_settings)
        validate_host = mock.Mock(return_value=False)
        snapshot_prefix = mock.Mock()
        configure_prefix = mock.Mock()
        render_runtime = mock.Mock()
        generate_configs = mock.Mock()
        release_lock = mock.Mock()
        require_inactive = mock.Mock()
        quiesce = mock.Mock()

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(LOAD, "parse_args", return_value=args))
            stack.enter_context(mock.patch.object(
                LOAD, "acquire_deployment_lock", return_value=74,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "release_deployment_lock", release_lock,
            ))
            stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Linux"))
            stack.enter_context(mock.patch.object(
                LOAD, "supports_local_ztp_services", return_value=True,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "resolve_project", return_value=self.project,
            ))
            stack.enter_context(mock.patch.object(LOAD, "initialize_from_template"))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_inputs", return_value=(remote_inputs, {}),
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_management_host", validate_host,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "require_artifact_builder_services_inactive",
                require_inactive,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "quiesce_services", quiesce,
            ))
            stack.enter_context(mock.patch.object(LOAD, "activate_project"))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_ztp_prefix_publication", snapshot_prefix,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "configure_ztp_prefix_publication", configure_prefix,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "render_ztp_runtime", render_runtime,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_release_links", return_value={},
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "generate_configs", generate_configs,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_and_publish_release", return_value=None,
            ))

            result = LOAD.main([])

        self.assertEqual(0, result)
        validate_host.assert_called_once_with(remote_settings, False)
        require_inactive.assert_called_once_with(False)
        quiesce.assert_not_called()
        snapshot_prefix.assert_not_called()
        configure_prefix.assert_not_called()
        render_runtime.assert_called_once()
        generate_configs.assert_called_once()
        release_lock.assert_called_once_with(74)

    def test_linux_artifact_builder_rejects_active_services_without_stopping(self) -> None:
        with mock.patch.object(
            LOAD, "active_managed_services",
            return_value=("apache2", "isc-dhcp-server"),
        ), mock.patch.object(LOAD, "run") as runner:
            with self.assertRaisesRegex(
                LOAD.LoadError, "service_ip.*服务正在运行",
            ):
                LOAD.require_artifact_builder_services_inactive(False)
        runner.assert_not_called()

    def test_macos_preparation_links_dhcp_manifest_and_commits_parent_release(self) -> None:
        """The configuration-only path still publishes a complete child/parent release."""
        manifest_rel = "config/isc-dhcp-server/dhcp-release-manifest.json"
        mapped = {
            ztp_rel: (project_rel, kind)
            for ztp_rel, project_rel, kind in SETUP.MAPPINGS
        }
        self.assertEqual(
            ("99-output-dhcp/dhcp-release-manifest.json", "output"),
            mapped.get(manifest_rel),
        )

        names = (
            "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
            "dhcpd_nvl.hosts", "dhcp-release-manifest.json",
        )
        runtime_paths = {}
        for name in names:
            ztp_rel = f"config/isc-dhcp-server/{name}"
            project_rel, kind = mapped[ztp_rel]
            self.assertEqual("output", kind)
            runtime_path = self.ztp / ztp_rel
            project_path = self.project / project_rel
            if name == "dhcp-release-manifest.json":
                runtime_path.unlink(missing_ok=True)
                project_path.unlink(missing_ok=True)
                with mock.patch.object(SETUP, "_DRY_RUN", False), mock.patch.object(
                    SETUP, "_LINK_ERRORS", 0,
                ):
                    result = SETUP._process_mapping(
                        str(self.project), ztp_rel, project_rel, kind,
                        link_root=str(self.ztp),
                    )
                self.assertEqual("linked", result)
            else:
                content = runtime_path.read_bytes() if runtime_path.is_file() else b""
                runtime_path.unlink(missing_ok=True)
                project_path.parent.mkdir(parents=True, exist_ok=True)
                project_path.write_bytes(content)
                runtime_path.symlink_to(project_path)
            runtime_paths[name] = runtime_path

        records = [{
            "hostname": "leaf01", "type": "eth", "iface": "eth0",
            "mac_norm": "02:00:00:00:00:01", "ip": "192.0.2.10",
            "netmask": "24", "identity_pending": False,
            "dhcp_assignment": "fixed", "served_subnet": "192.0.2.0/24",
            "src": str(self.devices_file),
        }]
        subnets = [{
            "shared_network": "clients", "subnet": "192.0.2.0",
            "netmask": "255.255.255.0", "range_start": "192.0.2.100",
            "range_end": "192.0.2.200", "routers": "192.0.2.1",
            "ztp_service_ip": "", "cumulus_profile": "none",
            "nvos_ztp": "no", "cumulus_provision_url": "",
            "bootfile_name": "", "_network": ipaddress.ip_network("192.0.2.0/24"),
        }]

        def generate_dhcp(
            _device_types, *, install_dhcp, dry_run, schema_version,
            eth_version, air_topology_policy,
        ):
            self.assertFalse(install_dhcp)
            self.assertFalse(dry_run)
            self.assertEqual(1, schema_version)
            self.assertIsNone(eth_version)
            self.assertIsNone(air_topology_policy)
            DHCP.write_dhcpd_conf(runtime_paths["dhcpd.conf"], subnets)
            DHCP.write_hosts(runtime_paths["dhcpd_eth.hosts"], records)
            DHCP.write_hosts(runtime_paths["dhcpd_ib.hosts"], [])
            DHCP.write_hosts(runtime_paths["dhcpd_nvl.hosts"], [])
            # c1 computes OUTPUT_MANIFEST from realpath(OUTPUT_CONF), so it
            # writes directly into the project output directory.  The setup
            # link must make that exact file visible to the parent validator.
            output_manifest = (
                runtime_paths["dhcpd.conf"].resolve().parent
                / "dhcp-release-manifest.json"
            )
            self.assertEqual(
                runtime_paths["dhcp-release-manifest.json"].resolve(),
                output_manifest,
            )
            DHCP.write_release_manifest(
                output_manifest, records, subnets,
                tuple(runtime_paths[name] for name in names[:4]),
            )

        args = SimpleNamespace(
            skip_doca=False, download_doca=False, dry_run=False,
            project=str(self.project), no_upgrade=True, p2p_file=None,
            skip_infra=True, skip_generate=False, start_services=False,
            start_ztp_monitor=False, ztp_monitor_scope="auto",
            ztp_monitor_interval=30,
        )
        remote_inputs = LOAD.replace(
            self.inputs,
            settings=LOAD.replace(
                self.inputs.settings, http_root=Path("/var/www/html"),
                ztp_prefix="/day0/project-ztp",
            ),
        )
        mount_dhcp = mock.Mock(side_effect=AssertionError(
            "macOS preparation must not install files under /etc/dhcp"
        ))
        configure_prefix = mock.Mock()
        snapshot_prefix = mock.Mock()

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(LOAD, "parse_args", return_value=args))
            stack.enter_context(mock.patch.object(
                LOAD, "acquire_deployment_lock", return_value=75,
            ))
            stack.enter_context(mock.patch.object(LOAD, "release_deployment_lock"))
            stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Darwin"))
            stack.enter_context(mock.patch.object(
                LOAD, "supports_local_ztp_services", return_value=False,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "resolve_project", return_value=self.project,
            ))
            stack.enter_context(mock.patch.object(LOAD, "initialize_from_template"))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_inputs", return_value=(remote_inputs, {}),
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_management_host",
                side_effect=AssertionError("Darwin must not validate local service IPs"),
            ))
            stack.enter_context(mock.patch.object(LOAD, "quiesce_services"))
            stack.enter_context(mock.patch.object(LOAD, "activate_project"))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_ztp_prefix_publication", snapshot_prefix,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "configure_ztp_prefix_publication", configure_prefix,
            ))
            stack.enter_context(mock.patch.object(LOAD, "render_ztp_runtime"))
            stack.enter_context(mock.patch.object(
                LOAD, "generate_configs", side_effect=generate_dhcp,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "mount_and_test_dhcp", mount_dhcp,
            ))

            result = LOAD.main([])

        self.assertEqual(0, result)
        snapshot_prefix.assert_not_called()
        configure_prefix.assert_not_called()
        mount_dhcp.assert_not_called()
        runtime_manifest = runtime_paths["dhcp-release-manifest.json"]
        project_manifest = self.project / mapped[manifest_rel][0]
        self.assertTrue(runtime_manifest.is_symlink())
        self.assertEqual(project_manifest.resolve(), runtime_manifest.resolve())
        self.assertGreater(project_manifest.stat().st_size, 0)
        parent = json.loads(
            (self.project / "99-output-ztp/current-release.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("passed", parent["validation"])
        self.assertEqual({"dhcp", "cumulus"}, set(parent["components"]))

        with mock.patch.object(UNSETUP, "ZTP", str(self.ztp)):
            self.assertIn(
                str(runtime_manifest), UNSETUP._known_ztp_project_links()
            )


if __name__ == "__main__":
    unittest.main()
