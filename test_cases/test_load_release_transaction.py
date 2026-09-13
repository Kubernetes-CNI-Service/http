"""Unified release validation, DHCP installation, and rollback transactions."""

from __future__ import annotations

import csv
from contextlib import ExitStack
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import inspect
import ipaddress
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
H04_SCHEMA_V1_HEADER = (
    "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw",
    "eth0_mac", "eth1_ip", "netmask", "eth1_gw", "eth1_mac", "lo_ip",
    "vrf_default", "vlan_id", "svi_ip", "netmask", "vrr_ip", "vrr_mac",
    "vlan_ports", "bgp_asn", "bgp_ports", "bond_ports", "bond_type",
    "bond_mac", "peerlink_ports", "vrl", "evpn_vrf", "evpn_l3vni",
    "evpn_l3vlan", "dhcp_relay", "evpn_l2vni", "evpn_l2vlan", "svi_ip",
    "netmask", "vrr_ip", "vrr_mac", "vlan_ports",
)
H04_COLLISION_HOSTNAME = "COLLIDE-LEAF01"
H04_VRR_MAC = "00:00:5e:00:01:c8"
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

GENERATOR_SPEC = importlib.util.spec_from_file_location(
    "cumulus_scope_generation_contract",
    ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
)
GENERATOR = importlib.util.module_from_spec(GENERATOR_SPEC)
assert GENERATOR_SPEC.loader is not None
sys.modules[GENERATOR_SPEC.name] = GENERATOR
GENERATOR_SPEC.loader.exec_module(GENERATOR)

PUBLISHER_SPEC = importlib.util.spec_from_file_location(
    "cumulus_scope_publication_contract",
    ROOT / "ztp/config/cumulus/d-hostname2mac.py",
)
PUBLISHER = importlib.util.module_from_spec(PUBLISHER_SPEC)
assert PUBLISHER_SPEC.loader is not None
sys.modules[PUBLISHER_SPEC.name] = PUBLISHER
PUBLISHER_SPEC.loader.exec_module(PUBLISHER)

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


def h19_mini_policy(*, unknown_role_action: str = "error") -> dict:
    """Independent, non-GB300 taxonomy for the real load-to-topology workflow."""
    return {
        "node_allowlist": {},
        "link_rewrites": [],
        "mini_sampling": {
            "location_prefix_regex": r"^(?:moon|mars|nova)-(?P<logical>.+)$",
            "unknown_role_action": unknown_role_action,
            "roles": [
                {
                    "name": "orbital-hub",
                    "hostname_regex": r"^orbital-hub-(?P<index>\d+)$",
                    "selection": {"mode": "first", "count": 1},
                },
                {
                    "name": "crystal-edge",
                    "hostname_regex": r"^crystal-edge-(?P<index>\d+)$",
                    "selection": {
                        "mode": "indices", "capture_group": "index",
                        "indices": [1],
                    },
                },
                {
                    "name": "anchor-gateway",
                    "hostname_regex": r"^anchor-gateway-(?P<index>\d+)$",
                    "selection": {
                        "mode": "anchor",
                        "peer_hostname_regex": r"^orbital-hub-.+$",
                        "peer_port_regex": r"^eth0$",
                    },
                },
            ],
        },
    }


def write_valid_nvos_image(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as stream:
        stream.write(b"#!/bin/sh")
        stream.truncate(1024 * 1024)


def write_shared_artifact_receipt(
    root: Path, project: Path, inputs, image: Path, *,
    project_name: str | None = None,
    deployment_scope: str | None = None,
    switch_scope: str | None = None,
    global_sha256: str | None = None,
    family: str = "eth",
    version: str = "5.18.1",
    artifact_size: int | None = None,
) -> Path:
    receipt_dir = root / ".shared-artifact-receipts"
    receipt_dir.mkdir(mode=0o755)
    input_files = {
        inputs.global_file.name: inputs.global_file,
        inputs.devices_file.name: inputs.devices_file,
    }
    if inputs.mini_devices_file is not None:
        input_files[inputs.mini_devices_file.name] = inputs.mini_devices_file
    identities = {
        name: {
            "sha256": sha256(path),
            "size": path.stat().st_size,
        }
        for name, path in input_files.items()
    }
    if global_sha256 is not None:
        identities[inputs.global_file.name]["sha256"] = global_sha256
    archive_sha = "a" * 64
    receipt = {
        "archive_sha256": archive_sha,
        "artifact_type": "http-ztp-shared-artifact-receipt",
        "artifacts": [{
            "consumers": [{"family": family, "version": version}],
            "kind": "switch-image",
            "platform": None,
            "sha256": sha256(image),
            "size": artifact_size if artifact_size is not None else image.stat().st_size,
            "target": "image/" + image.name,
        }],
        "metadata_sha256": "b" * 64,
        "project": project_name or project.name,
        "schema_version": 1,
        "selection": {
            "deployment_scope": deployment_scope or inputs.deployment_scope,
            "inputs": identities,
            "mini": inputs.mini_devices_file is not None,
            "mini_input": (
                inputs.mini_devices_file.name
                if inputs.mini_devices_file is not None else None
            ),
            "switch_scope": switch_scope or inputs.switch_scope,
            "upgrade_policy": "enabled",
        },
    }
    path = receipt_dir / f"{archive_sha}.json"
    path.write_text(
        json.dumps(receipt, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )
    path.chmod(0o600)
    return path


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

    def _prepare_h04_schema_v1_collision_generator(self) -> tuple[Path, Path]:
        template_dir = self.ztp / "config/cumulus/template"
        template_dir.mkdir(parents=True, exist_ok=True)
        tools_dir = self.root / "tools"
        tools_dir.mkdir(exist_ok=True)
        shutil.copy2(
            ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
            template_dir / "90-c2-generate_configs.py",
        )
        shutil.copy2(ROOT / "tools/project_contract.py", tools_dir)
        shutil.copy2(ROOT / "ztp/nvue_normalizer.py", self.ztp)
        shutil.copy2(
            ROOT / "ztp/config/cumulus/d-hostname2mac.py",
            template_dir.parent / "d-hostname2mac.py",
        )
        shutil.copy2(
            ROOT / "ztp/config/cumulus/default.yaml", template_dir.parent,
        )
        shutil.copytree(
            ROOT / "ztp/config/cumulus/template/03-templates-j2",
            template_dir / "03-templates-j2",
        )
        global_document = {
            "schema_version": 1,
            "bridge": {"domain": {"br_default": {"stp": {"priority": 4096}}}},
            "mlag": {"init-delay": 180},
            "version": "5.18.1",
            "vrf": {"default": {"router": {"bfd": {"profile": {
                "bgp-underlay-bfd": {
                    "detect-multiplier": 3,
                    "min-rx-interval": 300,
                    "min-tx-interval": 300,
                },
            }}}}},
            "system": {
                "aaa": {"user": {"cumulus": {
                    "full-name": "cumulus,,,,", "hashed-password": "'*'",
                }}},
                "date-time": {"timezone": "UTC"},
                "dns": {"server": ["192.0.2.53"], "vrf": "mgmt"},
                "ntp": {"server": ["192.0.2.123"], "vrf": "mgmt"},
            },
        }
        self.global_file.write_text(
            yaml.safe_dump(global_document, sort_keys=False), encoding="utf-8",
        )
        row = ["NA"] * len(H04_SCHEMA_V1_HEADER)
        for index, value in {
            0: H04_COLLISION_HOSTNAME, 1: "eth", 2: "tan-leaf",
            3: "192.0.2.10", 4: "24", 5: "192.0.2.1",
            6: "02:00:00:00:00:10", 11: "198.51.100.10",
            12: "default", 19: "65101", 20: "swp49",
            21: "bond1s0|bond10", 22: "evpn_multihoming",
            23: "02:00:00:00:10:10", 26: "BLUE", 27: "4000",
            28: "4000", 29: "false", 30: "100200", 31: "200",
            32: "192.0.2.2", 33: "24", 34: "192.0.2.1",
            35: H04_VRR_MAC, 36: "bond1s0/bond10",
        }.items():
            row[index] = value
        with self.devices_file.open("w", newline="", encoding="utf-8") as stream:
            csv.writer(stream).writerows((H04_SCHEMA_V1_HEADER, row))
        for name, target in (
            ("01-global.yaml", self.global_file),
            ("02-devices_config.csv", self.devices_file),
        ):
            (template_dir / name).symlink_to(target)
        devices = self.project / "99-output-eth/91-devices.yaml"
        devices.write_bytes(b"workflow-91-before-collision\n")
        devices.chmod(0o640)
        os.utime(devices, ns=(1_650_000_000_000_000_000,) * 2)
        (template_dir / "91-devices.yaml").symlink_to(devices)
        (template_dir / "99-output").symlink_to(self.project / "99-output-eth")
        (template_dir / "P2P").mkdir()
        return template_dir, devices

    def _exercise_main_transaction_failure(
        self, failure: BaseException, argv: list[str] | None = None,
        *, lifecycle_events: list[str] | None = None,
        authority_failure: BaseException | None = None,
    ):
        args = SimpleNamespace(
            skip_doca=False, download_doca=False, dry_run=False,
            project=str(self.project), no_upgrade=True, p2p_file=None,
            skip_infra=True, skip_generate=False, start_services=False,
            start_ztp_monitor=False, ztp_monitor_scope="auto",
            ztp_monitor_interval=30, ssh_dir=Path("/root/.ssh"),
        )
        candidate = LOAD.prepare_current_release(
            self.project,
            {"schema_version": 1, "release_id": "failure-candidate"},
        )
        quiesce = mock.Mock()
        restore_links = mock.Mock()
        restore_prefix = mock.Mock()
        release_lock = mock.Mock()
        runtime_backend = SimpleNamespace(name="supervisor")
        runtime_plan = SimpleNamespace(
            listener_names=("eno2",), endpoint_ips=("192.0.2.10",),
        )
        caught = None
        result = None
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(LOAD, "parse_args", return_value=args))
            stack.enter_context(mock.patch.object(LOAD, "acquire_deployment_lock", return_value=91))
            stack.enter_context(mock.patch.object(LOAD, "release_deployment_lock", release_lock))
            stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Linux"))
            stack.enter_context(mock.patch.object(LOAD, "supports_local_ztp_services", return_value=True))
            stack.enter_context(mock.patch.object(
                LOAD, "service_runtime_backend", return_value=runtime_backend,
            ))
            stack.enter_context(mock.patch.object(LOAD, "ensure_management_key"))
            stack.enter_context(mock.patch.object(LOAD, "prepare_pubkeys"))
            stack.enter_context(mock.patch.object(LOAD, "resolve_project", return_value=self.project))
            stack.enter_context(mock.patch.object(LOAD, "initialize_from_template"))
            stack.enter_context(mock.patch.object(LOAD, "validate_inputs", return_value=(self.inputs, {})))
            stack.enter_context(mock.patch.object(LOAD, "validate_management_host", return_value=True))
            stack.enter_context(mock.patch.object(
                LOAD, "plan_local_dhcp_runtime",
                return_value=runtime_plan,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "confirm_ztp_monitor_start", return_value=False,
            ))
            stack.enter_context(mock.patch.object(LOAD, "quiesce_services", quiesce))
            stack.enter_context(mock.patch.object(LOAD, "activate_project"))
            stack.enter_context(mock.patch.object(LOAD, "render_ztp_runtime"))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_ztp_prefix_publication",
                return_value=mock.sentinel.prefix_snapshot,
            ))
            stack.enter_context(mock.patch.object(LOAD, "configure_ztp_prefix_publication"))
            def attest_monitor_authority(*_args, **_kwargs):
                if lifecycle_events is not None:
                    lifecycle_events.append("monitor-authority-attest")
                if authority_failure is not None:
                    raise authority_failure

            stack.enter_context(mock.patch.object(
                LOAD, "verify_monitor_authority",
                side_effect=attest_monitor_authority,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_release_links",
                return_value={self.project / "99-output-eth/latest": "old-release"},
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "generate_configs",
                side_effect=(
                    (lambda *_args, **_kwargs: lifecycle_events.append("generate"))
                    if lifecycle_events is not None else None
                ),
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_and_publish_release",
                return_value={"schema_version": 1, "release_id": "failure-candidate"},
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "prepare_current_release", return_value=candidate,
            ))
            def fail_dhcp_transaction(*_args, **_kwargs):
                if lifecycle_events is not None:
                    lifecycle_events.append("dhcp-transaction")
                raise failure

            stack.enter_context(mock.patch.object(
                LOAD, "mount_and_test_dhcp", side_effect=fail_dhcp_transaction,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "restore_release_links", restore_links,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "restore_ztp_prefix_publication", restore_prefix,
            ))
            try:
                result = LOAD.main([] if argv is None else argv)
            except BaseException as exc:  # Assert propagation after cleanup below.
                caught = exc
        return (
            result, caught, candidate, quiesce, restore_links,
            restore_prefix, release_lock, runtime_backend, runtime_plan,
        )

    def test_writes_parent_release_after_all_components_match(self) -> None:
        result = LOAD.validate_and_publish_release(self.project, self.inputs)
        self.assertEqual(result["validation"], "passed")
        self.assertEqual(set(result["components"]), {"dhcp", "cumulus"})
        current = self.project / "99-output-ztp/current-release.json"
        self.assertEqual(json.loads(current.read_text())["release_id"], result["release_id"])

    def test_setup_publishes_every_nvos_name_that_load_can_select(self) -> None:
        filenames = (
            "nvos-amd64-25.03.1010.bin",
            "nvosv25-03-1010amd64.bin",
        )
        settings = LOAD.replace(
            self.inputs.settings, versions={"ib": "25.03.1010"},
        )
        for filename in filenames:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                project = root / "DAY0-Prepare/project"
                shared = root / "image"
                ztp = root / "ztp"
                project.mkdir(parents=True)
                image = shared / filename
                write_valid_nvos_image(image)

                with mock.patch.multiple(
                    SETUP,
                    HTTP_BASE=str(root),
                    IMAGE_DIR=str(shared),
                    ZTP=str(ztp),
                    _DRY_RUN=False,
                ), mock.patch.object(LOAD, "IMAGE_DIR", shared):
                    SETUP._process_bin_files()
                    resolved = LOAD.prepare_images(
                        project,
                        LOAD.expected_images(settings, frozenset({"ib"})),
                        quiet=True,
                    )

                published = ztp / "image/nvos" / filename
                self.assertTrue(published.is_symlink())
                self.assertEqual(image.resolve(), published.resolve())
                self.assertEqual(image, resolved["ib"])

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

    def test_parent_and_manual_preflight_bind_mini_air_device_file(self) -> None:
        policy = self.project / "03-air-topology-policy.json"
        policy.write_text(
            json.dumps(h19_mini_policy()) + "\n", encoding="utf-8",
        )
        mini_devices = self.project / "04-air-mini-devices.txt"
        mini_devices.write_text(
            "[minimum-required]\nleaf01\n\n[customer-provided]\nleaf01\n",
            encoding="utf-8",
        )
        inputs = LOAD.replace(
            self.inputs,
            air_topology_policy=policy,
            mini_devices_file=mini_devices,
        )
        parent = LOAD.validate_and_publish_release(self.project, inputs)
        self.assertEqual(
            sha256(policy), parent["inputs"]["air_topology_policy"],
        )
        self.assertEqual(
            sha256(mini_devices), parent["inputs"]["mini_air_devices"],
        )
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
            mini_devices.write_text(
                "[minimum-required]\nleaf01\n\n"
                "[customer-provided]\nleaf02\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                MANUAL.ManualZtpError, "mini AIR.*已变化",
            ):
                MANUAL.validate_parent_release_binding(self.project, device)

    def test_mini_release_without_project_policy_fails_before_basis_or_publish(self) -> None:
        mini_devices = self.project / "04-air-mini-devices.txt"
        mini_devices.write_text(
            "[minimum-required]\nleaf01\n\n[customer-provided]\nleaf01\n",
            encoding="utf-8",
        )
        current = self.project / "99-output-ztp/current-release.json"
        current.parent.mkdir(parents=True, exist_ok=True)
        original = b'{"release_id":"last-good"}\n'
        current.write_bytes(original)
        inputs = LOAD.replace(
            self.inputs, air_topology_policy=None,
            mini_devices_file=mini_devices,
        )
        basis_serialization_calls = []

        def reject_release_basis_serialization(*args, **kwargs):
            basis_serialization_calls.append((args, kwargs))
            raise AssertionError("release_basis serialization reached")

        with mock.patch.object(
            LOAD.json, "dumps", side_effect=reject_release_basis_serialization,
        ), mock.patch.object(LOAD, "publish_current_release") as publish:
            with self.assertRaisesRegex(
                LOAD.LoadError,
                r"03-air-topology-policy\.json.*mini_sampling",
            ):
                LOAD.validate_and_publish_release(self.project, inputs)
        self.assertEqual([], basis_serialization_calls)
        publish.assert_not_called()
        self.assertEqual(original, current.read_bytes())

        with mock.patch.object(LOAD, "run") as runner:
            with self.assertRaisesRegex(
                LOAD.LoadError,
                r"--mini.*03-air-topology-policy\.json.*mini_sampling",
            ):
                LOAD.generate_configs(
                    frozenset({"eth"}), install_dhcp=False, dry_run=True,
                    mini_air=True, mini_devices_file=mini_devices,
                    air_topology_policy=None,
                )
        runner.assert_not_called()

    def test_validated_customer_source_allows_canonical_refresh_and_rejects_drift(self) -> None:
        policy = self.project / "03-air-topology-policy.json"
        policy.write_text(
            json.dumps(h19_mini_policy()) + "\n", encoding="utf-8",
        )
        customer = self.project / "customer-mini.txt"
        customer.write_text("moon-crystal-edge-02\n", encoding="utf-8")
        canonical = self.project / "04-air-mini-devices.txt"
        canonical.write_text(
            "[minimum-required]\nstale-node\n\n[customer-provided]\n",
            encoding="utf-8",
        )
        args = SimpleNamespace(
            mini=customer.name, no_upgrade=True, p2p_file=None,
            deployment_scope="all", switch_scope="all",
            ssh_dir=Path("/root/.ssh"), dry_run=True,
        )
        with mock.patch.object(
            LOAD, "load_global", return_value=self.inputs.settings,
        ), mock.patch.object(
            LOAD, "apply_subnet_service_ips", return_value=self.inputs.settings,
        ), mock.patch.object(
            LOAD, "load_device_types", return_value=frozenset({"eth"}),
        ), mock.patch.object(
            LOAD, "select_p2p", return_value=self.p2p_file,
        ), mock.patch.object(
            LOAD, "validate_subnet_file",
        ), mock.patch.object(
            LOAD, "validate_shared_artifact_receipts",
        ), mock.patch.object(
            LOAD, "prepare_pubkeys", return_value=(),
        ):
            inputs, images = LOAD.validate_inputs(
                self.project, args, allow_management_key_generation=False,
            )
        self.assertEqual({}, images)
        self.assertNotIn("mini_air_devices", inputs.source_identities)
        self.assertEqual(
            sha256(customer),
            inputs.source_identities["mini_air_customer_source"],
        )

        refreshed = (
            "[minimum-required]\nmoon-crystal-edge-01\n\n"
            "[customer-provided]\nmoon-crystal-edge-02\n"
        )

        def refresh_canonical(command, **_kwargs):
            if len(command) > 1 and command[1] == "b-xlsx_to_dot.py":
                canonical.write_text(refreshed, encoding="utf-8")

        with mock.patch.object(
            LOAD, "run", side_effect=refresh_canonical,
        ), mock.patch.object(
            LOAD, "_device_types_after_dhcp", return_value=frozenset(),
        ):
            LOAD.generate_configs(
                frozenset({"eth"}), install_dhcp=False, dry_run=True,
                air_topology_policy=policy, mini_air=True,
                mini_devices_file=customer,
                deployment_scope="air", switch_scope="eth",
                source_identities=inputs.source_identities,
            )
        parent = LOAD.validate_and_publish_release(self.project, inputs)
        self.assertEqual(
            sha256(canonical), parent["inputs"]["mini_air_devices"],
        )

        stable = (
            self.project / "99-output-ztp/current-release.json"
        ).read_bytes()
        customer.write_text("moon-crystal-edge-99\n", encoding="utf-8")
        with self.assertRaisesRegex(
            LOAD.LoadError, r"customer.*changed|customer.*变化",
        ):
            LOAD.validate_and_publish_release(self.project, inputs)
        self.assertEqual(
            stable,
            (self.project / "99-output-ztp/current-release.json").read_bytes(),
        )

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
            LOAD, "plan_local_dhcp_runtime",
            return_value=SimpleNamespace(listener_names=("eno2",)),
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

    def test_supervisor_quiesce_plans_listeners_before_any_service_change(self) -> None:
        """The host-network listener gate must run before Supervisor is touched."""
        events = []
        expected_plan = SimpleNamespace(listener_names=("eno2", "eno3"))

        class Backend:
            name = "supervisor"

            @staticmethod
            def is_active(service):
                events.append(("status", service))
                return True

            @staticmethod
            def stop(service):
                events.append(("stop", service))

        with mock.patch.object(
            LOAD, "plan_local_dhcp_runtime",
            side_effect=lambda *_a, **_k: (
                events.append(("plan",)) or expected_plan
            ),
        ), mock.patch.object(
            LOAD, "supports_local_ztp_services", return_value=True,
        ), mock.patch.object(
            LOAD.subprocess, "run",
            side_effect=AssertionError("supervisor path must not invoke systemctl"),
        ):
            actual = LOAD.quiesce_services(
                False, inputs=self.inputs, runtime_backend=Backend(),
            )

        self.assertIs(expected_plan, actual)
        self.assertEqual(("plan",), events[0])
        self.assertEqual(
            [
                ("stop", "ztp-monitor"),
                ("stop", "switch-collection"),
                ("stop", "manual-ztp"),
                ("stop", "isc-dhcp-server"),
                ("stop", "apache2"),
            ],
            [event for event in events if event[0] == "stop"],
        )

    def test_supervisor_start_never_activates_dhcp_with_empty_listener_plan(self) -> None:
        events = []

        class Backend:
            name = "supervisor"

            @staticmethod
            def is_active(service):
                events.append(("status", service))
                return False

            @staticmethod
            def is_enabled(_service):
                return None

            @staticmethod
            def start(service):
                events.append(("start", service))

            @staticmethod
            def stop(service):
                events.append(("stop", service))

            @staticmethod
            def restart(service):
                events.append(("restart", service))

        plan = SimpleNamespace(listener_names=(), endpoint_ips=())
        with mock.patch.object(
            LOAD, "ensure_ztp_url_network_ready",
        ), mock.patch.object(
            LOAD, "verify_http_publication",
        ), mock.patch.object(
            LOAD.subprocess, "run",
            side_effect=AssertionError("supervisor path must not invoke systemctl"),
        ):
            LOAD.start_services(
                self.inputs, {}, dhcp_runtime_plan=plan,
                runtime_backend=Backend(),
            )

        self.assertNotIn(("start", "apache2"), events)
        self.assertNotIn(("start", "isc-dhcp-server"), events)
        self.assertNotIn(("restart", "isc-dhcp-server"), events)

    def test_supervisor_dhcp_only_starts_dhcp_and_stops_stale_apache(self) -> None:
        """A relay-ingress DHCP plan must not invent an HTTP endpoint."""
        events = []
        active = {"apache2": True, "isc-dhcp-server": False}

        class Backend:
            name = "supervisor"

            @staticmethod
            def is_active(service):
                events.append(("status", service))
                return active[service]

            @staticmethod
            def start(service):
                events.append(("start", service))
                active[service] = True

            @staticmethod
            def stop(service):
                events.append(("stop", service))
                active[service] = False

            @staticmethod
            def restart(service):
                events.append(("restart", service))
                active[service] = True

        plan = SimpleNamespace(
            listener_names=("eno7",), listener_ifindexes=(17,),
            endpoint_ips=(),
        )
        with mock.patch.object(
            LOAD, "ensure_ztp_url_network_ready",
            side_effect=AssertionError(
                "DHCP-only service start must not gate nonexistent HTTP endpoints"
            ),
        ), mock.patch.object(
            LOAD, "verify_http_publication",
            side_effect=AssertionError(
                "DHCP-only service start must not perform HTTP URL checks"
            ),
        ), mock.patch.object(
            LOAD.subprocess, "run",
            side_effect=AssertionError("supervisor path must not invoke systemctl"),
        ):
            LOAD.start_services(
                self.inputs, {}, dhcp_runtime_plan=plan,
                runtime_backend=Backend(),
            )

        self.assertEqual(
            [
                ("status", "apache2"),
                ("status", "isc-dhcp-server"),
                ("stop", "apache2"),
                ("start", "isc-dhcp-server"),
            ],
            events,
        )
        self.assertFalse(active["apache2"])
        self.assertTrue(active["isc-dhcp-server"])

    def test_supervisor_dhcp_only_main_installs_current_release_without_http(self) -> None:
        """The child load must install the DHCP release before hostctl converges it."""
        args = SimpleNamespace(
            skip_doca=False, download_doca=False, dry_run=False,
            project=str(self.project), no_upgrade=True, p2p_file=None,
            skip_infra=True, skip_generate=False, start_services=True,
            start_ztp_monitor=True, ztp_monitor_scope="air",
            ztp_monitor_interval=30, ssh_dir=Path("/root/.ssh"),
        )
        settings = LOAD.replace(
            self.inputs.settings,
            http_enabled=False, ztp_enabled=False, ztp_ips={}, boot_ips=(),
        )
        inputs = LOAD.replace(self.inputs, settings=settings)
        backend = SimpleNamespace(name="supervisor")
        plan = SimpleNamespace(
            listener_names=("eno7",), listener_ifindexes=(17,),
            endpoint_ips=(),
        )
        quiesce = mock.Mock()
        generate = mock.Mock()
        mount = mock.Mock()
        preflight = mock.Mock()
        start = mock.Mock()
        monitor = mock.Mock()
        switch = mock.Mock()
        manual = mock.Mock()
        prefix_snapshot = mock.Mock()
        prefix_publish = mock.Mock()

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(LOAD, "parse_args", return_value=args))
            stack.enter_context(mock.patch.object(
                LOAD, "acquire_deployment_lock", return_value=93,
            ))
            stack.enter_context(mock.patch.object(LOAD, "release_deployment_lock"))
            stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Linux"))
            stack.enter_context(mock.patch.object(
                LOAD, "supports_local_ztp_services", return_value=True,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "service_runtime_backend", return_value=backend,
            ))
            stack.enter_context(mock.patch.object(LOAD, "ensure_management_key"))
            stack.enter_context(mock.patch.object(LOAD, "prepare_pubkeys"))
            stack.enter_context(mock.patch.object(
                LOAD, "resolve_project", return_value=self.project,
            ))
            stack.enter_context(mock.patch.object(LOAD, "initialize_from_template"))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_inputs", return_value=(inputs, {}),
            ))
            validate_http = stack.enter_context(mock.patch.object(
                LOAD, "validate_management_host",
                side_effect=AssertionError(
                    "DHCP-only plan must not depend on HTTP service_ip availability"
                ),
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "plan_local_dhcp_runtime", return_value=plan,
            ))
            stack.enter_context(mock.patch.object(LOAD, "quiesce_services", quiesce))
            stack.enter_context(mock.patch.object(LOAD, "activate_project"))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_ztp_prefix_publication", prefix_snapshot,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "configure_ztp_prefix_publication", prefix_publish,
            ))
            stack.enter_context(mock.patch.object(LOAD, "render_ztp_runtime"))
            stack.enter_context(mock.patch.object(
                LOAD, "snapshot_release_links", return_value={},
            ))
            stack.enter_context(mock.patch.object(LOAD, "generate_configs", generate))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_and_publish_release", return_value=None,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "mount_and_test_dhcp", mount,
            ))
            stack.enter_context(mock.patch.object(LOAD, "preflight_services", preflight))
            stack.enter_context(mock.patch.object(LOAD, "start_services", start))
            stack.enter_context(mock.patch.object(LOAD, "start_ztp_monitor", monitor))
            stack.enter_context(mock.patch.object(
                LOAD, "start_switch_collection_worker", switch,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "start_manual_ztp_worker", manual,
            ))

            self.assertEqual(0, LOAD.main([]))

        validate_http.assert_not_called()
        quiesce.assert_called_once_with(
            False, dhcp_runtime_plan=plan, runtime_backend=backend,
            native_monitor_already_quiesced=False,
        )
        generate.assert_called_once_with(
            inputs.device_types,
            deployment_lock_descriptor=93,
            install_dhcp=True,
            dry_run=False,
            schema_version=inputs.settings.schema_version,
            eth_version=None,
            air_topology_policy=None,
            deployment_scope="all",
            switch_scope="all",
        )
        mount.assert_called_once_with(False, parent_candidate=None)
        preflight.assert_called_once_with(
            inputs, {}, False, dhcp_runtime_plan=plan,
            runtime_backend=backend,
        )
        start.assert_called_once_with(
            inputs, {}, False, dhcp_runtime_plan=plan,
            runtime_backend=backend,
        )
        prefix_snapshot.assert_not_called()
        prefix_publish.assert_not_called()
        monitor.assert_not_called()
        switch.assert_not_called()
        manual.assert_not_called()

    def test_parent_load_is_the_only_dhcp_runtime_publication_owner(self) -> None:
        generator_main = inspect.getsource(DHCP.main)
        parent_generation = inspect.getsource(LOAD.generate_configs)
        parent_install = inspect.getsource(LOAD.mount_and_test_dhcp)

        self.assertNotIn("subprocess.run", generator_main)
        self.assertNotIn("是否复制配置文件到 /etc/dhcp", generator_main)
        self.assertIn("DHCP 安装已延后到统一 release 验证通过之后", parent_generation)
        self.assertIn("dhcpd -t", parent_install)
        self.assertIn('"install", "-m", "0644"', parent_install)
        self.assertIn("commit_prepared_release", parent_install)

    def test_supervisor_backend_rejects_host_infra_setup_path(self) -> None:
        args = SimpleNamespace(skip_infra=False)
        with self.assertRaisesRegex(LOAD.LoadError, "--skip-infra"):
            LOAD.validate_runtime_options(
                args, SimpleNamespace(name="supervisor"),
            )

        # The default systemd deployment keeps its established infra behavior.
        LOAD.validate_runtime_options(
            args, SimpleNamespace(name="systemd"),
        )

    def test_local_dhcp_runtime_plan_uses_ip_json_and_no_fixed_nic_count(self) -> None:
        subnet = self.root / "dynamic-listeners.csv"
        subnet.write_text(
            "shared_network,subnet,netmask,range_start,range_end,routers,"
            "ztp_service_ip,cumulus_profile,nvos_ztp\n"
            "first,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
            "192.0.2.1,192.0.2.10,oob,no\n"
            "second,198.51.100.0,255.255.255.0,198.51.100.100,198.51.100.120,"
            "198.51.100.1,198.51.100.10,oob,no\n",
            encoding="utf-8",
        )
        inputs = LOAD.replace(self.inputs, subnet_file=subnet)
        links = [
            {
                "ifindex": 7, "ifname": "eno2", "link_type": "ether",
                "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                "operstate": "UP",
            },
            {
                "ifindex": 8, "ifname": "eno3", "link_type": "ether",
                "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                "operstate": "UP",
            },
        ]
        addresses = [
            {"ifindex": 7, "ifname": "eno2", "addr_info": [{
                "family": "inet", "local": "192.0.2.10", "prefixlen": 24,
                "scope": "global",
            }]},
            {"ifindex": 8, "ifname": "eno3", "addr_info": [{
                "family": "inet", "local": "198.51.100.10", "prefixlen": 24,
                "scope": "global",
            }]},
        ]

        plan = LOAD.plan_local_dhcp_runtime(
            inputs, link_snapshot=links, address_snapshot=addresses,
            environment={},
        )

        self.assertEqual(("eno2", "eno3"), plan.listener_names)
        self.assertEqual((7, 8), plan.listener_ifindexes)

    def test_local_runtime_snapshot_requests_detailed_link_kind(self) -> None:
        commands = []

        def runner(command, **kwargs):
            commands.append((command, kwargs))
            return SimpleNamespace(returncode=0, stdout="[]", stderr="")

        self.assertEqual(
            ("[]", "[]"),
            LOAD._local_ip_json_snapshots(command_runner=runner),
        )
        self.assertEqual(
            [
                ["ip", "-d", "-j", "link", "show"],
                ["ip", "-j", "-4", "address", "show"],
            ],
            [command for command, _kwargs in commands],
        )
        for _command, kwargs in commands:
            self.assertEqual(
                {"capture_output": True, "text": True, "check": False},
                kwargs,
            )

    def test_listener_plan_failure_precedes_quiesce_and_cleanup_stop(self) -> None:
        args = SimpleNamespace(
            skip_doca=False, download_doca=False, dry_run=False,
            project=str(self.project), no_upgrade=True, p2p_file=None,
            skip_infra=True, skip_generate=False, start_services=False,
            start_ztp_monitor=False, ztp_monitor_scope="auto",
            ztp_monitor_interval=30, ssh_dir=Path("/root/.ssh"),
        )
        backend = SimpleNamespace(name="supervisor")
        quiesce = mock.Mock()
        release_lock = mock.Mock()
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(LOAD, "parse_args", return_value=args))
            stack.enter_context(mock.patch.object(
                LOAD, "acquire_deployment_lock", return_value=92,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "release_deployment_lock", release_lock,
            ))
            stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Linux"))
            stack.enter_context(mock.patch.object(
                LOAD, "supports_local_ztp_services", return_value=True,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "service_runtime_backend", return_value=backend,
            ))
            stack.enter_context(mock.patch.object(LOAD, "ensure_management_key"))
            stack.enter_context(mock.patch.object(LOAD, "prepare_pubkeys"))
            stack.enter_context(mock.patch.object(
                LOAD, "resolve_project", return_value=self.project,
            ))
            stack.enter_context(mock.patch.object(LOAD, "initialize_from_template"))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_inputs", return_value=(self.inputs, {}),
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_management_host", return_value=True,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "plan_local_dhcp_runtime",
                side_effect=LOAD.LoadError("ambiguous listener fixture"),
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "quiesce_services", quiesce,
            ))
            activate = stack.enter_context(mock.patch.object(LOAD, "activate_project"))

            self.assertEqual(1, LOAD.main([]))

        quiesce.assert_not_called()
        activate.assert_not_called()
        release_lock.assert_called_once_with(92)

    def test_monitor_scope_failure_precedes_quiesce_activation_and_generation(self) -> None:
        args = SimpleNamespace(
            skip_doca=False, download_doca=False, dry_run=False,
            project=str(self.project), no_upgrade=True, p2p_file=None,
            skip_infra=True, skip_generate=False, start_services=True,
            start_ztp_monitor=True, ztp_monitor_scope="auto",
            ztp_monitor_interval=30, ssh_dir=Path("/root/.ssh"),
        )
        backend = SimpleNamespace(name="supervisor")
        plan = SimpleNamespace(
            listener_names=("eno2",), endpoint_ips=("192.0.2.10",),
        )
        quiesce = mock.Mock()
        activate = mock.Mock()
        generate = mock.Mock()
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(LOAD, "parse_args", return_value=args))
            stack.enter_context(mock.patch.object(
                LOAD, "acquire_deployment_lock", return_value=94,
            ))
            stack.enter_context(mock.patch.object(LOAD, "release_deployment_lock"))
            stack.enter_context(mock.patch.object(LOAD, "runtime_os", return_value="Linux"))
            stack.enter_context(mock.patch.object(
                LOAD, "supports_local_ztp_services", return_value=True,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "service_runtime_backend", return_value=backend,
            ))
            stack.enter_context(mock.patch.object(LOAD, "ensure_management_key"))
            stack.enter_context(mock.patch.object(LOAD, "prepare_pubkeys"))
            stack.enter_context(mock.patch.object(
                LOAD, "resolve_project", return_value=self.project,
            ))
            stack.enter_context(mock.patch.object(LOAD, "initialize_from_template"))
            stack.enter_context(mock.patch.object(
                LOAD, "validate_inputs", return_value=(self.inputs, {}),
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "plan_local_dhcp_runtime", return_value=plan,
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "supervisor_service_availability", return_value=(True, True),
            ))
            stack.enter_context(mock.patch.object(
                LOAD, "resolve_ztp_monitor_scope",
                side_effect=LOAD.LoadError("scope required before mutation"),
            ))
            stack.enter_context(mock.patch.object(LOAD, "quiesce_services", quiesce))
            stack.enter_context(mock.patch.object(LOAD, "activate_project", activate))
            stack.enter_context(mock.patch.object(LOAD, "generate_configs", generate))

            stderr = io.StringIO()
            with redirect_stderr(stderr):
                self.assertEqual(1, LOAD.main([]))

        quiesce.assert_not_called()
        activate.assert_not_called()
        generate.assert_not_called()
        self.assertIn("scope required before mutation", stderr.getvalue())

    def test_transaction_failure_reports_phase_safe_state_and_full_rerun(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = self._exercise_main_transaction_failure(
                ValueError("injected value error"),
                argv=["demo", "--start-services", "--ztp-monitor-scope", "air"],
            )[0]

        self.assertEqual(1, result)
        output = stderr.getvalue()
        self.assertIn("[FAILED] load 阶段失败：统一 release 一致性与 DHCP 事务安装", output)
        self.assertIn("[SAFE] 受管服务保持停止", output)
        self.assertIn("[SAFE] 未提交 release 的发布状态已回滚", output)
        self.assertIn("[NEXT] 修复上述错误后完整重跑：", output)
        self.assertIn("11-load.py", output)
        self.assertIn("--ztp-monitor-scope air", output)

    def test_skip_infra_real_main_attests_monitor_authority_before_generation(self) -> None:
        lifecycle_events: list[str] = []
        result = self._exercise_main_transaction_failure(
            ValueError("stop after ordered workflow"),
            lifecycle_events=lifecycle_events,
        )[0]

        self.assertEqual(1, result)
        self.assertEqual(
            [
                "monitor-authority-attest",
                "generate",
                "dhcp-transaction",
            ],
            lifecycle_events,
        )

    def test_unsafe_monitor_authority_keeps_native_apache_path_stopped(self) -> None:
        lifecycle_events: list[str] = []
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result, _caught, _candidate, quiesce, *_rest = (
                self._exercise_main_transaction_failure(
                    ValueError("DHCP transaction must remain unreachable"),
                    lifecycle_events=lifecycle_events,
                    authority_failure=LOAD.LoadError("unsafe fixed authority"),
                )
            )

        self.assertEqual(1, result)
        self.assertEqual(["monitor-authority-attest"], lifecycle_events)
        self.assertEqual(2, quiesce.call_count)
        self.assertIn("只读校验 Monitor cache authority", stderr.getvalue())

    def test_pre_mutation_failure_also_reports_exact_full_rerun(self) -> None:
        stderr = io.StringIO()
        argv = [
            "demo", "--skip-doca", "--download-doca", "--no-upgrade",
            "--ztp-monitor-scope", "prod",
        ]
        with mock.patch.object(LOAD, "runtime_os", return_value="Linux"), \
                redirect_stderr(stderr):
            result = LOAD.main(argv)

        self.assertEqual(1, result)
        output = stderr.getvalue()
        self.assertIn("[FAILED] load 阶段失败：启动前参数检查", output)
        self.assertIn("[NEXT] 修复上述错误后完整重跑：", output)
        self.assertIn("11-load.py", output)
        self.assertIn("--skip-doca --download-doca --no-upgrade", output)
        self.assertIn("--ztp-monitor-scope prod", output)
        self.assertNotIn("[SAFE] 受管服务保持停止", output)

    def test_main_value_error_rolls_back_links_parent_temp_and_services(self) -> None:
        (
            result, caught, candidate, quiesce, restore, restore_prefix,
            release_lock, runtime_backend, runtime_plan,
        ) = (
            self._exercise_main_transaction_failure(ValueError("injected value error"))
        )
        self.assertEqual(result, 1)
        self.assertIsNone(caught)
        self.assertFalse(candidate.temporary.exists())
        restore.assert_called_once()
        restore_prefix.assert_called_once_with(mock.sentinel.prefix_snapshot)
        self.assertEqual(quiesce.call_count, 2)
        for call in quiesce.call_args_list:
            self.assertIs(runtime_backend, call.kwargs["runtime_backend"])
            self.assertIs(runtime_plan, call.kwargs["dhcp_runtime_plan"])
        release_lock.assert_called_once_with(91)

    def test_main_keyboard_interrupt_cleans_up_then_propagates(self) -> None:
        (
            result, caught, candidate, quiesce, restore, restore_prefix,
            release_lock, runtime_backend, runtime_plan,
        ) = (
            self._exercise_main_transaction_failure(KeyboardInterrupt())
        )
        self.assertIsNone(result)
        self.assertIsInstance(caught, KeyboardInterrupt)
        self.assertFalse(candidate.temporary.exists())
        restore.assert_called_once()
        restore_prefix.assert_called_once_with(mock.sentinel.prefix_snapshot)
        self.assertEqual(quiesce.call_count, 2)
        for call in quiesce.call_args_list:
            self.assertIs(runtime_backend, call.kwargs["runtime_backend"])
            self.assertIs(runtime_plan, call.kwargs["dhcp_runtime_plan"])
        release_lock.assert_called_once_with(91)

    def test_transaction_failure_fixture_never_enters_optional_monitor_prompt(self) -> None:
        with mock.patch.object(
            LOAD, "confirm_ztp_monitor_start", return_value=False,
        ) as prompt:
            result, caught, *_rest = self._exercise_main_transaction_failure(
                ValueError("injected failure after the prompt boundary"),
            )

        self.assertEqual(1, result)
        self.assertIsNone(caught)
        prompt.assert_not_called()

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

    def test_deployment_scope_defaults_all_and_specific_scope_is_explicit(self) -> None:
        default = LOAD.parse_args(["example-project"])
        air = LOAD.parse_args(["example-project", "--air"])
        prod = LOAD.parse_args(["example-project", "--prod"])

        self.assertEqual("all", default.deployment_scope)
        self.assertEqual("air", air.deployment_scope)
        self.assertEqual("prod", prod.deployment_scope)
        self.assertEqual("auto", default.ztp_monitor_scope)
        self.assertEqual("auto", air.ztp_monitor_scope)
        self.assertEqual("auto", prod.ztp_monitor_scope)

    def test_switch_scope_defaults_all_and_air_defaults_eth(self) -> None:
        default = LOAD.parse_args(["example-project"])
        eth = LOAD.parse_args(["example-project", "--switch", "eth"])
        ib = LOAD.parse_args(["example-project", "--switch", "ib"])
        nvl = LOAD.parse_args(["example-project", "--switch", "nvl"])
        air = LOAD.parse_args(["example-project", "--air"])

        self.assertEqual(
            "all", LOAD.validate_switch_scope_options(default, "all"),
        )
        self.assertEqual("eth", LOAD.validate_switch_scope_options(eth, "all"))
        self.assertEqual("ib", LOAD.validate_switch_scope_options(ib, "all"))
        self.assertEqual("nvl", LOAD.validate_switch_scope_options(nvl, "all"))
        self.assertEqual("eth", LOAD.validate_switch_scope_options(air, "air"))

        for selected in ("ib", "nvl"):
            with self.subTest(selected=selected), self.assertRaisesRegex(
                LOAD.LoadError, "AIR.*--switch eth",
            ):
                LOAD.validate_switch_scope_options(
                    LOAD.parse_args([
                        "example-project", "--air", "--switch", selected,
                    ]),
                    "air",
                )

    def test_switch_scope_filters_platform_families_and_upgrade_images(self) -> None:
        settings = LOAD.replace(
            self.inputs.settings,
            versions={"eth": "5.18.1", "ib": "25.03.1010", "nvl": "25.02.4282"},
        )
        device_types = frozenset({"eth", "eth_spx", "spx", "ib", "nvl", "air"})
        self.assertEqual(
            frozenset({"eth", "eth_spx", "spx", "air"}),
            LOAD.filter_device_types_for_switch_scope(device_types, "eth"),
        )
        self.assertEqual(
            frozenset({"ib"}),
            LOAD.filter_device_types_for_switch_scope(device_types, "ib"),
        )
        self.assertEqual(
            frozenset({"nvl"}),
            LOAD.filter_device_types_for_switch_scope(device_types, "nvl"),
        )
        self.assertEqual(
            {"ib": "nvosv25-03-1010amd64.bin"},
            LOAD.expected_images(
                settings, device_types, deployment_scope="all", switch_scope="ib",
            ),
        )
        self.assertEqual(
            {"eth": "cumulus-linux-5.18.1-mlx-amd64.bin"},
            LOAD.expected_images(
                settings, device_types, deployment_scope="air", switch_scope="eth",
            ),
        )

    def test_shared_artifact_receipt_binds_selected_image_and_project_inputs(self) -> None:
        settings = LOAD.replace(
            self.inputs.settings, versions={"eth": "5.18.1"},
        )
        inputs = LOAD.replace(
            self.inputs, settings=settings,
            deployment_scope="air", switch_scope="eth",
        )
        self.root.chmod(0o755)
        image = self.root / "image/cumulus-linux-5.18.1-mlx-amd64.bin"
        write_valid_nvos_image(image)

        # Legacy/manual shared files remain supported when no receipt namespace
        # has ever been installed on this management server.
        self.assertIsNone(LOAD.validate_shared_artifact_receipts(
            self.project, inputs, {"eth": image},
            upgrade_enabled=True, root=self.root.resolve(),
        ))

        receipt = write_shared_artifact_receipt(
            self.root, self.project, inputs, image,
        )
        self.assertEqual(
            receipt.resolve(),
            LOAD.validate_shared_artifact_receipts(
                self.project, inputs, {"eth": image},
                upgrade_enabled=True, root=self.root.resolve(),
            ),
        )

    def test_shared_artifact_receipt_rejects_stale_or_misattributed_image(self) -> None:
        settings = LOAD.replace(
            self.inputs.settings, versions={"eth": "5.18.1"},
        )
        inputs = LOAD.replace(
            self.inputs, settings=settings,
            deployment_scope="air", switch_scope="eth",
        )
        self.root.chmod(0o755)
        image = self.root / "image/cumulus-linux-5.18.1-mlx-amd64.bin"
        write_valid_nvos_image(image)

        cases = (
            {"project_name": "other-project"},
            {"deployment_scope": "prod"},
            {"switch_scope": "all"},
            {"global_sha256": "0" * 64},
            {"family": "ib", "version": "25.03.1010"},
        )
        for index, arguments in enumerate(cases):
            with self.subTest(arguments=arguments):
                receipt_dir = self.root / ".shared-artifact-receipts"
                if receipt_dir.exists():
                    shutil.rmtree(receipt_dir)
                write_shared_artifact_receipt(
                    self.root, self.project, inputs, image, **arguments,
                )
                with self.assertRaisesRegex(
                    LOAD.LoadError,
                    "共享制品.*(receipt|项目|范围|输入|consumer|版本)",
                ):
                    LOAD.validate_shared_artifact_receipts(
                        self.project, inputs, {"eth": image},
                        upgrade_enabled=True, root=self.root.resolve(),
                    )

        receipt_dir = self.root / ".shared-artifact-receipts"
        shutil.rmtree(receipt_dir)
        write_shared_artifact_receipt(self.root, self.project, inputs, image)
        with image.open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaisesRegex(LOAD.LoadError, "共享制品.*(hash|大小)"):
            LOAD.validate_shared_artifact_receipts(
                self.project, inputs, {"eth": image},
                upgrade_enabled=True, root=self.root.resolve(),
            )

    def test_input_validation_checks_shared_receipt_before_key_or_image_write(self) -> None:
        settings = LOAD.replace(
            self.inputs.settings, versions={"eth": "5.18.1"},
        )
        args = SimpleNamespace(
            deployment_scope="air", switch_scope="eth", mini=None,
            p2p_file=None, no_upgrade=False, ssh_dir=self.root / "ssh",
            dry_run=False,
        )
        selected_image = self.root / "image/cumulus-linux-5.18.1-mlx-amd64.bin"
        write_valid_nvos_image(selected_image)
        prepare_pubkeys = mock.Mock(return_value=())
        with mock.patch.object(LOAD, "load_global", return_value=settings), \
             mock.patch.object(LOAD, "apply_subnet_service_ips", return_value=settings), \
             mock.patch.object(LOAD, "load_device_types", return_value=frozenset({"eth"})), \
             mock.patch.object(LOAD, "select_p2p", return_value=self.p2p_file), \
             mock.patch.object(LOAD, "validate_subnet_file"), \
             mock.patch.object(LOAD, "project_air_topology_policy", return_value=None), \
             mock.patch.object(LOAD, "project_mini_air_devices", return_value=(None, None)), \
             mock.patch.object(LOAD, "prepare_images", return_value={"eth": selected_image}), \
             mock.patch.object(LOAD, "prepare_pubkeys", prepare_pubkeys), \
             mock.patch.object(
                 LOAD, "validate_shared_artifact_receipts",
                 side_effect=LOAD.LoadError("共享制品 receipt stale"),
             ) as receipt_gate:
            with self.assertRaisesRegex(LOAD.LoadError, "共享制品 receipt stale"):
                LOAD.validate_inputs(
                    self.project, args, allow_management_key_generation=False,
                )

        receipt_gate.assert_called_once()
        prepare_pubkeys.assert_not_called()

    def test_no_upgrade_skips_receipts_and_one_receipt_must_cover_all_images(self) -> None:
        unsafe = self.root / ".shared-artifact-receipts"
        unsafe.write_text("not a directory", encoding="ascii")
        self.assertIsNone(LOAD.validate_shared_artifact_receipts(
            self.project, self.inputs, {},
            upgrade_enabled=False, root=self.root.resolve(),
        ))
        unsafe.unlink()

        self.root.chmod(0o755)
        settings = LOAD.replace(
            self.inputs.settings,
            versions={"eth": "5.18.1", "ib": "25.03.1010"},
        )
        inputs = LOAD.replace(
            self.inputs, settings=settings,
            deployment_scope="prod", switch_scope="all",
        )
        eth = self.root / "image/cumulus-linux-5.18.1-mlx-amd64.bin"
        ib = self.root / "image/nvos-amd64-25.03.1010.bin"
        write_valid_nvos_image(eth)
        write_valid_nvos_image(ib)
        write_shared_artifact_receipt(
            self.root, self.project, inputs, eth,
            deployment_scope="prod", switch_scope="all",
        )
        with self.assertRaisesRegex(LOAD.LoadError, "共享制品 receipt.*不一致"):
            LOAD.validate_shared_artifact_receipts(
                self.project, inputs, {"eth": eth, "ib": ib},
                upgrade_enabled=True, root=self.root.resolve(),
            )

    def test_shared_artifact_receipt_rejects_installer_impossible_size(self) -> None:
        settings = LOAD.replace(
            self.inputs.settings, versions={"eth": "5.18.1"},
        )
        inputs = LOAD.replace(
            self.inputs, settings=settings,
            deployment_scope="air", switch_scope="eth",
        )
        self.root.chmod(0o755)
        image = self.root / "image/cumulus-linux-5.18.1-mlx-amd64.bin"
        write_valid_nvos_image(image)
        write_shared_artifact_receipt(
            self.root, self.project, inputs, image,
            artifact_size=16 * 1024 * 1024 * 1024 + 1,
        )
        with self.assertRaisesRegex(LOAD.LoadError, "receipt artifact"):
            LOAD.validate_shared_artifact_receipts(
                self.project, inputs, {"eth": image},
                upgrade_enabled=True, root=self.root.resolve(),
            )
    def test_upgrade_image_requirements_follow_deployment_scope(self) -> None:
        settings = LOAD.replace(
            self.inputs.settings,
            versions={"eth": "5.18.1", "ib": "25.03.1010", "nvl": "25.02.4282"},
        )
        device_types = frozenset({"eth", "ib", "nvl", "air"})

        self.assertEqual(
            {
                "eth": "cumulus-linux-5.18.1-mlx-amd64.bin",
                "ib": "nvosv25-03-1010amd64.bin",
                "nvl": "nvosv25-02-4282amd64.bin",
            },
            LOAD.expected_images(
                settings, device_types, deployment_scope="all",
            ),
        )
        self.assertEqual(
            {"eth": "cumulus-linux-5.18.1-mlx-amd64.bin"},
            LOAD.expected_images(
                settings, device_types, deployment_scope="air",
            ),
        )
        self.assertEqual(
            {
                "eth": "cumulus-linux-5.18.1-mlx-amd64.bin",
                "ib": "nvosv25-03-1010amd64.bin",
                "nvl": "nvosv25-02-4282amd64.bin",
            },
            LOAD.expected_images(
                settings, device_types, deployment_scope="prod",
            ),
        )
        with self.assertRaisesRegex(LOAD.LoadError, "deployment scope"):
            LOAD.expected_images(
                settings, device_types, deployment_scope="invalid",
            )

    def test_monitor_scope_inherits_specific_deployment_scope_and_rejects_conflict(self) -> None:
        project = Path("/tmp/example-project")
        self.assertEqual(
            "air",
            LOAD.resolve_ztp_monitor_scope(
                project, "auto", deployment_scope="air",
            ),
        )
        self.assertEqual(
            "prod",
            LOAD.resolve_ztp_monitor_scope(
                project, "auto", deployment_scope="prod",
            ),
        )
        self.assertEqual(
            "air",
            LOAD.resolve_ztp_monitor_scope(
                project, "air", deployment_scope="air",
            ),
        )
        with self.assertRaisesRegex(LOAD.LoadError, "部署范围.*监控范围.*冲突"):
            LOAD.resolve_ztp_monitor_scope(
                project, "prod", deployment_scope="air",
            )

    def test_mini_implies_air_scope_and_rejects_explicit_prod(self) -> None:
        implicit = LOAD.parse_args(["example-project", "--mini"])
        explicit = LOAD.parse_args(["example-project", "--air", "--mini"])

        for args in (implicit, explicit):
            with self.subTest(argv=args):
                deployment_scope = LOAD.validate_deployment_scope_options(args)
                self.assertEqual("air", deployment_scope)
                self.assertEqual(
                    "eth",
                    LOAD.validate_switch_scope_options(args, deployment_scope),
                )

        with self.assertRaisesRegex(LOAD.LoadError, "--mini.*AIR|--prod"):
            LOAD.validate_deployment_scope_options(
                LOAD.parse_args(["example-project", "--prod", "--mini"]),
            )

    def test_main_propagates_implicit_mini_scope_before_input_validation(self) -> None:
        observed: dict[str, str] = {}

        def capture_selection(
            _project: Path, args, *, allow_management_key_generation: bool,
        ) -> tuple[object, object]:
            observed["deployment_scope"] = args.deployment_scope
            observed["switch_scope"] = args.switch_scope
            observed["allow_management_key_generation"] = (
                allow_management_key_generation
            )
            raise LOAD.LoadError("stop after normalized selection")

        with mock.patch.object(
            LOAD, "runtime_os", return_value="Linux",
        ), mock.patch.object(
            LOAD, "supports_local_ztp_services", return_value=False,
        ), mock.patch.object(
            LOAD, "resolve_project", return_value=self.project,
        ), mock.patch.object(
            LOAD, "initialize_from_template",
        ), mock.patch.object(
            LOAD, "validate_inputs", side_effect=capture_selection,
        ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = LOAD.main([str(self.project), "--mini", "--dry-run"])

        self.assertEqual(1, result)
        self.assertEqual(
            {
                "deployment_scope": "air",
                "switch_scope": "eth",
                "allow_management_key_generation": False,
            },
            observed,
        )

    def test_invalid_deployment_scope_stops_main_before_lock_or_project_write(self) -> None:
        invalid_argv = (
            ["example-project", "--prod", "--mini"],
            ["example-project", "--air", "--switch", "ib"],
            ["example-project", "--air", "--switch", "nvl"],
            [
                "example-project", "--air",
                "--ztp-monitor-scope", "prod",
            ],
        )
        for argv in invalid_argv:
            with self.subTest(argv=argv), mock.patch.object(
                LOAD, "acquire_deployment_lock",
                side_effect=AssertionError("invalid scope must not acquire lock"),
            ), mock.patch.object(
                LOAD, "initialize_from_template",
                side_effect=AssertionError("invalid scope must not touch project"),
            ), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(1, LOAD.main(argv))

    def test_dhcp_records_are_filtered_by_deployment_scope(self) -> None:
        records = [
            {"hostname": "leaf01", "type": "eth", "iface": "eth0"},
            {"hostname": "ib01", "type": "ib", "iface": "eth0"},
            {"hostname": "AIR-leaf01", "type": "air", "iface": "eth0"},
        ]
        self.assertEqual(
            ["leaf01", "ib01", "AIR-leaf01"],
            [item["hostname"] for item in DHCP.records_for_deployment_scope(
                records, "all",
            )],
        )
        self.assertEqual(
            ["leaf01", "ib01"],
            [item["hostname"] for item in DHCP.records_for_deployment_scope(
                records, "prod",
            )],
        )
        self.assertEqual(
            ["AIR-leaf01"],
            [item["hostname"] for item in DHCP.records_for_deployment_scope(
                records, "air",
            )],
        )

    def test_device_csv_validates_platform_fields_only_for_selected_switch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "02-devices_config.csv"
            with path.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                writer.writerow([
                    "hostname", "type", "template", "eth0_ip", "netmask",
                    "eth0_gw", "eth0_mac", "eth1_ip", "netmask",
                    "eth1_gw", "eth1_mac",
                ])
                writer.writerow([
                    "leaf01", "eth", "leaf", "192.0.2.10", "24",
                    "192.0.2.1", "02:00:00:00:00:01", "", "", "", "",
                ])
                writer.writerow([
                    "ib01", "ib", "", "not-an-ip", "", "", "", "",
                    "", "", "",
                ])

            self.assertEqual(
                frozenset({"eth"}),
                LOAD.load_device_types(path, switch_scope="eth"),
            )
            with self.assertRaisesRegex(LOAD.LoadError, "eth0_ip"):
                LOAD.load_device_types(path, switch_scope="ib")

    def test_publisher_validates_platform_fields_only_for_selected_switch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "02-devices_config.csv"
            with path.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                writer.writerow([
                    "hostname", "type", "template", "eth0_ip", "netmask",
                    "eth0_gw", "eth0_mac", "eth1_ip", "netmask",
                    "eth1_gw", "eth1_mac",
                ])
                writer.writerow([
                    "leaf01", "eth", "leaf", "", "24", "192.0.2.1",
                    "02:00:00:00:00:01", "", "", "", "",
                ])
                writer.writerow([
                    "ib01", "ib", "", "192.0.2.20", "24", "192.0.2.1",
                    "02:00:00:00:00:02", "", "", "", "",
                ])

            selected = PUBLISHER.load_csv(str(path), switch_scope="ib")
            self.assertEqual(["ib01"], [item["hostname"] for item in selected.values()])
            with self.assertRaisesRegex(ValueError, "必填字段"):
                PUBLISHER.load_csv(str(path), switch_scope="eth")

    def test_dhcp_records_are_filtered_by_environment_and_switch_scope(self) -> None:
        records = [
            {"hostname": "leaf01", "type": "eth", "iface": "eth0"},
            {"hostname": "spx01", "type": "eth_spx", "iface": "eth0"},
            {"hostname": "ib01", "type": "ib", "iface": "eth0"},
            {"hostname": "nvl01", "type": "nvl", "iface": "eth0"},
            {"hostname": "AIR-leaf01", "type": "air", "iface": "eth0"},
        ]
        self.assertEqual(
            ["leaf01", "spx01"],
            [item["hostname"] for item in DHCP.records_for_release_scope(
                records, deployment_scope="prod", switch_scope="eth",
            )],
        )
        self.assertEqual(
            ["ib01"],
            [item["hostname"] for item in DHCP.records_for_release_scope(
                records, deployment_scope="all", switch_scope="ib",
            )],
        )
        self.assertEqual(
            ["AIR-leaf01"],
            [item["hostname"] for item in DHCP.records_for_release_scope(
                records, deployment_scope="air", switch_scope="eth",
            )],
        )

    def test_switch_scope_is_forwarded_and_only_selected_generator_runs(self) -> None:
        def commands_for(selected: str) -> list[list[str]]:
            with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                LOAD, "ZTP_DIR", Path(directory),
            ), mock.patch.object(
                LOAD, "_device_types_after_dhcp",
                return_value=frozenset({selected}),
            ), mock.patch.object(LOAD, "run") as runner:
                LOAD.generate_configs(
                    frozenset({"eth", "ib", "nvl"}),
                    install_dhcp=False,
                    dry_run=True,
                    eth_version="5.18.1",
                    deployment_scope="prod",
                    switch_scope=selected,
                )
                return [call.args[0] for call in runner.call_args_list]

        eth_commands = commands_for("eth")
        ib_commands = commands_for("ib")
        nvl_commands = commands_for("nvl")

        self.assertTrue(any("b-xlsx_to_dot.py" in command for command in eth_commands))
        self.assertFalse(any("b-xlsx_to_dot.py" in command for command in ib_commands))
        self.assertFalse(any("b-xlsx_to_dot.py" in command for command in nvl_commands))
        for selected, commands in (
            ("eth", eth_commands), ("ib", ib_commands), ("nvl", nvl_commands),
        ):
            with self.subTest(selected=selected):
                self.assertTrue(commands)
                self.assertTrue(all(
                    "--switch" in command
                    and command[command.index("--switch") + 1] == selected
                    for command in commands
                    if command[1] != "b-xlsx_to_dot.py"
                ), commands)
                branches = [
                    command[command.index("--branch") + 1]
                    for command in commands if "--branch" in command
                ]
                self.assertEqual(
                    ["eth"] if selected == "eth" else ["ib"], branches,
                )

    def test_nvos_generator_validates_only_the_selected_switch_family(self) -> None:
        devices = [
            {"hostname": "ib01", "type": "ib"},
            {"hostname": "nvl01", "type": "nvl"},
        ]

        def validate(selected):
            return ["nvl invalid"] if any(
                item["type"] == "nvl" for item in selected
            ) else []

        with mock.patch.object(
            GENERATOR, "_load_csv_ib", return_value=(devices, []),
        ), mock.patch.object(
            GENERATOR, "_validate_fields_ib", side_effect=validate,
        ), mock.patch.object(
            GENERATOR, "_check_duplicates_ib", return_value=[],
        ), mock.patch.object(
            GENERATOR, "load_global", return_value={},
        ), mock.patch.object(
            GENERATOR, "_generate_group_ib", return_value=(1, 0),
        ) as generate, redirect_stdout(io.StringIO()):
            self.assertEqual(
                1, GENERATOR._generate_all_ib(switch_scope="ib"),
            )

        selected_devices = generate.call_args.args[0]
        self.assertEqual(["ib01"], [item["hostname"] for item in selected_devices])

    def test_dhcp_child_manifest_records_switch_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outputs = tuple(root / name for name in (
                "dhcpd.conf", "dhcpd_eth.hosts",
                "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
            ))
            for output in outputs:
                output.write_text(f"{output.name}\n", encoding="utf-8")
            manifest = root / "dhcp-release-manifest.json"
            DHCP.write_release_manifest(
                manifest,
                [{
                    "hostname": "ib01", "type": "ib", "iface": "eth0",
                    "mac_norm": "02:00:00:00:00:11", "ip": "192.0.2.11",
                    "netmask": "24", "identity_pending": False,
                    "dhcp_assignment": "fixed", "served_subnet": "192.0.2.0/24",
                    "src": "fixture.csv",
                }],
                [{
                    "shared_network": "clients",
                    "_network": ipaddress.ip_network("192.0.2.0/24"),
                    "range_start": "192.0.2.100", "range_end": "192.0.2.200",
                    "routers": "192.0.2.1", "ztp_service_ip": "192.0.2.2",
                    "cumulus_profile": "oob", "nvos_ztp": "yes",
                    "cumulus_provision_url": "", "bootfile_name": "nvos-amd64.bin",
                }],
                outputs,
                deployment_scope="prod",
                switch_scope="ib",
            )
            document = json.loads(manifest.read_text(encoding="utf-8"))

        self.assertEqual("prod", document["deployment_scope"])
        self.assertEqual("ib", document["switch_scope"])
        self.assertEqual(["ib01"], [item["hostname"] for item in document["devices"]])

    def test_switch_scope_retires_unselected_latest_links_transactionally(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            eth = project / "99-output-eth/latest"
            nvos = project / "99-output-ib_nvl/latest"
            eth.parent.mkdir(parents=True)
            nvos.parent.mkdir(parents=True)
            eth.symlink_to("eth-release")
            nvos.symlink_to("nvos-release")

            snapshot = LOAD.snapshot_release_links(project)
            LOAD.retire_unselected_release_links(project, "eth", dry_run=False)
            self.assertTrue(eth.is_symlink())
            self.assertFalse(os.path.lexists(nvos))
            LOAD.restore_release_links(snapshot)
            self.assertEqual("eth-release", os.readlink(eth))
            self.assertEqual("nvos-release", os.readlink(nvos))

    def test_parent_release_rejects_child_from_another_switch_scope(self) -> None:
        inputs = LOAD.replace(self.inputs, switch_scope="eth")
        inventory = [{
            "hostname": "leaf01", "hostname_key": "leaf01", "type": "eth",
            "eth0_mac": "02:00:00:00:00:01", "eth1_mac": "",
            "identity_state": "managed", "identity_source": "devices_config",
        }]
        with mock.patch.object(
            LOAD, "_release_inventory", return_value=inventory,
        ), mock.patch.object(
            LOAD, "_augment_air_json_inventory", return_value=inventory,
        ), mock.patch.object(
            LOAD, "_load_release_json",
            return_value={"deployment_scope": "all", "switch_scope": "ib"},
        ):
            with self.assertRaisesRegex(
                LOAD.LoadError, "DHCP release switch scope",
            ):
                LOAD.validate_and_publish_release(
                    self.project, inputs, publish=False,
                )

    def test_dhcp_release_manifest_binds_scope_and_excludes_other_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outputs = tuple(root / name for name in (
                "dhcpd.conf", "dhcpd_eth.hosts",
                "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
            ))
            for output in outputs:
                output.write_text(f"{output.name}\n", encoding="utf-8")
            manifest = root / "dhcp-release-manifest.json"
            records = [{
                "hostname": "AIR-leaf01", "type": "air", "iface": "eth0",
                "mac_norm": "02:00:00:00:00:01", "ip": "192.0.2.10",
                "netmask": "24", "identity_pending": False,
                "dhcp_assignment": "fixed", "served_subnet": "192.0.2.0/24",
                "src": "fixture.csv",
            }]
            subnets = [{
                "shared_network": "clients",
                "_network": ipaddress.ip_network("192.0.2.0/24"),
                "range_start": "192.0.2.100", "range_end": "192.0.2.200",
                "routers": "192.0.2.1", "ztp_service_ip": "192.0.2.2",
                "cumulus_profile": "oob", "nvos_ztp": "no",
                "cumulus_provision_url": "http://192.0.2.2/ztp/bootstrap",
                "bootfile_name": "",
            }]

            DHCP.write_release_manifest(
                manifest, records, subnets, outputs,
                deployment_scope="air",
            )
            document = json.loads(manifest.read_text(encoding="utf-8"))

        self.assertEqual("air", document["deployment_scope"])
        self.assertEqual(["AIR-leaf01"], [
            item["hostname"] for item in document["devices"]
        ])

    def test_scope_is_forwarded_to_every_generator_branch(self) -> None:
        def commands_for(scope: str) -> list[list[str]]:
            with tempfile.TemporaryDirectory() as directory, mock.patch.object(
                LOAD, "ZTP_DIR", Path(directory),
            ), mock.patch.object(
                LOAD, "_device_types_after_dhcp",
                return_value=(
                    frozenset({"air"}) if scope == "air"
                    else frozenset({"eth", "ib", "nvl"})
                ),
            ), mock.patch.object(LOAD, "run") as runner:
                LOAD.generate_configs(
                    frozenset({"eth", "ib", "nvl"}),
                    install_dhcp=False, dry_run=True,
                    eth_version="5.18.1", deployment_scope=scope,
                )
                return [call.args[0] for call in runner.call_args_list]

        all_commands = commands_for("all")
        prod_commands = commands_for("prod")
        air_commands = commands_for("air")
        self.assertTrue(all(
            "--deployment-scope" not in command for command in all_commands
        ))
        for command in prod_commands:
            self.assertEqual(
                "prod", command[command.index("--deployment-scope") + 1],
                command,
            )
        for command in air_commands:
            self.assertEqual(
                "air", command[command.index("--deployment-scope") + 1],
                command,
            )
        self.assertTrue(any(
            "--branch" in command
            and command[command.index("--branch") + 1] == "ib"
            for command in all_commands
        ))
        self.assertTrue(any(
            "--branch" in command
            and command[command.index("--branch") + 1] == "ib"
            for command in prod_commands
        ))
        self.assertFalse(any(
            "--branch" in command
            and command[command.index("--branch") + 1] == "ib"
            for command in air_commands
        ))

    def test_cumulus_air_scope_renders_only_required_production_sources(self) -> None:
        devices = {
            "leaf01": {"hostname": "leaf01"},
            "leaf02": {"hostname": "leaf02"},
            "leaf03": {"hostname": "leaf03"},
        }
        selected = GENERATOR.select_cumulus_generation_devices(
            devices,
            deployment_scope="air",
            air_source_hostnames={"leaf01", "leaf03"},
        )
        self.assertEqual(["leaf01", "leaf03"], list(selected))
        self.assertEqual(
            devices,
            GENERATOR.select_cumulus_generation_devices(
                devices, deployment_scope="all", air_source_hostnames=set(),
            ),
        )
        self.assertEqual(
            devices,
            GENERATOR.select_cumulus_generation_devices(
                devices, deployment_scope="prod", air_source_hostnames=set(),
            ),
        )
        with self.assertRaisesRegex(ValueError, "AIR.*来源设备.*missing"):
            GENERATOR.select_cumulus_generation_devices(
                devices,
                deployment_scope="air",
                air_source_hostnames={"leaf01", "missing"},
            )

    def test_air_mini_scope_is_forwarded_and_skips_nvos_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / "03-air-topology-policy.json"
            policy.write_text(
                json.dumps(h19_mini_policy()) + "\n", encoding="utf-8",
            )
            with mock.patch.object(
                LOAD, "ZTP_DIR", root,
            ), mock.patch.object(
                LOAD, "_device_types_after_dhcp",
                return_value=frozenset({"air"}),
            ), mock.patch.object(
                LOAD, "newest_directory", return_value=Path("run"),
            ), mock.patch.object(LOAD, "run") as runner:
                LOAD.generate_configs(
                    frozenset({"eth", "ib", "nvl"}),
                    install_dhcp=False,
                    dry_run=True,
                    eth_version="5.18.1",
                    air_topology_policy=policy,
                    mini_air=True,
                    mini_devices_file=root / "04-air-mini-devices.txt",
                    deployment_scope="air",
                )

        commands = [call.args[0] for call in runner.call_args_list]
        self.assertIn(
            [sys.executable, "c1-generate_dhcp.py", "-y", "--deployment-scope", "air"],
            commands,
        )
        self.assertTrue(any(
            command[1:] == [
                "90-c2-generate_configs.py", "--branch", "eth", "-y",
                "--deployment-scope", "air",
            ]
            for command in commands
        ), commands)
        self.assertFalse(any(
            len(command) > 2 and command[1] == "90-c2-generate_configs.py"
            and command[command.index("--branch") + 1] == "ib"
            for command in commands
        ), commands)

    def test_schema_v1_bond_collision_stops_load_before_child_or_parent_publish(self) -> None:
        template_dir, devices = self._prepare_h04_schema_v1_collision_generator()
        current = self.project / "99-output-ztp/current-release.json"
        current.parent.mkdir(parents=True)
        current.write_bytes(b"parent-release-before-collision\n")
        current.chmod(0o640)
        os.utime(current, ns=(1_640_000_000_000_000_000,) * 2)
        latest = self.project / "99-output-eth/latest"

        def regular_identity(path: Path) -> tuple[bytes, int, int, int, int]:
            metadata = path.stat()
            return (
                path.read_bytes(), metadata.st_dev, metadata.st_ino,
                stat.S_IMODE(metadata.st_mode), metadata.st_mtime_ns,
            )

        devices_before = regular_identity(devices)
        current_before = regular_identity(current)
        latest_before = (os.readlink(latest), latest.lstat())
        release_entries_before = tuple(sorted(
            path.name for path in (self.project / "99-output-eth").iterdir()
        ))
        commands = []

        def run_child(command, *, cwd=None, dry_run=False, **_kwargs):
            self.assertFalse(dry_run)
            commands.append(tuple(command))
            if len(command) > 1 and command[1] == "90-c2-generate_configs.py":
                completed = subprocess.run(
                    command,
                    cwd=cwd,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=30,
                    check=False,
                )
                if completed.returncode:
                    raise LOAD.LoadError(completed.stdout)

        messages = []
        newest = mock.Mock(side_effect=AssertionError("child publish is unreachable"))
        with mock.patch.object(LOAD, "run", side_effect=run_child), mock.patch.object(
            LOAD, "_device_types_after_dhcp", return_value=frozenset({"eth"}),
        ), mock.patch.object(LOAD, "newest_directory", newest), mock.patch.object(
            LOAD, "info", side_effect=messages.append,
        ), self.assertRaises(LOAD.LoadError) as raised:
            LOAD.generate_configs(
                frozenset({"eth"}), install_dhcp=True, schema_version=1,
            )

        diagnostic = str(raised.exception)
        self.assertIn(H04_COLLISION_HOSTNAME, diagnostic)
        self.assertIn("bond1s0", diagnostic)
        self.assertIn("bond10", diagnostic)
        self.assertEqual(
            ["b-xlsx_to_dot.py", "c1-generate_dhcp.py", "90-c2-generate_configs.py"],
            [command[1] for command in commands],
        )
        self.assertFalse(any(
            "d-hostname2mac.py" in command for command in commands
        ))
        newest.assert_not_called()
        self.assertFalse(any("DHCP 安装已延后" in message for message in messages))
        self.assertEqual(devices_before, regular_identity(devices))
        self.assertEqual(current_before, regular_identity(current))
        latest_after = latest.lstat()
        self.assertEqual(latest_before[0], os.readlink(latest))
        self.assertEqual(latest_before[1].st_dev, latest_after.st_dev)
        self.assertEqual(latest_before[1].st_ino, latest_after.st_ino)
        self.assertEqual(latest_before[1].st_mtime_ns, latest_after.st_mtime_ns)
        self.assertEqual(
            release_entries_before,
            tuple(sorted(
                path.name for path in (self.project / "99-output-eth").iterdir()
            )),
        )
        self.assertEqual([], list(template_dir.glob("91-devices.yaml.tmp.*")))

    def test_scope_selection_workflow_agrees_across_dhcp_generation_and_publication(self) -> None:
        records = [
            {"hostname": "leaf01", "type": "eth"},
            {"hostname": "leaf02", "type": "eth"},
            {"hostname": "AIR-leaf01", "type": "air"},
        ]
        generator_devices = {
            "leaf01": {"hostname": "leaf01"},
            "leaf02": {"hostname": "leaf02"},
        }
        publisher_devices = {
            "leaf01": {"hostname": "leaf01", "dev_type": "eth"},
            "leaf02": {"hostname": "leaf02", "dev_type": "eth"},
            "air-leaf01": {"hostname": "AIR-leaf01", "dev_type": "air"},
        }
        profiles = {
            "air-leaf01": {
                "hostname": "AIR-leaf01", "source_hostname": "leaf01",
                "profile": "full", "apply_mode": "replace",
            },
        }

        dhcp = DHCP.records_for_deployment_scope(records, "air")
        generated = GENERATOR.select_cumulus_generation_devices(
            generator_devices,
            deployment_scope="air",
            air_source_hostnames={"leaf01"},
        )
        published_devices, published_profiles = (
            PUBLISHER.scope_cumulus_publish_inventory(
                publisher_devices, profiles, deployment_scope="air",
            )
        )

        self.assertEqual(["AIR-leaf01"], [item["hostname"] for item in dhcp])
        self.assertEqual(["leaf01"], list(generated))
        self.assertEqual(["air-leaf01"], list(published_devices))
        self.assertEqual(["air-leaf01"], list(published_profiles))

    def test_description_patch_reports_unused_breakout_fillers_as_info(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "generated"
            output.mkdir()
            (output / "leaf01.yaml").write_text(
                "- set:\n"
                "    interface:\n"
                "      swp13:\n"
                "        link:\n"
                "          breakout:\n"
                "            8x:\n"
                "              lanes-per-port: '1'\n"
                "        type: swp\n"
                "      swp13s0:\n"
                "        type: swp\n"
                "      swp13s2:\n"
                "        type: swp\n"
                "      swp13s3:\n"
                "        type: swp\n"
                "        qos:\n"
                "          pfc-watchdog:\n"
                "            state: enable\n"
                "      swp13s4:\n"
                "        type: swp\n"
                "      swp99:\n"
                "        bridge:\n"
                "          domain:\n"
                "            br_default: {}\n"
                "        type: swp\n"
                "    router:\n"
                "      bgp:\n"
                "        autonomous-system:\n"
                "          '65000':\n"
                "            address-family:\n"
                "              ipv4-unicast:\n"
                "                redistribute:\n"
                "                  connected: {}\n"
                "            interface:\n"
                "              swp13s4:\n"
                "                type: unnumbered\n",
                encoding="utf-8",
            )
            dot = root / "topology-lldpq.dot"
            dot.write_text(
                '"site-leaf01":"swp13s0" -- "peer01":"swp1"\n',
                encoding="utf-8",
            )
            output_text = io.StringIO()
            with mock.patch.object(
                GENERATOR, "_load_csv_hostnames", return_value={"leaf01"},
            ), redirect_stdout(output_text):
                GENERATOR._run_patch_descriptions(str(dot), str(output))

        report = output_text.getvalue()
        self.assertIn(
            "[INFO] breakout 模式自动补齐的未使用子端口",
            report,
        )
        self.assertIn("P2P 无记录，未添加 description", report)
        self.assertIn("leaf01: swp13s2, swp13s3", report)
        self.assertIn(
            "[WARNING] yaml 中有此接口但 dot 中无连接记录，未添加 description",
            report,
        )
        self.assertIn("leaf01: swp99, swp13s4", report)

    def test_p2p_endpoint_states_accept_historical_empty_forms_only(self) -> None:
        empty_forms = (
            ("", ""),
            ("Empty", ""),
            ("empty", "Empty"),
            ("NA", "N/A"),
            ("None", "null"),
            ("-", ""),
        )
        for device, port in empty_forms:
            with self.subTest(device=device, port=port):
                self.assertEqual(
                    "empty",
                    TOPOLOGY._classify_p2p_endpoint(
                        device, port, context="TAN Links row 3 source",
                    ),
                )
        self.assertEqual(
            "real",
            TOPOLOGY._classify_p2p_endpoint(
                "leaf01", "1/1", context="TAN Links row 4 source",
            ),
        )
        for device, port in (
            ("leaf01", ""),
            ("", "1/1"),
            ("Empty", "1/1"),
            ("leaf01", "Empty"),
        ):
            with self.subTest(invalid=(device, port)):
                with self.assertRaisesRegex(ValueError, "端点只填写了一部分"):
                    TOPOLOGY._classify_p2p_endpoint(
                        device, port, context="TAN Links row 5 destination",
                    )

    def test_p2p_extraction_preserves_blank_and_placeholder_peer_intent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workbook_path = Path(directory) / "p2p.xlsx"
            workbook = TOPOLOGY.openpyxl.Workbook()
            sheet = workbook.active
            sheet.title = "TAN Links"
            sheet.append([None] * 6 + ["Source", None, None, None, None, None, "Dest", None])
            sheet.append([None] * 6 + ["name", "port", None, None, None, None, "name", "port"])
            sheet.append([None] * 6 + ["leaf01", "1/1", None, None, None, None, "peer01", "2/1"])
            sheet.append([None] * 6 + ["Empty", None, None, None, None, None, "leaf01", "1/2"])
            sheet.append([None] * 6 + [None, None, None, None, None, None, "leaf01", "1/3"])
            sheet.append([None] * 6 + ["leaf01", "1/4", None, None, None, None, "Empty", "Empty"])
            fallback = workbook.create_sheet("OOB Plan")
            fallback.cell(row=2, column=7, value="leaf99")
            fallback.cell(row=2, column=8, value="1/9")
            fallback.cell(row=2, column=13, value="Empty")
            workbook.save(workbook_path)
            workbook.close()

            source_rows = TOPOLOGY._extract_xlsx_rows(
                str(workbook_path), legacy_columns=True,
            )

        self.assertEqual(
            [
                ("leaf01", "1/1", "peer01", "2/1"),
                ("Empty", "", "leaf01", "1/2"),
                ("", "", "leaf01", "1/3"),
                ("leaf01", "1/4", "Empty", "Empty"),
            ],
            [row["fields"] for row in source_rows],
        )
        self.assertEqual([3, 4, 5, 6], [row["row"] for row in source_rows])
        self.assertEqual({"TAN Links"}, {row["sheet"] for row in source_rows})

    def test_p2p_empty_intent_is_bound_and_conflicts_with_real_peer(self) -> None:
        dot_bytes = b'graph "example" {\n"leaf01":"swp1" -- "peer01":"swp2"\n}\n'
        rows = [
            {"sheet": "TAN Links", "row": 3,
             "fields": ("leaf01", "swp1", "peer01", "swp2")},
            {"sheet": "TAN Links", "row": 4,
             "fields": ("leaf01", "swp3", "Empty", "")},
        ]
        document = TOPOLOGY._build_description_intent_document(
            rows,
            inv_patterns={"Eth-SW": ["leaf*"]}, type_order=["Eth-SW"],
            port_direct={}, port_switch={},
            splitter_profiles={}, lldpq_bytes=dot_bytes,
            source_workbook="p2p.xlsx",
        )
        self.assertEqual(1, document["schema_version"])
        self.assertEqual(hashlib.sha256(dot_bytes).hexdigest(), document["lldpq_sha256"])
        self.assertEqual(
            [{
                "device": "leaf01", "port": "swp3", "source_port": "swp3",
                "sheet": "TAN Links", "row": 4,
            }],
            document["empty_endpoints"],
        )
        physical, _ztp_bmc = TOPOLOGY._resolved_physical_links(
            [row["fields"] for row in rows],
            inv_patterns={"Eth-SW": ["leaf*"]}, type_order=["Eth-SW"],
            port_direct={}, port_switch={}, splitter_profiles={},
        )
        self.assertEqual(
            [("leaf01", "swp1", "peer01", "swp2")], physical,
        )

        conflicting = rows + [{
            "sheet": "TAN Links", "row": 5,
            "fields": ("leaf01", "swp3", "peer02", "swp4"),
        }]
        with self.assertRaisesRegex(
            ValueError, r"leaf01:swp3.*row 4.*row 5",
        ):
            TOPOLOGY._build_description_intent_document(
                conflicting,
                inv_patterns={"Eth-SW": ["leaf*"]}, type_order=["Eth-SW"],
                port_direct={}, port_switch={},
                splitter_profiles={}, lldpq_bytes=dot_bytes,
                source_workbook="p2p.xlsx",
            )

    def test_p2p_empty_intent_patches_description_and_keeps_fallback_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "generated"
            output.mkdir()
            (output / "leaf01.yaml").write_text(
                "- set:\n"
                "    interface:\n"
                "      swp13:\n"
                "        link:\n"
                "          breakout:\n"
                "            8x:\n"
                "              lanes-per-port: '1'\n"
                "        type: swp\n"
                "      swp13s0:\n"
                "        type: swp\n"
                "      swp13s1:\n"
                "        type: swp\n"
                "      swp13s2:\n"
                "        type: swp\n"
                "      swp13s3:\n"
                "        bridge:\n"
                "          domain:\n"
                "            br_default: {}\n"
                "        type: swp\n",
                encoding="utf-8",
            )
            dot = root / "topology-lldpq.dot"
            dot_bytes = (
                'graph "example" {\n'
                '"site-leaf01":"swp13s0" -- "peer01":"swp1"\n'
                '}\n'
            ).encode("utf-8")
            dot.write_bytes(dot_bytes)
            intent = TOPOLOGY._build_description_intent_document(
                [
                    {
                        "sheet": "TAN Links", "row": 9,
                        "fields": ("site-leaf01", "swp13s1", "Empty", ""),
                    },
                    {
                        "sheet": "TAN Links", "row": 10,
                        "fields": ("site-leaf01", "swp13s4", "", ""),
                    },
                    {
                        "sheet": "TAN Links", "row": 11,
                        "fields": ("site-missing01", "swp1", "Empty", "Empty"),
                    },
                ],
                inv_patterns={"Eth-SW": ["site-*"]},
                type_order=["Eth-SW"], port_direct={}, port_switch={},
                splitter_profiles={}, lldpq_bytes=dot_bytes,
                source_workbook="p2p.xlsx",
            )
            TOPOLOGY._write_description_intent(dot, intent)

            output_text = io.StringIO()
            with mock.patch.object(
                GENERATOR, "_load_csv_hostnames", return_value={"leaf01"},
            ), redirect_stdout(output_text):
                GENERATOR._run_patch_descriptions(str(dot), str(output))

            generated = GENERATOR._load_generated_yaml(
                (root / "generated_with_desc/leaf01.yaml").read_text(
                    encoding="utf-8",
                )
            )

        interfaces = generated[0]["set"]["interface"]
        self.assertEqual(
            "P2P:----UNUSED-----NO-PEER",
            interfaces["swp13s1"]["description"],
        )
        self.assertNotIn("description", interfaces["swp13s2"])
        report = output_text.getvalue()
        self.assertIn("breakout 模式自动补齐的未使用子端口", report)
        self.assertIn("P2P 空对端，已添加 description", report)
        self.assertIn("leaf01: swp13s1", report)
        self.assertIn("P2P 无记录，未添加 description", report)
        self.assertIn("leaf01: swp13s2", report)
        self.assertIn(
            "[WARNING] yaml 中有此接口但 dot 中无连接记录",
            report,
        )
        self.assertIn("leaf01: swp13s3", report)
        self.assertIn(
            "[WARNING] P2P 标记为空的接口未出现在 yaml 中",
            report,
        )
        self.assertIn("leaf01: swp13s4", report)
        self.assertIn("site-missing01: swp1", report)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dot = root / "stale-lldpq.dot"
            original = b'graph "example" {\n}\n'
            dot.write_bytes(original)
            intent = TOPOLOGY._build_description_intent_document(
                [], inv_patterns={}, type_order=[], port_direct={},
                port_switch={}, splitter_profiles={}, lldpq_bytes=original,
                source_workbook="p2p.xlsx",
            )
            TOPOLOGY._write_description_intent(dot, intent)
            dot.write_bytes(b'graph "changed" {\n}\n')
            with self.assertRaisesRegex(
                ValueError, "does not match current LLDPQ DOT",
            ):
                GENERATOR._load_description_intent(str(dot))

    def test_parent_release_rejects_child_from_another_deployment_scope(self) -> None:
        inputs = LOAD.replace(self.inputs, deployment_scope="air")
        air_inventory = [{
            "hostname": "AIR-leaf01", "hostname_key": "air-leaf01",
            "type": "air", "eth0_mac": "02:00:00:00:00:01",
            "eth1_mac": "", "identity_state": "identified",
        }]
        with mock.patch.object(
            LOAD, "_release_inventory", return_value=[],
        ), mock.patch.object(
            LOAD, "_augment_air_json_inventory", return_value=air_inventory,
        ), mock.patch.object(
            LOAD, "_load_release_json",
            return_value={"deployment_scope": "prod"},
        ):
            with self.assertRaisesRegex(
                LOAD.LoadError, "DHCP release deployment scope",
            ):
                LOAD.validate_and_publish_release(
                    self.project, inputs, publish=False,
                )

    def test_load_mini_reaches_real_air_dot_and_json_generation(self) -> None:
        self.assertEqual(
            "04-air-mini-devices.txt",
            LOAD.parse_args(["example-project", "--mini"]).mini,
        )
        self.assertEqual(
            "customer-devices.txt",
            LOAD.parse_args([
                "example-project", "--mini", "customer-devices.txt",
            ]).mini,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            mini_source = project / "customer-devices.txt"
            mini_devices = project / "04-air-mini-devices.txt"
            policy_path = project / "03-air-topology-policy.json"
            policy = {
                "node_allowlist": {},
                "link_rewrites": [],
                "mini_sampling": {
                    "location_prefix_regex": r"^[a-z]\d+-(?P<logical>.+)$",
                    "unknown_role_action": "error",
                    "roles": [
                        {
                            "name": "tan-spine",
                            "hostname_regex": r"^tan-spine(?P<index>\d+)$",
                            "selection": {"mode": "first", "count": 1},
                        },
                        {
                            "name": "tan-leaf",
                            "hostname_regex": (
                                r"^tan-pod(?P<zone>\d+)-leaf(?P<index>\d+)$"
                            ),
                            "selection": {"mode": "first", "count": 2},
                        },
                        {
                            "name": "anchored-oob-leaf",
                            "hostname_regex": (
                                r"^oob-pod(?P<zone>\d+)-leaf(?P<index>\d+)$"
                            ),
                            "selection": {
                                "mode": "anchor",
                                "peer_hostname_regex": r"^(?:tan|ib)(?:-|.+)$",
                                "peer_port_regex": r"^eth0$",
                            },
                        },
                        {
                            "name": "oob-spine",
                            "hostname_regex": (
                                r"^oob-pod(?P<zone>\d+)-spine(?P<index>\d+)$"
                            ),
                            "selection": {
                                "mode": "indices", "capture_group": "index",
                                "indices": [1, 3], "group_by": ["zone"],
                            },
                        },
                        {
                            "name": "rack-tor",
                            "hostname_regex": (
                                r"^oob-pod(?P<zone>\d+)r(?P<rack>\d+)-"
                                r"tor(?P<index>\d+)$"
                            ),
                            "selection": {
                                "mode": "match_fields",
                                "fields": {"rack": [1], "index": [1]},
                                "group_by": ["zone"],
                            },
                        },
                    ],
                },
            }
            policy_path.write_text(
                json.dumps(policy, sort_keys=True) + "\n", encoding="utf-8",
            )
            mini_source.write_text(
                "tan-spine02\n"
                "tan-spine02\n",
                encoding="utf-8",
            )
            lldpq = root / "source-lldpq.dot"
            lldpq.write_text(
                "graph synthetic {\n"
                '"a01-tan-spine01":"swp1" -- '
                '"a03-tan-pod1-leaf01":"swp1"\n'
                '"b01-tan-spine02":"swp1" -- '
                '"a03-tan-pod1-leaf01":"swp2"\n'
                '"c01-tan-spine03":"swp1" -- '
                '"a03-tan-pod1-leaf01":"swp3"\n'
                '"a01-tan-spine01":"swp2" -- '
                '"b03-tan-pod1-leaf02":"swp1"\n'
                '"b01-tan-spine02":"swp2" -- '
                '"c03-tan-pod1-leaf03":"swp1"\n'
                '"a01-tan-spine01":"eth0" -- '
                '"b05-oob-pod1-leaf07":"swp49"\n'
                '"b01-tan-spine02":"swp3" -- '
                '"a05-oob-pod1-leaf01":"swp48"\n'
                '"c05-oob-pod1-leaf03":"swp1" -- '
                '"c14-ib-pod1rail1-leaf01":"eth0"\n'
                '"c05-oob-pod1-leaf03":"swp49" -- '
                '"a06-oob-pod1-spine01":"swp1"\n'
                '"c05-oob-pod1-leaf03":"swp2" -- '
                '"z01-x86-mgmt-server01(ztp-server)":"eth1"\n'
                '"b05-oob-pod1-leaf07":"swp51" -- '
                '"c06-oob-pod1-spine03":"swp1"\n'
                '"a05-oob-pod1-leaf01":"swp49" -- '
                '"b06-oob-pod1-spine02":"swp1"\n'
                '"a07-oob-pod1r01-tor01":"swp49" -- '
                '"a06-oob-pod1-spine01":"swp2"\n'
                '"b07-oob-pod1r01-tor02":"swp49" -- '
                '"b06-oob-pod1-spine02":"swp2"\n'
                "}\n",
                encoding="utf-8",
            )
            air_dot = root / "air.dot"
            air_json = root / "air.json"

            def run_and_materialize_air(command, **_kwargs):
                if len(command) < 2 or command[1] != "b-xlsx_to_dot.py":
                    return
                TOPOLOGY.generate_air_dot(
                    lldpq, air_dot,
                    {"Eth-SW": [
                        "*tan-spine*", "*tan-pod*-leaf*", "*oob-pod*-leaf*",
                        "*oob-pod*-spine*", "*oob-pod*r*-tor*",
                    ]},
                    ["Eth-SW"],
                    os_version=command[command.index("--os-version") + 1],
                    template_file=TOPOLOGY.AIR_JSON_TEMPLATE,
                    air_topology_policy=TOPOLOGY.load_air_topology_policy(
                        Path(command[command.index("--air-link-policy") + 1]),
                        project_root=project,
                    ),
                    mini="--mini" in command,
                    mini_devices_file=Path(command[command.index("--mini") + 1]),
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
                    eth_version="5.18", mini_air=True,
                    air_topology_policy=policy_path,
                    mini_devices_file=mini_source,
                )

            command = runner.call_args_list[0].args[0]
            self.assertEqual([
                sys.executable, "b-xlsx_to_dot.py", "-y",
                "--os-version", "5.18",
                "--air-link-policy", str(policy_path),
                "--mini", str(mini_source),
            ], command)
            nodes = json.loads(
                air_json.read_text(encoding="utf-8")
            )["content"]["nodes"]
            self.assertEqual({
                "AIR-a01-tan-spine01",
                "AIR-b01-tan-spine02",
                "AIR-a03-tan-pod1-leaf01",
                "AIR-b03-tan-pod1-leaf02",
                "AIR-c05-oob-pod1-leaf03",
                "AIR-b05-oob-pod1-leaf07",
                "AIR-a06-oob-pod1-spine01",
                "AIR-c06-oob-pod1-spine03",
                "AIR-a07-oob-pod1r01-tor01",
                "ztp-server",
            }, set(nodes))
            dot_nodes, _links = TOPOLOGY._parse_air_dot(air_dot)
            self.assertTrue(dot_nodes)
            self.assertTrue(
                all(int(attributes["memory"]) >= 4096
                    for _name, attributes in dot_nodes),
                dot_nodes,
            )
            self.assertTrue(
                all(node["memory"] >= 4096 for node in nodes.values()),
                nodes,
            )
            self.assertEqual(
                {"cpu": 8, "memory": 8192, "storage": 80},
                {
                    field: nodes["ztp-server"][field]
                    for field in ("cpu", "memory", "storage")
                },
            )
            positions = {
                name: node["positioning"] for name, node in nodes.items()
            }
            self.assertEqual(len(positions), len({
                (position["x"], position["y"])
                for position in positions.values()
            }))
            tan = [name for name in nodes if "-tan-" in name]
            oob = [name for name in nodes if "-oob-" in name]
            self.assertTrue(tan)
            self.assertTrue(oob)
            self.assertLess(
                max(positions[name]["x"] for name in tan),
                min(positions[name]["x"] for name in oob),
            )
            for zone in (tan, oob):
                spines = [name for name in zone if "spine" in name]
                leaves = [
                    name for name in zone
                    if "leaf" in name or "tor" in name
                ]
                self.assertTrue(spines)
                self.assertTrue(leaves)
                self.assertLess(
                    max(positions[name]["y"] for name in spines),
                    min(positions[name]["y"] for name in leaves),
                )
            self.assertIn("[minimum-required]", mini_devices.read_text())
            self.assertEqual(2, mini_devices.read_text().count("tan-spine02"))
            self.assertTrue(mini_source.is_symlink())
            self.assertEqual("04-air-mini-devices.txt", os.readlink(mini_source))

    def test_load_to_real_air_mini_policy_binds_inputs_and_rolls_back_drift(self) -> None:
        policy_path = self.project / "03-air-topology-policy.json"
        policy_path.write_text(
            json.dumps(
                h19_mini_policy(unknown_role_action="keep"), sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        mini_source = self.project / "customer-mini.txt"
        mini_source.write_text("moon-crystal-edge-02\n", encoding="utf-8")
        canonical = self.project / "04-air-mini-devices.txt"
        lldpq = self.root / "heterogeneous-lldpq.dot"
        lldpq.write_text(
            "graph synthetic {\n"
            '"moon-orbital-hub-01":"swp1" -- '
            '"moon-crystal-edge-01":"swp1"\n'
            '"mars-orbital-hub-02":"swp1" -- '
            '"moon-crystal-edge-02":"swp1"\n'
            '"nova-anchor-gateway-01":"swp1" -- '
            '"moon-orbital-hub-01":"eth0"\n'
            '"comet-unclassified-switch":"swp1" -- '
            '"moon-crystal-edge-01":"swp2"\n'
            '"moon-crystal-edge-01":"swp3" -- '
            '"nova-x86-mgmt-server01(ztp-server)":"eth1"\n'
            "}\n",
            encoding="utf-8",
        )
        air_dot = self.root / "heterogeneous-air.dot"
        air_json = self.root / "heterogeneous-air.json"

        def run_real_topology(command, **_kwargs):
            if len(command) < 2 or command[1] != "b-xlsx_to_dot.py":
                return
            policy_argument = Path(
                command[command.index("--air-link-policy") + 1]
            )
            loaded_policy = TOPOLOGY.load_air_topology_policy(
                policy_argument, project_root=self.project,
            )
            TOPOLOGY.generate_air_dot(
                lldpq, air_dot,
                {"Eth-SW": [
                    "*orbital-hub*", "*crystal-edge*",
                    "*anchor-gateway*", "*unclassified-switch*",
                ]},
                ["Eth-SW"], os_version="5.18",
                template_file=TOPOLOGY.AIR_JSON_TEMPLATE,
                air_topology_policy=loaded_policy,
                mini=True,
                mini_devices_file=Path(command[command.index("--mini") + 1]),
            )
            TOPOLOGY.generate_air_json(
                air_dot, air_json, TOPOLOGY.AIR_JSON_TEMPLATE,
                lldpq_file=lldpq, air_topology_policy=loaded_policy,
            )

        with mock.patch.object(
            LOAD, "ZTP_DIR", self.root / "ztp-workflow",
        ), mock.patch.object(
            LOAD, "run", side_effect=run_real_topology,
        ) as runner:
            LOAD.generate_configs(
                frozenset({"eth"}), install_dhcp=False, dry_run=True,
                eth_version="5.18", air_topology_policy=policy_path,
                mini_air=True, mini_devices_file=mini_source,
            )

            topology_command = runner.call_args_list[0].args[0]
            self.assertIn("--air-link-policy", topology_command)
            self.assertEqual(
                str(policy_path),
                topology_command[topology_command.index("--air-link-policy") + 1],
            )
            nodes = set(json.loads(air_json.read_text(encoding="utf-8"))[
                "content"
            ]["nodes"])
            self.assertEqual({
                "AIR-moon-orbital-hub-01",
                "AIR-moon-crystal-edge-01",
                "AIR-moon-crystal-edge-02",
                "AIR-nova-anchor-gateway-01",
                "AIR-comet-unclassified-switch",
                "ztp-server",
            }, nodes)
            selection_report = json.loads(
                air_dot.with_name(
                    "heterogeneous-air-mini-selection.json"
                ).read_text(encoding="utf-8")
            )
            explicit_reason = next(
                item for item in selection_report["selection_reasons"]
                if item["hostname"] == "moon-crystal-edge-02"
            )
            self.assertEqual({
                "hostname": "moon-crystal-edge-02",
                "role": "crystal-edge",
                "selected": True,
                "reason": "explicit 04-air-mini-devices.txt selection",
            }, explicit_reason)
            self.assertTrue(mini_source.is_symlink())
            self.assertEqual(canonical.name, os.readlink(mini_source))

            # Generation above deliberately uses a hermetic script tree;
            # parent validation consumes the real setUp child manifests.
            LOAD.ZTP_DIR = self.ztp
            inputs = LOAD.replace(
                self.inputs, air_topology_policy=policy_path,
                mini_devices_file=canonical, mini_source_file=mini_source,
            )
            parent = LOAD.validate_and_publish_release(self.project, inputs)
            self.assertEqual(
                sha256(policy_path), parent["inputs"]["air_topology_policy"],
            )
            self.assertEqual(
                sha256(canonical), parent["inputs"]["mini_air_devices"],
            )
            current = self.project / "99-output-ztp/current-release.json"
            stable_current = current.read_bytes()
            stable_outputs = {
                path: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
                for path in (air_dot, air_json)
            }

            changed = h19_mini_policy(unknown_role_action="exclude")
            policy_path.write_text(
                json.dumps(changed, sort_keys=True) + "\n", encoding="utf-8",
            )
            with self.assertRaisesRegex(
                LOAD.LoadError, r"AIR.*policy.*changed|AIR.*策略.*变化",
            ):
                LOAD.validate_and_publish_release(self.project, inputs)
            self.assertEqual(stable_current, current.read_bytes())
            for path, expected in stable_outputs.items():
                self.assertEqual(expected, (
                    path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns,
                ))

            policy_path.write_text("{", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid AIR topology policy JSON"):
                LOAD.generate_configs(
                    frozenset({"eth"}), install_dhcp=False, dry_run=True,
                    eth_version="5.18", air_topology_policy=policy_path,
                    mini_air=True, mini_devices_file=mini_source,
                )
            self.assertEqual(stable_current, current.read_bytes())
            for path, expected in stable_outputs.items():
                self.assertEqual(expected, (
                    path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns,
                ))

    def test_load_mini_list_is_confined_to_project_and_aliases_only_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            customer = project / "customer.txt"
            customer.write_text("tan-spine02\n", encoding="utf-8")
            canonical = project / "04-air-mini-devices.txt"

            source, destination = LOAD.project_mini_air_devices(
                project, customer.name,
            )
            self.assertEqual(customer.resolve(), source)
            self.assertEqual(canonical.resolve(), destination)
            self.assertEqual(
                (canonical.resolve(), canonical.resolve()),
                LOAD.project_mini_air_devices(project, canonical.name),
            )

            outside = root / "outside.txt"
            outside.write_text("tan-spine03\n", encoding="utf-8")
            with self.assertRaisesRegex(LOAD.LoadError, "项目根目录"):
                LOAD.project_mini_air_devices(project, str(outside))

            customer.unlink()
            customer.symlink_to(outside)
            with self.assertRaisesRegex(LOAD.LoadError, "相对指向"):
                LOAD.project_mini_air_devices(project, customer.name)

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
                "02:00:00:00:00:12,,,,\n"
                "AIR-example-site-stale01,air,leaf,192.0.2.10,24,192.0.2.1,"
                "02:00:00:00:01:13,,,,\n",
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
                HTTP_ROOT=str(root),
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
            self.assertNotIn(
                "AIR-example-site-stale01",
                {item["hostname"] for item in devices},
            )
            with devices_file.open(newline="", encoding="utf-8") as stream:
                refreshed_rows = list(csv.DictReader(stream))
            self.assertNotIn(
                "AIR-example-site-stale01",
                {item["hostname"] for item in refreshed_rows},
            )

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

    def test_macos_requirements_print_before_password_preflight_and_any_lock(self) -> None:
        events = []
        original_validator = LOAD.validate_macos_client_requirements
        status = LOAD.MacOSClientRequirementStatus(
            python_version="3.9.6",
            python_supported=True,
            missing_generation_modules=(),
            missing_commands=(),
            missing_validation_modules=(),
            password_backend="Homebrew libxcrypt (/opt/homebrew/libcrypt.dylib)",
            homebrew="/opt/homebrew/bin/brew",
        )

        def show_requirements(**kwargs):
            self.assertTrue(kwargs["update_passwords"])
            events.append("requirements")
            return status

        def validate_requirements(received):
            self.assertIs(received, status)
            events.append("dependency-gate")
            original_validator(received)

        def reject_backend():
            events.append("password-backend")
            raise LOAD.LoadError("stop after macOS prerequisite order")

        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            LOAD, "runtime_os", return_value="Darwin",
        ), mock.patch.object(
            LOAD, "print_macos_client_requirements", side_effect=show_requirements,
        ), mock.patch.object(
            LOAD, "validate_macos_client_requirements",
            side_effect=validate_requirements,
        ), mock.patch.object(
            LOAD, "preflight_password_update_backend", side_effect=reject_backend,
        ), mock.patch.object(
            LOAD, "acquire_deployment_lock",
        ) as acquire, redirect_stdout(stdout), redirect_stderr(stderr):
            result = LOAD.main(["demo", "--update-passwords"])

        self.assertEqual(1, result)
        self.assertEqual(
            ["requirements", "dependency-gate", "password-backend"], events,
        )
        acquire.assert_not_called()
        self.assertIn("stop after macOS prerequisite order", stderr.getvalue())

    def test_macos_missing_generation_dependency_stops_before_password_and_lock(
        self,
    ) -> None:
        status = LOAD.MacOSClientRequirementStatus(
            python_version="3.9.6",
            python_supported=True,
            missing_generation_modules=("openpyxl",),
            missing_commands=("rsync",),
            missing_validation_modules=("XlsxWriter",),
            password_backend=None,
            homebrew=None,
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            LOAD, "runtime_os", return_value="Darwin",
        ), mock.patch.object(
            LOAD, "print_macos_client_requirements", return_value=status,
        ), mock.patch.object(
            LOAD, "preflight_password_update_backend",
        ) as password_backend, mock.patch.object(
            LOAD, "acquire_deployment_lock",
        ) as acquire, redirect_stdout(stdout), redirect_stderr(stderr):
            result = LOAD.main(["demo", "--update-passwords"])

        self.assertEqual(1, result)
        password_backend.assert_not_called()
        acquire.assert_not_called()
        self.assertRegex(stderr.getvalue(), r"openpyxl.*先安装")

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
            deployment_lock_descriptor=73,
            install_dhcp=False,
            dry_run=False,
            schema_version=remote_inputs.settings.schema_version,
            eth_version="5.18",
            air_topology_policy=air_policy,
            deployment_scope="all",
            switch_scope="all",
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
        stop_monitor = mock.Mock()

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
                LOAD, "stop_native_ztp_monitors", stop_monitor,
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
        require_inactive.assert_called_once_with(
            False, runtime_backend=mock.ANY,
        )
        quiesce.assert_not_called()
        stop_monitor.assert_called_once_with(LOAD.HTTP_ROOT)
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
            eth_version, air_topology_policy, deployment_scope, switch_scope,
            deployment_lock_descriptor,
        ):
            self.assertFalse(install_dhcp)
            self.assertFalse(dry_run)
            self.assertEqual(1, schema_version)
            self.assertIsNone(eth_version)
            self.assertIsNone(air_topology_policy)
            self.assertEqual("all", deployment_scope)
            self.assertEqual("all", switch_scope)
            self.assertEqual(75, deployment_lock_descriptor)
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
                deployment_scope=deployment_scope,
                switch_scope=switch_scope,
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
