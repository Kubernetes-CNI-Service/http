#!/usr/bin/env python3
"""Real DAY0 load -> DHCP-generator contract for optional generation."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest import mock

from test_cases.test_dhcp_optional_contract import (
    DHCP, EMPTY_SUBNET_TABLE, EMPTY_SUBNET_TABLE_SHA256, LOAD, SETUP,
    global_document, settings_for,
)
from test_cases.test_dhcp_switch_scope_preservation import AIR_HOST, ScopedDhcpFixture
from test_cases import test_load_release_transaction as release_fixture
from test_cases.module_loader import load_script
import yaml

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = load_script("optional_empty_subnet_runtime", ROOT / "tools/ztp_service_runtime.py")
ACTIVATE = load_script("optional_empty_subnet_docker", ROOT / "infra/docker/activate.py")


class DhcpOptionalWorkflowTests(unittest.TestCase):
    def test_r22_http_only_supervisor_is_shared_by_setup_load_runtime_and_docker(self):
        """Header-only off/off plus explicit HTTP address starts Apache alone."""
        with tempfile.TemporaryDirectory() as name:
            http_root = Path(name)
            project = http_root / "DAY0-Prepare/project"
            project.mkdir(parents=True)
            document = global_document("disabled")
            mgmt = document["common"]["mgmt"]
            mgmt["ztp"]["status"] = "disabled"
            mgmt["http"]["status"] = "enabled"
            mgmt["http"]["address"] = "192.0.2.88"
            global_yaml = project / "01-global.yaml"
            global_yaml.write_text(yaml.safe_dump(document), encoding="utf-8")
            subnet = project / "02-dhcp-subnet_config.csv"
            subnet.write_bytes(EMPTY_SUBNET_TABLE)
            self.assertEqual(([], []), SETUP._validate_subnet_csv(
                subnet, dhcp_enabled=False, ztp_enabled=False,
            ))
            settings = LOAD.apply_subnet_service_ips(LOAD.load_global(global_yaml), subnet)
            settings = LOAD.replace(settings, http_root=LOAD.HTTP_ROOT)
            LOAD.validate_subnet_file(subnet, settings)
            inputs = SimpleNamespace(settings=settings, subnet_file=subnet)
            native = LOAD.plan_local_dhcp_runtime(
                inputs, link_snapshot=[], address_snapshot=[], environment={},
            )
            runtime = RUNTIME.plan_dhcp_runtime(
                subnet, link_snapshot=[], address_snapshot=[],
                dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertEqual(((), ()), (native.endpoint_ips, native.listener_names))
            self.assertEqual(native.endpoint_ips, runtime.endpoint_ips)
            docker_settings = ACTIVATE.Settings(
                http_root=http_root, project_name="project", scope="air",
            )
            with mock.patch.object(ACTIVATE, "validate_project_mount"), \
                    mock.patch.object(
                        ACTIVATE, "capture_stable_network_snapshot", return_value=([], []),
                    ), mock.patch.object(ACTIVATE, "_load_runtime_module", return_value=RUNTIME):
                selected, _links, _addresses, _runtime = ACTIVATE.build_runtime_plan(
                    docker_settings,
                )
            listeners = ACTIVATE.project_http_listener_ips(docker_settings, selected)
            self.assertEqual(("192.0.2.88",), listeners)
            self.assertEqual(("apache2",), ACTIVATE.expected_services(
                selected, dhcp_status="disabled", http_listener_ips=listeners,
            ))
            with mock.patch.object(
                LOAD, "local_ipv4_addresses", return_value={"192.0.2.88"},
            ), mock.patch.object(LOAD, "verify_control_auth"), \
                    mock.patch.object(LOAD, "verify_published_files"), \
                    mock.patch.object(LOAD, "verify_apache_publication_boundary"), \
                    mock.patch.object(LOAD, "verify_http_publication") as publication, \
                    mock.patch.object(LOAD, "ensure_ztp_url_network_ready") as ztp_gate, \
                    mock.patch.object(LOAD, "run") as command, \
                    mock.patch.object(LOAD, "_runtime_service_action") as action:
                self.assertEqual(
                    (True, False), LOAD.supervisor_service_availability(inputs, native),
                )
                LOAD.preflight_services(
                    inputs, {}, dry_run=True, dhcp_runtime_plan=native,
                    runtime_backend=SimpleNamespace(name="supervisor"),
                )
                LOAD.start_services(
                    inputs, {}, dry_run=True, dhcp_runtime_plan=native,
                    runtime_backend=SimpleNamespace(name="supervisor"),
                )
            self.assertTrue(any("apache2ctl" in str(call) for call in command.call_args_list))
            self.assertEqual("apache2", action.call_args.args[2])
            self.assertEqual(1, action.call_count)
            publication.assert_called_once_with(inputs, {}, True)
            ztp_gate.assert_not_called()
            with mock.patch.object(
                LOAD, "local_ipv4_addresses", return_value={"192.0.2.99"},
            ), self.assertRaisesRegex(LOAD.LoadError, "管理服务器门禁"):
                LOAD.supervisor_service_availability(inputs, native)

            mgmt["http"]["status"] = "disabled"
            global_yaml.write_text(yaml.safe_dump(document), encoding="utf-8")
            disabled = LOAD.apply_subnet_service_ips(LOAD.load_global(global_yaml), subnet)
            disabled_inputs = SimpleNamespace(settings=disabled, subnet_file=subnet)
            self.assertEqual(
                (), ACTIVATE.project_http_listener_ips(docker_settings, selected),
            )
            self.assertEqual(
                (), ACTIVATE.expected_services(
                    selected, dhcp_status="disabled", http_listener_ips=(),
                ),
            )
            self.assertEqual(
                (False, False), LOAD.supervisor_service_availability(
                    disabled_inputs, native,
                ),
            )

    def test_r22_middle_blank_lines_are_shared_by_setup_load_runtime_and_docker(self):
        """Four real entry points consume the same enabled row after a blank line."""
        with tempfile.TemporaryDirectory() as name:
            http_root = Path(name)
            project = http_root / "DAY0-Prepare/project"
            project.mkdir(parents=True)
            document = global_document("enabled")
            document["common"]["mgmt"]["ztp"]["status"] = "enabled"
            global_yaml = project / "01-global.yaml"
            global_yaml.write_text(yaml.safe_dump(document), encoding="utf-8")
            subnet = project / "02-dhcp-subnet_config.csv"
            subnet.write_bytes(
                EMPTY_SUBNET_TABLE + b" \t\r\n"
                + b"mgmt,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
                  b"192.0.2.1,192.0.2.10,oob,no\n"
            )
            self.assertEqual(([], []), SETUP._validate_subnet_csv(
                subnet, dhcp_enabled=True, ztp_enabled=True,
            ))
            settings = LOAD.load_global(global_yaml)
            LOAD.validate_subnet_file(subnet, settings)
            links = [{
                "ifindex": 7, "ifname": "eno7", "link_type": "ether",
                "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                "operstate": "UP",
            }]
            addresses = [{
                "ifindex": 7, "ifname": "eno7", "addr_info": [{
                    "family": "inet", "local": "192.0.2.10", "prefixlen": 24,
                    "scope": "global",
                }],
            }]
            plan = RUNTIME.plan_dhcp_runtime(
                subnet, link_snapshot=links, address_snapshot=addresses,
                dhcp_enabled=True, ztp_enabled=True,
            )
            self.assertEqual(("192.0.2.10",), plan.endpoint_ips)
            docker_settings = ACTIVATE.Settings(
                http_root=http_root, project_name="project", scope="air",
            )
            with mock.patch.object(ACTIVATE, "validate_project_mount"), \
                    mock.patch.object(
                        ACTIVATE, "capture_stable_network_snapshot",
                        return_value=(links, addresses),
                    ), mock.patch.object(
                        ACTIVATE, "_load_runtime_module", return_value=RUNTIME,
                    ):
                docker_plan, _links, _addresses, _runtime = ACTIVATE.build_runtime_plan(
                    docker_settings,
                )
            self.assertEqual(plan.endpoint_ips, docker_plan.endpoint_ips)

    def test_r22_whitespace_tail_is_valid_across_four_real_scripts(self):
        """An off/off header may end with blank and whitespace-only lines."""
        with tempfile.TemporaryDirectory() as name:
            http_root = Path(name)
            project = http_root / "DAY0-Prepare/project"
            project.mkdir(parents=True)
            document = global_document("disabled")
            document["common"]["mgmt"]["ztp"]["status"] = "disabled"
            global_yaml = project / "01-global.yaml"
            global_yaml.write_text(yaml.safe_dump(document), encoding="utf-8")
            subnet = project / "02-dhcp-subnet_config.csv"
            subnet.write_bytes(EMPTY_SUBNET_TABLE + b" \t\r\n\t\n")
            errors, warnings = SETUP._validate_subnet_csv(
                subnet, dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertEqual(([], []), (errors, warnings))
            LOAD.validate_subnet_file(subnet, LOAD.load_global(global_yaml))
            runtime_plan = RUNTIME.plan_dhcp_runtime(
                subnet, link_snapshot=[], address_snapshot=[],
                dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertEqual((), runtime_plan.listener_names)
            docker_settings = ACTIVATE.Settings(
                http_root=http_root, project_name="project", scope="air",
            )
            with mock.patch.object(ACTIVATE, "validate_project_mount"), \
                    mock.patch.object(
                        ACTIVATE, "capture_stable_network_snapshot",
                        return_value=([], []),
                    ), mock.patch.object(
                        ACTIVATE, "_load_runtime_module", return_value=RUNTIME,
                    ):
                selected, links, addresses, _runtime = ACTIVATE.build_runtime_plan(
                    docker_settings,
                )
            self.assertEqual((), selected.listener_names)
            self.assertEqual(([], []), (links, addresses))

    def test_r22_inplace_write_cannot_change_bytes_between_lexing_and_semantics(self):
        """A held inode may be edited; all readers must bind one byte snapshot."""
        with tempfile.TemporaryDirectory() as name:
            subnet = Path(name) / "02-dhcp-subnet_config.csv"
            disabled = LOAD.replace(settings_for("disabled"), ztp_enabled=False)
            original_read = os.read
            for stage in ("setup", "load", "runtime"):
                with self.subTest(stage=stage):
                    subnet.write_bytes(EMPTY_SUBNET_TABLE)
                    identity = (subnet.stat().st_dev, subnet.stat().st_ino)
                    changed = False

                    def edit_after_first_block(fd, size):
                        nonlocal changed
                        block = original_read(fd, size)
                        try:
                            metadata = os.fstat(fd)
                        except OSError:
                            return block
                        if (block and not changed and
                                (metadata.st_dev, metadata.st_ino) == identity):
                            changed = True
                            subnet.write_bytes(EMPTY_SUBNET_TABLE + b",,,,,,,,\n")
                        return block

                    with mock.patch.object(os, "read", side_effect=edit_after_first_block):
                        if stage == "setup":
                            errors, _warnings = SETUP._validate_subnet_csv(
                                subnet, dhcp_enabled=False, ztp_enabled=False,
                            )
                            self.assertTrue(errors)
                        elif stage == "load":
                            with self.assertRaises(LOAD.LoadError):
                                LOAD.validate_subnet_file(subnet, disabled)
                        else:
                            with self.assertRaises(RUNTIME.RuntimeContractError):
                                RUNTIME._read_dhcp_networks(
                                    subnet, dhcp_enabled=False, ztp_enabled=False,
                                )
                    self.assertTrue(changed, "race injection did not reach the held file")

    def test_r22_delimiter_only_record_never_becomes_disabled_empty_table(self):
        """All four real scripts reject a CSV record, not silently skip it."""
        with tempfile.TemporaryDirectory() as name:
            http_root = Path(name)
            project = http_root / "DAY0-Prepare/project"
            project.mkdir(parents=True)
            document = global_document("disabled")
            document["common"]["mgmt"]["ztp"]["status"] = "disabled"
            (project / "01-global.yaml").write_text(
                yaml.safe_dump(document), encoding="utf-8",
            )
            subnet = project / "02-dhcp-subnet_config.csv"
            subnet.write_bytes(EMPTY_SUBNET_TABLE + b",,,,,,,,\n")
            settings = LOAD.load_global(project / "01-global.yaml")
            errors, _warnings = SETUP._validate_subnet_csv(
                subnet, dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertIn("行2", " ".join(errors))
            with self.assertRaisesRegex(LOAD.LoadError, r"第 2 行|line 2"):
                LOAD.validate_subnet_file(subnet, settings)
            with self.assertRaisesRegex(RUNTIME.RuntimeContractError, r"line 2"):
                RUNTIME.plan_dhcp_runtime(
                    subnet, link_snapshot=[], address_snapshot=[],
                    dhcp_enabled=False, ztp_enabled=False,
                )
            docker_settings = ACTIVATE.Settings(
                http_root=http_root, project_name="project", scope="air",
            )
            with mock.patch.object(ACTIVATE, "validate_project_mount"), \
                    mock.patch.object(
                        ACTIVATE, "capture_stable_network_snapshot",
                        return_value=([], []),
                    ), mock.patch.object(
                        ACTIVATE, "_load_runtime_module", return_value=RUNTIME,
                    ), self.assertRaisesRegex(ACTIVATE.ActivationError, r"line 2"):
                ACTIVATE.build_runtime_plan(docker_settings)

    def test_r22_forbidden_global_pair_stops_all_four_real_script_boundaries(self):
        """An empty CSV never licenses DHCP-off/ZTP-on in any entry point."""
        with tempfile.TemporaryDirectory() as name:
            http_root = Path(name)
            project = http_root / "DAY0-Prepare/project"
            project.mkdir(parents=True)
            document = global_document("disabled")
            document["common"]["mgmt"]["ztp"]["status"] = "enabled"
            (project / "01-global.yaml").write_text(
                yaml.safe_dump(document), encoding="utf-8",
            )
            subnet = project / "02-dhcp-subnet_config.csv"
            subnet.write_bytes(EMPTY_SUBNET_TABLE)
            settings = LOAD.replace(
                LOAD.load_global(project / "01-global.yaml"),
                dhcp_enabled=False, ztp_enabled=True,
            )
            errors, _warnings = SETUP._validate_subnet_csv(
                subnet, dhcp_enabled=False, ztp_enabled=True,
            )
            self.assertIn("DHCP", " ".join(errors))
            self.assertIn("ZTP", " ".join(errors))
            with self.assertRaisesRegex(LOAD.LoadError, "DHCP.*ZTP"):
                LOAD.validate_subnet_file(subnet, settings)
            with self.assertRaisesRegex(RUNTIME.RuntimeContractError, "DHCP.*ZTP"):
                RUNTIME.plan_dhcp_runtime(
                    subnet, link_snapshot=[], address_snapshot=[],
                    dhcp_enabled=False, ztp_enabled=True,
                )
            docker_settings = ACTIVATE.Settings(
                http_root=http_root, project_name="project", scope="air",
            )
            with mock.patch.object(ACTIVATE, "validate_project_mount"), \
                    mock.patch.object(
                        ACTIVATE, "capture_stable_network_snapshot",
                        return_value=([], []),
                    ), mock.patch.object(
                        ACTIVATE, "_load_runtime_module", return_value=RUNTIME,
                    ), self.assertRaisesRegex(ACTIVATE.ActivationError, "DHCP.*ZTP"):
                ACTIVATE.build_runtime_plan(docker_settings)

    def test_disabled_generation_and_preflight_ignore_missing_all_dhcp_outputs(self):
        with tempfile.TemporaryDirectory() as name:
            fixture = ScopedDhcpFixture(Path(name))
            for path in fixture.outputs.values():
                path.unlink()
            commands = []
            with mock.patch.object(LOAD, "ZTP_DIR", fixture.root / "ztp"), \
                    mock.patch.object(LOAD, "run", side_effect=lambda argv, **kwargs: commands.append(argv)), \
                    mock.patch.object(LOAD, "_device_types_after_dhcp", return_value=frozenset({"ib"})), \
                    mock.patch.object(LOAD, "newest_directory", return_value=fixture.root / "generated"):
                LOAD.generate_configs(
                    frozenset({"ib"}), install_dhcp=False, dhcp_enabled=False,
                )
            self.assertFalse(any(
                token in str(command)
                for argv in commands for command in argv
                for token in ("c1-generate_dhcp.py", "dhcpd", "install")
            ))
            self.assertTrue(all(not path.exists() for path in fixture.outputs.values()))
            disabled = LOAD.replace(settings_for("disabled"), ztp_enabled=False)
            with mock.patch.object(LOAD, "dhcp_file_mappings", side_effect=AssertionError("DHCP artifacts consulted")), \
                    mock.patch.object(LOAD, "run") as runtime_run:
                LOAD.preflight_services(
                    SimpleNamespace(settings=disabled), {},
                    runtime_backend=SimpleNamespace(name="systemd"),
                )
                runtime_run.assert_not_called()

    def test_air_scoped_setup_empty_hosts_cross_install_and_start_checks(self):
        """Real setup placeholders and c1 output must survive both load gates."""
        with tempfile.TemporaryDirectory() as name:
            fixture = ScopedDhcpFixture(Path(name))
            fixture.add_air_inventory()
            project = fixture.root / "DAY0-Prepare/project"
            project.mkdir(parents=True)
            for label in ("conf", "eth", "ib", "nvl", "manifest"):
                path = fixture.outputs[label]
                path.unlink()
                SETUP._process_mapping(
                    str(project), f"config/isc-dhcp-server/{path.name}",
                    f"99-output-dhcp/{path.name}", "output",
                    link_root=str(fixture.root / "ztp"),
                )
                self.assertEqual(b"", path.read_bytes())
            fixture.execute([
                "c1-generate_dhcp.py", "-y", "--deployment-scope", "air",
                "--switch", "eth",
            ])
            self.assertIn(AIR_HOST, fixture.outputs["eth"].read_text())
            self.assertEqual(b"", fixture.outputs["ib"].read_bytes())
            self.assertEqual(b"", fixture.outputs["nvl"].read_bytes())
            manifest = json.loads(fixture.outputs["manifest"].read_text())
            self.assertEqual(
                {"eth": 1, "ib": 0, "nvl": 0},
                manifest["counts"]["host_declarations_by_family"],
            )

            live = fixture.root / "etc-dhcp"
            live.mkdir()
            mappings = {
                fixture.outputs[label]: live / fixture.outputs[label].name
                for label in ("conf", "eth", "ib", "nvl")
            }
            for destination in mappings.values():
                destination.write_bytes(f"OLD-{destination.name}\n".encode("ascii"))
            before_live = {
                destination.name: (destination.read_bytes(), destination.stat().st_ino)
                for destination in mappings.values()
            }
            receipt = fixture.outputs["manifest"]
            original_receipt = receipt.read_bytes()
            invalid_receipt = json.loads(original_receipt)
            invalid_receipt["outputs"]["dhcpd_ib.hosts"]["sha256"] = "0" * 64
            receipt.write_text(json.dumps(invalid_receipt), encoding="utf-8")
            import zipfile
            workbook = io.BytesIO()
            with zipfile.ZipFile(workbook, "w") as archive:
                archive.writestr("xl/workbook.xml", "<workbook/>\n")
            input_payloads = {
                "global": ("01-global.yaml", fixture.global_file.read_bytes()),
                "devices": ("02-devices_config.csv", fixture.devices_file.read_bytes()),
                "subnet": ("02-dhcp-subnet_config.csv", fixture.subnet_file.read_bytes()),
                "p2p": ("fixture-topology.xlsx", workbook.getvalue()),
            }
            for filename, payload in input_payloads.values():
                (project / filename).write_bytes(payload)
            (project / "p2p.xlsx").symlink_to("fixture-topology.xlsx")
            parent = LOAD.prepare_current_release(project, {
                "schema_version": 2, "release_id": "air-empty-parent-fixture",
                "inputs": {key: hashlib.sha256(payload).hexdigest()
                           for key, (_, payload) in input_payloads.items()},
                "input_paths": {key: filename
                                for key, (filename, _) in input_payloads.items()},
                "validation": "passed", "dhcp_status": "enabled",
                "deployment_scope": "air",
                "switch_scope": "eth", "components": {"dhcp": {
                    "manifest_sha256": hashlib.sha256(original_receipt).hexdigest(),
                }},
            })
            with mock.patch.object(LOAD, "dhcp_file_mappings", return_value=mappings), \
                    mock.patch.object(LOAD, "run", side_effect=AssertionError("unsafe install")) as forbidden_run, \
                    mock.patch.object(LOAD, "sudo_command", side_effect=lambda *args: list(args)), \
                    mock.patch.object(LOAD, "_run_subprocess", return_value=SimpleNamespace(returncode=0)), \
                    mock.patch.object(LOAD, "commit_prepared_release") as forbidden_commit, \
                    self.assertRaisesRegex(LOAD.LoadError, "DHCP release 输出 hash 漂移"):
                LOAD.mount_and_test_dhcp(parent_candidate=parent)
            forbidden_run.assert_not_called()
            forbidden_commit.assert_not_called()
            self.assertFalse(parent.committed)
            self.assertEqual(before_live, {
                destination.name: (destination.read_bytes(), destination.stat().st_ino)
                for destination in mappings.values()
            })
            receipt.write_bytes(original_receipt)
            stale_but_self_consistent = json.loads(original_receipt)
            stale_but_self_consistent["generated_at"] = "different-generation"
            receipt.write_text(json.dumps(stale_but_self_consistent), encoding="utf-8")
            with mock.patch.object(LOAD, "dhcp_file_mappings", return_value=mappings), \
                    mock.patch.object(LOAD, "run", side_effect=AssertionError("unsafe install")) as forbidden_run, \
                    mock.patch.object(LOAD, "sudo_command", side_effect=lambda *args: list(args)), \
                    mock.patch.object(LOAD, "_run_subprocess", return_value=SimpleNamespace(returncode=0)), \
                    mock.patch.object(LOAD, "commit_prepared_release") as forbidden_commit, \
                    self.assertRaisesRegex(LOAD.LoadError, "parent.*DHCP manifest"):
                LOAD.mount_and_test_dhcp(parent_candidate=parent)
            forbidden_run.assert_not_called()
            forbidden_commit.assert_not_called()
            self.assertFalse(parent.committed)
            self.assertEqual(before_live, {
                destination.name: (destination.read_bytes(), destination.stat().st_ino)
                for destination in mappings.values()
            })
            receipt.write_bytes(original_receipt)
            original_parent = parent.temporary.read_bytes()
            wrong_scope_parent = json.loads(original_parent)
            wrong_scope_parent["switch_scope"] = "ib"
            parent.temporary.write_text(json.dumps(wrong_scope_parent), encoding="utf-8")
            with mock.patch.object(LOAD, "dhcp_file_mappings", return_value=mappings), \
                    mock.patch.object(LOAD, "run", side_effect=AssertionError("unsafe install")) as forbidden_run, \
                    mock.patch.object(LOAD, "commit_prepared_release") as forbidden_commit, \
                    self.assertRaisesRegex(LOAD.LoadError, "parent.*scope/身份"):
                LOAD.mount_and_test_dhcp(parent_candidate=parent)
            forbidden_run.assert_not_called()
            forbidden_commit.assert_not_called()
            self.assertFalse(parent.committed)
            parent.temporary.write_bytes(original_parent)
            checks = []
            fail_final_syntax = [True]
            drift_after_staged_syntax = [False]

            def run_local(command, **_kwargs):
                operation = command[0]
                if operation == "install":
                    if "-d" in command:
                        for target in command[command.index("--") + 1:]:
                            Path(target).mkdir(parents=True, exist_ok=True)
                            Path(target).chmod(int(command[command.index("-m") + 1], 8))
                            if Path(target).name == "backup":
                                self.assertEqual(0o700, stat.S_IMODE(Path(target).stat().st_mode),
                                                 "private install port must preserve root-only backup mode")
                    else:
                        shutil.copy2(command[-2], command[-1])
                    return
                if operation == "cp":
                    shutil.copy2(command[-2], command[-1])
                    return
                if operation == "dhcpd":
                    checks.append(tuple(command))
                    self.assertEqual("-t", command[1])
                    if command[-1] != "/etc/dhcp/dhcpd.conf":
                        staged = Path(command[-1]).parent
                        self.assertEqual(b"", (staged / "dhcpd_ib.hosts").read_bytes())
                        self.assertEqual(b"", (staged / "dhcpd_nvl.hosts").read_bytes())
                        if drift_after_staged_syntax[0]:
                            fixture.outputs["eth"].write_bytes(
                                original_eth + b"# late source drift\n"
                            )
                    if fail_final_syntax[0] and len(checks) == 2:
                        raise OSError("injected final DHCP syntax failure")
                    return
                if operation == "apache2ctl":
                    return
                raise AssertionError(command)

            def cleanup_local(command, **_kwargs):
                target = Path(command[-1])
                if command[0] == "rm":
                    target.unlink(missing_ok=True)
                elif command[0] == "cp":
                    shutil.copy2(command[-2], command[-1])
                elif command[0] == "rmdir":
                    target.rmdir()
                else:
                    raise AssertionError(command)
                return SimpleNamespace(returncode=0)

            commit_parent = LOAD.commit_prepared_release
            with mock.patch.object(LOAD, "dhcp_file_mappings", return_value=mappings), \
                    mock.patch.object(LOAD, "sudo_command", side_effect=lambda *args: list(args)), \
                    mock.patch.object(LOAD, "run", side_effect=run_local), \
                    mock.patch.object(LOAD, "_run_subprocess", side_effect=cleanup_local), \
                    mock.patch.object(LOAD, "commit_prepared_release") as forbidden_commit, \
                    self.assertRaisesRegex(OSError, "injected final DHCP syntax failure"):
                LOAD.mount_and_test_dhcp(parent_candidate=parent)
            forbidden_commit.assert_not_called()
            self.assertFalse(parent.committed)
            self.assertFalse(parent.destination.exists())
            self.assertEqual({
                filename: payload for filename, (payload, _inode) in before_live.items()
            }, {
                destination.name: destination.read_bytes()
                for destination in mappings.values()
            })
            self.assertEqual(2, len(checks))
            checks.clear()
            fail_final_syntax[0] = False
            original_eth = fixture.outputs["eth"].read_bytes()
            drift_after_staged_syntax[0] = True
            with mock.patch.object(LOAD, "dhcp_file_mappings", return_value=mappings), \
                    mock.patch.object(LOAD, "sudo_command", side_effect=lambda *args: list(args)), \
                    mock.patch.object(LOAD, "run", side_effect=run_local), \
                    mock.patch.object(LOAD, "_run_subprocess", side_effect=cleanup_local), \
                    self.assertRaisesRegex(LOAD.LoadError, "DHCP source changed after staged syntax"):
                LOAD.mount_and_test_dhcp(parent_candidate=parent)
            self.assertEqual(1, len(checks))
            self.assertFalse(parent.committed)
            self.assertFalse(parent.destination.exists())
            self.assertEqual({
                filename: payload for filename, (payload, _inode) in before_live.items()
            }, {
                destination.name: destination.read_bytes()
                for destination in mappings.values()
            })
            fixture.outputs["eth"].write_bytes(original_eth)
            drift_after_staged_syntax[0] = False
            checks.clear()
            with mock.patch.object(LOAD, "dhcp_file_mappings", return_value=mappings), \
                    mock.patch.object(LOAD, "sudo_command", side_effect=lambda *args: list(args)), \
                    mock.patch.object(LOAD, "run", side_effect=run_local), \
                    mock.patch.object(LOAD, "_run_subprocess", side_effect=cleanup_local), \
                    mock.patch.object(
                        LOAD, "commit_prepared_release", side_effect=commit_parent,
                    ) as commit:
                LOAD.mount_and_test_dhcp(parent_candidate=parent)
                commit.assert_called_once_with(parent)
                self.assertTrue(parent.committed)
                self.assertEqual(b"", (live / "dhcpd_ib.hosts").read_bytes())
                self.assertEqual(b"", (live / "dhcpd_nvl.hosts").read_bytes())
                with mock.patch.object(LOAD, "validate_management_host", return_value=True), \
                        mock.patch.object(LOAD, "verify_control_auth"), \
                        mock.patch.object(LOAD, "verify_published_files"), \
                        mock.patch.object(LOAD, "verify_apache_publication_boundary"):
                    LOAD.preflight_services(
                        SimpleNamespace(settings=settings_for("enabled"),
                            global_file=project / "01-global.yaml"), {},
                        runtime_backend=SimpleNamespace(name="systemd"),
                    )
            self.assertEqual(3, len(checks))

    def test_invalid_subnet_cannot_cross_setup_load_runtime_or_docker_boundary(self):
        with tempfile.TemporaryDirectory() as name:
            http_root = Path(name)
            day0 = http_root / "DAY0-Prepare"
            project = day0 / "project"
            project.mkdir(parents=True)
            document = global_document("disabled")
            document["common"]["mgmt"]["ztp"]["status"] = "disabled"
            (project / "01-global.yaml").write_text(
                yaml.safe_dump(document), encoding="utf-8",
            )
            (project / "02-devices_config.csv").write_text(
                "hostname,type\nib01,ib\n", encoding="utf-8",
            )
            subnet = project / "02-dhcp-subnet_config.csv"
            source = project / "symlink-target.csv"
            source.write_bytes(EMPTY_SUBNET_TABLE)
            settings = LOAD.replace(LOAD.load_global(project / "01-global.yaml"), ztp_enabled=False)
            docker_settings = SimpleNamespace(
                project_dir=project, subnet_csv=subnet, http_root=http_root,
                project_name="project", allowlist=(), relay_ingress=(),
            )
            cases = (
                ("missing", None), ("zero", b""), ("whitespace", b" \t\r\n"),
                ("wrong-header", b"wrong,columns\n"), ("symlink", "symlink"),
            )
            for label, payload in cases:
                if subnet.exists() or subnet.is_symlink():
                    subnet.unlink()
                if payload == "symlink":
                    subnet.symlink_to(source)
                elif payload is not None:
                    subnet.write_bytes(payload)
                with self.subTest(case=label, script="setup"), \
                        mock.patch.multiple(SETUP, _SWITCH_SCOPE="ib", _CSV_DIR=None), \
                        mock.patch.object(SETUP, "_validate_eth_csv", return_value=([], [])), \
                        mock.patch.object(SETUP, "_validate_global_yaml", return_value=([], [])), \
                        redirect_stdout(io.StringIO()):
                    self.assertFalse(SETUP._validate_project(str(project)))
                with self.subTest(case=label, script="load"):
                    with self.assertRaises(LOAD.LoadError):
                        LOAD.apply_subnet_service_ips(settings, subnet)
                    with self.assertRaises(LOAD.LoadError):
                        LOAD.validate_subnet_file(subnet, settings)
                with self.subTest(case=label, script="runtime"):
                    with self.assertRaises(RUNTIME.RuntimeContractError):
                        RUNTIME.plan_dhcp_runtime(
                            subnet, link_snapshot=[], address_snapshot=[],
                            dhcp_enabled=False, ztp_enabled=False,
                        )
                with self.subTest(case=label, script="docker"), \
                        mock.patch.object(ACTIVATE, "capture_stable_network_snapshot", return_value=([], [])), \
                        mock.patch.object(ACTIVATE, "_load_runtime_module", return_value=RUNTIME):
                    with self.assertRaises(ACTIVATE.ActivationError):
                        ACTIVATE.build_runtime_plan(docker_settings)

    def test_subnet_swap_after_check_stops_setup_load_and_runtime_workflow(self):
        """The same project CSV authority must survive each real-script reader."""
        with tempfile.TemporaryDirectory() as name:
            project = Path(name) / "DAY0-Prepare" / "project"
            project.mkdir(parents=True)
            document = global_document("disabled")
            document["common"]["mgmt"]["ztp"]["status"] = "disabled"
            (project / "01-global.yaml").write_text(
                yaml.safe_dump(document), encoding="utf-8",
            )
            settings = LOAD.load_global(project / "01-global.yaml")
            subnet = project / "02-dhcp-subnet_config.csv"
            alternate = project / "alternate.csv"
            alternate.write_bytes(EMPTY_SUBNET_TABLE)

            for stage in ("setup", "load", "runtime"):
                with self.subTest(stage=stage):
                    if subnet.exists() or subnet.is_symlink():
                        subnet.unlink()
                    subnet.write_bytes(EMPTY_SUBNET_TABLE)
                    original_lstat = os.lstat if stage == "setup" else Path.lstat
                    swapped = False

                    def replace_after_check(path, *args, **kwargs):
                        nonlocal swapped
                        metadata = original_lstat(path, *args, **kwargs)
                        if os.fspath(path) == os.fspath(subnet) and not swapped:
                            swapped = True
                            subnet.unlink()
                            subnet.symlink_to(alternate)
                        return metadata

                    patcher = (
                        mock.patch.object(os, "lstat", side_effect=replace_after_check)
                        if stage == "setup" else
                        mock.patch.object(Path, "lstat", new=replace_after_check)
                    )
                    with patcher:
                        if stage == "setup":
                            errors, _warnings = SETUP._validate_subnet_csv(
                                subnet, dhcp_enabled=False, ztp_enabled=False,
                            )
                            self.assertTrue(errors, "setup followed the replacement")
                        elif stage == "load":
                            with self.assertRaises(LOAD.LoadError):
                                LOAD.apply_subnet_service_ips(settings, subnet)
                        else:
                            with self.assertRaises(RUNTIME.RuntimeContractError):
                                RUNTIME.plan_dhcp_runtime(
                                    subnet, link_snapshot=[], address_snapshot=[],
                                    dhcp_enabled=False, ztp_enabled=False,
                                )
                    self.assertTrue(swapped, "the post-check replacement did not run")

    def test_setup_rejects_missing_subnet_before_template_can_fill_it(self):
        with tempfile.TemporaryDirectory() as name:
            project = Path(name) / "project"
            project.mkdir()
            document = global_document("disabled")
            document["common"]["mgmt"]["ztp"]["status"] = "disabled"
            (project / "01-global.yaml").write_text(
                yaml.safe_dump(document), encoding="utf-8",
            )
            subnet = project / "02-dhcp-subnet_config.csv"
            self.assertFalse(subnet.exists())
            with mock.patch.multiple(
                SETUP, _DRY_RUN=False, _SWITCH_SCOPE="ib", _CSV_DIR=None,
                _P2P_SOURCE=None, _STRICT=False,
            ), mock.patch.object(SETUP, "_prepare_laptop_public_key"), \
                    mock.patch.object(SETUP, "_select_p2p_source", return_value=project / "p2p.xlsx"), \
                    mock.patch.object(SETUP, "_validate_eth_csv", return_value=([], [])), \
                    mock.patch.object(SETUP, "_validate_global_yaml", return_value=([], [])), \
                    mock.patch.object(SETUP, "_check_p2p_source_identity", return_value=False) as identity_check, \
                    redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as stopped:
                    SETUP._setup_impl(str(project))
            self.assertEqual(1, stopped.exception.code)
            identity_check.assert_not_called()
            self.assertFalse(subnet.exists(), "setup must not materialize a missing required CSV")

    def test_enabled_header_only_subnet_rejects_before_p2p_selection(self):
        with tempfile.TemporaryDirectory() as name:
            project = Path(name)
            document = global_document("enabled")
            document["common"]["mgmt"]["ztp"]["status"] = "disabled"
            (project / "01-global.yaml").write_text(
                yaml.safe_dump(document), encoding="utf-8",
            )
            (project / "02-devices_config.csv").write_text("fixture\n", encoding="utf-8")
            (project / "02-dhcp-subnet_config.csv").write_bytes(EMPTY_SUBNET_TABLE)
            args = SimpleNamespace(
                switch_scope="ib", deployment_scope="all", p2p_file=None,
                no_upgrade=True, mini=None, ssh_dir=None, dry_run=True,
            )
            with mock.patch.object(LOAD, "find_placeholder_password_sections", return_value=()), \
                    mock.patch.object(LOAD, "load_device_types", return_value=frozenset({"ib"})), \
                    mock.patch.object(LOAD, "select_p2p", return_value=project / "p2p.xlsx") as selector, \
                    mock.patch.object(LOAD, "project_air_topology_policy", return_value=None), \
                    mock.patch.object(LOAD, "project_mini_air_devices", return_value=(None, None)), \
                    mock.patch.object(LOAD, "prepare_pubkeys", return_value=()), \
                    mock.patch.object(LOAD, "validate_shared_artifact_receipts"), \
                    redirect_stdout(io.StringIO()):
                with self.assertRaises(LOAD.LoadError):
                    LOAD.validate_inputs(
                        project, args, allow_management_key_generation=False,
                        host_role="workstation",
                    )
            selector.assert_not_called()

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
            (project / "02-dhcp-subnet_config.csv").write_bytes(EMPTY_SUBNET_TABLE)

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

    def test_ib_load_input_transaction_keeps_header_only_subnet_source_hash(self):
        with tempfile.TemporaryDirectory() as name:
            project = Path(name)
            global_file = project / "01-global.yaml"
            document = global_document("disabled")
            document["common"]["mgmt"]["ztp"]["status"] = "disabled"
            global_file.write_text(yaml.safe_dump(document), encoding="utf-8")
            (project / "02-devices_config.csv").write_text("fixture\n", encoding="utf-8")
            subnet = project / "02-dhcp-subnet_config.csv"
            subnet.write_bytes(EMPTY_SUBNET_TABLE)
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
            self.assertEqual(EMPTY_SUBNET_TABLE_SHA256,
                             inputs.source_identities["subnet"])

    def test_ib_header_only_subnet_passes_setup_load_and_both_runtime_planners(self):
        with tempfile.TemporaryDirectory() as name:
            project = Path(name) / "project"
            project.mkdir()
            global_file = project / "01-global.yaml"
            document = global_document("disabled")
            document["common"]["mgmt"]["ztp"]["status"] = "disabled"
            global_file.write_text(yaml.safe_dump(document), encoding="utf-8")
            subnet = project / "02-dhcp-subnet_config.csv"
            subnet.write_bytes(EMPTY_SUBNET_TABLE)
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
            self.assertEqual(EMPTY_SUBNET_TABLE_SHA256,
                             ACTIVATE.sha256_path(subnet))
            self.assertEqual((), docker.endpoint_ips)
            self.assertEqual(
                EMPTY_SUBNET_TABLE_SHA256,
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
