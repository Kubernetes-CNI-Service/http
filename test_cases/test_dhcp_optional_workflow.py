#!/usr/bin/env python3
"""Real DAY0 load -> DHCP-generator contract for optional generation."""

from __future__ import annotations

import hashlib
import csv
import io
import json
import os
from pathlib import Path
import shlex
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import yaml
from test_cases.module_loader import load_script
from test_cases.test_dhcp_optional_contract import (
    DHCP, LOAD, RUNTIME, SETUP, ROOT, _R22_ACTIVE_ROW, _R22_SUBNET_HEADER,
    global_document, settings_for,
)
from test_cases.test_dhcp_switch_scope_preservation import (
    DHCP as SCOPED_DHCP, ScopedDhcpFixture,
)
from test_cases import test_load_release_transaction as release_fixture
from test_cases import test_flow_release_platform_matrix as platform_fixture
from project_contract import DEVICE_BASE_COLUMNS, DEVICE_FIXED_COLUMNS


def prepare_r22_selected_nvos_core_flow(
    root: Path, selected: str, *, defer_dhcp: bool = False,
):
    """TEMP core-function chain; CLI dispatch, Docker and services are intercepted."""
    if selected not in {"ib", "nvl"}:
        raise ValueError(selected)
    # Reuse the independently exercised real multi-platform bootstrap only to
    # prepare valid project inputs and publisher prerequisites in a TEMP root.
    # The selected chain below runs the actual C1, NVOS C2, D and LOAD cores.
    flow = type("R22SelectedNvOsTempFlow", (platform_fixture.PlatformReleaseFlowTests,), {})
    flow._build_flow(root)
    document = yaml.safe_load(flow.global_file.read_text(encoding="utf-8"))
    document["common"]["mgmt"]["dhcp-server"] = {"status": "enabled"}
    document["common"]["mgmt"]["ztp"]["status"] = "enabled"
    document["common"]["mgmt"]["dhcp-server"]["package"] = "isc-dhcp-server"
    document["common"]["mgmt"]["http"] = {
        "status": "enabled", "package": "apache2", "port": 80,
        "http_root": str(root), "address": "192.0.2.10",
    }
    document["common"]["switch"]["system"].update({
        "dns": {"server": ["192.0.2.53"]},
        "ntp": {"server": ["192.0.2.123"]},
    })
    flow.global_file.write_text(yaml.safe_dump(document), encoding="utf-8")

    outputs = flow.project / "99-output-dhcp"
    outputs.mkdir()
    names = (
        "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
        "dhcpd_nvl.hosts", "dhcp-release-manifest.json",
    )
    for name in names:
        public = flow.dhcp / name
        public.rename(outputs / name)
        public.symlink_to(os.path.relpath(outputs / name, flow.dhcp))
    for family in {"eth", "ib", "nvl"} - {selected}:
        (outputs / f"dhcpd_{family}.hosts").write_bytes(b"")
    before = {
        name: ((outputs / name).stat().st_ino, (outputs / name).read_bytes())
        for name in names
    }
    candidate = (LOAD.DeferredDHCPOutput.create(flow.ztp, selected)
                 if defer_dhcp else None)
    parent_committed = False
    try:
        c1_args = [
            "c1-generate_dhcp.py", "-y", "--deployment-scope", "prod",
            "--switch", selected,
        ]
        if candidate is not None:
            c1_args.extend(["--candidate-output-dir", str(candidate.stage)])
        with mock.patch.object(sys, "argv", c1_args), mock.patch.multiple(
            DHCP, HTTP_ROOT=str(root), SCRIPT_DIR=str(flow.dhcp),
            OUTPUT_CONF=str(outputs / "dhcpd.conf"),
            OUTPUT_ETH=str(outputs / "dhcpd_eth.hosts"),
            OUTPUT_IB=str(outputs / "dhcpd_ib.hosts"),
            OUTPUT_NVL=str(outputs / "dhcpd_nvl.hosts"),
            OUTPUT_MANIFEST=str(outputs / "dhcp-release-manifest.json"),
            GLOBAL_YAML=str(flow.global_file), DEVICES_CSV=str(flow.devices_file),
            SUBNET_CSV=str(flow.subnet_file),
            P2P_AIR_JSON=str(flow.air_json), _AUTO_YES=False,
        ), mock.patch.object(DHCP, "stop_native_ztp_monitors"):
            DHCP.main()
        if candidate is not None:
            after = {
                name: ((outputs / name).stat().st_ino, (outputs / name).read_bytes())
                for name in names
            }
            if before != after:
                raise AssertionError("C1 changed public DHCP outputs before parent commit")

        template = flow.nvos / "template"
        selected_dir = template / f"99-output-ib_nvl/20260902_120000-{selected}"
        with mock.patch.multiple(
            platform_fixture.NVOS_GENERATOR,
            SCRIPT_DIR=str(template),
            _CSV_FILE=str(template / "02-devices_config.csv"),
            _GLOBAL_FILE=str(template / "01-global.yaml"),
            OUTPUT_IB_NVL_ROOT=str(template / "99-output-ib_nvl"),
            OUTPUT_IB_DIR=str(selected_dir if selected == "ib" else template / "unused-ib"),
            OUTPUT_NVL_DIR=str(selected_dir if selected == "nvl" else template / "unused-nvl"),
        ):
            generated = platform_fixture.NVOS_GENERATOR._generate_all_ib(
                switch_scope=selected,
            )
        if generated != 1:
            raise AssertionError(f"{selected} generated {generated}, expected one")
        publisher = platform_fixture.PUBLISHER
        devices = publisher.load_csv(str(flow.devices_file), switch_scope=selected)
        context = publisher._nvos_dir_context(str(selected_dir))
        with mock.patch.object(publisher, "_AUTO_YES", True):
            if not publisher._publish_single_nvos(
                context, devices, deployment_scope="prod", switch_scope=selected,
            ):
                raise AssertionError(f"{selected} publisher rejected selected release")
        settings = LOAD.load_global(flow.global_file)
        inputs = LOAD.ProjectInputs(
            global_file=flow.global_file, devices_file=flow.devices_file,
            subnet_file=flow.subnet_file, p2p_file=flow.p2p_file,
            device_types=frozenset({"eth", "air", "ib", "nvl"}), pubkeys=(),
            settings=settings, deployment_scope="prod", switch_scope=selected,
        )
        if candidate is not None:
            candidate.publish()
        with mock.patch.object(LOAD, "ZTP_DIR", flow.ztp):
            parent = LOAD.validate_and_publish_release(flow.project, inputs)
        parent_committed = True
        if candidate is not None:
            candidate.accept_committed()
        return flow, outputs, parent
    finally:
        if candidate is not None and not parent_committed:
            candidate.rollback()
            candidate.discard()


class DhcpOptionalWorkflowTests(unittest.TestCase):
    def test_f02_legacy_rows_materialize_valid_methods_in_real_c1_records(self):
        header = list(DEVICE_BASE_COLUMNS + DEVICE_FIXED_COLUMNS)
        with tempfile.TemporaryDirectory() as name:
            inventory = Path(name) / "02-devices_config.csv"
            rows = []
            for hostname, kind, address in (
                ("EXAMPLE-OOB01", "eth", "192.0.2.11"),
                ("EXAMPLE-IB01", "ib", "203.0.113.2"),
                ("EXAMPLE-NVL01", "nvl", "203.0.113.3"),
            ):
                row = [hostname, kind, "oob", address, "24", "192.0.2.1"]
                row.extend([""] * (len(header) - len(row)))
                rows.append(row)
            with inventory.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                writer.writerow(header)
                writer.writerows(rows)
            methods = {}
            self.assertEqual(
                frozenset({"eth", "ib", "nvl"}),
                LOAD.load_device_types(
                    inventory, schema_version=2, methods_out=methods,
                ),
            )
            records = DHCP.load_csv(str(inventory), schema_version=2)
            self.assertEqual(
                {"EXAMPLE-OOB01": "ztp", "EXAMPLE-IB01": "ztp", "EXAMPLE-NVL01": "ztp"},
                {record["hostname"]: record["config_method"] for record in records},
            )
            self.assertEqual(
                {record["hostname"].casefold(): record["config_method"] for record in records},
                methods,
            )

    def test_f02_v2_method_column_survives_load_to_dhcp_generator(self):
        header = list(DEVICE_BASE_COLUMNS + DEVICE_FIXED_COLUMNS) + ["config_method"]
        with tempfile.TemporaryDirectory() as name:
            inventory = Path(name) / "02-devices_config.csv"
            rows = []
            for hostname, kind, address, method in (
                ("EXAMPLE-IB01", "ib", "203.0.113.2", "initial-setup"),
                ("EXAMPLE-OOB01", "eth", "192.0.2.11", "ztp"),
            ):
                row = [hostname, kind, "oob", address, "24", "192.0.2.1"]
                row.extend([""] * (len(header) - len(row)))
                row[-1] = method
                rows.append(row)
            with inventory.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                writer.writerow(header)
                writer.writerows(rows)
            self.assertEqual(
                frozenset({"ib", "eth"}),
                LOAD.load_device_types(inventory, schema_version=2),
            )
            records = DHCP.load_csv(str(inventory), schema_version=2)
            self.assertEqual(2, len(records))
            self.assertEqual(
                {"EXAMPLE-IB01": "initial-setup", "EXAMPLE-OOB01": "ztp"},
                {record["hostname"]: record["config_method"] for record in records},
            )

            rows[1][-1] = "initial-setup"
            with inventory.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.writer(stream)
                writer.writerow(header)
                writer.writerows(rows)
            with self.assertRaisesRegex(LOAD.LoadError, "config_method"):
                LOAD.load_device_types(inventory, schema_version=2)
            with self.assertRaisesRegex(ValueError, "config_method"):
                DHCP.load_csv(str(inventory), schema_version=2)

    def test_r22_empty_subnet_parent_and_standalone_generator_disagree_no_longer(self):
        for dhcp_status in ("disabled", "enabled"):
            with self.subTest(dhcp_status=dhcp_status), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                global_yaml = root / "01-global.yaml"
                subnet = root / "02-dhcp-subnet_config.csv"
                document = global_document(dhcp_status)
                document["common"]["mgmt"]["ztp"]["status"] = "disabled"
                global_yaml.write_text(yaml.safe_dump(document), encoding="utf-8")
                subnet.write_text(_R22_SUBNET_HEADER, encoding="utf-8")
                settings = LOAD.load_global(global_yaml)
                if dhcp_status == "disabled":
                    LOAD.validate_subnet_file(subnet, settings)
                else:
                    with self.assertRaises(LOAD.LoadError):
                        LOAD.validate_subnet_file(subnet, settings)
                output_names = (
                    "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
                    "dhcpd_nvl.hosts", "dhcp-release-manifest.json",
                )
                with mock.patch.object(sys, "argv", ["c1-generate_dhcp.py", "-y"]), \
                        mock.patch.multiple(
                            DHCP, GLOBAL_YAML=str(global_yaml), SUBNET_CSV=str(subnet),
                            DEVICES_CSV=str(root / "missing-devices.csv"),
                            OUTPUT_CONF=str(root / output_names[0]),
                            OUTPUT_ETH=str(root / output_names[1]),
                            OUTPUT_IB=str(root / output_names[2]),
                            OUTPUT_NVL=str(root / output_names[3]),
                            OUTPUT_MANIFEST=str(root / output_names[4]),
                            _AUTO_YES=False,
                        ), mock.patch.object(sys, "stdout", io.StringIO()) as output:
                    with self.assertRaises(SystemExit) as rejected:
                        DHCP.main()
                self.assertEqual(1, rejected.exception.code)
                self.assertIn(f"DHCP {dhcp_status}", output.getvalue())
                self.assertTrue(all(not (root / item).exists() for item in output_names))

    def test_f02_dhcp_on_ztp_off_real_load_and_c1_emit_no_ztp_options(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            flow = type("F02DhcpOnlyFlow", (platform_fixture.PlatformReleaseFlowTests,), {})
            flow._build_flow(root)
            document = yaml.safe_load(flow.global_file.read_text(encoding="utf-8"))
            mgmt = document["common"]["mgmt"]
            mgmt["dhcp-server"] = {"status": "enabled", "package": "isc-dhcp-server"}
            mgmt["ztp"]["status"] = "disabled"
            mgmt["http"].update({
                "status": "disabled", "package": "apache2",
                "http_root": str(root), "port": 80,
            })
            system = document["common"]["switch"]["system"]
            system["dns"] = {"server": ["192.0.2.53"]}
            system["ntp"] = {"server": ["192.0.2.123"]}
            flow.global_file.write_text(yaml.safe_dump(document), encoding="utf-8")
            flow.subnet_file.write_text(
                _R22_SUBNET_HEADER + _R22_ACTIVE_ROW.replace(
                    "192.0.2.10,oob,no", ",none,no",
                ), encoding="utf-8",
            )
            settings = LOAD.load_global(flow.global_file)
            LOAD.validate_subnet_file(flow.subnet_file, settings)
            output = flow.dhcp / "dhcpd.conf"
            with mock.patch.object(sys, "argv", ["c1-generate_dhcp.py", "-y"]), \
                    mock.patch.multiple(
                        DHCP, SCRIPT_DIR=str(flow.dhcp), HTTP_ROOT=str(root),
                        GLOBAL_YAML=str(flow.global_file),
                        SUBNET_CSV=str(flow.subnet_file),
                        DEVICES_CSV=str(flow.devices_file),
                        P2P_AIR_JSON=str(root / "missing-air.json"),
                        OUTPUT_CONF=str(output),
                        OUTPUT_ETH=str(flow.dhcp / "dhcpd_eth.hosts"),
                        OUTPUT_IB=str(flow.dhcp / "dhcpd_ib.hosts"),
                        OUTPUT_NVL=str(flow.dhcp / "dhcpd_nvl.hosts"),
                        OUTPUT_MANIFEST=str(flow.dhcp / "dhcp-release-manifest.json"),
                        _AUTO_YES=False,
                    ), mock.patch.object(DHCP, "stop_native_ztp_monitors"):
                DHCP.main()
            generated = output.read_text(encoding="utf-8")
            self.assertIn("range 192.0.2.100 192.0.2.120", generated)
            self.assertNotIn("option cumulus-provision-url", generated)
            self.assertNotIn("option bootfile-name", generated)

    def test_f02_dhcp_off_ztp_on_rejected_by_load_and_generator_before_output(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            global_yaml = root / "01-global.yaml"
            subnet = root / "02-dhcp-subnet_config.csv"
            document = global_document("disabled")
            document["common"]["mgmt"]["ztp"]["status"] = "enabled"
            global_yaml.write_text(yaml.safe_dump(document), encoding="utf-8")
            subnet.write_text(_R22_SUBNET_HEADER + _R22_ACTIVE_ROW, encoding="utf-8")
            with self.assertRaisesRegex(LOAD.LoadError, "DHCP disabled.*ZTP enabled"):
                LOAD.load_global(global_yaml)
            output = root / "dhcpd.conf"
            with mock.patch.object(sys, "argv", ["c1-generate_dhcp.py", "-y"]), \
                    mock.patch.multiple(
                        DHCP, GLOBAL_YAML=str(global_yaml), SUBNET_CSV=str(subnet),
                        DEVICES_CSV=str(root / "02-devices_config.csv"),
                        OUTPUT_CONF=str(output), _AUTO_YES=False,
                    ), mock.patch.object(sys, "stdout", io.StringIO()) as stdout:
                with self.assertRaises(SystemExit) as rejected:
                    DHCP.main()
            self.assertEqual(1, rejected.exception.code)
            self.assertIn("DHCP disabled + ZTP enabled", stdout.getvalue())
            self.assertFalse(output.exists())

    def test_f02_load_and_generator_both_reject_ztp_disabled_row_conflict(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            global_yaml = root / "01-global.yaml"
            subnet = root / "02-dhcp-subnet_config.csv"
            document = global_document("enabled")
            document["common"]["mgmt"]["ztp"]["status"] = "disabled"
            global_yaml.write_text(yaml.safe_dump(document), encoding="utf-8")
            subnet.write_text(_R22_SUBNET_HEADER + _R22_ACTIVE_ROW, encoding="utf-8")
            settings = LOAD.load_global(global_yaml)
            with self.assertRaisesRegex(LOAD.LoadError, "第 2 行.*global ZTP disabled"):
                LOAD.validate_subnet_file(subnet, settings)
            prefix, _schema, port, address, enabled = DHCP.load_project_global(
                global_yaml, include_ztp_status=True,
            )
            with mock.patch.object(sys, "stdout", io.StringIO()), self.assertRaises(SystemExit):
                DHCP.load_subnet_csv(
                    subnet, prefix, port=port, http_address=address,
                    ztp_enabled=enabled,
                )
            output_names = (
                "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
                "dhcpd_nvl.hosts", "dhcp-release-manifest.json",
            )
            with mock.patch.object(sys, "argv", ["c1-generate_dhcp.py", "-y"]), \
                    mock.patch.multiple(
                        DHCP,
                        GLOBAL_YAML=str(global_yaml), SUBNET_CSV=str(subnet),
                        DEVICES_CSV=str(root / "02-devices_config.csv"),
                        OUTPUT_CONF=str(root / output_names[0]),
                        OUTPUT_ETH=str(root / output_names[1]),
                        OUTPUT_IB=str(root / output_names[2]),
                        OUTPUT_NVL=str(root / output_names[3]),
                        OUTPUT_MANIFEST=str(root / output_names[4]),
                        _AUTO_YES=False,
                    ), mock.patch.object(sys, "stdout", io.StringIO()) as stdout:
                with self.assertRaises(SystemExit) as rejected:
                    DHCP.main()
            self.assertEqual(1, rejected.exception.code)
            self.assertIn("第 2 行", stdout.getvalue())
            self.assertIn("global ZTP disabled", stdout.getvalue())
            self.assertTrue(all(not (root / item).exists() for item in output_names))

    def test_f02_mixed_rows_emit_no_platform_options_in_none_row(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            global_yaml = root / "01-global.yaml"
            subnet = root / "02-dhcp-subnet_config.csv"
            output = root / "dhcpd.conf"
            document = global_document("enabled")
            global_yaml.write_text(yaml.safe_dump(document), encoding="utf-8")
            active = _R22_ACTIVE_ROW
            inactive = active.replace("mgmt,", "mgmt2,", 1).replace(
                "192.0.2.", "198.51.100.",
            ).replace("198.51.100.10,oob,no", ",none,no")
            subnet.write_text(
                _R22_SUBNET_HEADER + active + inactive, encoding="utf-8",
            )
            settings = LOAD.load_global(global_yaml)
            LOAD.validate_subnet_file(subnet, settings)
            prefix, _schema, port, address, enabled = DHCP.load_project_global(
                global_yaml, include_ztp_status=True,
            )
            rows = DHCP.load_subnet_csv(
                subnet, prefix, port=port, http_address=address,
                ztp_enabled=enabled,
            )
            DHCP.write_dhcpd_conf(output, rows)
            generated = output.read_text(encoding="utf-8")
            active_block = generated.split("shared-network mgmt {", 1)[1].split(
                "shared-network mgmt2 {", 1,
            )[0]
            inactive_block = generated.split("shared-network mgmt2 {", 1)[1]
            self.assertIn('option cumulus-provision-url "', active_block)
            self.assertNotIn('option cumulus-provision-url "', inactive_block)
            self.assertNotIn('option bootfile-name "', inactive_block)
            self.assertIn("range 198.51.100.100 198.51.100.120", inactive_block)

    def test_f02_load_to_infra_http_ip_requires_independent_project_input(self):
        deploy = load_script(
            "f02_independent_http_infra_consumer", ROOT / "infra/deploy_infra.py",
        )
        settings = LOAD.replace(
            settings_for("enabled"),
            ztp_ips={"eth": ("192.0.2.10",)},
            http_address=None,
        )
        inputs = SimpleNamespace(
            settings=settings,
            global_file=Path("01-global.yaml"),
            devices_file=Path("02-devices_config.csv"),
        )
        with mock.patch.object(LOAD, "run") as runner:
            with self.assertRaisesRegex(LOAD.LoadError, "common.mgmt.http.address"):
                LOAD.prepare_infra(inputs, dry_run=True, skip_doca=True)
            runner.assert_not_called()

        inputs.settings = LOAD.replace(settings, http_address="198.51.100.20")
        with mock.patch.object(LOAD, "run") as runner:
            LOAD.prepare_infra(inputs, dry_run=True, skip_doca=True)
        command = runner.call_args_list[0].args[0]
        self.assertIn("--http-server-ip", command)
        selected = command[command.index("--http-server-ip") + 1]
        with mock.patch.object(
            deploy, "_local_ipv4_addresses", return_value={"198.51.100.20"},
        ), mock.patch.object(
            deploy, "detect_route_source_ipv4",
            side_effect=AssertionError("route-derived HTTP authority"),
        ):
            self.assertEqual(
                "198.51.100.20", deploy.determine_http_source_ip([], selected),
            )

    def test_r22_private_c1_candidate_real_nvos_chain_commits_with_parent(self):
        """The real C1→NVOS C2→D→LOAD path publishes C1 only with its parent."""
        activate = load_script(
            "r22_private_nvos_activate_workflow", ROOT / "infra/docker/activate.py",
        )
        for selected in ("ib", "nvl"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as name:
                flow, outputs, parent = prepare_r22_selected_nvos_core_flow(
                    Path(name), selected, defer_dhcp=True,
                )
                self.assertEqual("passed", parent["validation"])
                self.assertEqual(
                    hashlib.sha256(
                        (outputs / "dhcp-release-manifest.json").read_bytes(),
                    ).hexdigest(),
                    parent["components"]["dhcp"]["manifest_sha256"],
                )
                self.assertTrue((outputs / f"dhcpd_{selected}.hosts").read_bytes())
                self.assertEqual([], list(outputs.glob(".load-dhcp-*")))
                settings = activate.Settings(
                    project_name=flow.project.name, scope="prod",
                    switch_scope=selected, http_root=flow.root,
                )
                activate.validate_parent_release(
                    settings, flow.project / "99-output-ztp/current-release.json",
                )

    def test_r22_real_nvos_selected_c1_c2_d_load_activate_with_empty_unselected(self):
        """Real TEMP cores cross C1→NVOS C2→D→LOAD→ACTIVATE for IB/NVL.

        CLI dispatch is intercepted by direct core calls; this is not an
        un-intercepted CLI, Docker, network or service-switch proof.
        """
        activate = load_script(
            "r22_selected_nvos_activate_workflow", ROOT / "infra/docker/activate.py",
        )
        for selected in ("ib", "nvl"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory() as name:
                flow, outputs, parent = prepare_r22_selected_nvos_core_flow(
                    Path(name), selected,
                )
                child = json.loads((outputs / "dhcp-release-manifest.json").read_text())
                expected_counts = {"eth": 0, "ib": 0, "nvl": 0}
                expected_counts[selected] = 2 if selected == "ib" else 1
                self.assertEqual(
                    expected_counts, child["counts"]["host_declarations_by_family"],
                )
                self.assertEqual(
                    {"dhcp", "nvos"}, set(parent["components"]),
                )
                self.assertEqual("passed", parent["validation"])
                self.assertEqual(selected, parent["switch_scope"])
                release = flow.project / "99-output-ztp/current-release.json"
                child_path = outputs / "dhcp-release-manifest.json"
                self.assertEqual(hashlib.sha256(child_path.read_bytes()).hexdigest(),
                                 parent["components"]["dhcp"]["manifest_sha256"])
                nvos_dir = flow.project / parent["components"]["nvos"]["release_dir"]
                self.assertEqual(nvos_dir.resolve(strict=True),
                                 (flow.nvos / "latest_yaml").resolve(strict=True))
                before = {
                    path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                    for path in (release, *(outputs / item for item in (
                        "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
                        "dhcpd_nvl.hosts", "dhcp-release-manifest.json",
                    )))
                }
                settings = activate.Settings(
                    project_name="demo", scope="prod", switch_scope=selected,
                    http_root=flow.root,
                )
                activate.validate_project_mount(settings)
                self.assertEqual("enabled", activate.current_project_dhcp_status(
                    settings,
                ))
                try:
                    activate.validate_parent_release(settings, release)
                except activate.ActivationError as exc:
                    self.fail(f"real-core selected {selected} parent rejected: {exc}")
                self.assertEqual(
                    before,
                    {path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                     for path in before},
                )

    @staticmethod
    def _r22_csv_project(root: Path, payload: str, dhcp_status: str):
        project = root / "DAY0-Prepare" / "fixture"
        project.mkdir(parents=True)
        global_yaml = project / "01-global.yaml"
        document = global_document(dhcp_status)
        document["common"]["mgmt"]["ztp"]["status"] = "disabled"
        document["common"]["mgmt"]["http"]["status"] = "disabled"
        global_yaml.write_text(yaml.safe_dump(document), encoding="utf-8")
        (project / "02-devices_config.csv").write_text(
            "hostname,type,mac\n", encoding="utf-8"
        )
        subnet = project / "02-dhcp-subnet_config.csv"
        subnet.write_text(payload, encoding="utf-8")
        activate = load_script(
            "r22_csv_workflow_activate", ROOT / "infra/docker/activate.py"
        )
        settings = activate.Settings(
            project_name="fixture", scope="prod", http_root=root,
            state_root=root / "state", log_root=root / "log",
            apache_listeners=root / "apache.conf",
            dhcp_leases=root / "dhcp" / "leases",
        )
        return global_yaml, subnet, activate, settings

    @staticmethod
    def _r22_docker_observation(activate):
        return (
            mock.patch.object(
                activate, "capture_stable_network_snapshot", return_value=([], [])
            ),
            mock.patch.object(activate, "_load_runtime_module", return_value=RUNTIME),
        )

    def test_r22_header_only_off_off_flows_through_four_real_scripts(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            global_yaml, subnet, activate, docker_settings = self._r22_csv_project(
                root, _R22_SUBNET_HEADER + " \t\n", "disabled"
            )
            setup_errors, _warnings = SETUP._validate_subnet_csv(
                subnet, dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertEqual([], setup_errors)
            load_settings = LOAD.load_global(global_yaml)
            LOAD.validate_subnet_file(subnet, load_settings)
            runtime_plan = RUNTIME.plan_dhcp_runtime(
                subnet, link_snapshot=[], address_snapshot=[],
                dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertEqual((), runtime_plan.listener_names)
            snapshot, runtime = self._r22_docker_observation(activate)
            with snapshot, runtime, mock.patch.object(
                activate, "ensure_runtime_directories"
            ) as mkdir, mock.patch.object(activate, "_atomic_write") as write:
                selected, _runtime, payload = activate.prepare_runtime(docker_settings)
            self.assertEqual((), selected.listener_names)
            self.assertEqual((), selected.endpoint_ips)
            self.assertEqual(
                hashlib.sha256(subnet.read_bytes()).hexdigest(),
                payload["subnet_sha256"],
            )
            self.assertEqual((), activate.expected_services(
                selected, dhcp_status="disabled", http_listener_ips=(),
            ))
            mkdir.assert_called_once_with(docker_settings)
            self.assertEqual(2, write.call_count)
            self.assertNotIn("Listen ", write.call_args_list[0].args[1])

    def test_r22_real_c1_load_parent_accepts_empty_unselected_hosts_for_activation(self):
        """A real eth-only child accepted by LOAD must remain activatable."""
        fixture = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match",
        )
        fixture.setUp()
        try:
            inputs, outputs, child = (
                release_fixture.prepare_r22_empty_unselected_dhcp_fixture(fixture)
            )
            load_settings = LOAD.load_global(fixture.global_file)
            LOAD.validate_subnet_file(fixture.subnet_file, load_settings)
            self.assertEqual(
                {"eth": 1, "ib": 0, "nvl": 0},
                child["counts"]["host_declarations_by_family"],
            )
            self.assertEqual(b"", (outputs / "dhcpd_ib.hosts").read_bytes())
            self.assertEqual(b"", (outputs / "dhcpd_nvl.hosts").read_bytes())
            parent = release_fixture.LOAD.validate_and_publish_release(
                fixture.project, inputs,
            )
            self.assertEqual("enabled", parent["dhcp_status"])
            current = fixture.project / "99-output-ztp/current-release.json"
            before = {
                path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                for path in (current, *(outputs / name for name in (
                    "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
                    "dhcpd_nvl.hosts", "dhcp-release-manifest.json",
                )))
            }
            activate = load_script(
                "r22_scoped_empty_hosts_activate_workflow",
                ROOT / "infra/docker/activate.py",
            )
            docker_settings = activate.Settings(
                project_name="demo", scope="prod", switch_scope="eth",
                http_root=fixture.root,
            )
            activation_error = None
            try:
                activate.validate_parent_release(docker_settings, current)
            except activate.ActivationError as exc:
                activation_error = exc
            self.assertIsNone(activation_error, str(activation_error))
            self.assertEqual(
                before,
                {path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                 for path in before},
            )
        finally:
            fixture.tearDown()

    def test_r22_real_c1_load_rejects_malformed_empty_host_counts_before_parent_write(self):
        """Real c1's 0-byte unselected outputs need exact typed proof at LOAD."""
        fixture = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match",
        )
        fixture.setUp()
        try:
            inputs, outputs, child = (
                release_fixture.prepare_r22_empty_unselected_dhcp_fixture(fixture)
            )
            load_settings = LOAD.load_global(fixture.global_file)
            LOAD.validate_subnet_file(fixture.subnet_file, load_settings)
            self.assertEqual(
                {"eth": 1, "ib": 0, "nvl": 0},
                child["counts"]["host_declarations_by_family"],
            )
            release_fixture.LOAD.validate_and_publish_release(fixture.project, inputs)
            current = fixture.project / "99-output-ztp/current-release.json"
            child_path = outputs / "dhcp-release-manifest.json"
            accepted_child = child_path.read_bytes()
            accepted_parent = current.read_bytes()
            output_snapshot = {
                name: (outputs / name).read_bytes() for name in (
                    "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
                    "dhcpd_nvl.hosts",
                )
            }
            for label, altered_counts in (
                ("missing nested", None),
                ("boolean zero", {"eth": 1, "ib": False, "nvl": 0}),
                ("negative zero", {"eth": 1, "ib": -1, "nvl": 0}),
                ("extra key", {"eth": 1, "ib": 0, "nvl": 0, "extra": 0}),
            ):
                with self.subTest(case=label):
                    altered = json.loads(accepted_child)
                    if altered_counts is None:
                        altered["counts"].pop("host_declarations_by_family")
                    else:
                        altered["counts"]["host_declarations_by_family"] = altered_counts
                    child_path.write_text(json.dumps(altered), encoding="utf-8")
                    parent_stat = current.stat()
                    try:
                        with self.assertRaises(release_fixture.LOAD.LoadError):
                            release_fixture.LOAD.validate_and_publish_release(
                                fixture.project, inputs,
                            )
                        self.assertEqual(accepted_parent, current.read_bytes())
                        self.assertEqual(parent_stat.st_ino, current.stat().st_ino)
                        self.assertEqual(parent_stat.st_mtime_ns, current.stat().st_mtime_ns)
                        self.assertEqual(output_snapshot, {
                            name: (outputs / name).read_bytes() for name in output_snapshot
                        })
                    finally:
                        child_path.write_bytes(accepted_child)
                        current.write_bytes(accepted_parent)
        finally:
            fixture.tearDown()

    def test_r22_real_c1_load_rejects_zero_count_nonempty_host_with_matching_hash(self):
        """A matched SHA cannot authorize a stale count-zero preserved family."""
        fixture = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match",
        )
        fixture.setUp()
        try:
            inputs, outputs, child = (
                release_fixture.prepare_r22_empty_unselected_dhcp_fixture(fixture)
            )
            load_settings = LOAD.load_global(fixture.global_file)
            LOAD.validate_subnet_file(fixture.subnet_file, load_settings)
            release_fixture.LOAD.validate_and_publish_release(fixture.project, inputs)
            current = fixture.project / "99-output-ztp/current-release.json"
            child_path = outputs / "dhcp-release-manifest.json"
            ib_hosts = outputs / "dhcpd_ib.hosts"
            self.assertEqual(b"", ib_hosts.read_bytes())
            self.assertEqual(0, child["counts"]["host_declarations_by_family"]["ib"])
            accepted_parent = current.read_bytes()
            accepted_child = child_path.read_bytes()
            other_outputs = {
                name: (outputs / name).read_bytes() for name in (
                    "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_nvl.hosts",
                )
            }
            ib_hosts.write_bytes(
                b"host preserved-ib01 {\n"
                b"  hardware ethernet 02:00:00:00:20:01;\n"
                b"}\n"
            )
            child["outputs"]["dhcpd_ib.hosts"]["sha256"] = (
                release_fixture.sha256(ib_hosts)
            )
            child_path.write_text(json.dumps(child), encoding="utf-8")
            self.assertEqual(
                child["outputs"]["dhcpd_ib.hosts"]["sha256"],
                release_fixture.sha256(ib_hosts),
            )
            parent_stat = current.stat()
            try:
                with self.assertRaises(release_fixture.LOAD.LoadError):
                    release_fixture.LOAD.validate_and_publish_release(
                        fixture.project, inputs,
                    )
                self.assertEqual(accepted_parent, current.read_bytes())
                self.assertEqual(parent_stat.st_ino, current.stat().st_ino)
                self.assertEqual(parent_stat.st_mtime_ns, current.stat().st_mtime_ns)
                self.assertEqual(other_outputs, {
                    name: (outputs / name).read_bytes() for name in other_outputs
                })
            finally:
                ib_hosts.write_bytes(b"")
                child_path.write_bytes(accepted_child)
                current.write_bytes(accepted_parent)
        finally:
            fixture.tearDown()

    def test_r22_real_c1_rejects_rebound_preserved_zero_host_before_child_publish(self):
        """An unselected 0-byte host cannot be counted through a new same-empty leaf."""
        with tempfile.TemporaryDirectory() as name:
            fixture = ScopedDhcpFixture(Path(name))
            fixture.outputs["ib"].write_bytes(b"")
            fixture.outputs["nvl"].write_bytes(b"")
            before = fixture.snapshot()
            detached = fixture.root / "detached-ib.hosts"
            foreign = fixture.root / "foreign" / "same-empty.hosts"
            foreign.parent.mkdir()
            foreign.write_bytes(b"")
            canonical_ib = os.path.realpath(fixture.outputs["ib"])
            original_lstat = os.lstat
            switched = False

            def rebind_after_preserved_stat(path, *args, **kwargs):
                nonlocal switched
                metadata = original_lstat(path, *args, **kwargs)
                frame = sys._getframe(1)
                counting_preserved = False
                while frame is not None:
                    if frame.f_code.co_name == "_count_preserved_host_declarations":
                        counting_preserved = True
                        break
                    frame = frame.f_back
                if (
                    os.fspath(path) == canonical_ib
                    and counting_preserved
                    and not switched
                ):
                    switched = True
                    fixture.outputs["ib"].rename(detached)
                    fixture.outputs["ib"].symlink_to(foreign)
                return metadata

            rejection = None
            with mock.patch.object(
                SCOPED_DHCP.os, "lstat", side_effect=rebind_after_preserved_stat,
            ), mock.patch.object(SCOPED_DHCP, "stop_native_ztp_monitors"):
                try:
                    fixture.execute([
                        "c1-generate_dhcp.py", "-y", "--deployment-scope", "prod",
                        "--switch", "eth",
                    ])
                except (OSError, ValueError, SystemExit) as exc:
                    rejection = exc
            self.assertTrue(switched)
            self.assertEqual(b"", detached.read_bytes())
            self.assertEqual(b"", foreign.read_bytes())
            self.assertIsNotNone(rejection, "c1 published after preserved leaf rebind")
            for label in ("conf", "eth", "nvl", "manifest"):
                path = fixture.outputs[label]
                metadata = path.lstat()
                self.assertEqual(before[label][0], path.read_bytes(), label)
                self.assertEqual(before[label][1][1], metadata.st_ino, label)
                self.assertEqual(before[label][1][3], metadata.st_mtime_ns, label)

    def test_r22_invalid_subnet_rejects_before_docker_runtime_write(self):
        cases = (
            ("missing off", None, "disabled"),
            ("missing on", None, "enabled"),
            ("zero-byte off", "", "disabled"),
            ("zero-byte on", "", "enabled"),
            ("whitespace off", " \t\n", "disabled"),
            ("whitespace on", " \t\n", "enabled"),
            ("bad header off", _R22_SUBNET_HEADER.replace(
                "shared_network", "shared_networb"), "disabled"),
            ("bad header on", _R22_SUBNET_HEADER.replace(
                "shared_network", "shared_networb"), "enabled"),
            ("enabled header-only", _R22_SUBNET_HEADER, "enabled"),
            ("delimiter-only off", _R22_SUBNET_HEADER + ",,,,,,,,\n", "disabled"),
        )
        for label, payload, dhcp_status in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                global_yaml, subnet, activate, docker_settings = self._r22_csv_project(
                    root, _R22_SUBNET_HEADER if payload is None else payload,
                    dhcp_status,
                )
                if payload is None:
                    subnet.unlink()
                # This is a prewrite preservation sentinel, not a forged
                # accepted parent-release proof.
                prior_release = global_yaml.parent / "99-output-ztp/current-release.json"
                prior_release.parent.mkdir()
                prior_release.write_bytes(b"prior release sentinel\n")
                prior_release_witness = (
                    prior_release.read_bytes(), prior_release.stat().st_ino,
                    prior_release.stat().st_mtime_ns,
                )
                with self.subTest(stage="setup"):
                    errors, _warnings = SETUP._validate_subnet_csv(
                        subnet, dhcp_enabled=dhcp_status == "enabled",
                        ztp_enabled=False,
                    )
                    self.assertTrue(errors, label)
                with self.subTest(stage="load"):
                    load_settings = LOAD.load_global(global_yaml)
                    with self.assertRaises(LOAD.LoadError):
                        LOAD.validate_subnet_file(subnet, load_settings)
                docker_settings.state_root.mkdir()
                docker_settings.apache_listeners.write_bytes(b"old-apache\n")
                docker_settings.runtime_plan.write_bytes(b"old-plan\n")
                witnesses = tuple(
                    (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                    for path in (
                        docker_settings.apache_listeners, docker_settings.runtime_plan,
                    )
                )
                snapshot, runtime = self._r22_docker_observation(activate)
                with self.subTest(stage="docker"), snapshot, runtime, mock.patch.object(
                    activate, "ensure_runtime_directories"
                ) as mkdir, mock.patch.object(activate, "_atomic_write") as write:
                    with self.assertRaises(activate.ActivationError):
                        activate.prepare_runtime(docker_settings)
                    mkdir.assert_not_called()
                    write.assert_not_called()
                self.assertEqual(
                    witnesses,
                    tuple(
                        (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                        for path in (
                            docker_settings.apache_listeners, docker_settings.runtime_plan,
                        )
                    ),
                )
                self.assertEqual(
                    prior_release_witness,
                    (prior_release.read_bytes(), prior_release.stat().st_ino,
                     prior_release.stat().st_mtime_ns),
                )

    def test_r22_setup_cli_rejects_bad_subnet_before_native_stop_or_setup(self):
        cases = (
            ("missing", None),
            ("zero-byte", ""),
            ("bad header", _R22_SUBNET_HEADER.replace(
                "shared_network", "shared_networb")),
        )
        for label, payload in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                global_yaml, subnet, _activate, _settings = self._r22_csv_project(
                    root, _R22_SUBNET_HEADER if payload is None else payload,
                    "disabled",
                )
                if payload is None:
                    subnet.unlink()
                # The setup entry must not touch an existing release path.
                prior_release = global_yaml.parent / "99-output-ztp/current-release.json"
                prior_release.parent.mkdir()
                prior_release.write_bytes(b"prior release sentinel\n")
                prior_release_witness = (
                    prior_release.read_bytes(), prior_release.stat().st_ino,
                    prior_release.stat().st_mtime_ns,
                )
                args = SimpleNamespace(
                    project=str(global_yaml.parent), csv_dir=None, p2p_file=None,
                    create=False, dry_run=False, host_role="management-server",
                    _server_delegated=False,
                )
                with mock.patch.object(SETUP, "require_project_eligible"), mock.patch.object(
                    SETUP, "stop_native_ztp_monitors"
                ) as stop, mock.patch.object(SETUP, "setup") as setup:
                    with self.assertRaises(ValueError):
                        SETUP._main_locked(args)
                stop.assert_not_called()
                setup.assert_not_called()
                self.assertEqual(
                    None if payload is None else payload.encode("utf-8"),
                    subnet.read_bytes() if subnet.exists() else None,
                )
                self.assertEqual(
                    prior_release_witness,
                    (prior_release.read_bytes(), prior_release.stat().st_ino,
                     prior_release.stat().st_mtime_ns),
                )

    def test_r22_symlink_subnet_is_rejected_across_real_consumers(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            global_yaml, subnet, activate, docker_settings = self._r22_csv_project(
                root, _R22_SUBNET_HEADER, "disabled",
            )
            original = subnet.with_name("real-subnet.csv")
            subnet.rename(original)
            subnet.symlink_to(original)
            prior_release = global_yaml.parent / "99-output-ztp/current-release.json"
            prior_release.parent.mkdir()
            # These sentinels prove prewrite preservation, not acceptance of
            # a fabricated parent release or upload archive.
            prior_release.write_bytes(b"prior release sentinel\n")
            prior_archive = root / "prior-upload.tar.gz"
            prior_archive.write_bytes(b"prior archive sentinel\n")
            docker_settings.state_root.mkdir()
            docker_settings.apache_listeners.write_bytes(b"prior-apache\n")
            docker_settings.runtime_plan.write_bytes(b"prior-plan\n")
            old_paths = (
                prior_release, prior_archive, docker_settings.apache_listeners,
                docker_settings.runtime_plan,
            )
            old = tuple(
                (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                for path in old_paths
            )
            errors, _warnings = SETUP._validate_subnet_csv(
                subnet, dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertTrue(errors)
            args = SimpleNamespace(
                project=str(global_yaml.parent), csv_dir=None, p2p_file=None,
                create=False, dry_run=False, host_role="management-server",
                _server_delegated=False,
            )
            with mock.patch.object(SETUP, "require_project_eligible"), mock.patch.object(
                SETUP, "stop_native_ztp_monitors"
            ) as stop, mock.patch.object(SETUP, "setup") as setup:
                with self.assertRaises(ValueError):
                    SETUP._main_locked(args)
            stop.assert_not_called()
            setup.assert_not_called()
            load_settings = LOAD.load_global(global_yaml)
            with self.assertRaisesRegex(LOAD.LoadError, "symlink|软链接|普通文件"):
                LOAD.validate_subnet_file(subnet, load_settings)
            with self.assertRaisesRegex(RUNTIME.RuntimeContractError, "symlink|regular"):
                RUNTIME.plan_dhcp_runtime(
                    subnet, link_snapshot=[], address_snapshot=[],
                    dhcp_enabled=False, ztp_enabled=False,
                )
            snapshot, runtime = self._r22_docker_observation(activate)
            with snapshot, runtime, mock.patch.object(
                activate, "ensure_runtime_directories"
            ) as mkdir, mock.patch.object(activate, "_atomic_write") as write:
                with self.assertRaises(activate.ActivationError):
                    activate.prepare_runtime(docker_settings)
            mkdir.assert_not_called()
            write.assert_not_called()
            package = load_script(
                "r22_symlink_package_direct_workflow",
                ROOT / "tools/_package_common.py",
            )
            with mock.patch.object(package, "ROOT", root):
                with self.assertRaises(ValueError):
                    package._bind_package_project_inputs(
                        [global_yaml.parent], maximum_size=None,
                    )
            self.assertEqual(
                old,
                tuple(
                    (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                    for path in old_paths
                ),
            )
            self.assertFalse(docker_settings.dhcp_leases.exists())

    def test_r22_hardlink_subnet_is_rejected_before_docker_writes(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            global_yaml, subnet, activate, docker_settings = self._r22_csv_project(
                root, _R22_SUBNET_HEADER, "disabled",
            )
            original = subnet.with_name("real-subnet.csv")
            subnet.rename(original)
            os.link(original, subnet)
            self.assertEqual(2, subnet.stat().st_nlink)
            errors, _warnings = SETUP._validate_subnet_csv(
                subnet, dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertTrue(errors)
            load_settings = LOAD.load_global(global_yaml)
            with self.assertRaisesRegex(LOAD.LoadError, "single-link|硬链接"):
                LOAD.validate_subnet_file(subnet, load_settings)
            with self.assertRaisesRegex(
                RUNTIME.RuntimeContractError, "single-link|hardlink"
            ):
                RUNTIME.plan_dhcp_runtime(
                    subnet, link_snapshot=[], address_snapshot=[],
                    dhcp_enabled=False, ztp_enabled=False,
                )
            snapshot, runtime = self._r22_docker_observation(activate)
            with snapshot, runtime, mock.patch.object(
                activate, "ensure_runtime_directories"
            ) as mkdir, mock.patch.object(activate, "_atomic_write") as write:
                with self.assertRaises(activate.ActivationError):
                    activate.prepare_runtime(docker_settings)
            mkdir.assert_not_called()
            write.assert_not_called()
            self.assertFalse(docker_settings.state_root.exists())

    def test_r22_setup_generation_swap_rejects_before_writes_while_new_input_is_valid(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            global_yaml, subnet, activate, docker_settings = self._r22_csv_project(
                root, _R22_SUBNET_HEADER + " \n", "disabled",
            )
            replacement = subnet.with_name("replacement.csv")
            replacement.write_text(_R22_SUBNET_HEADER + "\t\n", encoding="utf-8")
            old = subnet.with_name("old.csv")
            self.assertEqual(subnet.stat().st_size, replacement.stat().st_size)
            actual_validate = SETUP._validate_subnet_csv
            swapped = False

            def swap_after_validated_read(path, **kwargs):
                nonlocal swapped
                result = actual_validate(path, **kwargs)
                if not swapped:
                    subnet.rename(old)
                    replacement.rename(subnet)
                    swapped = True
                return result

            with mock.patch.object(
                SETUP, "_validate_subnet_csv", side_effect=swap_after_validated_read,
            ), mock.patch.object(
                SETUP, "_initialize_project_from_template",
                side_effect=AssertionError("setup write boundary was reached"),
            ) as initialize:
                with self.assertRaisesRegex(ValueError, "来源|identity|变化|drift"):
                    SETUP._setup_impl(global_yaml.parent)
            initialize.assert_not_called()
            self.assertTrue(swapped)
            self.assertTrue(old.exists())
            self.assertFalse(docker_settings.state_root.exists())

            # The new generation is independently valid; rejection is about
            # mixing generations within one setup transaction, not its rows.
            load_settings = LOAD.load_global(global_yaml)
            LOAD.validate_subnet_file(subnet, load_settings)
            runtime_plan = RUNTIME.plan_dhcp_runtime(
                subnet, link_snapshot=[], address_snapshot=[],
                dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertEqual((), runtime_plan.listener_names)
            snapshot, runtime = self._r22_docker_observation(activate)
            with snapshot, runtime:
                selected, _loaded, _payload, _apache = activate.observe_runtime(
                    docker_settings
                )
            self.assertEqual((), selected.listener_names)
            self.assertFalse(docker_settings.state_root.exists())

    def test_r22_load_runtime_docker_rejects_inplace_subnet_change_before_plan_write(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            global_yaml, subnet, activate, settings = self._r22_csv_project(
                root, _R22_SUBNET_HEADER + " \n", "disabled",
            )
            load_settings = LOAD.load_global(global_yaml)
            LOAD.validate_subnet_file(subnet, load_settings)
            source_sha = hashlib.sha256(subnet.read_bytes()).hexdigest()
            settings.state_root.mkdir()
            settings.apache_listeners.write_bytes(b"old-apache\n")
            settings.runtime_plan.write_bytes(b"old-plan\n")
            previous = tuple(
                (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                for path in (settings.apache_listeners, settings.runtime_plan)
            )
            actual_plan = RUNTIME.plan_dhcp_runtime
            changed = False

            def change_after_parse(*args, **kwargs):
                nonlocal changed
                plan = actual_plan(*args, **kwargs)
                if not changed:
                    subnet.write_text(_R22_SUBNET_HEADER + "\t\n", encoding="utf-8")
                    changed = True
                return plan

            snapshot, runtime = self._r22_docker_observation(activate)
            with snapshot, runtime, mock.patch.object(
                RUNTIME, "plan_dhcp_runtime", side_effect=change_after_parse,
            ), mock.patch.object(
                activate, "ensure_runtime_directories",
            ) as mkdir, mock.patch.object(activate, "_atomic_write") as write:
                with self.assertRaisesRegex(
                    activate.ActivationError, "subnet.*(changed|drift)"
                ):
                    activate.prepare_runtime(settings)
            self.assertTrue(changed)
            self.assertNotEqual(source_sha, hashlib.sha256(subnet.read_bytes()).hexdigest())
            LOAD.validate_subnet_file(subnet, load_settings)
            mkdir.assert_not_called()
            write.assert_not_called()
            self.assertEqual(
                previous,
                tuple(
                    (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                    for path in (settings.apache_listeners, settings.runtime_plan)
                ),
            )

    def test_r22_load_sha_drift_and_package_parser_reject_same_invalid_generation(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            global_yaml, subnet, _activate, docker_settings = self._r22_csv_project(
                root, _R22_SUBNET_HEADER, "disabled",
            )
            project = global_yaml.parent
            setup_errors, _warnings = SETUP._validate_subnet_csv(
                subnet, dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertEqual([], setup_errors)
            replacement = project / "replacement.csv"
            replacement.write_text(
                _R22_SUBNET_HEADER.replace("shared_network", "shared_networb"),
                encoding="utf-8",
            )
            self.assertEqual(subnet.stat().st_size, replacement.stat().st_size)
            p2p = project / "p2p.xlsx"
            p2p.write_bytes(b"read-only fixture\n")
            actual_validate = LOAD.validate_subnet_file
            swapped = False

            def swap_after_validation(path, settings):
                nonlocal swapped
                actual_validate(path, settings)
                subnet.rename(project / "old.csv")
                replacement.rename(subnet)
                swapped = True

            args = SimpleNamespace(
                p2p_file=None, deployment_scope="all", switch_scope="all",
                no_upgrade=True, mini=None, ssh_dir=None,
            )
            with mock.patch.object(
                LOAD, "find_placeholder_password_sections", return_value=(),
            ), mock.patch.object(
                LOAD, "apply_subnet_service_ips", side_effect=lambda settings, _path: settings,
            ), mock.patch.object(
                LOAD, "load_device_types", return_value=frozenset(),
            ), mock.patch.object(
                LOAD, "select_p2p", return_value=p2p,
            ), mock.patch.object(
                LOAD, "project_air_topology_policy", return_value=None,
            ), mock.patch.object(
                LOAD, "project_mini_air_devices", return_value=(None, None),
            ), mock.patch.object(
                LOAD, "validate_subnet_file", side_effect=swap_after_validation,
            ), mock.patch.object(
                LOAD, "validate_shared_artifact_receipts",
                side_effect=AssertionError("release prewrite boundary reached"),
            ) as receipts:
                with self.assertRaisesRegex(LOAD.LoadError, "subnet|source|来源|changed"):
                    LOAD.validate_inputs(
                        project, args, allow_management_key_generation=False,
                        host_role="workstation",
                    )
            self.assertTrue(swapped)
            receipts.assert_not_called()
            package = load_script(
                "r22_package_source_workflow", ROOT / "tools/_package_common.py"
            )
            with self.assertRaisesRegex(ValueError, "header"):
                package._bind_package_project_inputs([project], maximum_size=None)
            self.assertFalse(docker_settings.state_root.exists())

    def test_r22_temp_archive_source_sha_roundtrip_and_invalid_retain_old(self):
        """Exercise real bound-input and archive verifiers without publishing."""
        package = load_script("r22_bound_package_workflow", ROOT / "tools/_package_common.py")
        upload = load_script("r22_upload_verify_workflow", ROOT / "tools/tar-for-upload.py")
        installer = load_script(
            "r22_archive_verify_workflow", ROOT / "tools/deploy-upload-archive.py"
        )
        payloads = (
            ("disabled semantic row", "disabled", _R22_SUBNET_HEADER
             + "mgmt,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.110,"
               "192.0.2.1,,none,no\n"),
            ("disabled canonical empty", "disabled", _R22_SUBNET_HEADER + "\n \n"),
            ("enabled semantic row", "enabled", _R22_SUBNET_HEADER
             + "mgmt,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.110,"
               "192.0.2.1,,none,no\n"),
        )
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            project = root / "DAY0-Prepare" / "fixture"
            project.mkdir(parents=True)
            global_yaml = project / "01-global.yaml"
            global_yaml.write_text(
                "schema_version: 2\ncommon:\n  mgmt:\n"
                "    dhcp-server:\n      status: disabled\n"
                "    ztp:\n      status: disabled\n",
                encoding="utf-8",
            )
            devices = project / "02-devices_config.csv"
            devices.write_text("hostname,type,mac\n", encoding="utf-8")
            subnet = project / "02-dhcp-subnet_config.csv"
            archive_path = root / "previous-upload.tar.gz"
            installer_path = root / "deploy-upload-archive.py"
            installer_path.write_bytes((ROOT / "tools/deploy-upload-archive.py").read_bytes())
            installer_path.chmod(0o500)
            guard_bytes = (ROOT / "tools/deployment_prewrite_guard.py").read_bytes()

            for label, dhcp_status, csv_text in payloads:
                with self.subTest(case=label):
                    global_yaml.write_text(
                        "schema_version: 2\ncommon:\n  mgmt:\n"
                        "    dhcp-server:\n"
                        f"      status: {dhcp_status}\n"
                        "    ztp:\n      status: disabled\n",
                        encoding="utf-8",
                    )
                    subnet.write_text(csv_text, encoding="utf-8")
                    with mock.patch.object(package, "ROOT", root):
                        bound = package._bind_package_project_inputs(
                            [project], maximum_size=None,
                        )
                        package._recheck_package_project_inputs(bound)
                    bound_pair = bound["DAY0-Prepare/fixture"]
                    subnet_bound = next(item for item in bound_pair if item.name == subnet.name)
                    with mock.patch.object(package, "ROOT", root):
                        subnet_member_name = subnet_bound.member_name
                    bound_filter = mock.Mock(side_effect=lambda info: info)
                    bound_filter.bound_inputs_by_member = {
                        subnet_member_name: subnet_bound,
                    }
                    source_bytes = csv_text.encode("utf-8")
                    self.assertEqual(source_bytes, subnet_bound.payload)
                    members = {
                        "tools/deploy-upload-archive.py": installer_path.read_bytes(),
                        "tools/deployment_prewrite_guard.py": guard_bytes,
                        "DAY0-Prepare/fixture/01-global.yaml": global_yaml.read_bytes(),
                        "DAY0-Prepare/fixture/02-devices_config.csv": devices.read_bytes(),
                        "DAY0-Prepare/fixture/02-dhcp-subnet_config.csv": subnet_bound.payload,
                    }
                    # The production image-source manifest covers executable
                    # source, not mutable DAY0 project inputs. The latter are
                    # bound by the package producer before tar publication.
                    records = [
                        {"path": relative, "type": "file", "target": None,
                         "sha256": hashlib.sha256(payload).hexdigest()}
                        for relative, payload in members.items()
                        if relative.startswith("tools/")
                    ]
                    self.assertNotIn(
                        "DAY0-Prepare/fixture/02-dhcp-subnet_config.csv",
                        {record["path"] for record in records},
                    )
                    manifest = (
                        json.dumps(
                            {"schema_version": 1, "files": records},
                            sort_keys=True, separators=(",", ":"),
                        ) + "\n"
                    ).encode("ascii")
                    manifest_path = root / "current-source-manifest.json"
                    manifest_path.write_bytes(manifest)
                    members["infra/docker/deployment-source-manifest.json"] = manifest
                    with tarfile.open(archive_path, "w:gz") as archive:
                        for relative, payload in members.items():
                            if relative == "DAY0-Prepare/fixture/02-dhcp-subnet_config.csv":
                                package._add_reproducible_source(
                                    archive, subnet, "./" + relative, bound_filter,
                                )
                                continue
                            info = tarfile.TarInfo("./" + relative)
                            info.mode = 0o500 if relative == "tools/deploy-upload-archive.py" else 0o644
                            info.size = len(payload)
                            archive.addfile(info, io.BytesIO(payload))
                    archive_path.chmod(0o600)
                    with mock.patch.object(upload, "ROOT", root), mock.patch.object(
                        upload.package_core, "write_deployment_source_manifest",
                        return_value=manifest_path,
                    ):
                        upload.validate_uploaded_archive_for_deploy(archive_path, project)
                    verified = installer.verify_inputs(
                        archive_path, installer_path, required_uid=os.getuid(),
                    )
                    self.assertEqual("fixture", verified.project)
                    self.assertEqual(
                        hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                        verified.archive_sha256,
                    )
                    with tarfile.open(archive_path, "r:gz") as archive:
                        archived = archive.extractfile(
                            "./DAY0-Prepare/fixture/02-dhcp-subnet_config.csv"
                        ).read()
                    self.assertEqual(source_bytes, archived)
                    self.assertEqual(
                        hashlib.sha256(source_bytes).hexdigest(),
                        hashlib.sha256(archived).hexdigest(),
                    )

            old = (
                archive_path.read_bytes(), archive_path.stat().st_ino,
                archive_path.stat().st_mtime_ns,
            )
            invalid = (
                ("missing", None),
                ("zero-byte", ""),
                ("blank", " \t\n\r\n"),
                ("bad header", _R22_SUBNET_HEADER.replace(
                    "shared_network", "shared_networb")),
                ("enabled header-only", _R22_SUBNET_HEADER),
                ("delimiter-only row", _R22_SUBNET_HEADER + ",,,,,,,,\n"),
            )
            for label, csv_text in invalid:
                with self.subTest(case=label):
                    if csv_text is None:
                        subnet.unlink()
                    else:
                        subnet.write_text(csv_text, encoding="utf-8")
                    with mock.patch.object(package, "ROOT", root):
                        with self.assertRaises(ValueError):
                            package._bind_package_project_inputs(
                                [project], maximum_size=None,
                            )
                    self.assertEqual(
                        old,
                        (archive_path.read_bytes(), archive_path.stat().st_ino,
                         archive_path.stat().st_mtime_ns),
                    )
            # The final drift probe uses the disabled/header-only valid case.
            global_yaml.write_text(
                "schema_version: 2\ncommon:\n  mgmt:\n"
                "    dhcp-server:\n      status: disabled\n"
                "    ztp:\n      status: disabled\n",
                encoding="utf-8",
            )
            subnet.write_text(_R22_SUBNET_HEADER + " \n", encoding="utf-8")
            with mock.patch.object(package, "ROOT", root):
                drift_bound = package._bind_package_project_inputs(
                    [project], maximum_size=None,
                )
                drift_item = next(
                    item for item in drift_bound["DAY0-Prepare/fixture"]
                    if item.name == subnet.name
                )
                drift_member_name = drift_item.member_name
            subnet.write_text(_R22_SUBNET_HEADER + "\t\n", encoding="utf-8")
            drift_filter = mock.Mock(side_effect=lambda info: info)
            drift_filter.bound_inputs_by_member = {
                drift_member_name: drift_item,
            }
            with self.assertRaisesRegex(ValueError, "drifted before publication"):
                package._recheck_package_project_inputs(drift_bound)
            with self.assertRaisesRegex(ValueError, "bound package input changed"):
                with tarfile.open(root / "drift-candidate.tar.gz", "w:gz") as archive:
                    package._add_reproducible_source(
                        archive, subnet, drift_member_name, drift_filter,
                    )
            self.assertEqual(
                old,
                (archive_path.read_bytes(), archive_path.stat().st_ino,
                 archive_path.stat().st_mtime_ns),
            )
            candidate = root / "tampered-candidate.tar.gz"
            altered = dict(members)
            altered["tools/deployment_prewrite_guard.py"] = guard_bytes + b"# tampered\n"
            with tarfile.open(candidate, "w:gz") as archive:
                for relative, payload in altered.items():
                    info = tarfile.TarInfo("./" + relative)
                    info.mode = 0o500 if relative == "tools/deploy-upload-archive.py" else 0o644
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
            candidate.chmod(0o600)
            with self.assertRaisesRegex(
                installer.InstallError,
                "source manifest hash mismatch for tools/deployment_prewrite_guard.py",
            ):
                installer.verify_inputs(
                    candidate, installer_path, required_uid=os.getuid(),
                )
            self.assertEqual(
                old,
                (archive_path.read_bytes(), archive_path.stat().st_ino,
                 archive_path.stat().st_mtime_ns),
            )

    def test_http_only_real_load_plan_matches_container_config_consumer(self):
        """Real DAY0 plan and Docker activation select the same HTTP-only services."""
        activate = load_script(
            "dhcp_optional_container_activation",
            Path(__file__).resolve().parents[1] / "infra/docker/activate.py",
        )
        settings = LOAD.replace(
            settings_for("disabled"), http_root=LOAD.HTTP_ROOT,
            http_address="192.0.2.10",
        )
        with tempfile.TemporaryDirectory() as name:
            subnet = Path(name) / "02-dhcp-subnet_config.csv"
            subnet.write_text(_R22_SUBNET_HEADER, encoding="utf-8")
            inputs = SimpleNamespace(settings=settings, subnet_file=subnet)
            with mock.patch.object(
                LOAD, "local_ipv4_addresses", return_value={"192.0.2.10"},
            ):
                selected = LOAD.plan_local_dhcp_runtime(inputs)
                self.assertEqual(
                    (True, False),
                    LOAD.supervisor_service_availability(inputs, selected),
                )
            self.assertEqual((), selected.endpoint_ips)
            self.assertEqual((), selected.listener_names)
            self.assertEqual(
                ("apache2",),
                activate.expected_services(
                    selected, dhcp_status="disabled",
                    http_listener_ips=settings.http_listener_ips,
                ),
            )
            apache = activate.render_apache_listener_config(
                settings.http_listener_ips, port=settings.http_port,
            )
            self.assertIn("192.0.2.10", apache)

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
