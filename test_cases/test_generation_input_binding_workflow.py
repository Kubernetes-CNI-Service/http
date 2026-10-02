#!/usr/bin/env python3
"""Real setup/load/c2 handoff when a project input changes after validation."""

from __future__ import annotations

import base64
import copy
import csv
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import openpyxl
import yaml

from test_cases.module_loader import load_script
from test_cases.test_v2_generation_flow import (
    BASE_HEADER,
    EVPN_HEADER,
    FIXED_HEADER,
    V2MlagSetupPreflightTests,
    v2_mlag_preflight_global,
)
from test_cases.test_mlag_evpn_generation import border_globals
from test_cases import test_flow_release_platform_matrix as PLATFORM_FLOW


ROOT = Path(__file__).resolve().parents[1]
SETUP = load_script(
    "r22_generation_binding_workflow_setup", ROOT / "DAY0-Prepare/01-a-setup.py",
)
LOAD = load_script(
    "r22_generation_binding_workflow_load", ROOT / "DAY0-Prepare/11-load.py",
)
C2 = load_script(
    "r22_generation_binding_workflow_c2",
    ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
)
ACTIVATE = load_script(
    "r22_generation_binding_workflow_activate", ROOT / "infra/docker/activate.py",
)
PUBLISHER = load_script(
    "r22_generation_binding_workflow_publisher",
    ROOT / "ztp/config/cumulus/d-hostname2mac.py",
)
SUBNET_HEADER = (
    "shared_network,subnet,netmask,range_start,range_end,routers,"
    "ztp_service_ip,cumulus_profile,nvos_ztp\n"
)

REAL_CHILD_SCRIPTS = (
    "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
    "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
    "ztp/config/cumulus/template/90-c2-generate_configs.py",
    "ztp/config/cumulus/d-hostname2mac.py",
)
DHCP_OUTPUTS = (
    "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
    "dhcpd_nvl.hosts", "dhcp-release-manifest.json",
)


def _write_legal_project(project: Path, rows: list[list[str]]) -> None:
    project.mkdir()
    document = v2_mlag_preflight_global()
    document["common"]["mgmt"].update({
        "dhcp-server": {"status": "disabled", "package": "isc-dhcp-server"},
        "http": {
            "status": "disabled", "http_root": "/var/www/html",
            "package": "apache2", "port": 80,
        },
        "ztp": {"status": "disabled", "ztp_url_prefix": "/ztp"},
    })
    document["common"]["switch"] = {
        "system": {"dns": {}, "ntp": {}, "date-time": {}},
    }
    document["switches"][0]["eth"]["system"]["aaa"] = {
        "user": {"cumulus": {"hashed-password": "$6$fixture$safe-value"}},
    }
    (project / "01-global.yaml").write_text(
        yaml.safe_dump(document, sort_keys=False), encoding="utf-8",
    )
    with (project / "02-devices_config.csv").open(
        "w", newline="", encoding="utf-8",
    ) as stream:
        csv.writer(stream).writerows([BASE_HEADER + FIXED_HEADER + EVPN_HEADER, *rows])
    (project / "02-dhcp-subnet_config.csv").write_text(
        SUBNET_HEADER, encoding="utf-8",
    )
    workbook = openpyxl.Workbook()
    try:
        workbook.save(project / "p2p.xlsx")
    finally:
        workbook.close()
    # A literal, structurally valid OpenSSH public key keeps LOAD's real
    # workstation key preflight on the path without touching the real HOME.
    key_type = b"ssh-ed25519"
    wire = (
        struct.pack(">I", len(key_type)) + key_type
        + struct.pack(">I", 32) + b"\x11" * 32
    )
    (project / "operator.pub").write_text(
        "ssh-ed25519 " + base64.b64encode(wire).decode("ascii") + " fixture\n",
        encoding="utf-8",
    )
    (project / ".management-pubkeys").write_text(
        "mgmt-server.pub\n", encoding="utf-8",
    )
    (project / "mgmt-server.pub").write_bytes(b"")


def _private_real_chain(
    root: Path, dns_ip: str, *, http_enabled: bool = False,
) -> tuple[Path, Path]:
    """Build only the files real LOAD/b/c1/c2/d read under a private root."""
    project = root / "DAY0-Prepare/project"
    project.parent.mkdir(parents=True)
    _write_legal_project(project, V2MlagSetupPreflightTests().pair())
    global_file = project / "01-global.yaml"
    document = yaml.safe_load(global_file.read_text(encoding="utf-8"))
    document["common"]["mgmt"]["dhcp-server"]["status"] = "enabled"
    document["common"]["mgmt"]["ztp"]["status"] = "enabled"
    if http_enabled:
        document["common"]["mgmt"]["http"]["status"] = "enabled"
    complete = border_globals()
    eth = document["switches"][0]["eth"]
    eth["bridge"] = complete["bridge"]
    eth["version"] = complete["version"]
    eth["vrf"] = complete["vrf"]
    eth["mlag"].update(complete["mlag"])
    eth["mlag"]["priority"] = [100, 200]
    eth["system"]["date-time"] = complete["system"]["date-time"]
    eth["system"]["ntp"] = complete["system"]["ntp"]
    eth["system"]["dns"] = {"server": [dns_ip], "vrf": "mgmt"}
    eth["system"]["aaa"]["user"]["cumulus"]["full-name"] = "cumulus,,,"
    global_file.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    (project / "02-dhcp-subnet_config.csv").write_text(
        SUBNET_HEADER
        + "mgmt,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.120,"
        "192.0.2.1,192.0.2.20,oob,no\n",
        encoding="utf-8",
    )
    workbook = openpyxl.Workbook()
    try:
        sheet = workbook.active
        sheet.title = "OOB Server-LF"
        sheet.cell(1, 5, "Source")
        sheet.cell(1, 11, "Dest")
        for col, value in ((7, "name"), (8, "HCA/port"), (13, "name"), (14, "port")):
            sheet.cell(2, col, value)
        sheet.cell(3, 7, "Border01")
        sheet.cell(3, 8, "swp53")
        sheet.cell(3, 13, "Border02")
        sheet.cell(3, 14, "swp53")
        workbook.save(project / "selected-p2p.xlsx")
    finally:
        workbook.close()
    (project / "p2p.xlsx").unlink()
    (project / "p2p.xlsx").symlink_to("selected-p2p.xlsx")

    ztp = root / "ztp"
    shutil.copytree(ROOT / "tools", root / "tools")
    resources = (
        "ztp/nvue_normalizer.py",
        "ztp/config/topology_rules.py",
        "ztp/config/cumulus/template/P2P/lldpq-template.dot",
        "ztp/config/cumulus/template/P2P/air-template-no-oob.json",
        "ztp/config/cumulus/default.yaml",
        "ztp/optimize/sample_links.py",
        *REAL_CHILD_SCRIPTS,
    )
    for resource in resources:
        destination = root / resource
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / resource, destination)
    shutil.copytree(
        ROOT / "ztp/config/cumulus/template/03-templates-j2",
        ztp / "config/cumulus/template/03-templates-j2",
    )

    def link(path: Path, target: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(os.path.relpath(target, path.parent))

    p2p = ztp / "config/cumulus/template/P2P"
    link(p2p / "p2p.xlsx", project / "p2p.xlsx")
    (p2p / "01-inventory.log").write_text("[Eth-SW]\nBorder01\nBorder02\n")
    (p2p / "02-port-mapping.log").write_text("[Eth-SW]\nswp53,swp53\n")
    (p2p / "output-p2p").mkdir()
    for directory in (ztp / "config/isc-dhcp-server", ztp / "config/cumulus/template"):
        link(directory / "01-global.yaml", global_file)
        link(directory / "02-devices_config.csv", project / "02-devices_config.csv")
    link(
        ztp / "config/isc-dhcp-server/02-subnet_config.csv",
        project / "02-dhcp-subnet_config.csv",
    )
    # A scoped ETH generation preserves the untouched families' existing
    # host files. Seed empty private files exactly as an installed tree does.
    for filename in ("dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts", "dhcpd.conf"):
        (ztp / "config/isc-dhcp-server" / filename).write_bytes(b"")
    output = project / "99-output-eth"
    output.mkdir()
    link(ztp / "config/cumulus/template/99-output", output)
    (ztp / "config/cumulus/latest_yaml").symlink_to("template/99-output/latest")
    return project, ztp


def _artifact_tree(root: Path) -> dict[str, tuple[str, str]]:
    """Include file bytes and symlink destinations, not volatile directory mtimes."""
    result = {}
    for item in sorted(root.rglob("*")):
        relative = str(item.relative_to(root))
        if item.is_symlink():
            result[relative] = ("link", os.readlink(item))
        elif item.is_file():
            result[relative] = ("file", hashlib.sha256(item.read_bytes()).hexdigest())
        elif item.is_dir():
            result[relative] = ("dir", "")
        else:
            raise AssertionError(f"unexpected artifact type: {item}")
    return result


def _publish_private_dhcp_outputs(project: Path, ztp: Path) -> None:
    """Model setup's canonical project-owned five-output publication."""
    dhcp_dir = ztp / "config/isc-dhcp-server"
    project_dhcp = project / "99-output-dhcp"
    project_dhcp.mkdir()
    for name in DHCP_OUTPUTS:
        public_output = dhcp_dir / name
        project_output = project_dhcp / name
        shutil.copy2(public_output, project_output)
        public_output.unlink()
        public_output.symlink_to(os.path.relpath(project_output, dhcp_dir))


def _write_same_inode(path: Path, data: bytes, original: os.stat_result) -> None:
    descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        current = os.fstat(descriptor)
        if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
            raise AssertionError("mutation target must be a single-link regular file")
        if current.st_ino != original.st_ino or len(data) != original.st_size:
            raise AssertionError("A/B mutation must preserve inode and size")
        os.lseek(descriptor, 0, os.SEEK_SET)
        written = 0
        while written < len(data):
            written += os.write(descriptor, data[written:])
        os.ftruncate(descriptor, len(data))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns), follow_symlinks=False)
    after = path.stat()
    if (after.st_ino, after.st_size, after.st_mtime_ns) != (
        original.st_ino, original.st_size, original.st_mtime_ns,
    ):
        raise AssertionError("A/B mutation unexpectedly changed inode, size or mtime")


class GenerationInputBindingWorkflowTests(unittest.TestCase):
    """LOAD's frozen A authority must survive a real downstream c2 read."""

    def test_c2_crash_residue_blocks_real_publisher_base_fallback(self):
        """C2's cold gap cannot make d publish the unpatched base tree."""
        with tempfile.TemporaryDirectory(prefix="r22-c2-publisher-gap-") as name:
            output = Path(name) / "ztp/config/cumulus/template/99-output"
            output.mkdir(parents=True)
            timestamp = "20261002_120000"
            base = output / timestamp
            base.mkdir()
            (base / "Border01.yaml").write_bytes(b"base without descriptions\n")
            final = output / f"{timestamp}_with_desc"
            old = output / f".{final.name}.tmp.crash.old"
            stage = output / f".{final.name}.tmp.crash"
            old.mkdir()
            stage.mkdir()
            (old / "Border01.yaml").write_bytes(b"complete A descriptions\n")
            (stage / "Border01.yaml").write_bytes(b"incomplete B descriptions\n")
            before = _artifact_tree(output)

            inventory = C2._inspect_description_output_recovery(str(final))
            self.assertEqual("gap-after-old-rename", inventory["state"])
            self.assertEqual(str(old), inventory["old_candidate"])
            context = PUBLISHER._cumulus_dir_context(str(base))
            self.assertIsNotNone(context)
            with self.assertRaisesRegex(ValueError, "unresolved description"):
                PUBLISHER._preferred_cumulus_contexts([context])
            self.assertEqual(before, _artifact_tree(output))

    def test_real_nvos_scoped_generation_parent_remains_activatable(self):
        """Real IB/NVL generation must retain accepted empty unselected hosts."""
        private_parent = os.environ.get("R22_TEST_PRIVATE_ROOT")
        for selected in ("ib", "nvl"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory(
                prefix=f"r22-nvos-{selected}-activation-", dir=private_parent,
            ) as name:
                private = Path(name)

                class ScopedNVOSFlow(PLATFORM_FLOW.PlatformReleaseFlowTests):
                    selected_scope = selected

                    @classmethod
                    def _run_dhcp_generator(cls):
                        document = yaml.safe_load(cls.global_file.read_text(encoding="utf-8"))
                        document["common"]["mgmt"]["dhcp-server"] = {
                            "status": "enabled", "package": "isc-dhcp-server",
                        }
                        cls.global_file.write_text(
                            yaml.safe_dump(document, sort_keys=False), encoding="utf-8",
                        )
                        for filename in ("dhcpd_eth.hosts", "dhcpd_ib.hosts",
                                         "dhcpd_nvl.hosts", "dhcpd.conf"):
                            (cls.dhcp / filename).write_bytes(b"")
                        executed = []

                        def real_child(command, **_kwargs):
                            script = command[1]
                            executed.append((script, list(command[2:])))
                            if (command[command.index("--switch") + 1]
                                    != cls.selected_scope):
                                raise AssertionError((cls.selected_scope, command))
                            if (command[command.index("--deployment-scope") + 1]
                                    != "prod"):
                                raise AssertionError(command)
                            if script == "c1-generate_dhcp.py":
                                bindings = {
                                    "HTTP_ROOT": str(cls.root),
                                    "SCRIPT_DIR": str(cls.dhcp),
                                    "OUTPUT_ETH": str(cls.dhcp / "dhcpd_eth.hosts"),
                                    "OUTPUT_IB": str(cls.dhcp / "dhcpd_ib.hosts"),
                                    "OUTPUT_NVL": str(cls.dhcp / "dhcpd_nvl.hosts"),
                                    "OUTPUT_CONF": str(cls.dhcp / "dhcpd.conf"),
                                    "OUTPUT_MANIFEST": str(cls.dhcp / "dhcp-release-manifest.json"),
                                    "SUBNET_CSV": str(cls.dhcp / "02-subnet_config.csv"),
                                    "GLOBAL_YAML": str(cls.dhcp / "01-global.yaml"),
                                    "P2P_AIR_JSON": str(cls.dhcp / "p2p-air.json"),
                                    "DEVICES_CSV": str(cls.dhcp / "02-devices_config.csv"),
                                    "_AUTO_YES": False,
                                }
                                with mock.patch.multiple(PLATFORM_FLOW.DHCP, **bindings), \
                                        mock.patch.object(sys, "argv", list(command[1:])):
                                    PLATFORM_FLOW.DHCP.main()
                            elif script == "90-c2-generate_configs.py":
                                template = cls.nvos / "template"
                                ib_dir = template / f"99-output-ib_nvl/{PLATFORM_FLOW.TIMESTAMP}-ib"
                                nvl_dir = template / f"99-output-ib_nvl/{PLATFORM_FLOW.TIMESTAMP}-nvl"
                                with mock.patch.multiple(
                                    PLATFORM_FLOW.NVOS_GENERATOR,
                                    SCRIPT_DIR=str(template),
                                    _CSV_FILE=str(template / "02-devices_config.csv"),
                                    _GLOBAL_FILE=str(template / "01-global.yaml"),
                                    OUTPUT_IB_NVL_ROOT=str(template / "99-output-ib_nvl"),
                                    OUTPUT_IB_DIR=str(ib_dir),
                                    OUTPUT_NVL_DIR=str(nvl_dir),
                                ):
                                    generated = PLATFORM_FLOW.NVOS_GENERATOR._generate_all_ib(
                                        switch_scope=cls.selected_scope,
                                    )
                                if generated != 1:
                                    raise AssertionError((cls.selected_scope, generated))
                            elif script == "d-hostname2mac.py":
                                devices = PLATFORM_FLOW.PUBLISHER.load_csv(
                                    cls.devices_file, switch_scope=cls.selected_scope,
                                )
                                contexts = [
                                    PLATFORM_FLOW.PUBLISHER._nvos_dir_context(path)
                                    for path in command[2:]
                                    if str(path).endswith(f"-{cls.selected_scope}")
                                ]
                                if len(contexts) != 1:
                                    raise AssertionError((cls.selected_scope, command, contexts))
                                with mock.patch.object(PLATFORM_FLOW.PUBLISHER, "_AUTO_YES", True):
                                    published = PLATFORM_FLOW.PUBLISHER._publish_single_nvos(
                                        contexts[0], devices,
                                        deployment_scope="prod",
                                        switch_scope=cls.selected_scope,
                                    )
                                if not published:
                                    raise AssertionError("real scoped NVOS publisher rejected artifacts")
                            else:
                                raise AssertionError(f"unexpected real child: {command!r}")

                        with mock.patch.object(LOAD, "ZTP_DIR", cls.ztp), \
                                mock.patch.object(LOAD, "run", side_effect=real_child), \
                                redirect_stdout(io.StringIO()):
                            LOAD.generate_configs(
                                frozenset({cls.selected_scope}),
                                install_dhcp=False, dry_run=False, dhcp_enabled=True,
                                schema_version=1, deployment_scope="prod",
                                switch_scope=cls.selected_scope,
                            )
                        cls.executed = executed
                        _publish_private_dhcp_outputs(cls.project, cls.ztp)

                    @classmethod
                    def _run_cumulus_generator_and_publisher(cls, _p2p_output):
                        # A selected NVOS run does not execute Cumulus generation.
                        return None

                    @classmethod
                    def _run_nvos_generator_and_publisher(cls):
                        # Already executed by the real LOAD child dispatch above.
                        cls.nvos_release = (cls.nvos / "latest_yaml").resolve(strict=True)

                    @classmethod
                    def _run_parent_consumer(cls):
                        settings = LOAD.GlobalSettings(
                            dhcp_enabled=True, dhcp_package="isc-dhcp-server",
                            http_enabled=True, http_package="apache2",
                            http_root=cls.root, ztp_enabled=True,
                            ztp_prefix="/ztp", ztp_ips={"prod_oob": ("192.0.2.2",)},
                            versions={"cumulus": "5.16.4", "nvos": "25.02"},
                        )
                        inputs = LOAD.ProjectInputs(
                            global_file=cls.global_file, devices_file=cls.devices_file,
                            subnet_file=cls.subnet_file, p2p_file=cls.p2p_file,
                            device_types=frozenset({cls.selected_scope}),
                            pubkeys=(), settings=settings,
                            deployment_scope="prod",
                            switch_scope=cls.selected_scope,
                        )
                        with mock.patch.object(LOAD, "ZTP_DIR", cls.ztp):
                            LOAD.validate_dhcp_output_sources(LOAD.dhcp_file_mappings())
                            cls.parent = LOAD.validate_and_publish_release(
                                cls.project, inputs, publish=True,
                            )

                with redirect_stdout(io.StringIO()):
                    ScopedNVOSFlow._build_flow(private)
                self.assertEqual(
                    ["c1-generate_dhcp.py", "90-c2-generate_configs.py",
                     "d-hostname2mac.py"],
                    [script for script, _ in ScopedNVOSFlow.executed],
                )
                dhcp_dir = ScopedNVOSFlow.dhcp
                selected_hosts = dhcp_dir / f"dhcpd_{selected}.hosts"
                self.assertGreater(selected_hosts.stat().st_size, 0)
                for other in {"eth", "ib", "nvl"} - {selected}:
                    self.assertEqual(0, (dhcp_dir / f"dhcpd_{other}.hosts").stat().st_size)
                parent_path = ScopedNVOSFlow.project / "99-output-ztp/current-release.json"
                self.assertEqual(
                    ScopedNVOSFlow.parent["release_id"],
                    json.loads(parent_path.read_text())["release_id"],
                )
                settings = ACTIVATE.Settings(
                    http_root=private, project_name=ScopedNVOSFlow.project.name,
                    scope="prod", switch_scope=selected,
                )
                before = (_artifact_tree(ScopedNVOSFlow.project),
                          _artifact_tree(ScopedNVOSFlow.ztp))
                identity = ACTIVATE.validate_parent_release(settings, parent_path)
                self.assertEqual(before, (_artifact_tree(ScopedNVOSFlow.project),
                                          _artifact_tree(ScopedNVOSFlow.ztp)))
                self.assertEqual(
                    hashlib.sha256(parent_path.read_bytes()).hexdigest(),
                    identity["parent_release_sha256"],
                )

    def test_scoped_empty_dhcp_hosts_accepted_by_load_remain_activatable(self):
        """A LOAD-accepted zero-host family cannot invalidate its parent."""
        private_parent = os.environ.get("R22_TEST_PRIVATE_ROOT")
        with tempfile.TemporaryDirectory(
            prefix="r22-empty-host-activation-", dir=private_parent,
        ) as name:
            private = Path(name)
            project, ztp = _private_real_chain(private, "192.0.2.53")
            for relative in REAL_CHILD_SCRIPTS:
                self.assertEqual((ROOT / relative).read_bytes(),
                                 (private / relative).read_bytes())
            errors, warnings = SETUP._validate_v2_mlag_project(
                str(project / "01-global.yaml"),
                str(project / "02-devices_config.csv"),
            )
            self.assertEqual(([], []), (errors, warnings))
            args = SimpleNamespace(
                switch_scope="eth", deployment_scope="prod", p2p_file=None,
                no_upgrade=True, mini=None, ssh_dir=None, dry_run=True,
            )
            validated, _ = LOAD.validate_inputs(
                project, args, allow_management_key_generation=False,
                host_role="workstation",
            )
            self.assertEqual(frozenset({"eth"}), validated.device_types)

            original_subprocess = LOAD._run_subprocess
            executed = []

            def real_private_child(command, **kwargs):
                script = command[1] if len(command) > 1 else command[0]
                cwd = kwargs.get("cwd")
                self.assertIsNotNone(cwd)
                child_dir = Path(cwd).resolve(strict=True)
                self.assertTrue(child_dir.is_relative_to(private.resolve()), child_dir)
                self.assertIn(script, {Path(path).name for path in REAL_CHILD_SCRIPTS})
                self.assertTrue((child_dir / script).is_file())
                if not kwargs.get("capture_output"):
                    kwargs = {
                        **kwargs, "stdout": subprocess.PIPE,
                        "stderr": subprocess.STDOUT, "text": True,
                    }
                result = original_subprocess(command, timeout=120, **kwargs)
                executed.append((script, result.returncode))
                self.assertEqual(0, result.returncode, result.stdout)
                return result

            with (
                mock.patch.object(LOAD, "ZTP_DIR", ztp),
                mock.patch.object(LOAD, "_run_subprocess", side_effect=real_private_child),
                redirect_stdout(io.StringIO()),
            ):
                LOAD.generate_configs(
                    validated.device_types, install_dhcp=False, dry_run=False,
                    dhcp_enabled=True, schema_version=validated.settings.schema_version,
                    deployment_scope="prod", switch_scope="eth",
                    source_identities=validated.source_identities,
                )
                self.assertEqual(
                    [Path(path).name for path in REAL_CHILD_SCRIPTS],
                    [script for script, _ in executed],
                )
                _publish_private_dhcp_outputs(project, ztp)
                dhcp_dir = ztp / "config/isc-dhcp-server"
                self.assertEqual(
                    0, (dhcp_dir / "dhcpd_ib.hosts").stat().st_size,
                )
                self.assertEqual(
                    0, (dhcp_dir / "dhcpd_nvl.hosts").stat().st_size,
                )
                LOAD.validate_dhcp_output_sources(LOAD.dhcp_file_mappings())
                parent = LOAD.validate_and_publish_release(project, validated)

            parent_path = project / "99-output-ztp/current-release.json"
            self.assertEqual(parent["release_id"],
                             json.loads(parent_path.read_text())["release_id"])
            settings = ACTIVATE.Settings(
                http_root=private, project_name=project.name,
                scope="prod", switch_scope="eth",
            )
            before = (_artifact_tree(project), _artifact_tree(ztp))
            activation_error = None
            try:
                identity = ACTIVATE.validate_parent_release(settings, parent_path)
            except ACTIVATE.ActivationError as error:
                activation_error = str(error)
            self.assertEqual(before, (_artifact_tree(project), _artifact_tree(ztp)))
            self.assertIsNone(activation_error, activation_error)
            self.assertEqual(
                hashlib.sha256(parent_path.read_bytes()).hexdigest(),
                identity["parent_release_sha256"],
            )

    def test_real_load_child_chain_rejects_same_inode_global_aba_before_publisher(self):
        """A c2-only B read cannot publish B after LOAD validated A."""
        private_parent = os.environ.get("R22_TEST_PRIVATE_ROOT")
        with tempfile.TemporaryDirectory(
            prefix="r22-real-generation-", dir=private_parent,
        ) as name:
            # macOS may report /var for a /private/var subprocess cwd; the
            # candidate API deliberately requires one canonical project path.
            private = Path(name).resolve()
            project, ztp = _private_real_chain(
                private / "A", "192.0.2.53", http_enabled=True,
            )
            project_b, _ = _private_real_chain(
                private / "B", "192.0.2.54", http_enabled=True,
            )
            # Activation currently requires nonempty private includes even
            # when this scoped ETH run does not own IB/NVL.  Valid DHCP
            # comments model pre-existing, unchanged family files; c1 still
            # produces and hashes the complete five-output child receipt.
            for family in ("ib", "nvl"):
                (ztp / "config/isc-dhcp-server" / f"dhcpd_{family}.hosts").write_text(
                    "# no selected hosts for this family\n", encoding="utf-8",
                )
            for relative in REAL_CHILD_SCRIPTS:
                self.assertEqual(
                    (ROOT / relative).read_bytes(),
                    (private / "A" / relative).read_bytes(),
                )
            source = project / "01-global.yaml"
            bytes_a = source.read_bytes()
            bytes_b = (project_b / "01-global.yaml").read_bytes()
            self.assertNotEqual(bytes_a, bytes_b)
            self.assertEqual(len(bytes_a), len(bytes_b))
            self.assertIn(b"192.0.2.53", bytes_a)
            self.assertIn(b"192.0.2.54", bytes_b)

            args = SimpleNamespace(
                switch_scope="eth", deployment_scope="prod", p2p_file=None,
                no_upgrade=True, mini=None, ssh_dir=None, dry_run=True,
            )
            for candidate in (project, project_b):
                errors, warnings = SETUP._validate_v2_mlag_project(
                    str(candidate / "01-global.yaml"),
                    str(candidate / "02-devices_config.csv"),
                )
                self.assertEqual(([], []), (errors, warnings))
                validated, _ = LOAD.validate_inputs(
                    candidate, args, allow_management_key_generation=False,
                    host_role="workstation",
                )
                self.assertEqual(frozenset({"eth"}), validated.device_types)

            original_subprocess = LOAD._run_subprocess
            state = {
                "inject": False, "injected": False, "children": [],
                "post_c1_activation_error": None,
            }
            original = None
            transcript = io.StringIO()

            def real_private_child(command, **kwargs):
                script = command[1] if len(command) > 1 else command[0]
                cwd = kwargs.get("cwd")
                if cwd is None:
                    self.assertEqual("/usr/bin/ssh-keygen", command[0])
                    self.assertEqual("-l", command[1])
                else:
                    child_dir = Path(cwd).resolve()
                    self.assertTrue(child_dir.is_relative_to(private.resolve()), child_dir)
                    self.assertIn(script, {Path(path).name for path in REAL_CHILD_SCRIPTS})
                    self.assertTrue((child_dir / script).is_file())
                    if not kwargs.get("capture_output"):
                        kwargs = {
                            **kwargs, "stdout": subprocess.PIPE,
                            "stderr": subprocess.STDOUT, "text": True,
                        }
                is_c2 = script == "90-c2-generate_configs.py" and state["inject"]
                if is_c2:
                    self.assertFalse(state["injected"])
                    state["injected"] = True
                    _write_same_inode(source, bytes_b, original)
                started = time.monotonic()
                try:
                    result = original_subprocess(command, timeout=120, **kwargs)
                finally:
                    if is_c2:
                        _write_same_inode(source, bytes_a, original)
                state["children"].append((script, result.returncode))
                if cwd is not None and result.stdout:
                    transcript.write(result.stdout)
                if result.returncode and (
                    not state["inject"] or script == "c1-generate_dhcp.py"
                ):
                    self.fail(
                        f"real private child {script} exited {result.returncode}: "
                        f"{result.stdout!r}"
                    )
                if state["inject"] and script == "c1-generate_dhcp.py":
                    try:
                        ACTIVATE.validate_parent_release(settings, parent_path)
                    except ACTIVATE.ActivationError as error:
                        state["post_c1_activation_error"] = str(error)
                self.assertLess(time.monotonic() - started, 120)
                return result

            def run_chain(validated, *, dhcp_candidate_dir=None):
                candidate_options = (
                    {} if dhcp_candidate_dir is None
                    else {"dhcp_candidate_dir": dhcp_candidate_dir}
                )
                return LOAD.generate_configs(
                    validated.device_types, install_dhcp=False, dry_run=False,
                    dhcp_enabled=validated.settings.dhcp_enabled,
                    schema_version=validated.settings.schema_version,
                    deployment_scope="prod", switch_scope="eth",
                    source_identities=validated.source_identities,
                    **candidate_options,
                )

            with (
                mock.patch.object(LOAD, "ZTP_DIR", ztp),
                mock.patch.object(LOAD, "_run_subprocess", side_effect=real_private_child),
                redirect_stdout(transcript),
            ):
                validated_a, _ = LOAD.validate_inputs(
                    project, args, allow_management_key_generation=False,
                    host_role="workstation",
                )
                self.assertEqual(
                    hashlib.sha256(bytes_a).hexdigest(),
                    validated_a.source_identities["global"],
                )
                run_chain(validated_a)

                # Publish the real c1 child manifest through the same
                # project-owned path and canonical public link that Docker
                # activation requires.  No release JSON or hash is forged.
                dhcp_dir = ztp / "config/isc-dhcp-server"
                _publish_private_dhcp_outputs(project, ztp)
                parent = LOAD.validate_and_publish_release(project, validated_a)
                parent_path = project / "99-output-ztp/current-release.json"
                self.assertEqual(parent["release_id"],
                                 json.loads(parent_path.read_text())["release_id"])
                settings = ACTIVATE.Settings(
                    http_root=private / "A", project_name=project.name,
                    scope="prod", switch_scope="eth",
                )
                accepted_parent = ACTIVATE.validate_parent_release(
                    settings, parent_path,
                )
                self.assertEqual(
                    hashlib.sha256(parent_path.read_bytes()).hexdigest(),
                    accepted_parent["parent_release_sha256"],
                )
                # The same preflight LOAD now uses before any B generation
                # must migrate the already committed A while its source bytes
                # and published DHCP child are still independently verifiable.
                self.assertEqual(
                    f"generations/{parent['release_id']}",
                    LOAD.ensure_previous_generation_frozen(project),
                )
                committed_a = (
                    project / "99-output-ztp/generations" / parent["release_id"]
                )
                selector = project / "99-output-ztp/current"
                self.assertEqual(
                    parent["release_id"],
                    ACTIVATE.validate_pinned_generation(
                        settings, selector, expected_release_id=parent["release_id"],
                    )["release_id"],
                )
                # LOAD has selected A, so ACTIVATE's legacy flat-input writer
                # must not publish a runtime plan without binding that selector.
                with mock.patch.object(
                    ACTIVATE, "ensure_runtime_directories",
                ) as runtime_dirs, mock.patch.object(
                    ACTIVATE, "_atomic_write",
                ) as runtime_write:
                    with self.assertRaisesRegex(
                        ACTIVATE.ActivationError, "selector|generation",
                    ):
                        ACTIVATE.prepare_runtime(settings)
                runtime_dirs.assert_not_called()
                runtime_write.assert_not_called()
                frozen_global = committed_a / "inputs/global"
                original_global = frozen_global.read_bytes()
                frozen_global.write_bytes(b"other generation input\n")
                with self.assertRaisesRegex(ACTIVATE.ActivationError, "pinned input"):
                    ACTIVATE.validate_pinned_generation(
                        settings, selector, expected_release_id=parent["release_id"],
                    )
                frozen_global.write_bytes(original_global)

                # The prior release is a real successful publication, not a
                # same-timestamp c2 staging directory or a synthetic marker.
                latest = project / "99-output-eth/latest"
                prior_name = os.readlink(latest)
                prior_release = latest.parent / prior_name
                prior_state = _artifact_tree(prior_release)
                self.assertIn("Border01.yaml", prior_state)
                dhcp_dir = ztp / "config/isc-dhcp-server"
                dhcp_before = {
                    item: (dhcp_dir / item).read_bytes() for item in DHCP_OUTPUTS
                }
                boundary = int(time.time())
                while int(time.time()) == boundary:
                    time.sleep(0.025)

                original = source.stat()
                state["inject"] = True
                private_candidate = (
                    project / "99-output-dhcp" /
                    ".load-dhcp-candidate-0123456789abcdef"
                )
                private_candidate.mkdir(mode=0o700)
                validated_a, _ = LOAD.validate_inputs(
                    project, args, allow_management_key_generation=False,
                    host_role="workstation",
                )
                self.assertEqual(
                    hashlib.sha256(bytes_a).hexdigest(),
                    validated_a.source_identities["global"],
                )
                failure = None
                try:
                    run_chain(validated_a, dhcp_candidate_dir=private_candidate)
                except LOAD.LoadError as error:
                    failure = error

            self.assertTrue(state["injected"], state)
            self.assertEqual(
                parent["release_id"],
                ACTIVATE.validate_pinned_generation(
                    settings, selector, expected_release_id=parent["release_id"],
                )["release_id"],
            )
            self.assertEqual(
                (original.st_ino, original.st_size, original.st_mtime_ns),
                (source.stat().st_ino, source.stat().st_size, source.stat().st_mtime_ns),
            )
            self.assertEqual(bytes_a, source.read_bytes())
            final_name = os.readlink(latest)
            final_yaml = (latest / "Border01.yaml").read_bytes()
            dhcp_after = {item: (dhcp_dir / item).read_bytes() for item in DHCP_OUTPUTS}
            dhcp_changed = [
                key for key in DHCP_OUTPUTS if dhcp_before[key] != dhcp_after[key]
            ]
            detail = (
                f"children={state['children']!r}; prior={prior_name}; final={final_name}; "
                f"new YAML sha256={hashlib.sha256(final_yaml).hexdigest()}; "
                f"DHCP changed={dhcp_changed}; "
                f"post-c1 activation={state['post_c1_activation_error']!r}; "
                f"child output tail={transcript.getvalue()[-1000:]!r}"
            )
            with self.subTest("accepted parent survives completed c1 before c2"):
                self.assertIsNone(state["post_c1_activation_error"], detail)
            with self.subTest("refuse drift from validated A"):
                self.assertIsNotNone(failure, detail)
                self.assertRegex(
                    (str(failure) + transcript.getvalue()).lower(),
                    r"input|source|authority|drift|chang",
                )
            with self.subTest("latest remains the previously published release"):
                self.assertEqual(prior_name, final_name, detail)
            with self.subTest("prior published release bytes are untouched"):
                self.assertEqual(prior_state, _artifact_tree(prior_release), detail)
            with self.subTest("validated A never publishes B"):
                self.assertFalse(b"192.0.2.54" in final_yaml, detail)
            with self.subTest("refusal leaves five prior DHCP outputs untouched"):
                self.assertEqual([], dhcp_changed, detail)
            with self.subTest("c1 wrote private complete candidate before c2 refused B"):
                self.assertEqual(
                    set(DHCP_OUTPUTS),
                    {item.name for item in private_candidate.iterdir()}, detail,
                )
            # The actual LOAD child chain has left the previously committed A
            # selected.  A subsequent, independently legal B edit to the
            # mutable source must not be used when ACTIVATE observes A's plan.
            # This is read-only planning, not a service activation receipt.
            network_links = [{
                "ifindex": 4, "ifname": "eth0",
                "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                "address": "02:00:00:00:00:04", "operstate": "UP",
                "link_type": "ether",
            }]
            network_addresses = [{
                "ifindex": 4, "ifname": "eth0",
                "addr_info": [{
                    "family": "inet", "local": "192.0.2.20", "prefixlen": 24,
                    "scope": "global", "flags": [],
                    "valid_life_time": "forever",
                    "preferred_life_time": "forever",
                }],
            }]
            source.write_bytes(bytes_b)
            try:
                with mock.patch.object(
                    ACTIVATE, "capture_stable_network_snapshot",
                    return_value=(network_links, network_addresses),
                ):
                    _plan, _runtime, payload, _apache = (
                        ACTIVATE.observe_pinned_runtime(
                            settings, selector,
                            expected_release_id=parent["release_id"],
                        )
                    )
                self.assertEqual(parent["release_id"],
                                 payload["selected_generation_release_id"])
                self.assertEqual(
                    hashlib.sha256((committed_a / "inputs/subnet").read_bytes()).hexdigest(),
                    payload["subnet_sha256"],
                )
            finally:
                source.write_bytes(bytes_a)

    def test_load_setup_c2_rejects_same_inode_second_read_and_preserves_existing_same_name_output(self):
        rows_a = V2MlagSetupPreflightTests().pair()
        rows_b = copy.deepcopy(rows_a)
        rows_b[0][0] = "Border03"
        rows_b[1][0] = "Border04"
        with tempfile.TemporaryDirectory(prefix="r22-generation-workflow-") as name:
            private = Path(name)
            project_a = private / "project-a"
            project_b = private / "project-b"
            _write_legal_project(project_a, rows_a)
            _write_legal_project(project_b, rows_b)
            source = project_a / "02-devices_config.csv"
            bytes_a = source.read_bytes()
            bytes_b = (project_b / "02-devices_config.csv").read_bytes()
            self.assertNotEqual(bytes_a, bytes_b)
            self.assertEqual(len(bytes_a), len(bytes_b))

            # Both generations independently pass the actual setup validator.
            for project in (project_a, project_b):
                errors, warnings = SETUP._validate_v2_mlag_project(
                    str(project / "01-global.yaml"),
                    str(project / "02-devices_config.csv"),
                )
                self.assertEqual(([], []), (errors, warnings))

            args = SimpleNamespace(
                switch_scope="all", deployment_scope="prod", p2p_file=None,
                no_upgrade=True, mini=None, ssh_dir=None, dry_run=True,
            )
            inputs_a, images_a = LOAD.validate_inputs(
                project_a, args, allow_management_key_generation=False,
                host_role="workstation",
            )
            inputs_b, images_b = LOAD.validate_inputs(
                project_b, args, allow_management_key_generation=False,
                host_role="workstation",
            )
            self.assertEqual({}, images_a)
            self.assertEqual({}, images_b)
            self.assertEqual(frozenset({"eth"}), inputs_a.device_types)
            self.assertEqual(frozenset({"eth"}), inputs_b.device_types)
            self.assertEqual(
                hashlib.sha256(bytes_a).hexdigest(),
                inputs_a.source_identities["devices"],
            )
            self.assertEqual(
                hashlib.sha256(bytes_b).hexdigest(),
                inputs_b.source_identities["devices"],
            )

            dot = private / "fixture-lldpq.dot"
            dot.write_text("", encoding="utf-8")
            generation = private / "generation"
            generation.mkdir()
            (generation / "new-marker.txt").write_bytes(b"candidate-from-A")
            existing = private / "generation_with_desc"
            existing.mkdir()
            old_artifact = existing / "old-marker.txt"
            old_artifact.write_bytes(b"existing-same-name")
            initial = source.stat()
            real_copytree = C2.shutil.copytree
            observed = {"injected": False}

            def mutate_after_copy(src, dst, *copy_args, **copy_kwargs):
                result = real_copytree(src, dst, *copy_args, **copy_kwargs)
                source.write_bytes(bytes_b)
                os.utime(source, ns=(initial.st_atime_ns, initial.st_mtime_ns))
                changed = source.stat()
                observed.update({
                    "injected": True,
                    "same_inode": changed.st_ino == initial.st_ino,
                    "same_size": changed.st_size == initial.st_size,
                    "same_mtime": changed.st_mtime_ns == initial.st_mtime_ns,
                })
                return result

            transcript = io.StringIO()
            failure = None
            with (
                mock.patch.object(C2, "_CSV_FILE", str(source)),
                mock.patch.object(C2.shutil, "copytree", side_effect=mutate_after_copy),
                redirect_stdout(transcript),
            ):
                try:
                    C2._run_patch_descriptions(str(dot), str(generation))
                except Exception as error:
                    failure = error

            self.assertTrue(observed["injected"], observed)
            self.assertTrue(observed["same_inode"], observed)
            self.assertTrue(observed["same_size"], observed)
            self.assertTrue(observed["same_mtime"], observed)
            with self.subTest("refuse cross-generation input"):
                self.assertIsNotNone(
                    failure,
                    "c2 accepted project B after setup/load validated and bound A; "
                    f"actual c2 output was: {transcript.getvalue()!r}",
                )
                self.assertRegex(
                    str(failure).lower(), r"input|source|authority|drift|chang",
                )
            with self.subTest("preserve same-name existing output"):
                self.assertTrue(old_artifact.is_file())
                self.assertEqual(
                    b"existing-same-name", old_artifact.read_bytes(),
                )
                self.assertFalse((existing / "new-marker.txt").exists())


if __name__ == "__main__":
    unittest.main()
