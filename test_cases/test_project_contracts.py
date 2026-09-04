#!/usr/bin/env python3
"""Fast, read-only regression checks for cross-directory project contracts."""

from __future__ import annotations

import argparse
import csv
import contextlib
from datetime import date, timedelta
import gzip
import importlib.util
from importlib.machinery import SourceFileLoader
import ipaddress
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


class TemplateContractTests(unittest.TestCase):
    def test_extra_aaa_users_are_generic_and_reject_unsafe_names(self):
        generator = load_module(
            "generic_aaa_user_contract",
            ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
        )
        global_config = {
            "system": {"aaa": {"user": {
                "cumulus": {
                    "full-name": "cumulus,,,,",
                    "hashed-password": "'$6$existing'",
                },
                "ops-reader": {
                    "full-name": "Operations: read only #1",
                    "hashed-password": "$6$example",
                    "role": "nvue-monitor",
                },
            }}}
        }

        self.assertEqual(
            [{
                "username": "ops-reader",
                "full_name": "Operations: read only #1",
                "hashed_password": "$6$example",
                "role": "nvue-monitor",
            }],
            generator._extra_aaa_users(global_config),
        )

        malicious = {
            "system": {"aaa": {"user": {
                "cumulus": {"hashed-password": "'$6$existing'"},
                "bad-user:\n          injected": {
                    "hashed-password": "$6$example",
                    "role": "system-admin",
                },
            }}}
        }
        with self.assertRaisesRegex(ValueError, "AAA username"):
            generator._extra_aaa_users(malicious)

        templates = ROOT / "ztp/config/cumulus/template/03-templates-j2"
        device_templates = sorted(
            path for path in templates.glob("*.yaml.j2")
            if not path.name.startswith("_")
        )
        self.assertTrue(device_templates)
        for path in device_templates:
            source = path.read_text(encoding="utf-8")
            legacy_customer_user = "vision" + "bay"
            self.assertNotIn(legacy_customer_user, source.casefold(), path.name)
            self.assertIn("_extra_aaa_users.yaml.j2", source, path.name)

    def test_public_canonical_templates_are_locked_and_use_safe_examples(self):
        global_config = yaml.safe_load(
            (ROOT / "DAY0-Prepare/template/01-global.yaml").read_text(
                encoding="utf-8"
            )
        )
        switch_configs = {
            next(iter(entry)): next(iter(entry.values()))
            for entry in global_config["switches"]
        }
        # Cumulus Jinja templates emit this scalar verbatim.  The outer YAML
        # quotes therefore preserve inner quotes so the generated document
        # contains a literal locked-password value, not a YAML alias.
        self.assertEqual(
            "'*'",
            switch_configs["eth"]["system"]["aaa"]["user"]["cumulus"][
                "hashed-password"
            ],
        )
        generator = load_module(
            "public_template_password_contract",
            ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
        )
        source_template = (
            ROOT
            / "ztp/config/cumulus/template/03-templates-j2/oob-leaf.yaml.j2"
        ).read_text(encoding="utf-8")
        password_line = next(
            line.strip()
            for line in source_template.splitlines()
            if "g.system.aaa.user.cumulus['hashed-password']" in line
        )
        rendered_password = generator.build_env().from_string(
            password_line + "\n"
        ).render(g=switch_configs["eth"])
        self.assertEqual(
            "*", yaml.safe_load(rendered_password)["hashed-password"]
        )
        for switch_type in ("ib", "nvl"):
            self.assertEqual(
                "*",
                switch_configs[switch_type]["system"]["aaa"]["user"]["admin"][
                    "password"
                ],
            )

        documentation_networks = tuple(
            ipaddress.ip_network(cidr)
            for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
        )
        global_text = (ROOT / "DAY0-Prepare/template/01-global.yaml").read_text(
            encoding="utf-8"
        )
        global_addresses = {
            ipaddress.ip_address(value)
            for value in re.findall(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])", global_text)
        }
        self.assertTrue(global_addresses)
        self.assertTrue(
            all(any(address in network for network in documentation_networks)
                for address in global_addresses)
        )
        global_macs = re.findall(
            r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])",
            global_text,
        )
        vrr_base_mac = ":".join(("02", "00", "5e", "01", "00", "00"))
        self.assertTrue(global_macs)
        self.assertTrue(
            all(
                mac.lower().startswith("02:00:")
                or mac.lower() == vrr_base_mac
                for mac in global_macs
            )
        )
        self.assertEqual(
            1,
            sum(mac.lower() == vrr_base_mac for mac in global_macs),
            "the only non-synthetic MAC in the public template is the VRR base",
        )

        with (ROOT / "DAY0-Prepare/template/02-dhcp-subnet_config.csv").open(
            newline="", encoding="utf-8-sig"
        ) as stream:
            subnet_rows = list(csv.DictReader(stream))
        self.assertEqual(3, len(subnet_rows))
        for row in subnet_rows:
            for field in (
                "subnet", "range_start", "range_end", "routers", "ztp_service_ip"
            ):
                address = ipaddress.ip_address(row[field])
                self.assertTrue(
                    any(address in network for network in documentation_networks),
                    (row["shared_network"], field),
                )

        default_contracts = {
            ROOT / "ztp/config/cumulus/default.yaml": ("hashed-password", "cumulus"),
            ROOT / "ztp/config/cumulus/default_5.16.5.yaml": (
                "hashed-password", "cumulus"
            ),
            ROOT / "ztp/config/nvos/default.yaml": ("password", "admin"),
        }
        for path, (password_key, username) in default_contracts.items():
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            system = document[0]["set"]["system"]
            self.assertEqual("*", system["aaa"]["user"][username][password_key], path)
            self.assertEqual(
                {"1.1.1.1", "9.9.9.9"}, set(system["dns"]["server"]), path
            )
            self.assertEqual(
                {"time.cloudflare.com", "ntp.ubuntu.com"},
                set(system["ntp"]["server"]),
                path,
            )

        for key_path in (
            ROOT / "DAY0-Prepare/template/laptop.pub",
            ROOT / "DAY0-Prepare/template/mgmt-server.pub",
        ):
            self.assertEqual(b"", key_path.read_bytes(), key_path)
        binary_placeholders = list(
            (ROOT / "DAY0-Prepare/template").glob("*.bin")
        ) + [ROOT / "DAY0-Prepare/template/p2p.xlsx"]
        self.assertTrue(binary_placeholders)
        for placeholder in binary_placeholders:
            self.assertEqual(0, placeholder.stat().st_size, placeholder)

        for name in ("air-template.json", "air-template-no-oob.json"):
            air_text = (
                ROOT / "ztp/config/cumulus/template/P2P" / name
            ).read_text(encoding="utf-8")
            air_addresses = {
                ipaddress.ip_address(value)
                for value in re.findall(
                    r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])",
                    air_text,
                )
            }
            self.assertTrue(
                all(any(address in network for network in documentation_networks)
                    for address in air_addresses),
                name,
            )
            air_macs = re.findall(
                r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])",
                air_text,
            )
            self.assertTrue(air_macs, name)
            self.assertTrue(
                all(mac.lower().startswith("02:00:") for mac in air_macs), name
            )

    def test_infra_common_packages_include_jq(self):
        source = (ROOT / "infra/infra-setup.sh").read_text(encoding="utf-8")
        match = re.search(r"^common_packages=\(([^)]*)\)$", source, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertIn("jq", match.group(1).split())
        self.assertIn('"${common_packages[@]}"', source)

    def test_public_documentation_boundary_has_safe_entrypoints(self):
        public_paths = (
            ".github/README.md",
            "PUBLIC_REPOSITORY.md",
            "SECURITY.md",
        )
        for relative in public_paths:
            with self.subTest(relative=relative):
                path = ROOT / relative
                self.assertTrue(path.is_file(), relative)
                self.assertTrue(path.read_text(encoding="utf-8").strip(), relative)

        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        for relative in (
            "README.md", "USER_MANUAL.md", "DAY0-Prepare/README.md",
            "infra/README.md", "monitor/README.md", "tools/README.md",
        ):
            self.assertIn(f"/{relative}", ignore)

    def test_lldp_analyzer_source_is_deployable_but_runtime_outputs_are_not(self):
        contract = load_module(
            "project_contract_lldp_deploy", ROOT / "tools/project_contract.py",
        )
        self.assertTrue(contract.is_tools_deployable_file(
            "tools/lldp-analyze-tool/analyze_lldp.py"
        ))
        self.assertTrue(contract.is_tools_deployable_file(
            "tools/lldp-analyze-tool/build_report.py"
        ))
        self.assertFalse(contract.is_tools_deployable_file(
            "tools/lldp-analyze-tool/node_modules/pkg/index.js"
        ))
        self.assertFalse(contract.is_tools_deployable_file(
            "tools/ibdiagnet-analyze-tool/analyze.py"
        ))
        self.assertNotIn("lldp-analyze-tool/", contract.rsync_excludes())

    def test_readmes_are_excluded_from_sync_and_shared_transfer_contract(self):
        contract = load_module(
            "project_contract_readme_exclude", ROOT / "tools/project_contract.py",
        )
        sync = load_module("sync_code_readme_exclude", ROOT / "tools/sync-code.py")
        for relative in (
            "README.md",
            "DAY0-Prepare/project/README.txt",
            "tools/lldp-analyze-tool/readme.MD",
        ):
            with self.subTest(relative=relative):
                self.assertEqual(
                    "README documentation", contract.transfer_exclude_reason(relative),
                )
        self.assertFalse(contract.is_tools_deployable_file("tools/README.md"))
        self.assertFalse(contract.is_tools_deployable_file(
            "tools/lldp-analyze-tool/README.md"
        ))
        self.assertIn("[Rr][Ee][Aa][Dd][Mm][Ee]*", contract.rsync_excludes())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("excluded\n", encoding="utf-8")
            (root / "readme.txt").write_text("excluded\n", encoding="utf-8")
            (root / "guide.md").write_text("included\n", encoding="utf-8")
            selected = sync.matching_files(root, ("*.md", "*.txt"))
            self.assertEqual((root / "guide.md",), selected)

    def test_existing_project_is_completed_from_template_without_overwrite(self):
        load = load_module("day0_load_template_completion", ROOT / "DAY0-Prepare/11-load.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            template = root / "template"
            project = root / "project"
            (template / "p2p").mkdir(parents=True)
            (template / "empty-required.pub").touch()
            (template / "p2p/README.txt").write_text("guide\n", encoding="utf-8")
            project.mkdir()
            (project / "customer.txt").write_text("keep\n", encoding="utf-8")
            original = load.TEMPLATE_DIR
            try:
                load.TEMPLATE_DIR = template
                with contextlib.redirect_stdout(io.StringIO()):
                    load.initialize_from_template(project)
            finally:
                load.TEMPLATE_DIR = original
            self.assertEqual("keep\n", (project / "customer.txt").read_text(encoding="utf-8"))
            self.assertTrue((project / "empty-required.pub").is_file())
            self.assertEqual(0, (project / "empty-required.pub").stat().st_size)
            self.assertTrue((project / "p2p").is_dir())

    def test_existing_project_template_dry_run_is_not_reported_as_creation(self):
        load = load_module("day0_load_template_dry_run_log", ROOT / "DAY0-Prepare/11-load.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            template = root / "template"
            project = root / "project"
            template.mkdir()
            (template / "required.txt").write_text("template\n", encoding="utf-8")
            project.mkdir()
            (project / "customer.txt").write_text("keep\n", encoding="utf-8")
            original = load.TEMPLATE_DIR
            output = io.StringIO()
            try:
                load.TEMPLATE_DIR = template
                with contextlib.redirect_stdout(output):
                    load.initialize_from_template(project, dry_run=True)
            finally:
                load.TEMPLATE_DIR = original
            self.assertIn("[SYNC]", output.getvalue())
            self.assertNotIn("创建项目模板", output.getvalue())
            self.assertFalse((project / "required.txt").exists())

    def test_empty_project_template_dry_run_reports_future_creation(self):
        load = load_module("day0_load_empty_template_dry_run_log", ROOT / "DAY0-Prepare/11-load.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            template = root / "template"
            project = root / "new-project"
            template.mkdir()
            (template / "required.txt").write_text("template\n", encoding="utf-8")
            original_here = load.HERE
            original_template = load.TEMPLATE_DIR
            output = io.StringIO()
            try:
                load.HERE = root
                load.TEMPLATE_DIR = template
                with contextlib.redirect_stdout(output):
                    result = load.main([str(project), "--dry-run"])
            finally:
                load.HERE = original_here
                load.TEMPLATE_DIR = original_template
            self.assertEqual(2, result)
            self.assertIn("dry-run：实际执行时将创建项目模板", output.getvalue())
            self.assertNotIn("项目模板已创建。", output.getvalue())
            self.assertFalse(project.exists())

    def test_latest_versioned_p2p_becomes_stable_root_link(self):
        setup = load_module("day0_setup_versioned_p2p", ROOT / "DAY0-Prepare/01-a-setup.py")
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            versions = project / "p2p"
            versions.mkdir()
            older = versions / "Customer-P2P-v1.xlsx"
            newer = versions / "Customer-P2P-v2.xlsx"
            older.write_bytes(b"old")
            newer.write_bytes(b"new")
            os.utime(older, (100, 100))
            os.utime(newer, (200, 200))
            (project / "p2p.xlsx").touch()
            old_explicit, old_dry = setup._P2P_FILE, setup._DRY_RUN
            try:
                setup._P2P_FILE = None
                setup._DRY_RUN = False
                selected = setup._select_p2p_source(str(project))
                canonical = setup._ensure_project_p2p_link(str(project), selected)
            finally:
                setup._P2P_FILE, setup._DRY_RUN = old_explicit, old_dry
            self.assertEqual(newer, Path(selected))
            self.assertEqual(project / "p2p.xlsx", Path(canonical))
            self.assertTrue((project / "p2p.xlsx").is_symlink())
            self.assertEqual(newer.resolve(), (project / "p2p.xlsx").resolve())

    def test_project_p2p_link_is_inside_setup_transaction(self):
        setup = load_module("day0_setup_p2p_transaction", ROOT / "DAY0-Prepare/01-a-setup.py")
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            self.assertIn(
                str(project / "p2p.xlsx"),
                setup._setup_transaction_paths(str(project)),
            )

    def test_load_passes_nested_p2p_path_to_setup(self):
        load = load_module("day0_load_nested_p2p", ROOT / "DAY0-Prepare/11-load.py")
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(load, "run") as run:
            project = Path(directory) / "project"
            p2p = project / "p2p/Customer-P2P-v2.xlsx"
            p2p.parent.mkdir(parents=True)
            p2p.touch()
            with mock.patch.object(load, "active_project", side_effect=[None, project]):
                load.activate_project(project, p2p)
            command = run.call_args.args[0]
            self.assertIn("--p2p-file=p2p/Customer-P2P-v2.xlsx", command)

    def test_load_has_no_entry_dependency_gate_before_auto_infra(self):
        source = (ROOT / "DAY0-Prepare/11-load.py").read_text(encoding="utf-8")
        self.assertNotIn("preflight_runtime_dependencies", source)
        self.assertNotIn("infra_recovery_command", source)
        self.assertNotIn("缺少 load 运行依赖", source)
        self.assertNotIn("load 运行依赖检查", source)

    def test_upload_apps_policy_is_explicit_for_noninteractive_uploads(self):
        upload = load_module("tar_upload_apps_policy", ROOT / "tools/tar-for-upload.py")
        args = argparse.Namespace(
            include_apps=None, dry_run=False, target_os=None, target_arch=None,
        )
        with mock.patch.object(upload.sys.stdin, "isatty", return_value=False):
            with self.assertRaisesRegex(ValueError, "--include-apps"):
                upload.resolve_apps_policy(args)
        args = argparse.Namespace(
            include_apps=None, dry_run=True, target_os=None, target_arch=None,
        )
        with contextlib.redirect_stdout(io.StringIO()):
            upload.resolve_apps_policy(args)
        self.assertFalse(args.include_apps)

    def test_upload_offline_repository_must_match_target_platform(self):
        upload = load_module("tar_upload_platform_policy", ROOT / "tools/tar-for-upload.py")
        args = argparse.Namespace(
            include_apps=True, dry_run=False,
            target_os="ubuntu-22.04", target_arch="amd64",
        )
        with self.assertRaisesRegex(ValueError, "ubuntu-22.04/amd64/Packages.gz"):
            upload.resolve_apps_policy(args)

    def test_upload_rejects_broken_offline_repository_index(self):
        upload = load_module("tar_upload_repo_validation", ROOT / "tools/tar-for-upload.py")
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            with gzip.open(repository / "Packages.gz", "wt", encoding="utf-8") as stream:
                stream.write(
                    "Package: example\nVersion: 1\nArchitecture: amd64\n"
                    "Filename: ./missing.deb\n\n"
                )
            with self.assertRaisesRegex(ValueError, "missing.deb"):
                upload.validate_flat_apt_repository(
                    repository, "ubuntu-24.04/amd64"
                )

    def test_upload_extra_client_platform_requires_offline_apps(self):
        upload = load_module("tar_upload_extra_platform", ROOT / "tools/tar-for-upload.py")
        args = argparse.Namespace(
            include_apps=False, dry_run=False, target_os=None, target_arch=None,
            client_platform=["ubuntu-24.04/arm64"],
        )
        with self.assertRaisesRegex(ValueError, "--client-platform"):
            upload.resolve_apps_policy(args)

    def test_upload_rejects_repository_metadata_for_wrong_os(self):
        upload = load_module("tar_upload_repo_metadata", ROOT / "tools/tar-for-upload.py")
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            stanzas = []
            for package in sorted(upload.REQUIRED_OFFLINE_PACKAGES):
                filename = f"{package}.deb"
                (repository / filename).touch()
                stanzas.append(
                    f"Package: {package}\nVersion: 1\nArchitecture: amd64\n"
                    f"Filename: ./{filename}\n"
                )
            with gzip.open(repository / "Packages.gz", "wt", encoding="utf-8") as stream:
                stream.write("\n".join(stanzas))
            (repository / "repository.meta").write_text(
                "schema_version=1\nos_id=ubuntu\nos_version=22.04\n"
                "architecture=amd64\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "os_version=22.04"):
                upload.validate_flat_apt_repository(
                    repository, "ubuntu-24.04/amd64"
                )

    def test_upload_offline_repository_needs_only_flat_apt_repository(self):
        upload = load_module("tar_upload_no_npm_cache", ROOT / "tools/tar-for-upload.py")
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            stanzas = []
            for package in sorted(upload.REQUIRED_OFFLINE_PACKAGES):
                filename = f"{package}.deb"
                (repository / filename).touch()
                stanzas.append(
                    f"Package: {package}\nVersion: 1\nArchitecture: amd64\n"
                    f"Filename: ./{filename}\n"
                )
            with gzip.open(repository / "Packages.gz", "wt", encoding="utf-8") as stream:
                stream.write("\n".join(stanzas))
            (repository / "repository.meta").write_text(
                "schema_version=1\nos_id=ubuntu\nos_version=24.04\n"
                "architecture=amd64\n",
                encoding="utf-8",
            )
            upload.validate_flat_apt_repository(repository, "ubuntu-24.04/amd64")

    def test_load_auto_infra_precedes_configuration_generation(self):
        source = (ROOT / "DAY0-Prepare/11-load.py").read_text(encoding="utf-8")
        main = source.split("def main(", 1)[1]
        self.assertLess(main.index("prepare_infra("), main.index("generate_configs("))
        self.assertIn('"bash", str(INFRA_DIR / "infra-setup.sh"), "--mgmt"', source)

    def test_all_cumulus_lacp_templates_enable_bypass(self):
        templates = ROOT / "ztp/config/cumulus/template/03-templates-j2"
        lacp_templates = []
        for path in sorted(templates.glob("*.yaml.j2")):
            content = path.read_text(encoding="utf-8")
            if "mode: lacp" not in content:
                continue
            lacp_templates.append(path.name)
            self.assertIn(
                "lacp-bypass: enabled",
                content,
                f"{path.name} generates LACP bonds without enabling bypass",
            )
        self.assertTrue(lacp_templates)

    def test_dhcp_shared_network_names_are_unique(self):
        path = ROOT / "DAY0-Prepare/template/02-dhcp-subnet_config.csv"
        with path.open(newline="", encoding="utf-8-sig") as stream:
            names = [row["shared_network"].strip() for row in csv.DictReader(stream)]
        self.assertTrue(all(names))
        self.assertEqual(len(names), len(set(names)))

    def test_all_runtime_output_skeletons_exist(self):
        template = ROOT / "DAY0-Prepare/template"
        expected = {
            "99-output-backup", "99-output-dhcp", "99-output-eth",
            "99-output-ib_nvl", "99-output-monitor", "99-output-p2p",
            "99-output-ztp",
        }
        self.assertEqual(expected, {p.name for p in template.glob("99-output-*") if p.is_dir()})
        for directory in expected:
            self.assertTrue((template / directory / ".gitkeep").is_file(), directory)
        for directory in (
            "ndr-upgrade-logs",
            "xdr-initial-setup-logs",
            "xdr-upgrade-logs",
        ):
            self.assertTrue(
                (
                    template
                    / "99-output-ib_nvl/bringup"
                    / directory
                    / ".gitkeep"
                ).is_file(),
                directory,
            )

    def test_monitor_global_is_setup_managed(self):
        setup = load_module("day0_setup_contract", ROOT / "DAY0-Prepare/01-a-setup.py")
        mappings = {(workspace, project) for workspace, project, _ in setup.WORKSPACE_INPUT_MAPPINGS}
        self.assertIn(("monitor/01-global.yaml", "01-global.yaml"), mappings)

    def test_separate_air_inventory_is_fully_retired(self):
        self.assertEqual([], list(ROOT.rglob("02-AIR-devices_config.csv")))
        setup = load_module("day0_setup_unified_inventory", ROOT / "DAY0-Prepare/01-a-setup.py")
        serialized = repr(setup.WORKSPACE_INPUT_MAPPINGS) + repr(setup.MAPPINGS)
        self.assertNotIn("02-AIR-devices_config.csv", serialized)

    def test_ztp_monitor_requires_reachable_environment(self):
        load = load_module("day0_load_ztp_scope", ROOT / "DAY0-Prepare/11-load.py")
        monitor = load_module("day0_ztp_monitor_scope", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        header = (
            "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,"
            "eth1_ip,netmask,eth1_gw,eth1_mac\n"
        )
        rows = (
            "EXAMPLE-Leaf01,eth,oob,192.0.2.11,24,192.0.2.1,02:00:00:00:00:11,,,,\n"
            "EXAMPLE-IB01,ib,NA,192.0.2.12,24,192.0.2.1,02:00:00:00:00:12,,,,\n"
            "AIR-EXAMPLE-Leaf01,air,oob,192.0.2.11,24,192.0.2.1,02:00:00:00:01:11,,,,\n"
            "AIR-EXAMPLE-Leaf02,air,oob,192.0.2.13,24,192.0.2.1,02:00:00:00:01:13,,,,\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            inventory = project / "02-devices_config.csv"
            inventory.write_text(header + rows, encoding="utf-8")
            self.assertEqual(
                "air", load.resolve_ztp_monitor_scope(
                    project, "auto", prompt_fn=lambda _: "AIR"
                )
            )
            self.assertEqual("prod", load.resolve_ztp_monitor_scope(project, "prod"))
            read = lambda scope: monitor.read_devices(
                inventory, scope, air_json=project / "missing-air.json",
                dhcp_leases=None,
            )
            self.assertEqual(4, len(read("all")))
            self.assertEqual(2, len(read("prod")))
            self.assertEqual(2, len(read("air")))

            self.assertEqual("air", monitor.parser().parse_args([str(project), "--air"]).scope)
            self.assertEqual("prod", monitor.parser().parse_args([str(project), "--prod"]).scope)
            self.assertEqual(
                "air", monitor.parser().parse_args([str(project), "--type", "air"]).scope
            )
            self.assertEqual("air", load.parse_args([str(project), "--air"]).ztp_monitor_scope)
            self.assertEqual("prod", load.parse_args([str(project), "--prod"]).ztp_monitor_scope)
            self.assertEqual(
                "prod", load.parse_args([str(project), "--type", "prod"]).ztp_monitor_scope
            )

    def test_air_only_topology_nodes_join_active_dhcp_lease_and_ack(self):
        resolver = load_module(
            "dynamic_air_inventory_contract", ROOT / "ztp/dynamic_air_inventory.py",
        )
        monitor = load_module(
            "day0_dynamic_air_monitor", ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        manual = load_module(
            "manual_dynamic_air_contract", ROOT / "ztp/manual-ztp.py",
        )
        backup = load_module(
            "backup_dynamic_air_contract", ROOT / "ztp/backup/yaml-collect.py",
        )
        html = load_module(
            "monitor_dynamic_air_contract", ROOT / "monitor/generate-monitor-html.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            inventory = project / "02-devices_config.csv"
            inventory.write_text(
                "hostname,type,template,eth0_ip,netmask,eth0_mac\n"
                "AIR-EXAMPLE-Leaf01,air,oob-leaf,192.0.2.10,24,02:00:00:00:00:10\n",
                encoding="utf-8",
            )
            output = project / "99-output-p2p"
            output.mkdir()
            air_json = output / "sample-air.json"
            air_json.write_text(json.dumps({"content": {"nodes": {
                "AIR-EXAMPLE-Leaf01": {
                    "os": "cumulus-vx-5.16.4",
                    "management_interfaces": {"eth0": {
                        "mac_address": "02:00:00:00:00:10",
                    }},
                },
                "AIR-EXAMPLE-FW01": {
                    "os": "cumulus-vx-5.16.4",
                    "management_interfaces": {"eth0": {
                        "mac_address": "02:00:00:00:00:21",
                    }},
                },
                "AIR-EXAMPLE-FW02": {
                    "os": "cumulus-vx-5.16.4",
                    "management_interfaces": {"eth0": {
                        "mac_address": "02:00:00:00:00:22",
                    }},
                },
                "AIR-EXAMPLE-host": {
                    "os": "ubuntu-24.04",
                    "management_interfaces": {"eth0": {
                        "mac_address": "02:00:00:00:00:23",
                    }},
                },
            }}}), encoding="utf-8")
            leases = project / "dhcpd.leases"
            leases.write_text(
                "lease 192.0.2.20 {\n"
                "  binding state active;\n"
                "  hardware ethernet 02:00:00:00:00:21;\n"
                "  }\n"
                "lease 192.0.2.20 {\n"
                "  binding state free;\n"
                "  hardware ethernet 02:00:00:00:00:21;\n"
                "  }\n"
                "lease 192.0.2.21 {\n"
                "  binding state active;\n"
                "  hardware ethernet 02:00:00:00:00:21;\n"
                "  }\n",
                encoding="utf-8",
            )

            dynamic = resolver.dynamic_air_devices(inventory, leases=leases)
            self.assertEqual(["AIR-EXAMPLE-FW01", "AIR-EXAMPLE-FW02"], [d["hostname"] for d in dynamic])
            self.assertEqual("192.0.2.21", dynamic[0]["ip"])
            self.assertEqual("fw", dynamic[0]["template"])
            self.assertEqual("", dynamic[1]["ip"])

            devices = monitor.read_devices(inventory, "air", dhcp_leases=leases)
            self.assertEqual(3, len(devices))
            fw = {device["hostname"]: device for device in devices if device.get("dynamic_dhcp")}
            self.assertEqual(["192.0.2.21"], fw["AIR-EXAMPLE-FW01"]["ssh_ips"])
            self.assertEqual([], fw["AIR-EXAMPLE-FW02"]["ssh_ips"])
            events = monitor.parse_dhcp(
                "2026-08-30T17:00:00+08:00 DHCPACK on 192.0.2.22 "
                "to 02:00:00:00:00:22 via eth0\n"
            )
            monitor.apply_dynamic_dhcp_addresses(devices, events)
            self.assertEqual("192.0.2.22", fw["AIR-EXAMPLE-FW02"]["ip"])
            self.assertEqual("dhcp-event", fw["AIR-EXAMPLE-FW02"]["address_source"])

            manual_devices = manual.read_devices(inventory, dhcp_leases=leases)
            manual_fw = {
                device["hostname"]: device
                for device in manual_devices if device.get("dynamic_dhcp")
            }
            self.assertEqual([("192.0.2.21", "eth0")], manual_fw["AIR-EXAMPLE-FW01"]["candidates"])
            self.assertEqual([], manual_fw["AIR-EXAMPLE-FW02"]["candidates"])
            (project / "02-dhcp-subnet_config.csv").write_text(
                "shared_network,subnet,netmask,range_start,range_end,routers,"
                "ztp_service_ip,cumulus_profile,nvos_ztp\n",
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = manual.main([
                    "-p", str(project), "--dhcp-leases", str(leases),
                    "--dry-run", "AIR-EXAMPLE-FW02",
                ])
            self.assertEqual(2, rc)
            self.assertIn("尚无可用 SSH 地址", stderr.getvalue())
            self.assertNotIn("没有匹配", stderr.getvalue())

            runner = project / "runner"
            runner.mkdir()
            inventory_link = runner / "02-devices_config.csv"
            inventory_link.symlink_to(inventory)
            backup_devices, backup_warnings = backup.load_dynamic_air_backup_devices(
                inventory_link, leases,
            )
            self.assertEqual(["AIR-EXAMPLE-FW01"], [d["hostname"] for d in backup_devices])
            self.assertTrue(backup_devices[0]["dynamic_dhcp"])
            self.assertTrue(any("AIR-EXAMPLE-FW02" in warning for warning in backup_warnings))

            report_dir = project / "ztp-status" / "20260830_170000"
            report_dir.mkdir(parents=True)
            (report_dir / "report.json").write_text(json.dumps({
                "project": "dynamic", "generated_at": "2026-08-30T17:00:00+08:00",
                "devices": [{
                    "hostname": "AIR-EXAMPLE-FW01", "type": "air", "template": "fw",
                    "ip": "192.0.2.21", "mac": "02:00:00:00:00:21",
                    "dynamic_dhcp": True, "address_source": "dhcp-lease",
                    "stages": {}, "overall": "warning", "issues": [],
                }],
            }), encoding="utf-8")
            status = html.load_ztp_status(report_dir.parent, inventory, scope="air")
            self.assertEqual(1, len(status["devices"]), status)
            current_dynamic = status["devices"][0]
            self.assertTrue(current_dynamic["dynamic_dhcp"])
            self.assertNotIn("promotion_pending", current_dynamic)

    def test_unbound_dhcp_platforms_are_split_into_managed_and_manual_flows(self):
        runtime = load_module(
            "dhcp_runtime_inventory_contract", ROOT / "ztp/dhcp_runtime_inventory.py",
        )
        monitor = load_module(
            "day0_unbound_dhcp_monitor", ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        html = load_module(
            "monitor_unbound_dhcp_contract", ROOT / "monitor/generate-monitor-html.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / "02-devices_config.csv"
            inventory.write_text(
                "hostname,type,template,eth0_ip,netmask,eth0_mac\n"
                "EXAMPLE-Leaf01,eth,leaf,192.0.2.10,24,02:00:00:00:00:10\n",
                encoding="utf-8",
            )
            leases = root / "dhcpd.leases"
            leases.write_text(
                "lease 192.0.2.21 {\n"
                "  starts 3 2026/08/30 12:00:00;\n"
                "  ends 3 2099/08/30 13:00:00;\n"
                "  binding state active;\n"
                "  hardware ethernet 02:00:00:00:00:21;\n}\n"
                "lease 192.0.2.22 {\n"
                "  starts 3 2026/08/30 12:00:00;\n"
                "  ends 3 2099/08/30 13:00:00;\n"
                "  binding state active;\n"
                "  hardware ethernet 02:00:00:00:00:22;\n}\n",
                encoding="utf-8",
            )
            journal = (
                "2026-08-30T20:00:00+08:00 dhcpd ZTP_DHCP_EVENT_V1 "
                "event=packet msg=DHCPDISCOVER mac=02:00:00:00:00:21 ip=- "
                "known=0 vendor60_hex=43:75:6d:75:6c:75:73 "
                "client61_hex=- user77_hex=-\n"
                "2026-08-30T20:00:01+08:00 dhcpd ZTP_DHCP_EVENT_V1 "
                "event=packet msg=DHCPDISCOVER mac=02:00:00:00:00:22 ip=- "
                "known=0 vendor60_hex=- client61_hex=- user77_hex=-\n"
            )

            discovered = runtime.unknown_dhcp_devices(
                journal_text=journal, lease_path=leases, inventory_path=inventory,
            )
            self.assertEqual(["cumulus", "unknown"], sorted(
                item["platform"] for item in discovered
            ))
            devices = monitor.runtime_unknown_devices(
                inventory, journal, scope="prod", dhcp_leases=leases,
            )
            by_platform = {device["platform_family"]: device for device in devices}
            managed = by_platform["cumulus"]
            unknown = by_platform["unknown"]
            self.assertTrue(managed["managed_ztp"])
            self.assertTrue(managed["ssh_collect_enabled"])
            self.assertEqual("pending_eth", managed["type"])
            self.assertEqual("192.0.2.21", managed["ip"])
            self.assertFalse(unknown["managed_ztp"])
            self.assertFalse(unknown["ssh_collect_enabled"])
            self.assertEqual("unknown", unknown["type"])

            monitor.analyze_switch(managed, {
                "kind": "ok", "connected_ip": "192.0.2.21", "attempts": [],
                "remote_hostname": "cumulus",
                "remote_eth0_mac": "02:00:00:00:00:21",
                "boot_id": "boot-1", "boot_time": "1",
                "ztp_log": (
                    "[2026-08-30 20:00:02] [ZTP] ZTP START\n"
                    "[2026-08-30 20:00:03] [ZTP] MAC cfg not found, load default cfg\n"
                    "[2026-08-30 20:00:04] [ZTP] Default config:default.yaml patch and save complete\n"
                    "[2026-08-30 20:00:05] [ZTP] SSH public key installed: mgmt-server.pub\n"
                    "[2026-08-30 20:00:06] [ZTP] Cumulus provision complete\n"
                    "======================== ZTP FINISH ========================\n"
                ),
                "ifreload_log": "", "failed_yaml": "", "stderr": "",
                "host_key_refreshed": False,
            })
            self.assertTrue(managed["access_ready"])
            self.assertEqual("success", managed["stages"]["ssh"]["status"])
            self.assertEqual("success", managed["stages"]["ssh_keys"]["status"])
            managed["ztp_round"] = 1
            for stage_value in managed["stages"].values():
                if stage_value["status"] in {"success", "warning"}:
                    stage_value["success_index"] = 1
            monitor.finalize_device(managed)
            unknown["ztp_round"] = 1
            unknown["stages"]["dhcp"]["success_index"] = 1
            monitor.finalize_device(unknown)
            rendered = html.render_ztp_status_rows({
                "available": True,
                "generated_at": "2026-08-30T20:00:10+08:00",
                "devices": [managed, unknown],
            })
            self.assertIn('data-group="production__other"', rendered)
            self.assertIn('ztp-success ztp-dhcp-dynamic">成功1', rendered)
            self.assertIn("DHCP 重新获取（先绑定）", rendered)
            self.assertIn("需要人工识别", rendered)

            inventory.write_text(
                "hostname,type,template,eth0_ip,netmask,eth0_mac\n"
                "EXAMPLE-Leaf01,eth,leaf,192.0.2.10,24,02:00:00:00:00:10\n"
                "EXAMPLE-Leaf02,eth,leaf,192.0.2.30,24,02:00:00:00:00:21\n",
                encoding="utf-8",
            )
            remaining = runtime.unknown_dhcp_devices(
                journal_text=journal, lease_path=leases, inventory_path=inventory,
            )
            self.assertEqual(["02:00:00:00:00:22"], [item["mac"] for item in remaining])
            static_devices = monitor.read_devices(
                inventory, "prod", dhcp_leases=leases,
            )
            monitor.apply_static_runtime_lease_fallbacks(
                static_devices, inventory, journal, dhcp_leases=leases,
            )
            leaf02 = next(
                device for device in static_devices if device["hostname"] == "EXAMPLE-Leaf02"
            )
            self.assertIn("192.0.2.21", leaf02["dynamic_lease_ips"])
            self.assertTrue(leaf02["promotion_pending"])
            migrated = monitor.merge_previous_unbound_identities({
                "devices": [{
                    "hostname": "DISCOVERED-CUMULUS-000021",
                    "type": "pending_eth", "mac": "02:00:00:00:00:21",
                    "dynamic_dhcp": True, "unbound_identity": True,
                    "stages": {},
                }],
            }, static_devices)
            self.assertEqual("EXAMPLE-Leaf02", migrated["devices"][0]["hostname"])
            self.assertTrue(migrated["devices"][0]["promotion_pending"])

    def test_dynamic_air_device_promotes_by_mac_and_keeps_old_lease_as_transition(self):
        resolver = load_module(
            "dynamic_air_promotion_contract", ROOT / "ztp/dynamic_air_inventory.py",
        )
        monitor = load_module(
            "day0_dynamic_air_promotion", ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        manual = load_module(
            "manual_dynamic_air_promotion", ROOT / "ztp/manual-ztp.py",
        )
        backup = load_module(
            "backup_dynamic_air_promotion", ROOT / "ztp/backup/yaml-collect.py",
        )
        html = load_module(
            "monitor_dynamic_air_promotion", ROOT / "monitor/generate-monitor-html.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            inventory = project / "02-devices_config.csv"
            inventory.write_text(
                "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,"
                "eth1_ip,netmask,eth1_gw,eth1_mac\n"
                "AIR-EXAMPLE-Canonical-Border01,air,border,192.0.2.30,24,192.0.2.1,"
                "02:00:00:00:00:21,,,,\n",
                encoding="utf-8",
            )
            output = project / "99-output-p2p"
            output.mkdir()
            (output / "sample-air.json").write_text(json.dumps({"content": {"nodes": {
                # The topology still carries the pre-promotion alias.  MAC is
                # the physical identity and must suppress a duplicate row.
                "AIR-EXAMPLE-Old-FW01": {
                    "os": "cumulus-vx-5.16.4",
                    "management_interfaces": {"eth0": {
                        "mac_address": "02:00:00:00:00:21",
                    }},
                },
            }}}), encoding="utf-8")
            leases = project / "dhcpd.leases"
            leases.write_text(
                "lease 192.0.2.21 {\n"
                "  binding state active;\n"
                "  hardware ethernet 02:00:00:00:00:21;\n"
                "  }\n",
                encoding="utf-8",
            )

            self.assertEqual([], resolver.dynamic_air_devices(inventory, leases=leases))
            transitions = resolver.static_air_lease_fallbacks(inventory, leases=leases)
            self.assertEqual(1, len(transitions))
            self.assertEqual("AIR-EXAMPLE-Canonical-Border01", transitions[0]["hostname"])
            self.assertEqual("192.0.2.21", transitions[0]["ip"])
            self.assertEqual("192.0.2.30", transitions[0]["configured_ip"])

            devices = monitor.read_devices(inventory, "air", dhcp_leases=leases)
            self.assertEqual(1, len(devices))
            self.assertFalse(devices[0].get("dynamic_dhcp", False))
            self.assertEqual("192.0.2.30", devices[0]["ip"])
            self.assertEqual(
                ["192.0.2.30", "192.0.2.21"], devices[0]["ssh_ips"],
            )
            self.assertEqual(["192.0.2.21"], devices[0]["dynamic_lease_ips"])
            monitor.analyze_switch(devices[0], {
                "kind": "ok", "connected_ip": "192.0.2.21",
                "attempts": [{"ip": "192.0.2.21", "status": "success"}],
                "remote_hostname": "cumulus", "remote_eth0_mac": "02:00:00:00:00:21",
                "host_key_refreshed": False, "ztp_log": "", "ifreload_log": "",
                "failed_yaml": "", "stderr": "", "host_key_commands": [],
            })
            self.assertEqual("success", devices[0]["stages"]["ssh"]["status"])
            self.assertIn(
                "HOSTNAME_TRANSITION", {item["code"] for item in devices[0]["issues"]},
            )

            wrong_identity = monitor.read_devices(inventory, "air", dhcp_leases=leases)[0]
            monitor.analyze_switch(wrong_identity, {
                "kind": "ok", "connected_ip": "192.0.2.21",
                "attempts": [{"ip": "192.0.2.21", "status": "success"}],
                "remote_hostname": "cumulus", "remote_eth0_mac": "02:00:00:00:00:99",
                "host_key_refreshed": False,
                "ztp_log": "[2026-08-30 17:00:00] [ZTP] Cumulus provision complete",
                "ifreload_log": "", "failed_yaml": "", "stderr": "",
                "host_key_commands": [],
            })
            self.assertEqual("failed", wrong_identity["stages"]["ssh"]["status"])
            self.assertEqual("pending", wrong_identity["stages"]["complete"]["status"])
            self.assertIn(
                "MANAGEMENT_MAC_MISMATCH",
                {item["code"] for item in wrong_identity["issues"]},
            )

            manual_device = manual.read_devices(inventory, dhcp_leases=leases)[0]
            self.assertIn(
                ("192.0.2.21", "eth0(DHCP过渡)"), manual_device["candidates"],
            )
            ready, reason = manual.dedicated_yaml_ready(project, manual_device)
            self.assertFalse(ready)
            self.assertIn("latest", reason)
            latest = project / "99-output-eth" / "latest"
            latest.mkdir(parents=True)
            hostname_yaml = latest / "AIR-EXAMPLE-Canonical-Border01.yaml"
            hostname_yaml.write_text("system:\n  hostname: AIR-EXAMPLE-Canonical-Border01\n")
            (latest / "020000000021.yaml").symlink_to(hostname_yaml.name)
            self.assertEqual(
                (True, ""), manual.dedicated_yaml_ready(project, manual_device),
            )
            backup_device = backup.load_devices_csv(inventory)[0]
            backup.apply_static_air_lease_fallbacks(
                [backup_device], inventory, leases,
            )
            self.assertEqual(["192.0.2.21"], backup_device["transition_ssh_ips"])

            report_dir = project / "ztp-status" / "20260830_170000"
            report_dir.mkdir(parents=True)
            (report_dir / "report.json").write_text(json.dumps({
                "project": "promotion", "generated_at": "2026-08-30T17:00:00+08:00",
                "devices": [{
                    "hostname": "AIR-EXAMPLE-Canonical-Border01", "type": "air",
                    "template": "fw", "ip": "192.0.2.21",
                    "mac": "02:00:00:00:00:21", "dynamic_dhcp": True,
                    "stages": {}, "overall": "pending",
                }],
            }), encoding="utf-8")
            status = html.load_ztp_status(report_dir.parent, inventory, scope="air")
            self.assertTrue(status.get("available"), status)
            self.assertEqual(1, len(status.get("devices", [])), status)
            promoted = status["devices"][0]
            self.assertNotIn("dynamic_dhcp", promoted)
            self.assertEqual("192.0.2.30", promoted["ip"])
            self.assertTrue(promoted["promotion_pending"])
            self.assertIn(
                "STATIC_PROMOTION_PENDING",
                {item["code"] for item in promoted["issues"]},
            )
            self.assertEqual("border_oob", html.ztp_device_group(promoted))
            self.assertEqual(
                ("other", "其他"),
                html.classify_host("AIR-EXAMPLE-Unknown01", "ETH", "missing", "", True),
            )
            cron_source = (ROOT / "ethernet/monitor/cron.sh").read_text(
                encoding="utf-8",
            )
            self.assertIn("--include-static-transitions", cron_source)
            self.assertIn('address_source" == "dhcp-lease-transition"', cron_source)

    def test_static_promotion_clears_old_default_success_without_incrementing_round(self):
        monitor = load_module(
            "day0_static_promotion_round", ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        previous = {
            "generated_at": "2026-08-30T16:00:00+08:00",
            "devices": [{
                "hostname": "AIR-EXAMPLE-FW01", "type": "air", "dynamic_dhcp": True,
                "ztp_round": 1, "cycle_started_at": "2026-08-30T15:00:00+08:00",
                "stages": {
                    name: monitor.stage(
                        "success", "old default evidence",
                        "2026-08-30T15:10:00+08:00", 1,
                    ) for name in monitor.STAGE_NAMES
                },
            }],
        }
        device = {
            "hostname": "AIR-EXAMPLE-FW01", "type": "air", "template": "border",
            "ip": "192.0.2.30", "mac": "02:00:00:00:00:21",
            "observed_at": "2026-08-30T17:00:00+08:00",
            "stages": {
                name: monitor.stage(
                    "success", "old default evidence",
                    "2026-08-30T15:10:00+08:00",
                ) for name in monitor.STAGE_NAMES
            },
            "issues": [], "events": [],
        }
        monitor.assign_ztp_rounds([device], previous, {})
        monitor.assign_stage_success_indices([device], previous)
        monitor.finalize_device(device)
        self.assertEqual(1, device["ztp_round"])
        self.assertTrue(device["promotion_pending"])
        self.assertTrue(all(
            item["success_index"] == 0 for item in device["stages"].values()
        ))
        self.assertEqual(0, device["progress"]["percent"])
        self.assertIn(
            "STATIC_PROMOTION_PENDING", {item["code"] for item in device["issues"]},
        )

    def test_default_yaml_apply_is_warning_with_diagnosis(self):
        monitor = load_module(
            "day0_default_yaml_warning", ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        device = {
            "hostname": "AIR-EXAMPLE-FW01", "type": "air", "template": "fw",
            "ip": "192.0.2.21", "ssh_ips": ["192.0.2.21"],
            "ssh_interfaces": {"192.0.2.21": "eth0"},
            "mac_plain": "020000000021",
            "stages": {name: monitor.stage() for name in monitor.STAGE_NAMES},
            "issues": [], "events": [],
        }
        log_text = "\n".join((
            "[2026-08-30 17:00:00] [ZTP] ZTP START",
            "[2026-08-30 17:00:01] [ZTP] MAC cfg not found, load default cfg",
            "[2026-08-30 17:00:02] [ZTP] Default config: patch and save complete",
            "[2026-08-30 17:00:03] [ZTP] Cumulus provision complete",
            "[2026-08-30 17:00:03] [ZTP] ZTP FINISH",
        ))
        monitor.analyze_switch(device, {
            "kind": "ok", "observed_at": "2026-08-30T17:00:04+08:00",
            "connected_ip": "192.0.2.21",
            "attempts": [{"ip": "192.0.2.21", "status": "success"}],
            "host_key_refreshed": False, "remote_hostname": "AIR-EXAMPLE-FW01",
            "remote_eth0_mac": "02:00:00:00:00:21",
            "boot_id": "boot-1", "boot_time": "", "ztp_log": log_text,
            "ifreload_log": "", "failed_yaml": "", "stderr": "",
            "host_key_commands": [],
        }, monitor.dt.timezone(monitor.dt.timedelta(hours=8)))
        self.assertEqual("warning", device["stages"]["config_apply"]["status"])
        self.assertEqual("warning", device["stages"]["complete"]["status"])
        issue = next(item for item in device["issues"] if item["code"] == "DEFAULT_CONFIG_USED")
        self.assertIn("没有专属 MAC YAML", issue["message"])
        self.assertIn("总体状态按警告显示", issue["message"])

    def test_ztp_round_increments_once_for_each_rebuild(self):
        monitor = load_module("day0_ztp_rounds", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        previous = {"devices": [{
            "hostname": "AIR-EXAMPLE-TAN-Leaf01", "ztp_round": 1,
            "boot_id": "old-boot", "cycle_marker": "2026-08-24T10:00:00+00:00",
            "stages": {"complete": {"timestamp": "2026-08-24T10:10:00+00:00"}},
        }]}
        current = [{
            "hostname": "AIR-EXAMPLE-TAN-Leaf01", "boot_id": "",
            "events": [{"source": "dhcp", "kind": "DHCPDISCOVER",
                        "timestamp": "2026-08-24T10:20:00+00:00"}],
        }]
        monitor.assign_ztp_rounds(current, previous)
        self.assertEqual(2, current[0]["ztp_round"])
        self.assertEqual("automatic", current[0]["trigger_source"])
        repeated_previous = {"devices": [dict(current[0])]}
        repeated = [dict(current[0], boot_id="new-boot")]
        monitor.assign_ztp_rounds(repeated, repeated_previous)
        self.assertEqual(2, repeated[0]["ztp_round"])

    def test_manual_and_automatic_ztp_share_one_round_index_with_source(self):
        monitor = load_module("day0_ztp_round_sources", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        previous = {
            "generated_at": "2026-08-24T10:10:00+00:00",
            "devices": [{
                "hostname": "AIR-EXAMPLE-Leaf01", "ztp_round": 2,
                "manual_cycle_marker": "", "trigger_source": "automatic",
                "stages": {"complete": {"timestamp": "2026-08-24T10:05:00+00:00"}},
            }],
        }
        current = [{"hostname": "AIR-EXAMPLE-Leaf01", "events": []}]
        marker = {"air-example-leaf01": {
            "timestamp": "2026-08-24T10:20:00+00:00",
            "trigger_source": "manual_web", "trigger_id": "web-123",
        }}
        monitor.assign_ztp_rounds(current, previous, marker)
        self.assertEqual(3, current[0]["ztp_round"])
        self.assertEqual("manual_web", current[0]["trigger_source"])
        self.assertEqual("web-123", current[0]["trigger_id"])
        repeated = [{"hostname": "AIR-EXAMPLE-Leaf01", "events": []}]
        monitor.assign_ztp_rounds(
            repeated, {"generated_at": "2026-08-24T10:21:00+00:00", "devices": current}, marker,
        )
        self.assertEqual(3, repeated[0]["ztp_round"])

    def test_accepted_manual_round_marks_dhcp_as_skipped_with_index(self):
        monitor = load_module(
            "day0_manual_dhcp_skip", ROOT / "DAY0-Prepare/12-ztp-monitor.py"
        )
        previous = {
            "generated_at": "2026-08-24T10:10:00+00:00",
            "devices": [{
                "hostname": "AIR-EXAMPLE-Leaf01", "ztp_round": 2,
                "manual_cycle_marker": "", "trigger_source": "automatic",
                "stages": {name: monitor.stage() for name in monitor.STAGE_NAMES},
            }],
        }
        current = [{
            "hostname": "AIR-EXAMPLE-Leaf01", "events": [],
            "stages": {name: monitor.stage() for name in monitor.STAGE_NAMES},
            "issues": [],
        }]
        marker = {"air-example-leaf01": {
            "timestamp": "2026-08-24T10:20:00+00:00",
            "trigger_source": "manual_web", "trigger_id": "web-123",
        }}
        monitor.assign_ztp_rounds(current, previous, marker)
        monitor.assign_stage_success_indices(current, previous)
        monitor.finalize_device(current[0])
        dhcp = current[0]["stages"]["dhcp"]
        self.assertEqual("skipped", dhcp["status"])
        self.assertEqual(3, dhcp["success_index"])
        self.assertEqual(1, current[0]["progress"]["done"])

    def test_accepted_manual_reset_restarts_at_round_one_with_all_stages_pending(self):
        monitor = load_module(
            "day0_manual_reset_round", ROOT / "DAY0-Prepare/12-ztp-monitor.py"
        )
        old_stages = {
            name: monitor.stage(
                "success", "old", "2026-08-24T10:00:00+00:00", 5,
            )
            for name in monitor.STAGE_NAMES
        }
        previous = {
            "generated_at": "2026-08-24T10:10:00+00:00",
            "devices": [{
                "hostname": "AIR-EXAMPLE-Leaf01", "ztp_round": 5,
                "trigger_source": "automatic", "stages": old_stages,
            }],
        }
        current = [{
            "hostname": "AIR-EXAMPLE-Leaf01", "events": [], "issues": [],
            "stages": {name: monitor.stage() for name in monitor.STAGE_NAMES},
        }]
        marker = {"air-example-leaf01": {
            "timestamp": "2026-08-24T10:20:00+00:00",
            "trigger_source": "manual_reset_web", "trigger_id": "reset-1",
            "operation": "reset",
        }}
        monitor.assign_ztp_rounds(current, previous, marker)
        monitor.assign_stage_success_indices(current, previous)
        self.assertEqual(1, current[0]["ztp_round"])
        self.assertEqual("manual_reset_web", current[0]["trigger_source"])
        self.assertEqual("reset", current[0]["manual_operation"])
        self.assertTrue(all(
            stage["status"] == "pending" and stage["success_index"] == 0
            for stage in current[0]["stages"].values()
        ))

    def test_manual_reset_requires_reboot_before_old_success_can_complete_round_one(self):
        monitor = load_module(
            "day0_manual_reset_reboot_gate", ROOT / "DAY0-Prepare/12-ztp-monitor.py"
        )
        old_stages = {
            name: monitor.stage(
                "success", "old", "2026-08-24T10:00:00+00:00", 5,
            )
            for name in monitor.STAGE_NAMES
        }
        previous = {
            "generated_at": "2026-08-24T10:10:00+00:00",
            "devices": [{
                "hostname": "AIR-EXAMPLE-Leaf01", "ztp_round": 5,
                "boot_id": "old-boot", "trigger_source": "automatic",
                "stages": old_stages,
            }],
        }
        marker = {"air-example-leaf01": {
            "timestamp": "2026-08-24T10:20:00+00:00",
            "trigger_source": "manual_reset_web", "trigger_id": "reset-1",
            "operation": "reset",
        }}
        before_reboot = [{
            "hostname": "AIR-EXAMPLE-Leaf01", "boot_id": "old-boot", "events": [],
            "issues": [],
            "stages": {
                name: monitor.stage(
                    "success", "still old", "2026-08-24T10:00:00+00:00",
                ) for name in monitor.STAGE_NAMES
            },
        }]
        monitor.assign_ztp_rounds(before_reboot, previous, marker)
        monitor.assign_stage_success_indices(before_reboot, previous)
        monitor.finalize_device(before_reboot[0])
        self.assertEqual(1, before_reboot[0]["ztp_round"])
        self.assertFalse(before_reboot[0]["reset_reboot_observed"])
        self.assertEqual(0, before_reboot[0]["progress"]["percent"])
        self.assertTrue(all(
            item["success_index"] == 0
            for item in before_reboot[0]["stages"].values()
        ))

        after_reboot = [{
            "hostname": "AIR-EXAMPLE-Leaf01", "boot_id": "new-boot", "events": [],
            "issues": [],
            "stages": {
                name: monitor.stage(
                    "success", "new", "2026-08-24T10:21:00+00:00",
                ) for name in monitor.STAGE_NAMES
            },
        }]
        reset_report = {
            "generated_at": "2026-08-24T10:20:10+00:00",
            "devices": before_reboot,
        }
        monitor.assign_ztp_rounds(after_reboot, reset_report, marker)
        monitor.assign_stage_success_indices(after_reboot, reset_report)
        monitor.finalize_device(after_reboot[0])
        self.assertTrue(after_reboot[0]["reset_reboot_observed"])
        self.assertEqual(100, after_reboot[0]["progress"]["percent"])
        self.assertEqual("success", after_reboot[0]["overall"])

    def test_manual_reset_uses_fresh_log_bundle_across_timezone_change(self):
        monitor = load_module(
            "day0_manual_reset_timezone_bundle",
            ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        old_stages = {
            name: monitor.stage(
                "success", "old", "2026-08-31T12:00:00+08:00", 5,
            )
            for name in monitor.STAGE_NAMES
        }
        previous = {
            "generated_at": "2026-08-31T12:40:00+08:00",
            "devices": [{
            "hostname": "AIR-EXAMPLE-OOB-Core01", "ztp_round": 5,
            "boot_id": "old-boot", "trigger_source": "automatic",
            "stages": old_stages,
            }],
        }
        marker = {"air-example-oob-core01": {
            "timestamp": "2026-08-31T12:55:00+08:00",
            "trigger_source": "manual_reset_web", "trigger_id": "reset-tz-1",
            "operation": "reset",
        }}
        mac_plain = "02000000005b"
        device = {
            "hostname": "AIR-EXAMPLE-OOB-Core01", "type": "air",
            "ip": "192.0.2.3", "ssh_ips": ["192.0.2.3"],
            "candidate_identity": {"192.0.2.3": ("eth0", mac_plain)},
            "mac_plain": mac_plain, "issues": [], "events": [],
            "stages": {name: monitor.stage() for name in monitor.STAGE_NAMES},
        }
        device["stages"]["dhcp"] = monitor.stage(
            "success", "DHCPACK", "2026-08-31T12:56:00+08:00",
        )
        # The device starts in UTC (04:57), then the dedicated YAML changes its
        # timezone to UTC+8 before apply/key/complete are logged (12:57).  Every
        # line belongs to one file written after this reset boot.
        ztp_log = "\n".join((
            "[2026-08-31 04:57:24] ======================== ZTP START ========================",
            "[2026-08-31 04:57:27] [ZTP] Network check passed: vrf=mgmt",
            "[2026-08-31 04:57:27] [ZTP] Version matched, continue provisioning",
            "[2026-08-31 04:57:28] [ZTP] Load per-MAC config:http://ztp/latest_yaml/02000000005b.yaml",
            "[2026-08-31 12:57:39] [ZTP] Dedicated config:/tmp/ztp/02000000005b.yaml apply and save complete",
            "[2026-08-31 12:57:39] [ZTP] ACCESS_READY: 2 prefetched SSH public key source(s) installed",
            "[2026-08-31 12:57:39] [ZTP] Cumulus provision complete",
            "[2026-08-31 12:57:39] ======================== ZTP FINISH ========================",
        ))
        boot_epoch = int(monitor.dt.datetime.fromisoformat(
            "2026-08-31T04:56:00+00:00",
        ).timestamp())
        log_mtime = int(monitor.dt.datetime.fromisoformat(
            "2026-08-31T04:57:40+00:00",
        ).timestamp())
        monitor.analyze_switch(device, {
            "kind": "ok", "observed_at": "2026-08-31T13:00:00+08:00",
            "connected_ip": "192.0.2.3", "attempts": [], "stderr": "",
            "remote_hostname": "AIR-EXAMPLE-OOB-Core01",
            "remote_eth0_mac": "02:00:00:00:00:5b", "remote_eth1_mac": "",
            "boot_id": "new-boot", "boot_time": str(boot_epoch),
            "ztp_log": ztp_log, "ztp_log_mtime": str(log_mtime),
            "ifreload_log": "", "failed_yaml": "",
            "host_key_refreshed": False, "host_key_commands": [],
        }, monitor.dt.timezone(monitor.dt.timedelta(hours=8)))
        monitor.assign_ztp_rounds([device], previous, marker)
        monitor.assign_stage_success_indices([device], previous)
        monitor.finalize_device(device)

        self.assertEqual(1, device["ztp_round"])
        self.assertTrue(device["reset_reboot_observed"])
        self.assertTrue(device["ztp_log_current_boot"])
        self.assertTrue(monitor._timestamp_near_boundary(
            device["ztp_log_mtime"], device["cycle_started_at"],
        ))
        self.assertEqual(1, device["stages"]["network"]["success_index"])
        self.assertEqual(1, device["stages"]["version"]["success_index"])
        self.assertEqual({"done": 9, "total": 9, "percent": 100}, device["progress"])
        self.assertEqual("success", device["overall"])
        self.assertIn("__ZTP_LOG_MTIME_BEGIN__", monitor.REMOTE_SCRIPT)
        self.assertIn("__ZTP_LOG_POINTER_STATE_BEGIN__", monitor.REMOTE_SCRIPT)
        self.assertIn(
            'log_pointer="$log_dir/latest-log"',
            monitor.REMOTE_SCRIPT,
        )
        self.assertLess(
            monitor.REMOTE_SCRIPT.index('log_pointer="$log_dir/latest-log"'),
            monitor.REMOTE_SCRIPT.index('"$HOME"/ztp-result.log_*'),
        )

    def test_log_pointer_beats_future_mtime_and_invalid_pointer_fails_closed(self):
        monitor = load_module(
            "day0_log_pointer_selection",
            ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        start = monitor.REMOTE_SCRIPT.index("log_dir=/var/lib/nvidia-ztp/logs")
        end = monitor.REMOTE_SCRIPT.index("printf '__IFRELOAD_BEGIN__", start)
        selector = monitor.REMOTE_SCRIPT[start:end]
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            logs = root / "logs"
            home = root / "home"
            logs.mkdir()
            home.mkdir()
            selected = logs / "ztp-result.log_selected"
            stale = logs / "ztp-result.log_stale"
            selected.write_text("SELECTED\n", encoding="utf-8")
            stale.write_text("STALE-FUTURE\n", encoding="utf-8")
            pointer = logs / "latest-log"
            pointer.write_text(selected.name + "\n", encoding="utf-8")
            for path in (selected, stale, pointer):
                path.chmod(0o644)
            future = 4_102_444_800
            os.utime(stale, (future, future))
            owner_mode = f"{pointer.owner()}:644"
            command = selector.replace(
                "log_dir=/var/lib/nvidia-ztp/logs",
                f"log_dir={str(logs)!r}",
            ).replace("root:644", owner_mode).replace(
                "stat -c '%U:%a' --", "stat -f '%Su:%Lp'",
            ).replace(
                "stat -c '%Y' --", "stat -f '%m'",
            )
            result = subprocess.run(
                ["sh", "-c", command], text=True, capture_output=True,
                env={**os.environ, "HOME": str(home)}, check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("__ZTP_LOG_POINTER_STATE_BEGIN__\nvalid\n", result.stdout)
            self.assertIn(f"__FILE__={selected}", result.stdout)
            self.assertIn("SELECTED", result.stdout)
            self.assertNotIn("STALE-FUTURE", result.stdout)

            pointer.unlink()
            pointer.symlink_to(stale)
            result = subprocess.run(
                ["sh", "-c", command], text=True, capture_output=True,
                env={**os.environ, "HOME": str(home)}, check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("__ZTP_LOG_POINTER_STATE_BEGIN__\ninvalid\n", result.stdout)
            self.assertNotIn("__FILE__=", result.stdout)
            self.assertNotIn("STALE-FUTURE", result.stdout)

    def test_invalid_log_pointer_is_reported_without_mtime_fallback(self):
        monitor = load_module(
            "day0_invalid_log_pointer_analysis",
            ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        device = {
            "hostname": "EXAMPLE-Leaf01", "type": "eth", "ip": "192.0.2.10",
            "ssh_ips": ["192.0.2.10"],
            "candidate_identity": {"192.0.2.10": ("eth0", "020000000001")},
            "mac_plain": "020000000001", "issues": [], "events": [],
            "stages": {name: monitor.stage() for name in monitor.STAGE_NAMES},
        }
        monitor.analyze_switch(device, {
            "kind": "ok", "observed_at": "2026-08-31T13:00:00+08:00",
            "connected_ip": "192.0.2.10", "attempts": [], "stderr": "",
            "remote_hostname": "EXAMPLE-Leaf01",
            "remote_eth0_mac": "02:00:00:00:00:01", "remote_eth1_mac": "",
            "boot_id": "boot-1", "boot_time": "0", "ztp_log": "",
            "ztp_log_pointer_state": "invalid", "ztp_log_mtime": "",
            "ifreload_log": "", "failed_yaml": "",
            "host_key_refreshed": False, "host_key_commands": [],
        }, monitor.dt.timezone.utc)
        codes = [issue["code"] for issue in device["issues"]]
        self.assertIn("ZTP_LOG_POINTER_INVALID", codes)
        self.assertNotIn("ZTP_LOG_NOT_FOUND", codes)

    def test_switch_time_offset_is_measured_only_after_identity_verification(self):
        monitor = load_module(
            "day0_switch_time_measurement",
            ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        def make_device():
            return {
                "hostname": "EXAMPLE-Leaf01", "type": "eth", "ip": "192.0.2.10",
                "ssh_ips": ["192.0.2.10"],
                "ssh_interfaces": {"192.0.2.10": "eth0"},
                "candidate_identity": {
                    "192.0.2.10": ("eth0", "020000000001"),
                },
                "mac_plain": "020000000001", "issues": [], "events": [],
                "stages": {name: monitor.stage() for name in monitor.STAGE_NAMES},
            }
        result = {
            "kind": "ok", "connected_ip": "192.0.2.10", "attempts": [],
            "remote_hostname": "EXAMPLE-Leaf01", "remote_eth0_mac": "02:00:00:00:00:01",
            "remote_eth1_mac": "", "remote_interface_macs": {
                "eth0": "020000000001",
            },
            "local_started_epoch": 1000.0, "local_finished_epoch": 1002.0,
            "remote_time_start": "1000.2", "remote_time_end": "1002.2",
            "host_key_refreshed": False, "boot_id": "", "boot_time": "",
            "ztp_log": "", "ztp_log_mtime": "", "ifreload_log": "",
            "failed_yaml": "", "stderr": "", "host_key_commands": [],
        }
        device = make_device()
        monitor.analyze_switch(device, result)
        self.assertEqual("success", device["time_sync"]["status"])
        self.assertAlmostEqual(0.2, device["time_sync"]["offset_seconds"], places=2)
        self.assertIn("±", device["time_sync"]["detail"])
        self.assertIn("__REMOTE_TIME_START_BEGIN__", monitor.REMOTE_SCRIPT)
        self.assertIn("__REMOTE_TIME_END_BEGIN__", monitor.REMOTE_SCRIPT)

        wrong = make_device()
        monitor.analyze_switch(wrong, {
            **result, "remote_eth0_mac": "02:00:00:00:00:ff",
            "remote_interface_macs": {"eth0": "0200000000ff"},
        })
        self.assertEqual("unknown", wrong["time_sync"]["status"])
        self.assertIn("不能信任", wrong["time_sync"]["detail"])

    def test_incomplete_old_log_keeps_boot_epoch_and_is_rejected(self):
        monitor = load_module(
            "day0_incomplete_stale_log_gate",
            ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        mac_plain = "020000000001"
        device = {
            "hostname": "AIR-EXAMPLE-OOB-Leaf01", "type": "air",
            "ip": "192.0.2.1", "ssh_ips": ["192.0.2.1"],
            "candidate_identity": {"192.0.2.1": ("eth0", mac_plain)},
            "mac_plain": mac_plain, "issues": [], "events": [],
            "stages": {name: monitor.stage() for name in monitor.STAGE_NAMES},
        }
        boot_epoch = int(monitor.dt.datetime.fromisoformat(
            "2026-08-31T10:20:00+00:00",
        ).timestamp())
        log_mtime = int(monitor.dt.datetime.fromisoformat(
            "2026-08-31T10:00:02+00:00",
        ).timestamp())
        # This previous-boot file is deliberately incomplete: the absence of a
        # provision-complete line must not zero the independently valid btime.
        ztp_log = "\n".join((
            "[2026-08-31 10:00:00] [ZTP] ZTP START",
            "[2026-08-31 10:00:01] [ZTP] Network check passed",
        ))
        monitor.analyze_switch(device, {
            "kind": "ok", "observed_at": "2026-08-31T10:21:00+00:00",
            "connected_ip": "192.0.2.1", "attempts": [], "stderr": "",
            "remote_hostname": "AIR-EXAMPLE-OOB-Leaf01",
            "remote_eth0_mac": "02:00:00:00:00:01", "remote_eth1_mac": "",
            "boot_id": "new-boot", "boot_time": str(boot_epoch),
            "ztp_log": ztp_log, "ztp_log_mtime": str(log_mtime),
            "ifreload_log": "", "failed_yaml": "",
            "host_key_refreshed": False, "host_key_commands": [],
        }, monitor.dt.timezone.utc)

        self.assertFalse(device["ztp_log_current_boot"])
        self.assertEqual([], device["ztp_log_stage_names"])
        self.assertEqual("pending", device["stages"]["bootstrap"]["status"])
        self.assertEqual("pending", device["stages"]["network"]["status"])
        self.assertIn(
            "STALE_ZTP_LOG_AFTER_REBOOT",
            {issue["code"] for issue in device["issues"]},
        )

    def test_reset_rejects_pre_boundary_boot_log_and_same_boot_dhcp_noise(self):
        monitor = load_module(
            "day0_reset_generation_boundary_gate",
            ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        boundary = "2026-08-31T10:20:00+00:00"
        old_stages = {
            name: monitor.stage(
                "success", "old", "2026-08-31T09:00:00+00:00", 5,
            )
            for name in monitor.STAGE_NAMES
        }
        previous = {
            "generated_at": "2026-08-31T10:10:00+00:00",
            "devices": [{
                "hostname": "AIR-EXAMPLE-OOB-Leaf01", "ztp_round": 5,
                "boot_id": "boot-a", "trigger_source": "automatic",
                "stages": old_stages,
            }],
        }
        marker = {"air-example-oob-leaf01": {
            "timestamp": boundary, "trigger_source": "manual_reset_web",
            "trigger_id": "reset-boundary-1", "operation": "reset",
        }}
        log_stages = [
            name for name in monitor.STAGE_NAMES if name not in {"dhcp", "ssh"}
        ]
        pre_boundary_boot = int(monitor.dt.datetime.fromisoformat(
            "2026-08-31T10:00:00+00:00",
        ).timestamp())
        independent_reboot = [{
            "hostname": "AIR-EXAMPLE-OOB-Leaf01", "boot_id": "boot-b",
            "boot_time": str(pre_boundary_boot), "events": [], "issues": [],
            "ztp_log_current_boot": True,
            "ztp_log_mtime": "2026-08-31T10:05:00+00:00",
            "ztp_log_stage_names": log_stages,
            "stages": {
                name: monitor.stage(
                    "success", "pre-reset log", "2026-08-31T10:05:00+00:00",
                )
                for name in monitor.STAGE_NAMES
            },
        }]
        monitor.assign_ztp_rounds(independent_reboot, previous, marker)
        monitor.assign_stage_success_indices(independent_reboot, previous)
        self.assertFalse(independent_reboot[0]["reset_reboot_observed"])
        self.assertTrue(all(
            value["success_index"] == 0
            for value in independent_reboot[0]["stages"].values()
        ))

        # Even a post-boundary DISCOVER is only an early heuristic. Once SSH
        # proves the boot ID is unchanged it must not advance reset stages.
        same_boot = [{
            "hostname": "AIR-EXAMPLE-OOB-Leaf01", "boot_id": "boot-a",
            "boot_time": str(int(monitor.dt.datetime.fromisoformat(
                "2026-08-31T09:00:00+00:00",
            ).timestamp())),
            "events": [{
                "source": "dhcp", "kind": "DHCPDISCOVER",
                "timestamp": "2026-08-31T10:21:00+00:00",
            }],
            "issues": [],
            "stages": {
                name: monitor.stage(
                    "success", "same boot", "2026-08-31T10:21:30+00:00",
                )
                for name in monitor.STAGE_NAMES
            },
        }]
        monitor.assign_ztp_rounds(same_boot, previous, marker)
        monitor.assign_stage_success_indices(same_boot, previous)
        self.assertFalse(same_boot[0]["reset_reboot_observed"])
        self.assertTrue(all(
            value["success_index"] == 0
            for value in same_boot[0]["stages"].values()
        ))

        request_only = dict(same_boot[0])
        request_only["events"] = [{
            "source": "dhcp", "kind": "DHCPREQUEST",
            "timestamp": "2026-08-31T10:22:00+00:00",
        }]
        self.assertEqual("", monitor._latest_dhcp_cycle_marker(request_only))

    def test_reset_log_bundle_does_not_invent_a_missing_stage(self):
        monitor = load_module(
            "day0_manual_reset_incomplete_bundle",
            ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        stages = {
            name: monitor.stage(
                "success", "new", "2026-08-31T04:57:00+08:00",
            )
            for name in monitor.STAGE_NAMES
        }
        stages["version"] = monitor.stage()
        device = {
            "hostname": "AIR-EXAMPLE-OOB-Core01", "ztp_round": 1,
            "trigger_source": "manual_reset_web", "manual_operation": "reset",
            "manual_cycle_marker": "2026-08-31T12:55:00+08:00",
            "cycle_started_at": "2026-08-31T12:55:00+08:00",
            "boot_id": "new-boot", "reset_boot_id_before": "old-boot",
            "reset_reboot_observed": True, "ztp_log_current_boot": True,
            "ztp_log_mtime": "2026-08-31T04:57:40+00:00",
            "ztp_log_stage_names": [
                name for name in monitor.STAGE_NAMES if name not in {"dhcp", "ssh", "version"}
            ],
            "stages": stages, "issues": [],
        }
        monitor.assign_stage_success_indices([device], None)
        monitor.finalize_device(device)
        self.assertEqual("pending", device["stages"]["version"]["status"])
        self.assertEqual(0, device["stages"]["version"]["success_index"])
        self.assertLess(device["progress"]["percent"], 100)

    def test_manual_round_accepts_changed_switch_events_with_small_clock_skew(self):
        monitor = load_module(
            "day0_manual_clock_skew", ROOT / "DAY0-Prepare/12-ztp-monitor.py"
        )
        previous_stages = {
            name: monitor.stage(
                "success", "old", "2026-08-24T10:00:00+00:00", 2,
            )
            for name in monitor.STAGE_NAMES
        }
        previous = {"devices": [{
            "hostname": "AIR-EXAMPLE-Leaf01", "ztp_round": 2,
            "stages": previous_stages,
        }]}
        current_stages = {
            name: monitor.stage(
                "success", "new", "2026-08-24T10:19:57+00:00",
            )
            for name in monitor.STAGE_NAMES
        }
        current = [{
            "hostname": "AIR-EXAMPLE-Leaf01", "ztp_round": 3,
            "trigger_source": "manual_web",
            "manual_cycle_marker": "2026-08-24T10:20:00+00:00",
            "cycle_started_at": "2026-08-24T10:20:00+00:00",
            "stages": current_stages, "issues": [],
        }]
        monitor.assign_stage_success_indices(current, previous)
        monitor.finalize_device(current[0])
        self.assertEqual("skipped", current[0]["stages"]["dhcp"]["status"])
        self.assertTrue(all(
            int(stage.get("success_index") or 0) == 3
            for stage in current[0]["stages"].values()
        ))
        self.assertEqual(100, current[0]["progress"]["percent"])

    def test_manual_round_reclassifies_complete_log_emitted_before_command_return(self):
        monitor = load_module(
            "day0_manual_command_window_bundle",
            ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        marker_time = "2026-08-31T06:42:22+00:00"
        log_mtime = "2026-08-31T06:40:07+00:00"
        previous_stages = {
            name: monitor.stage() for name in monitor.STAGE_NAMES
        }
        previous_stages["network"] = monitor.stage(
            "success", "ZTP 网络检查通过",
            "2026-08-31T06:40:06+00:00", 1,
        )
        previous_stages["complete"] = monitor.stage(
            "success", "bootstrap 已结束",
            "2026-08-31T06:40:07+00:00", 1,
        )
        previous = {
            "generated_at": "2026-08-31T06:43:00+00:00",
            "devices": [{
                "hostname": "AIR-EXAMPLE-SITE02-OOB-Staging-Leaf04",
                "type": "air", "ztp_round": 2,
                "cycle_started_at": marker_time,
                "manual_cycle_marker": marker_time,
                "trigger_source": "manual_web", "trigger_id": "web-ztp-2",
                "manual_operation": "ztp", "stages": previous_stages,
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            result_dir = (
                Path(directory) / "manual-trigger/run-2/"
                "AIR-EXAMPLE-SITE02-OOB-Staging-Leaf04"
            )
            result_dir.mkdir(parents=True)
            # This is an existing pre-upgrade result: it has only started_at,
            # so the monitor must use it as the compatible command-window start.
            (result_dir / "result.json").write_text(json.dumps({
                "hostname": "AIR-EXAMPLE-SITE02-OOB-Staging-Leaf04",
                "type": "air", "state": "triggered",
                "started_at": "2026-08-31T06:39:50+00:00",
                "finished_at": marker_time,
                "trigger_source": "manual_web", "trigger_id": "web-ztp-2",
                "operation": "ztp",
            }), encoding="utf-8")
            markers = monitor.latest_manual_trigger_markers(Path(directory))

        current_stages = {
            name: monitor.stage() for name in monitor.STAGE_NAMES
        }
        current_stages["network"] = monitor.stage(
            "success", "ZTP 网络检查通过",
            "2026-08-31T06:40:06+00:00",
        )
        current_stages["complete"] = monitor.stage(
            "success", "bootstrap 已结束",
            "2026-08-31T06:40:07+00:00",
        )
        current = [{
            "hostname": "AIR-EXAMPLE-SITE02-OOB-Staging-Leaf04", "type": "air",
            "events": [], "issues": [], "ztp_log_current_boot": True,
            "ztp_log_mtime": log_mtime,
            "ztp_log_stage_names": ["network", "complete"],
            "stages": current_stages,
        }]
        monitor.assign_ztp_rounds(current, previous, markers)
        monitor.assign_stage_success_indices(current, previous)

        device = current[0]
        self.assertEqual(2, device["ztp_round"])
        self.assertEqual(
            "2026-08-31T06:39:50+00:00",
            device["manual_command_started_at"],
        )
        self.assertEqual(2, device["stages"]["network"]["success_index"])
        self.assertEqual(2, device["stages"]["complete"]["success_index"])

        stale = json.loads(json.dumps(current))
        stale[0]["ztp_log_mtime"] = "2026-08-31T06:38:00+00:00"
        stale[0]["stages"]["network"]["success_index"] = 0
        stale[0]["stages"]["complete"]["success_index"] = 0
        monitor.assign_ztp_rounds(stale, previous, markers)
        monitor.assign_stage_success_indices(stale, previous)
        self.assertEqual(1, stale[0]["stages"]["network"]["success_index"])
        self.assertEqual(1, stale[0]["stages"]["complete"]["success_index"])

    def test_manual_round_binds_exact_log_when_device_clock_is_minutes_behind(self):
        monitor = load_module(
            "day0_manual_command_digest_bundle",
            ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        host = "AIR-EXAMPLE-SITE04-OOB-Rack01-TOR02"
        remote_log = "\n".join((
            "[2026-08-31T07:23:52Z] ======================== ZTP START ========================",
            "[2026-08-31T07:23:54Z] [ZTP] Network check passed: vrf=mgmt, interface=eth0",
            "[2026-08-31T07:23:54Z] [ZTP] Version matched, continue provisioning",
            "[2026-08-31T07:23:54Z] [ZTP] Load per-MAC config:http://server/config.yaml",
            "[2026-08-31T07:23:55Z] [ZTP] Dedicated config:/tmp/config.yaml apply and save complete",
            "[2026-08-31T07:23:55Z] [ZTP] ACCESS_READY: 2 prefetched SSH public key source(s) installed",
            "[2026-08-31T07:23:55Z] [ZTP] Cumulus provision complete",
            "[2026-08-31T07:23:55Z] ======================== ZTP FINISH ========================",
        )) + "\n"
        digest, complete = monitor.ztp_log_evidence(remote_log)
        self.assertTrue(complete)

        with tempfile.TemporaryDirectory() as directory:
            result_dir = Path(directory) / "manual-trigger/run-2" / host
            result_dir.mkdir(parents=True)
            (result_dir / "result.json").write_text(json.dumps({
                "hostname": host, "type": "air", "state": "triggered",
                "started_at": "2026-08-31T07:26:05+00:00",
                "command_started_at": "2026-08-31T07:26:06+00:00",
                "finished_at": "2026-08-31T07:26:10+00:00",
                "trigger_source": "manual_web", "trigger_id": "web-clock-skew",
                "operation": "ztp",
            }), encoding="utf-8")
            (result_dir / "trigger.log").write_text(
                "command: http-manual-ztp-oobofoob\nreturncode: 0\nstdout:\n"
                + remote_log + "\nstderr:\n",
                encoding="utf-8",
            )
            markers = monitor.latest_manual_trigger_markers(Path(directory))

        self.assertEqual(digest, markers[host.casefold()]["command_ztp_log_sha256"])
        self.assertTrue(markers[host.casefold()]["command_ztp_complete"])
        previous_stages = {
            name: monitor.stage("success", "old", "2026-08-31T07:23:55+00:00", 1)
            for name in monitor.STAGE_NAMES
        }
        previous = {
            "generated_at": "2026-08-31T07:25:00+00:00",
            "devices": [{
                "hostname": host, "type": "air", "ztp_round": 1,
                "cycle_started_at": "2026-08-31T07:23:55+00:00",
                "stages": previous_stages,
            }],
        }

        def current_device(log_digest=digest, bootstrap_time="2026-08-31T07:26:06+00:00"):
            stages = {name: monitor.stage() for name in monitor.STAGE_NAMES}
            stages["bootstrap"] = monitor.stage("success", "HTTP 200", bootstrap_time)
            stages["config_http"] = monitor.stage(
                "success", "HTTP 200", "2026-08-31T07:26:08+00:00",
            )
            stages["ssh"] = monitor.stage(
                "success", "identity verified", "2026-08-31T07:26:20+00:00",
            )
            for name in ("network", "version", "config_apply", "ssh_keys", "complete"):
                stages[name] = monitor.stage(
                    "success", "device log", "2026-08-31T07:23:55+00:00",
                )
            return {
                "hostname": host, "type": "air", "events": [], "issues": [],
                "ztp_log_current_boot": True,
                "ztp_log_mtime": "2026-08-31T07:23:55+00:00",
                "ztp_log_sha256": log_digest,
                "ztp_log_stage_names": [
                    "bootstrap", "network", "version", "config_http",
                    "config_apply", "ssh_keys", "complete",
                ],
                "stages": stages,
            }

        current = [current_device()]
        monitor.assign_ztp_rounds(current, previous, markers)
        monitor.assign_stage_success_indices(current, previous)
        self.assertEqual(2, current[0]["ztp_round"])
        for name in ("network", "version", "config_apply", "ssh_keys", "complete"):
            self.assertEqual(2, current[0]["stages"][name]["success_index"], name)

        for rejected in (
            current_device("0" * 64),
            current_device(digest, "2026-08-31T07:20:00+00:00"),
        ):
            sample = [rejected]
            monitor.assign_ztp_rounds(sample, previous, markers)
            monitor.assign_stage_success_indices(sample, previous)
            self.assertEqual(1, sample[0]["stages"]["network"]["success_index"])
            self.assertEqual(1, sample[0]["stages"]["complete"]["success_index"])

    def test_switch_evidence_does_not_move_http_stage_time_backwards(self):
        monitor = load_module(
            "day0_stage_clock_order", ROOT / "DAY0-Prepare/12-ztp-monitor.py"
        )
        device = {"stages": {
            "config_http": monitor.stage(
                "success", "HTTP 200", "2026-08-24T10:20:05+00:00"
            ),
        }}
        monitor.set_stage(
            device, "config_http", "success", "交换机已下载专用 YAML",
            "2026-08-24T10:19:59+00:00",
        )
        self.assertEqual(
            "2026-08-24T10:20:05+00:00",
            device["stages"]["config_http"]["timestamp"],
        )

    def test_only_accepted_manual_result_becomes_cycle_marker(self):
        monitor = load_module("day0_manual_markers", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for run, state, source, stamp in (
                ("one", "failed", "manual_web", "2026-08-24T10:00:00+00:00"),
                ("two", "triggered", "manual_cli", "2026-08-24T10:05:00+00:00"),
            ):
                target = root / "manual-trigger" / run / "AIR-EXAMPLE-Leaf01"
                target.mkdir(parents=True)
                (target / "result.json").write_text(json.dumps({
                    "hostname": "AIR-EXAMPLE-Leaf01", "state": state,
                    "started_at": stamp, "trigger_source": source,
                    "trigger_id": run,
                }), encoding="utf-8")
            markers = monitor.latest_manual_trigger_markers(root)
        self.assertEqual("2026-08-24T10:05:00+00:00", markers["air-example-leaf01"]["timestamp"])
        self.assertEqual("manual_cli", markers["air-example-leaf01"]["trigger_source"])
        self.assertEqual("two", markers["air-example-leaf01"]["trigger_id"])

    def test_manual_marker_uses_remote_accept_time_and_survives_midflight_snapshot(self):
        monitor = load_module(
            "day0_manual_accept_race", ROOT / "DAY0-Prepare/12-ztp-monitor.py"
        )
        previous = {
            "generated_at": "2026-08-24T10:00:05+00:00",
            "devices": [{
                "hostname": "AIR-EXAMPLE-Leaf01", "ztp_round": 2,
                # A legacy/in-flight snapshot had seen the start marker but
                # had not associated its trigger id or accepted return yet.
                "manual_cycle_marker": "2026-08-24T10:00:00+00:00",
                "trigger_source": "automatic", "trigger_id": "",
                "stages": {"complete": monitor.stage(
                    "success", "old", "2026-08-24T09:59:00+00:00", 2,
                )},
            }],
        }
        current = [{"hostname": "AIR-EXAMPLE-Leaf01", "events": []}]
        marker = {"air-example-leaf01": {
            "timestamp": "2026-08-24T10:00:10+00:00",
            "trigger_source": "manual_cli", "trigger_id": "cli-123",
        }}
        monitor.assign_ztp_rounds(current, previous, marker)
        self.assertEqual(3, current[0]["ztp_round"])
        self.assertEqual("manual_cli", current[0]["trigger_source"])
        self.assertEqual("cli-123", current[0]["trigger_id"])
        self.assertEqual(marker["air-example-leaf01"]["timestamp"], current[0]["manual_cycle_marker"])

        repeated = [{"hostname": "AIR-EXAMPLE-Leaf01", "events": []}]
        monitor.assign_ztp_rounds(
            repeated,
            {"generated_at": "2026-08-24T10:00:20+00:00", "devices": current},
            marker,
        )
        self.assertEqual(3, repeated[0]["ztp_round"])

    def test_latest_manual_marker_prefers_successful_return_time(self):
        monitor = load_module(
            "day0_manual_accept_time", ROOT / "DAY0-Prepare/12-ztp-monitor.py"
        )
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "manual-trigger/run/AIR-EXAMPLE-Leaf01"
            target.mkdir(parents=True)
            (target / "result.json").write_text(json.dumps({
                "hostname": "AIR-EXAMPLE-Leaf01", "state": "triggered",
                "started_at": "2026-08-24T10:00:00+00:00",
                "command_started_at": "2026-08-24T10:00:03+00:00",
                "finished_at": "2026-08-24T10:00:10+00:00",
                "trigger_source": "manual_cli", "trigger_id": "cli-123",
            }), encoding="utf-8")
            markers = monitor.latest_manual_trigger_markers(Path(directory))
        self.assertEqual(
            "2026-08-24T10:00:10+00:00",
            markers["air-example-leaf01"]["timestamp"],
        )
        self.assertEqual(
            "2026-08-24T10:00:03+00:00",
            markers["air-example-leaf01"]["command_started_at"],
        )

    def test_completed_monitor_keeps_configured_watch_interval(self):
        source = (ROOT / "DAY0-Prepare/12-ztp-monitor.py").read_text(encoding="utf-8")
        self.assertNotIn("--post-complete-watch", source)
        self.assertIn("controlled_sleep(max(args.watch, 5))", source)

    def test_load_does_not_prompt_or_configure_management_service_ip(self):
        source = (ROOT / "DAY0-Prepare/11-load.py").read_text(encoding="utf-8")
        self.assertNotIn("可选配置管理服务器 service_ip", source)
        self.assertNotIn("是否根据 02-dhcp-subnet_config.csv 把 service_ip", source)
        self.assertNotIn("maybe_configure_service_ips(inputs", source)
        self.assertNotIn('mgmt.get("service_ip"', source)

    def test_load_renders_both_role_specific_manual_ztp_helpers(self):
        load = load_module("day0_load_manual_helpers", ROOT / "DAY0-Prepare/11-load.py")
        with tempfile.TemporaryDirectory() as directory:
            ztp_root = Path(directory) / "ztp"
            templates = ztp_root / "templates"
            templates.mkdir(parents=True)
            (templates / "ztp-bootstrap.sh").write_text(
                (ROOT / "ztp/templates/ztp-bootstrap.sh").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            pubkey = Path(directory) / "laptop.pub"
            pubkey.write_text("ssh-ed25519 AAAATEST test\n", encoding="utf-8")
            management_placeholder = Path(directory) / "mgmt-server.pub"
            management_placeholder.touch()
            settings = load.GlobalSettings(
                dhcp_enabled=True, dhcp_package="isc-dhcp-server",
                http_enabled=True, http_package="apache2",
                http_root=ROOT, ztp_enabled=True, ztp_prefix="/ztp",
                ztp_ips={
                    "air_oob": ("192.0.2.10",),
                    "air_oobofoob": ("198.51.100.10",),
                },
                versions={"eth": "5.16.4"},
            )
            original = load.ZTP_DIR
            try:
                load.ZTP_DIR = ztp_root
                with contextlib.redirect_stdout(io.StringIO()):
                    load.render_ztp_runtime(
                        settings, (pubkey, management_placeholder),
                        frozenset({"eth"}), dry_run=False,
                    )
            finally:
                load.ZTP_DIR = original
            for filename in (
                "ztp-bootstrap_oob.sh", "ztp-bootstrap_oobofoob.sh",
            ):
                rendered_path = ztp_root / filename
                rendered = rendered_path.read_text(encoding="utf-8")
                self.assertIn(
                    'MANUAL_ZTP_OOB_URL="http://192.0.2.10/ztp/ztp-bootstrap_oob.sh"',
                    rendered,
                )
                self.assertIn(
                    'MANUAL_ZTP_OOBOFOOB_URL="http://198.51.100.10/ztp/ztp-bootstrap_oobofoob.sh"',
                    rendered,
                )
                self.assertNotIn('reset_helper="/usr/local/sbin/http-manual-reset-${role}"', rendered)
                self.assertNotIn("scheduled Cumulus reinstall", rendered)
                self.assertIn("legacy reset helpers removed", rendered)
                self.assertIn(
                    '"${ZTP_URL_PREFIX}/config/publickey/laptop.pub"', rendered,
                )
                self.assertIn(
                    '"${ZTP_URL_PREFIX}/config/publickey/mgmt-server.pub"', rendered,
                    "empty preparation placeholder must retain the fixed management-key URL",
                )
                syntax = subprocess.run(
                    ["bash", "-n", str(rendered_path)],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(0, syntax.returncode, syntax.stderr)

    def test_load_generates_nvos_ztp_json_from_immutable_safe_template(self):
        load = load_module("day0_load_nvos_ztp_json", ROOT / "DAY0-Prepare/11-load.py")
        with tempfile.TemporaryDirectory() as directory:
            ztp_root = Path(directory) / "ztp"
            templates = ztp_root / "templates"
            templates.mkdir(parents=True)
            for filename in ("ztp-bootstrap.sh", "ztp.json"):
                (templates / filename).write_bytes(
                    (ROOT / "ztp/templates" / filename).read_bytes()
                )
            template_before = (templates / "ztp.json").read_bytes()
            pubkey = Path(directory) / "operator.pub"
            pubkey.write_text(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest operator\n",
                encoding="utf-8",
            )
            settings = load.GlobalSettings(
                dhcp_enabled=True, dhcp_package="isc-dhcp-server",
                http_enabled=True, http_package="apache2",
                http_root=ROOT, ztp_enabled=True, ztp_prefix="/day0-ztp",
                ztp_ips={"prod_oob": ("192.0.2.20",)},
                versions={"eth": "5.16.4"},
            )
            original = load.ZTP_DIR
            try:
                load.ZTP_DIR = ztp_root
                with contextlib.redirect_stdout(io.StringIO()):
                    load.render_ztp_runtime(
                        settings, (pubkey,), frozenset({"ib"}), dry_run=True,
                    )
                self.assertFalse((ztp_root / "ztp.json").exists())
                with contextlib.redirect_stdout(io.StringIO()):
                    load.render_ztp_runtime(
                        settings, (pubkey,), frozenset({"ib"}), dry_run=False,
                    )
            finally:
                load.ZTP_DIR = original

            self.assertEqual(template_before, (templates / "ztp.json").read_bytes())
            rendered = json.loads((ztp_root / "ztp.json").read_text(encoding="utf-8"))
            self.assertEqual(
                ["192.0.2.20", "localhost"],
                rendered["ztp"]["01-connectivity-check"]["ping-hosts"],
            )
            self.assertEqual(
                "http://192.0.2.20/day0-ztp/config/nvos/disable-password-hardening.nv",
                rendered["ztp"]["02-commands-list"]["url"],
            )
            self.assertEqual(
                "http://192.0.2.20/day0-ztp/ztp-bootstrap_oob.sh",
                rendered["ztp"]["03-provisioning-script"]["url"],
            )

    def test_dhcp_restart_requires_all_ztp_url_ips_on_local_interfaces(self):
        load = load_module("day0_load_dhcp_url_gate", ROOT / "DAY0-Prepare/11-load.py")
        bindings = ("192.0.2.200/24", "198.51.100.200/24")
        assignments = {
            "192.0.2.200": {("bond0", 24)},
            "198.51.100.200": {("bond0", 25)},
        }
        self.assertEqual(
            ["198.51.100.200/24"],
            load.missing_ztp_url_bindings(bindings, assignments),
        )
        source = (ROOT / "DAY0-Prepare/11-load.py").read_text(encoding="utf-8")
        gate = source.index("ensure_ztp_url_network_ready(inputs, dry_run=dry_run)")
        restart = source.index('"restart", "isc-dhcp-server"', gate)
        self.assertLess(gate, restart)
        self.assertIn("非交互模式无法确认接口/路由配置", source)

    def test_ztp_monitor_uses_same_subnet_svi_as_ssh_fallback(self):
        monitor = load_module("day0_ztp_monitor_fallback", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        header = (
            "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,"
            "eth1_ip,netmask,eth1_gw,eth1_mac,vlan_id,svi_ip,netmask\n"
        )
        rows = (
            "EXAMPLE-OOB-Leaf03,eth,oobofoob-leaf,192.0.2.150,24,192.0.2.1,"
            "02:00:00:00:00:30,,,,,100,192.0.2.145,24\n"
            "AIR-EXAMPLE-OOB-Leaf03,air,oobofoob-leaf,192.0.2.150,24,192.0.2.1,"
            "02:00:00:00:01:30,,,,,,,\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / "02-devices_config.csv"
            inventory.write_text(header + rows, encoding="utf-8")
            devices = {
                device["hostname"]: device
                for device in monitor.read_devices(
                    inventory, "all", air_json=root / "missing-air.json",
                    dhcp_leases=None,
                )
            }
        self.assertEqual(
            ["192.0.2.150", "192.0.2.145"],
            devices["EXAMPLE-OOB-Leaf03"]["ssh_ips"],
        )
        self.assertEqual(
            ["192.0.2.150", "192.0.2.145"],
            devices["AIR-EXAMPLE-OOB-Leaf03"]["ssh_ips"],
        )
        self.assertEqual(
            {"192.0.2.150": "eth0", "192.0.2.145": "vlan100"},
            devices["AIR-EXAMPLE-OOB-Leaf03"]["ssh_interfaces"],
        )

    def test_ztp_monitor_ssh_falls_back_after_eth0_is_unreachable(self):
        monitor = load_module("day0_ztp_monitor_ssh_fallback", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        device = {
            "hostname": "EXAMPLE-OOB-Staging-Leaf03", "type": "eth", "template": "oobofoob-leaf",
            "ip": "192.0.2.150", "ssh_ips": ["192.0.2.150", "192.0.2.145"],
            "ssh_user": "cumulus", "mac_plain": "0200000000c0",
        }

        def fake_run(command, timeout=20):
            target = next((part for part in command if part.startswith("cumulus@")), "")
            if target.endswith("@192.0.2.150"):
                return {"returncode": 255, "stdout": "", "stderr": "No route to host"}
            return {
                "returncode": 0,
                "stdout": "__HOSTNAME_BEGIN__\nOOB-Staging-Leaf03\n__HOSTNAME_END__\n",
                "stderr": "",
            }

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            monitor, "run_command", side_effect=fake_run,
        ):
            result = monitor.collect_switch(
                device, 2, None, Path(directory) / "known_hosts"
            )
        self.assertEqual("ok", result["kind"])
        self.assertEqual("192.0.2.145", result["connected_ip"])
        self.assertIn("192.0.2.150", result["attempt_errors"][0])
        self.assertEqual([
            {"ip": "192.0.2.150", "status": "failed", "error": "No route to host"},
            {"ip": "192.0.2.145", "status": "success", "error": ""},
        ], result["attempts"])

    def test_ztp_ip_cell_colors_failed_and_connected_candidates(self):
        html = load_module(
            "monitor_ztp_ip_probe_colors", ROOT / "monitor/generate-monitor-html.py",
        )
        stages = {
            name: {"status": "pending"}
            for name in ("dhcp", "bootstrap", "config_http", "ssh", "network",
                         "version", "config_apply", "ssh_keys", "complete")
        }
        status = {
            "available": True, "generated_at": "2026-08-24T10:00:00+08:00",
            "devices": [{
                "hostname": "AIR-EXAMPLE-Leaf03", "type": "air", "ip": "192.0.2.150",
                "mac": "02:00:00:00:00:03", "stages": stages,
                "overall": "warning", "progress": {"percent": 80}, "issues": [],
                "ip_probe": {
                    "candidates": ["192.0.2.150", "192.0.2.145"],
                    "interfaces": {
                        "192.0.2.150": "eth0", "192.0.2.145": "vlan100",
                    },
                    "connected_ip": "192.0.2.145",
                    "attempts": [
                        {"ip": "192.0.2.150", "status": "failed"},
                        {"ip": "192.0.2.145", "status": "success"},
                    ],
                },
            }],
        }
        rows = html.render_ztp_status_rows(status)
        self.assertRegex(rows, r'ztp-ip-failed[^>]*>.*eth0:</span> 192\.0\.2\.150</span>')
        self.assertRegex(rows, r'ztp-ip-success[^>]*>.*vlan100:</span> 192\.0\.2\.145</span>')

    def test_dynamic_air_dhcp_success_and_eth0_address_are_yellow(self):
        html = load_module(
            "monitor_dynamic_air_dhcp_color", ROOT / "monitor/generate-monitor-html.py",
        )
        stages = {
            name: {"status": "pending", "success_index": 0}
            for name in ("dhcp", "bootstrap", "config_http", "ssh", "network",
                         "version", "config_apply", "ssh_keys", "complete")
        }
        stages["dhcp"] = {
            "status": "success", "success_index": 1,
            "detail": "DHCPACK 192.0.2.21",
        }
        rendered = html.render_ztp_status_rows({
            "available": True,
            "generated_at": "2026-08-30T17:00:00+08:00",
            "devices": [{
                "hostname": "AIR-EXAMPLE-FW01", "type": "air", "template": "fw",
                "ip": "192.0.2.21", "mac": "02:00:00:00:00:21",
                "dynamic_dhcp": True, "address_source": "dhcp-event",
                "ztp_round": 1, "stages": stages, "overall": "running",
                "progress": {"percent": 10}, "issues": [],
                "ip_probe": {
                    "candidates": ["192.0.2.21"],
                    "interfaces": {"192.0.2.21": "eth0"},
                    "connected_ip": "192.0.2.21",
                    "attempts": [{"ip": "192.0.2.21", "status": "success"}],
                },
            }],
        })
        self.assertIn('data-group="air__other"', rendered)
        self.assertIn('ztp-success ztp-dhcp-dynamic">成功1', rendered)
        self.assertIn('class="ztp-ip ztp-ip-dynamic"', rendered)
        self.assertIn("地址由动态 DHCP 分配", rendered)

    def test_missing_eth0_ip_renders_bound_ztp_transit_address_yellow(self):
        html = load_module(
            "monitor_ztp_transit_fallback_color",
            ROOT / "monitor/generate-monitor-html.py",
        )
        stages = {
            name: {"status": "pending", "success_index": 0}
            for name in ("dhcp", "bootstrap", "config_http", "ssh", "network",
                         "version", "config_apply", "ssh_keys", "complete")
        }
        stages["dhcp"] = {
            "status": "success", "success_index": 1,
            "detail": "DHCPACK 198.51.100.201",
        }
        rendered = html.render_ztp_status_rows({
            "available": True,
            "generated_at": "2026-08-31T14:37:01+08:00",
            "devices": [{
                "hostname": "AIR-EXAMPLE-FGT-FW", "type": "air", "ip": "",
                "mac": "02:00:00:00:00:49", "ztp_round": 1,
                "stages": stages, "overall": "warning",
                "progress": {"percent": 33}, "issues": [],
                "ssh_ips": ["198.51.100.201"],
                "ztp_transport_ips": ["198.51.100.201"],
                "ip_probe": {
                    "candidates": ["198.51.100.201"],
                    "interfaces": {"198.51.100.201": "ZTP transit (swp2)"},
                    "connected_ip": "198.51.100.201",
                    "attempts": [{
                        "ip": "198.51.100.201", "status": "success",
                    }],
                },
            }],
        })
        self.assertIn('class="ztp-ip ztp-ip-dynamic"', rendered)
        self.assertIn("ZTP transit (swp2):", rendered)
        self.assertIn("198.51.100.201", rendered)
        self.assertIn("ZTP transit 地址已通过双重 MAC 校验", rendered)
        self.assertNotIn("DHCP 未分配", rendered)

    def test_unused_vlan_candidate_is_rendered_gray(self):
        html = load_module(
            "monitor_ztp_unused_vlan_gray", ROOT / "monitor/generate-monitor-html.py",
        )
        stages = {name: {"status": "pending"} for name in (
            "dhcp", "bootstrap", "config_http", "ssh", "network", "version",
            "config_apply", "ssh_keys", "complete",
        )}
        status = {
            "available": True, "generated_at": "2026-08-24T10:00:00+08:00",
            "devices": [{
                "hostname": "EXAMPLE-Leaf03", "type": "eth", "ip": "192.0.2.150",
                "mac": "02:00:00:00:00:03", "stages": stages,
                "overall": "success", "progress": {"percent": 100}, "issues": [],
                "ip_probe": {
                    "candidates": ["192.0.2.150", "192.0.2.145"],
                    "interfaces": {
                        "192.0.2.150": "eth0", "192.0.2.145": "vlan100",
                    },
                    "connected_ip": "192.0.2.150",
                    "attempts": [{"ip": "192.0.2.150", "status": "success"}],
                },
            }],
        }
        rows = html.render_ztp_status_rows(status)
        self.assertRegex(rows, r'ztp-ip-neutral[^>]*>.*vlan100:</span> 192\.0\.2\.145</span>')

    def test_ztp_shared_ip_events_belong_only_to_observed_mac(self):
        monitor = load_module("day0_ztp_monitor_identity", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        devices = [
            {
                "hostname": "EXAMPLE-Border01", "type": "eth", "ip": "192.0.2.10",
                "mac_plain": "020000000001", "events": [],
                "stages": {name: monitor.stage() for name in monitor.STAGE_NAMES},
            },
            {
                "hostname": "AIR-EXAMPLE-Border01", "type": "air", "ip": "192.0.2.10",
                "mac_plain": "020000000002", "events": [],
                "stages": {name: monitor.stage() for name in monitor.STAGE_NAMES},
            },
        ]
        dhcp = [{
            "kind": "DHCPACK", "mac_plain": "020000000002", "ip": "192.0.2.10",
            "timestamp": "2026-08-24T14:30:00+08:00", "raw": "DHCPACK",
        }]
        apache = [{
            "ip": "192.0.2.10", "path": "/ztp/ztp-bootstrap_oob.sh",
            "method": "GET", "status": 200,
            "timestamp": "2026-08-24T14:30:01+08:00", "raw": "GET",
        }]

        owners = monitor.correlate_server_events(devices, dhcp, apache)
        self.assertIs(owners["192.0.2.10"], devices[1])
        self.assertEqual("pending", devices[0]["stages"]["dhcp"]["status"])
        self.assertEqual("pending", devices[0]["stages"]["bootstrap"]["status"])
        self.assertEqual("success", devices[1]["stages"]["dhcp"]["status"])
        self.assertEqual("success", devices[1]["stages"]["bootstrap"]["status"])
        self.assertEqual([devices[1]], monitor.devices_for_switch_collection(devices, owners))

    def test_air_hostname_keeps_environment_prefix(self):
        monitor = load_module("day0_ztp_monitor_air_hostname", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        device = {
            "hostname": "AIR-EXAMPLE-OOBofOOB-Leaf01", "type": "air",
            "ip": "192.0.2.10", "issues": [],
            "stages": {name: monitor.stage() for name in monitor.STAGE_NAMES},
        }
        result = {
            "kind": "ok", "stderr": "", "remote_hostname": "AIR-EXAMPLE-OOBOFOOB-Leaf01",
            "host_key_refreshed": False, "ztp_log": "", "ifreload_log": "",
            "failed_yaml": "", "host_key_commands": [],
        }
        monitor.analyze_switch(device, result)
        self.assertNotIn("HOSTNAME_MISMATCH", {issue["code"] for issue in device["issues"]})

    def test_ztp_completion_uses_device_log_timestamp(self):
        monitor = load_module(
            "day0_ztp_completion_timestamp", ROOT / "DAY0-Prepare/12-ztp-monitor.py"
        )
        timestamp = monitor.ztp_completion_timestamp(
            "[2026-08-24 06:31:07] [ZTP] Cumulus provision complete\n"
            "[2026-08-24 06:31:08] ======================== ZTP FINISH ========================\n",
            monitor.dt.timezone.utc,
        )
        self.assertEqual("2026-08-24T06:31:07+00:00", timestamp)
        self.assertEqual(
            "2026-08-24T06:30:58+00:00",
            monitor.ztp_event_timestamp(
                "[2026-08-24 06:30:58] [ZTP] Network check passed: vrf=default\n",
                r"Network check passed", monitor.dt.timezone.utc,
            ),
        )
        self.assertEqual(
            "2026-08-24T06:31:07+00:00",
            monitor.ztp_completion_timestamp(
                "[2026-08-24T06:31:07Z] [ZTP] Cumulus provision complete\n",
                monitor.dt.timezone(monitor.dt.timedelta(hours=8)),
            ),
        )
        self.assertEqual(
            "2026-08-24T06:30:58+00:00",
            monitor.ztp_event_timestamp(
                "[2026-08-24T06:30:58Z] [ZTP] Network check passed: vrf=default\n",
                r"Network check passed",
                monitor.dt.timezone(monitor.dt.timedelta(hours=8)),
            ),
        )

    def test_bootstrap_logs_use_rfc3339_utc(self):
        expected = "date -u '+%Y-%m-%dT%H:%M:%SZ'"
        legacy = "date '+%Y-%m-%d %H:%M:%S'"
        source = (ROOT / "ztp/templates/ztp-bootstrap.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(expected, source)
        self.assertNotIn(legacy, source)

    def test_switch_log_stages_keep_their_own_event_times(self):
        monitor = load_module(
            "day0_ztp_stage_event_times", ROOT / "DAY0-Prepare/12-ztp-monitor.py"
        )
        device = {
            "hostname": "EXAMPLE-Leaf01", "type": "eth", "ip": "192.0.2.10",
            "issues": [], "ssh_ips": ["192.0.2.10"],
            "ssh_interfaces": {"192.0.2.10": "eth0"},
            "stages": {name: monitor.stage() for name in monitor.STAGE_NAMES},
        }
        log = "\n".join([
            "[2026-08-24 06:30:50] ======================== ZTP START ========================",
            "[2026-08-24 06:30:51] [ZTP] Network check passed: vrf=default",
            "[2026-08-24 06:30:52] [ZTP] Version matched, continue provisioning",
            "[2026-08-24 06:30:53] [ZTP] Load per-MAC config:leaf.yaml",
            "[2026-08-24 06:30:54] [ZTP] Dedicated config:leaf.yaml apply and save complete",
            "[2026-08-24 06:30:55] [ZTP] SSH public key installed: id_ed25519.pub",
            "[2026-08-24 06:30:56] [ZTP] Cumulus provision complete",
            "[2026-08-24 06:30:57] ======================== ZTP FINISH ========================",
        ])
        monitor.analyze_switch(device, {
            "kind": "ok", "connected_ip": "192.0.2.10", "attempts": [],
            "observed_at": "2026-08-24T06:31:00+00:00", "stderr": "",
            "remote_hostname": "EXAMPLE-Leaf01", "host_key_refreshed": False,
            "ztp_log": log, "ifreload_log": "", "failed_yaml": "",
            "host_key_commands": [],
        }, monitor.dt.timezone.utc)
        self.assertEqual(
            "2026-08-24T06:30:51+00:00", device["stages"]["network"]["timestamp"]
        )
        self.assertEqual(
            "2026-08-24T06:30:54+00:00", device["stages"]["config_apply"]["timestamp"]
        )
        self.assertEqual(
            "2026-08-24T06:30:56+00:00", device["stages"]["complete"]["timestamp"]
        )
        self.assertEqual(
            "2026-08-24T06:31:00+00:00", device["stages"]["ssh"]["timestamp"]
        )

    def test_reboot_ignores_completion_log_from_previous_boot(self):
        monitor = load_module(
            "day0_ztp_reboot_cycle", ROOT / "DAY0-Prepare/12-ztp-monitor.py"
        )
        device = {
            "hostname": "EXAMPLE-Leaf01", "type": "eth", "ip": "192.0.2.10",
            "issues": [], "ssh_ips": ["192.0.2.10"],
            "ssh_interfaces": {"192.0.2.10": "eth0"},
            "stages": {name: monitor.stage() for name in monitor.STAGE_NAMES},
        }
        monitor.analyze_switch(device, {
            "kind": "ok", "connected_ip": "192.0.2.10", "attempts": [],
            "observed_at": "2026-08-24T07:00:00+00:00", "stderr": "",
            "remote_hostname": "EXAMPLE-Leaf01", "host_key_refreshed": False,
            "boot_id": "new-boot", "boot_time": "2000000000",
            "ztp_log": (
                "[2026-08-24 06:30:56] [ZTP] Cumulus provision complete\n"
                "[2026-08-24 06:30:57] ======================== ZTP FINISH ========================\n"
            ),
            "ifreload_log": "", "failed_yaml": "", "host_key_commands": [],
        }, monitor.dt.timezone.utc)
        self.assertEqual("pending", device["stages"]["complete"]["status"])
        self.assertIn(
            "STALE_ZTP_LOG_AFTER_REBOOT",
            {issue["code"] for issue in device["issues"]},
        )

    def test_completion_signature_changes_for_a_new_boot_cycle(self):
        monitor = load_module(
            "day0_ztp_completion_cycle", ROOT / "DAY0-Prepare/12-ztp-monitor.py"
        )
        def report(boot_id, timestamp):
            return {"devices": [{
                "hostname": "EXAMPLE-Leaf01", "boot_id": boot_id,
                "stages": {"complete": {"status": "success", "timestamp": timestamp}},
            }]}
        first = monitor.completion_signature(report("boot-a", "2026-08-24T06:00:00+00:00"))
        same = monitor.completion_signature(report("boot-a", "2026-08-24T06:00:00+00:00"))
        second = monitor.completion_signature(report("boot-b", "2026-08-24T08:00:00+00:00"))
        self.assertEqual(first, same)
        self.assertNotEqual(first, second)

    def test_monitor_page_has_restricted_start_stop_control(self):
        html = (ROOT / "monitor/generate-monitor-html.py").read_text(encoding="utf-8")
        ztp_cgi = (ROOT / "monitor/ztp-monitor-control.cgi").read_text(encoding="utf-8")
        switch_cgi = (ROOT / "monitor/switch-collection-control.cgi").read_text(encoding="utf-8")
        self.assertIn("/cgi-bin/ztp-monitor-control", html)
        self.assertIn("/cgi-bin/switch-collection-control", html)
        self.assertIn("结束 ZTP 监控", html)
        self.assertIn("开始 ZTP 监控", html)
        self.assertIn("X-Requested-With", html)
        self.assertIn("action not in {\"start\", \"stop\"}", ztp_cgi)
        self.assertNotIn("collect", ztp_cgi)
        self.assertIn('action not in {"collect", "stop"}', switch_cgi)
        self.assertIn("body: `action=${{action}}`", html)
        self.assertIn("立即收集 Switch Status", html)
        self.assertIn("停止收集", html)
        self.assertIn("label.textContent = '收集中'", html)
        self.assertNotIn("subprocess", ztp_cgi)
        self.assertNotIn("subprocess", switch_cgi)

    def test_ztp_control_does_not_recognize_switch_collection_request(self):
        monitor = load_module(
            "day0_ztp_isolated_control", ROOT / "DAY0-Prepare/12-ztp-monitor.py"
        )
        with tempfile.TemporaryDirectory() as directory:
            control = Path(directory) / "ztp-monitor.control"
            control.write_text("collect\n", encoding="utf-8")
            self.assertEqual("running", monitor.monitor_control_state(control))

    def test_switch_worker_resources_are_separate_from_ztp(self):
        worker = (ROOT / "monitor/switch-collection-worker.py").read_text(encoding="utf-8")
        switch_cgi = (ROOT / "monitor/switch-collection-control.cgi").read_text(encoding="utf-8")
        for text in (worker, switch_cgi):
            self.assertIn("switch-collection.request", text)
            self.assertIn("switch-collection.pid", text)
            self.assertNotIn("ztp-monitor.control", text)
            self.assertNotIn("ztp-monitor.pid", text)

    def test_switch_collection_pending_request_is_reported_independently(self):
        with tempfile.TemporaryDirectory() as directory:
            cgi_copy = Path(directory) / "switch_collection_cgi.py"
            cgi_copy.write_text(
                (ROOT / "monitor/switch-collection-control.cgi").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            cgi = load_module("switch_collection_cgi", cgi_copy)
            request = Path(directory) / "switch-collection.request"
            request.write_text("collect\n", encoding="utf-8")
            with mock.patch.object(cgi, "REQUEST_FILE", request):
                self.assertEqual("collect", cgi.request_action())

    def test_switch_worker_scope_commands_are_fixed(self):
        worker = load_module(
            "switch_collection_worker", ROOT / "monitor/switch-collection-worker.py"
        )
        air = worker.commands_for_scope("air")
        prod = worker.commands_for_scope("prod")
        self.assertEqual("--air", air[0][-1])
        self.assertIn("--wait-lock", air[0])
        self.assertEqual("600", air[0][air[0].index("--wait-lock") + 1])
        self.assertNotIn("--prod", [item for command in air for item in command])
        self.assertEqual("--prod", prod[0][-1])
        self.assertEqual(3, len(prod))

    def test_manual_collection_waits_for_existing_cron_lock(self):
        for relative in (
            "ethernet/monitor/cron.sh",
            "infiniband/monitor/cron.sh",
            "nvlink/monitor/cron.sh",
        ):
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("--wait-lock", source)
            self.assertIn('flock "${lock_args[@]}" 200', source)
            self.assertIn("LOCK_WAIT=0", source)

    def test_switch_stop_targets_only_known_collection_scripts(self):
        source = (ROOT / "monitor/switch-collection-worker.py").read_text(encoding="utf-8")
        self.assertIn("def stop_all_collectors", source)
        self.assertIn("any(argument in scripts for argument in argv)", source)
        self.assertIn('if claim_request("stop") == "stop"', source)
        self.assertNotIn("pkill", source)

    def test_switch_collection_column_reports_success_and_failure(self):
        html = load_module(
            "monitor_switch_collection_result", ROOT / "monitor/generate-monitor-html.py"
        )
        success = html.make_missing_switch("EXAMPLE-Leaf01", "ETH")
        success.update({
            "health": "ok", "collect_time": "2026-08-24 18:30:00",
            "collection_error": "",
        })
        success_row = html.render_sw_list_row(success)
        self.assertIn("collect-ok", success_row)
        self.assertIn("成功 · 2026-08-24 18:30:00", success_row)

        failure = html.make_missing_switch("EXAMPLE-Leaf02", "ETH")
        failure["collection_attempt_time"] = "2026-08-24 18:31:00"
        failure_row = html.render_sw_list_row(failure)
        self.assertIn("collect-fail", failure_row)
        self.assertIn("失败 · 2026-08-24 18:31:00", failure_row)
        self.assertIn("本批次未返回采集文件", failure_row)

    def test_production_archive_name_provides_collection_time(self):
        html = load_module(
            "monitor_prod_archive_time", ROOT / "monitor/generate-monitor-html.py"
        )
        parsed = html.parse_archive_time_utc(Path("20260824-1030-prod.tar.gz"))
        self.assertIsNotNone(parsed)

    def test_paused_monitor_wait_does_not_busy_spin(self):
        monitor = load_module(
            "day0_ztp_pause_wait", ROOT / "DAY0-Prepare/12-ztp-monitor.py"
        )
        with mock.patch.object(
            monitor, "monitor_control_state", side_effect=["paused", "running"]
        ), mock.patch.object(
            monitor.time, "monotonic", side_effect=[0, 0, 1, 2]
        ), mock.patch.object(monitor.time, "sleep") as sleep:
            monitor.paused_sleep(10)
        sleep.assert_called_once_with(2)

    def test_ztp_row_puts_event_times_under_status_and_simplifies_overall(self):
        html = load_module(
            "monitor_ztp_completion_time", ROOT / "monitor/generate-monitor-html.py"
        )
        stages = {name: {"status": "success", "timestamp": ""} for name in (
            "dhcp", "bootstrap", "config_http", "ssh", "network", "version",
            "config_apply", "ssh_keys", "complete",
        )}
        stages["complete"]["timestamp"] = "2026-08-24T06:31:07+00:00"
        status = {
            "available": True, "generated_at": "2026-08-24T14:52:10+08:00",
            "devices": [{
                "hostname": "EXAMPLE-Leaf01", "type": "eth", "ip": "192.0.2.10",
                "mac": "02:00:00:00:00:01", "stages": stages,
                "observed_at": "2026-08-24T14:52:09+08:00",
                "overall": "success", "progress": {"percent": 100}, "issues": [],
            }],
        }
        rows = html.render_ztp_status_rows(status)
        self.assertIn(
            '<span class="ztp-event-time">'
            + html.format_ztp_write_time("2026-08-24T06:31:07+00:00")
            + "</span>",
            rows,
        )
        self.assertNotIn("完成：", rows)
        self.assertIn(
            "检查：" + html.format_ztp_write_time("2026-08-24T14:52:09+08:00"),
            rows,
        )
        self.assertNotIn(
            "检查：" + html.format_ztp_write_time("2026-08-24T14:52:10+08:00"),
            rows,
        )
        self.assertIn(
            '<div class="ztp-meta-row ztp-overall-result">'
            '<span class="ztp-state ztp-success">成功1</span>'
            '<span class="ztp-write-time">来源：自动</span></div>',
            rows,
        )
        self.assertIn(
            '<span class="ztp-diagnosis" title="">原因：-</span>', rows,
        )

    def test_air_completion_handoff_uses_scoped_collection(self):
        monitor = load_module("day0_ztp_monitor_handoff", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        scripts = {
            "ethernet": Path("/collect/ethernet.sh"),
            "infiniband": Path("/collect/infiniband.sh"),
            "nvlink": Path("/collect/nvlink.sh"),
        }
        commands = monitor.completion_collection_commands(
            {"devices": [{"type": "air"}]}, scripts,
        )
        self.assertEqual([["bash", "/collect/ethernet.sh", "--air"]], commands)

    def test_prod_completion_handoff_uses_scoped_collection(self):
        monitor = load_module("day0_ztp_monitor_prod_handoff", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        scripts = {
            "ethernet": Path("/collect/ethernet.sh"),
            "infiniband": Path("/collect/infiniband.sh"),
            "nvlink": Path("/collect/nvlink.sh"),
        }
        commands = monitor.completion_collection_commands(
            {"devices": [{"type": "eth"}, {"type": "ib"}]}, scripts,
        )
        self.assertEqual([
            ["bash", "/collect/ethernet.sh", "--prod"],
            ["bash", "/collect/infiniband.sh"],
        ], commands)

    def test_all_scope_handoff_collects_air_and_prod(self):
        monitor = load_module("day0_ztp_monitor_all_handoff", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        scripts = {
            "ethernet": Path("/collect/ethernet.sh"),
            "infiniband": Path("/collect/infiniband.sh"),
            "nvlink": Path("/collect/nvlink.sh"),
        }
        commands = monitor.completion_collection_commands(
            {"devices": [{"type": "air"}, {"type": "eth"}, {"type": "nvl"}]}, scripts,
        )
        self.assertEqual([
            ["bash", "/collect/ethernet.sh", "--air"],
            ["bash", "/collect/ethernet.sh", "--prod"],
            ["bash", "/collect/nvlink.sh"],
        ], commands)

    def test_ztp_html_refresh_propagates_scope(self):
        monitor = load_module("day0_ztp_monitor_html_scope", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "generate-monitor-html.py"
            script.touch()
            with mock.patch.object(
                monitor, "run_command",
                return_value={"returncode": 0, "stdout": "", "stderr": ""},
            ) as run:
                self.assertTrue(monitor.generate_monitor_html(script, "air"))
            self.assertEqual(
                [sys.executable, str(script), "--type", "air"],
                run.call_args.args[0],
            )

    def test_completion_handoff_logs_collector_output_with_timezone(self):
        monitor = load_module("day0_ztp_monitor_logging", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "cron.sh"
            script.touch()
            report = {"devices": [{"type": "air"}]}
            output = io.StringIO()
            with mock.patch.object(
                monitor, "completion_collection_commands",
                return_value=[["bash", str(script), "--air"]],
            ), mock.patch.object(
                monitor, "run_command",
                return_value={"returncode": 0, "stdout": "cron output\n", "stderr": ""},
            ), mock.patch.object(
                monitor, "generate_monitor_html", return_value=True,
            ), contextlib.redirect_stdout(output):
                self.assertTrue(monitor.run_completion_handoff(report, Path("unused"), 60))
            text = output.getvalue()
            self.assertIn("[COLLECT][stdout] cron output", text)
            self.assertRegex(text, r"\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}\]")
            cron_log = (script.parent / "cronjob.log").read_text(encoding="utf-8")
            self.assertIn("[ZTP-HANDOFF][RUN]", cron_log)
            self.assertIn("cron output", cron_log)
            self.assertIn("[ZTP-HANDOFF][EXIT] 0", cron_log)

    def test_snapshot_history_keeps_only_three_timestamp_directories(self):
        monitor = load_module("day0_ztp_monitor_retention", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for number in range(5):
                (root / f"20260824_12000{number}").mkdir()
            (root / "fixed-data").mkdir()
            removed = monitor._prune_snapshot_history(root)
            self.assertEqual(2, len(removed))
            snapshots = sorted(path.name for path in root.iterdir() if path.name.startswith("2026"))
            self.assertEqual(
                ["20260824_120002", "20260824_120003", "20260824_120004"], snapshots,
            )
            self.assertTrue((root / "fixed-data").is_dir())

    def test_monitor_ssh_preparation_cannot_consume_host_list_stdin(self):
        script = (ROOT / "ethernet/monitor/cron.sh").read_text(encoding="utf-8")
        self.assertIn(
            'output=$(ssh -n $ssh_options "${user}@${candidate}" "$remote_command" 2>&1)',
            script,
        )

    def test_dynamic_air_monitor_accepts_default_hostname_only_after_mac_match(self):
        source = (ROOT / "ethernet/monitor/cron.sh").read_text(encoding="utf-8")

        def shell_function(name):
            start = source.index(f"{name}() {{")
            end = source.index("\n}\n", start) + 3
            return source[start:end]

        harness_source = "\n".join((
            "#!/bin/bash",
            shell_function("valid_host_entry"),
            shell_function("prepare_ssh_host_resilient"),
            r'''
ssh() {
    local remote="${!#}"
    hostname() { printf '%s\n' "$FAKE_HOSTNAME"; }
    cat() {
        if [[ "$1" == "/sys/class/net/eth0/address" ]]; then
            printf '%s\n' "$FAKE_MAC"
        else
            command cat "$@"
        fi
    }
    eval "$remote"
}
SSH_KEY='ssh-ed25519 AAAATEST monitor-test'
PREPARED_ENTRY=''
prepare_ssh_host_resilient 'AIR-EXAMPLE-FW01|192.0.2.21' cumulus "$TEST_ROOT/monitor" ''
result=$?
printf '__RC__=%s\n__PREPARED__=%s\n' "$result" "$PREPARED_ENTRY"
exit 0
''',
        ))

        def run_case(identity, actual_hostname, actual_mac):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                identities = root / "dynamic-identities"
                identities.write_text(identity, encoding="utf-8")
                harness = root / "harness.sh"
                harness.write_text(harness_source, encoding="utf-8")
                environment = os.environ.copy()
                environment.update({
                    "DYNAMIC_AIR_IDENTITIES": str(identities),
                    "FAKE_HOSTNAME": actual_hostname,
                    "FAKE_MAC": actual_mac,
                    "TEST_ROOT": str(root),
                    "HOME": str(root / "home"),
                })
                return subprocess.run(
                    ["bash", str(harness)], env=environment,
                    capture_output=True, text=True, check=False,
                )

        accepted = run_case(
            "AIR-EXAMPLE-FW01|02:00:00:00:00:21|dhcp-lease\n",
            "cumulus", "02:00:00:00:00:21",
        )
        self.assertIn("__RC__=0", accepted.stdout, accepted)
        self.assertIn("__PREPARED__=AIR-EXAMPLE-FW01|192.0.2.21", accepted.stdout)
        self.assertIn("MAC-VERIFIED-HOSTNAME-TRANSITION", accepted.stdout)

        wrong_mac = run_case(
            "AIR-EXAMPLE-FW01|02:00:00:00:00:21|dhcp-lease\n",
            "cumulus", "02:00:00:00:00:99",
        )
        self.assertIn("__RC__=11", wrong_mac.stdout, wrong_mac)
        self.assertIn("ETH0-MAC-MISMATCH", wrong_mac.stdout)

        ordinary_device = run_case("", "cumulus", "02:00:00:00:00:21")
        self.assertIn("__RC__=11", ordinary_device.stdout, ordinary_device)
        self.assertIn("HOSTNAME-MISMATCH", ordinary_device.stdout)

        self.assertIn('>> "$DYNAMIC_AIR_IDENTITIES"', source)

    def test_air_monitor_target_inherits_same_subnet_production_svi(self):
        script = (ROOT / "ethernet/monitor/cron.sh").read_text(encoding="utf-8")
        parser = re.search(
            r"if ! awk -F',' '(.*?)\n    ' mode=\"\$mode\"", script, re.S,
        )
        self.assertIsNotNone(parser)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / "eth.csv"
            inventory.write_text(
                "hostname,type,eth0_ip,netmask,svi_ip,netmask\n"
                "EXAMPLE-Leaf03,eth,192.0.2.150,26,192.0.2.145,26\n"
                "AIR-EXAMPLE-Site-Leaf03,air,192.0.2.150,26,NA,NA\n",
                encoding="utf-8",
            )
            outputs = {name: root / name for name in ("eth", "spx", "ib", "nv")}
            result = subprocess.run([
                "awk", "-F,", parser.group(1), "mode=eth", "filter=air",
                f"eth_file={outputs['eth']}", f"spx_file={outputs['spx']}",
                f"ib_file={outputs['ib']}", f"nv_file={outputs['nv']}",
                str(inventory),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(
                "AIR-EXAMPLE-Site-Leaf03|192.0.2.150|192.0.2.145\n",
                outputs["eth"].read_text(encoding="utf-8"),
            )

    def test_ethernet_cron_closes_loop_with_exact_archive(self):
        script = (ROOT / "ethernet/monitor/cron.sh").read_text(encoding="utf-8")
        archive_assignment = 'ETH_ARCHIVE="${dir}.tar.gz"'
        post_command = 'python3 "$POST_COLLECT"'
        self.assertIn(archive_assignment, script)
        self.assertIn('--archive "$ETH_ARCHIVE"', script)
        self.assertIn('--environment "${COLLECTION_ENV:-prod}"', script)
        self.assertLess(script.index(archive_assignment), script.index(post_command))
        self.assertIn(
            'python3 "$HTML_GENERATOR" --type "${COLLECTION_ENV:-prod}"',
            script,
        )
        self.assertIn('hosts_file_has_entries "$IB" || hosts_file_has_entries "$NV"', script)

    def test_ethernet_post_collect_accepts_mismatch_report_and_refreshes_scope(self):
        module = load_module(
            "ethernet_post_collect",
            ROOT / "ethernet/monitor/post-collect.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "20260830-1200-air.tar.gz"
            archive.write_bytes(b"archive")
            analyzer = root / "analyze_lldp.py"
            analyzer.touch()
            html_generator = root / "generate-monitor-html.py"
            html_generator.touch()
            output_dir = root / "99-output-p2p"
            output_dir.mkdir()
            air_dot = output_dir / "project-air.dot"
            air_dot.write_text('"AIR-EXAMPLE-A":"swp1" -- "AIR-EXAMPLE-B":"swp1"\n', encoding="utf-8")
            report = output_dir / "20260830-1200-air-ethernet-topology-validation.xlsx"

            def fake_run(command):
                if command[1] == str(analyzer):
                    report.write_bytes(b"xlsx")
                    return subprocess.CompletedProcess(command, 1, "mismatch\n", "")
                return subprocess.CompletedProcess(command, 0, "generated\n", "")

            with mock.patch.object(module, "ANALYZER", analyzer), \
                    mock.patch.object(module, "HTML_GENERATOR", html_generator), \
                    mock.patch.object(module, "OUTPUT_DIR", output_dir), \
                    mock.patch.object(module, "run_command", side_effect=fake_run) as run, \
                    contextlib.redirect_stdout(io.StringIO()):
                result = module.main([
                    "--archive", str(archive), "--environment", "air",
                ])

            self.assertEqual(0, result)
            self.assertEqual(2, run.call_count)
            analyze_command = run.call_args_list[0].args[0]
            self.assertEqual(
                str(archive.resolve()),
                analyze_command[analyze_command.index("--archive") + 1],
            )
            self.assertNotIn("--archive-dir", analyze_command)
            self.assertEqual(
                str(air_dot.resolve()),
                analyze_command[analyze_command.index("--dot") + 1],
            )
            self.assertEqual(
                [sys.executable, str(html_generator), "--type", "air"],
                run.call_args_list[1].args[0],
            )

    def test_ethernet_post_collect_does_not_refresh_html_without_report(self):
        module = load_module(
            "ethernet_post_collect_failure",
            ROOT / "ethernet/monitor/post-collect.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "20260830-1200-prod.tar.gz"
            archive.write_bytes(b"archive")
            analyzer = root / "analyze_lldp.py"
            analyzer.touch()
            html_generator = root / "generate-monitor-html.py"
            html_generator.touch()
            output_dir = root / "99-output-p2p"
            output_dir.mkdir()
            (output_dir / "project-lldpq.dot").write_text(
                '"A":"swp1" -- "B":"swp1"\n', encoding="utf-8",
            )
            failed = subprocess.CompletedProcess([], 2, "", "builder missing")
            with mock.patch.object(module, "ANALYZER", analyzer), \
                    mock.patch.object(module, "HTML_GENERATOR", html_generator), \
                    mock.patch.object(module, "OUTPUT_DIR", output_dir), \
                    mock.patch.object(module, "run_command", return_value=failed) as run, \
                    contextlib.redirect_stdout(io.StringIO()):
                result = module.main([
                    "--archive", str(archive), "--environment", "prod",
                ])
            self.assertEqual(2, result)
            self.assertEqual(1, run.call_count)


class ZtpDhcpLifecycleContractTests(unittest.TestCase):
    def test_variable_width_isc_mac_keeps_runtime_lease_lifecycle(self):
        monitor = load_module(
            "day0_dhcp_variable_width_mac_contract",
            ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        mac_plain = "0200000000c1"
        common = (
            " known=- vendor60_hex=- client61_hex=- user77_hex=-"
        )
        commit = (
            "2026-08-30T20:00:00+08:00 dhcpd ZTP_DHCP_EVENT_V1 "
            "event=commit msg=5 mac=2:0:0:0:0:c1 ip=192.0.2.21"
            f"{common} lease_state=active\n"
        )
        release = (
            "2026-08-30T20:00:01+08:00 dhcpd ZTP_DHCP_EVENT_V1 "
            "event=release msg=7 mac=2:0:0:0:0:c1 ip=192.0.2.21"
            f"{common} lease_state=released\n"
        )
        expiry = (
            "2026-08-30T20:00:02+08:00 dhcpd ZTP_DHCP_EVENT_V1 "
            "event=expiry msg=- mac=2:0:0:0:0:c1 ip=192.0.2.21"
            f"{common} lease_state=expired\n"
        )

        events = monitor.parse_dhcp(commit + release + expiry)
        self.assertEqual(
            ["LEASE_COMMIT", "LEASE_RELEASE", "LEASE_EXPIRY"],
            [event["kind"] for event in events],
        )
        self.assertEqual({mac_plain}, {event["mac_plain"] for event in events})

        def dynamic_device():
            return {
                "hostname": "EXAMPLE-UNKNOWN-0200000000c1",
                "dynamic_dhcp": True,
                "mac_plain": mac_plain,
                "ip": "",
                "ssh_ips": [],
                "lease_state": "active",
                "address_source": "unresolved",
                "issues": [],
                "unbound_identity": True,
                "platform_family": "cumulus",
            }

        committed = dynamic_device()
        monitor.apply_dynamic_dhcp_addresses(
            [committed], monitor.parse_dhcp(commit),
        )
        self.assertEqual("192.0.2.21", committed["ip"])

        released = dynamic_device()
        monitor.apply_dynamic_dhcp_addresses(
            [released], monitor.parse_dhcp(commit + release),
        )
        self.assertEqual("", released["ip"])

        expired = dynamic_device()
        monitor.apply_dynamic_dhcp_addresses(
            [expired], monitor.parse_dhcp(commit + expiry),
        )
        self.assertEqual("", expired["ip"])

    def test_release_clears_live_ip_and_old_ack_cannot_restore_it(self):
        runtime = load_module(
            "dhcp_runtime_release_contract", ROOT / "ztp/dhcp_runtime_inventory.py",
        )
        monitor = load_module(
            "day0_dhcp_release_contract", ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / "02-devices_config.csv"
            inventory.write_text(
                "hostname,type,template,eth0_ip,netmask,eth0_mac\n",
                encoding="utf-8",
            )
            leases = root / "dhcpd.leases"
            leases.write_text(
                "lease 192.0.2.21 {\n"
                "  starts 3 2026/08/30 10:00:00;\n"
                "  ends 3 2099/08/30 13:00:00;\n"
                "  binding state active;\n"
                "  hardware ethernet 02:00:00:00:00:21;\n}\n",
                encoding="utf-8",
            )
            journal = (
                "2026-08-30T20:00:00+08:00 dhcpd ZTP_DHCP_EVENT_V1 "
                "event=packet msg=1 mac=02:00:00:00:00:21 ip=- known=0 "
                "vendor60_hex=43:75:6d:75:6c:75:73 client61_hex=- user77_hex=-\n"
                "2026-08-30T20:00:01+08:00 dhcpd ZTP_DHCP_EVENT_V1 "
                "event=commit msg=5 mac=02:00:00:00:00:21 ip=192.0.2.21 "
                "known=- vendor60_hex=- client61_hex=- user77_hex=- lease_state=active\n"
                "2026-08-30T20:00:02+08:00 dhcpd ZTP_DHCP_EVENT_V1 "
                "event=release msg=7 mac=02:00:00:00:00:21 ip=192.0.2.21 "
                "known=- vendor60_hex=- client61_hex=- user77_hex=- lease_state=released\n"
            )

            discovered = runtime.unknown_dhcp_devices(
                journal_text=journal, lease_path=leases, inventory_path=inventory,
            )
            self.assertEqual(1, len(discovered))
            self.assertIsNone(discovered[0]["ip"])
            self.assertEqual("192.0.2.21", discovered[0]["last_lease_ip"])
            self.assertEqual("released", discovered[0]["lease_state"])

            devices = monitor.runtime_unknown_devices(
                inventory, journal, scope="prod", dhcp_leases=leases,
            )
            self.assertEqual(1, len(devices))
            device = devices[0]
            self.assertEqual("", device["ip"])
            self.assertEqual([], device["ssh_ips"])
            self.assertFalse(device["ssh_collect_enabled"])
            self.assertEqual("running", device["stages"]["dhcp"]["status"])
            self.assertIn(
                "DHCP_LEASE_NOT_ACTIVE",
                {issue["code"] for issue in device["issues"]},
            )

            events = monitor.parse_dhcp(
                "2026-08-30T19:59:59+08:00 DHCPACK on 192.0.2.21 "
                "to 02:00:00:00:00:21 via eth0\n" + journal
            )
            monitor.apply_dynamic_dhcp_addresses(devices, events)
            self.assertEqual("", device["ip"])
            self.assertEqual([], device["ssh_ips"])
            self.assertEqual({}, device["candidate_identity"])

    def test_older_lease_file_and_ack_do_not_override_new_journal_commit(self):
        runtime = load_module(
            "dhcp_runtime_recency_contract", ROOT / "ztp/dhcp_runtime_inventory.py",
        )
        monitor = load_module(
            "day0_dhcp_recency_contract", ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / "02-devices_config.csv"
            inventory.write_text(
                "hostname,type,template,eth0_ip,netmask,eth0_mac\n",
                encoding="utf-8",
            )
            leases = root / "dhcpd.leases"
            leases.write_text(
                "lease 192.0.2.21 {\n"
                "  starts 3 2026/08/30 10:00:00;\n"
                "  ends 3 2099/08/30 13:00:00;\n"
                "  binding state active;\n"
                "  hardware ethernet 02:00:00:00:00:21;\n}\n",
                encoding="utf-8",
            )
            journal = (
                "2026-08-30T20:00:00+08:00 dhcpd ZTP_DHCP_EVENT_V1 "
                "event=packet msg=1 mac=02:00:00:00:00:21 ip=- known=0 "
                "vendor60_hex=43:75:6d:75:6c:75:73 client61_hex=- user77_hex=-\n"
                "2026-08-30T20:00:01+08:00 dhcpd ZTP_DHCP_EVENT_V1 "
                "event=commit msg=5 mac=02:00:00:00:00:21 ip=192.0.2.22 "
                "known=- vendor60_hex=- client61_hex=- user77_hex=- lease_state=active\n"
            )
            discovered = runtime.unknown_dhcp_devices(
                journal_text=journal, lease_path=leases, inventory_path=inventory,
            )
            self.assertEqual("192.0.2.22", discovered[0]["ip"])
            self.assertEqual("192.0.2.22", discovered[0]["last_lease_ip"])

            device = {
                "hostname": "AIR-EXAMPLE-FW01", "dynamic_dhcp": True,
                "mac_plain": "020000000021", "ip": "192.0.2.22",
                "ssh_ips": ["192.0.2.22"], "lease_state": "active",
                "address_source": "dhcp-lease", "issues": [],
            }
            old_ack = monitor.parse_dhcp(
                "2026-08-30T19:00:00+08:00 DHCPACK on 192.0.2.21 "
                "to 02:00:00:00:00:21 via eth0\n"
            )
            monitor.apply_dynamic_dhcp_addresses([device], old_ack)
            self.assertEqual("192.0.2.22", device["ip"])
            self.assertEqual(["192.0.2.22"], device["ssh_ips"])

    def test_nvos_success_skips_cumulus_version_stage_and_reaches_100(self):
        monitor = load_module(
            "day0_nvos_version_contract", ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        mac_plain = "020000000031"
        device = {
            "hostname": "EXAMPLE-IB-Leaf01", "type": "ib", "template": "leaf",
            "ip": "192.0.2.31", "ssh_ips": ["192.0.2.31"],
            "ssh_interfaces": {"192.0.2.31": "eth0"},
            "mac": "02:00:00:00:00:31", "mac_plain": mac_plain,
            "candidate_identity": {"192.0.2.31": ("eth0", mac_plain)},
            "stages": {name: monitor.stage() for name in monitor.STAGE_NAMES},
            "issues": [], "events": [], "ztp_round": 1,
        }
        device["stages"]["dhcp"] = monitor.stage(
            "success", "DHCPACK", "2026-08-30T20:00:00+08:00",
        )
        ztp_log = "\n".join((
            "[2026-08-30 20:00:01] [ZTP] ZTP START",
            "[2026-08-30 20:00:02] [ZTP] Network check passed",
            "[2026-08-30 20:00:03] [ZTP] Load per-MAC config:http://mgmt/020000000031.yaml",
            "[2026-08-30 20:00:04] [ZTP] Dedicated config:020000000031.yaml apply and save complete",
            "[2026-08-30 20:00:05] [ZTP] SSH public key installed: mgmt-server.pub",
            "[2026-08-30 20:00:06] [ZTP] NVOS provision complete",
            "[2026-08-30 20:00:06] [ZTP] ZTP FINISH",
        ))
        monitor.analyze_switch(device, {
            "kind": "ok", "observed_at": "2026-08-30T20:00:07+08:00",
            "connected_ip": "192.0.2.31", "attempts": [],
            "remote_hostname": "EXAMPLE-IB-Leaf01",
            "remote_eth0_mac": "02:00:00:00:00:31", "remote_eth1_mac": "",
            "boot_id": "boot-nvos-1", "boot_time": "0", "ztp_log": ztp_log,
            "ifreload_log": "", "failed_yaml": "", "stderr": "",
            "host_key_refreshed": False, "host_key_commands": [],
        }, monitor.dt.timezone(monitor.dt.timedelta(hours=8)))
        monitor.assign_stage_success_indices([device], None)
        monitor.finalize_device(device)
        self.assertEqual("skipped", device["stages"]["version"]["status"])
        self.assertEqual(1, device["stages"]["version"]["success_index"])
        self.assertEqual({"done": 9, "total": 9, "percent": 100}, device["progress"])
        self.assertEqual("success", device["overall"])

    def test_boot_identity_survives_missing_ztp_log(self):
        monitor = load_module(
            "day0_boot_without_log_contract", ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        mac_plain = "020000000031"
        device = {
            "hostname": "EXAMPLE-IB-Leaf01", "type": "ib", "ip": "192.0.2.31",
            "ssh_ips": ["192.0.2.31"], "ssh_interfaces": {"192.0.2.31": "eth0"},
            "mac_plain": mac_plain,
            "candidate_identity": {"192.0.2.31": ("eth0", mac_plain)},
            "stages": {name: monitor.stage() for name in monitor.STAGE_NAMES},
            "issues": [], "events": [],
        }
        monitor.analyze_switch(device, {
            "kind": "ok", "connected_ip": "192.0.2.31", "attempts": [],
            "remote_hostname": "EXAMPLE-IB-Leaf01",
            "remote_eth0_mac": "02:00:00:00:00:31", "remote_eth1_mac": "",
            "boot_id": "new-boot", "boot_time": "12345", "ztp_log": "",
            "ifreload_log": "", "failed_yaml": "", "stderr": "",
            "host_key_refreshed": False, "host_key_commands": [],
        })
        self.assertEqual("new-boot", device["boot_id"])
        self.assertEqual("12345", device["boot_time"])
        self.assertIn("ZTP_LOG_NOT_FOUND", {item["code"] for item in device["issues"]})

    def test_same_boot_dhcp_request_is_not_a_new_round(self):
        monitor = load_module(
            "day0_request_renewal_round_contract", ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        previous = {"devices": [{
            "hostname": "EXAMPLE-IB-Leaf01", "ztp_round": 1, "boot_id": "same-boot",
            "cycle_marker": "2026-08-30T20:00:00+08:00",
            "stages": {"complete": {"timestamp": "2026-08-30T20:05:00+08:00"}},
        }]}
        current = [{
            "hostname": "EXAMPLE-IB-Leaf01", "boot_id": "same-boot",
            "events": [{"source": "dhcp", "kind": "DHCPREQUEST",
                        "timestamp": "2026-08-30T20:10:00+08:00"}],
        }]
        monitor.assign_ztp_rounds(current, previous)
        self.assertEqual(1, current[0]["ztp_round"])

        rebooted = [dict(current[0], boot_id="new-boot")]
        monitor.assign_ztp_rounds(rebooted, previous)
        self.assertEqual(2, rebooted[0]["ztp_round"])

    def test_unbound_pending_or_promoting_device_blocks_completion_handoff(self):
        monitor = load_module(
            "day0_completion_identity_gate", ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        base = {"hostname": "EXAMPLE-Leaf01", "progress": {"percent": 100}}
        for flag in ("unbound_identity", "identity_pending", "promotion_pending"):
            device = dict(base, **{flag: True})
            self.assertFalse(monitor.all_devices_complete({"devices": [device]}), flag)
        self.assertTrue(monitor.all_devices_complete({"devices": [base]}))


class DhcpUnifiedInventoryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dhcp = load_module(
            "dhcp_unified_inventory_contract",
            ROOT / "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
        )

    def load_subnets(self, root: Path, rows: str, *, prefix: str = "/ztp"):
        source = root / "02-dhcp-subnet_config.csv"
        source.write_text(
            "shared_network,subnet,netmask,range_start,range_end,routers,"
            "ztp_service_ip,cumulus_profile,nvos_ztp\n" + rows,
            encoding="utf-8",
        )
        return self.dhcp.load_subnet_csv(source, prefix)

    def test_air_rows_are_rebuilt_at_eof_atomically_and_idempotently(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / "02-devices_config.csv"
            inventory.write_text(
                "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac\n"
                "Prod01,eth,leaf,192.0.2.10,24,192.0.2.1,02:00:00:00:00:01\n"
                "AIR-EXAMPLE-Stale,air,old,192.0.2.99,24,192.0.2.1,02:00:00:00:00:99\n"
                "EXAMPLE-Server01,server,NA,192.0.2.20,24,192.0.2.1,02:00:00:00:00:20\n",
                encoding="utf-8",
            )
            air_records = [{
                "hostname": "AIR-EXAMPLE-Prod01",
                "mac": "02:00:00:00:01:01",
            }]

            self.assertEqual(
                (1, 0, 0),
                self.dhcp.append_air_records_to_csv(
                    str(inventory), air_records, [], production_path=str(inventory)
                ),
            )
            first = inventory.read_bytes()
            with inventory.open(newline="", encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(["Prod01", "EXAMPLE-Server01", "AIR-EXAMPLE-Prod01"], [r["hostname"] for r in rows])
            self.assertEqual("air", rows[-1]["type"])

            self.assertEqual("leaf", rows[-1]["template"])
            self.assertEqual("192.0.2.10", rows[-1]["eth0_ip"])

            second_records = [{
                "hostname": "AIR-EXAMPLE-Prod01",
                "mac": "02:00:00:00:01:01",
            }]
            self.assertEqual(
                (0, 0, 1),
                self.dhcp.append_air_records_to_csv(
                    str(inventory), second_records, [], production_path=str(inventory)
                ),
            )
            self.assertEqual(first, inventory.read_bytes())

    def test_site_prefixed_air_device_may_reuse_resolved_production_ip(self):
        production = {
            "hostname": "EXAMPLE-Staging-Border01", "type": "eth",
        }
        air = {
            "hostname": "AIR-EXAMPLE-SITE01-Staging-Border01", "type": "air",
            "production_hostname": "EXAMPLE-Staging-Border01",
        }
        self.assertTrue(self.dhcp._production_air_pair(production, air))

    def test_unrelated_air_device_cannot_reuse_production_ip(self):
        production = {"hostname": "EXAMPLE-Staging-Border01", "type": "eth"}
        air = {
            "hostname": "AIR-EXAMPLE-SITE01-Other01", "type": "air",
            "production_hostname": "Other01",
        }
        self.assertFalse(self.dhcp._production_air_pair(production, air))

    def test_static_record_mask_must_match_declared_dhcp_subnet(self):
        subnets = [{"_network": __import__("ipaddress").ip_network("198.51.100.128/25")}]
        records = [{
            "src": "devices.csv:2", "hostname": "EXAMPLE-TAN01", "iface": "eth0",
            "ip": "198.51.100.147", "netmask": "26",
        }]
        errors = self.dhcp.validate_records_against_subnets(records, subnets)
        self.assertEqual(1, len(errors))
        self.assertIn("198.51.100.128/26", errors[0])
        self.assertIn("198.51.100.128/25", errors[0])

    def test_out_of_scope_static_record_is_not_rejected(self):
        subnets = [{"_network": __import__("ipaddress").ip_network("192.0.2.0/24")}]
        records = [{
            "src": "devices.csv:2", "hostname": "EXAMPLE-Remote01", "iface": "eth0",
            "ip": "198.51.100.10", "netmask": "24",
        }]
        self.assertEqual(
            [], self.dhcp.validate_records_against_subnets(records, subnets)
        )

    def test_platform_boot_options_are_mutually_exclusive_and_cumulus_case_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "dhcpd.conf"
            subnets = self.load_subnets(
                root,
                "mgmt,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.200,"
                "192.0.2.1,192.0.2.2,oob,yes\n",
            )
            self.dhcp.write_dhcpd_conf(target, subnets)
            text = target.read_text(encoding="utf-8")
        self.assertIn(
            'substring(option vendor-class-identifier, 0, 7) = "cumulus"', text,
        )
        self.assertIn(
            'substring(option vendor-class-identifier, 0, 7) = "Cumulus"', text,
        )
        self.assertRegex(
            text,
            r'if substring\(option vendor-class-identifier, 0, 7\) = "cumulus"\n'
            r'\s+or substring\(option vendor-class-identifier, 0, 7\) = "Cumulus" \{\n'
            r'\s+option cumulus-provision-url .*?\n'
            r'\s+\} elsif substring\(option dhcp-client-identifier, 0, 6\) = "NVOS##" \{\n'
            r'\s+option bootfile-name .*?\n'
            r'\s+\} elsif substring\(option user-class, 0, 8\) = "NVOS-ZTP"\n'
            r'\s+or substring\(option user-class, 1, 8\) = "NVOS-ZTP" \{\n'
            r'\s+option bootfile-name ',
        )
        self.assertNotIn("member(", text)
        self.assertNotIn('class "ztp-', text)
        subnet_body = text.split("subnet 192.0.2.0", 1)[1]
        self.assertNotRegex(subnet_body, r'(?m)^\s{4}option bootfile-name')
        self.assertIn(
            'option cumulus-provision-url "http://192.0.2.2/ztp/'
            'ztp-bootstrap_oob.sh";',
            subnet_body,
        )
        self.assertIn(
            'option bootfile-name "http://192.0.2.2/ztp/ztp.json";',
            subnet_body,
        )
        # There is deliberately no catch-all branch: a client that matches none
        # of the Cumulus/NVOS fingerprints gets an address, but no ZTP URL.
        self.assertNotRegex(subnet_body, r'(?m)^\s*else\s*\{')

    def test_disabled_platforms_emit_no_subnet_ztp_options(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "dhcpd.conf"
            subnets = self.load_subnets(
                root,
                "plain,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.200,"
                "192.0.2.1,,none,no\n",
            )
            self.dhcp.write_dhcpd_conf(target, subnets)
            subnet_body = target.read_text(encoding="utf-8").split(
                "subnet 192.0.2.0", 1,
            )[1]
        self.assertNotIn("member(\"ztp-cumulus-vendor60\")", subnet_body)
        self.assertNotIn("member(\"ztp-nvos-client61\")", subnet_body)
        self.assertNotIn("member(\"ztp-nvos-user77\")", subnet_body)
        self.assertNotIn("option cumulus-provision-url", subnet_body)
        self.assertNotIn("option bootfile-name", subnet_body)

    def test_nvos_disabled_emits_only_cumulus_url_with_custom_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "dhcpd.conf"
            subnets = self.load_subnets(
                root,
                "cumulus,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.200,"
                "192.0.2.1,198.51.100.20,oobofoob,no\n",
                prefix="/day0/project-ztp/",
            )
            self.dhcp.write_dhcpd_conf(target, subnets)
            subnet_body = target.read_text(encoding="utf-8").split(
                "subnet 192.0.2.0", 1,
            )[1]
        self.assertIn(
            'http://198.51.100.20/day0/project-ztp/'
            'ztp-bootstrap_oobofoob.sh',
            subnet_body,
        )
        self.assertNotIn("option bootfile-name", subnet_body)

    def test_cumulus_profile_none_emits_only_nvos_url(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "dhcpd.conf"
            subnets = self.load_subnets(
                root,
                "nvos,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.200,"
                "192.0.2.1,198.51.100.30,none,yes\n",
                prefix="/project-ztp",
            )
            self.dhcp.write_dhcpd_conf(target, subnets)
            subnet_body = target.read_text(encoding="utf-8").split(
                "subnet 192.0.2.0", 1,
            )[1]
        self.assertNotIn("option cumulus-provision-url", subnet_body)
        self.assertIn(
            'option bootfile-name "http://198.51.100.30/project-ztp/ztp.json";',
            subnet_body,
        )

    def test_dhcp_generator_rejects_percent_encoded_ztp_prefix(self):
        with self.assertRaisesRegex(ValueError, "安全绝对 URL path"):
            self.dhcp._validate_ztp_url_prefix("/safe/%2e%2e/ztp")

    def test_subnet_schema_rejects_legacy_urls_invalid_enums_and_service_ip(self):
        cases = (
            (
                "shared_network,subnet,netmask,range_start,range_end,routers,"
                "bootfile_name,cumulus_provision_url\n"
                "legacy,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.200,"
                "192.0.2.1,http://192.0.2.2/ztp/ztp.json,"
                "http://192.0.2.2/ztp/ztp-bootstrap_oob.sh\n",
                "废弃 URL 列|缺少列",
            ),
            (
                "shared_network,subnet,netmask,range_start,range_end,routers,"
                "ztp_service_ip,cumulus_profile,nvos_ztp\n"
                "net,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.200,"
                "192.0.2.1,192.0.2.2,invalid,no\n",
                "cumulus_profile",
            ),
            (
                "shared_network,subnet,netmask,range_start,range_end,routers,"
                "ztp_service_ip,cumulus_profile,nvos_ztp\n"
                "net,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.200,"
                "192.0.2.1,192.0.2.2,oob,enabled\n",
                "nvos_ztp",
            ),
            (
                "shared_network,subnet,netmask,range_start,range_end,routers,"
                "ztp_service_ip,cumulus_profile,nvos_ztp\n"
                "net,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.200,"
                "192.0.2.1,,oob,no\n",
                "ztp_service_ip",
            ),
            (
                "shared_network,subnet,netmask,range_start,range_end,routers,"
                "ztp_service_ip,cumulus_profile,nvos_ztp\n"
                "net,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.200,"
                "192.0.2.1,192.0.2.2,none,no\n",
                "ztp_service_ip",
            ),
        )
        for content, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "02-dhcp-subnet_config.csv"
                source.write_text(content, encoding="utf-8")
                output = io.StringIO()
                with contextlib.redirect_stdout(output), self.assertRaises(SystemExit):
                    self.dhcp.load_subnet_csv(source, "/ztp")
                self.assertRegex(output.getvalue(), message)

    def test_pending_mac_and_transit_assignment_do_not_create_fixed_reservation(self):
        records = [{
            "src": "devices.csv:2", "hostname": "EXAMPLE-IB01", "iface": "eth0",
            "type": "ib", "ip": "203.0.113.10", "netmask": "24",
            "mac": "", "dynamic": False,
        }, {
            "src": "devices.csv:3", "hostname": "EXAMPLE-IB02", "iface": "eth0",
            "type": "ib", "ip": "203.0.113.11", "netmask": "24",
            "mac": "02:00:00:00:00:22", "dynamic": False,
        }]
        valid, errors = self.dhcp.validate(records)
        self.assertEqual([], errors)
        subnets = [{
            "_network": __import__("ipaddress").ip_network("192.0.2.0/24"),
            "range_start": "192.0.2.100", "range_end": "192.0.2.200",
        }]
        self.assertEqual([], self.dhcp.plan_dhcp_assignments(valid, subnets))
        self.assertEqual("identity_pending", valid[0]["dhcp_assignment"])
        self.assertEqual("transit_dynamic", valid[1]["dhcp_assignment"])
        with tempfile.TemporaryDirectory() as directory:
            hosts = Path(directory) / "dhcpd_ib.hosts"
            self.dhcp.write_hosts(hosts, valid)
            text = hosts.read_text(encoding="utf-8")
        self.assertNotIn("host EXAMPLE-IB01-eth0", text)
        self.assertIn("host EXAMPLE-IB02-eth0", text)
        self.assertNotIn("fixed-address", text)


class CumulusDhcpRelayUpstreamContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.generator = load_module(
            "cumulus_dhcp_relay_upstream_contract",
            ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
        )

    @staticmethod
    def _device():
        return {
            "lo_ip": "203.0.113.1/32",
            "vrfs": [{
                "evpn_vrf": "Vrf_2", "evpn_l3vni": 2,
                "l2vlans": [
                    {"vlan_id": 98, "svi_ip": "198.51.100.126/25",
                     "vrr_ip": "", "vrr_mac": "02:00:00:00:00:98",
                     "dhcp_relay": True, "dhcp_server": "02-ztp"},
                    {"vlan_id": 118, "svi_ip": "198.51.100.190/26",
                     "vrr_ip": "", "vrr_mac": "02:00:00:00:01:18",
                     "dhcp_relay": True, "dhcp_server": "03-bcm"},
                ],
            }],
        }

    def test_each_server_group_resolves_its_own_upstream(self):
        catalog = {"Vrf_2": {
            "02-ztp": {"servers": ["198.51.100.80"], "upstream_interface": ""},
            "03-bcm": {"servers": ["203.0.113.71"], "upstream_interface": ""},
        }}
        relay = self.generator._resolve_device_dhcp_relays(self._device(), catalog)[0]
        groups = {item["name"]: item for item in relay["server_groups"]}
        self.assertEqual(
            ["vlan2_l3", "vlan98"], groups["02-ztp"]["upstream_interfaces"]
        )
        self.assertEqual(
            ["vlan2_l3"], groups["03-bcm"]["upstream_interfaces"]
        )

    def test_explicit_upstream_is_added_without_replacing_defaults(self):
        catalog = {"Vrf_2": {
            "02-ztp": {"servers": ["198.51.100.80"],
                       "upstream_interface": "vlan118"},
            "03-bcm": {"servers": ["203.0.113.71"], "upstream_interface": ""},
        }}
        relay = self.generator._resolve_device_dhcp_relays(self._device(), catalog)[0]
        groups = {item["name"]: item for item in relay["server_groups"]}
        self.assertEqual(
            ["vlan2_l3", "vlan98", "vlan118"],
            groups["02-ztp"]["upstream_interfaces"],
        )


class SetupUnifiedInventoryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.setup = load_module(
            "day0_setup_unified_inventory_contract",
            ROOT / "DAY0-Prepare/01-a-setup.py",
        )

    def test_site_prefixed_air_pair_may_share_ip_when_resolution_is_unique(self):
        self.assertTrue(self.setup._is_matching_production_air_pair(
            "Staging-Border01", "eth",
            "AIR-EXAMPLE-SITE01-Staging-Border01", "air",
            ["Staging-Border01", "EXAMPLE-OOB-Staging-Leaf01"],
        ))

    def test_site_prefixed_air_pair_is_rejected_when_resolution_is_ambiguous(self):
        self.assertFalse(self.setup._is_matching_production_air_pair(
            "EXAMPLE-Leaf01", "eth", "AIR-EXAMPLE-SITE01-Leaf01", "air",
            ["EXAMPLE-Leaf01", "SITE01-Leaf01"],
        ))


class AirTopologyZtpInterfaceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.topology = load_module(
            "air_topology_ztp_interface_contract",
            ROOT / "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
        )

    def test_explicit_ztp_eth_interfaces_are_preserved(self):
        links = [
            ("EXAMPLE-Leaf01", "swp1", "site-ztp-server", "eth3"),
            ("EXAMPLE-Leaf02", "swp2", "site-ztp-server", "eth1"),
            ("EXAMPLE-Leaf03", "swp3", "site-ztp-server", "BF-P1"),
            ("EXAMPLE-Leaf04", "swp4", "site-ztp-server", "BF-P2"),
        ]
        mapped = self.topology._air_ztp_server_interfaces(links)
        self.assertEqual(["eth3", "eth1", "eth2", "eth4"], [item[1] for item in mapped])


class MonitorContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.monitor = load_module(
            "monitor_contract", ROOT / "monitor/generate-monitor-html.py"
        )

    def test_project_timezone_is_loaded(self):
        with tempfile.TemporaryDirectory() as directory:
            global_file = Path(directory) / "01-global.yaml"
            global_file.write_text(
                "common:\n"
                "  switch:\n"
                "    system:\n"
                "      date-time:\n"
                "        timezone: Asia/Taipei\n",
                encoding="utf-8",
            )
            zone = self.monitor.load_display_timezone(global_file)
        self.assertEqual(str(zone), "Asia/Taipei")

    def test_collection_retention_removes_only_expired_batch_directories(self):
        source = (ROOT / "ethernet/monitor/cron.sh").read_text(encoding="utf-8")
        function = "cleanup_data_dirs() {" + source.split(
            "cleanup_data_dirs() {", 1,
        )[1].split("# ── Main", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "eth-info"
            data.mkdir()
            old_day = (date.today() - timedelta(days=8)).strftime("%Y%m%d")
            recent_day = (date.today() - timedelta(days=1)).strftime("%Y%m%d")
            today = date.today().strftime("%Y%m%d")
            old_batch = data / f"{old_day}-1200-air"
            recent_batch = data / f"{recent_day}-1200-air"
            current_batch = data / f"{today}-1200-air"
            unrelated = data / "operator-notes"
            outside = root / "outside"
            for path in (old_batch, recent_batch, current_batch, unrelated, outside):
                path.mkdir()
                (path / "evidence.info").write_text("fixture\n", encoding="utf-8")
            unsafe_link = data / f"{old_day}-1300-air"
            unsafe_link.symlink_to(outside, target_is_directory=True)
            (data / f"{old_day}-1200-air.tar.gz").write_bytes(b"old archive")
            (data / f"{old_day}-1200-air.csv").write_text("old\n", encoding="utf-8")

            harness = root / "cleanup.sh"
            harness.write_text(
                "#!/bin/bash\nset -euo pipefail\nRETAIN_DAYS=7\n"
                "log() { printf '%s\\n' \"$*\"; }\n"
                + function + f"\ncleanup_data_dirs {str(data)!r}\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                ["bash", str(harness)], text=True, capture_output=True, check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse(old_batch.exists())
            self.assertFalse((data / f"{old_day}-1200-air.tar.gz").exists())
            self.assertFalse((data / f"{old_day}-1200-air.csv").exists())
            self.assertTrue(recent_batch.is_dir())
            self.assertTrue(current_batch.is_dir())
            self.assertTrue(unrelated.is_dir())
            self.assertTrue(unsafe_link.is_symlink())
            self.assertTrue((outside / "evidence.info").is_file())
            self.assertIn("deleted stale batch directory", result.stdout)

    def test_completion_handoff_signature_survives_monitor_restart(self):
        monitor = load_module(
            "persistent_ztp_handoff_contract",
            ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            state = root / monitor.HANDOFF_STATE_NAME
            signature = (
                ("EXAMPLE-Leaf01", "boot-a", "2026-08-31T12:00:00+00:00"),
                ("EXAMPLE-Leaf02", "boot-b", "2026-08-31T12:00:01+00:00"),
            )
            monitor.persist_completion_handoff_signatures(
                state, project, {"air-ethernet": signature},
            )
            self.assertEqual(
                {"air-ethernet": signature},
                monitor.load_completion_handoff_signatures(state, project),
            )
            other_project = root / "other-project"
            other_project.mkdir()
            self.assertEqual(
                {}, monitor.load_completion_handoff_signatures(state, other_project),
            )
            self.assertEqual(0o644, state.stat().st_mode & 0o777)

    def test_failed_completion_handoff_retries_are_bounded(self):
        monitor = load_module(
            "ztp_handoff_retry_contract",
            ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        self.assertEqual(120, monitor.completion_handoff_retry_delay(None))
        self.assertEqual(120, monitor.completion_handoff_retry_delay(5))
        self.assertEqual(480, monitor.completion_handoff_retry_delay(120))
        self.assertEqual(600, monitor.completion_handoff_retry_delay(3600))

    def test_switch_collection_cooldown_is_shared_across_managed_sources(self):
        gate_module = load_module(
            "switch_collection_cooldown_contract",
            ROOT / "monitor/switch_collection_gate.py",
        )
        clock = [1_000_000.0]
        with tempfile.TemporaryDirectory() as directory:
            status_dir = Path(directory)
            with gate_module.CollectionGate(
                "/project/a", "air", collection_keys=("air-ethernet",),
                status_dir=status_dir,
                clock=lambda: clock[0],
            ) as first:
                self.assertTrue(first.decision.allowed)
                first.mark_success()

            clock[0] += 1799
            with gate_module.CollectionGate(
                "/project/a", "air", collection_keys=("air-ethernet",),
                status_dir=status_dir,
                clock=lambda: clock[0],
            ) as second:
                self.assertFalse(second.decision.allowed)
                self.assertEqual("cooldown", second.decision.reason)
                self.assertEqual(1, second.decision.remaining_seconds)

            with gate_module.CollectionGate(
                "/project/b", "air", collection_keys=("air-ethernet",),
                status_dir=status_dir,
                clock=lambda: clock[0],
            ) as other_project:
                self.assertTrue(other_project.decision.allowed)

            clock[0] += 1
            with gate_module.CollectionGate(
                "/project/a", "air", collection_keys=("air-ethernet",),
                status_dir=status_dir,
                clock=lambda: clock[0],
            ) as after_cooldown:
                self.assertTrue(after_cooldown.decision.allowed)

            state = status_dir / gate_module.STATE_NAME
            self.assertEqual(0o600, state.stat().st_mode & 0o777)

    def test_auto_handoff_does_not_treat_manual_cooldown_as_cycle_proof(self):
        monitor = load_module(
            "ztp_handoff_shared_cooldown_contract",
            ROOT / "DAY0-Prepare/12-ztp-monitor.py",
        )
        gate_module = load_module(
            "switch_collection_cooldown_fixture",
            ROOT / "monitor/switch_collection_gate.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            status_dir = root / "status"
            with gate_module.CollectionGate(
                str(project.resolve()), "air", status_dir=status_dir,
            ) as gate:
                gate.mark_success()
            with mock.patch.object(
                monitor, "run_completion_handoff", return_value=True,
            ) as run:
                self.assertTrue(monitor.run_completion_handoff_with_gate(
                    {"scope": "air", "handoff_group": "air-ethernet",
                     "devices": [{"type": "air"}]}, Path("unused"), 60,
                    project, "air-ethernet", status_dir,
                ))
            run.assert_called_once()

    def test_vx_is_parsed_as_virtual_ethernet_without_hiding_health(self):
        def section(command, output):
            return (
                "\n####################################################\n"
                f"# Execute Command: {command}\n"
                "####################################################\n"
                f"{output}\n"
            )

        content = (
            "Device: AIR-EXAMPLE-Leaf01\nSwitch Type: UNKNOWN (VX)\n"
            "Collect Time: 2026-08-24 12:00:00\n"
            + section("nv show platform", "system-type  VX")
            + section("nv show system health", "status      Not OK")
            + section(
                "nv show interface",
                "swp1  up  up  100G  9216  swp\n"
                "swp2  up  down  100G  9216  swp\n"
                "swp3  down  down  100G  9216  swp",
            )
            + section(
                "nv show vrf default router bgp neighbor",
                "Neighbor  Hostname  AS  State  Uptime\n"
                "--------  --------  --  -----  ------\n"
                "swp1  EXAMPLE-Leaf02  65002  established  1d",
            )
            + section(
                "df -PT",
                "Filesystem Type 1024-blocks Used Available Capacity Mounted on\n"
                "/dev/sda1 ext4 1000 200 800 20% /",
            )
            + section(
                "free -b",
                "              total        used        free      shared  buff/cache   available\n"
                "Mem:     1000000000   250000000   500000000           0   250000000   750000000",
            )
            + section(
                "env LC_ALL=C top -bn2 -d 1",
                "top - 12:00:00 up 1 day\n"
                "%Cpu(s): 10.0 us, 5.0 sy, 0.0 ni, 85.0 id, 0.0 wa\n"
                "top - 12:00:01 up 1 day\n"
                "%Cpu(s): 12.0 us, 6.0 sy, 0.0 ni, 82.0 id, 0.0 wa",
            )
        )
        parsed = self.monitor.parse_info_file("AIR-EXAMPLE-Leaf01", content)
        self.assertEqual("ETH", parsed["sw_type"])
        self.assertEqual("not ok", parsed["health"])
        self.assertEqual((1, 3), (parsed["interfaces_up"], parsed["interfaces_total"]))
        self.assertEqual(1, parsed["interfaces_down_count"])
        self.assertEqual(["swp2"], parsed["interfaces_down"])
        row = self.monitor.render_sw_list_row(parsed)
        card = self.monitor.render_eth_card(parsed)
        self.assertIn('<span class="i-warn">1/3</span>', row)
        self.assertIn('(1↓)</span>', row)
        self.assertIn('Admin up / Oper down:', row)
        self.assertNotIn('swp3', row)
        self.assertIn('<span class="i-warn">1/3 up</span>', card)
        self.assertIn('(1 down)</span>', card)
        self.assertEqual((1, 1), (parsed["bgp_established"], parsed["bgp_total"]))
        self.assertEqual(20, parsed["disk_use"]["/"])
        self.assertEqual(25, parsed["mem_use"])
        self.assertEqual(18, parsed["cpu_use"])
        self.assertRegex(
            (ROOT / "ethernet/monitor/sw-info.sh").read_text(encoding="utf-8"),
            r"VX\)\s+SW_TYPE=\"ETH\"",
        )

    def test_interface_warning_count_is_not_truncated_with_tooltip(self):
        rows = "\n".join(
            f"swp{index}  up  down  100G  9216  swp"
            for index in range(1, 22)
        )
        content = (
            "Device: EXAMPLE-Leaf01\nSwitch Type: ETH (VX)\n"
            "\n####################################################\n"
            "# Execute Command: nv show interface\n"
            "####################################################\n"
            f"{rows}\n"
        )
        parsed = self.monitor.parse_info_file("EXAMPLE-Leaf01", content)
        self.assertEqual(21, parsed["interfaces_down_count"])
        self.assertEqual(20, len(parsed["interfaces_down"]))
        row = self.monitor.render_sw_list_row(parsed)
        self.assertIn("(21↓)</span>", row)
        self.assertIn("… plus 1 more", row)

    def test_switch_status_bgp_uses_colored_health_format(self):
        switch = self.monitor.parse_info_file(
            "EXAMPLE-Leaf01", "Device: EXAMPLE-Leaf01\nSwitch Type: ETH (VX)\n",
        )
        switch["bgp_established"] = 2
        switch["bgp_total"] = 2
        row = self.monitor.render_sw_list_row(switch)
        card = self.monitor.render_eth_card(switch)
        self.assertIn('<span class="i-ok">2/2</span>', row)
        self.assertIn('<span class="i-ok">2/2 established</span>', card)

        switch["bgp_established"] = 1
        row = self.monitor.render_sw_list_row(switch)
        card = self.monitor.render_eth_card(switch)
        self.assertIn('<span class="i-warn">1/2</span>', row)
        self.assertIn('<span class="i-down">(1↓)</span>', row)
        self.assertIn('<span class="i-warn">1/2 established</span>', card)
        self.assertIn('<span class="i-down">(1 down)</span>', card)

    def test_switch_status_use_columns_follow_displayed_percentage_thresholds(self):
        expected = {
            30: ("30%", "use-ok"),
            31: ("31%", "use-warn"),
            74: ("74%", "use-warn"),
            75: ("75%", "use-crit"),
        }
        for value, result in expected.items():
            with self.subTest(value=value):
                self.assertEqual(result, self.monitor.use_percent_display(value))

        switch = self.monitor.parse_info_file(
            "EXAMPLE-Leaf01", "Device: EXAMPLE-Leaf01\nSwitch Type: ETH (VX)\n",
        )
        switch.update({
            "cpu_use": 30,
            "mem_use": 31,
            "disk_use": {"/": 74, "/var": 75},
        })
        row = self.monitor.render_sw_list_row(switch)
        self.assertIn('<span class="use-ok">30%</span>', row)
        self.assertIn('<span class="use-warn">31%</span>', row)
        self.assertIn('<span class="disk-use-item use-warn">{ /: 74% }</span>', row)
        self.assertIn('<span class="disk-use-item use-crit">{ /var: 75% }</span>', row)

    def test_switch_status_temperature_uses_collected_max_crit_and_state(self):
        table = """\
Name                       Cur Temp (°C)  Crit Temp  Max Temp  Min Temp  State
-------------------------  -------------  ---------  --------  --------  -----
Asic-Temp-Sensor           64.0           120.0      105.0     5         ok
CPU-Package-Sensor         32.4           100.0      95.0      5         ok
PSU1-Temp-Sensor           28.0           85         63.0      5         ok
"""
        details = self.monitor.parse_temp_table_details(table)
        self.assertEqual(3, len(details))
        self.assertEqual(120.0, details[0]["critical"])
        self.assertEqual(105.0, details[0]["maximum"])
        self.assertEqual("t-ok", self.monitor.temperature_status_class(details[0]))
        self.assertEqual("t-ok", self.monitor.temperature_status_class(details[2]))

        at_max = dict(details[2], current=63.0)
        at_crit = dict(details[2], current=85.0)
        bad_state = dict(details[2], current=28.0, state="alarm")
        self.assertEqual("t-warn", self.monitor.temperature_status_class(at_max))
        self.assertEqual("t-crit", self.monitor.temperature_status_class(at_crit))
        self.assertEqual("t-crit", self.monitor.temperature_status_class(bad_state))
        self.assertEqual("—", self.monitor.render_temperature_values([], []))

        switch = self.monitor.parse_info_file(
            "EXAMPLE-Leaf01",
            "Device: EXAMPLE-Leaf01\nSwitch Type: ETH (SN5610)\n"
            "\n####################################################\n"
            "# Execute Command: nv show platform environment temperature\n"
            "####################################################\n"
            + table,
        )
        row = self.monitor.render_sw_list_row(switch)
        card = self.monitor.render_eth_card(switch)
        self.assertIn('<span class="t-ok" title="Asic-Temp-Sensor:', row)
        self.assertIn('<span class="t-ok" title="PSU1-Temp-Sensor:', row)
        self.assertIn('Max 105.0°C', row)
        self.assertIn('Crit 85.0°C', row)
        self.assertIn('<span class="t-ok" title="Asic-Temp-Sensor:', card)

    def test_switch_status_summarizes_evpn_and_mlag_bonds_after_bgp(self):
        def fixed_row(header, values):
            width = max(
                len(header),
                *(header.index(label) + len(str(value)) for label, value in values.items()),
            )
            chars = [" "] * width
            for label, value in values.items():
                start = header.index(label)
                text = str(value)
                chars[start:start + len(text)] = text
            return "".join(chars).rstrip()

        evpn_header = (
            "ESI                             ESInterface     NHG         DFPref  "
            "VNICnt  MacCnt  RemoteVTEPs       Flags"
        )
        evpn = "\n".join((
            evpn_header,
            "-" * len(evpn_header),
            fixed_row(evpn_header, {
                "ESI": "03:00:00:00:00:00:00:00:00:01", "ESInterface": "bond1s0",
                "NHG": "536870913", "RemoteVTEPs": "203.0.113.1", "Flags": "lrf*bsA",
            }),
            fixed_row(evpn_header, {"RemoteVTEPs": "203.0.113.2"}),
            fixed_row(evpn_header, {
                "ESI": "03:00:00:00:00:00:00:00:00:02", "ESInterface": "bond2",
                "NHG": "536870914", "RemoteVTEPs": "203.0.113.3", "Flags": "lrx*bsA",
            }),
            fixed_row(evpn_header, {
                "ESI": "03:00:00:00:00:00:00:00:00:03", "ESInterface": "bond3",
                "NHG": "536870915", "Flags": "lf*bs",
            }),
            fixed_row(evpn_header, {
                "ESI": "03:00:00:00:00:00:00:00:00:04",
                "NHG": "536870916", "RemoteVTEPs": "203.0.113.4", "Flags": "rA",
            }),
        ))
        evpn_records = self.monitor.parse_evpn_multihoming_bonds(evpn)
        self.assertEqual(["bond1s0", "bond2", "bond3"], [
            item["interface"] for item in evpn_records
        ])
        self.assertEqual(2, sum(bool(item["up"]) for item in evpn_records))
        self.assertEqual(["203.0.113.1", "203.0.113.2"], evpn_records[0]["remote_vteps"])

        # Also cover the NVUE variant where Flags precedes RemoteVTEPs.
        swapped_header = (
            "ESI                             ESInterface     NHG         DFPref  "
            "VNICnt  MacCnt  Flags       RemoteVTEPs"
        )
        swapped = "\n".join((
            swapped_header, "-" * len(swapped_header),
            fixed_row(swapped_header, {
                "ESI": "03:00:00:00:00:00:00:00:00:05", "ESInterface": "bond4",
                "NHG": "536870917", "Flags": "lr*bsA", "RemoteVTEPs": "203.0.113.5",
            }),
        ))
        self.assertTrue(self.monitor.parse_evpn_multihoming_bonds(swapped)[0]["up"])

        clag_header = (
            "Our Interface      Peer Interface     CLAG Id   Conflicts              "
            "Proto-Down Reason"
        )
        clag = "\n".join((
            "The peer is alive", "CLAG Interfaces", clag_header,
            "-" * len(clag_header),
            fixed_row(clag_header, {
                "Our Interface": "bond11s0", "Peer Interface": "-",
                "CLAG Id": "110", "Conflicts": "-", "Proto-Down Reason": "-",
            }),
            fixed_row(clag_header, {
                "Our Interface": "bond13s0", "Peer Interface": "-",
                "CLAG Id": "130", "Conflicts": "-", "Proto-Down Reason": "-",
            }),
            fixed_row(clag_header, {
                "Our Interface": "bond29", "Peer Interface": "bond29",
                "CLAG Id": "29", "Conflicts": "-", "Proto-Down Reason": "-",
            }),
            fixed_row(clag_header, {
                "Our Interface": "bond30", "Peer Interface": "-",
                "CLAG Id": "30", "Conflicts": "-", "Proto-Down Reason": "-",
            }),
        ))
        clag_records = self.monitor.parse_clag_bonds(clag)
        self.assertEqual(4, len(clag_records))
        self.assertEqual(1, sum(bool(item["up"]) for item in clag_records))

        def section(command, output):
            return (
                "\n####################################################\n"
                f"# Execute Command: {command}\n"
                "####################################################\n"
                f"{output}\n"
            )

        parsed = self.monitor.parse_info_file(
            "EXAMPLE-TAN-CP-Leaf01",
            "Device: EXAMPLE-TAN-CP-Leaf01\nSwitch Type: ETH (SN5610)\n"
            + section("nv show evpn multihoming esi", evpn)
            + section("clagctl", clag),
        )
        self.assertEqual((2, 3), (parsed["evpn_bond_up"], parsed["evpn_bond_total"]))
        self.assertEqual((1, 4), (parsed["mlag_bond_up"], parsed["mlag_bond_total"]))
        summary = self.monitor.render_bond_multihoming_summary(parsed)
        self.assertIn("EVPN 2/3 UP", summary)
        self.assertIn("MLAG 1/4 UP", summary)
        row = self.monitor.render_sw_list_row(parsed)
        self.assertEqual(21, row.count("<td"))
        card = self.monitor.render_eth_card(parsed)
        self.assertLess(card.index("BGP Peers"), card.index("EVPN/MLAG Bond"))

        source = (ROOT / "monitor/generate-monitor-html.py").read_text(encoding="utf-8")
        self.assertIn(
            '"<th>NTP Sync</th><th>接口</th><th>BGP</th>"\n'
            '        "<th>EVPN/MLAG Bond</th><th>健康</th>"',
            source,
        )
        self.assertIn("SWITCH_LIST_COLUMN_COUNT = 21", source)
        self.assertNotIn('colspan="20"', source)
        missing = self.monitor.render_sw_list_row(
            self.monitor.make_missing_switch("AIR-EXAMPLE-Missing", "ETH")
        )
        self.assertIn('colspan="16"', missing)

    def test_cumulus_internal_mounts_are_hidden_from_disk_use(self):
        output = (
            "Filesystem Type 1024-blocks Used Available Capacity Mounted on\n"
            "/dev/sda1 ext4 1000 230 770 23% /\n"
            "/dev/sda2 ext4 1000 10 990 1% /mnt/cl-etc\n"
            "/dev/sda3 ext4 1000 10 990 1% /mnt/cl-system-2\n"
            "/dev/sda4 ext4 1000 20 980 2% /var/log\n"
        )
        self.assertEqual(
            {"/": 23, "/var/log": 2},
            self.monitor.parse_disk_filesystems(output),
        )

    def test_switch_collector_executes_top_with_external_c_locale(self):
        source = (ROOT / "ethernet/monitor/sw-info.sh").read_text(encoding="utf-8")
        self.assertIn('"top -bn2 -d 1"', source)
        self.assertNotIn('"LC_ALL=C top -bn2 -d 1"', source)
        self.assertNotIn('"env LC_ALL=C top -bn2 -d 1"', source)
        self.assertIn('LC_ALL=C bash -c "${cmd}"', source)

    def test_status_tabs_have_independent_auto_refresh_controls(self):
        source = (ROOT / "monitor/generate-monitor-html.py").read_text(encoding="utf-8")
        for tab in ("ztp", "eth", "spx", "ibl", "nvl"):
            self.assertIn(f"auto_refresh_control('{tab}')", source)
        self.assertIn("const autoRefreshSettings = Object.fromEntries", source)
        self.assertNotIn("let autoRefreshEnabled", source)

    def test_link_validation_tabs_are_next_to_their_status_or_monitor_tabs(self):
        source = (ROOT / "monitor/generate-monitor-html.py").read_text(encoding="utf-8")
        tabs = source.split('<div id="tabs">', 1)[1].split("</div>", 1)[0]
        tab_ids = re.findall(r"switchTab\('([^']+)'\)", tabs)
        labels = re.findall(r">([^<]+)</button>", tabs)
        self.assertEqual(
            ["ztp", "eth", "etop", "spx", "itop", "ibl", "nvl", "p2p", "air"],
            tab_ids,
        )
        self.assertEqual(
            [
                "ZTP Status", "Switch Status", "Eth Link Validation",
                "SPX Link Monitor", "IB Link Validation", "IB Link Monitor",
                "NVLink Monitor", "Ethernet Diagram", "AIR Diagram",
            ],
            labels,
        )
        self.assertIn(
            "const TAB_NAMES = ['ztp','eth','etop','spx','itop','ibl','nvl','p2p','air'];",
            source,
        )

    def test_switch_list_has_no_duplicate_global_column_header(self):
        source = (ROOT / "monitor/generate-monitor-html.py").read_text(encoding="utf-8")
        list_view = source.split('<div id="list-view" style="display:none">', 1)[1].split(
            "</div>", 1
        )[0]
        self.assertNotIn("<thead>", list_view)
        self.assertIn('class="lst-repeat-head"', source)
        self.assertNotIn(".lst-tbl thead th", source)

    def test_refresh_preserves_the_active_tab(self):
        source = (ROOT / "monitor/generate-monitor-html.py").read_text(encoding="utf-8")
        self.assertIn("function reloadActiveTab()", source)
        self.assertIn("window.setTimeout(reloadActiveTab", source)
        self.assertIn("tabFromLocation() || storageGet(ACTIVE_TAB_KEY)", source)
        self.assertNotIn('id="panel-ztp" class="panel active"', source)
        self.assertNotIn('class="tab active"', source)

    def test_refresh_preserves_switch_card_or_list_view(self):
        source = (ROOT / "monitor/generate-monitor-html.py").read_text(encoding="utf-8")
        self.assertIn("const SWITCH_VIEW_KEY", source)
        self.assertIn("storageSet(SWITCH_VIEW_KEY, isCard ? 'card' : 'list')", source)
        self.assertIn(
            "setView(storageGet(SWITCH_VIEW_KEY) === 'list' ? 'list' : 'card', false)",
            source,
        )

    def test_switch_collection_does_not_relabel_ztp_control(self):
        source = (ROOT / "monitor/generate-monitor-html.py").read_text(encoding="utf-8")
        self.assertIn("let ztpMonitorState = 'unknown'", source)
        self.assertIn("let switchCollectionState = 'unknown'", source)
        self.assertIn("function renderZtpMonitorControl", source)
        self.assertIn("function renderSwitchCollectionControl", source)
        ztp_renderer = source.split("function renderZtpMonitorControl", 1)[1].split(
            "async function", 1
        )[0]
        self.assertNotIn("switch-collect-button", ztp_renderer)

    def test_ztp_status_badges_include_current_round(self):
        stages = {
            name: {
                "status": "success", "success_index": 2,
                "detail": "", "timestamp": "",
            }
            for name in (
                "dhcp", "bootstrap", "config_http", "ssh", "network",
                "version", "config_apply", "ssh_keys", "complete",
            )
        }
        html = self.monitor.render_ztp_status_rows({
            "available": True, "generated_at": "2026-08-24T10:00:00+08:00",
            "devices": [{
                "hostname": "AIR-EXAMPLE-TAN-Leaf01", "type": "air", "template": "tan",
                "ip": "203.0.113.1", "mac": "02:00:00:00:00:55", "ztp_round": 2,
                "stages": stages, "overall": "success", "progress": {"percent": 100},
                "issues": [],
            }],
        })
        self.assertIn(">成功2</span>", html)

    def test_manual_ztp_dhcp_stage_renders_skipped_round(self):
        html = self.monitor.render_ztp_status_rows({
            "available": True, "generated_at": "2026-08-24T10:00:00+08:00",
            "devices": [{
                "hostname": "AIR-EXAMPLE-TAN-Leaf01", "type": "air", "template": "tan",
                "ip": "203.0.113.1", "mac": "02:00:00:00:00:55", "ztp_round": 3,
                "trigger_source": "manual_web",
                "stages": {
                    "dhcp": {
                        "status": "skipped", "success_index": 3,
                        "detail": "手工 ZTP 直接执行 bootstrap，跳过 DHCP",
                        "timestamp": "2026-08-24T10:00:00+08:00",
                    },
                },
                "overall": "running", "progress": {"percent": 11}, "issues": [],
            }],
        })
        self.assertIn(">跳过3</span>", html)

    def test_ztp_status_hides_previous_round_stage_success(self):
        html = self.monitor.render_ztp_status_rows({
            "available": True, "generated_at": "2026-08-24T10:00:00+08:00",
            "devices": [{
                "hostname": "AIR-EXAMPLE-TAN-Leaf01", "type": "air", "template": "tan",
                "ip": "203.0.113.1", "mac": "02:00:00:00:00:55", "ztp_round": 3,
                "stages": {
                    "dhcp": {"status": "success", "success_index": 3},
                    "bootstrap": {"status": "success", "success_index": 2},
                },
                "overall": "running", "progress": {"percent": 10}, "issues": [],
            }],
        })
        self.assertIn('data-ztp-stage="dhcp"><span class="ztp-state ztp-success">成功3</span>', html)
        self.assertIn('data-ztp-stage="bootstrap"><span class="ztp-stage-event"', html)
        self.assertIn('>等待</span></span>', html)
        self.assertIn('上一轮成功 index=2；等待第 3 轮新证据', html)

    def test_ztp_status_does_not_show_old_completion_time_for_new_round(self):
        html = self.monitor.render_ztp_status_rows({
            "available": True, "generated_at": "2026-08-24T10:10:00+08:00",
            "devices": [{
                "hostname": "AIR-EXAMPLE-Leaf01", "type": "air", "template": "tan",
                "ip": "203.0.113.1", "mac": "02:00:00:00:00:55", "ztp_round": 3,
                "stages": {"complete": {
                    "status": "success", "success_index": 2,
                    "timestamp": "2026-08-24T09:00:00+08:00",
                }},
                "overall": "running", "progress": {"percent": 0}, "issues": [],
            }],
        })
        self.assertNotIn('完成：', html)
        self.assertRegex(
            html,
            r'data-ztp-stage="complete">.*?ztp-pending">\u7b49\u5f85</span></span>'
            r'<span class="ztp-event-time">—</span>',
        )

    def test_ibdiagnet_report_is_discovered(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "20260810-08-ibdiagnet2-topology-validation.xlsx"
            report.touch()
            self.assertEqual(
                self.monitor.find_latest_topology_report(Path(directory), "infiniband"),
                report,
            )

    def test_index_local_targets_are_source_files_or_declared_runtime_pages(self):
        text = (ROOT / "index.html").read_text(encoding="utf-8")
        runtime_targets = {"monitor/monitor.html"}
        referenced_runtime = set()
        for href in re.findall(r'href=["\']([^"\']+)', text):
            if "://" in href or href.startswith(("#", "mailto:")):
                continue
            target = href.split("#", 1)[0]
            if target in runtime_targets:
                referenced_runtime.add(target)
                self.assertTrue(
                    (ROOT / "monitor/generate-monitor-html.py").is_file()
                )
                continue
            self.assertTrue((ROOT / target).exists(), href)
        self.assertEqual(runtime_targets, referenced_runtime)

    def test_eth_archive_environment_metadata_is_authoritative(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "collection.json"
            payload.write_text('{"environment":"air"}\n', encoding="utf-8")
            archive = root / "20260824-1200-prod.tar.gz"
            with tarfile.open(archive, "w:gz") as stream:
                stream.add(payload, arcname="20260824-1200-prod/collection.json")
            selected = self.monitor.find_latest_eth_tars(root)
            self.assertEqual(selected["air"], archive)

    def test_environment_cli_aliases_are_equivalent(self):
        self.assertEqual("all", self.monitor.parse_args([]).scope)
        self.assertEqual("air", self.monitor.parse_args(["--air"]).scope)
        self.assertEqual("prod", self.monitor.parse_args(["--prod"]).scope)
        self.assertEqual("air", self.monitor.parse_args(["--type", "air"]).scope)

    def test_air_scope_keeps_project_ethernet_diagram(self):
        source = (ROOT / "monitor/generate-monitor-html.py").read_text(encoding="utf-8")
        air_scope = source.split('if scope == "air":', 1)[1].split(
            'elif scope == "prod":', 1
        )[0]
        self.assertNotIn("ethernet_diagram = empty_diagram", air_scope)

    def test_ztp_report_loading_honors_environment_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / "devices.csv"
            inventory.write_text(
                "hostname,type,template\n"
                "EXAMPLE-Leaf01,eth,oob-leaf\n"
                "AIR-EXAMPLE-Leaf01,air,oob-leaf\n",
                encoding="utf-8",
            )
            reports = (
                ("prod", "EXAMPLE-Leaf01", "eth"),
                ("air", "AIR-EXAMPLE-Leaf01", "air"),
            )
            for index, (scope, hostname, device_type) in enumerate(reports, start=1):
                run = root / f"20260824_12000{index}"
                run.mkdir()
                (run / "report.json").write_text(json.dumps({
                    "project": "sample", "scope": scope,
                    "generated_at": f"2026-08-24T12:00:0{index}+08:00",
                    "devices": [{"hostname": hostname, "type": device_type, "overall": "success"}],
                }), encoding="utf-8")
            air = self.monitor.load_ztp_status(root, inventory, scope="air")
            prod = self.monitor.load_ztp_status(root, inventory, scope="prod")
            both = self.monitor.load_ztp_status(root, inventory, scope="all")
            self.assertEqual(["AIR-EXAMPLE-Leaf01"], [d["hostname"] for d in air["devices"]])
            self.assertEqual(["EXAMPLE-Leaf01"], [d["hostname"] for d in prod["devices"]])
            self.assertEqual(2, len(both["devices"]))

    def test_switch_status_keeps_unbound_devices_without_collection_archives(self):
        def runtime_device(
            hostname, platform, device_type, managed, product="",
            environment="production",
        ):
            return {
                "hostname": hostname, "type": device_type,
                "environment": environment, "platform_family": platform,
                "product": product, "serial": "", "unbound_identity": True,
                "managed_ztp": managed, "dynamic_dhcp": True,
                "ip": "192.0.2.20", "mac": "02:00:00:00:00:20",
                "lease_state": "active", "ztp_round": 1, "stages": {},
                "overall": "warning", "progress": {"percent": 0}, "issues": [],
            }

        status = {
            "available": True, "source": "fixture", "project": "sample",
            "generated_at": "2026-08-31T00:00:00+08:00",
            "environment_updates": {
                "air": "2026-08-31T00:00:00+08:00",
                "production": "2026-08-31T00:00:00+08:00",
            },
            "counts": {"warning": 6},
            "devices": [
                runtime_device(
                    "DISCOVERED-CUMULUS-020000000010", "cumulus",
                    "pending_eth", True, environment="air",
                ),
                runtime_device(
                    "DISCOVERED-NVOS-020000000011", "nvos",
                    "pending_nvos", True, "unknown-nvos", "air",
                ),
                runtime_device(
                    "UNKNOWN-UNKNOWN-020000000012", "unknown",
                    "unknown", False, environment="air",
                ),
                runtime_device(
                    "DISCOVERED-CUMULUS-020000000020", "cumulus",
                    "pending_eth", True,
                ),
                runtime_device(
                    "DISCOVERED-NVOS-020000000021", "nvos",
                    "pending_nvos", True, "unknown-nvos",
                ),
                runtime_device(
                    "UNKNOWN-UNKNOWN-020000000022", "unknown",
                    "unknown", False,
                ),
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            empty = root / "empty"
            empty.mkdir()
            output = root / "monitor.html"
            with mock.patch.object(
                self.monitor, "load_ztp_status", return_value=status,
            ), mock.patch.object(
                self.monitor, "load_dynamic_air_inventory", return_value=[],
            ), mock.patch.multiple(
                self.monitor,
                ETH_INFO_DIR=empty, SPX_LINK_DIR=empty,
                IB_INFO_DIR=empty, IBL_LINK_DIR=empty,
                NV_INFO_DIR=empty, NVL_LINK_DIR=empty,
                P2P_OUTPUT_DIR=empty, OUTPUT=output,
                LOG_FILE=root / "generate-monitor.log",
            ):
                self.monitor.main("all")

            document = output.read_text(encoding="utf-8")
            card_panel = document.split('<div id="card-grid">', 1)[1].split(
                '<div id="list-view"', 1,
            )[0]
            air_group = card_panel.split(
                '<section class="card-env-group" data-environment="air">', 1,
            )[1].split(
                '<section class="card-env-group" data-environment="production">', 1,
            )[0]
            production_group = card_panel.split(
                '<section class="card-env-group" data-environment="production">', 1,
            )[1]
            for group, suffix in ((air_group, "010"), (production_group, "020")):
                self.assertIn("Ethernet Switches (1)", group)
                self.assertIn(f"DISCOVERED-CUMULUS-020000000{suffix}", group)
                self.assertIn("未绑定 / 未分类设备（其他） (2)", group)
                unbound_section = group.split(
                    "未绑定 / 未分类设备（其他） (2)", 1,
                )[1]
                self.assertIn(f"DISCOVERED-NVOS-020000000{int(suffix) + 1:03d}", unbound_section)
                self.assertIn(f"UNKNOWN-UNKNOWN-020000000{int(suffix) + 2:03d}", unbound_section)
                self.assertIn("未发起", unbound_section)
                self.assertIn("NVOS 平台已识别", unbound_section)
                self.assertIn("平台未知", unbound_section)
                self.assertNotIn("成功 ·", unbound_section)

    def test_switch_status_marks_unbound_cumulus_unattempted_when_only_other_environment_has_archive(self):
        status = {
            "available": True, "source": "fixture", "project": "sample",
            "generated_at": "2026-08-31T00:00:00+08:00",
            "environment_updates": {
                "air": "2026-08-31T00:00:00+08:00",
                "production": "2026-08-31T00:00:00+08:00",
            },
            "counts": {"warning": 1},
            "devices": [{
                "hostname": "DISCOVERED-CUMULUS-020000000030",
                "type": "pending_eth", "environment": "production",
                "platform_family": "cumulus", "product": "", "serial": "",
                "unbound_identity": True, "managed_ztp": True,
                "dynamic_dhcp": True, "ip": "192.0.2.30",
                "mac": "02:00:00:00:00:30", "lease_state": "active",
                "ztp_round": 1, "stages": {}, "overall": "warning",
                "progress": {"percent": 0}, "issues": [],
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "data"
            data.mkdir()
            output = root / "monitor.html"
            archive_path = data / "20260831_000000-air.tar.gz"
            collection = json.dumps({"environment": "air"}).encode("utf-8")
            with tarfile.open(archive_path, "w:gz") as archive:
                member = tarfile.TarInfo("collection.json")
                member.size = len(collection)
                archive.addfile(member, io.BytesIO(collection))
            with mock.patch.object(
                self.monitor, "load_ztp_status", return_value=status,
            ), mock.patch.object(
                self.monitor, "load_dynamic_air_inventory", return_value=[],
            ), mock.patch.multiple(
                self.monitor,
                ETH_INFO_DIR=data, SPX_LINK_DIR=data,
                IB_INFO_DIR=data, IBL_LINK_DIR=data,
                NV_INFO_DIR=data, NVL_LINK_DIR=data,
                P2P_OUTPUT_DIR=data, OUTPUT=output,
                LOG_FILE=root / "generate-monitor.log",
            ):
                self.monitor.main("all")

            document = output.read_text(encoding="utf-8")
            production_group = document.split(
                '<section class="card-env-group" data-environment="production">', 1,
            )[1].split('<div id="list-view"', 1)[0]
            card = production_group.split(
                "DISCOVERED-CUMULUS-020000000030", 1,
            )[1].split('</div>\n</div>', 1)[0]
            self.assertIn("未发起", card)
            self.assertNotIn("失败", card)
            self.assertIn("当前没有可用的 Switch Status 采集归档", card)


class TransferContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ROOT / "tools"))
        import project_contract
        cls.contract = project_contract

    def test_manual_backup_names_are_excluded_from_deploy(self):
        for name in ("01-global_副本.yaml", "global_copy.yaml", "global_bak.yaml"):
            self.assertTrue(self.contract.is_manual_backup_name(name), name)
        self.assertFalse(self.contract.is_manual_backup_name("01-global.yaml"))
        self.assertFalse(self.contract.is_manual_backup_name("Customer IP Assignment.xlsx"))

    def test_scoped_ubuntu_2404_repository_contract_uses_isolated_fixtures(self):
        upload = load_module(
            "tar_upload_scoped_repository_contract",
            ROOT / "tools/tar-for-upload.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for arch in ("amd64", "arm64"):
                repository = root / f"ubuntu-24.04/{arch}"
                repository.mkdir(parents=True)
                stanzas = []
                for package in sorted(upload.REQUIRED_OFFLINE_PACKAGES):
                    filename = f"{package}_1_{arch}.deb"
                    (repository / filename).write_bytes(b"fixture")
                    stanzas.append(
                        f"Package: {package}\nVersion: 1\n"
                        f"Architecture: {arch}\nFilename: ./{filename}\n"
                    )
                packages = "\n".join(stanzas)
                (repository / "Packages").write_text(
                    packages, encoding="utf-8"
                )
                with gzip.open(
                    repository / "Packages.gz", "wt", encoding="utf-8"
                ) as stream:
                    stream.write(packages)
                (repository / "repository.meta").write_text(
                    "schema_version=1\nos_id=ubuntu\nos_version=24.04\n"
                    f"architecture={arch}\n",
                    encoding="utf-8",
                )
                upload.validate_flat_apt_repository(
                    repository, f"ubuntu-24.04/{arch}"
                )


class OptimizeFeedbackContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.feedback = load_module(
            "feedback_contract", ROOT / "ztp/optimize/feedback.py"
        )

    def test_both_environments_use_unified_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory)
            prod = sample / "02-devices_config.csv"
            generated = sample / "generated-latest"
            prod.write_text(
                "hostname,type\nprod01,eth\nair01,air\n", encoding="utf-8"
            )
            generated.mkdir()

            self.assertEqual(
                Path(self.feedback.sample_inventory_for_source(
                    sample, generated, requested_type="air"
                )),
                prod,
            )
            self.assertEqual(
                Path(self.feedback.sample_inventory_for_source(
                    sample, generated, requested_type="prod"
                )),
                prod,
            )

    def test_generated_air_yaml_uses_real_air_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            generated = Path(directory)
            air = generated / "AIR-EXAMPLE-Prod01.yaml"
            air.write_text("- set: {}\n", encoding="utf-8")

            selected = self.feedback.discover_yaml_files(
                generated, allowed_hostnames={"AIR-EXAMPLE-Prod01"},
            )
            self.assertEqual(selected, {"AIR-EXAMPLE-Prod01": air})

    def test_csv_hostname_comes_from_yaml_configuration(self):
        info = {
            "template": "border", "eth0_ip": "NA", "netmask": "NA",
            "eth0_gw": "NA", "eth0_mac": "02:00:00:00:00:01",
            "eth1_ip": "NA", "eth1_nm": "NA", "eth1_gw": "NA",
            "eth1_mac": "NA",
        }
        row, _groups = self.feedback.parse_device(
            {"system": {"hostname": "AIR-EXAMPLE-Border01"}, "interface": {}},
            "AIR-EXAMPLE-Border01", "air", info,
        )
        self.assertEqual(row[0], "AIR-EXAMPLE-Border01")

    def test_managed_monitor_keeps_observed_hostname_drift(self):
        inventory = {"EXAMPLE-OOB-Leaf01": {"type": "eth"}}
        self.assertIsNone(self.feedback.inventory_hostname_filter(
            Path("monitor-prod-latest"), True, inventory,
        ))
        self.assertEqual(
            self.feedback.inventory_hostname_filter(
                Path("generated-latest"), True, inventory,
            ),
            {"EXAMPLE-OOB-Leaf01"},
        )


class ManualZtpContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manual = load_module(
            "manual_ztp_contract", ROOT / "ztp/manual-ztp.py"
        )
        cls.worker = load_module(
            "manual_ztp_worker_contract", ROOT / "monitor/manual-ztp-worker.py"
        )
        cls.cgi = load_module(
            "manual_ztp_cgi_contract", ROOT / "monitor/manual-ztp-control.cgi"
        )

    @staticmethod
    def devices():
        return [
            {"hostname": "AIR-EXAMPLE-SITE01-TAN-Leaf01", "type": "air"},
            {"hostname": "AIR-EXAMPLE-SITE01-TAN-Leaf02", "type": "air"},
            {"hostname": "EXAMPLE-TAN-Leaf01", "type": "eth"},
            {"hostname": "EXAMPLE-IB-Leaf01", "type": "ib"},
        ]

    def test_positional_patterns_and_type_expand_to_deduplicated_devices(self):
        selected = self.manual.select_devices(
            self.devices(), ["AIR-EXAMPLE-SITE01-*", "*-Leaf01"], "air"
        )
        self.assertEqual(
            ["AIR-EXAMPLE-SITE01-TAN-Leaf01", "AIR-EXAMPLE-SITE01-TAN-Leaf02"],
            [device["hostname"] for device in selected],
        )

    def test_any_unmatched_selector_rejects_the_entire_request(self):
        with self.assertRaises(self.manual.ManualZtpError):
            self.manual.select_devices(
                self.devices(), ["AIR-EXAMPLE-SITE01-*", "does-not-exist*"], "air"
            )

    @staticmethod
    def write_ztp_inputs(
        root: Path, rows: str, *, prefix: str = "/ztp",
    ) -> tuple[Path, Path]:
        global_yaml = root / "01-global.yaml"
        global_yaml.write_text(
            "common:\n"
            "  mgmt:\n"
            "    ztp:\n"
            f"      ztp_url_prefix: {prefix}\n",
            encoding="utf-8",
        )
        subnet_csv = root / "02-dhcp-subnet_config.csv"
        subnet_csv.write_text(
            "shared_network,subnet,netmask,range_start,range_end,routers,"
            "ztp_service_ip,cumulus_profile,nvos_ztp\n" + rows,
            encoding="utf-8",
        )
        return subnet_csv, global_yaml

    def test_manual_urls_are_derived_from_service_ip_profile_and_global_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            subnet, global_yaml = self.write_ztp_inputs(
                Path(directory),
                "oob,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.199,"
                "192.0.2.1,192.0.2.2,oob,yes\n"
                "bootstrap,198.51.100.0,255.255.255.0,198.51.100.100,"
                "198.51.100.199,198.51.100.1,198.51.100.2,oobofoob,no\n",
                prefix="/day0/ztp/",
            )
            urls = self.manual.provision_urls(subnet, global_yaml)
        self.assertEqual([
            (
                __import__("ipaddress").ip_network("192.0.2.0/24"),
                "http://192.0.2.2/day0/ztp/ztp-bootstrap_oob.sh",
            ),
            (
                __import__("ipaddress").ip_network("198.51.100.0/24"),
                "http://198.51.100.2/day0/ztp/ztp-bootstrap_oobofoob.sh",
            ),
        ], urls)

    def test_manual_profile_none_does_not_create_cumulus_url(self):
        with tempfile.TemporaryDirectory() as directory:
            subnet, global_yaml = self.write_ztp_inputs(
                Path(directory),
                "disabled,192.0.2.0,255.255.255.0,192.0.2.100,"
                "192.0.2.199,192.0.2.1,,none,no\n",
            )
            with self.assertRaisesRegex(
                self.manual.ManualZtpError, "没有启用 Cumulus ZTP",
            ):
                self.manual.provision_urls(subnet, global_yaml)

    def test_manual_subnet_contract_rejects_invalid_enums_or_service_ip(self):
        invalid_rows = (
            (
                "net,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.199,"
                "192.0.2.1,192.0.2.2,border,no\n",
                "cumulus_profile",
            ),
            (
                "net,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.199,"
                "192.0.2.1,192.0.2.2,oob,enabled\n",
                "nvos_ztp",
            ),
            (
                "net,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.199,"
                "192.0.2.1,,oob,no\n",
                "ztp_service_ip 不能为空",
            ),
            (
                "net,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.199,"
                "192.0.2.1,192.0.2.2,none,no\n",
                "ztp_service_ip 必须为空",
            ),
            (
                "net,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.199,"
                "192.0.2.1,0.0.0.0,oob,no\n",
                "不是可用单播地址",
            ),
            (
                "net,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.199,"
                "192.0.2.1,239.1.2.3,oob,no\n",
                "不是可用单播地址",
            ),
            (
                "net,2001:db8::,64,2001:db8::100,2001:db8::199,"
                "2001:db8::1,192.0.2.2,oob,no\n",
                "subnet/netmask 无效",
            ),
        )
        for row, message in invalid_rows:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                subnet, global_yaml = self.write_ztp_inputs(Path(directory), row)
                with self.assertRaisesRegex(self.manual.ManualZtpError, message):
                    self.manual.provision_urls(subnet, global_yaml)

    def test_manual_subnet_contract_rejects_legacy_or_duplicate_columns(self):
        invalid_headers = (
            (
                "shared_network,subnet,netmask,range_start,range_end,routers,"
                "bootfile_name,cumulus_provision_url\n",
                "已废弃 URL 列",
            ),
            (
                "shared_network,subnet,netmask,range_start,range_end,routers,"
                "ztp_service_ip,cumulus_profile,nvos_ztp,nvos_ztp\n",
                "列名重复: nvos_ztp",
            ),
        )
        for header, message in invalid_headers:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                subnet, global_yaml = self.write_ztp_inputs(root, "")
                subnet.write_text(header, encoding="utf-8")
                with self.assertRaisesRegex(self.manual.ManualZtpError, message):
                    self.manual.provision_urls(subnet, global_yaml)

    def test_manual_subnet_contract_rejects_profile_service_ip_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            subnet, global_yaml = self.write_ztp_inputs(
                Path(directory),
                "first,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.199,"
                "192.0.2.1,192.0.2.2,oob,no\n"
                "second,198.51.100.0,255.255.255.0,198.51.100.100,"
                "198.51.100.199,198.51.100.1,198.51.100.2,oob,no\n",
            )
            with self.assertRaisesRegex(
                self.manual.ManualZtpError, "同一 profile 只能有一个 ztp_service_ip",
            ):
                self.manual.provision_urls(subnet, global_yaml)

    def test_manual_subnet_contract_rejects_nvos_service_ip_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            subnet, global_yaml = self.write_ztp_inputs(
                Path(directory),
                "first,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.199,"
                "192.0.2.1,192.0.2.2,none,yes\n"
                "second,198.51.100.0,255.255.255.0,198.51.100.100,"
                "198.51.100.199,198.51.100.1,198.51.100.2,none,yes\n",
            )
            with self.assertRaisesRegex(
                self.manual.ManualZtpError, "ztp.json 只能有一个 ztp_service_ip",
            ):
                self.manual.provision_urls(subnet, global_yaml)

    def test_manual_transit_lease_selects_the_derived_subnet_url(self):
        with tempfile.TemporaryDirectory() as directory:
            subnet, global_yaml = self.write_ztp_inputs(
                Path(directory),
                "transit,192.0.2.0,255.255.255.0,192.0.2.100,"
                "192.0.2.199,192.0.2.1,192.0.2.2,oobofoob,no\n",
                prefix="/project-ztp",
            )
            urls = self.manual.provision_urls(subnet, global_yaml)
        device = {
            "hostname": "AIR-EXAMPLE-Leaf01", "type": "air", "ip": "198.51.100.10",
            "dynamic_lease_ips": ["192.0.2.123"],
        }
        self.assertEqual(
            "http://192.0.2.2/project-ztp/ztp-bootstrap_oobofoob.sh",
            self.manual.bootstrap_url(device, urls),
        )
        self.assertEqual("192.0.2.123", device["bootstrap_source_ip"])
        self.assertEqual("192.0.2.0/24", device["bootstrap_source_network"])

    def test_gui_worker_command_has_fixed_action_and_exact_hostname(self):
        command = self.worker.command_for("AIR-EXAMPLE-SITE01-TAN-Leaf01", "air")
        self.assertEqual("AIR-EXAMPLE-SITE01-TAN-Leaf01", command[2])
        self.assertIn("--non-interactive", command)
        self.assertNotIn("--refresh-host-key", command)
        self.assertEqual("web", command[command.index("--origin") + 1])
        self.assertNotIn("shell", " ".join(command).casefold())
        self.assertNotIn("http://", " ".join(command).casefold())

    def test_sudo_password_is_only_enabled_for_explicit_url(self):
        default = self.manual.parser().parse_args(["AIR-EXAMPLE-Leaf01"])
        self.manual.apply_sudo_policy(default)
        self.assertFalse(default.sudo_password)

        obsolete = self.manual.parser().parse_args(["AIR-EXAMPLE-Leaf01", "--sudo-password"])
        self.manual.apply_sudo_policy(obsolete)
        self.assertFalse(obsolete.sudo_password)

        explicit = self.manual.parser().parse_args([
            "AIR-EXAMPLE-Leaf01", "--url", "http://192.0.2.1/ztp/ztp-bootstrap_oob.sh",
        ])
        self.manual.apply_sudo_policy(explicit)
        self.assertTrue(explicit.sudo_password)

        rejected = self.manual.parser().parse_args([
            "AIR-EXAMPLE-Leaf01", "--url", "http://192.0.2.1/ztp/ztp-bootstrap_oob.sh",
            "--no-sudo-password",
        ])
        with self.assertRaisesRegex(self.manual.ManualZtpError, "显式 URL"):
            self.manual.apply_sudo_policy(rejected)

    def test_gui_reset_uses_fixed_zero_url_command(self):
        command = self.worker.command_for("AIR-EXAMPLE-Leaf01", "air", "reset")
        self.assertEqual(str(ROOT / "ztp/manual-reset.py"), command[1])
        self.assertNotIn("http://", " ".join(command).casefold())
        self.assertIn("--non-interactive", command)
        self.assertNotIn("--refresh-host-key", command)

    def test_reset_uses_fixed_background_nvue_force_command_without_sudo(self):
        client = mock.Mock()
        client.args.command_timeout = 10
        client.args.non_interactive = True
        client.run.side_effect = [
            mock.Mock(returncode=0, stdout="config\n", stderr=""),
            mock.Mock(returncode=0, stdout="scheduled\n", stderr=""),
        ]
        device = {
            "hostname": "AIR-EXAMPLE-Leaf01", "type": "air", "user": "cumulus",
            "ip": "192.0.2.1", "mac_plain": "020000000001",
        }
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            self.manual, "connect_and_verify", return_value=("192.0.2.1", "eth0"),
        ):
            result = self.manual.trigger_one(
                client, device, "", Path(directory) / "manual-reset/run1",
                "manual_reset_web", "reset-1", "reset",
            )
        self.assertEqual("triggered", result["state"])
        remote = client.run.call_args_list[1].args[2]
        self.assertIn("nohup sh -c", remote)
        self.assertIn("nv action reset system factory-default force", remote)
        self.assertIn("/home/cumulus/http-manual-reset.log", remote)
        self.assertNotIn("onie-install", remote)
        self.assertNotIn("printf", remote)
        client.sudo_command.assert_not_called()

    def test_reset_parser_exposes_no_image_or_sudo_override(self):
        reset_parser = self.manual.parser("reset")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            reset_parser.parse_args([
                "AIR-EXAMPLE-Leaf01", "--image-url", "http://example/image.bin",
            ])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            reset_parser.parse_args(["AIR-EXAMPLE-Leaf01", "--sudo-password"])

    def test_rebuilt_switch_host_key_is_refreshed_then_identity_verified(self):
        client = mock.Mock()
        client.args.connect_timeout = 5
        client.args.refresh_host_key = False
        client.args.ssh_password = False
        client.run.side_effect = [
            mock.Mock(
                returncode=255, stdout="",
                stderr="WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!",
            ),
            mock.Mock(
                returncode=0,
                stdout="AIR-EXAMPLE-Leaf01\n02:00:00:00:00:01\n", stderr="",
            ),
        ]
        device = {
            "hostname": "AIR-EXAMPLE-Leaf01", "type": "air", "user": "cumulus",
            "mac_plain": "020000000001",
            "candidates": [("192.0.2.1", "eth0")],
        }
        self.assertEqual(
            ("192.0.2.1", "eth0"),
            self.manual.connect_and_verify(client, device),
        )
        client.reset_host_key.assert_called_once_with("192.0.2.1")

    def test_production_host_key_mismatch_is_fail_closed_by_default(self):
        client = mock.Mock()
        client.args.connect_timeout = 5
        client.args.refresh_host_key = False
        client.args.ssh_password = False
        client.run.return_value = mock.Mock(
            returncode=255, stdout="",
            stderr="WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!",
        )
        device = {
            "hostname": "EXAMPLE-TAN-Leaf01", "type": "eth", "user": "cumulus",
            "mac_plain": "020000000001",
            "candidates": [("192.0.2.1", "eth0")],
        }
        with self.assertRaisesRegex(
            self.manual.ManualZtpError, "Production defaults to fail-closed",
        ):
            self.manual.connect_and_verify(client, device)
        client.reset_host_key.assert_not_called()
        self.assertEqual(1, client.run.call_count)

    def test_exact_interactive_production_refresh_still_checks_identity(self):
        args = self.manual.parser().parse_args([
            "EXAMPLE-TAN-Leaf01", "--refresh-host-key",
        ])
        device = {
            "hostname": "EXAMPLE-TAN-Leaf01", "type": "eth", "user": "cumulus",
            "mac_plain": "020000000001",
            "candidates": [("192.0.2.1", "eth0")],
        }
        self.manual.validate_host_key_refresh_policy(args, [device])
        invalid_identities = (
            ("EXAMPLE-wrong-host\n02:00:00:00:00:01\n", "hostname"),
            ("EXAMPLE-TAN-Leaf01\n02:00:00:00:00:02\n", "MAC"),
        )
        for stdout, message in invalid_identities:
            with self.subTest(message=message):
                client = mock.Mock(args=args)
                client.run.side_effect = [
                    mock.Mock(
                        returncode=255, stdout="",
                        stderr="WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!",
                    ),
                    mock.Mock(returncode=0, stdout=stdout, stderr=""),
                ]
                with self.assertRaisesRegex(self.manual.ManualZtpError, message):
                    self.manual.connect_and_verify(client, device)
                client.reset_host_key.assert_called_once_with("192.0.2.1")
        client = mock.Mock(args=args)
        client.run.side_effect = [
            mock.Mock(
                returncode=255, stdout="",
                stderr="WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!",
            ),
            mock.Mock(
                returncode=0,
                stdout="EXAMPLE-TAN-Leaf01\n02:00:00:00:00:01\n", stderr="",
            ),
        ]
        self.assertEqual(
            ("192.0.2.1", "eth0"),
            self.manual.connect_and_verify(client, device),
        )
        client.reset_host_key.assert_called_once_with("192.0.2.1")

    def test_refresh_host_key_rejects_gui_noninteractive_and_nonexact_targets(self):
        production = {"hostname": "EXAMPLE-TAN-Leaf01", "type": "eth"}
        air = {"hostname": "AIR-EXAMPLE-Leaf01", "type": "air"}
        cases = (
            (
                [
                    "EXAMPLE-TAN-Leaf01", "--refresh-host-key", "--non-interactive",
                    "--yes",
                ],
                [production],
                "交互 CLI",
            ),
            (
                ["EXAMPLE-TAN-Leaf01", "--refresh-host-key", "--origin", "web"],
                [production],
                "GUI",
            ),
            (
                ["EXAMPLE-TAN-*", "--refresh-host-key"],
                [production],
                "完整 hostname",
            ),
            (
                ["AIR-EXAMPLE-Leaf01", "--refresh-host-key"],
                [air],
                "仅用于 Production",
            ),
        )
        for argv, devices, message in cases:
            with self.subTest(argv=argv), self.assertRaisesRegex(
                self.manual.ManualZtpError, message,
            ):
                args = self.manual.parser().parse_args(argv)
                self.manual.validate_host_key_refresh_policy(args, devices)

    def test_refresh_host_key_help_states_production_identity_risk(self):
        help_text = self.manual.parser().format_help()
        self.assertIn("--refresh-host-key", help_text)
        self.assertIn("高风险显式授权", help_text)
        self.assertIn("Production", help_text)
        self.assertIn("hostname", help_text)
        self.assertIn("身份 MAC", help_text)

    def test_password_ssh_never_auto_refreshes_air_host_key(self):
        client = mock.Mock()
        client.args.connect_timeout = 5
        client.args.refresh_host_key = False
        client.args.ssh_password = True
        client.run.return_value = mock.Mock(
            returncode=255, stdout="",
            stderr="Host key verification failed",
        )
        device = {
            "hostname": "AIR-EXAMPLE-Leaf01", "type": "air", "user": "cumulus",
            "mac_plain": "020000000001",
            "candidates": [("192.0.2.1", "eth0")],
        }
        with self.assertRaisesRegex(
            self.manual.ManualZtpError, "password SSH never refreshes",
        ):
            self.manual.connect_and_verify(client, device)
        client.reset_host_key.assert_not_called()
        self.assertEqual(1, client.run.call_count)

    def test_host_key_failure_does_not_claim_restricted_helper_is_missing(self):
        host_key_error = (
            "action=http-manual-ztp-oobofoob "
            "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!"
        )
        self.assertFalse(self.worker.needs_helper_hint(host_key_error))
        self.assertTrue(self.worker.needs_helper_hint("sudo: a password is required"))

    def test_gui_worker_rejects_wildcard_request_even_if_file_is_modified(self):
        with tempfile.TemporaryDirectory() as directory:
            request = Path(directory) / "request.json"
            request.write_text(
                '{"action":"trigger","hostname":"AIR-EXAMPLE-SITE01-*"}\n',
                encoding="utf-8",
            )
            original = self.worker.REQUEST_FILE
            try:
                self.worker.REQUEST_FILE = request
                self.assertEqual([], self.worker.pop_requests())
            finally:
                self.worker.REQUEST_FILE = original

    def test_gui_queue_keeps_different_devices_and_deduplicates_same_device(self):
        with tempfile.TemporaryDirectory() as directory:
            request = Path(directory) / "request.json"
            request.write_text('{"requests":[]}\n', encoding="utf-8")
            worker_request = self.worker.REQUEST_FILE
            cgi_request = self.cgi.REQUEST_FILE
            try:
                self.worker.REQUEST_FILE = request
                self.cgi.REQUEST_FILE = request
                self.assertTrue(self.cgi.enqueue_request("AIR-EXAMPLE-Leaf01"))
                self.assertTrue(self.cgi.enqueue_request("AIR-EXAMPLE-Leaf02"))
                self.assertFalse(self.cgi.enqueue_request("air-example-leaf01"))
                queued = self.worker.pop_requests()
            finally:
                self.worker.REQUEST_FILE = worker_request
                self.cgi.REQUEST_FILE = cgi_request
        self.assertEqual(
            {"AIR-EXAMPLE-Leaf01", "AIR-EXAMPLE-Leaf02"},
            {item["hostname"] for item in queued},
        )

    def test_gui_reset_queue_preserves_operation_and_device_isolation(self):
        with tempfile.TemporaryDirectory() as directory:
            request = Path(directory) / "request.json"
            request.write_text('{"requests":[]}\n', encoding="utf-8")
            worker_request, cgi_request = self.worker.REQUEST_FILE, self.cgi.REQUEST_FILE
            try:
                self.worker.REQUEST_FILE = request
                self.cgi.REQUEST_FILE = request
                self.assertTrue(self.cgi.enqueue_request("AIR-EXAMPLE-Leaf01", "reset"))
                self.assertTrue(self.cgi.enqueue_request("AIR-EXAMPLE-Leaf02", "trigger"))
                queued = self.worker.pop_requests()
            finally:
                self.worker.REQUEST_FILE = worker_request
                self.cgi.REQUEST_FILE = cgi_request
        self.assertEqual(
            {"AIR-EXAMPLE-Leaf01": "reset", "AIR-EXAMPLE-Leaf02": "trigger"},
            {item["hostname"]: item["action"] for item in queued},
        )

    def test_worker_retains_confirm_while_preview_future_is_still_active(self):
        """The exact confirm must survive preview_ready/future.done ordering."""
        with tempfile.TemporaryDirectory() as directory:
            request = Path(directory) / "request.json"
            request.write_text('{"requests":[]}\n', encoding="utf-8")
            worker_request = self.worker.REQUEST_FILE
            cgi_request = self.cgi.REQUEST_FILE
            try:
                self.worker.REQUEST_FILE = request
                self.cgi.REQUEST_FILE = request
                self.assertTrue(self.cgi.enqueue_request(
                    "AIR-EXAMPLE-Leaf01", "trigger", "web:preview-1",
                    "web:preview-1:AIR-EXAMPLE-Leaf01", "confirm",
                ))
                self.assertTrue(self.cgi.enqueue_request(
                    "AIR-EXAMPLE-Leaf02", "trigger", "web:preview-2",
                    "web:preview-2:AIR-EXAMPLE-Leaf02", "preview",
                ))

                runnable = self.worker.pop_requests({"air-example-leaf01"})
                self.assertEqual(
                    ["AIR-EXAMPLE-Leaf02"],
                    [item["hostname"] for item in runnable],
                )
                retained = self.cgi.read_queue()
                self.assertEqual(1, len(retained))
                self.assertEqual("AIR-EXAMPLE-Leaf01", retained[0]["hostname"])
                self.assertEqual("confirm", retained[0]["phase"])
                self.assertEqual("web:preview-1", retained[0]["operation_id"])

                # A CGI request arriving after that poll is preserved alongside
                # the deferred confirm; neither device blocks the other.
                self.assertTrue(self.cgi.enqueue_request(
                    "AIR-EXAMPLE-Leaf03", "trigger", "web:preview-3",
                    "web:preview-3:AIR-EXAMPLE-Leaf03", "preview",
                ))
                next_poll = self.worker.pop_requests()
            finally:
                self.worker.REQUEST_FILE = worker_request
                self.cgi.REQUEST_FILE = cgi_request
        self.assertEqual(
            ["AIR-EXAMPLE-Leaf01", "AIR-EXAMPLE-Leaf03"],
            [item["hostname"] for item in next_poll],
        )
        self.assertEqual("web:preview-1:AIR-EXAMPLE-Leaf01", next_poll[0]["trigger_id"])

    def test_worker_never_truncates_an_oversize_request_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            request = Path(directory) / "request.json"
            payload = b"x" * (self.worker.QUEUE_MAX_BYTES + 1)
            request.write_bytes(payload)
            original = self.worker.REQUEST_FILE
            try:
                self.worker.REQUEST_FILE = request
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual([], self.worker.pop_requests())
            finally:
                self.worker.REQUEST_FILE = original
            self.assertEqual(payload, request.read_bytes())

    def test_worker_releases_at_most_one_same_device_request_per_poll(self):
        with tempfile.TemporaryDirectory() as directory:
            request = Path(directory) / "request.json"
            request.write_text(json.dumps({"requests": [
                {
                    "action": "trigger", "hostname": "AIR-EXAMPLE-Leaf01",
                    "phase": "preview", "operation_id": "web:first",
                    "trigger_id": "web:first:AIR-EXAMPLE-Leaf01",
                },
                {
                    "action": "trigger", "hostname": "air-example-leaf01",
                    "phase": "confirm", "operation_id": "web:second",
                    "trigger_id": "web:second:AIR-EXAMPLE-Leaf01",
                },
            ]}) + "\n", encoding="utf-8")
            original = self.worker.REQUEST_FILE
            try:
                self.worker.REQUEST_FILE = request
                first_poll = self.worker.pop_requests()
                retained = json.loads(request.read_text(encoding="utf-8"))[
                    "requests"
                ]
                blocked_poll = self.worker.pop_requests({"AIR-EXAMPLE-LEAF01"})
                final_poll = self.worker.pop_requests()
            finally:
                self.worker.REQUEST_FILE = original
        self.assertEqual(["web:first"], [
            item["operation_id"] for item in first_poll
        ])
        self.assertEqual(["web:second"], [
            item["operation_id"] for item in retained
        ])
        self.assertEqual([], blocked_poll)
        self.assertEqual(["web:second"], [
            item["operation_id"] for item in final_poll
        ])

    def test_gui_status_updates_are_independent_per_device(self):
        with tempfile.TemporaryDirectory() as directory:
            status_file = Path(directory) / "status.json"
            original = self.worker.STATUS_FILE
            try:
                self.worker.STATUS_FILE = status_file
                self.worker.initialize_status("air")
                self.worker.write_device_status("AIR-EXAMPLE-Leaf01", "running", scope="air")
                self.worker.write_device_status("AIR-EXAMPLE-Leaf02", "success", scope="air")
                devices = self.worker.read_status("air")["devices"]
            finally:
                self.worker.STATUS_FILE = original
        self.assertEqual("running", devices["AIR-EXAMPLE-Leaf01"]["state"])
        self.assertEqual("success", devices["AIR-EXAMPLE-Leaf02"]["state"])

    def test_worker_discovers_cli_operation_from_active_project(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            devices_csv = project / "02-devices_config.csv"
            trigger_dir = project / "99-output-ztp/manual-trigger/20260824_150000"
            trigger_dir.mkdir(parents=True)
            devices_csv.write_text("hostname,type\nAIR-EXAMPLE-Leaf01,air\n", encoding="utf-8")
            (trigger_dir / "summary.json").write_text(json.dumps({
                "project": "project", "trigger_source": "manual_cli",
                "state": "triggered", "requested_at": "2026-08-24T15:00:00+00:00",
                "generated_at": "2026-08-24T15:00:10+00:00",
                "targets": [{"hostname": "AIR-EXAMPLE-Leaf01", "type": "air"}],
                "results": [{
                    "hostname": "AIR-EXAMPLE-Leaf01", "state": "triggered",
                    "trigger_id": "cli-123", "started_at": "2026-08-24T15:00:01+00:00",
                    "finished_at": "2026-08-24T15:00:09+00:00",
                }],
            }), encoding="utf-8")
            original = self.worker.DEVICES_CSV
            try:
                self.worker.DEVICES_CSV = devices_csv
                operations = self.worker.latest_cli_operations()
            finally:
                self.worker.DEVICES_CSV = original
        operation = operations["air-example-leaf01"]
        self.assertEqual("triggered", operation["state"])
        self.assertEqual("cli-123", operation["operation_id"])
        self.assertEqual("manual_cli", operation["trigger_source"])

    def test_gui_waits_for_a_new_completed_ztp_round(self):
        old_complete = {
            "ztp_round": 4, "progress": 100,
            "complete_status": "success",
        }
        new_running = {
            "ztp_round": 5, "progress": 80,
            "complete_status": "pending",
        }
        new_complete = {
            "ztp_round": 5, "progress": 100,
            "complete_status": "success",
        }
        self.assertFalse(self.worker.new_round_complete(old_complete, 4))
        self.assertFalse(self.worker.new_round_complete(new_running, 4))
        self.assertTrue(self.worker.new_round_complete(new_complete, 4))

    def test_gui_accepts_exact_current_round_air_baseline_warning_as_complete(self):
        completed_warning = {
            "hostname": "AIR-EXAMPLE-FGT-FW", "ztp_round": 1, "progress": 100,
            "overall": "warning", "complete_status": "warning",
            "complete_success_index": 1, "failure_reason": "",
            "report_generated_at": "2026-09-01T05:59:04+00:00",
            "trigger_source": "manual_reset_web",
            "trigger_id": "reset-air-example-fgt-fw",
        }
        self.assertTrue(self.worker.new_round_complete(
            completed_warning, 0, "2026-09-01T05:52:42+00:00",
            "operation-air-example-fgt-fw", "manual_reset_web",
            "reset-air-example-fgt-fw",
        ))
        for field, value in (
            ("complete_success_index", 0),
            ("overall", "failed"),
            ("failure_reason", "dedicated config failed"),
        ):
            with self.subTest(field=field):
                rejected = {**completed_warning, field: value}
                self.assertFalse(self.worker.new_round_complete(
                    rejected, 0, "2026-09-01T05:52:42+00:00",
                    "operation-air-example-fgt-fw", "manual_reset_web",
                    "reset-air-example-fgt-fw",
                ))

    def test_completion_wait_closes_air_baseline_warning_without_timeout(self):
        completed_warning = {
            "hostname": "AIR-EXAMPLE-FGT-FW", "ztp_round": 1, "progress": 100,
            "overall": "warning", "complete_status": "warning",
            "complete_success_index": 1, "failure_reason": "",
            "report_generated_at": "2026-09-01T05:59:04+00:00",
            "trigger_source": "manual_reset_web",
            "trigger_id": "reset-air-example-fgt-fw",
        }
        with mock.patch.object(
            self.worker, "latest_device_state", return_value=completed_warning,
        ), mock.patch.object(
            self.worker, "write_device_status",
        ) as write_status, mock.patch.object(
            self.worker.time, "sleep",
        ) as sleep:
            result = self.worker.wait_for_completion(
                "AIR-EXAMPLE-FGT-FW", "air", 0,
                "2026-09-01T05:52:42+00:00",
                "2026-09-01T05:52:44+00:00", 60, 1,
                "operation-air-example-fgt-fw", "manual_reset_web", "reset",
                "reset-air-example-fgt-fw", "reset",
            )
        self.assertTrue(result)
        sleep.assert_not_called()
        self.assertEqual("success", write_status.call_args.args[1])
        self.assertEqual("warning", write_status.call_args.kwargs["overall"])
        self.assertEqual(1, write_status.call_args.kwargs["completed_round"])

    def test_gui_completion_requires_the_same_manual_operation(self):
        completed = {
            "ztp_round": 5, "progress": 100,
            "complete_status": "success",
            "report_generated_at": "2026-08-24T10:02:00+08:00",
            "trigger_source": "automatic", "trigger_id": "",
        }
        self.assertFalse(self.worker.new_round_complete(
            completed, 4, "2026-08-24T10:00:00+08:00",
            "cli-123", "manual_cli",
        ))
        completed.update({
            "trigger_source": "manual_cli", "trigger_id": "cli-123",
        })
        self.assertTrue(self.worker.new_round_complete(
            completed, 4, "2026-08-24T10:00:00+08:00",
            "cli-123", "manual_cli",
        ))

    def test_reset_transient_ssh_failure_is_not_a_terminal_operation_failure(self):
        transient = {
            "trigger_id": "reset-123", "trigger_source": "manual_reset_web",
            "report_generated_at": "2026-08-31T13:07:10+08:00",
            "overall": "failed", "complete_status": "pending",
            "failure_reason": "AUTHENTICATION_FAILED",
        }
        self.assertEqual("", self.worker.matching_terminal_failure(
            transient, "2026-08-31T13:07:00+08:00",
            "reset-123", "manual_reset_web",
        ))

        completed_failure = {
            **transient,
            "report_generated_at": "2026-08-31T13:08:30+08:00",
            "ztp_round": 1, "complete_success_index": 1,
            "complete_status": "warning",
            "failure_reason": "专用 YAML apply 失败，已完成默认配置回退",
        }
        self.assertIn("专用 YAML apply 失败", self.worker.matching_terminal_failure(
            completed_failure, "2026-08-31T13:07:00+08:00",
            "reset-123", "manual_reset_web",
        ))

        explicit_complete_failure = {
            **transient, "overall": "running", "complete_status": "failed",
            "failure_reason": "bootstrap terminal failure",
        }
        self.assertEqual(
            "bootstrap terminal failure",
            self.worker.matching_terminal_failure(
                explicit_complete_failure, "2026-08-31T13:07:00+08:00",
                "reset-123", "manual_reset_web",
            ),
        )

        stale_complete = {
            **completed_failure,
            "ztp_round": 5, "complete_success_index": 4,
            "failure_reason": "AUTHENTICATION_FAILED",
        }
        self.assertEqual("", self.worker.matching_terminal_failure(
            stale_complete, "2026-08-31T13:07:00+08:00",
            "reset-123", "manual_reset_web",
        ))

    def test_completion_wait_survives_transient_ssh_failure_then_succeeds(self):
        transient = {
            "hostname": "AIR-EXAMPLE-Border01", "ztp_round": 1, "progress": 33,
            "overall": "failed", "complete_status": "pending",
            "complete_success_index": 0,
            "report_generated_at": "2026-08-31T13:07:10+08:00",
            "trigger_source": "manual_reset_web", "trigger_id": "reset-123",
            "failure_reason": "AUTHENTICATION_FAILED",
        }
        completed = {
            **transient, "progress": 100, "overall": "success",
            "complete_status": "success", "complete_success_index": 1,
            "report_generated_at": "2026-08-31T13:08:30+08:00",
            "failure_reason": "",
        }
        with mock.patch.object(
            self.worker, "latest_device_state", side_effect=[transient, completed],
        ), mock.patch.object(
            self.worker, "write_device_status",
        ) as write_status, mock.patch.object(self.worker.time, "sleep"):
            result = self.worker.wait_for_completion(
                "AIR-EXAMPLE-Border01", "air", 0,
                "2026-08-31T13:07:00+08:00",
                "2026-08-31T13:07:05+08:00", 60, 1,
                "operation-123", "manual_reset_web", "reset", "reset-123",
                "reset",
            )
        self.assertTrue(result)
        written_states = [call.args[1] for call in write_status.call_args_list]
        self.assertEqual(["ztp_running", "success"], written_states)
        self.assertNotIn("failed", written_states)

    def test_failed_operation_reconciliation_requires_exact_completed_report(self):
        failed = {
            "state": "failed", "hostname": "AIR-EXAMPLE-Border01", "scope": "air",
            "started_at": "2026-08-31T13:07:00+08:00",
            "command_finished_at": "2026-08-31T13:07:05+08:00",
            "baseline_round": 0, "expected_round": 1,
            "operation_id": "operation-123", "trigger_id": "reset-123",
            "trigger_source": "manual_reset_web", "operation": "reset",
            "effective_operation": "reset", "requested_operation": "reset",
        }
        completed = {
            "hostname": "AIR-EXAMPLE-Border01", "ztp_round": 1, "progress": 100,
            "overall": "success", "complete_status": "success",
            "complete_success_index": 1,
            "report_generated_at": "2026-08-31T13:08:30+08:00",
            "trigger_source": "manual_reset_web", "trigger_id": "reset-123",
            "failure_reason": "",
        }
        with mock.patch.object(
            self.worker, "read_status",
            return_value={"scope": "air", "devices": {"AIR-EXAMPLE-Border01": failed}},
        ), mock.patch.object(
            self.worker, "latest_device_state", return_value=completed,
        ), mock.patch.object(
            self.worker, "write_device_status",
        ) as write_status:
            corrected = self.worker.reconcile_failed_operations("air", set())
        self.assertEqual(1, corrected)
        self.assertEqual("AIR-EXAMPLE-Border01", write_status.call_args.args[0])
        self.assertEqual("success", write_status.call_args.args[1])
        self.assertEqual(1, write_status.call_args.kwargs["completed_round"])
        self.assertEqual("reset-123", write_status.call_args.kwargs["trigger_id"])

    def test_failed_air_baseline_operation_reconciles_from_warning_completion(self):
        failed = {
            "state": "failed", "hostname": "AIR-EXAMPLE-FGT-FW", "scope": "air",
            "started_at": "2026-09-01T05:52:42+00:00",
            "command_finished_at": "2026-09-01T05:52:44+00:00",
            "baseline_round": 0, "expected_round": 1,
            "operation_id": "operation-air-example-fgt-fw",
            "trigger_id": "reset-air-example-fgt-fw",
            "trigger_source": "manual_reset_web", "operation": "reset",
            "effective_operation": "reset", "requested_operation": "reset",
        }
        completed_warning = {
            "hostname": "AIR-EXAMPLE-FGT-FW", "ztp_round": 1, "progress": 100,
            "overall": "warning", "complete_status": "warning",
            "complete_success_index": 1, "failure_reason": "",
            "report_generated_at": "2026-09-01T05:59:04+00:00",
            "trigger_source": "manual_reset_web",
            "trigger_id": "reset-air-example-fgt-fw",
        }
        with mock.patch.object(
            self.worker, "read_status",
            return_value={"scope": "air", "devices": {"AIR-EXAMPLE-FGT-FW": failed}},
        ), mock.patch.object(
            self.worker, "latest_device_state", return_value=completed_warning,
        ), mock.patch.object(
            self.worker, "write_device_status",
        ) as write_status:
            corrected = self.worker.reconcile_failed_operations("air", set())
        self.assertEqual(1, corrected)
        self.assertEqual("success", write_status.call_args.args[1])
        self.assertEqual("warning", write_status.call_args.kwargs["overall"])
        self.assertEqual(1, write_status.call_args.kwargs["completed_round"])

    def test_failed_operation_reconciliation_rejects_mismatch_or_active_host(self):
        failed = {
            "state": "failed", "hostname": "AIR-EXAMPLE-Border01",
            "started_at": "2026-08-31T13:07:00+08:00",
            "baseline_round": 0, "operation_id": "operation-123",
            "trigger_id": "reset-123", "trigger_source": "manual_reset_web",
            "operation": "reset",
        }
        completed = {
            "hostname": "AIR-EXAMPLE-Border01", "ztp_round": 1, "progress": 100,
            "overall": "success", "complete_status": "success",
            "complete_success_index": 1,
            "report_generated_at": "2026-08-31T13:08:30+08:00",
            "trigger_source": "manual_reset_web", "trigger_id": "other-reset",
        }
        status = {"scope": "air", "devices": {"AIR-EXAMPLE-Border01": failed}}
        with mock.patch.object(
            self.worker, "read_status", return_value=status,
        ), mock.patch.object(
            self.worker, "latest_device_state", return_value=completed,
        ) as latest_state, mock.patch.object(
            self.worker, "write_device_status",
        ) as write_status:
            self.assertEqual(
                0, self.worker.reconcile_failed_operations("air", set())
            )
            latest_state.return_value = {
                **completed, "trigger_id": "reset-123",
                "trigger_source": "manual_cli",
            }
            self.assertEqual(
                0, self.worker.reconcile_failed_operations("air", set())
            )
            latest_state.return_value = {
                **completed, "hostname": "AIR-EXAMPLE-Border02",
                "trigger_id": "reset-123",
            }
            self.assertEqual(
                0, self.worker.reconcile_failed_operations("air", set())
            )
            latest_state.return_value = {
                **completed, "trigger_id": "reset-123",
            }
            self.assertEqual(
                0,
                self.worker.reconcile_failed_operations(
                    "air", {"air-example-border01"},
                ),
            )
        write_status.assert_not_called()

    def test_gui_does_not_accept_an_old_report_when_baseline_is_missing(self):
        old_report = {
            "ztp_round": 4, "progress": 100,
            "complete_status": "success",
            "report_generated_at": "2026-08-24T09:00:00+08:00",
        }
        self.assertFalse(self.worker.new_round_complete(
            old_report, 0, "2026-08-24T10:00:00+08:00",
        ))

    def test_gui_reads_newest_exact_device_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, generated, ztp_round, percent, complete in (
                ("first", "2026-08-24T10:00:00+08:00", 2, 100, "success"),
                ("second", "2026-08-24T10:01:00+08:00", 3, 60, "pending"),
            ):
                run = root / name
                run.mkdir()
                (run / "report.json").write_text(json.dumps({
                    "generated_at": generated,
                    "devices": [{
                        "hostname": "AIR-EXAMPLE-Leaf01", "ztp_round": ztp_round,
                        "progress": {"percent": percent}, "overall": "pending",
                        "stages": {"complete": {"status": complete}},
                    }],
                }), encoding="utf-8")
            original = self.worker.ZTP_STATUS_DIR
            try:
                self.worker.ZTP_STATUS_DIR = root
                state = self.worker.latest_device_state("AIR-EXAMPLE-Leaf01")
            finally:
                self.worker.ZTP_STATUS_DIR = original
        self.assertEqual(3, state["ztp_round"])
        self.assertEqual(60, state["progress"])

    def test_gui_device_state_exposes_complete_success_index(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / "current"
            run.mkdir()
            (run / "report.json").write_text(json.dumps({
                "generated_at": "2026-08-31T13:08:30+08:00",
                "devices": [{
                    "hostname": "AIR-EXAMPLE-Border01", "ztp_round": 1,
                    "progress": {"percent": 100}, "overall": "success",
                    "stages": {"complete": {
                        "status": "success", "success_index": 1,
                    }},
                }],
            }), encoding="utf-8")
            original = self.worker.ZTP_STATUS_DIR
            try:
                self.worker.ZTP_STATUS_DIR = root
                state = self.worker.latest_device_state("AIR-EXAMPLE-Border01")
            finally:
                self.worker.ZTP_STATUS_DIR = original
        self.assertEqual(1, state["complete_success_index"])

    def test_gui_completion_wait_closes_only_on_new_successful_round(self):
        completed = {
            "hostname": "AIR-EXAMPLE-Leaf01", "ztp_round": 3,
            "progress": 100, "overall": "success",
            "complete_status": "success",
            "trigger_source": "manual_web", "trigger_id": "",
            "report_generated_at": "2026-08-24T10:02:00+08:00",
        }
        with mock.patch.object(
            self.worker, "latest_device_state", return_value=completed,
        ), mock.patch.object(self.worker, "write_device_status") as write_status:
            self.assertTrue(self.worker.wait_for_completion(
                "AIR-EXAMPLE-Leaf01", "air", 2,
                "2026-08-24T10:00:00+08:00",
                "2026-08-24T10:00:30+08:00", 60, 1,
            ))
        self.assertEqual("AIR-EXAMPLE-Leaf01", write_status.call_args.args[0])
        self.assertEqual("success", write_status.call_args.args[1])
        self.assertEqual(3, write_status.call_args.kwargs["completed_round"])

    def test_cli_finished_marker_matches_report_by_trigger_id(self):
        operation = {
            "operation_id": "cli-123",
            "started_at": "2026-08-24T10:00:00+08:00",
            "updated_at": "2026-08-24T10:00:10+08:00",
        }
        self.assertTrue(self.worker.operation_marker_matches(
            {"trigger_id": "cli-123", "manual_cycle_marker": operation["updated_at"]},
            operation,
        ))
        self.assertFalse(self.worker.operation_marker_matches(
            {"trigger_id": "another", "manual_cycle_marker": operation["updated_at"]},
            operation,
        ))
        operation["operation_id"] = ""
        self.assertTrue(self.worker.operation_marker_matches(
            {"manual_cycle_marker": operation["updated_at"]}, operation,
        ))

    def test_cumulus_gui_uses_restricted_no_argument_helper(self):
        source = (ROOT / "ztp/manual-ztp.py").read_text(encoding="utf-8")
        template = (ROOT / "ztp/templates/ztp-bootstrap.sh").read_text(encoding="utf-8")
        self.assertEqual(
            "/usr/local/sbin/http-manual-ztp-oob",
            self.manual.restricted_helper(
                "http://192.0.2.1/ztp/ztp-bootstrap_oob.sh"
            ),
        )
        self.assertEqual(
            "/usr/local/sbin/http-manual-ztp-oobofoob",
            self.manual.restricted_helper(
                "http://192.0.2.2/ztp/ztp-bootstrap_oobofoob.sh"
            ),
        )
        self.assertIn("http-manual-ztp-oobofoob", source)
        self.assertIn('if [ "\\$#" -ne 0 ]', template)
        self.assertIn('"oob|${MANUAL_ZTP_OOB_URL}"', template)
        self.assertIn('"oobofoob|${MANUAL_ZTP_OOBOFOOB_URL}"', template)
        self.assertIn("cumulus ALL=(root) NOPASSWD: %s", template)
        self.assertNotIn('reset_helper="/usr/local/sbin/http-manual-reset-${role}"', template)
        self.assertNotIn("scheduled Cumulus reinstall", template)
        self.assertIn("legacy reset helpers removed", template)

    def test_interactive_cumulus_trigger_supports_sudo_password(self):
        args = argparse.Namespace(
            sudo_password=True, non_interactive=False,
            ssh_password=False, connect_timeout=10, identity=None,
        )
        with tempfile.TemporaryDirectory() as directory, mock.patch(
            "getpass.getpass", return_value="secret"
        ):
            client = self.manual.SshClient(args, Path(directory) / "known_hosts")
            command, stdin = client.sudo_command(
                {"hostname": "EXAMPLE-Leaf01", "user": "cumulus"},
                ["ztp", "-r", "http://192.0.2.1/ztp/bootstrap.sh"],
            )
        self.assertTrue(command.startswith("sudo -S -p '' -- ztp -r "))
        self.assertEqual("secret\n", stdin)

    def test_manual_result_records_unified_source_and_trigger_id(self):
        client = mock.Mock()
        client.args.command_timeout = 10
        client.args.non_interactive = True
        client.sudo_command.return_value = ("sudo -n helper", "")
        client.run.side_effect = [
            mock.Mock(returncode=0, stdout="config\n", stderr=""),
            mock.Mock(
                returncode=0,
                stdout=(
                    "[2026-08-31T07:23:52Z] ======================== ZTP START ========================\n"
                    "[2026-08-31T07:23:55Z] [ZTP] Cumulus provision complete\n"
                    "[2026-08-31T07:23:55Z] ======================== ZTP FINISH ========================\n"
                ),
                stderr="",
            ),
        ]
        device = {
            "hostname": "AIR-EXAMPLE-Leaf01", "type": "air",
            "ip": "192.0.2.1", "eth0_ip": "192.0.2.1",
            "mac_plain": "020000000001",
        }
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            self.manual, "connect_and_verify", return_value=("192.0.2.1", "eth0"),
        ):
            result = self.manual.trigger_one(
                client, device, "http://192.0.2.2/ztp/ztp-bootstrap_oob.sh",
                Path(directory) / "manual-trigger/run1",
                "manual_web", "web-123",
            )
        self.assertEqual("triggered", result["state"])
        self.assertEqual("manual_web", result["trigger_source"])
        self.assertEqual("web-123", result["trigger_id"])
        self.assertTrue(result["command_started_at"])
        self.assertLessEqual(result["command_started_at"], result["finished_at"])
        self.assertRegex(result["command_ztp_log_sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(result["command_ztp_complete"])

    def test_monitor_button_requires_user_confirmation(self):
        source = (ROOT / "monitor/generate-monitor-html.py").read_text(encoding="utf-8")
        self.assertIn("手工 ZTP", source)
        self.assertIn("window.confirm", source)
        self.assertIn("ManualZTPControl", source)
        self.assertIn("'ztp_running'", source)
        self.assertIn("ZTP执行中…", source)
        self.assertIn("ZTP 已完成", source)
        cgi = (ROOT / "monitor/manual-ztp-control.cgi").read_text(encoding="utf-8")
        self.assertIn('"queued", "running", "ztp_running", "time_sync_queued", "time_sync_running"', cgi)
        self.assertIn("manualZtpDeviceState", source)
        self.assertIn("resetManualZtpRow", source)
        self.assertIn("manualZtpIntents", source)
        self.assertIn("setManualZtpIntent", source)
        self.assertIn("renderManualZtpFailureRow", source)
        self.assertIn("重试${{idleLabel}}", source)
        self.assertIn("action=preview&operation=${{action}}", source)
        self.assertIn("action=confirm&hostname=${{encodeURIComponent(hostname)}}", source)
        self.assertIn("changed_paths", source)
        # This JavaScript lives inside a Python triple-quoted template.  The
        # source therefore needs two backslashes so the generated HTML keeps
        # one literal ``\\n`` escape instead of emitting a syntax-breaking
        # newline inside a single-quoted JavaScript string.
        self.assertIn("join('\\\\n')", source)
        self.assertIn("requestManualRenew", source)
        self.assertIn("等待${{expected}}", source)
        self.assertIn("CLI执行中…", source)
        self.assertIn("resetReportMatchesIntent", source)
        self.assertIn("manualTriggerSourceLabel", source)
        self.assertIn('class="ztp-overall-meta"', source)
        self.assertIn('class="ztp-meta-row"', source)
        self.assertEqual(3, source.count('class="ztp-overall-meta"'))
        self.assertEqual(3, source.count('class="ztp-meta-row"'))
        self.assertEqual(
            3, source.count('class="ztp-meta-row ztp-overall-result"'),
        )
        self.assertIn(".ztp-meta-row {{ display:flex;", source)
        self.assertIn(".ztp-event-time {{ display:block;", source)
        self.assertIn("root.querySelectorAll('.ztp-event-time')", source)
        self.assertIn("return isReset ? 'CLI 重置' : 'CLI 手工';", source)
        self.assertIn("padding:8px 7px; text-align:center", source)
        self.assertIn("text-align:center; vertical-align:middle", source)
        self.assertIn("margin:1px auto", source)
        self.assertIn(
            "if (!force && isReset && resetReportMatchesIntent(row, deviceState)) return;",
            source,
        )
        self.assertIn(
            "if (!force && !isReset && renderedRound > baselineRound) return;",
            source,
        )
        self.assertIn("workerReset ? 0 : renderedRound", source)
        self.assertIn("workerReset ? 1 : renderedRound + 1", source)
        self.assertIn("nv action reset system factory-default force", source)
        self.assertIn("手工重置：等待系统重启并重新进入 ZTP", source)
        self.assertNotIn("手工重置：等待系统安装并重新进入 ZTP", source)
        self.assertIn("convertDisplayedTimes", source)
        self.assertNotIn("let manualZtpState =", source)
        self.assertIn("requestTimeSync", source)
        self.assertIn("action=time-sync", source)
        self.assertIn("TIME_SYNC_BUSY_STATES", source)
        self.assertIn("const timeSyncOperation = timeSyncBusy", source)
        self.assertIn("if (timeSyncOperation && intent)", source)
        self.assertIn(
            "if ((previewBusy || operationBusy || previewReady) && !intent)",
            source,
        )
        self.assertNotIn("if ((workerBusy || previewReady) && !intent)", source)
        self.assertIn("http-sync-management-time", (
            ROOT / "ztp/templates/ztp-bootstrap.sh"
        ).read_text(encoding="utf-8"))

    def test_rendered_ztp_device_has_exact_hostname_action_button(self):
        monitor = load_module(
            "manual_ztp_monitor_render_contract",
            ROOT / "monitor/generate-monitor-html.py",
        )
        html = monitor.render_ztp_status_rows({
            "available": True,
            "generated_at": "2026-08-24T12:00:00+00:00",
            "devices": [{
                "hostname": "AIR-EXAMPLE-SITE01-TAN-Leaf01", "type": "air",
                "template": "tan-leaf", "ip": "192.0.2.10",
                "mac": "02:00:00:00:00:01", "ztp_round": 1,
                "stages": {"dhcp": {
                    "status": "success", "success_index": 1,
                    "timestamp": "2026-08-24T12:00:01+00:00",
                }},
                "time_sync": {
                    "status": "success", "offset_seconds": 0.2,
                    "checked_at": "2026-08-24T12:00:02+00:00",
                },
                "issues": [], "overall": "pending",
                "progress": {"percent": 0},
            }],
        })
        self.assertIn('data-hostname="AIR-EXAMPLE-SITE01-TAN-Leaf01"', html)
        self.assertIn('data-device-type="air"', html)
        self.assertIn('data-ztp-round="1"', html)
        self.assertIn('data-ztp-stage="dhcp"', html)
        self.assertIn('data-ztp-stage="bootstrap"', html)
        self.assertIn('data-ztp-stage="overall"', html)
        self.assertIn('>手工 ZTP</button>', html)
        self.assertIn('>手工重置</button>', html)
        self.assertIn('data-time-sync="status"', html)
        self.assertIn('>时间同步</button>', html)
        self.assertIn(
            '<span class="ztp-event-time">'
            + monitor.format_ztp_write_time("2026-08-24T12:00:01+00:00")
            + "</span>",
            html,
        )
        self.assertIn(
            '<span class="ztp-event-time">'
            + monitor.format_ztp_write_time("2026-08-24T12:00:02+00:00")
            + "</span>",
            html,
        )

    def test_time_sync_worker_uses_fixed_manual_operation(self):
        command = self.worker.command_for(
            "AIR-EXAMPLE-Leaf01", "air", "time-sync", "op-1", "trigger-1",
        )
        self.assertIn("--operation", command)
        self.assertIn("time-sync", command)
        self.assertNotIn("date", " ".join(command))

    def test_time_sync_helper_discovers_and_validates_runtime_vrfs(self):
        source = (ROOT / "ztp/templates/ztp-bootstrap.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("ip vrf show 2>/dev/null | awk", source)
        self.assertIn("length(\\$1) <= 15", source)
        self.assertIn("\\$1 ~ /^[A-Za-z0-9_.-]+\\$/", source)
        self.assertIn(
            'ip vrf exec "\\${route}" curl -fsS --connect-timeout 2',
            source,
        )
        self.assertIn("routes=\\$(list_routes)", source)
        self.assertIn("hwclock --systohc --utc", source)
        self.assertIn("url=%s rtc=%s", source)
        self.assertNotIn("for route in direct mgmt", source)
        main_start = source.index(
            'log "======================== ZTP START ========================"'
        )
        sync_call = source.index(
            "if ! sync_management_clock_for_ztp; then", main_start,
        )
        prefetch_call = source.index("\nprefetch_ssh_pubkeys\n", main_start)
        self.assertLess(sync_call, prefetch_call)
        self.assertIn(
            "Refusing to continue with an unverified ZTP-stage clock",
            source,
        )
        self.assertIn("[ZTP] TIME_SYNC_V1 before=", source)

    def test_reset_round_one_rejects_unindexed_old_success_and_then_shows_new_progress(self):
        monitor = load_module(
            "manual_reset_monitor_render_contract",
            ROOT / "monitor/generate-monitor-html.py",
        )
        stages = {
            name: {
                "status": "success", "success_index": 0,
                "timestamp": "2026-08-30T14:00:00+08:00",
            }
            for name in (
                "dhcp", "bootstrap", "config_http", "ssh", "network",
                "version", "config_apply", "ssh_keys", "complete",
            )
        }
        reset_device = {
            "hostname": "AIR-EXAMPLE-TAN-CP-Leaf01", "type": "air",
            "template": "tan-leaf", "ip": "192.0.2.10",
            "mac": "02:00:00:00:00:01", "ztp_round": 1,
            "trigger_source": "manual_reset_web",
            "trigger_id": "reset-2", "manual_operation": "reset",
            "manual_cycle_marker": "2026-08-30T15:00:00+08:00",
            "cycle_started_at": "2026-08-30T15:00:00+08:00",
            "reset_reboot_observed": False,
            "stages": stages, "issues": [], "overall": "running",
            "progress": {"percent": 0},
        }
        self.assertFalse(monitor.ztp_completed(reset_device))
        html = monitor.render_ztp_status_rows({
            "available": True,
            "generated_at": "2026-08-30T15:00:05+08:00",
            "devices": [reset_device],
        })
        self.assertIn('data-manual-operation="reset"', html)
        self.assertIn('data-trigger-id="reset-2"', html)
        self.assertIn('data-reset-reboot-observed="false"', html)
        self.assertRegex(
            html,
            r'data-ztp-stage="dhcp">.*?ztp-pending">等待1</span>',
        )
        self.assertRegex(
            html,
            r'data-ztp-stage="complete">.*?ztp-pending">等待1</span>',
        )
        self.assertNotIn("完成：", html)
        self.assertIn("来源：页面重置", html)

        reset_device["reset_reboot_observed"] = True
        reset_device["stages"]["dhcp"] = {
            "status": "success", "success_index": 1,
            "timestamp": "2026-08-30T15:01:00+08:00",
        }
        reset_device["stages"]["bootstrap"] = {
            "status": "pending", "success_index": 0, "timestamp": "",
        }
        html = monitor.render_ztp_status_rows({
            "available": True,
            "generated_at": "2026-08-30T15:01:05+08:00",
            "devices": [reset_device],
        })
        self.assertRegex(
            html,
            r'data-ztp-stage="dhcp">.*?ztp-success">成功1</span>',
        )
        self.assertRegex(
            html,
            r'data-ztp-stage="bootstrap">.*?ztp-pending">等待1</span>',
        )

        legacy_device = {
            "ztp_round": 1,
            "stages": {"complete": {"status": "success"}},
        }
        self.assertTrue(monitor.ztp_completed(legacy_device))

    def test_monitor_converts_all_displayed_times_in_the_browser(self):
        source = (ROOT / "monitor/generate-monitor-html.py").read_text(encoding="utf-8")
        self.assertIn("PAGE_SOURCE_TIME_ZONE", source)
        self.assertIn("sourceWallTimeToDate", source)
        self.assertIn("convertDisplayedTimes();", source)
        self.assertIn("date.getTimezoneOffset()", source)
        self.assertIn("zulu ? 'Z' : offset", source)
        self.assertIn("document.querySelectorAll('iframe')", source)


class EnvironmentProbeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.probe = load_module(
            "environment_probe_contract", ROOT / "ztp/environment_probe.py"
        )

    def test_same_ip_is_classified_by_actual_air_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / "devices.csv"
            inventory.write_text(
                "hostname,type,template,eth0_ip,eth0_pfx,eth0_gw,eth0_mac\n"
                "EXAMPLE-Border01,eth,default,192.0.2.10,24,192.0.2.1,02:00:00:00:00:01\n"
                "AIR-EXAMPLE-Border01,air,default,192.0.2.10,24,192.0.2.1,02:00:00:00:00:02\n",
                encoding="utf-8",
            )
            environment, details = self.probe.detect_environment(
                str(inventory),
                probe=lambda _ip, _user, _timeout: (
                    "AIR-EXAMPLE-Border01", "02:00:00:00:00:02"
                ),
            )
            self.assertEqual(environment, "air")
            self.assertEqual(details[0]["ip"], "192.0.2.10")

    def test_same_subnet_svi_is_used_when_eth0_is_unreachable(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / "devices.csv"
            inventory.write_text(
                "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,svi_ip,netmask\n"
                "EXAMPLE-Leaf03,eth,default,192.0.2.10,24,192.0.2.1,02:00:00:00:00:01,192.0.2.20,24\n"
                "AIR-EXAMPLE-Leaf03,air,default,192.0.2.10,24,192.0.2.1,02:00:00:00:00:02,,\n",
                encoding="utf-8",
            )
            attempts = []

            def probe(ip, _user, _timeout):
                attempts.append(ip)
                if ip == "192.0.2.20":
                    return "AIR-EXAMPLE-Leaf03", "02:00:00:00:00:02"
                return None

            environment, details = self.probe.detect_environment(
                str(inventory), probe=probe,
            )
            self.assertEqual(environment, "air")
            self.assertEqual(attempts, ["192.0.2.10", "192.0.2.20"])
            self.assertEqual(details[0]["connected_ip"], "192.0.2.20")

    def test_conflicting_hostname_and_mac_are_rejected(self):
        prod = self.probe.Identity("EXAMPLE-Border01", "192.0.2.10", "02:00:00:00:00:01", "prod")
        air = self.probe.Identity("AIR-EXAMPLE-Border01", "192.0.2.10", "02:00:00:00:00:02", "air")
        with self.assertRaises(RuntimeError):
            self.probe.classify_identity(
                "AIR-EXAMPLE-Border01", "02:00:00:00:00:01", prod, air
            )

    def test_unknown_actual_mac_is_rejected_even_when_hostname_matches(self):
        prod = self.probe.Identity("EXAMPLE-Border01", "192.0.2.10", "02:00:00:00:00:01", "prod")
        air = self.probe.Identity("AIR-EXAMPLE-Border01", "192.0.2.10", "02:00:00:00:00:02", "air")
        with self.assertRaises(RuntimeError):
            self.probe.classify_identity(
                "AIR-EXAMPLE-Border01", "02:00:00:00:00:ff", prod, air
            )


class YamlCollectFallbackContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.collector = load_module(
            "yaml_collect_fallback_contract", ROOT / "ztp/backup/yaml-collect.py"
        )

    def test_air_row_inherits_production_same_subnet_svi(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / "devices.csv"
            inventory.write_text(
                "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,svi_ip,netmask,svi_ip,netmask\n"
                "EXAMPLE-Leaf03,eth,default,192.0.2.10,24,192.0.2.1,02:00:00:00:00:01,198.51.100.20,24,192.0.2.20,24\n"
                "AIR-EXAMPLE-Leaf03,air,default,192.0.2.10,24,192.0.2.1,02:00:00:00:00:02,,,,\n",
                encoding="utf-8",
            )
            devices = self.collector.load_devices_csv(str(inventory))
            by_name = {device["hostname"]: device for device in devices}
            self.assertEqual(
                by_name["EXAMPLE-Leaf03"]["alternate_ssh_ips"], ["192.0.2.20"]
            )
            self.assertEqual(
                by_name["AIR-EXAMPLE-Leaf03"]["alternate_ssh_ips"], ["192.0.2.20"]
            )


class DualYamlPublishContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.publisher = load_module(
            "hostname2mac_contract", ROOT / "ztp/config/cumulus/d-hostname2mac.py"
        )

    def test_pair_gate_allows_only_hostname_delta(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prod = root / "EXAMPLE-Border01.yaml"
            air = root / "AIR-EXAMPLE-Border01.yaml"
            prod.write_text(
                "- set:\n    system:\n      hostname: EXAMPLE-Border01\n"
                "    interface:\n      swp1:\n        description: uplink\n",
                encoding="utf-8",
            )
            air.write_text(prod.read_text().replace(
                "hostname: EXAMPLE-Border01", "hostname: AIR-EXAMPLE-Border01"
            ), encoding="utf-8")
            devices = {
                "border01": {"hostname": "EXAMPLE-Border01", "dev_type": "eth"},
                "air-example-border01": {"hostname": "AIR-EXAMPLE-Border01", "dev_type": "air"},
            }
            self.assertEqual(
                self.publisher._validate_air_production_yaml_pairs(
                    str(root), devices
                ),
                1,
            )
            air.write_text(air.read_text().replace("uplink", "drift"), encoding="utf-8")
            with self.assertRaises(ValueError):
                self.publisher._validate_air_production_yaml_pairs(str(root), devices)


if __name__ == "__main__":
    unittest.main()
