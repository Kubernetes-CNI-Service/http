#!/usr/bin/env python3
"""Focused regression tests for the ZTP/release core review."""

from __future__ import annotations

import datetime as dt
import importlib.util
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
DEVICE_HEADER = (
    "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,"
    "eth1_ip,netmask,eth1_gw,eth1_mac\n"
)


def load_module(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


class BootstrapPublicationContractTests(unittest.TestCase):
    def test_load_renders_scripts_equal_template_except_runtime_parameters(self):
        runtime_line_keys = (
            "ZTP_SERVER", "ZTP_URL_PREFIX", "MANUAL_ZTP_OOB_URL",
            "MANUAL_ZTP_OOBOFOOB_URL", "TARGET_CL_VER", "ZTP_UPGRADE_ENABLED",
        )

        def normalized(path: Path) -> str:
            source = path.read_text(encoding="utf-8")
            for key in runtime_line_keys:
                source, count = re.subn(
                    rf"^{key}=.*$", f"{key}=<runtime>", source,
                    count=1, flags=re.MULTILINE,
                )
                self.assertEqual(1, count, f"{path}: {key}")
            source, count = re.subn(
                r"^PUBKEY_PATHS=\(\n.*?^\)$",
                "PUBKEY_PATHS=(<runtime>)", source, count=1,
                flags=re.MULTILINE | re.DOTALL,
            )
            self.assertEqual(1, count, str(path))
            return source

        load = load_module("day0_load_bootstrap_publication", "DAY0-Prepare/11-load.py")
        canonical = ROOT / "ztp/templates/ztp-bootstrap.sh"
        with tempfile.TemporaryDirectory() as directory:
            ztp_root = Path(directory) / "ztp"
            template_dir = ztp_root / "templates"
            template_dir.mkdir(parents=True)
            template = template_dir / "ztp-bootstrap.sh"
            template.write_bytes(canonical.read_bytes())
            public_key = Path(directory) / "operator.pub"
            public_key.write_text(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest operator\n",
                encoding="utf-8",
            )
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
                with mock.patch("builtins.print"):
                    load.render_ztp_runtime(
                        settings, (public_key,), frozenset({"eth"}),
                    )
            finally:
                load.ZTP_DIR = original

            expected = normalized(template)
            for relative in ("ztp-bootstrap_oob.sh", "ztp-bootstrap_oobofoob.sh"):
                rendered = ztp_root / relative
                self.assertEqual(expected, normalized(rendered), str(rendered))
                self.assertTrue(rendered.stat().st_mode & stat.S_IXUSR)
                self.assertNotIn('TMP_DIR="/tmp/ztp"', rendered.read_text())

    def test_authorized_keys_deduplicates_by_type_and_blob_on_bash_3(self):
        template = (ROOT / "ztp/templates/ztp-bootstrap.sh").read_text(encoding="utf-8")
        start = template.index("install_ssh_pubkeys() {")
        end = template.index("# 检查网络可达性", start)
        function = template[start:end]
        blob1 = "AAAAC3NzaC1lZDI1NTE5AAAAIFirst11111111111111111111111111111"
        blob2 = "AAAAC3NzaC1lZDI1NTE5AAAAISecond2222222222222222222222222222"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            switch_home = root / os.environ.get("USER", "operator")
            ssh_dir = switch_home / ".ssh"
            cache = root / "cache"
            ssh_dir.mkdir(parents=True)
            cache.mkdir()
            auth = ssh_dir / "authorized_keys"
            first = f'from="192.0.2.1" ssh-ed25519 {blob1} original-comment'
            auth.write_text(
                first + "\n" + f"ssh-ed25519 {blob1} duplicate-old-comment\n",
                encoding="utf-8",
            )
            (cache / "pubkey.1.cache").write_text(
                f"ssh-ed25519 {blob1} laptop-comment\n"
                f"ssh-ed25519 {blob2} management-comment\n",
                encoding="utf-8",
            )
            harness = root / "harness.sh"
            harness.write_text(
                "#!/bin/bash\nset -euo pipefail\n"
                f"TMP_DIR={shlex.quote(str(cache))}\n"
                "PUBKEY_PATHS=(/ztp/config/publickey/test.pub)\n"
                "log() { printf '%s\\n' \"$*\"; }\n"
                + function
                + f"\ninstall_ssh_pubkeys {shlex.quote(str(switch_home))}\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                ["bash", str(harness)], text=True, capture_output=True, check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr + result.stdout)
            lines = auth.read_text(encoding="utf-8").splitlines()
            self.assertEqual(first, lines[0])
            self.assertEqual(1, sum(blob1 in line for line in lines))
            self.assertEqual(1, sum(blob2 in line for line in lines))
            self.assertNotIn("laptop-comment", "\n".join(lines))
            self.assertIn("ACCESS_READY", result.stdout)
            self.assertEqual(0o600, stat.S_IMODE(auth.stat().st_mode))


class DhcpAndInventoryBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dynamic = load_module("review_dynamic_air", "ztp/dynamic_air_inventory.py")
        cls.load = load_module("review_day0_load", "DAY0-Prepare/11-load.py")
        cls.dhcp = load_module(
            "review_dhcp_generator", "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
        )
        cls.publisher = load_module(
            "review_hostname_publisher", "ztp/config/cumulus/d-hostname2mac.py",
        )
        cls.backup = load_module("review_yaml_collect", "ztp/backup/yaml-collect.py")
        cls.manual = load_module("review_manual_ztp", "ztp/manual-ztp.py")

    def test_dynamic_air_rejects_expired_active_lease(self):
        now = dt.datetime(2026, 8, 31, 12, 0, tzinfo=dt.timezone.utc)
        text = (
            "lease 192.0.2.10 {\n"
            "  ends 1 2026/08/31 11:59:59;\n"
            "  binding state active;\n"
            "  hardware ethernet 02:00:00:00:00:01;\n}\n"
            "lease 192.0.2.11 {\n"
            "  ends 1 2026/08/31 12:00:01;\n"
            "  binding state active;\n"
            "  hardware ethernet 02:00:00:00:00:02;\n}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dhcpd.leases"
            path.write_text(text, encoding="utf-8")
            leases = self.dynamic.active_leases(path, now=now)
        self.assertNotIn("020000000001", leases)
        self.assertEqual("192.0.2.11", leases["020000000002"])

    def test_positional_consumers_fail_closed_on_reordered_header(self):
        bad = DEVICE_HEADER.replace("eth0_ip,netmask", "netmask,eth0_ip", 1)
        row = "leaf01,eth,leaf,24,192.0.2.10,192.0.2.1,02:00:00:00:00:01,,,,\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "devices.csv"
            path.write_text(bad + row, encoding="utf-8")
            with self.assertRaises((ValueError, self.load.LoadError)):
                self.load.load_device_types(path)
            with self.assertRaises(ValueError):
                self.dhcp.load_csv(str(path))
            with self.assertRaises(ValueError):
                self.publisher.load_csv(str(path))
            with self.assertRaises(ValueError):
                self.backup.load_devices_csv(str(path))

    def test_unsafe_or_duplicate_hostname_never_becomes_a_path_or_dhcp_name(self):
        row = "../escape,eth,leaf,192.0.2.10,24,192.0.2.1,02:00:00:00:00:01,,,,\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "devices.csv"
            path.write_text(DEVICE_HEADER + row, encoding="utf-8")
            with self.assertRaises(self.load.LoadError):
                self.load.load_device_types(path)
            valid, errors = self.dhcp.validate(self.dhcp.load_csv(str(path)))
            self.assertEqual([], valid)
            self.assertTrue(any("hostname" in error for error in errors))
            with self.assertRaises(ValueError):
                self.publisher.load_csv(str(path))
            with self.assertRaises(ValueError):
                self.backup.load_devices_csv(str(path))

            path.write_text(
                DEVICE_HEADER
                + "Leaf01,eth,leaf,192.0.2.10,24,192.0.2.1,02:00:00:00:00:01,,,,\n"
                + "leaf01,air,leaf,192.0.2.11,24,192.0.2.1,02:00:00:00:00:02,,,,\n",
                encoding="utf-8",
            )
            with self.assertRaises(self.manual.ManualZtpError):
                self.manual.read_devices(path, dhcp_leases=Path(directory) / "none")

    def test_manual_deployment_lock_rejects_symlink_and_hardlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.touch()
            lock = root / ".deployment.lock"
            lock.symlink_to(target)
            original = self.manual.DEPLOYMENT_LOCK
            self.manual.DEPLOYMENT_LOCK = lock
            try:
                with self.assertRaises(self.manual.ManualZtpError):
                    self.manual.acquire_deployment_lock()
            finally:
                self.manual.DEPLOYMENT_LOCK = original

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / ".deployment.lock"
            replacement = root / "replacement"
            lock.touch()
            replacement.touch()
            original = self.manual.DEPLOYMENT_LOCK
            self.manual.DEPLOYMENT_LOCK = lock
            try:
                with mock.patch(
                    "deployment_lock.os.lstat",
                    return_value=os.lstat(replacement),
                ):
                    with self.assertRaises(self.manual.ManualZtpError):
                        self.manual.acquire_deployment_lock()
            finally:
                self.manual.DEPLOYMENT_LOCK = original

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / ".deployment.lock"
            lock.touch()
            os.link(lock, root / "second-name")
            original = self.manual.DEPLOYMENT_LOCK
            self.manual.DEPLOYMENT_LOCK = lock
            try:
                with self.assertRaises(self.manual.ManualZtpError):
                    self.manual.acquire_deployment_lock()
            finally:
                self.manual.DEPLOYMENT_LOCK = original


class OptimizeAndTopologySafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.feedback = load_module("review_feedback", "ztp/optimize/feedback.py")
        cls.links = load_module("review_sample_links", "ztp/optimize/sample_links.py")
        cls.topology = load_module(
            "review_cumulus_p2p", "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py",
        )
        cls.nvos = load_module(
            "review_nvos_p2p", "ztp/config/nvos/template/P2P/p2p-to-validation.py",
        )

    def test_archive_destination_symlink_and_directory_flood_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive_path = root / "input.tar"
            source = root / "source"
            source.mkdir()
            (source / "a").mkdir()
            (source / "b").mkdir()
            with tarfile.open(archive_path, "w") as archive:
                archive.add(source / "a", arcname="a")
                archive.add(source / "b", arcname="b")
            outside = root / "outside"
            outside.mkdir()
            linked = root / "linked"
            linked.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                self.feedback.extract_archive(archive_path, linked)
            old_limit = self.feedback.MAX_ARCHIVE_FILES
            self.feedback.MAX_ARCHIVE_FILES = 1
            try:
                with self.assertRaises(ValueError):
                    self.feedback.extract_archive(archive_path, root / "output")
            finally:
                self.feedback.MAX_ARCHIVE_FILES = old_limit

    def test_generated_latest_cannot_escape_project_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            output = project / "99-output-eth"
            outside = root / "outside"
            output.mkdir(parents=True)
            outside.mkdir()
            (outside / ".published-complete").write_text("ok\n", encoding="utf-8")
            (outside / "leaf.yaml").write_text("- set: {}\n", encoding="utf-8")
            (output / "latest").symlink_to(outside, target_is_directory=True)
            self.assertIsNone(self.links.latest_generated(project))

    def test_dot_tokens_and_xlsx_resource_limits_fail_closed(self):
        self.assertEqual(
            "Leaf01", self.topology._validate_dot_token("Leaf01", context="device"),
        )
        for value in ('Leaf"01', "Leaf\\01", "Leaf\n01"):
            with self.assertRaises(ValueError):
                self.topology._validate_dot_token(value, context="device")

        with tempfile.TemporaryDirectory() as directory:
            workbook = Path(directory) / "large.xlsx"
            with zipfile.ZipFile(workbook, "w") as archive:
                archive.writestr("one.xml", "x")
                archive.writestr("two.xml", "y")
            old_limit = self.nvos.MAX_XLSX_ENTRIES
            self.nvos.MAX_XLSX_ENTRIES = 1
            try:
                with zipfile.ZipFile(workbook) as archive:
                    with self.assertRaises(self.nvos.ConversionError):
                        self.nvos.validate_xlsx_archive(archive)
            finally:
                self.nvos.MAX_XLSX_ENTRIES = old_limit

    def test_lldpq_template_contains_only_synthetic_example_topology(self):
        template = Path(self.topology.LLDPQ_TEMPLATE)
        source = template.read_text(encoding="utf-8")
        header = self.topology._lldpq_header(str(template))
        self.assertTrue(header.startswith("/*"))
        self.assertTrue(header.rstrip().endswith("*/"))
        self.assertIn("Synthetic LLDP topology template", header)
        self.assertNotRegex(header.casefold(), r"see\s+license|lldpq\s+project")
        body = source.split("*/", 1)[1]
        self.assertIn('graph "EXAMPLE"', body)
        self.assertLessEqual(body.count(" -- "), 3)
        forbidden = "(?:gb" + "300|st" + "03|vision" + "bay|vbgb" + "300)"
        self.assertNotRegex(body.casefold(), forbidden)
        for line in body.splitlines():
            if " -- " in line:
                self.assertIn("EXAMPLE-", line)

        splitter = template.with_name("03-splitter.log").read_text(
            encoding="utf-8"
        )
        self.assertNotRegex(splitter.casefold(), forbidden)
        for line in splitter.splitlines():
            if line.strip():
                self.assertTrue(line.startswith("EXAMPLE-"), line)

    def test_cumulus_p2p_help_succeeds_but_unknown_argument_fails(self):
        script = ROOT / "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py"
        help_result = subprocess.run(
            [sys.executable, str(script), "--help"], cwd=ROOT,
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(0, help_result.returncode, help_result.stderr)
        self.assertIn("Usage:", help_result.stdout)
        bad_result = subprocess.run(
            [sys.executable, str(script), "--definitely-unknown"], cwd=ROOT,
            text=True, capture_output=True, check=False,
        )
        self.assertNotEqual(0, bad_result.returncode)
        self.assertIn("Usage:", bad_result.stderr)


if __name__ == "__main__":
    unittest.main()
