#!/usr/bin/env python3
"""Focused regression tests for the ZTP/release core review."""

from __future__ import annotations

import base64
import ast
import datetime as dt
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
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
        cls.generator = load_module(
            "review_cumulus_generator",
            "ztp/config/cumulus/template/90-c2-generate_configs.py",
        )
        cls.backup = load_module("review_yaml_collect", "ztp/backup/yaml-collect.py")
        cls.manual = load_module("review_manual_ztp", "ztp/manual-ztp.py")

    def test_standalone_dhcp_help_routes_both_runtime_backends(self):
        output = io.StringIO()
        with mock.patch.object(
            sys, "argv", ["c1-generate_dhcp.py", "--help"],
        ), mock.patch("sys.stdout", output):
            self.dhcp.main()
        guidance = output.getvalue()
        self.assertIn("独立生成仅用于开发预览", guidance)
        self.assertIn("Native/systemd", guidance)
        self.assertIn("DAY0-Prepare/11-load.py", guidance)
        self.assertIn("Docker/Supervisor", guidance)
        self.assertIn("infra/docker/deploy.sh deploy", guidance)
        self.assertIn("deploy-preloaded <IMAGE_ID>", guidance)
        self.assertIn("没有 source write", guidance)
        self.assertNotIn("统一由 DAY0-Prepare/11-load.py", guidance)

    def test_yaml_backup_password_fd_is_bounded_and_replaces_interactive_prompts(self):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, "shared backup secret".encode("utf-8"))
        finally:
            os.close(write_fd)
        parsed = self.backup._parse_args([
            "-y", "--type", "prod", "--password-fd", str(read_fd),
        ])
        self.assertEqual((True, "prod", False, read_fd), parsed)
        self.assertEqual(
            "shared backup secret", self.backup._read_password_fd(read_fd),
        )
        with mock.patch.object(
            self.backup, "_ask_password",
            side_effect=AssertionError("Web password must bypass interactive prompts"),
        ):
            self.assertEqual(
                ("shared backup secret",) * 3,
                self.backup._resolve_backup_passwords(
                    3, 2, 1, "shared backup secret",
                ),
            )

        for payload in (b"contains\nnewline", b"x" * 1025, b"bad\x00secret"):
            read_fd, write_fd = os.pipe()
            try:
                os.write(write_fd, payload)
            finally:
                os.close(write_fd)
            with self.subTest(payload=payload[:20]), self.assertRaises(ValueError):
                self.backup._read_password_fd(read_fd)

    def test_yaml_backup_sends_sudo_password_only_over_ssh_stdin(self):
        sentinel = "SENTINEL-shared-sudo-password"
        calls = []

        def fake_ssh(_user, _password, _ip, command, timeout=30, **kwargs):
            del timeout
            calls.append((command, kwargs))
            if command.startswith("hostname"):
                return "leaf01\n", "", 0
            if command.startswith("sudo "):
                return "set:\n  system:\n    hostname: leaf01\n", "", 0
            return "", "", 0

        device = {
            "hostname": "leaf01", "fmt": "eth",
            "eth0_ip": "192.0.2.10", "eth0_pfx": "24",
            "eth0_gw": "192.0.2.1", "eth0_mac": "02:00:00:00:00:01",
            "eth1_ip": "", "eth1_pfx": "", "eth1_gw": "",
            "alternate_ssh_ips": [], "transition_ssh_ips": [],
            "dynamic_dhcp": False,
        }
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "eth").mkdir()
            with mock.patch.object(self.backup, "_ssh", side_effect=fake_ssh):
                self.backup.collect_device(device, directory, sentinel, "", "")

        sudo_calls = [
            item for item in calls
            if "sudo" in item[0] and " cat " in item[0]
        ]
        self.assertEqual(1, len(sudo_calls))
        command, kwargs = sudo_calls[0]
        self.assertNotIn(sentinel, command)
        self.assertNotIn("printf", command)
        self.assertEqual(sentinel + "\n", kwargs.get("stdin_text"))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fake_bin = root / "bin"
            fake_bin.mkdir()
            records = root / "records.jsonl"
            fake_ssh = fake_bin / "ssh"
            fake_ssh.write_text(
                "#!/usr/bin/env python3\n"
                "import base64, json, os, sys\n"
                "payload = sys.stdin.buffer.read()\n"
                "record = {'argv': sys.argv[1:], "
                "'stdin_b64': base64.b64encode(payload).decode('ascii')}\n"
                "with open(os.environ['SSH_RECORD'], 'a') as stream:\n"
                " stream.write(json.dumps(record) + '\\n')\n",
                encoding="utf-8",
            )
            fake_ssh.chmod(0o755)
            environment = dict(os.environ)
            environment.update({
                "PATH": str(fake_bin) + os.pathsep + environment.get("PATH", ""),
                "SSH_RECORD": str(records),
            })
            self.backup._run_ssh(
                "cumulus", "192.0.2.10", command, 30,
                self.backup._KEY_AUTH_OPTS, env=environment,
                stdin_text=sentinel + "\n",
            )
            self.backup._run_ssh(
                "cumulus", "192.0.2.10", "hostname", 30,
                self.backup._KEY_AUTH_OPTS, env=environment,
            )
            calls = [
                json.loads(line)
                for line in records.read_text(encoding="utf-8").splitlines()
            ]
        self.assertEqual(2, len(calls))
        self.assertNotIn(sentinel, " ".join(calls[0]["argv"]))
        self.assertEqual(
            sentinel.encode("utf-8") + b"\n",
            base64.b64decode(calls[0]["stdin_b64"]),
        )
        self.assertEqual(b"", base64.b64decode(calls[1]["stdin_b64"]))

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

    def test_single_host_generation_does_not_recommend_incomplete_publish(self):
        guidance = self.generator.eth_followup_text(
            "20260906_120000", has_patch=False, target="EXAMPLE-Leaf01",
        )
        self.assertIn("仅生成了单台设备", guidance)
        self.assertIn("python3 90-c2-generate_configs.py -y", guidance)
        self.assertNotIn("python3 d-hostname2mac.py", guidance)

        full = self.generator.eth_followup_text(
            "20260906_120000", has_patch=True, target=None,
        )
        self.assertIn(
            "python3 d-hostname2mac.py template/99-output/20260906_120000",
            full,
        )

    def test_generator_uses_one_strict_parser_for_reference_and_description_options(self):
        with tempfile.TemporaryDirectory() as directory:
            reference = Path(directory) / "reference"
            reference.mkdir()
            equals = self.generator.parse_generation_args(
                ["--verify", f"--ref-dir={reference}", "EXAMPLE-Leaf01"],
                branch="eth",
            )
            spaced = self.generator.parse_generation_args(
                ["--verify", "--ref-dir", str(reference), "EXAMPLE-Leaf01"],
                branch="eth",
            )
            self.assertEqual(str(reference), equals.ref_dir)
            self.assertEqual(vars(equals), vars(spaced))

            reference_alias = Path(directory) / "reference-alias"
            reference_alias.symlink_to(reference, target_is_directory=True)
            for invalid_reference in (
                "", str(Path(directory) / "missing"), str(reference_alias),
            ):
                with self.subTest(reference=invalid_reference), \
                        redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        self.generator.parse_generation_args(
                            [f"--ref-dir={invalid_reference}"], branch="eth",
                        )

        skipped = self.generator.parse_generation_args(
            ["--skip-descriptions"], branch="eth",
        )
        self.assertTrue(skipped.skip_descriptions)
        self.assertFalse(self.generator.should_prompt_descriptions(skipped))

        ordinary = self.generator.parse_generation_args([], branch="eth")
        self.assertTrue(self.generator.should_prompt_descriptions(ordinary))

        for invalid in (
            ["--ref-dir"],
            ["--ref-dir=.", "--ref-dir", "."],
            ["--unknown"],
            ["host-a", "host-b"],
        ):
            with self.subTest(argv=invalid), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    self.generator.parse_generation_args(invalid, branch="eth")

        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.generator.parse_generation_args(
                ["--skip-descriptions"], branch="ib",
            )

        self.assertIn(
            "USER_MANUAL.md",
            self.generator.generation_parser("eth").format_help(),
        )

    def test_site_default_rendering_never_mutates_the_neutral_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            default = root / "default_5.16.4.yaml"
            global_file = root / "01-global.yaml"
            neutral = (
                "- set:\n"
                "    system:\n"
                "      date-time:\n"
                "        timezone: Etc/UTC\n"
            )
            default.write_text(neutral, encoding="utf-8")
            global_file.write_text(
                "schema_version: 1\n"
                "common:\n"
                "  switch:\n"
                "    system:\n"
                "      date-time:\n"
                "        timezone: UTC\n"
                "switches:\n"
                "  - eth:\n"
                "      version: 5.16.4\n"
                "      system: {}\n",
                encoding="utf-8",
            )

            name, rendered = self.generator._render_cumulus_default_from_global(
                str(default), str(global_file),
            )

            self.assertEqual("default_5.16.4.yaml", name)
            self.assertEqual(neutral, default.read_text(encoding="utf-8"))
            document = self.generator.yaml.safe_load(rendered)
            self.assertEqual(
                "UTC", document[0]["set"]["system"]["date-time"]["timezone"],
            )

    def test_production_scope_publishes_site_rendered_default_without_mutating_neutral(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = root / "config/cumulus"
            production = service / "template/99-output/20260907_120000"
            production.mkdir(parents=True)
            neutral_default = service / "default_5.18.1.yaml"
            neutral_text = (
                "- set:\n"
                "    system:\n"
                "      date-time:\n"
                "        timezone: Etc/UTC\n"
            )
            neutral_default.write_text(neutral_text, encoding="utf-8")
            (service / "template/01-global.yaml").write_text(
                "schema_version: 1\n"
                "common:\n"
                "  switch:\n"
                "    system:\n"
                "      date-time:\n"
                "        timezone: Asia/Shanghai\n"
                "switches:\n"
                "  - eth:\n"
                "      version: 5.18.1\n"
                "      system: {}\n",
                encoding="utf-8",
            )
            (production / "leaf01.yaml").write_text(
                "- set: {system: {hostname: leaf01}}\n", encoding="utf-8",
            )
            context = self.publisher._cumulus_dir_context(str(production))
            devices = {
                "leaf01": {
                    "hostname": "leaf01", "dev_type": "eth",
                    "eth0_mac": "02:00:00:00:00:01", "eth1_mac": "",
                    "identity_pending": False,
                },
            }
            with mock.patch.object(
                self.publisher, "_process_yaml_files",
                return_value=(True, {}, {"leaf01"}),
            ), mock.patch.object(
                self.publisher, "_print_process_summary",
            ), mock.patch.object(
                self.publisher, "_write_cumulus_mode_sidecars", return_value=0,
            ), mock.patch.object(
                self.publisher, "_confirm_replace", return_value=True,
            ), mock.patch.object(
                self.publisher, "_set_latest_yaml", return_value=True,
            ), mock.patch.object(
                self.publisher, "_archive_combined_sources",
            ), redirect_stdout(io.StringIO()):
                self.assertTrue(
                    self.publisher._publish_production_cumulus(context, devices)
                )

            published_default = (
                Path(context["combine_dir"]) / neutral_default.name
            )
            document = self.publisher.yaml.safe_load(
                published_default.read_text(encoding="utf-8")
            )
            self.assertEqual(
                "Asia/Shanghai",
                document[0]["set"]["system"]["date-time"]["timezone"],
            )
            self.assertEqual(neutral_text, neutral_default.read_text(encoding="utf-8"))

    def test_site_default_artifact_rejects_aliases_specials_and_hash_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / self.publisher.AIR_EFFECTIVE_DEFAULT_ARTIFACT
            content = b"- set:\n    system: {}\n"
            artifact.write_bytes(content)
            self.assertEqual(
                content,
                self.publisher._read_effective_default_artifact(str(artifact)),
            )

            second_name = root / "second-name"
            os.link(artifact, second_name)
            with self.assertRaisesRegex(ValueError, "single-link"):
                self.publisher._read_effective_default_artifact(str(artifact))
            second_name.unlink()

            outside = root / "outside"
            artifact.rename(outside)
            artifact.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "安全读取"):
                self.publisher._read_effective_default_artifact(str(artifact))
            artifact.unlink()

            os.mkfifo(artifact)
            with self.assertRaisesRegex(ValueError, "single-link"):
                self.publisher._read_effective_default_artifact(str(artifact))
            artifact.unlink()

            service = root / "config/cumulus"
            production = service / "template/99-output/20260906_120000"
            air = service / "template/99-output/20260906_120000_air"
            production.mkdir(parents=True)
            air.mkdir()
            (service / "default.yaml").write_bytes(content)
            (service / "template/01-global.yaml").write_text(
                "schema_version: 1\n"
                "common: {switch: {system: {}}}\n"
                "switches:\n"
                "  - eth: {version: '', system: {}}\n",
                encoding="utf-8",
            )
            generated = air / self.publisher.AIR_EFFECTIVE_DEFAULT_ARTIFACT
            generated.write_bytes(content)
            manifest = {
                "schema_version": 1,
                "environment": "air",
                "effective_default": "default.yaml",
                "effective_default_artifact": generated.name,
                "effective_default_sha256": hashlib.sha256(b"different\n").hexdigest(),
                "target_cumulus_version": "",
                "devices": [{
                    "hostname": "air-leaf", "profile": "baseline",
                    "apply_mode": "patch", "mac": "02:00:00:00:00:01",
                }],
            }
            (air / "air-config-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8",
            )
            contexts = [
                self.publisher._cumulus_dir_context(str(production)),
                self.publisher._cumulus_dir_context(str(air)),
            ]
            with redirect_stdout(io.StringIO()):
                self.assertFalse(
                    self.publisher._publish_combined_cumulus(contexts, {})
                )
            self.assertFalse((service / "latest_yaml").exists())

    def test_dhcp_hosts_partition_production_and_air_with_stable_order(self):
        records = [
            {
                "hostname": "z-prod", "iface": "eth0", "type": "eth",
                "mac_norm": "02:00:00:00:00:03", "ip": "192.0.2.13",
                "dhcp_assignment": "fixed",
            },
            {
                "hostname": "a-air", "iface": "eth0", "type": "air",
                "mac_norm": "02:00:00:00:00:02", "ip": "192.0.2.12",
                "dhcp_assignment": "fixed",
            },
            {
                "hostname": "a-prod", "iface": "eth0", "type": "eth",
                "mac_norm": "02:00:00:00:00:01", "ip": "192.0.2.11",
                "dhcp_assignment": "fixed",
            },
        ]

        def generated(order):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "dhcpd_eth.hosts"
                with redirect_stdout(io.StringIO()):
                    self.dhcp.write_hosts(path, order)
                return "\n".join(
                    line for line in path.read_text(encoding="utf-8").splitlines()
                    if not line.startswith("##### Generated at ")
                )

        first = generated(records)
        second = generated(list(reversed(records)))
        self.assertEqual(first, second)
        self.assertLess(
            first.index("##### Production reservations"),
            first.index("host a-prod"),
        )
        self.assertLess(first.index("host a-prod"), first.index("host z-prod"))
        self.assertLess(
            first.index("##### AIR reservations"), first.index("host a-air"),
        )
        self.assertLess(first.index("host z-prod"), first.index("##### AIR reservations"))
        self.assertIn("##### Production 2 entries; AIR 1 entries", first)

    def test_missing_hostname_diagnostic_is_capped_and_names_real_remedy(self):
        missing = [f"EXAMPLE-Leaf{index:04d}" for index in range(15)]
        output = io.StringIO()
        with mock.patch("sys.stdout", output):
            self.publisher.print_missing_expected_hosts(missing, limit=10)
        rendered = output.getvalue()
        self.assertIn("以下 15 台", rendered)
        self.assertIn("EXAMPLE-Leaf0009.yaml", rendered)
        self.assertNotIn("EXAMPLE-Leaf0010.yaml", rendered)
        self.assertIn("(+5 more)", rendered)
        self.assertIn(
            "先不带 HOSTNAME 重新运行 90-c2-generate_configs.py",
            rendered,
        )

    def test_standalone_dhcp_generation_never_installs_runtime_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            global_yaml = root / "01-global.yaml"
            subnet_csv = root / "02-subnet_config.csv"
            devices_csv = root / "02-devices_config.csv"
            global_yaml.write_text(
                "schema_version: 1\n"
                "common:\n"
                "  mgmt:\n"
                "    ztp:\n"
                "      ztp_url_prefix: /ztp\n",
                encoding="utf-8",
            )
            subnet_csv.write_text(
                "shared_network,subnet,netmask,range_start,range_end,routers,"
                "ztp_service_ip,cumulus_profile,nvos_ztp\n"
                "mgmt,192.0.2.0,255.255.255.0,192.0.2.100,192.0.2.199,"
                "192.0.2.1,192.0.2.2,oob,yes\n",
                encoding="utf-8",
            )
            devices_csv.write_text(
                DEVICE_HEADER
                + "leaf01,eth,leaf,192.0.2.10,255.255.255.0,192.0.2.1,"
                "02:00:00:00:00:01,,,,\n",
                encoding="utf-8",
            )
            prompts = []

            def confirm(prompt, default="y"):
                prompts.append((prompt, default))
                return True

            output = io.StringIO()
            install = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
            with mock.patch.multiple(
                self.dhcp,
                HTTP_ROOT=str(root),
                SCRIPT_DIR=str(root),
                OUTPUT_ETH=str(root / "dhcpd_eth.hosts"),
                OUTPUT_IB=str(root / "dhcpd_ib.hosts"),
                OUTPUT_NVL=str(root / "dhcpd_nvl.hosts"),
                OUTPUT_CONF=str(root / "dhcpd.conf"),
                OUTPUT_MANIFEST=str(root / "dhcp-release-manifest.json"),
                SUBNET_CSV=str(subnet_csv),
                GLOBAL_YAML=str(global_yaml),
                P2P_AIR_JSON=str(root / "absent-air.json"),
                DEVICES_CSV=str(devices_csv),
                _AUTO_YES=False,
            ), mock.patch.object(
                self.dhcp, "_confirm", side_effect=confirm,
            ), mock.patch.object(
                self.dhcp, "subprocess", mock.Mock(run=install), create=True,
            ), mock.patch.object(
                sys, "argv", ["c1-generate_dhcp.py"],
            ), mock.patch("sys.stdout", output):
                self.dhcp.main()

            self.assertEqual(
                [("[Y/n] 是否生成配置文件？", "y")], prompts,
            )
            install.assert_not_called()
            guidance = output.getvalue()
            self.assertIn("独立生成仅用于开发预览", guidance)
            self.assertIn("DAY0-Prepare/11-load.py", guidance)
            self.assertIn("infra/docker/deploy.sh deploy", guidance)
            self.assertIn("deploy-preloaded <IMAGE_ID>", guidance)
            self.assertIn(
                "没有 source write 且已有运行中的 inactive 控制容器",
                guidance,
            )
            self.assertNotIn(
                "统一由 DAY0-Prepare/11-load.py 事务处理", guidance,
            )

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

    @staticmethod
    def _h19_mini_policy(*, unknown_role_action="error"):
        """Independent heterogeneous mini-sampling authority used by H-19."""
        return {
            "node_allowlist": {},
            "link_rewrites": [],
            "mini_sampling": {
                "location_prefix_regex": r"^[a-z]\d+-(?P<logical>.+)$",
                "unknown_role_action": unknown_role_action,
                "anchors": [{
                    "name": "management-eth0",
                    "local_roles": ["oob-core-leaf"],
                    "local_hostname_regex": r"^oob-leaf.+$",
                    "peer_hostname_regex": r"^(?:tan|ib)(?:-|.+)$",
                    "peer_port_regex": r"^eth0$",
                }],
                "roles": [
                    {
                        "name": "firewall",
                        "hostname_regex": r"^fgt-.+-fw(?P<index>\d+)$",
                        "selection": {"mode": "first", "count": 2},
                    },
                    {
                        "name": "border",
                        "hostname_regex": r"^border(?P<index>\d+)$",
                        "selection": {"mode": "first", "count": 2},
                    },
                    {
                        "name": "oob-core",
                        "hostname_regex": r"^oob-core(?P<index>\d+)$",
                        "selection": {"mode": "first", "count": 2},
                    },
                    {
                        "name": "oob-core-leaf",
                        "hostname_regex": r"^oob-leaf(?P<index>\d+)$",
                        "selection": {
                            "mode": "indices", "capture_group": "index",
                            "indices": [1, 5, 13, 17],
                        },
                    },
                    {
                        "name": "oob-pod-leaf",
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
                        "name": "oob-pod-spine",
                        "hostname_regex": (
                            r"^oob-pod(?P<zone>\d+)-spine(?P<index>\d+)$"
                        ),
                        "selection": {
                            "mode": "indices", "capture_group": "index",
                            "indices": [1, 3], "group_by": ["zone"],
                        },
                    },
                    {
                        "name": "oob-rack-tor",
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
                    {
                        "name": "oobofoob-leaf",
                        "hostname_regex": r"^oobofoob-leaf(?P<index>\d+)$",
                        "selection": {"mode": "first", "count": 2},
                    },
                    {
                        "name": "oobofoob-spine",
                        "hostname_regex": r"^oobofoob-spine(?P<index>\d+)$",
                        "selection": {"mode": "first", "count": 2},
                    },
                    {
                        "name": "oobofoob-pod-leaf",
                        "hostname_regex": (
                            r"^oobofoob-pod(?P<zone>\d+)-leaf(?P<index>\d+)$"
                        ),
                        "selection": {
                            "mode": "first", "count": 1,
                            "group_by": ["zone"],
                        },
                    },
                    {
                        "name": "tan-spine",
                        "hostname_regex": r"^tan-spine(?P<index>\d+)$",
                        "selection": {"mode": "first", "count": 1},
                    },
                    {
                        "name": "tan-pod-leaf",
                        "hostname_regex": (
                            r"^tan-pod(?P<zone>\d+)-leaf(?P<index>\d+)$"
                        ),
                        "selection": {"mode": "first", "count": 2},
                    },
                    {
                        "name": "tan-cp-leaf",
                        "hostname_regex": r"^tan-cp-leaf(?P<index>\d+)$",
                        "selection": {"mode": "first", "count": 4},
                    },
                    {
                        "name": "tan-cp-1g-leaf",
                        "hostname_regex": r"^tan-cp-1gleaf(?P<index>\d+)$",
                        "selection": {"mode": "first", "count": 1},
                    },
                    {
                        "name": "tan-hps-leaf",
                        "hostname_regex": r"^tan-hps-leaf(?P<index>\d+)$",
                        "selection": {"mode": "first", "count": 2},
                    },
                    {
                        "name": "tan-obj-leaf",
                        "hostname_regex": r"^tan-obj-leaf(?P<index>\d+)$",
                        "selection": {"mode": "first", "count": 2},
                    },
                ],
            },
        }

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
        self.assertIn("--os-version VERSION", help_result.stdout)
        self.assertIn("--mini", help_result.stdout)
        bad_result = subprocess.run(
            [sys.executable, str(script), "--definitely-unknown"], cwd=ROOT,
            text=True, capture_output=True, check=False,
        )
        self.assertNotEqual(0, bad_result.returncode)
        self.assertIn("Usage:", bad_result.stderr)

    def test_air_dot_and_json_enforce_4096_mb_memory_floor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lldpq = root / "source.dot"
            lldpq.write_text(
                "graph synthetic {\n"
                '"example-oob-leaf01":"swp1" -- '
                '"example-oob-leaf02":"swp1"\n'
                "}\n",
                encoding="utf-8",
            )
            generated_dot = root / "generated-air.dot"
            self.topology.generate_air_dot(
                lldpq,
                generated_dot,
                {"Eth-SW": ["example-*"]},
                ["Eth-SW"],
                os_version="5.18",
                template_file=self.topology.AIR_JSON_TEMPLATE,
            )
            dot_nodes, _links = self.topology._parse_air_dot(generated_dot)
            self.assertTrue(dot_nodes)
            self.assertTrue(
                all(int(attributes["memory"]) >= 4096
                    for _name, attributes in dot_nodes),
                dot_nodes,
            )

            low_memory_dot = root / "low-memory-air.dot"
            low_memory_dot.write_text(
                "graph network {\n"
                '"AIR-example-oob-leaf01" '
                '[ memory="1024" model="SN2201" os="cumulus-vx-5.18" '
                'cpus="2" oob="false" template_node="OOB-Leaf" ]\n'
                '"AIR-example-oobofoob-leaf10" '
                '[ memory="1024" model="SN2201" os="cumulus-vx-5.18" '
                'cpus="2" oob="false" template_node="OOB-Leaf" ]\n'
                '"AIR-example-oob-leaf01":"swp1" -- '
                '"AIR-example-oobofoob-leaf10":"swp1"\n'
                "}\n",
                encoding="utf-8",
            )
            generated_json = root / "generated-air.json"
            template = (
                ROOT / "ztp/config/cumulus/template/P2P/air-template.json"
            )
            self.topology.generate_air_json(
                low_memory_dot,
                generated_json,
                template,
            )
            document = json.loads(generated_json.read_text(encoding="utf-8"))
            nodes = document["content"]["nodes"]
            self.assertEqual(4096, nodes["AIR-example-oob-leaf01"]["memory"])
            self.assertEqual(
                4096,
                nodes["AIR-example-oobofoob-leaf10"]["memory"],
            )
            oob_nodes = document["content"]["oob"]["nodes"]
            self.assertEqual(4096, oob_nodes["oob-mgmt-server"]["memory"])
            self.assertEqual(5120, oob_nodes["oob-mgmt-switch"]["memory"])

    def test_air_ztp_server_uses_dedicated_resources_in_dot_and_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lldpq = root / "ztp-server-lldpq.dot"
            lldpq.write_text(
                "graph synthetic {\n"
                '"example-oob-leaf01":"swp1" -- '
                '"example-x86-mgmt-server01(ztp-server)":"eth1"\n'
                "}\n",
                encoding="utf-8",
            )
            for template_name in (
                "air-template.json",
                "air-template-no-oob.json",
            ):
                with self.subTest(template=template_name):
                    template = Path(self.topology.SCRIPT_DIR) / template_name
                    dot = root / f"{template_name}.dot"
                    output = root / f"{template_name}.output.json"
                    self.topology.generate_air_dot(
                        lldpq,
                        dot,
                        {"Eth-SW": ["example-oob-leaf*"]},
                        ["Eth-SW"],
                        os_version="5.18",
                        template_file=template,
                    )
                    dot_nodes, _links = self.topology._parse_air_dot(dot)
                    attributes = dict(dot_nodes)["ztp-server"]
                    self.assertEqual("8", attributes["cpus"])
                    self.assertEqual("8192", attributes["memory"])
                    self.assertEqual("80", attributes["storage"])

                    self.topology.generate_air_json(
                        dot,
                        output,
                        template,
                        lldpq_file=lldpq,
                    )
                    nodes = json.loads(output.read_text(encoding="utf-8"))[
                        "content"
                    ]["nodes"]
                    ztp_server = nodes["ztp-server"]
                    self.assertEqual(8, ztp_server["cpu"])
                    self.assertEqual(8192, ztp_server["memory"])
                    self.assertEqual(80, ztp_server["storage"])
                    switch = nodes["AIR-example-oob-leaf01"]
                    self.assertNotEqual(8, switch["cpu"])
                    self.assertNotEqual(8192, switch["memory"])
                    self.assertNotEqual(80, switch["storage"])

    def test_air_json_positioning_follows_ethernet_diagram_layout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            template = root / "air-template.json"
            template.write_text(json.dumps({
                "format": "JSON",
                "ztp": None,
                "content": {
                    "nodes": {
                        "generic": {
                            "cpu": 2,
                            "memory": 4096,
                            "storage": 32,
                            "os": "cumulus-vx-5.18",
                            "labels": {"model": "generic"},
                            "management_interfaces": {
                                "eth0": {
                                    "ip": None,
                                    "mac_address": "02:00:00:00:00:01",
                                },
                            },
                            "positioning": {"x": 0, "y": 0},
                        },
                    },
                    "links": [],
                    "oob": False,
                },
            }), encoding="utf-8")

            names = [
                "AIR-oob-leaf09", "AIR-tan-leaf01", "AIR-border01",
                "AIR-oobofoob-leaf01", "AIR-site-fw01",
                "AIR-oob-spine01", "AIR-tan-spine02",
                "AIR-tan-spine01", "AIR-oobofoob-spine01",
                "AIR-tan-leaf99", "ztp-server",
                *[f"AIR-oob-leaf{index:02d}" for index in range(1, 9)],
            ]
            edges = [
                ("AIR-site-fw01", "swp1", "AIR-border01", "swp1"),
                ("AIR-border01", "swp2", "AIR-tan-spine01", "swp1"),
                ("AIR-border01", "swp3", "AIR-tan-spine02", "swp1"),
                ("AIR-border01", "swp4", "AIR-oob-spine01", "swp1"),
                ("AIR-oobofoob-spine01", "swp1",
                 "AIR-oobofoob-leaf01", "swp1"),
                ("AIR-tan-spine01", "swp2", "AIR-tan-leaf99", "swp1"),
                ("AIR-tan-spine02", "swp2", "AIR-tan-leaf01", "swp1"),
                *[
                    ("AIR-oob-spine01", f"swp{index + 1}",
                     f"AIR-oob-leaf{index:02d}", "swp1")
                    for index in range(1, 10)
                ],
                ("AIR-oob-leaf01", "swp2", "ztp-server", "eth1"),
                ("AIR-tan-leaf99", "swp2", "ztp-server", "eth2"),
                ("AIR-oobofoob-leaf01", "swp2", "ztp-server", "eth3"),
            ]

            def render(node_order, edge_order, suffix):
                dot = root / f"layout-{suffix}.dot"
                output = root / f"layout-{suffix}.json"
                lines = ["graph network {"]
                for name in node_order:
                    lines.append(
                        f'"{name}" [ memory="4096" model="generic" '
                        'os="cumulus-vx-5.18" cpus="2" oob="false" '
                        'template_node="generic" ]'
                    )
                for left, left_port, right, right_port in edge_order:
                    lines.append(
                        f'"{left}":"{left_port}" -- '
                        f'"{right}":"{right_port}"'
                    )
                lines.append("}")
                dot.write_text("\n".join(lines) + "\n", encoding="utf-8")
                self.topology.generate_air_json(dot, output, template)
                nodes = json.loads(output.read_text(encoding="utf-8"))[
                    "content"
                ]["nodes"]
                return {
                    name: node["positioning"] for name, node in nodes.items()
                }

            positions = render(names, edges, "forward")
            shuffled = render(list(reversed(names)), list(reversed(edges)), "reverse")
            self.assertEqual(positions, shuffled)
            self.assertEqual(len(positions), len({
                (position["x"], position["y"])
                for position in positions.values()
            }))
            self.assertTrue(all(
                isinstance(value, int) and value % 275 == 0
                for position in positions.values()
                for value in position.values()
            ))

            self.assertLess(
                positions["AIR-site-fw01"]["y"],
                positions["AIR-border01"]["y"],
            )
            self.assertLess(
                positions["AIR-border01"]["y"],
                positions["AIR-oobofoob-spine01"]["y"],
            )
            self.assertLess(
                positions["AIR-oobofoob-spine01"]["y"],
                positions["AIR-oobofoob-leaf01"]["y"],
            )

            tan_spines = ["AIR-tan-spine01", "AIR-tan-spine02"]
            tan_leaves = ["AIR-tan-leaf01", "AIR-tan-leaf99"]
            oob_spines = ["AIR-oob-spine01"]
            oob_leaves = [f"AIR-oob-leaf{index:02d}" for index in range(1, 10)]
            main_spines = tan_spines + oob_spines
            main_leaves = tan_leaves + oob_leaves
            self.assertLess(
                positions["AIR-oobofoob-leaf01"]["y"],
                min(positions[name]["y"] for name in main_spines),
            )
            self.assertLess(
                max(positions[name]["y"] for name in main_spines),
                min(positions[name]["y"] for name in main_leaves),
            )
            self.assertLess(
                max(positions[name]["y"] for name in main_leaves),
                positions["ztp-server"]["y"],
            )
            self.assertLess(
                max(positions[name]["x"] for name in tan_spines + tan_leaves),
                min(positions[name]["x"] for name in oob_spines + oob_leaves),
            )
            self.assertLess(
                max(positions[name]["x"] for name in tan_spines + tan_leaves),
                positions["ztp-server"]["x"],
            )
            self.assertLess(
                positions["ztp-server"]["x"],
                min(positions[name]["x"] for name in oob_spines + oob_leaves),
                "a TAN/OOB shared server belongs between both zones",
            )
            self.assertLess(
                positions["AIR-tan-leaf99"]["x"],
                positions["AIR-tan-leaf01"]["x"],
                "leaf order must follow its upstream spine before hostname",
            )
            self.assertGreater(
                len({positions[name]["y"] for name in oob_leaves}), 1,
                "a role/zone row must wrap after seven devices",
            )

    def test_cumulus_p2p_inventory_keeps_pdu_out_of_air_switches(self):
        patterns, order = self.topology.load_inventory(
            self.topology.DEFAULT_INV
        )
        pdu = "example-oob-corepod-pdu01"
        self.assertEqual("PDU", self.topology.get_device_type(
            pdu, patterns, order,
        ))
        self.assertFalse(self.topology._is_eth_sw(pdu, patterns, order))
        self.assertEqual("Eth-SW", self.topology.get_device_type(
            "example-oob-core01", patterns, order,
        ))
        self.assertEqual("dell-bf", self.topology.get_device_type(
            "example-knode01", patterns, order,
        ))
        self.assertFalse(self.topology._is_eth_sw(
            "example-knode01", patterns, order,
        ))

    def test_cumulus_p2p_os_version_option_is_explicit_and_fail_closed(self):
        (
            template, version, policy, mini_devices, deployment_scope,
        ) = self.topology._parse_cli_args([
            "--os-version", "5.18", "--air-template=air-template-no-oob.json",
            "--air-link-policy", "03-air-topology-policy.json",
            "--deployment-scope", "air", "--mini", "customer-devices.txt",
        ])
        self.assertEqual("air-template-no-oob.json", template)
        self.assertEqual("5.18", version)
        self.assertEqual("03-air-topology-policy.json", policy)
        self.assertEqual("customer-devices.txt", mini_devices)
        self.assertEqual("air", deployment_scope)
        self.assertEqual("5.18", self.topology._validate_air_os_version(version))
        self.assertEqual(
            (self.topology.AIR_JSON_TEMPLATE, None, None, None, "all"),
            self.topology._parse_cli_args([]),
        )
        self.assertEqual(
            self.topology._MINI_AIR_DEVICES_NAME,
            self.topology._parse_cli_args([
                "--deployment-scope", "air", "--mini",
            ])[3],
        )
        self.assertEqual(
            "customer-devices.txt",
            self.topology._parse_cli_args([
                "--deployment-scope=air", "--mini=customer-devices.txt",
            ])[3],
        )
        with self.assertRaisesRegex(ValueError, "AIR OS version"):
            self.topology._validate_air_os_version('5.18" malicious=true')
        with self.assertRaises(ValueError):
            self.topology._parse_cli_args(["--os-version"])
        with self.assertRaisesRegex(ValueError, "duplicate argument"):
            self.topology._parse_cli_args([
                "--deployment-scope", "air", "--mini", "--mini",
            ])
        with self.assertRaisesRegex(ValueError, "\.txt"):
            self.topology._parse_cli_args([
                "--deployment-scope", "air", "--mini=not-a-text-file",
            ])
        with self.assertRaisesRegex(ValueError, "--mini requires"):
            self.topology._parse_cli_args(["--mini"])
        with self.assertRaisesRegex(ValueError, "unsupported deployment scope"):
            self.topology._parse_cli_args(["--deployment-scope=invalid"])

    def test_air_mini_device_file_has_two_sections_and_allows_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            source_file = project / "customer-devices.txt"
            canonical_file = project / "04-air-mini-devices.txt"
            source_file.write_text(
                "# one hostname per line; duplicates are valid\n"
                "border01\n"
                "tan-spine02\n"
                "tan-spine02\n",
                encoding="utf-8",
            )
            required = {"a01-border01", "b01-tan-spine01"}
            eligible = required | {"c01-tan-spine02"}
            mini_sampling = self._h19_mini_policy()["mini_sampling"]

            selected, report = self.topology._resolve_mini_air_device_selection(
                source_file,
                canonical_file,
                required,
                eligible,
                ztp_server_names={"e01-x86-mgmt-server01(ztp-server)"},
                mini_sampling=mini_sampling,
            )

            self.assertEqual(eligible, selected)
            self.assertEqual(
                ["border01", "tan-spine01", "ztp-server"],
                report["minimum_required"],
            )
            self.assertEqual(
                ["border01", "tan-spine02", "tan-spine02"],
                report["customer_provided"],
            )
            self.assertEqual(["tan-spine02"], report["customer_additions"])
            self.assertEqual(1, report["duplicate_customer_entries"])
            self.assertEqual(
                {"border01", "tan-spine01", "tan-spine02", "ztp-server"},
                set(report["selected"]),
            )
            self.assertTrue(source_file.is_symlink())
            self.assertEqual("04-air-mini-devices.txt", os.readlink(source_file))
            refreshed = canonical_file.read_text(encoding="utf-8")
            self.assertEqual(1, refreshed.count("[minimum-required]"))
            self.assertEqual(1, refreshed.count("[customer-provided]"))
            self.assertNotIn("stale-leaf01", refreshed)
            self.assertEqual(2, refreshed.count("tan-spine02"))

            canonical_before_error = canonical_file.read_bytes()
            with self.assertRaisesRegex(ValueError, "unknown mini AIR device"):
                source_file.unlink()
                source_file.write_text(
                    "[minimum-required]\n"
                    "border01\n"
                    "[customer-provided]\n"
                    "not-a-real-device\n",
                    encoding="utf-8",
                )
                self.topology._resolve_mini_air_device_selection(
                    source_file,
                    canonical_file,
                    required,
                    eligible,
                    ztp_server_names={"e01-x86-mgmt-server01(ztp-server)"},
                    mini_sampling=mini_sampling,
                )
            self.assertEqual(canonical_before_error, canonical_file.read_bytes())
            self.assertTrue(source_file.is_file())
            self.assertFalse(source_file.is_symlink())

            source_file.unlink()
            canonical_file.unlink()
            canonical_file.symlink_to(canonical_file.name)
            with self.assertRaisesRegex(ValueError, "canonical.*regular file"):
                self.topology._resolve_mini_air_device_selection(
                    canonical_file,
                    canonical_file,
                    required,
                    eligible,
                    ztp_server_names={"e01-x86-mgmt-server01(ztp-server)"},
                    mini_sampling=mini_sampling,
                )

    def test_air_mini_uses_approved_role_samples_and_switch_eth0_anchors(self):
        patterns = {
            "FW": ["*fgt*"],
            "IB-SW": ["*ib-*"],
            "Eth-SW": ["*border*", "*tan*", "*oob-*", "*oobofoob*", "*custom-switch*"],
            "dell-bf": ["*ztp-server*"],
        }
        order = ["FW", "IB-SW", "Eth-SW", "dell-bf"]
        devices = [
            "a01-fgt-7081f-fw01", "b01-fgt-7081f-fw02",
            "a02-border01", "b02-border02", "c02-border03",
            "a03-oob-core01", "b03-oob-core02", "c03-oob-core03",
            "a04-oob-leaf01", "b04-oob-leaf02", "c04-oob-leaf05",
            "d04-oob-leaf13", "e04-oob-leaf14", "f04-oob-leaf15",
            "g04-oob-leaf16", "h04-oob-leaf17", "i04-oob-leaf18",
            "a05-oob-pod1-leaf01", "b05-oob-pod1-leaf03",
            "c05-oob-pod1-leaf07", "d05-oob-pod2-leaf03",
            "e05-oob-pod2-leaf07",
            "a06-oob-pod1-spine01", "b06-oob-pod1-spine02",
            "c06-oob-pod1-spine03", "d06-oob-pod1-spine04",
            "e06-oob-pod2-spine01", "f06-oob-pod2-spine02",
            "g06-oob-pod2-spine03", "h06-oob-pod2-spine04",
            "a07-oob-pod1r01-tor01", "b07-oob-pod1r01-tor02",
            "c07-oob-pod1r02-tor01", "d07-oob-pod2r01-tor01",
            "e07-oob-pod2r01-tor02",
            "a08-oobofoob-leaf10", "b08-oobofoob-leaf11",
            "c08-oobofoob-leaf12", "a09-oobofoob-spine01",
            "b09-oobofoob-spine02", "c09-oobofoob-spine03",
            "a10-oobofoob-pod1-leaf01", "b10-oobofoob-pod1-leaf02",
            "c10-oobofoob-pod2-leaf02", "d10-oobofoob-pod2-leaf03",
            "a11-tan-spine01", "b11-tan-spine02", "c11-tan-spine03",
            "a12-tan-pod1-leaf01", "b12-tan-pod1-leaf02",
            "c12-tan-pod1-leaf03", "d12-tan-pod2-leaf01",
            "a13-tan-cp-leaf01", "b13-tan-cp-leaf02",
            "c13-tan-cp-leaf03", "d13-tan-cp-leaf04",
            "e13-tan-cp-leaf05", "a14-tan-cp-1gleaf01",
            "b14-tan-cp-1gleaf02", "a15-tan-hps-leaf01",
            "b15-tan-hps-leaf02", "c15-tan-hps-leaf03",
            "a16-tan-obj-leaf01", "b16-tan-obj-leaf02",
            "c16-tan-obj-leaf03",
        ]
        edges = [
            ("e04-oob-leaf14", "swp1", "a20-ib-spine01", "eth0"),
            ("f04-oob-leaf15", "swp1", "a11-tan-spine01", "eth0"),
            ("g04-oob-leaf16", "swp1", "a13-tan-cp-leaf01", "eth0"),
            ("b05-oob-pod1-leaf03", "swp1", "a21-ib-pod1-leaf01", "eth0"),
            ("c05-oob-pod1-leaf07", "swp1", "a12-tan-pod1-leaf01", "eth0"),
            ("d05-oob-pod2-leaf03", "swp1", "a22-ib-pod2-leaf01", "eth0"),
            ("e05-oob-pod2-leaf07", "swp1", "d12-tan-pod2-leaf01", "eth0"),
            ("a08-oobofoob-leaf10", "swp1", "example-ztp-server", "eth1"),
        ]
        policy = self._h19_mini_policy()
        policy["node_allowlist"] = {"FW": [
            "a01-fgt-7081f-fw01", "b01-fgt-7081f-fw02",
        ]}

        selected, omitted_by_role, reasons = self.topology._select_mini_air_nodes(
            devices, edges, patterns, order, air_topology_policy=policy,
        )

        self.assertEqual({
            "a01-fgt-7081f-fw01", "b01-fgt-7081f-fw02",
            "a02-border01", "b02-border02",
            "a03-oob-core01", "b03-oob-core02",
            "a04-oob-leaf01", "c04-oob-leaf05", "d04-oob-leaf13",
            "e04-oob-leaf14", "f04-oob-leaf15", "g04-oob-leaf16",
            "h04-oob-leaf17",
            "b05-oob-pod1-leaf03", "c05-oob-pod1-leaf07",
            "d05-oob-pod2-leaf03", "e05-oob-pod2-leaf07",
            "a06-oob-pod1-spine01", "c06-oob-pod1-spine03",
            "e06-oob-pod2-spine01", "g06-oob-pod2-spine03",
            "a07-oob-pod1r01-tor01", "d07-oob-pod2r01-tor01",
            "a08-oobofoob-leaf10", "b08-oobofoob-leaf11",
            "a09-oobofoob-spine01", "b09-oobofoob-spine02",
            "a10-oobofoob-pod1-leaf01", "c10-oobofoob-pod2-leaf02",
            "a11-tan-spine01", "a12-tan-pod1-leaf01",
            "b12-tan-pod1-leaf02", "a13-tan-cp-leaf01",
            "b13-tan-cp-leaf02", "c13-tan-cp-leaf03",
            "d13-tan-cp-leaf04", "a14-tan-cp-1gleaf01",
            "a15-tan-hps-leaf01", "b15-tan-hps-leaf02",
            "a16-tan-obj-leaf01", "b16-tan-obj-leaf02",
        }, selected)
        self.assertEqual(1, omitted_by_role["border"])
        self.assertEqual(2, omitted_by_role["oob-core-leaf"])
        self.assertEqual(1, omitted_by_role["oob-pod-leaf"])
        self.assertEqual(4, omitted_by_role["oob-pod-spine"])
        self.assertEqual(3, omitted_by_role["oob-rack-tor"])
        self.assertEqual(2, omitted_by_role["tan-spine"])
        self.assertEqual(2, omitted_by_role["tan-pod-leaf"])
        self.assertEqual(
            sorted(reasons, key=lambda item: (item["hostname"], item["reason"])),
            reasons,
        )
        self.assertTrue(all(
            set(item) == {"hostname", "role", "selected", "reason"}
            for item in reasons
        ))
        self.assertEqual(
            "role=oob-core-leaf selected by policy anchor=management-eth0",
            next(item["reason"] for item in reasons
                 if item["hostname"] == "e04-oob-leaf14"),
        )

        with self.assertRaisesRegex(
            ValueError,
            r"a17-custom-switch01.*role=unknown.*mini_sampling\.roles",
        ):
            self.topology._select_mini_air_nodes(
                devices + ["a17-custom-switch01"], edges, patterns, order,
                air_topology_policy=policy,
            )

    def test_air_mini_policy_drives_heterogeneous_roles_unknown_actions_and_priority(self):
        patterns = {"Eth-SW": ["*"]}
        order = ["Eth-SW"]
        devices = {
            "moon9-orbit-hub-01", "mars2-orbit-hub-02",
            "moon4-crystal-edge-01", "moon4-crystal-edge-02",
            "quasar-unclassified-switch",
        }
        policy = {
            "node_allowlist": {},
            "link_rewrites": [],
            "mini_sampling": {
                "location_prefix_regex": r"^(?:moon9|mars2|moon4)-(?P<logical>.+)$",
                "unknown_role_action": "keep",
                "roles": [
                    {
                        "name": "orbit-hub",
                        "hostname_regex": r"^orbit-hub-(?P<index>\d+)$",
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
                ],
            },
        }
        selected, omitted, reasons = self.topology._select_mini_air_nodes(
            devices, [], patterns, order, air_topology_policy=policy,
            explicit_devices={"moon4-crystal-edge-02"},
        )
        self.assertEqual({
            "moon9-orbit-hub-01",
            "moon4-crystal-edge-01",
            "moon4-crystal-edge-02",
            "quasar-unclassified-switch",
        }, selected)
        self.assertEqual({"orbit-hub": 1}, omitted)
        by_host = {item["hostname"]: item for item in reasons}
        self.assertEqual("explicit 04-air-mini-devices.txt selection",
                         by_host["moon4-crystal-edge-02"]["reason"])
        self.assertEqual("unknown role kept by mini_sampling.unknown_role_action=keep",
                         by_host["quasar-unclassified-switch"]["reason"])

        excluded = json.loads(json.dumps(policy))
        excluded["mini_sampling"]["unknown_role_action"] = "exclude"
        output = io.StringIO()
        with redirect_stdout(output):
            selected, _omitted, reasons = self.topology._select_mini_air_nodes(
                devices, [], patterns, order, air_topology_policy=excluded,
                explicit_devices={"moon4-crystal-edge-02"},
            )
        self.assertNotIn("quasar-unclassified-switch", selected)
        expected_reason = (
            "quasar-unclassified-switch: role=unknown excluded by "
            "mini_sampling.unknown_role_action=exclude"
        )
        self.assertIn(expected_reason, output.getvalue())
        self.assertEqual(expected_reason, next(
            item["reason"] for item in reasons
            if item["hostname"] == "quasar-unclassified-switch"
        ))

        rejected = json.loads(json.dumps(policy))
        rejected["mini_sampling"]["unknown_role_action"] = "error"
        with self.assertRaisesRegex(
            ValueError,
            r"quasar-unclassified-switch.*role=unknown.*mini_sampling\.roles",
        ):
            self.topology._select_mini_air_nodes(
                devices, [], patterns, order, air_topology_policy=rejected,
            )

    def test_air_mini_policy_schema_and_exact_project_file_fail_closed(self):
        base = self._h19_mini_policy()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            policy = project / "03-air-topology-policy.json"

            def write(document):
                policy.write_text(json.dumps(document), encoding="utf-8")

            write(base)
            loaded = self.topology.load_air_topology_policy(
                policy, project_root=project,
            )
            self.assertEqual("error", loaded["mini_sampling"]["unknown_role_action"])

            policy.unlink()
            with self.assertRaisesRegex(ValueError, "03-air-topology-policy.*not found"):
                self.topology.load_air_topology_policy(
                    policy, project_root=project,
                )
            write(base)
            wrong_name = project / "policy.json"
            wrong_name.write_bytes(policy.read_bytes())
            with self.assertRaisesRegex(ValueError, "03-air-topology-policy"):
                self.topology.load_air_topology_policy(
                    wrong_name, project_root=project,
                )

            for label, mutate, pattern in (
                ("missing-mini", lambda doc: doc.pop("mini_sampling"),
                 r"mini_sampling"),
                ("missing-action", lambda doc: doc["mini_sampling"].pop(
                    "unknown_role_action"), r"mini_sampling\.unknown_role_action"),
                ("bad-action", lambda doc: doc["mini_sampling"].update(
                    unknown_role_action="drop"), r"keep\|exclude\|error"),
                ("bad-prefix", lambda doc: doc["mini_sampling"].update(
                    location_prefix_regex="("), r"location_prefix_regex"),
                ("unknown-key", lambda doc: doc["mini_sampling"].update(
                    compiled_fallback=True), r"unknown key"),
                ("anchors-not-list", lambda doc: doc["mini_sampling"].update(
                    anchors={}), r"mini_sampling\.anchors.*list"),
                ("anchor-not-object", lambda doc: doc["mini_sampling"].update(
                    anchors=[1]), r"mini_sampling\.anchors\[1\].*object"),
                ("anchor-unknown-role", lambda doc: doc["mini_sampling"][
                    "anchors"][0].update(local_roles=["does-not-exist"]),
                 r"anchors\[1\].*local_roles.*does-not-exist"),
                ("anchor-bad-peer-regex", lambda doc: doc["mini_sampling"][
                    "anchors"][0].update(peer_hostname_regex="("),
                 r"anchors\[1\].*peer_hostname_regex"),
                ("anchor-bad-local-regex", lambda doc: doc["mini_sampling"][
                    "anchors"][0].update(local_hostname_regex="("),
                 r"anchors\[1\].*local_hostname_regex"),
                ("anchor-unknown-key", lambda doc: doc["mini_sampling"][
                    "anchors"][0].update(site_default=True), r"unknown key"),
            ):
                candidate = json.loads(json.dumps(base))
                mutate(candidate)
                write(candidate)
                with self.subTest(label=label), self.assertRaisesRegex(
                    ValueError, pattern,
                ):
                    self.topology.load_air_topology_policy(
                        policy, project_root=project,
                    )

            policy.write_text(
                '{"mini_sampling":{"unknown_role_action":"keep",'
                '"unknown_role_action":"exclude"}}', encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate"):
                self.topology.load_air_topology_policy(
                    policy, project_root=project,
                )

            write(base)
            outside = root / "03-air-topology-policy.json"
            outside.write_bytes(policy.read_bytes())
            with self.assertRaisesRegex(ValueError, "project.*03-air-topology-policy"):
                self.topology.load_air_topology_policy(
                    outside, project_root=project,
                )
            policy.unlink()
            policy.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "symlink"):
                self.topology.load_air_topology_policy(
                    policy, project_root=project,
                )
            policy.unlink()
            os.link(outside, policy)
            with self.assertRaisesRegex(ValueError, "single-link regular"):
                self.topology.load_air_topology_policy(
                    policy, project_root=project,
                )
            policy.unlink()
            policy.mkdir()
            with self.assertRaisesRegex(ValueError, "regular file"):
                self.topology.load_air_topology_policy(
                    policy, project_root=project,
                )
            policy.rmdir()
            policy.write_bytes(b"{" + b" " * (1024 * 1024) + b"}")
            with self.assertRaisesRegex(ValueError, "1 MiB"):
                self.topology.load_air_topology_policy(
                    policy, project_root=project,
                )

    def test_air_mini_policy_rejects_ambiguous_roles_and_compiled_site_fallback(self):
        policy = self._h19_mini_policy()
        policy["mini_sampling"]["roles"] = [
            {
                "name": "one", "hostname_regex": r"^custom-(?P<index>\d+)$",
                "selection": {"mode": "first", "count": 1},
            },
            {
                "name": "two", "hostname_regex": r"^custom-(?P<index>\d+)$",
                "selection": {"mode": "first", "count": 1},
            },
        ]
        with self.assertRaisesRegex(
            ValueError, r"custom-01.*ambiguous.*mini_sampling\.roles",
        ):
            self.topology._select_mini_air_nodes(
                {"custom-01"}, [], {"Eth-SW": ["*"]}, ["Eth-SW"],
                air_topology_policy=policy,
            )

        source_path = ROOT / "ztp/config/cumulus/template/P2P/b-xlsx_to_dot.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        forbidden_names = {
            "_MINI_AIR_SIMPLE_ROLE_LIMITS",
            "_MINI_AIR_CORE_LEAF_SAMPLES",
        }
        assigned = {
            target.id
            for node in ast.walk(tree)
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            for target in (
                node.targets if isinstance(node, ast.Assign) else [node.target]
            )
            if isinstance(target, ast.Name)
        }
        self.assertTrue(forbidden_names.isdisjoint(assigned), assigned)
        forbidden_literals = {
            "oob-core-leaf", "oob-pod-leaf", "oob-pod-spine",
            "oob-rack-tor", "oobofoob-pod-leaf", "tan-pod-leaf",
            "tan-cp-1g-leaf", "tan-hps-leaf", "tan-obj-leaf",
        }
        literals = {
            node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        self.assertTrue(forbidden_literals.isdisjoint(literals),
                        forbidden_literals & literals)

    def test_air_policy_rewrites_only_air_and_filters_inventory_type(self):
        leaf = "example-oobofoob-leaf10"
        ztp_server = "example-x86-mgmt-server01(ztp-server)"
        allowed_fw = "example-fgt-7081f-fw01"
        excluded_fw = "example-pa-3420-fw01"
        edges = [
            (leaf, "eth0", leaf, "swp32"),
            (allowed_fw, "swp1", leaf, "swp1"),
            (excluded_fw, "swp1", leaf, "swp2"),
            (ztp_server, "eth1", leaf, "swp3"),
        ]
        document = {
            "node_allowlist": {"FW": [allowed_fw]},
            "link_rewrites": [{
                "scope": "air",
                "match": [
                    {"device": leaf, "port": "eth0"},
                    {"device": leaf, "port": "swp32"},
                ],
                "replacement": [
                    {"device": ztp_server, "port": "eth2"},
                    {"device": leaf, "port": "eth0"},
                ],
            }],
        }
        patterns, order = self.topology.load_inventory(self.topology.DEFAULT_INV)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_file = root / "03-air-topology-policy.json"
            policy_file.write_text(json.dumps(document), encoding="utf-8")
            policy = self.topology.load_air_topology_policy(policy_file)
            self.assertEqual(
                {0},
                self.topology._validate_air_topology_policy(
                    policy, edges, patterns, order,
                ),
            )

            lldpq = root / "source-lldpq.dot"
            lldpq.write_text(
                "graph synthetic {\n"
                + "\n".join(
                    f'"{left}":"{left_port}" -- '
                    f'"{right}":"{right_port}"'
                    for left, left_port, right, right_port in edges
                )
                + "\n}\n",
                encoding="utf-8",
            )
            air_dot = root / "air.dot"
            air_json = root / "air.json"
            self.topology.generate_air_dot(
                lldpq,
                air_dot,
                patterns,
                order,
                os_version="5.18",
                template_file=self.topology.AIR_JSON_TEMPLATE,
                air_topology_policy=policy,
            )
            air_source = air_dot.read_text(encoding="utf-8")
            self.assertIn(f'"AIR-{allowed_fw}" [', air_source)
            self.assertNotIn(f'"AIR-{excluded_fw}" [', air_source)
            self.assertIn(
                f'"AIR-{leaf}":"eth0" -- "ztp-server":"eth2"',
                air_source,
            )
            self.assertNotIn(
                f'"AIR-{leaf}":"eth0" -- "AIR-{leaf}":"swp32"',
                air_source,
            )

            # The physical/LLDPQ source remains unchanged; only AIR is rewritten.
            self.assertIn(
                f'"{leaf}":"eth0" -- "{leaf}":"swp32"',
                lldpq.read_text(encoding="utf-8"),
            )
            self.topology.generate_air_json(
                air_dot,
                air_json,
                self.topology.AIR_JSON_TEMPLATE,
                lldpq_file=lldpq,
                air_topology_policy=policy,
            )
            generated = json.loads(air_json.read_text(encoding="utf-8"))
            leaf_node = generated["content"]["nodes"][f"AIR-{leaf}"]
            template = json.loads(
                Path(self.topology.AIR_JSON_TEMPLATE).read_text(encoding="utf-8")
            )["content"]["nodes"]["OOB-Leaf"]
            # OOBofOOB inherits the OOB leaf hardware shape, but the explicit
            # project OS version must replace the prototype's stale image.
            self.assertEqual("cumulus-vx-5.18", leaf_node["os"])
            for field in ("cpu", "storage", "nic_model", "labels"):
                self.assertEqual(template[field], leaf_node[field], field)
            self.assertEqual(4096, leaf_node["memory"])
            connected = [
                link for link in generated["content"]["links"]
                if len(link) == 2 and all(isinstance(item, dict) for item in link)
            ]
            endpoints = {
                frozenset(
                    (item["node"], item["interface"])
                    for item in link
                )
                for link in connected
            }
            self.assertIn(
                frozenset({(f"AIR-{leaf}", "eth0"), ("ztp-server", "eth2")}),
                endpoints,
            )
            self.assertNotIn(
                frozenset({
                    (f"AIR-{leaf}", "eth0"),
                    (f"AIR-{leaf}", "swp32"),
                }),
                endpoints,
            )

    def test_air_policy_schema_and_edge_matching_fail_closed(self):
        leaf = "leaf01"
        base = {
            "node_allowlist": {},
            "link_rewrites": [{
                "scope": "air",
                "match": [
                    {"device": leaf, "port": "swp1"},
                    {"device": leaf, "port": "swp2"},
                ],
                "replacement": [
                    {"device": "ztp-server", "port": "eth2"},
                    {"device": leaf, "port": "swp1"},
                ],
            }],
        }
        patterns = {"Eth-SW": ["leaf*"]}
        order = ["Eth-SW"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            unknown = root / "unknown.json"
            unknown.write_text(
                json.dumps({**base, "unexpected": True}), encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unknown key"):
                self.topology.load_air_topology_policy(unknown)

            policy_file = root / "policy.json"
            policy_file.write_text(json.dumps(base), encoding="utf-8")
            policy = self.topology.load_air_topology_policy(policy_file)
            with self.assertRaisesRegex(ValueError, "matched 0"):
                self.topology._validate_air_topology_policy(
                    policy,
                    [(leaf, "swp3", "peer01", "swp4")],
                    patterns,
                    order,
                )
            with self.assertRaisesRegex(ValueError, "matched 2"):
                self.topology._validate_air_topology_policy(
                    policy,
                    [
                        (leaf, "swp1", leaf, "swp2"),
                        (" LEAF01 ", "swp2", "leaf01", "swp1"),
                    ],
                    patterns,
                    order,
                )

            self_replacement = json.loads(json.dumps(base))
            self_replacement["link_rewrites"][0]["replacement"] = [
                {"device": leaf, "port": "swp10"},
                {"device": " LEAF01 ", "port": "swp11"},
            ]
            policy_file.write_text(
                json.dumps(self_replacement), encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "replacement.*self-link"):
                self.topology.load_air_topology_policy(policy_file)

            with self.assertRaisesRegex(ValueError, "unsafe.*\u7aef\u53e3\u51b2\u7a81"):
                self.topology._validate_air_topology_policy(
                    policy,
                    [
                        (leaf, "swp1", leaf, "swp2"),
                        ("ztp-server", "eth2", "peer01", "swp4"),
                    ],
                    patterns,
                    order,
                )

    def test_cumulus_p2p_rejects_normalized_device_self_link(self):
        records = [
            (" Leaf01 ", "swp1", "leaf01", "swp2"),
            ("unrelated-private-node", "swp3", "peer02", "swp4"),
        ]

        conflict_indices, messages = (
            self.topology._find_duplicate_or_conflicting_links(records)
        )

        self.assertEqual({0}, conflict_indices)
        self.assertEqual(
            ["  [自连接] 记录 #1: Leaf01:swp1 -- leaf01:swp2"],
            messages,
        )
        self.assertNotIn("unrelated-private-node", "\n".join(messages))

    def test_cumulus_p2p_main_fails_closed_on_self_link_workbook(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workbook = self.topology.openpyxl.Workbook()
            sheet = workbook.active
            sheet.title = "TAN synthetic"
            sheet.append(["Source", "", "Dest", ""])
            sheet.append(["name", "port", "name", "port"])
            sheet.append(["Leaf01", "swp1", "leaf01", "swp2"])
            workbook.save(root / "p2p.xlsx")
            workbook.close()

            inventory = root / "01-inventory.log"
            inventory.write_text("[Eth-SW]\n*leaf*\n", encoding="utf-8")
            port_map = root / "02-port-mapping.log"
            port_map.write_text("", encoding="utf-8")
            devices = root / "02-devices_config.csv"
            devices.write_text(DEVICE_HEADER, encoding="utf-8")
            lldpq = root / "lldpq-template.dot"
            lldpq.write_text("/* synthetic */\n", encoding="utf-8")
            air_template = root / "air-template-no-oob.json"
            air_template.write_text("{}\n", encoding="utf-8")

            stdout = io.StringIO()
            stderr = io.StringIO()
            patches = (
                mock.patch.object(self.topology, "HTTP_ROOT", root),
                mock.patch.object(self.topology, "SCRIPT_DIR", str(root)),
                mock.patch.object(self.topology, "DEFAULT_INV", str(inventory)),
                mock.patch.object(self.topology, "DEFAULT_PORT_MAP", str(port_map)),
                mock.patch.object(self.topology, "DEVICES_CONFIG", str(devices)),
                mock.patch.object(self.topology, "LLDPQ_TEMPLATE", str(lldpq)),
                mock.patch.object(
                    self.topology, "AIR_JSON_TEMPLATE", str(air_template),
                ),
                mock.patch.object(self.topology, "_AUTO_YES", False),
                mock.patch.object(
                    self.topology.sys,
                    "argv",
                    ["b-xlsx_to_dot.py", "-y", "--os-version", "5.18"],
                ),
                mock.patch.object(self.topology.sys, "stdout", stdout),
                mock.patch.object(self.topology.sys, "stderr", stderr),
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4], \
                    patches[5], patches[6], patches[7], patches[8], patches[9], \
                    patches[10]:
                with self.assertRaises(SystemExit) as raised:
                    self.topology.main()

            self.assertEqual(1, raised.exception.code)
            error = stderr.getvalue()
            self.assertIn("记录 #1", error)
            self.assertIn("Leaf01:swp1 -- leaf01:swp2", error)
            self.assertNotIn("Generated:", stdout.getvalue())
            self.assertFalse(any((root / "output-p2p").glob("*.dot")))


class BackupAuthenticationContractTests(unittest.TestCase):
    """Direct, implementation-independent oracles for BACKUP-AUTH-R1."""

    SECRET = "SENTINEL spaces 'quotes' $dollar \\slash 密码"
    TARGET = "192.0.2.10"

    def setUp(self):
        self.backup = load_module(
            f"review_backup_auth_{id(self)}", "ztp/backup/yaml-collect.py",
        )
        self.backup._AUTH_MODES.clear()
        self.backup._ASKPASS_PATH = None

    def tearDown(self):
        try:
            self.backup._cleanup_askpass()
        except (OSError, AttributeError):
            pass

    @staticmethod
    def _device(hostname="leaf01", target=TARGET):
        return {
            "hostname": hostname, "fmt": "eth", "eth0_ip": target,
            "eth0_pfx": "24", "eth0_gw": "192.0.2.1",
            "eth0_mac": "02:00:00:00:00:01", "eth1_ip": "",
            "eth1_pfx": "", "eth1_gw": "", "eth1_mac": "",
            "alternate_ssh_ips": [], "transition_ssh_ips": [],
            "dynamic_dhcp": False,
        }

    @staticmethod
    def _option_values(options, name):
        prefix = name.casefold() + "="
        return [
            options[index + 1].split("=", 1)[1]
            for index, value in enumerate(options[:-1])
            if value == "-o" and options[index + 1].casefold().startswith(prefix)
        ]

    @staticmethod
    def _expected_pin_name(scope, target):
        identity = json.dumps(
            {"scope": scope, "target": target},
            ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode("ascii")
        return hashlib.sha256(identity).hexdigest() + ".known_hosts"

    @staticmethod
    def _remote_result(command):
        if command.startswith("hostname"):
            return "leaf01\n"
        if command.startswith("sudo "):
            return "set:\n  system:\n    hostname: leaf01\n"
        if "eth0/address" in command:
            return "02:00:00:00:00:01\n"
        if "eth1/address" in command:
            return ""
        if "addr show eth0" in command and "a[1]" in command:
            return "192.0.2.10\n"
        if "addr show eth0" in command and "a[2]" in command:
            return "24\n"
        if "route show default" in command:
            return "192.0.2.1\n"
        if command == "true":
            return ""
        if "platform inventory" in command:
            return "SN-LEAF01\n"
        return ""

    def test_password_calls_use_verified_one_shot_fifos_and_project_tofu(self):
        seen_fifos = []
        seen_helpers = []
        password_calls = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            configured = root / "configured askpass"
            configured.mkdir(mode=0o700)
            configured.chmod(0o700)
            unusable_tmp = root / "not-a-directory"
            unusable_tmp.write_text("must not be used\n", encoding="utf-8")
            project_output = root / "project output [prod] $literal"
            run_output = project_output / "20260911_2300-prod-backup"
            for category in ("eth", "spx", "ib", "nvl"):
                (run_output / category).mkdir(parents=True, exist_ok=True)

            def fake_run(_user, _ip, command, _timeout, extra_opts,
                         env=None, stdin_text=None, pass_fds=()):
                combined = list(self.backup.SSH_OPTS) + list(extra_opts)
                if self._option_values(combined, "BatchMode") == ["yes"]:
                    self.assertEqual(
                        ["no"], self._option_values(combined, "StrictHostKeyChecking"),
                    )
                    self.assertEqual(
                        ["/dev/null"],
                        self._option_values(combined, "UserKnownHostsFile"),
                    )
                    return subprocess.CompletedProcess([], 255, "", "key rejected")

                password_calls.append((command, combined, stdin_text))
                self.assertIsNotNone(env)
                self.assertFalse(any(
                    self.SECRET in str(value) for value in env.values()
                ), "the cleartext secret reached a child environment")
                self.assertNotIn(self.SECRET, command)
                self.assertNotIn(self.SECRET, " ".join(combined))
                self.assertEqual(
                    ["yes"],
                    self._option_values(combined, "StrictHostKeyChecking"),
                )
                self.assertEqual(
                    ["/dev/null"],
                    self._option_values(combined, "GlobalKnownHostsFile"),
                )
                self.assertEqual(
                    ["1"], self._option_values(combined, "NumberOfPasswordPrompts"),
                )
                known_values = self._option_values(combined, "UserKnownHostsFile")
                self.assertEqual(["/dev/null"], known_values)
                self.assertEqual((), tuple(pass_fds))
                self.assertEqual(
                    ["ssh-ed25519"],
                    self._option_values(combined, "HostKeyAlgorithms"),
                )
                self.assertEqual(
                    ["no"], self._option_values(combined, "CheckHostIP"),
                )
                self.assertEqual(
                    ["no"], self._option_values(combined, "UpdateHostKeys"),
                )
                known_command = self._option_values(combined, "KnownHostsCommand")
                self.assertEqual(1, len(known_command))
                self.assertTrue(known_command[0].startswith("/usr/bin/printf "))

                fifo = Path(env["ZTP_BACKUP_PASSWORD_FIFO"])
                helper = Path(env["SSH_ASKPASS"])
                seen_fifos.append(fifo)
                seen_helpers.append(helper)
                fifo_stat = fifo.lstat()
                self.assertTrue(stat.S_ISFIFO(fifo_stat.st_mode))
                self.assertEqual(0o600, stat.S_IMODE(fifo_stat.st_mode))
                self.assertEqual(os.geteuid(), fifo_stat.st_uid)
                self.assertEqual(1, fifo_stat.st_nlink)
                self.assertTrue(helper.is_file())
                self.assertEqual(0o700, stat.S_IMODE(helper.stat().st_mode))
                self.assertTrue(helper.is_relative_to(configured))
                self.assertNotEqual(configured, helper.parent)
                self.assertEqual(0o700, stat.S_IMODE(helper.parent.stat().st_mode))
                helper_bytes = helper.read_bytes()
                self.assertNotIn(self.SECRET.encode("utf-8"), helper_bytes)
                asked = subprocess.run(
                    [str(helper)], env=env, text=True, capture_output=True,
                    timeout=5, check=False,
                )
                self.assertEqual(0, asked.returncode, asked.stderr)
                self.assertEqual(self.SECRET + "\n", asked.stdout)
                return subprocess.CompletedProcess(
                    [], 0, self._remote_result(command), "",
                )

            environment = {
                "HTTP_ZTP_RUNTIME_BACKEND": "supervisor",
                "HTTP_ZTP_ASKPASS_TMPDIR": str(configured),
                "TMPDIR": str(unusable_tmp),
            }
            with mock.patch.dict(os.environ, environment, clear=False), \
                    mock.patch.object(self.backup, "_ENVIRONMENT", "prod"), \
                    mock.patch.object(
                        self.backup, "_scan_offered_host_key",
                        return_value=(
                            f"{self.TARGET} ssh-ed25519 "
                            "AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER"
                        ),
                    ), \
                    mock.patch.object(self.backup, "_run_ssh", side_effect=fake_run):
                log, result = self.backup.collect_device(
                    self._device(), str(run_output), self.SECRET, "", "",
                )

            self.assertTrue(result["yaml_ok"], "\n".join(log))
            self.assertGreater(len(password_calls), 1)
            self.assertEqual(len(seen_fifos), len(set(seen_fifos)))
            self.assertTrue(all(not path.exists() for path in seen_fifos))
            sudo = [item for item in password_calls if item[0].startswith("sudo ")]
            self.assertEqual(1, len(sudo))
            self.assertEqual(self.SECRET + "\n", sudo[0][2])
            self.assertTrue(all(
                item[2] is None for item in password_calls if item is not sudo[0]
            ))
            self.assertFalse(any(
                option in {"-t", "-tt"} or option.startswith("RequestTTY=")
                for _, options, _ in password_calls for option in options
            ))
            self.assertNotIn(self.SECRET, "\n".join(log) + repr(result))
            for fifo, helper in zip(seen_fifos, seen_helpers):
                self.assertNotIn(self.SECRET, fifo.name)
                self.assertNotIn(self.SECRET, helper.name)
                self.assertNotIn(
                    self.SECRET.encode("utf-8"), helper.read_bytes(),
                )

    def test_unsafe_configured_roots_and_missing_supervisor_root_fail_pre_spawn(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            safe = root / "safe"
            safe.mkdir(mode=0o700)
            wrong_mode = root / "wrong-mode"
            wrong_mode.mkdir(mode=0o755)
            regular = root / "regular"
            regular.write_text("not a directory\n", encoding="utf-8")
            alias = root / "alias"
            alias.symlink_to(safe, target_is_directory=True)
            cases = [
                ("relative", "relative/root", None),
                ("missing", str(root / "missing"), None),
                ("regular", str(regular), None),
                ("symlink", str(alias), None),
                ("wrong-mode", str(wrong_mode), None),
                ("wrong-owner", str(safe), os.geteuid() + 1),
                ("supervisor-unset", None, None),
            ]
            for label, configured, fake_uid in cases:
                with self.subTest(label=label):
                    password_spawns = []

                    def recorder(_user, _ip, _command, _timeout, options,
                                 env=None, **_kwargs):
                        combined = list(self.backup.SSH_OPTS) + list(options)
                        if self._option_values(combined, "BatchMode") == ["yes"]:
                            return subprocess.CompletedProcess([], 255, "", "key rejected")
                        password_spawns.append(True)
                        return subprocess.CompletedProcess([], 255, "", "auth rejected")

                    environment = dict(os.environ)
                    environment["HTTP_ZTP_RUNTIME_BACKEND"] = "supervisor"
                    environment.pop("HTTP_ZTP_ASKPASS_TMPDIR", None)
                    if configured is not None:
                        environment["HTTP_ZTP_ASKPASS_TMPDIR"] = configured
                    patches = [
                        mock.patch.dict(os.environ, environment, clear=True),
                        mock.patch.object(self.backup, "_run_ssh", side_effect=recorder),
                    ]
                    if fake_uid is not None:
                        patches.append(mock.patch.object(
                            self.backup.os, "geteuid", return_value=fake_uid,
                        ))
                    try:
                        with patches[0], patches[1]:
                            if len(patches) == 3:
                                with patches[2]:
                                    self.backup.collect_device(
                                        self._device(), str(root), self.SECRET, "", "",
                                    )
                            else:
                                self.backup.collect_device(
                                    self._device(), str(root), self.SECRET, "", "",
                                )
                    except (OSError, RuntimeError, ValueError):
                        pass
                    self.assertEqual(
                        [], password_spawns,
                        f"{label} reached a password-bearing SSH child",
                    )
                    self.backup._AUTH_MODES.clear()
                    self.backup._ASKPASS_PATH = None

    def test_fifo_cleanup_covers_timeout_exception_and_interrupt(self):
        failures = (
            subprocess.TimeoutExpired(["ssh"], 1),
            OSError("synthetic spawn failure"),
            RuntimeError("synthetic unexpected failure"),
            KeyboardInterrupt(),
        )
        for index, failure in enumerate(failures):
            with self.subTest(failure=type(failure).__name__), \
                    tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                configured = root / "askpass"
                configured.mkdir(mode=0o700)
                observed = []

                def fail_after_fifo(_user, _ip, _command, _timeout, options,
                                    env=None, **_kwargs):
                    combined = list(self.backup.SSH_OPTS) + list(options)
                    if self._option_values(combined, "BatchMode") == ["yes"]:
                        return subprocess.CompletedProcess([], 255, "", "key rejected")
                    if env and env.get("ZTP_BACKUP_PASSWORD_FIFO"):
                        observed.append(Path(env["ZTP_BACKUP_PASSWORD_FIFO"]))
                    raise failure

                environment = {
                    "HTTP_ZTP_RUNTIME_BACKEND": "supervisor",
                    "HTTP_ZTP_ASKPASS_TMPDIR": str(configured),
                }
                scan_record = (
                    f"{self.TARGET} ssh-ed25519 "
                    "AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER"
                )
                try:
                    with mock.patch.dict(os.environ, environment, clear=False), \
                            mock.patch.object(
                                self.backup, "_scan_offered_host_key",
                                return_value=scan_record,
                            ), \
                            mock.patch.object(
                                self.backup, "_run_ssh", side_effect=fail_after_fifo,
                            ):
                        self.backup.collect_device(
                            self._device(hostname=f"leaf{index + 1:02d}"),
                            str(root), self.SECRET, "", "",
                        )
                except BaseException:  # includes the required interrupt path
                    pass
                self.assertEqual(1, len(observed))
                self.assertFalse(observed[0].exists())
                self.backup._AUTH_MODES.clear()
                self.backup._ASKPASS_PATH = None

    def test_shared_options_are_neutral_and_openssh_first_value_is_proven(self):
        forbidden = {
            "stricthostkeychecking", "userknownhostsfile",
            "globalknownhostsfile", "batchmode", "passwordauthentication",
            "preferredauthentications", "kbdinteractiveauthentication",
            "knownhostscommand", "hostkeyalgorithms", "checkhostip",
            "updatehostkeys",
        }
        neutral_names = {
            item.split("=", 1)[0].casefold()
            for item in self.backup.SSH_OPTS if "=" in item
        }
        def effective(*options):
            completed = subprocess.run(
                ["ssh", "-G", "-F", "/dev/null", *options, "example.invalid"],
                text=True, capture_output=True, timeout=10, check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            return dict(
                line.split(None, 1) for line in completed.stdout.splitlines()
                if " " in line
            )

        weak_first = effective(
            "-o", "StrictHostKeyChecking=no",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "UserKnownHostsFile=/tmp/project-known-hosts",
        )
        strict_first = effective(
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/tmp/project-known-hosts",
            "-o", "UserKnownHostsFile=/dev/null",
        )
        self.assertEqual("false", weak_first["stricthostkeychecking"])
        self.assertEqual("/dev/null", weak_first["userknownhostsfile"])
        self.assertEqual("accept-new", strict_first["stricthostkeychecking"])
        self.assertEqual(
            "/tmp/project-known-hosts", strict_first["userknownhostsfile"],
        )

        key_effective = effective(*self.backup._KEY_AUTH_OPTS)
        self.assertEqual("yes", key_effective["batchmode"])
        self.assertEqual("no", key_effective["passwordauthentication"])
        self.assertEqual("false", key_effective["stricthostkeychecking"])
        self.assertEqual("/dev/null", key_effective["userknownhostsfile"])

        password_options = list(self.backup._PASSWORD_AUTH_BASE_OPTS) + [
            "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "KnownHostsCommand=/usr/bin/printf %%s\\n example.invalid ssh-ed25519 AAAA",
            "-o", "HostKeyAlgorithms=ssh-ed25519",
            "-o", "CheckHostIP=no",
            "-o", "UpdateHostKeys=no",
        ]
        password_effective = effective(*password_options)
        self.assertEqual("no", password_effective["batchmode"])
        self.assertEqual("false", password_effective["pubkeyauthentication"])
        self.assertEqual("yes", password_effective["passwordauthentication"])
        self.assertEqual("yes", password_effective["kbdinteractiveauthentication"])
        self.assertEqual(
            "password,keyboard-interactive",
            password_effective["preferredauthentications"],
        )
        self.assertEqual("1", password_effective["numberofpasswordprompts"])
        self.assertEqual("true", password_effective["stricthostkeychecking"])
        self.assertEqual("/dev/null", password_effective["userknownhostsfile"])
        self.assertEqual(
            "/dev/null", password_effective["globalknownhostsfile"],
        )
        self.assertEqual("ssh-ed25519", password_effective["hostkeyalgorithms"])
        self.assertEqual("no", password_effective["checkhostip"])
        self.assertEqual("false", password_effective["updatehostkeys"])
        self.assertIn(
            "/usr/bin/printf", password_effective["knownhostscommand"],
        )

        def option_names(options):
            return [
                options[index + 1].split("=", 1)[0].casefold()
                for index, value in enumerate(options[:-1]) if value == "-o"
            ]

        for options, required in (
            (self.backup._KEY_AUTH_OPTS, {
                "batchmode", "passwordauthentication",
                "stricthostkeychecking", "userknownhostsfile",
            }),
            (password_options, {
                "batchmode", "pubkeyauthentication", "passwordauthentication",
                "kbdinteractiveauthentication", "preferredauthentications",
                "numberofpasswordprompts", "stricthostkeychecking",
                "userknownhostsfile", "globalknownhostsfile",
                "knownhostscommand", "hostkeyalgorithms", "checkhostip",
                "updatehostkeys",
            }),
        ):
            names = option_names(options)
            for name in required:
                self.assertEqual(1, names.count(name), (name, names))

        source = (ROOT / "ztp/backup/yaml-collect.py").read_text(encoding="utf-8")
        for required_flag in (
            "os.O_RDWR", "os.O_NONBLOCK", "os.O_CLOEXEC", "os.O_NOFOLLOW",
        ):
            with self.subTest(required_flag=required_flag):
                if required_flag not in source:
                    self.fail(f"required FIFO open flag is absent: {required_flag}")
        self.assertTrue(forbidden.isdisjoint(neutral_names), neutral_names)

    def test_known_hosts_command_support_and_system_helper_trust_fail_closed(self):
        require_support = getattr(
            self.backup, "_require_known_hosts_command_support", None,
        )
        trusted_helper = getattr(
            self.backup, "_trusted_known_hosts_command_helper", None,
        )
        self.assertTrue(callable(require_support))
        self.assertTrue(callable(trusted_helper))

        probe_calls = []

        def unsupported(argv, *_args, **_kwargs):
            probe_calls.append(list(argv))
            if "-V" in argv:
                return subprocess.CompletedProcess(
                    argv, 0, "", "OpenSSH_9.9p1 test-build",
                )
            return subprocess.CompletedProcess(
                argv, 255, "", "Bad configuration option: KnownHostsCommand",
            )

        with mock.patch.object(
            self.backup, "_KNOWN_HOSTS_COMMAND_EVIDENCE", None, create=True,
        ), mock.patch.object(
            self.backup, "_run_bounded_process", side_effect=unsupported,
        ), self.assertRaisesRegex(
            RuntimeError, r"KnownHostsCommand.*OpenSSH 8\.5.*OpenSSH_9\.9p1",
        ):
            require_support()
        self.assertEqual(1, sum("-V" in argv for argv in probe_calls))
        config_probes = [argv for argv in probe_calls if "-G" in argv]
        self.assertEqual(1, len(config_probes), probe_calls)
        self.assertIn("-F", config_probes[0])
        self.assertIn("/dev/null", config_probes[0])
        self.assertTrue(any(
            "KnownHostsCommand=" in value for value in config_probes[0]
        ))

        with mock.patch.object(
            self.backup, "_KNOWN_HOSTS_COMMAND_EVIDENCE", None, create=True,
        ):
            evidence = require_support()
        self.assertRegex(evidence, r"OpenSSH_[0-9]+\.[0-9]+")

        helper = Path(trusted_helper())
        self.assertEqual(Path("/usr/bin/printf"), helper)
        printf_record = (
            f"{self.TARGET} ssh-ed25519 "
            "AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER"
        )
        printf_result = subprocess.run(
            [str(helper), "%s\n", printf_record],
            text=True, capture_output=True, timeout=5, check=False,
        )
        self.assertEqual(0, printf_result.returncode, printf_result.stderr)
        self.assertEqual(printf_record + "\n", printf_result.stdout)
        ssh_binary = Path("/usr/bin/ssh")
        for executable in (helper, ssh_binary):
            metadata = executable.lstat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(0, metadata.st_uid)
            self.assertEqual(0, stat.S_IMODE(metadata.st_mode) & 0o022)
            self.assertTrue(os.access(executable, os.X_OK))
            current = executable.parent
            while True:
                ancestor = current.lstat()
                self.assertTrue(stat.S_ISDIR(ancestor.st_mode))
                self.assertEqual(0, ancestor.st_uid)
                self.assertEqual(0, stat.S_IMODE(ancestor.st_mode) & 0o022)
                self.assertEqual(current, current.resolve(strict=True))
                if current == current.parent:
                    break
                current = current.parent

        real_lstat = self.backup.os.lstat
        for hostile in (
            "final-symlink", "final-wrong-owner", "final-writable",
            "final-nonexec", "unsafe-ancestor", "unsafe-grandancestor",
        ):
            with self.subTest(hostile=hostile), tempfile.TemporaryDirectory() as directory:
                project = Path(directory).resolve()
                (project / ".ssh-known-hosts").mkdir(mode=0o700)
                password_spawns = []

                def hostile_lstat(path, *args, **kwargs):
                    result = real_lstat(path, *args, **kwargs)
                    candidate = Path(path)
                    values = list(result)
                    if hostile == "final-symlink" and candidate == helper:
                        values[0] = stat.S_IFLNK | 0o777
                    elif hostile == "final-wrong-owner" and candidate == helper:
                        values[4] = 1
                    elif hostile == "final-writable" and candidate == helper:
                        values[0] |= 0o022
                    elif hostile == "final-nonexec" and candidate == helper:
                        values[0] &= ~0o111
                    elif hostile == "unsafe-ancestor" and candidate == helper.parent:
                        values[0] |= 0o002
                    elif (
                        hostile == "unsafe-grandancestor"
                        and candidate == helper.parent.parent
                    ):
                        values[0] |= 0o002
                    return os.stat_result(values)

                def rejected_key(_user, _ip, _command, _timeout, options, **_kwargs):
                    combined = list(self.backup.SSH_OPTS) + list(options)
                    if self._option_values(combined, "BatchMode") != ["yes"]:
                        password_spawns.append(True)
                    return subprocess.CompletedProcess([], 255, "", "key rejected")

                with mock.patch.object(
                    self.backup.os, "lstat", side_effect=hostile_lstat,
                ), self.assertRaises((RuntimeError, ValueError)):
                    trusted_helper()
                with mock.patch.object(
                    self.backup.os, "lstat", side_effect=hostile_lstat,
                ), mock.patch.object(
                    self.backup, "_scan_offered_host_key",
                ) as scan, mock.patch.object(
                    self.backup, "_run_ssh", side_effect=rejected_key,
                ):
                    try:
                        self.backup._ssh(
                            "cumulus", self.SECRET, self.TARGET, "true",
                            project_output=project, scope="prod",
                        )
                    except (OSError, RuntimeError, ValueError):
                        pass
                self.assertEqual(0, scan.call_count)
                self.assertEqual([], password_spawns)

    @unittest.skipUnless(
        Path("/usr/sbin/sshd").is_file() or shutil.which("sshd"),
        "C1 stock OpenSSH loopback requires sshd; CI NOT-COVERED is tracked in REAL_ENVIRONMENT",
    )
    def test_stock_openssh_known_hosts_command_is_strict_on_loopback(self):
        ssh = Path("/usr/bin/ssh")
        sshd = Path(shutil.which("sshd") or "/usr/sbin/sshd")
        ssh_keygen = Path("/usr/bin/ssh-keygen")
        ssh_keyscan = Path("/usr/bin/ssh-keyscan")
        self.assertTrue(all(
            path.is_file() for path in (ssh, sshd, ssh_keygen, ssh_keyscan)
        ))
        formal_marker = "HTTP_P_FORMAL_LOOPBACK_SSHD"
        active_loopback = None
        consumer = None
        if formal_marker in os.environ:
            self.assertEqual("1", os.environ[formal_marker])
            publication = importlib.import_module(
                "test_cases.test_public_publication_workflow"
            )
            consumer = getattr(
                publication,
                "_formal_loopback_sshd_authority_from_environment",
            )
            active_loopback = consumer()
            self.assertIsNotNone(active_loopback)
            active_snapshot = Path(
                os.environ["HTTP_P_DEPENDENCY_ACTIVE_SNAPSHOT"]
            ).resolve()
            self.assertEqual(
                active_snapshot.parent / "formal-loopback-sshd",
                active_loopback.root,
            )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            if active_loopback is None:
                host_key = root / "host-ed25519"
                other_key = root / "host-rsa"
                for algorithm, key in (("ed25519", host_key), ("rsa", other_key)):
                    generated = subprocess.run(
                        [str(ssh_keygen), "-q", "-t", algorithm, "-N", "", "-f", str(key)],
                        text=True, capture_output=True, timeout=10, check=False,
                    )
                    self.assertEqual(0, generated.returncode, generated.stderr)
                ed_fields = host_key.with_suffix(".pub").read_text().split()
                rsa_fields = other_key.with_suffix(".pub").read_text().split()
                fingerprints = {}
                for label, public_key, expected_bits in (
                    ("ed25519", host_key.with_suffix(".pub"), "256"),
                    ("rsa", other_key.with_suffix(".pub"), "3072"),
                ):
                    fingerprint = subprocess.run(
                        [str(ssh_keygen), "-lf", str(public_key), "-E", "sha256"],
                        text=True, capture_output=True, timeout=10, check=False,
                    )
                    self.assertEqual(0, fingerprint.returncode, fingerprint.stderr)
                    self.assertEqual("", fingerprint.stderr)
                    fields = fingerprint.stdout.strip().split()
                    self.assertGreaterEqual(len(fields), 4)
                    self.assertEqual(expected_bits, fields[0])
                    self.assertRegex(fields[1], r"\ASHA256:[A-Za-z0-9+/]{43}\Z")
                    self.assertEqual(f"({label.upper()})", fields[-1])
                    fingerprints[label] = fields[1]
                with socket.socket() as reservation:
                    reservation.bind(("127.0.0.1", 0))
                    port = reservation.getsockname()[1]
                config = root / "sshd_config"
                config.write_text(
                    f"Port {port}\n"
                    "ListenAddress 127.0.0.1\n"
                    f"HostKey {host_key}\n"
                    f"PidFile {root / 'sshd.pid'}\n"
                    "AuthorizedKeysFile none\n"
                    "PasswordAuthentication no\n"
                    "KbdInteractiveAuthentication no\n"
                    "UsePAM no\n"
                    "PermitRootLogin no\n"
                    "StrictModes no\n"
                    "MaxStartups 100\n"
                    "PerSourcePenalties no\n"
                    "LogLevel ERROR\n",
                    encoding="utf-8",
                )
            else:
                port = active_loopback.port
                ed_fields = active_loopback.public_keys["ed25519"].split()
                rsa_fields = active_loopback.public_keys["rsa"].split()
                fingerprints = dict(active_loopback.fingerprints)
                self.assertEqual(2, len(ed_fields))
                self.assertEqual(2, len(rsa_fields))
                self.assertEqual("ssh-ed25519", ed_fields[0])
                self.assertEqual("ssh-rsa", rsa_fields[0])
            helper = root / "known-hosts-helper.py"
            helper.write_text(
                "#!/usr/bin/env python3\n"
                "import os, sys\n"
                "with open(os.environ['KHC_CALLS'], 'a') as stream:\n"
                " stream.write(' '.join(sys.argv[1:]) + '\\n')\n"
                "mode = os.environ.get('KHC_MODE', 'match')\n"
                "if mode == 'nonzero': raise SystemExit(9)\n"
                "if mode != 'empty': print(os.environ['KHC_RECORD'])\n",
                encoding="utf-8",
            )
            helper.chmod(0o700)
            calls = root / "known-hosts-calls"
            daemon_log = (
                root / "sshd.stderr" if active_loopback is None
                else active_loopback.daemon_log
            )
            if active_loopback is None:
                daemon_log.touch(mode=0o600)
            daemon_log_metadata = daemon_log.lstat()
            self.assertTrue(stat.S_ISREG(daemon_log_metadata.st_mode))
            self.assertEqual(0o600, stat.S_IMODE(daemon_log_metadata.st_mode))
            self.assertEqual(1, daemon_log_metadata.st_nlink)
            daemon_log_stream = None
            daemon = None
            if active_loopback is None:
                daemon_log_stream = daemon_log.open("w", encoding="utf-8")
                try:
                    daemon = subprocess.Popen(
                        [str(sshd), "-D", "-e", "-f", str(config)],
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                        stderr=daemon_log_stream, text=True, start_new_session=True,
                    )
                except BaseException:
                    daemon_log_stream.close()
                    raise

            def daemon_alive():
                if daemon is not None:
                    return daemon.poll() is None
                try:
                    os.kill(active_loopback.daemon_pid, 0)
                except ProcessLookupError:
                    return False
                return True
            try:
                def daemon_diagnostics():
                    try:
                        return daemon_log.read_text(encoding="utf-8")[-4096:]
                    except OSError as error:
                        return f"<unavailable sshd diagnostics: {error}>"

                host = f"[127.0.0.1]:{port}"
                deadline = time.monotonic() + 8
                readiness_attempts = []
                ready = False
                for _attempt in range(3):
                    if not daemon_alive():
                        self.fail("loopback sshd exited: " + daemon_diagnostics())
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    scanned = subprocess.run(
                        [
                            str(ssh_keyscan), "-T", "2", "-p", str(port),
                            "-t", "ed25519", "127.0.0.1",
                        ],
                        text=True, capture_output=True,
                        timeout=min(4, remaining), check=False,
                    )
                    scan_lines = [
                        line for line in scanned.stdout.splitlines()
                        if line and not line.startswith("#")
                    ]
                    readiness_attempts.append((scanned.returncode, tuple(scan_lines)))
                    if scan_lines:
                        self.assertEqual(0, scanned.returncode, scanned.stderr)
                        self.assertEqual(1, len(scan_lines), scanned.stdout)
                        scan_fields = scan_lines[0].split()
                        self.assertEqual(
                            [host, ed_fields[0], ed_fields[1]], scan_fields,
                            scanned.stdout,
                        )
                        scanned_fingerprint = "SHA256:" + base64.b64encode(
                            hashlib.sha256(base64.b64decode(scan_fields[2])).digest(),
                        ).rstrip(b"=").decode("ascii")
                        self.assertEqual(
                            fingerprints["ed25519"], scanned_fingerprint,
                        )
                        ready = True
                        break
                    time.sleep(0.05)
                if not ready:
                    self.fail(
                        "loopback sshd did not complete a reviewed host-key KEX: "
                        f"attempts={readiness_attempts!r}; " + daemon_diagnostics()
                    )

                matching = f"{host} {ed_fields[0]} {ed_fields[1]}"
                same_algorithm_other_key = (
                    f"{host} {ed_fields[0]} "
                    + base64.b64encode(
                        base64.b64decode(ed_fields[1])[:-1] + b"\x7f",
                    ).decode("ascii")
                )
                different_algorithm = f"{host} {rsa_fields[0]} {rsa_fields[1]}"

                def connect(
                    mode, record, helper_path=helper, algorithm="ssh-ed25519",
                    known_hosts_command=None, run_timeout=5,
                ):
                    if run_timeout <= 0:
                        raise AssertionError("loopback SSH retry deadline expired")
                    prior_reasons = (
                        calls.read_text(encoding="utf-8").splitlines()
                        if calls.exists() else []
                    )
                    environment = dict(os.environ)
                    environment.update({
                        "KHC_CALLS": str(calls), "KHC_MODE": mode,
                        "KHC_RECORD": record,
                    })
                    argv = [
                            str(ssh), "-vv", "-F", "/dev/null", "-p", str(port),
                            "-o", "BatchMode=yes",
                            "-o", "PasswordAuthentication=no",
                            "-o", "StrictHostKeyChecking=yes",
                            "-o", "UserKnownHostsFile=/dev/null",
                            "-o", "GlobalKnownHostsFile=/dev/null",
                            "-o", "KnownHostsCommand=" + (
                                known_hosts_command
                                or f"{helper_path} %I %H"
                            ),
                            "-o", "CheckHostIP=no",
                            "-o", "UpdateHostKeys=no",
                            "-o", "ConnectTimeout=2",
                            "nobody@127.0.0.1", "true",
                    ]
                    if algorithm is not None:
                        argv[-2:-2] = ["-o", f"HostKeyAlgorithms={algorithm}"]
                    completed = subprocess.run(
                        argv,
                        env=environment, text=True, capture_output=True,
                        timeout=min(5, run_timeout), check=False,
                    )
                    all_reasons = (
                        calls.read_text(encoding="utf-8").splitlines()
                        if calls.exists() else []
                    )
                    self.assertEqual(prior_reasons, all_reasons[:len(prior_reasons)])
                    completed.known_hosts_reasons = all_reasons[len(prior_reasons):]
                    return completed

                def assert_verified_terminal(
                    completed, algorithm, fingerprint, *, helper_reasons=True,
                ):
                    stderr = completed.stderr.casefold()
                    host_key_marker = (
                        f"server host key: {algorithm} {fingerprint}".casefold()
                    )
                    match_marker = (
                        f"is known and matches the {algorithm.removeprefix('ssh-')} host key"
                    )
                    helper_marker = "knownhostscommand-hostname"
                    self.assertNotEqual(0, completed.returncode)
                    self.assertIn(host_key_marker, stderr)
                    self.assertIn(match_marker, stderr)
                    self.assertIn(helper_marker, stderr)
                    if helper_reasons:
                        self.assertEqual(
                            [f"ORDER {host}", f"HOSTNAME {host}"],
                            completed.known_hosts_reasons,
                        )
                    else:
                        self.assertEqual([], completed.known_hosts_reasons)
                    self.assertNotIn("host key verification failed", stderr)
                    accepted_terminals = (
                        "permission denied",
                        f"connection closed by 127.0.0.1 port {port}",
                    )
                    selected = [
                        terminal for terminal in accepted_terminals
                        if terminal in stderr
                    ]
                    self.assertEqual(1, len(selected), completed.stderr)
                    nonempty_lines = [line for line in stderr.splitlines() if line]
                    self.assertTrue(nonempty_lines, completed.stderr)
                    self.assertIn(selected[0], nonempty_lines[-1])
                    positions = (
                        stderr.index(host_key_marker), stderr.index(match_marker),
                        stderr.index(helper_marker), stderr.rindex(selected[0]),
                    )
                    self.assertEqual(tuple(sorted(positions)), positions, completed.stderr)

                def is_exact_pre_hostkey_transient(completed, daemon_alive):
                    stderr = completed.stderr.casefold()
                    terminal = f"connection closed by 127.0.0.1 port {port}"
                    lines = [line for line in stderr.splitlines() if line]
                    return (
                        daemon_alive
                        and completed.returncode == 255
                        and completed.stdout == ""
                        and bool(lines) and lines[-1] == terminal
                        and stderr.count(terminal) == 1
                        and "ssh2_msg_kexinit sent" in stderr
                        and "server host key:" not in stderr
                        and "is known and matches" not in stderr
                        and "knownhostscommand-" not in stderr
                        and "host key verification failed" not in stderr
                        and "knownhostscommand failed" not in stderr
                        and "no matching host key type found" not in stderr
                        and "permission denied" not in stderr
                        and completed.known_hosts_reasons == []
                    )

                def connect_with_verified_retry(
                    connect_once, *, daemon_alive, now=time.monotonic,
                    sleeper=time.sleep,
                ):
                    retry_deadline = now() + 8
                    attempts = []
                    for attempt in range(3):
                        remaining = retry_deadline - now()
                        if remaining <= 0:
                            raise AssertionError(
                                "loopback SSH retry deadline expired"
                            )
                        completed = connect_once(remaining)
                        attempts.append(completed)
                        if not is_exact_pre_hostkey_transient(
                            completed, daemon_alive(),
                        ):
                            return completed, attempts
                        if attempt == 2 or now() >= retry_deadline:
                            raise AssertionError(
                                "loopback sshd repeatedly closed before host-key evidence"
                            )
                        sleeper(0.05)
                    raise AssertionError("unreachable loopback retry state")

                def fake_result(stderr, *, reasons=(), returncode=255):
                    completed = subprocess.CompletedProcess(
                        [str(ssh)], returncode, "", stderr,
                    )
                    completed.known_hosts_reasons = list(reasons)
                    return completed

                transient = fake_result(
                    "debug1: SSH2_MSG_KEXINIT sent\n"
                    f"Connection closed by 127.0.0.1 port {port}\n"
                )
                verified = fake_result(
                    f"debug1: Server host key: ssh-ed25519 {fingerprints['ed25519']}\n"
                    "debug1: Host is known and matches the ED25519 host key.\n"
                    "debug3: knownhostscommand-hostname\n"
                    "Permission denied\n",
                    reasons=(f"ORDER {host}", f"HOSTNAME {host}"),
                )
                fake_sequence = iter((transient, verified))
                retried, fake_attempts = connect_with_verified_retry(
                    lambda _remaining: next(fake_sequence), daemon_alive=lambda: True,
                    now=lambda: 0, sleeper=lambda _delay: None,
                )
                self.assertIs(verified, retried)
                self.assertEqual([transient, verified], fake_attempts)
                assert_verified_terminal(
                    retried, "ssh-ed25519", fingerprints["ed25519"],
                )
                with self.assertRaisesRegex(
                    AssertionError, "repeatedly closed before host-key evidence",
                ):
                    connect_with_verified_retry(
                        lambda _remaining: transient, daemon_alive=lambda: True,
                        now=lambda: 0, sleeper=lambda _delay: None,
                    )
                reversed_evidence = fake_result(
                    f"debug1: Server host key: ssh-ed25519 {fingerprints['ed25519']}\n"
                    "debug3: knownhostscommand-hostname\n"
                    "debug1: Host is known and matches the ED25519 host key.\n"
                    "Permission denied\n",
                    reasons=(f"ORDER {host}", f"HOSTNAME {host}"),
                )
                with self.assertRaises(AssertionError):
                    assert_verified_terminal(
                        reversed_evidence, "ssh-ed25519", fingerprints["ed25519"],
                    )
                fake_clock = [0.0]
                deadline_budgets = []
                def delayed_transient(remaining):
                    deadline_budgets.append(remaining)
                    fake_clock[0] += 4.1
                    return transient
                with self.assertRaisesRegex(
                    AssertionError, "retry deadline expired|repeatedly closed",
                ):
                    connect_with_verified_retry(
                        delayed_transient, daemon_alive=lambda: True,
                        now=lambda: fake_clock[0], sleeper=lambda _delay: None,
                    )
                self.assertEqual(2, len(deadline_budgets))
                self.assertEqual(8, deadline_budgets[0])
                self.assertGreater(deadline_budgets[1], 0)
                self.assertLess(deadline_budgets[1], 4)
                self.assertGreaterEqual(fake_clock[0], 8)
                non_retryable = (
                    fake_result(
                        f"debug1: Server host key: ssh-ed25519 SHA256:{'A' * 43}\n"
                        f"Connection closed by 127.0.0.1 port {port}\n"
                    ),
                    fake_result(
                        transient.stderr,
                        reasons=(f"ORDER {host}",),
                    ),
                    fake_result("arbitrary ssh failure\n"),
                )
                for label, result, alive in (
                    ("mismatched-host-key", non_retryable[0], True),
                    ("helper-evidence", non_retryable[1], True),
                    ("arbitrary-stderr", non_retryable[2], True),
                    ("daemon-dead", transient, False),
                ):
                    calls_made = []
                    with self.subTest(retry_rejection=label):
                        returned, attempts = connect_with_verified_retry(
                            lambda _remaining, result=result: (
                                calls_made.append(True) or result
                            ),
                            daemon_alive=lambda alive=alive: alive,
                            now=lambda: 0, sleeper=lambda _delay: None,
                        )
                        self.assertIs(result, returned)
                        self.assertEqual([True], calls_made)
                        self.assertEqual([result], attempts)

                ordered, ordered_attempts = connect_with_verified_retry(
                    lambda remaining: connect(
                        "match", matching, algorithm=None, run_timeout=remaining,
                    ),
                    daemon_alive=daemon_alive,
                )
                self.assertLessEqual(len(ordered_attempts), 3)
                assert_verified_terminal(ordered, "ssh-ed25519", fingerprints["ed25519"])
                matched, matched_attempts = connect_with_verified_retry(
                    lambda remaining: connect(
                        "match", matching, algorithm=None, run_timeout=remaining,
                    ),
                    daemon_alive=daemon_alive,
                )
                self.assertLessEqual(len(matched_attempts), 3)
                assert_verified_terminal(matched, "ssh-ed25519", fingerprints["ed25519"])
                printf_command = (
                    "/usr/bin/printf '%%s\\n' " + shlex.quote(matching)
                )
                printf_matched, printf_attempts = connect_with_verified_retry(
                    lambda remaining: connect(
                        "match", matching, known_hosts_command=printf_command,
                        run_timeout=remaining,
                    ),
                    daemon_alive=daemon_alive,
                )
                self.assertLessEqual(len(printf_attempts), 3)
                assert_verified_terminal(
                    printf_matched, "ssh-ed25519", fingerprints["ed25519"],
                    helper_reasons=False,
                )
                reasons = calls.read_text(encoding="utf-8").splitlines()
                self.assertTrue(
                    any(line.startswith("ORDER ") for line in reasons), reasons,
                )
                self.assertTrue(
                    any(line.startswith("HOSTNAME ") for line in reasons), reasons,
                )

                for label, completed, rejection in (
                    (
                        "same-algorithm", connect("match", same_algorithm_other_key),
                        "host key verification failed",
                    ),
                    (
                        "different-algorithm",
                        connect("match", different_algorithm, algorithm="ssh-rsa"),
                        "no matching host key type found",
                    ),
                    ("empty", connect("empty", matching), "host key verification failed"),
                    ("nonzero", connect("nonzero", matching), "knownhostscommand failed"),
                    (
                        "missing", connect("match", matching, root / "missing-helper"),
                        "host key verification failed",
                    ),
                ):
                    with self.subTest(label=label):
                        self.assertNotEqual(0, completed.returncode)
                        self.assertNotIn("permission denied", completed.stderr.casefold())
                        self.assertNotIn(
                            f"connection closed by 127.0.0.1 port {port}",
                            completed.stderr.casefold(),
                        )
                        self.assertIn(rejection, completed.stderr.casefold())
            finally:
                if daemon is not None:
                    try:
                        os.killpg(daemon.pid, 9)
                    except ProcessLookupError:
                        pass
                    try:
                        daemon.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(daemon.pid, 9)
                        except ProcessLookupError:
                            pass
                        daemon.wait(timeout=2)
                    finally:
                        daemon_log_stream.close()
                    self.assertIsNotNone(daemon.poll())
                    self.assertTrue(daemon_log_stream.closed)
                else:
                    self.assertTrue(daemon_alive())
                    active_again = consumer()
                    self.assertEqual(active_loopback.root, active_again.root)
                    self.assertEqual(active_loopback.port, active_again.port)
                    self.assertEqual(
                        active_loopback.daemon_pid, active_again.daemon_pid,
                    )
                    self.assertEqual(
                        active_loopback.public_keys, active_again.public_keys,
                    )
                    self.assertEqual(
                        active_loopback.fingerprints, active_again.fingerprints,
                    )
                    self.assertEqual(
                        active_loopback.source_fds, active_again.source_fds,
                    )
                    for descriptor in active_again.source_fds:
                        os.fstat(descriptor)
                closed_log_metadata = daemon_log.lstat()
                self.assertTrue(stat.S_ISREG(closed_log_metadata.st_mode))
                self.assertEqual(0o600, stat.S_IMODE(closed_log_metadata.st_mode))
                self.assertEqual(1, closed_log_metadata.st_nlink)
                self.assertEqual(
                    (daemon_log_metadata.st_dev, daemon_log_metadata.st_ino),
                    (closed_log_metadata.st_dev, closed_log_metadata.st_ino),
                )

    def test_ssh_capability_and_execution_bind_canonical_binary_identity(self):
        require_support = getattr(
            self.backup, "_require_known_hosts_command_support", None,
        )
        if not callable(require_support):
            self.fail("KnownHostsCommand capability probe is absent")
        blob = "AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()
            for location in (first, second):
                for name in ("ssh", "ssh-keyscan"):
                    executable = location / name
                    executable.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
                    executable.chmod(0o755)
            calls = []

            def fake_bounded(argv, *_args, **_kwargs):
                calls.append(list(argv))
                if "-V" in argv:
                    return subprocess.CompletedProcess(
                        argv, 0, "", "OpenSSH_10.2p1 bound-test",
                    )
                if "-G" in argv:
                    return subprocess.CompletedProcess(
                        argv, 0, "hostname example.invalid\n", "",
                    )
                if Path(argv[0]).name == "ssh-keyscan":
                    return subprocess.CompletedProcess(
                        argv, 0,
                        f"{self.TARGET} ssh-ed25519 {blob}\n", "",
                    )
                return subprocess.CompletedProcess(argv, 0, "", "")

            first_path = str(first) + os.pathsep + os.environ.get("PATH", "")
            second_path = str(second) + os.pathsep + os.environ.get("PATH", "")
            with mock.patch.dict(os.environ, {"PATH": first_path}, clear=False), \
                    mock.patch.object(
                        self.backup, "_SSH_BINARY", None, create=True,
                    ), mock.patch.object(
                        self.backup, "_SSH_KEYSCAN_BINARY", None, create=True,
                    ), mock.patch.object(
                        self.backup, "_KNOWN_HOSTS_COMMAND_EVIDENCE", None,
                        create=True,
                    ), mock.patch.object(
                        self.backup, "_run_bounded_process",
                        side_effect=fake_bounded,
                    ):
                require_support()
                self.backup._scan_offered_host_key(
                    self.TARGET, 5, key_type="ssh-ed25519",
                )
                with mock.patch.dict(
                    os.environ, {"PATH": second_path}, clear=False,
                ):
                    self.backup._run_ssh(
                        "cumulus", self.TARGET, "true", 5,
                        self.backup._KEY_AUTH_OPTS,
                    )
                    self.backup._scan_offered_host_key(
                        self.TARGET, 5, key_type="ssh-ed25519",
                    )
            ssh_execs = [
                Path(argv[0]) for argv in calls
                if Path(argv[0]).name == "ssh"
            ]
            scan_execs = [
                Path(argv[0]) for argv in calls
                if Path(argv[0]).name == "ssh-keyscan"
            ]
            self.assertTrue(ssh_execs)
            self.assertTrue(scan_execs)
            self.assertTrue(all(path == first / "ssh" for path in ssh_execs))
            self.assertTrue(all(
                path == first / "ssh-keyscan" for path in scan_execs
            ))

    def test_parallel_password_calls_hold_unique_private_fifos(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            configured = root / "askpass"
            configured.mkdir(mode=0o700)
            output = root / "project-output" / "20260911_2300-prod-backup"
            for category in ("eth", "spx", "ib", "nvl"):
                (output / category).mkdir(parents=True, exist_ok=True)
            barrier = threading.Barrier(2)
            lock = threading.Lock()
            first_targets = set()
            simultaneous = []

            def fake_run(_user, ip, command, _timeout, options,
                         env=None, **_kwargs):
                combined = list(self.backup.SSH_OPTS) + list(options)
                if self._option_values(combined, "BatchMode") == ["yes"]:
                    return subprocess.CompletedProcess([], 255, "", "key rejected")
                with lock:
                    first = ip not in first_targets
                    first_targets.add(ip)
                if first:
                    fifo_text = (env or {}).get("ZTP_BACKUP_PASSWORD_FIFO")
                    simultaneous.append(Path(fifo_text) if fifo_text else None)
                    barrier.wait(timeout=5)
                    self.assertTrue(all(
                        path is not None and path.exists() for path in simultaneous
                    ))
                hostname = "leaf01" if ip.endswith(".10") else "leaf02"
                if command.startswith("hostname"):
                    stdout = hostname + "\n"
                elif command.startswith("sudo "):
                    stdout = "set:\n  system:\n    hostname: " + hostname + "\n"
                elif "eth0/address" in command:
                    stdout = "02:00:00:00:00:01\n"
                else:
                    stdout = ""
                return subprocess.CompletedProcess([], 0, stdout, "")

            devices = [
                self._device("leaf01", "192.0.2.10"),
                self._device("leaf02", "192.0.2.11"),
            ]
            environment = {
                "HTTP_ZTP_RUNTIME_BACKEND": "supervisor",
                "HTTP_ZTP_ASKPASS_TMPDIR": str(configured),
            }
            def scan_record(target, *_args, **_kwargs):
                return (
                    f"{target} ssh-ed25519 "
                    "AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER"
                )
            with mock.patch.dict(os.environ, environment, clear=False), \
                    mock.patch.object(self.backup, "_ENVIRONMENT", "prod"), \
                    mock.patch.object(
                        self.backup, "_scan_offered_host_key",
                        side_effect=scan_record,
                    ) as scan, \
                    mock.patch.object(self.backup, "_run_ssh", side_effect=fake_run):
                with ThreadPoolExecutor(max_workers=2) as executor:
                    results = list(executor.map(
                        lambda device: self.backup.collect_device(
                            device, str(output), self.SECRET, "", "",
                        ),
                        devices,
                    ))
            self.assertTrue(all(result is not None for _, result in results))
            self.assertEqual(2, len(simultaneous))
            self.assertEqual(2, scan.call_count)
            self.assertNotEqual(simultaneous[0], simultaneous[1])
            self.assertTrue(all(not path.exists() for path in simultaneous))

    def test_fifo_runtime_identity_rejects_path_rebind_without_unlinking_replacement(self):
        """The real helper must bind its read to the FIFO identity primed by parent."""
        replacement_kinds = ("symlink", "hardlink", "second-fifo", "regular")
        for kind in replacement_kinds:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                exec_root = root / "exec"
                exec_root.mkdir(mode=0o700)
                project = root / "project" / "run-prod-backup"
                (project / "eth").mkdir(parents=True)
                outside = root / "outside"
                outside.write_text("outside-stays\n", encoding="utf-8")
                observed = []

                def fake_run(_user, _ip, _command, _timeout, options,
                             env=None, **_kwargs):
                    combined = list(self.backup.SSH_OPTS) + list(options)
                    if self._option_values(combined, "BatchMode") == ["yes"]:
                        return subprocess.CompletedProcess([], 255, "", "key rejected")
                    fifo_text = (env or {}).get("ZTP_BACKUP_PASSWORD_FIFO")
                    self.assertTrue(fifo_text, "password call did not expose a FIFO path")
                    fifo = Path(fifo_text)
                    before = fifo.lstat()
                    self.assertTrue(stat.S_ISFIFO(before.st_mode))
                    self.assertEqual(os.geteuid(), before.st_uid)
                    self.assertEqual(0o600, stat.S_IMODE(before.st_mode))
                    self.assertEqual(1, before.st_nlink)
                    displaced = fifo.with_name(fifo.name + ".held")
                    fifo.rename(displaced)
                    if kind == "symlink":
                        fifo.symlink_to(outside)
                    elif kind == "hardlink":
                        os.link(displaced, fifo)
                    elif kind == "second-fifo":
                        os.mkfifo(fifo, 0o600)
                    else:
                        fifo.write_text("attacker replacement\n", encoding="utf-8")
                    helper = Path(env["SSH_ASKPASS"])
                    asked = subprocess.run(
                        [str(helper)], env=env, text=True, capture_output=True,
                        timeout=2, check=False,
                    )
                    observed.append((fifo, displaced, asked.returncode))
                    raise RuntimeError("synthetic stop after identity rebind")

                environment = {
                    "HTTP_ZTP_RUNTIME_BACKEND": "supervisor",
                    "HTTP_ZTP_ASKPASS_TMPDIR": str(exec_root),
                }
                scan_record = (
                    f"{self.TARGET} ssh-ed25519 "
                    "AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER"
                )
                try:
                    with mock.patch.dict(os.environ, environment, clear=False), \
                            mock.patch.object(self.backup, "_ENVIRONMENT", "prod"), \
                            mock.patch.object(
                                self.backup, "_scan_offered_host_key",
                                return_value=scan_record,
                            ) as scan, \
                            mock.patch.object(self.backup, "_run_ssh", side_effect=fake_run):
                        self.backup.collect_device(
                            self._device(), str(project), self.SECRET, "", "",
                        )
                except (OSError, RuntimeError, TypeError, ValueError):
                    pass
                self.assertEqual(1, scan.call_count)
                self.assertEqual(1, len(observed))
                fifo, displaced, helper_rc = observed[0]
                self.assertNotEqual(0, helper_rc, "rebound FIFO reached askpass")
                self.assertTrue(fifo.exists() or fifo.is_symlink())
                self.assertEqual("outside-stays\n", outside.read_text(encoding="utf-8"))
                if fifo.is_symlink() or fifo.is_file():
                    fifo.unlink()
                elif fifo.exists():
                    fifo.unlink()
                if displaced.exists():
                    displaced.unlink()

    def test_native_unset_exec_root_uses_private_platform_temp_without_fallback_on_unsafe_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            platform_temp = root / "platform-temp"
            platform_temp.mkdir()
            output = root / "output"
            (output / "eth").mkdir(parents=True)
            previous_tempdir = self.backup.tempfile.tempdir
            self.backup.tempfile.tempdir = str(platform_temp)
            password_calls = []

            def fake_run(_user, _ip, command, _timeout, options, env=None, **_kwargs):
                combined = list(self.backup.SSH_OPTS) + list(options)
                if self._option_values(combined, "BatchMode") == ["yes"]:
                    return subprocess.CompletedProcess([], 255, "", "key rejected")
                password_calls.append(env)
                helper = Path(env["SSH_ASKPASS"])
                self.assertTrue(helper.is_relative_to(platform_temp))
                self.assertEqual(0o700, stat.S_IMODE(helper.parent.stat().st_mode))
                asked = subprocess.run(
                    [str(helper)], env=env, text=True, capture_output=True,
                    timeout=2, check=False,
                )
                self.assertEqual(self.SECRET + "\n", asked.stdout)
                stdout = self._remote_result(command)
                return subprocess.CompletedProcess([], 0, stdout, "")

            environment = dict(os.environ)
            environment["HTTP_ZTP_RUNTIME_BACKEND"] = "native"
            environment.pop("HTTP_ZTP_ASKPASS_TMPDIR", None)
            scan_record = (
                f"{self.TARGET} ssh-ed25519 "
                "AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER"
            )
            try:
                with mock.patch.dict(os.environ, environment, clear=True), \
                        mock.patch.object(
                            self.backup, "_scan_offered_host_key",
                            return_value=scan_record,
                        ) as scan, \
                        mock.patch.object(self.backup, "_run_ssh", side_effect=fake_run):
                    _log, result = self.backup.collect_device(
                        self._device(), str(output), self.SECRET, "", "",
                    )
                self.assertTrue(result and result["yaml_ok"])
                self.assertGreater(len(password_calls), 1)
                self.assertEqual(1, scan.call_count)
                self.backup._cleanup_askpass()
                self.assertEqual([], list(platform_temp.iterdir()))

                unsafe = root / "unsafe"
                unsafe.mkdir(mode=0o755)
                unsafe.chmod(0o755)
                environment["HTTP_ZTP_ASKPASS_TMPDIR"] = str(unsafe)
                password_calls.clear()
                self.backup._AUTH_MODES.clear()
                with mock.patch.dict(os.environ, environment, clear=True), \
                        mock.patch.object(self.backup, "_run_ssh", side_effect=fake_run):
                    try:
                        self.backup.collect_device(
                            self._device(), str(output), self.SECRET, "", "",
                        )
                    except (OSError, RuntimeError, ValueError):
                        pass
                self.assertEqual([], password_calls)
            finally:
                self.backup.tempfile.tempdir = previous_tempdir
                self.backup._cleanup_askpass()

    def test_ssh_subprocess_has_hard_group_deadline_fd_whitelist_and_output_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fake_bin = root / "bin"
            fake_bin.mkdir()
            pid_file = root / "descendant.pid"
            fake_ssh = fake_bin / "ssh"
            fake_ssh.write_text(
                "#!/usr/bin/env python3\n"
                "import os, subprocess, sys, time\n"
                "if os.environ.get('FAKE_OVERSIZE') == '1':\n"
                " print('O' * 300000)\n"
                " print('E' * 300000, file=sys.stderr)\n"
                " raise SystemExit(7)\n"
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'])\n"
                "open(os.environ['PID_FILE'], 'w').write(str(child.pid))\n"
                "time.sleep(5)\n",
                encoding="utf-8",
            )
            fake_ssh.chmod(0o755)
            environment = dict(os.environ)
            environment.update({
                "PATH": str(fake_bin) + os.pathsep + environment.get("PATH", ""),
                "PID_FILE": str(pid_file),
            })
            spawn_kwargs = []
            real_popen = subprocess.Popen

            def recording_popen(*args, **kwargs):
                spawn_kwargs.append(dict(kwargs))
                return real_popen(*args, **kwargs)

            started = time.monotonic()
            try:
                with mock.patch.object(self.backup.subprocess, "Popen", side_effect=recording_popen):
                    self.backup._run_ssh(
                        "cumulus", self.TARGET, "true", 0.1,
                        self.backup._KEY_AUTH_OPTS, env=environment,
                    )
            except subprocess.TimeoutExpired:
                pass
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 1.0, "descendant-held pipes defeated deadline")
            self.assertTrue(spawn_kwargs)
            first = spawn_kwargs[0]
            self.assertIs(first.get("close_fds"), True)
            self.assertTrue(first.get("start_new_session"))
            self.assertEqual((), tuple(first.get("pass_fds", ())))
            if pid_file.exists():
                descendant = int(pid_file.read_text(encoding="utf-8"))
                deadline = time.monotonic() + 0.5
                alive = True
                while time.monotonic() < deadline:
                    try:
                        os.kill(descendant, 0)
                    except ProcessLookupError:
                        alive = False
                        break
                    time.sleep(0.02)
                self.assertFalse(alive, "timed-out SSH descendant survived")

            environment["FAKE_OVERSIZE"] = "1"
            result = self.backup._run_ssh(
                "cumulus", self.TARGET, "true", 2,
                self.backup._KEY_AUTH_OPTS, env=environment,
            )
            limit = getattr(self.backup, "MAX_SSH_OUTPUT_BYTES", None)
            self.assertIsInstance(limit, int)
            self.assertGreater(limit, 0)
            self.assertLessEqual(len(result.stdout.encode("utf-8")), limit)
            self.assertLessEqual(len(result.stderr.encode("utf-8")), limit)

    def test_ssh_flood_is_cut_off_before_timeout_and_descendant_is_reaped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fake_bin = root / "bin"
            fake_bin.mkdir()
            leader_file = root / "leader.pid"
            child_file = root / "child.pid"
            fake_ssh = fake_bin / "ssh"
            fake_ssh.write_text(
                "#!/usr/bin/env python3\n"
                "import os, subprocess, sys\n"
                "open(os.environ['LEADER_PID'], 'w').write(str(os.getpid()))\n"
                "child = subprocess.Popen([sys.executable, '-c', "
                "'import time; time.sleep(20)'])\n"
                "open(os.environ['CHILD_PID'], 'w').write(str(child.pid))\n"
                "chunk = b'X' * 8192\n"
                "for _ in range(10): os.write(1, chunk)\n"
                "for _ in range(10): os.write(2, chunk)\n"
                "import time; time.sleep(20)\n",
                encoding="utf-8",
            )
            fake_ssh.chmod(0o755)
            environment = dict(os.environ)
            environment.update({
                "PATH": str(fake_bin) + os.pathsep + environment.get("PATH", ""),
                "LEADER_PID": str(leader_file),
                "CHILD_PID": str(child_file),
            })
            started = time.monotonic()
            result = self.backup._run_ssh(
                "cumulus", self.TARGET, "true", 5,
                self.backup._KEY_AUTH_OPTS, env=environment,
            )
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 1.5, "output flood was buffered until timeout")
            self.assertEqual(125, result.returncode)
            self.assertLessEqual(
                len(result.stdout.encode("utf-8")),
                self.backup.MAX_SSH_OUTPUT_BYTES,
            )
            self.assertLessEqual(
                len(result.stderr.encode("utf-8")),
                self.backup.MAX_SSH_OUTPUT_BYTES,
            )
            self.assertTrue(leader_file.is_file())
            self.assertTrue(child_file.is_file())
            for pid_file in (leader_file, child_file):
                pid = int(pid_file.read_text(encoding="utf-8"))
                deadline = time.monotonic() + 0.5
                while time.monotonic() < deadline:
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.02)
                else:
                    self.fail(f"SSH process survived bounded-output stop: {pid}")

    def test_ssh_successful_leader_cannot_leave_pipe_holding_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fake_bin = root / "bin"
            fake_bin.mkdir()
            child_file = root / "child.pid"
            fake_ssh = fake_bin / "ssh"
            fake_ssh.write_text(
                "#!/usr/bin/env python3\n"
                "import os, subprocess, sys\n"
                "child = subprocess.Popen([sys.executable, '-c', "
                "'import time; time.sleep(20)'])\n"
                "open(os.environ['CHILD_PID'], 'w').write(str(child.pid))\n",
                encoding="utf-8",
            )
            fake_ssh.chmod(0o755)
            environment = dict(os.environ)
            environment.update({
                "PATH": str(fake_bin) + os.pathsep + environment.get("PATH", ""),
                "CHILD_PID": str(child_file),
            })
            before_fds = len(list(Path("/dev/fd").iterdir()))
            started = time.monotonic()
            result = self.backup._run_ssh(
                "cumulus", self.TARGET, "true", 1,
                self.backup._KEY_AUTH_OPTS, env=environment,
            )
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertNotEqual(0, result.returncode)
            self.assertTrue(child_file.is_file())
            descendant = int(child_file.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 0.5
            while time.monotonic() < deadline:
                try:
                    os.kill(descendant, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.02)
            else:
                self.fail(f"successful SSH leader escaped descendant: {descendant}")
            self.assertEqual(before_fds, len(list(Path("/dev/fd").iterdir())))

    def test_ssh_successful_leader_cleans_detached_stdio_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fake_bin = root / "bin"
            fake_bin.mkdir()
            child_file = root / "child.pid"
            fake_ssh = fake_bin / "ssh"
            fake_ssh.write_text(
                "#!/usr/bin/env python3\n"
                "import os, subprocess, sys\n"
                "child = subprocess.Popen([sys.executable, '-c', "
                "'import time; time.sleep(20)'], stdin=subprocess.DEVNULL, "
                "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, "
                "close_fds=True)\n"
                "open(os.environ['CHILD_PID'], 'w').write(str(child.pid))\n",
                encoding="utf-8",
            )
            fake_ssh.chmod(0o755)
            environment = dict(os.environ)
            environment.update({
                "PATH": str(fake_bin) + os.pathsep + environment.get("PATH", ""),
                "CHILD_PID": str(child_file),
            })
            real_popen = subprocess.Popen
            spawned = []

            def recording_popen(*args, **kwargs):
                process = real_popen(*args, **kwargs)
                spawned.append(process)
                return process

            before_fds = len(list(Path("/dev/fd").iterdir()))
            descendant = None
            try:
                started = time.monotonic()
                with mock.patch.object(
                    self.backup.subprocess, "Popen", side_effect=recording_popen,
                ):
                    result = self.backup._run_ssh(
                        "cumulus", self.TARGET, "true", 1,
                        self.backup._KEY_AUTH_OPTS, env=environment,
                    )
                elapsed = time.monotonic() - started
                self.assertLess(elapsed, 1.5)
                self.assertEqual(0, result.returncode)
                self.assertEqual(1, len(spawned))
                self.assertIsNotNone(spawned[0].poll(), "SSH leader was not reaped")
                self.assertTrue(spawned[0].stdout.closed)
                self.assertTrue(spawned[0].stderr.closed)
                self.assertTrue(child_file.is_file())
                descendant = int(child_file.read_text(encoding="utf-8"))
                deadline = time.monotonic() + 0.5
                while time.monotonic() < deadline:
                    try:
                        os.kill(descendant, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.02)
                else:
                    self.fail(
                        f"successful SSH leader detached descendant: {descendant}"
                    )
                self.assertEqual(
                    before_fds, len(list(Path("/dev/fd").iterdir())),
                )
            finally:
                if descendant is None and child_file.is_file():
                    descendant = int(child_file.read_text(encoding="utf-8"))
                if descendant is not None:
                    try:
                        os.kill(descendant, 9)
                    except ProcessLookupError:
                        pass

    def test_ssh_spawn_and_stream_faults_reap_group_close_streams_and_fds(self):
        def fd_count():
            return len(list(Path("/dev/fd").iterdir()))

        before_constructor = fd_count()
        with mock.patch.object(
            self.backup.subprocess, "Popen", side_effect=OSError("spawn failed"),
        ), self.assertRaises(OSError):
            self.backup._run_ssh(
                "cumulus", self.TARGET, "true", 1,
                self.backup._KEY_AUTH_OPTS,
            )
        self.assertEqual(before_constructor, fd_count())

        drain = getattr(self.backup, "_drain_ssh_process", None)
        self.assertTrue(callable(drain), "bounded SSH stream reader is absent")
        failures = (
            (OSError("stream read failed"), None),
            (RuntimeError("unexpected drain failure"), self.SECRET + "\n"),
            (KeyboardInterrupt(), self.SECRET + "\n"),
        )
        for failure, stdin_text in failures:
            with self.subTest(failure=type(failure).__name__), \
                    tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                fake_bin = root / "bin"
                fake_bin.mkdir()
                child_file = root / "fault-child.pid"
                fake_ssh = fake_bin / "ssh"
                fake_ssh.write_text(
                    "#!/usr/bin/env python3\n"
                    "import os, subprocess, sys, time\n"
                    "child = subprocess.Popen([sys.executable, '-c', "
                    "'import time; time.sleep(20)'])\n"
                    "open(os.environ['FAULT_CHILD_PID'], 'w').write(str(child.pid))\n"
                    "time.sleep(20)\n",
                    encoding="utf-8",
                )
                fake_ssh.chmod(0o755)
                environment = dict(os.environ)
                environment["PATH"] = (
                    str(fake_bin) + os.pathsep + environment.get("PATH", "")
                )
                environment["FAULT_CHILD_PID"] = str(child_file)
                spawned = []
                real_popen = subprocess.Popen

                def recording_popen(*args, **kwargs):
                    process = real_popen(*args, **kwargs)
                    spawned.append(process)
                    return process

                def fail_after_descendant(*_args, **_kwargs):
                    deadline = time.monotonic() + 1
                    while time.monotonic() < deadline and not child_file.exists():
                        time.sleep(0.01)
                    raise failure

                before = fd_count()
                raised = None
                try:
                    with mock.patch.object(
                        self.backup.subprocess, "Popen", side_effect=recording_popen,
                    ), mock.patch.object(
                        self.backup, "_drain_ssh_process",
                        side_effect=fail_after_descendant,
                    ):
                        self.backup._run_ssh(
                            "cumulus", self.TARGET, "true", 5,
                            self.backup._KEY_AUTH_OPTS, env=environment,
                            stdin_text=stdin_text,
                        )
                except BaseException as exc:
                    raised = exc
                self.assertNotIn(self.SECRET, repr(raised))
                self.assertEqual(1, len(spawned))
                process = spawned[0]
                self.assertIsNotNone(process.poll(), "SSH leader was not reaped")
                self.assertTrue(process.stdout.closed)
                self.assertTrue(process.stderr.closed)
                if stdin_text is not None:
                    self.assertTrue(process.stdin.closed)
                if child_file.exists():
                    descendant = int(child_file.read_text(encoding="utf-8"))
                    deadline = time.monotonic() + 0.5
                    while time.monotonic() < deadline:
                        try:
                            os.kill(descendant, 0)
                        except ProcessLookupError:
                            break
                        time.sleep(0.02)
                    else:
                        self.fail(f"faulted SSH descendant survived: {descendant}")
                self.assertEqual(before, fd_count())

    def test_actual_pin_and_auth_cache_are_isolated_by_project_scope_and_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            exec_root = root / "exec"
            exec_root.mkdir(mode=0o700)
            runs = [
                (root / "project-a" / "run-prod", "prod"),
                (root / "project-a" / "run-air", "air"),
                (root / "project-b" / "run-prod", "prod"),
            ]
            for output, _scope in runs:
                (output / "eth").mkdir(parents=True)
            key_probes = []
            password_commands = []

            def fake_run(_user, ip, command, _timeout, options,
                         env=None, **_kwargs):
                combined = list(self.backup.SSH_OPTS) + list(options)
                if self._option_values(combined, "BatchMode") == ["yes"]:
                    key_probes.append(ip)
                    return subprocess.CompletedProcess([], 255, "", "key rejected")
                known = self._option_values(combined, "UserKnownHostsFile")
                self.assertEqual(["/dev/null"], known)
                command_values = self._option_values(
                    combined, "KnownHostsCommand",
                )
                self.assertEqual(1, len(command_values))
                password_commands.append(command_values[0])
                return subprocess.CompletedProcess([], 0, self._remote_result(command), "")

            def scan_record(target, *_args, **_kwargs):
                return (
                    f"{target} ssh-ed25519 "
                    "AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER"
                )

            environment = {
                "HTTP_ZTP_RUNTIME_BACKEND": "supervisor",
                "HTTP_ZTP_ASKPASS_TMPDIR": str(exec_root),
            }
            with mock.patch.dict(os.environ, environment, clear=False), \
                    mock.patch.object(
                        self.backup, "_scan_offered_host_key",
                        side_effect=scan_record,
                    ) as scan, \
                    mock.patch.object(self.backup, "_run_ssh", side_effect=fake_run):
                for output, scope in runs:
                    with mock.patch.object(self.backup, "_ENVIRONMENT", scope):
                        _log, result = self.backup.collect_device(
                            self._device(), str(output), self.SECRET, "", "",
                        )
                    self.assertTrue(result and result["yaml_ok"])
            self.assertEqual(3, len(key_probes), "auth cache crossed project/scope")
            self.assertEqual(3, scan.call_count)
            unique_pins = {
                path
                for output, _scope in runs
                for path in (output.parent / ".ssh-known-hosts").glob("*.known_hosts")
            }
            self.assertEqual(3, len(unique_pins))
            expected = {
                output.parent / ".ssh-known-hosts" / self._expected_pin_name(scope, self.TARGET)
                for output, scope in runs
            }
            self.assertEqual(expected, unique_pins)
            self.assertTrue(all(
                "AAAAC3NzaC1lZDI1NTE5" in command
                for command in password_commands
            ))

    def test_host_key_authority_rejects_hostile_directory_pin_and_records_pre_spawn(self):
        mismatched_wire_blob = base64.b64encode(
            b"\x00\x00\x00\x07ssh-rsa\x01",
        ).decode("ascii")
        hostile_dir_kinds = ("symlink", "regular", "wrong-mode", "wrong-owner")
        hostile_pin_kinds = (
            "symlink", "hardlink", "directory", "wrong-mode",
            "wrong-owner", "foreign-record", "unparsable-record",
            "invalid-base64", "unknown-algorithm", "truncated-wire",
            "mismatched-wire-algorithm", "malformed-key-body",
        )
        for authority_kind, kinds in (("directory", hostile_dir_kinds), ("pin", hostile_pin_kinds)):
            for kind in kinds:
                with self.subTest(authority=authority_kind, kind=kind), \
                        tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    output = root / "project" / "run-prod"
                    (output / "eth").mkdir(parents=True)
                    known_dir = output.parent / ".ssh-known-hosts"
                    pin = known_dir / self._expected_pin_name("prod", self.TARGET)
                    outside = root / "outside"
                    outside.write_text("outside-stays\n", encoding="utf-8")
                    if authority_kind == "directory":
                        if kind == "symlink":
                            known_dir.symlink_to(root, target_is_directory=True)
                        elif kind == "regular":
                            known_dir.write_text("not a directory\n", encoding="utf-8")
                        else:
                            known_dir.mkdir(mode=0o700)
                            if kind == "wrong-mode":
                                known_dir.chmod(0o755)
                    else:
                        known_dir.mkdir(mode=0o700)
                        if kind == "symlink":
                            pin.symlink_to(outside)
                        elif kind == "hardlink":
                            os.link(outside, pin)
                        elif kind == "directory":
                            pin.mkdir()
                        elif kind == "wrong-mode":
                            pin.write_text(f"{self.TARGET} ssh-ed25519 AAAA\n")
                            pin.chmod(0o644)
                        elif kind == "foreign-record":
                            pin.write_text("198.51.100.1 ssh-ed25519 AAAA\n")
                            pin.chmod(0o600)
                        elif kind == "unparsable-record":
                            pin.write_text("not-a-host-key-record\n")
                            pin.chmod(0o600)
                        elif kind == "invalid-base64":
                            pin.write_text(
                                f"{self.TARGET} ssh-ed25519 !!!\n",
                                encoding="utf-8",
                            )
                            pin.chmod(0o600)
                        elif kind == "unknown-algorithm":
                            pin.write_text(
                                f"{self.TARGET} ssh-unknown AAAA\n",
                                encoding="utf-8",
                            )
                            pin.chmod(0o600)
                        elif kind == "truncated-wire":
                            pin.write_text(
                                f"{self.TARGET} ssh-ed25519 AAAA\n",
                                encoding="utf-8",
                            )
                            pin.chmod(0o600)
                        elif kind == "mismatched-wire-algorithm":
                            pin.write_text(
                                f"{self.TARGET} ssh-ed25519 "
                                f"{mismatched_wire_blob}\n",
                                encoding="utf-8",
                            )
                            pin.chmod(0o600)
                        elif kind == "malformed-key-body":
                            pin.write_text(
                                f"{self.TARGET} ssh-ed25519 "
                                "AAAAC3NzaC1lZDI1NTE5AQ==\n",
                                encoding="utf-8",
                            )
                            pin.chmod(0o600)
                        else:
                            pin.write_text(f"{self.TARGET} ssh-ed25519 AAAA\n")
                            pin.chmod(0o600)
                    password_spawns = []

                    def fake_run(_user, _ip, _command, _timeout, options, **_kwargs):
                        combined = list(self.backup.SSH_OPTS) + list(options)
                        if self._option_values(combined, "BatchMode") == ["yes"]:
                            return subprocess.CompletedProcess([], 255, "", "key rejected")
                        password_spawns.append(True)
                        return subprocess.CompletedProcess([], 255, "", "must not spawn")

                    patches = [
                        mock.patch.object(self.backup, "_ENVIRONMENT", "prod"),
                        mock.patch.object(self.backup, "_run_ssh", side_effect=fake_run),
                    ]
                    if kind == "wrong-owner":
                        real_lstat = os.lstat

                        def hostile_lstat(path, *args, **kwargs):
                            result = real_lstat(path, *args, **kwargs)
                            candidate = Path(path)
                            target = known_dir if authority_kind == "directory" else pin
                            if candidate == target:
                                values = list(result)
                                values[4] = os.geteuid() + 1
                                return os.stat_result(values)
                            return result
                        patches.append(mock.patch.object(self.backup.os, "lstat", side_effect=hostile_lstat))
                    try:
                        with patches[0], patches[1]:
                            if len(patches) == 3:
                                with patches[2]:
                                    self.backup.collect_device(
                                        self._device(), str(output), self.SECRET, "", "",
                                    )
                            else:
                                self.backup.collect_device(
                                    self._device(), str(output), self.SECRET, "", "",
                                )
                    except (OSError, RuntimeError, TypeError, ValueError):
                        pass
                    self.assertEqual([], password_spawns)
                    self.assertEqual("outside-stays\n", outside.read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / "project" / "run-prod"
            (output / "eth").mkdir(parents=True)
            known_dir = output.parent / ".ssh-known-hosts"
            known_dir.mkdir(mode=0o700)
            pin = known_dir / self._expected_pin_name("prod", self.TARGET)
            pin.write_text(
                f"{self.TARGET} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER\n",
                encoding="utf-8",
            )
            pin.chmod(0o600)
            spawned = []

            def positive_run(_user, _ip, command, _timeout, options, **_kwargs):
                combined = list(self.backup.SSH_OPTS) + list(options)
                if self._option_values(combined, "BatchMode") == ["yes"]:
                    return subprocess.CompletedProcess([], 255, "", "key rejected")
                spawned.append(True)
                return subprocess.CompletedProcess([], 0, self._remote_result(command), "")

            with mock.patch.object(self.backup, "_ENVIRONMENT", "prod"), \
                    mock.patch.object(self.backup, "_run_ssh", side_effect=positive_run):
                _log, result = self.backup.collect_device(
                    self._device(), str(output), self.SECRET, "", "",
                )
            self.assertTrue(result and result["yaml_ok"])
            self.assertGreater(len(spawned), 1)

    def test_changed_key_fingerprints_derive_from_raw_records_not_stderr_claim(self):
        pinned_blob = "AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER"
        offered_blob = "AAAAC3NzaC1lZDI1NTE5AAAAICIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi"

        def fingerprint(blob):
            return "SHA256:" + base64.b64encode(
                hashlib.sha256(base64.b64decode(blob)).digest()
            ).decode("ascii").rstrip("=")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / "project" / "run-prod"
            (output / "eth").mkdir(parents=True)
            known_dir = output.parent / ".ssh-known-hosts"
            known_dir.mkdir(mode=0o700)
            pin = known_dir / self._expected_pin_name("prod", self.TARGET)
            pin.write_text(
                f"{self.TARGET} ssh-ed25519 {pinned_blob}\n", encoding="utf-8",
            )
            pin.chmod(0o600)
            password_envs = []

            def fake_run(_user, _ip, _command, _timeout, options, env=None, **_kwargs):
                combined = list(self.backup.SSH_OPTS) + list(options)
                if self._option_values(combined, "BatchMode") == ["yes"]:
                    return subprocess.CompletedProcess([], 255, "", "key rejected")
                password_envs.append(env)
                return subprocess.CompletedProcess(
                    [], 255, "",
                    "REMOTE HOST IDENTIFICATION HAS CHANGED!\n"
                    "offered_fingerprint=SHA256:ATTACKER-CONTROLLED\n",
                )

            scanner = getattr(self.backup, "_scan_offered_host_key", None)
            self.assertTrue(callable(scanner), "raw offered-key acquisition is absent")
            with mock.patch.object(
                self.backup, "_scan_offered_host_key",
                return_value=f"{self.TARGET} ssh-ed25519 {offered_blob}\n",
            ) as scan, mock.patch.object(
                self.backup, "_ENVIRONMENT", "prod",
            ), mock.patch.object(
                self.backup, "_run_ssh", side_effect=fake_run,
            ):
                log, result = self.backup.collect_device(
                    self._device(), str(output), self.SECRET, "", "",
                )
            combined = "\n".join(log) + repr(result)
            self.assertEqual(1, scan.call_count)
            self.assertIn("pinned_fingerprint=" + fingerprint(pinned_blob), combined)
            self.assertIn("offered_fingerprint=" + fingerprint(offered_blob), combined)
            self.assertNotIn("ATTACKER-CONTROLLED", combined)
            self.assertEqual(1, len(password_envs))
            self.assertFalse(any(
                self.SECRET in str(value) for value in password_envs[0].values()
            ))

    def test_changed_key_remedy_never_follows_post_read_pin_rebind(self):
        pinned_blob = "AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER"
        offered_blob = "AAAAC3NzaC1lZDI1NTE5AAAAICIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / "project" / "run-prod"
            (output / "eth").mkdir(parents=True)
            known_dir = output.parent / ".ssh-known-hosts"
            known_dir.mkdir(mode=0o700)
            pin = known_dir / self._expected_pin_name("prod", self.TARGET)
            pin.write_text(
                f"{self.TARGET} ssh-ed25519 {pinned_blob}\n", encoding="utf-8",
            )
            pin.chmod(0o600)
            held = pin.with_suffix(".held")
            outside = root / "outside-victim"
            outside.write_text("outside-stays\n", encoding="utf-8")

            def fake_run(_user, _ip, _command, _timeout, options, **_kwargs):
                combined = list(self.backup.SSH_OPTS) + list(options)
                if self._option_values(combined, "BatchMode") == ["yes"]:
                    return subprocess.CompletedProcess([], 255, "", "key rejected")
                return subprocess.CompletedProcess(
                    [], 255, "", "REMOTE HOST IDENTIFICATION HAS CHANGED!\n",
                )

            def rebind_then_scan(*_args, **_kwargs):
                pin.rename(held)
                pin.symlink_to(outside)
                return f"{self.TARGET} ssh-ed25519 {offered_blob}\n"

            combined = ""
            try:
                with mock.patch.object(
                    self.backup, "_scan_offered_host_key",
                    side_effect=rebind_then_scan,
                ), mock.patch.object(
                    self.backup, "_ENVIRONMENT", "prod",
                ), mock.patch.object(
                    self.backup, "_run_ssh", side_effect=fake_run,
                ):
                    log, result = self.backup.collect_device(
                        self._device(), str(output), self.SECRET, "", "",
                    )
                combined = "\n".join(log) + repr(result)
            except (OSError, RuntimeError, ValueError):
                pass
            self.assertNotIn("rm -- " + shlex.quote(str(outside)), combined)
            self.assertNotIn(str(outside), combined)
            self.assertEqual("outside-stays\n", outside.read_text(encoding="utf-8"))
            self.assertTrue(pin.is_symlink())
            pin.unlink()
            held.unlink()

    def test_authority_dirfd_blocks_first_use_parent_rebind_and_closes_fd(self):
        pinned_blob = "AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / "project" / "run-prod"
            (output / "eth").mkdir(parents=True)
            known_dir = output.parent / ".ssh-known-hosts"
            held_dir = root / "held-authority"
            outside_dir = root / "outside-authority"
            outside_dir.mkdir(mode=0o700)
            sentinel = outside_dir / "sentinel"
            sentinel.write_text("outside-stays\n", encoding="utf-8")
            password_events = []

            def fake_run(_user, _ip, _command, _timeout, options,
                         pass_fds=(), **_kwargs):
                combined = list(self.backup.SSH_OPTS) + list(options)
                if self._option_values(combined, "BatchMode") == ["yes"]:
                    return subprocess.CompletedProcess([], 255, "", "key rejected")
                known_value = self._option_values(
                    combined, "UserKnownHostsFile",
                )[0]
                password_events.append((combined, tuple(pass_fds)))
                if len(password_events) == 1:
                    known_dir.rename(held_dir)
                    known_dir.symlink_to(outside_dir, target_is_directory=True)
                    if known_value != "/dev/null":
                        path = Path(known_value)
                        path.write_text(
                            f"{self.TARGET} ssh-ed25519 {pinned_blob}\n",
                            encoding="utf-8",
                        )
                        path.chmod(0o600)
                return subprocess.CompletedProcess([], 0, "", "")

            raised = None
            result = None
            with mock.patch.object(
                self.backup, "_scan_offered_host_key",
                return_value=f"{self.TARGET} ssh-ed25519 {pinned_blob}",
            ) as scan, mock.patch.object(
                self.backup, "_run_ssh", side_effect=fake_run,
            ):
                try:
                    result = self.backup._ssh(
                        "cumulus", self.SECRET, self.TARGET, "true",
                        project_output=output.parent, scope="prod",
                    )
                except (OSError, RuntimeError, ValueError) as exc:
                    raised = exc
            self.assertEqual(1, scan.call_count)
            self.assertEqual(1, len(password_events))
            combined_options, inherited = password_events[0]
            self.assertEqual((), inherited)
            self.assertEqual(
                ["yes"],
                self._option_values(combined_options, "StrictHostKeyChecking"),
            )
            self.assertEqual(
                ["/dev/null"],
                self._option_values(combined_options, "UserKnownHostsFile"),
            )
            self.assertEqual(
                ["ssh-ed25519"],
                self._option_values(combined_options, "HostKeyAlgorithms"),
            )
            self.assertEqual(
                ["no"], self._option_values(combined_options, "CheckHostIP"),
            )
            self.assertEqual(
                ["no"], self._option_values(combined_options, "UpdateHostKeys"),
            )
            command = self._option_values(
                combined_options, "KnownHostsCommand",
            )
            self.assertEqual(1, len(command))
            self.assertTrue(command[0].startswith("/usr/bin/printf "))
            self.assertIn(pinned_blob, command[0])
            self.assertTrue(raised is not None or result[2] != 0)
            self.assertEqual("outside-stays\n", sentinel.read_text(encoding="utf-8"))
            self.assertEqual([sentinel], list(outside_dir.iterdir()))

    def test_changed_key_parent_rebind_fails_before_scan_or_remedy(self):
        pinned_blob = "AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER"
        offered_blob = "AAAAC3NzaC1lZDI1NTE5AAAAICIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / "project" / "run-prod"
            (output / "eth").mkdir(parents=True)
            known_dir = output.parent / ".ssh-known-hosts"
            known_dir.mkdir(mode=0o700)
            pin = known_dir / self._expected_pin_name("prod", self.TARGET)
            pin.write_text(
                f"{self.TARGET} ssh-ed25519 {pinned_blob}\n", encoding="utf-8",
            )
            pin.chmod(0o600)
            held_dir = root / "held-authority"
            inherited_fds = []

            def fake_run(_user, _ip, _command, _timeout, options,
                         pass_fds=(), **_kwargs):
                combined = list(self.backup.SSH_OPTS) + list(options)
                if self._option_values(combined, "BatchMode") == ["yes"]:
                    return subprocess.CompletedProcess([], 255, "", "key rejected")
                inherited_fds.extend(pass_fds)
                known_dir.rename(held_dir)
                known_dir.symlink_to(held_dir, target_is_directory=True)
                return subprocess.CompletedProcess(
                    [], 255, "", "REMOTE HOST IDENTIFICATION HAS CHANGED!",
                )

            combined = ""
            with mock.patch.object(
                self.backup, "_scan_offered_host_key",
                return_value=f"{self.TARGET} ssh-ed25519 {offered_blob}",
            ) as scan, mock.patch.object(
                self.backup, "_run_ssh", side_effect=fake_run,
            ):
                try:
                    _stdout, stderr, _returncode = self.backup._ssh(
                        "cumulus", self.SECRET, self.TARGET, "true",
                        project_output=output.parent, scope="prod",
                    )
                    combined = stderr
                except (OSError, RuntimeError, ValueError) as exc:
                    combined = str(exc)
            self.assertEqual(0, scan.call_count)
            self.assertNotIn("rm -- ", combined)
            self.assertEqual([], inherited_fds)

    def test_first_use_pin_openat_create_and_eexist_compare_fail_closed(self):
        persist = getattr(self.backup, "_persist_first_use_pin", None)
        self.assertTrue(callable(persist))
        pinned_blob = "AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER"
        other_blob = "AAAAC3NzaC1lZDI1NTE5AAAAICIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi"
        record = f"{self.TARGET} ssh-ed25519 {pinned_blob}"
        other = f"{self.TARGET} ssh-ed25519 {other_blob}"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            root.chmod(0o700)
            descriptor = os.open(
                root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            name = self._expected_pin_name("prod", self.TARGET)
            try:
                real_fsync = os.fsync
                synced = []

                def recording_fsync(fd):
                    synced.append((fd, os.fstat(fd)))
                    return real_fsync(fd)

                with mock.patch.object(
                    self.backup.os, "fsync", side_effect=recording_fsync,
                ):
                    persist(descriptor, name, record, self.TARGET)
                self.assertTrue(
                    any(fd == descriptor for fd, _metadata in synced),
                    "authority directory was not fsynced",
                )
                self.assertTrue(
                    any(
                        fd != descriptor and stat.S_ISREG(metadata.st_mode)
                        for fd, metadata in synced
                    ),
                    "created regular pin file was not fsynced",
                )
                pin = root / name
                metadata = pin.lstat()
                self.assertTrue(stat.S_ISREG(metadata.st_mode))
                self.assertEqual(0o600, stat.S_IMODE(metadata.st_mode))
                self.assertEqual(1, metadata.st_nlink)
                self.assertEqual(record + "\n", pin.read_text(encoding="utf-8"))
                persist(descriptor, name, record, self.TARGET)
                with self.assertRaises((RuntimeError, ValueError)):
                    persist(descriptor, name, other, self.TARGET)
                self.assertEqual(record + "\n", pin.read_text(encoding="utf-8"))
                for hostile in ("symlink", "hardlink"):
                    hostile_root = root / (hostile + "-authority")
                    hostile_root.mkdir(mode=0o700)
                    hostile_fd = os.open(
                        hostile_root,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
                        | os.O_NOFOLLOW,
                    )
                    outside = root / (hostile + "-outside-sentinel")
                    outside.write_text("outside-stays\n", encoding="utf-8")
                    hostile_path = hostile_root / name
                    try:
                        if hostile == "symlink":
                            hostile_path.symlink_to(outside)
                        else:
                            os.link(outside, hostile_path)
                        with self.subTest(hostile=hostile), self.assertRaises(
                            (RuntimeError, ValueError),
                        ):
                            persist(hostile_fd, name, record, self.TARGET)
                        self.assertEqual(
                            "outside-stays\n", outside.read_text(encoding="utf-8"),
                        )
                    finally:
                        os.close(hostile_fd)
                        hostile_path.unlink()
            finally:
                os.close(descriptor)

    def test_host_key_scan_is_bounded_target_checked_and_secret_sanitized(self):
        offered_blob = "AAAAC3NzaC1lZDI1NTE5AAAAICIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi"
        mismatched_wire_blob = base64.b64encode(
            b"\x00\x00\x00\x07ssh-rsa\x01",
        ).decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fake_bin = root / "bin"
            fake_bin.mkdir()
            record = root / "scan.jsonl"
            leader_file = root / "scan-leader.pid"
            child_file = root / "scan-child.pid"
            fake_scan = fake_bin / "ssh-keyscan"
            fake_scan.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, subprocess, sys\n"
                f"secret = {self.SECRET!r}\n"
                f"target = {self.TARGET!r}\n"
                f"blob = {offered_blob!r}\n"
                f"mismatched = {mismatched_wire_blob!r}\n"
                "mode = os.environ.get('SCAN_MODE', 'valid')\n"
                "event = {'argv': sys.argv[1:], 'secret_env_keys': "
                "sorted(k for k, v in os.environ.items() if secret in v)}\n"
                "with open(os.environ['SCAN_RECORD'], 'a') as stream:\n"
                " stream.write(json.dumps(event) + '\\n')\n"
                "if mode == 'wrong': print('198.51.100.9 ssh-ed25519 ' + blob)\n"
                "elif mode == 'malformed': print(target + ' ssh-ed25519 !!!')\n"
                "elif mode == 'truncated': print(target + ' ssh-ed25519 AAAA')\n"
                "elif mode == 'mismatched-wire': "
                "print(target + ' ssh-ed25519 ' + mismatched)\n"
                "elif mode == 'malformed-body': "
                "print(target + ' ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AQ==')\n"
                "elif mode == 'mixed':\n"
                " print(target + ' ssh-rsa AAAA')\n"
                " print(target + ' ssh-ed25519 ' + blob)\n"
                "elif mode == 'no-match': print(target + ' ssh-rsa AAAA')\n"
                "elif mode == 'conflict':\n"
                " print(target + ' ssh-ed25519 ' + blob)\n"
                " print(target + ' ssh-ed25519 "
                "AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER')\n"
                "elif mode == 'flood':\n"
                " open(os.environ['SCAN_LEADER'], 'w').write(str(os.getpid()))\n"
                " child = subprocess.Popen([sys.executable, '-c', "
                "'import time; time.sleep(20)'])\n"
                " open(os.environ['SCAN_CHILD'], 'w').write(str(child.pid))\n"
                " chunk = b'K' * 8192\n"
                " while True: os.write(1, chunk)\n"
                "else: print(target + ' ssh-ed25519 ' + blob)\n",
                encoding="utf-8",
            )
            fake_scan.chmod(0o755)
            environment = dict(os.environ)
            environment.update({
                "PATH": str(fake_bin) + os.pathsep + environment.get("PATH", ""),
                "SCAN_RECORD": str(record),
                "SCAN_LEADER": str(leader_file),
                "SCAN_CHILD": str(child_file),
                "WRAPPED_SECRET": "prefix-" + self.SECRET + "-suffix",
                "ZTP_BACKUP_PASSWORD": self.SECRET,
            })
            with mock.patch.dict(os.environ, environment, clear=True):
                raw = self.backup._scan_offered_host_key(
                    self.TARGET, 5, self.SECRET,
                )
            self.assertEqual(f"{self.TARGET} ssh-ed25519 {offered_blob}", raw)
            first = json.loads(record.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual([], first["secret_env_keys"])
            self.assertEqual(
                ["-T", "5", "-t", "ed25519,ecdsa,rsa", self.TARGET],
                first["argv"],
            )

            for mode in (
                "wrong", "malformed", "truncated", "mismatched-wire",
                "malformed-body",
            ):
                environment["SCAN_MODE"] = mode
                with self.subTest(mode=mode), mock.patch.dict(
                    os.environ, environment, clear=True,
                ), self.assertRaises((RuntimeError, ValueError)):
                    self.backup._scan_offered_host_key(
                        self.TARGET, 5, self.SECRET,
                    )

            environment["SCAN_MODE"] = "mixed"
            with mock.patch.dict(os.environ, environment, clear=True):
                matching = self.backup._scan_offered_host_key(
                    self.TARGET, 5, self.SECRET,
                    key_type="ssh-ed25519",
                )
            self.assertEqual(
                f"{self.TARGET} ssh-ed25519 {offered_blob}", matching,
            )
            latest = json.loads(record.read_text(encoding="utf-8").splitlines()[-1])
            self.assertEqual(
                ["-T", "5", "-t", "ed25519", self.TARGET], latest["argv"],
            )
            for mode in ("no-match", "conflict"):
                environment["SCAN_MODE"] = mode
                with self.subTest(mode=mode), mock.patch.dict(
                    os.environ, environment, clear=True,
                ), self.assertRaises((RuntimeError, ValueError)):
                    self.backup._scan_offered_host_key(
                        self.TARGET, 5, self.SECRET,
                        key_type="ssh-ed25519",
                    )

            environment["SCAN_MODE"] = "flood"
            started = time.monotonic()
            with mock.patch.dict(os.environ, environment, clear=True), \
                    self.assertRaises((RuntimeError, ValueError)):
                self.backup._scan_offered_host_key(
                    self.TARGET, 5, self.SECRET,
                )
            self.assertLess(time.monotonic() - started, 1.5)
            for pid_file in (leader_file, child_file):
                self.assertTrue(pid_file.is_file())
                pid = int(pid_file.read_text(encoding="utf-8"))
                deadline = time.monotonic() + 0.5
                while time.monotonic() < deadline:
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.02)
                else:
                    self.fail(f"ssh-keyscan process survived flood stop: {pid}")

    def test_fifo_creation_does_not_depend_on_path_chmod_nofollow_support(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            exec_root = root / "exec"
            exec_root.mkdir(mode=0o700)
            output = root / "project" / "run-prod"
            (output / "eth").mkdir(parents=True)
            real_chmod = self.backup.os.chmod

            def portable_chmod(path, mode, *args, **kwargs):
                if kwargs.get("follow_symlinks") is False:
                    raise NotImplementedError("nofollow chmod unsupported")
                return real_chmod(path, mode, *args, **kwargs)

            def fake_run(_user, ip, command, _timeout, options, **_kwargs):
                combined = list(self.backup.SSH_OPTS) + list(options)
                if self._option_values(combined, "BatchMode") == ["yes"]:
                    return subprocess.CompletedProcess([], 255, "", "key rejected")
                known = self._option_values(combined, "UserKnownHostsFile")
                if known and not Path(known[0]).exists():
                    Path(known[0]).write_text(
                        f"{ip} ssh-ed25519 "
                        "AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER\n",
                        encoding="utf-8",
                    )
                    Path(known[0]).chmod(0o600)
                return subprocess.CompletedProcess([], 0, self._remote_result(command), "")

            environment = {
                "HTTP_ZTP_RUNTIME_BACKEND": "supervisor",
                "HTTP_ZTP_ASKPASS_TMPDIR": str(exec_root),
            }
            scan_record = (
                f"{self.TARGET} ssh-ed25519 "
                "AAAAC3NzaC1lZDI1NTE5AAAAIBERERERERERERERERERERERERERERERERERERERERER"
            )
            with mock.patch.dict(os.environ, environment, clear=False), \
                    mock.patch.object(self.backup.os, "chmod", side_effect=portable_chmod), \
                    mock.patch.object(
                        self.backup, "_scan_offered_host_key",
                        return_value=scan_record,
                    ) as scan, \
                    mock.patch.object(self.backup, "_run_ssh", side_effect=fake_run):
                _log, result = self.backup.collect_device(
                    self._device(), str(output), self.SECRET, "", "",
                )
            self.assertTrue(result and result["yaml_ok"])
            self.assertEqual(1, scan.call_count)


if __name__ == "__main__":
    unittest.main()
