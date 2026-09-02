#!/usr/bin/env python3
"""Safety and behavior tests for the read-only ZTP diagnostic collector."""

from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


COLLECTOR = load_module(
    "ztp_diagnostic_collector", ROOT / "tools/collect-ztp-diagnostics.py"
)
CONTRACT = load_module("diagnostic_project_contract", ROOT / "tools/project_contract.py")


class DiagnosticBundleTests(unittest.TestCase):
    def test_remote_probe_prefers_strict_latest_pointer_then_legacy_fallback(self):
        pointer = 'log_pointer="$log_dir/latest-log"'
        persistent = "/var/lib/nvidia-ztp/logs/ztp-result.log_*"
        legacy = '"$HOME"/ztp-result.log_*'
        self.assertIn(pointer, COLLECTOR.REMOTE_PROBE)
        self.assertIn(persistent, COLLECTOR.REMOTE_PROBE)
        self.assertIn(legacy, COLLECTOR.REMOTE_PROBE)
        self.assertLess(
            COLLECTOR.REMOTE_PROBE.index(pointer),
            COLLECTOR.REMOTE_PROBE.index(persistent),
        )
        self.assertLess(
            COLLECTOR.REMOTE_PROBE.index(persistent),
            COLLECTOR.REMOTE_PROBE.index(legacy),
        )
        self.assertIn('[ "$pointer_seen" = false ]', COLLECTOR.REMOTE_PROBE)
        self.assertIn("latest_log_pointer_error=", COLLECTOR.REMOTE_PROBE)

    def test_structured_redaction_removes_secrets_but_keeps_bgp_community(self):
        sentinel = "SENTINEL-diagnostic-secret"
        source = f"""
set:
  system:
    aaa:
      password: {sentinel}
      hashed-password: $6$salt$hashvalue
  snmp-server:
    community:
      public-secret:
        access: any
  router:
    bgp:
      community: 65000:123
  callback: https://user:{sentinel}@example.test/path?token={sentinel}
  pem: |
    -----BEGIN PRIVATE KEY-----
    {sentinel}
    -----END PRIVATE KEY-----
""".encode()
        redacted, error = COLLECTOR.structured_redaction(
            source, ".yaml", require_container=True
        )
        self.assertEqual("", error)
        self.assertIsNotNone(redacted)
        text = redacted.decode()
        self.assertNotIn(sentinel, text)
        self.assertNotIn("$6$salt$hashvalue", text)
        self.assertNotIn("BEGIN PRIVATE KEY", text)
        self.assertNotIn("public-secret", text)
        self.assertIn("65000:123", text)
        self.assertIn("<redacted", text)

        nested = {
            "diff_excerpt": (
                '{"password":"' + sentinel + '",'
                '"Authorization":"Bearer ' + sentinel + '",'
                '"ssh":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI' + sentinel + '",'
                '"snmp":"snmp-server community ' + sentinel + '"}'
            )
        }
        redacted_json, error = COLLECTOR.structured_redaction(
            json.dumps(nested).encode(), ".json", require_container=True
        )
        self.assertEqual("", error)
        json.loads(redacted_json)
        self.assertNotIn(sentinel, redacted_json.decode())

    def test_unparseable_sensitive_config_is_omitted_fail_closed(self):
        sentinel = b"SENTINEL-malformed-password"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "broken.yaml"
            source.write_bytes(b"password: [" + sentinel + b"\n")
            staging = root / "staging"
            builder = COLLECTOR.BundleBuilder(staging, "artifact")
            COLLECTOR.capture_file(
                builder,
                source,
                "project/broken.yaml",
                allowed_roots=[root],
                structured=True,
            )
            self.assertFalse((staging / "project/broken.yaml").exists())
            omitted = staging / "project/broken.yaml.omitted.json"
            self.assertTrue(omitted.is_file())
            self.assertNotIn(sentinel, omitted.read_bytes())
            value = json.loads(omitted.read_text())
            self.assertEqual("omitted", value["status"])
            self.assertIn("unparseable", value["reason"])
            self.assertEqual(len(source.read_bytes()), value["source_size"])

    def test_output_root_and_member_paths_fail_closed(self):
        for value in ("../escape", "/absolute", "a/../../b", "a/./b"):
            with self.subTest(value=value):
                with self.assertRaises(COLLECTOR.DiagnosticError):
                    COLLECTOR.safe_relative(value)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            document_root = base / "www"
            document_root.mkdir(mode=0o700)
            inside = document_root / "diagnostics"
            with mock.patch.object(COLLECTOR, "HTTP_ROOT", document_root):
                with self.assertRaises(COLLECTOR.DiagnosticError):
                    COLLECTOR.prepare_output_root(str(inside))
            target = base / "real-output"
            target.mkdir(mode=0o700)
            link = base / "output-link"
            link.symlink_to(target)
            with mock.patch.object(COLLECTOR, "HTTP_ROOT", document_root):
                with self.assertRaises(COLLECTOR.DiagnosticError):
                    COLLECTOR.prepare_output_root(str(link))

    def test_bounded_command_sanitizes_environment_and_caps_output(self):
        secret_name = "ZTP_DIAGNOSTIC_ENV_SENTINEL"
        with mock.patch.dict(os.environ, {secret_name: "must-not-leak"}):
            result = COLLECTOR.run_bounded_command(["env"], timeout=5)
        self.assertEqual(0, result["returncode"])
        self.assertNotIn(secret_name, result["output"])

        result = COLLECTOR.run_bounded_command(
            [sys.executable, "-c", "import sys; sys.stdout.write('x'*100000)"],
            timeout=5,
            max_bytes=1024,
        )
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["output"].encode()), 1024)

    def test_archive_has_one_safe_tree_and_regular_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging = root / "staging"
            builder = COLLECTOR.BundleBuilder(staging, "artifact")
            builder.write("server/state.txt", b"ok\n", source="test")
            builder.finalize({"project": "project", "scope": "air"})
            destination = root / "bundle.tar.gz"
            COLLECTOR.create_archive(staging, destination, "artifact")
            self.assertEqual(0o600, stat.S_IMODE(destination.stat().st_mode))
            with tarfile.open(destination, "r:gz") as archive:
                names = archive.getnames()
                self.assertTrue(names)
                self.assertTrue(all(name == "artifact" or name.startswith("artifact/") for name in names))
                self.assertTrue(all(member.isdir() or member.isfile() for member in archive.getmembers()))
                self.assertFalse(any(".." in Path(name).parts for name in names))

    def test_runtime_project_resolution_uses_fixed_inventory_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            day0 = root / "DAY0-Prepare"
            active = day0 / "active-project"
            runtime = root / "ztp/config/isc-dhcp-server"
            active.mkdir(parents=True)
            runtime.mkdir(parents=True)
            inventory = active / "02-devices_config.csv"
            inventory.write_text("hostname,type\nleaf01,eth\n")
            (runtime / "02-devices_config.csv").symlink_to(inventory)
            with mock.patch.multiple(COLLECTOR, ROOT=root, DAY0_ROOT=day0):
                self.assertEqual(active, COLLECTOR.runtime_active_project())
                (runtime / "02-devices_config.csv").unlink()
                outside = root / "outside.csv"
                outside.write_text("x")
                (runtime / "02-devices_config.csv").symlink_to(outside)
                self.assertIsNone(COLLECTOR.runtime_active_project())

    def test_remote_identity_mismatch_never_collects_device_config(self):
        output = """__IDENTITY_BEGIN__
wrong-host
aa:bb:cc:dd:ee:ff

__IDENTITY_END__
__STATE_BEGIN__
password: SENTINEL
__STATE_END__
__ZTP_LOG_BEGIN__
success
__ZTP_LOG_END__
__APPLIED_BEGIN__
__APPLIED_END__
__NV_CONFIG_BEGIN__
set: []
__NV_CONFIG_END__
"""
        result = {
            "argv": ["ssh"], "returncode": 0, "duration_ms": 1,
            "timed_out": False, "truncated": False, "output": output,
        }
        device = {
            "hostname": "leaf01", "type": "eth", "ip": "192.0.2.10",
            "identity_macs": {"eth0": "02:00:00:00:00:55"},
        }
        with tempfile.TemporaryDirectory() as directory:
            staging = Path(directory) / "staging"
            builder = COLLECTOR.BundleBuilder(staging, "artifact")
            with mock.patch.object(COLLECTOR, "run_bounded_command", return_value=result):
                COLLECTOR.collect_live_device(
                    builder, device, identity=None,
                    known_hosts=Path(directory) / "known_hosts",
                )
            device_root = staging / "devices/leaf01"
            self.assertTrue((device_root / "connection-attempts.json").is_file())
            self.assertFalse((device_root / "state.txt").exists())
            self.assertFalse((device_root / "nv-config-show.yaml").exists())
            self.assertTrue(any("identity gates" in warning for warning in builder.warnings))

    def test_live_collection_skips_non_active_project_but_keeps_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            day0 = root / "DAY0-Prepare"
            requested = day0 / "requested"
            active = day0 / "active"
            requested.mkdir(parents=True)
            active.mkdir()
            output = root / "output"
            output.mkdir(mode=0o700)
            document_root = root / "www"
            document_root.mkdir(mode=0o700)
            report = {
                "devices": [{
                    "hostname": "leaf01", "type": "air", "ip": "192.0.2.10",
                    "identity_macs": {"eth0": "02:00:00:00:00:55"},
                }]
            }
            selected = report["devices"]
            no_op = mock.Mock()
            with (
                mock.patch.multiple(
                    COLLECTOR,
                    ROOT=root,
                    DAY0_ROOT=day0,
                    HTTP_ROOT=document_root,
                    DEFAULT_OUTPUT_ROOT=output,
                ),
                mock.patch.object(COLLECTOR, "load_latest_report", return_value=(None, report)),
                mock.patch.object(COLLECTOR, "runtime_active_project", return_value=active),
                mock.patch.object(COLLECTOR, "select_devices", return_value=selected),
                mock.patch.object(COLLECTOR, "collect_project_inputs", no_op),
                mock.patch.object(COLLECTOR, "collect_runtime_files", no_op),
                mock.patch.object(COLLECTOR, "collect_selected_published_configs", no_op),
                mock.patch.object(COLLECTOR, "collect_selected_operation_metadata", no_op),
                mock.patch.object(COLLECTOR, "collect_server_commands", no_op),
                mock.patch.object(COLLECTOR, "collect_public_key_fingerprints", no_op),
                mock.patch.object(COLLECTOR, "collect_monitor_state", no_op),
                mock.patch.object(COLLECTOR, "collect_switch_archives", no_op),
                mock.patch.object(COLLECTOR, "validate_ssh_inputs") as validate_ssh,
            ):
                rc = COLLECTOR.main([
                    "-p", "requested", "--air", "--host", "leaf01",
                    "--output-dir", str(output),
                ])
            self.assertEqual(2, rc)
            validate_ssh.assert_not_called()
            archives = list(output.glob("*.tar.gz"))
            self.assertEqual(1, len(archives))
            with tarfile.open(archives[0], "r:gz") as archive:
                name = next(name for name in archive.getnames() if name.endswith("/manifest.json"))
                manifest = json.load(archive.extractfile(name))
            self.assertTrue(manifest["partial"])
            self.assertTrue(any("active runtime project" in item for item in manifest["warnings"]))

    def test_collector_is_part_of_tools_deployment_contract(self):
        self.assertTrue(CONTRACT.is_tools_deployable_file(
            "tools/collect-ztp-diagnostics.py"
        ))

    def test_help_uses_a_neutral_public_project_example(self):
        parser = COLLECTOR.parse_args
        with mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
            with self.assertRaises(SystemExit) as raised:
                parser(["--help"])
        self.assertEqual(0, raised.exception.code)
        help_text = stdout.getvalue()
        self.assertIn("2099-example-site", help_text)
        self.assertNotIn("2026-" + "06-vb", help_text)


if __name__ == "__main__":
    unittest.main()
