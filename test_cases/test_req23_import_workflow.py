"""REQ23: real LOAD children publish frozen imported bytes as a new parent."""

from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.module_loader import load_script
from test_cases.test_generation_input_binding_workflow import (
    _private_real_chain, _publish_private_dhcp_outputs,
)
from test_cases.test_ssh_key_preparation_contract import public_line


ROOT = Path(__file__).resolve().parents[1]
LOAD = load_script("req23_import_workflow_load", ROOT / "DAY0-Prepare/11-load.py")
ACTIVATE = load_script("req23_import_workflow_activate", ROOT / "infra/docker/activate.py")
PUBLISHER = load_script(
    "req23_import_workflow_publisher", ROOT / "ztp/config/cumulus/d-hostname2mac.py",
)
MONITOR = load_script("req23_import_workflow_monitor", ROOT / "DAY0-Prepare/12-ztp-monitor.py")


class ImportedConfigurationWorkflow(unittest.TestCase):
    def test_real_children_import_publish_parent_and_activate_without_rewriting_source(self):
        private_parent = os.environ.get("R22_TEST_PRIVATE_ROOT")
        with tempfile.TemporaryDirectory(prefix="req23-import-", dir=private_parent) as name:
            private = Path(name).resolve()
            project, ztp = _private_real_chain(private, "192.0.2.53", http_enabled=True)
            for family in ("ib", "nvl"):
                (ztp / "config/isc-dhcp-server" / f"dhcpd_{family}.hosts").write_text(
                    "# no selected hosts for this family\n", encoding="utf-8",
                )
            args = SimpleNamespace(
                switch_scope="eth", deployment_scope="prod", p2p_file=None,
                no_upgrade=True, mini=None, ssh_dir=None, dry_run=True,
            )
            validated, _ = LOAD.validate_inputs(
                project, args, allow_management_key_generation=False,
                host_role="workstation",
            )
            original = LOAD._run_subprocess
            children: list[str] = []

            def run_real_child(command, **kwargs):
                script = command[1] if len(command) > 1 else command[0]
                if kwargs.get("cwd") is not None:
                    self.assertTrue(Path(kwargs["cwd"]).resolve().is_relative_to(private))
                    children.append(script)
                    kwargs = {**kwargs, "stdout": subprocess.PIPE,
                              "stderr": subprocess.STDOUT, "text": True}
                result = original(command, timeout=120, **kwargs)
                if result.returncode:
                    self.fail(f"real child {script} exited {result.returncode}: {result.stdout!r}")
                return result

            with mock.patch.object(LOAD, "ZTP_DIR", ztp), \
                    mock.patch.object(LOAD, "_run_subprocess", side_effect=run_real_child), \
                    redirect_stdout(io.StringIO()):
                LOAD.generate_configs(
                    validated.device_types, install_dhcp=False, dry_run=False,
                    dhcp_enabled=True, schema_version=validated.settings.schema_version,
                    deployment_scope="prod", switch_scope="eth",
                    source_identities=validated.source_identities,
                )
                _publish_private_dhcp_outputs(project, ztp)
                old = LOAD.validate_and_publish_release(project, validated)
                self.assertNotIn("imported_configs", old)

                source = project / "import-configs" / "20261003_101112"
                source.mkdir(parents=True)
                current = (ztp / "config/cumulus/latest_yaml").resolve(strict=True)
                devices = PUBLISHER.load_csv(
                    str(project / "02-devices_config.csv"), switch_scope="eth",
                )
                authoritative = {}
                for device in devices.values():
                    if device["dev_type"] not in {"eth", "eth_spx", "spx"}:
                        continue
                    filename = f"{device['hostname']}.yaml"
                    data = (current / filename).read_bytes() + b"\n# imported fixture\n"
                    (source / filename).write_bytes(data)
                    authoritative[filename] = hashlib.sha256(data).hexdigest()
                self.assertTrue(authoritative)
                source_before = {
                    entry.name: hashlib.sha256(entry.read_bytes()).hexdigest()
                    for entry in source.iterdir()
                }
                with LOAD.select_import_config_set(project, "") as selected:
                    snapshot = LOAD.preflight_import_configs(
                        selected, project / "02-devices_config.csv",
                    )
                    children.clear()
                    LOAD.generate_configs(
                        validated.device_types, install_dhcp=False, dry_run=False,
                        dhcp_enabled=True, schema_version=validated.settings.schema_version,
                        deployment_scope="prod", switch_scope="eth",
                        source_identities=validated.source_identities,
                        imported_configs=snapshot, import_selection=selected,
                        import_devices_file=project / "02-devices_config.csv",
                        import_output_timestamp="20261003_111213",
                    )
                    LOAD.assert_import_source_unchanged(
                        selected, snapshot, project / "02-devices_config.csv",
                    )
                    self.assertNotIn("90-c2-generate_configs.py", children)
                    self.assertIn("d-hostname2mac.py", children)
                    new = LOAD.validate_and_publish_release(
                        project, validated, imported_configs=snapshot,
                    )
                self.assertNotEqual(old["release_id"], new["release_id"])
                self.assertEqual(new["imported_configs"], {
                    "source_name": "20261003_101112", "sha256": snapshot.digest,
                })
                release = (ztp / "config/cumulus/latest_yaml").resolve(strict=True)
                self.assertEqual(release.name, "20261003_111213_combine")
                for filename, sha in authoritative.items():
                    self.assertEqual(hashlib.sha256((release / filename).read_bytes()).hexdigest(), sha)
                self.assertEqual(source_before, {
                    entry.name: hashlib.sha256(entry.read_bytes()).hexdigest()
                    for entry in source.iterdir()
                })
                parent_path = project / "99-output-ztp/current-release.json"
                settings = ACTIVATE.Settings(
                    http_root=private, project_name=project.name,
                    scope="prod", switch_scope="eth",
                )
                identity = ACTIVATE.validate_parent_release(settings, parent_path)
                self.assertEqual(identity["parent_release_sha256"],
                                 hashlib.sha256(parent_path.read_bytes()).hexdigest())
                monitor_identity = MONITOR.load_release_identity(project)
                self.assertEqual(monitor_identity["release_id"], new["release_id"])
                publickey = ztp / "config/publickey"
                publickey.mkdir(parents=True)
                for filename, seed in (("laptop.pub", 31), ("mgmt-server.pub", 47)):
                    leaf = project / filename
                    leaf.write_bytes(public_line("ssh-ed25519", seed, filename))
                    (publickey / filename).symlink_to(leaf)
                report = LOAD.generation_report.build_report(
                    project, new, published_dir=publickey,
                )
                self.assertEqual(report["release_id"], new["release_id"])


if __name__ == "__main__":
    unittest.main()
