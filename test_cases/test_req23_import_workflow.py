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
        self._real_children_import_transaction()

    def test_real_children_rebound_alias_target_refuses_parent_and_restores_dhcp(self):
        self._real_children_import_transaction(source_mutation="alias-target")

    def test_real_children_late_unknown_member_refuses_parent_and_restores_dhcp(self):
        self._real_children_import_transaction(source_mutation="unknown-member")

    def _real_children_import_transaction(self, *, source_mutation=None):
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

                import_root = project / "import-configs"
                if source_mutation == "alias-target":
                    import_root.mkdir()
                    import_root.rename(project / "operator-source")
                    import_root.symlink_to(project / "operator-source", target_is_directory=True)
                source = import_root / "20261003_101112"
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

                # The real setup/generator/publisher chain above has produced B.
                # Model the final DHCP transaction in a private directory: a
                # newer operator set arriving after installation must prevent
                # the parent commit and restore every previously live file.
                source_dir = ztp / "config/isc-dhcp-server"
                live_dir = private / "etc-dhcp"
                live_dir.mkdir()
                names = (
                    "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
                    "dhcpd_nvl.hosts",
                )
                mappings = {source_dir / name: live_dir / name for name in names}
                for destination in mappings.values():
                    destination.write_text(
                        f"old:{destination.name}\n", encoding="utf-8",
                    )
                parent_before = parent_path.read_bytes()
                candidate = LOAD.prepare_current_release(project, new)
                newer = project / "import-configs" / "20261004_000000"
                syntax_checks = []
                final_check_armed = False
                publisher = LOAD._import_publisher_module()
                original_parser = publisher._strict_yaml_load

                def mutate_during_final_source_parse(stream):
                    nonlocal final_check_armed
                    document = original_parser(stream)
                    if final_check_armed and source_mutation == "unknown-member":
                        final_check_armed = False
                        (source / "unknown.yaml").write_bytes(b"# foreign late member\n")
                    return document

                def fake_dhcp_run(command, **_kwargs):
                    nonlocal final_check_armed
                    operation = command[0]
                    if operation == "install":
                        if "-d" in command:
                            mode = int(command[command.index("-m") + 1], 8)
                            for item in command[command.index("--") + 1:]:
                                Path(item).mkdir(parents=True, exist_ok=True)
                                Path(item).chmod(mode)
                        else:
                            shutil.copy2(command[-2], command[-1])
                    elif operation == "cp":
                        shutil.copy2(command[-2], command[-1])
                    elif operation == "dhcpd":
                        syntax_checks.append(command[-1])
                        if command[-1] == "/etc/dhcp/dhcpd.conf":
                            if source_mutation == "alias-target":
                                (project / "operator-source").rename(project / "held-original-source")
                                (project / "operator-source").mkdir()
                            elif source_mutation == "unknown-member":
                                final_check_armed = True
                            else:
                                newer.mkdir()
                    else:
                        self.fail(f"unexpected DHCP command: {command!r}")

                try:
                    with LOAD.select_import_config_set(project, "") as selected:
                        snapshot = LOAD.preflight_import_configs(
                            selected, project / "02-devices_config.csv",
                        )
                        candidate.precommit_check = lambda: LOAD.assert_import_source_unchanged(
                            selected, snapshot, project / "02-devices_config.csv",
                        )
                        with mock.patch.object(
                            LOAD, "dhcp_file_mappings", return_value=mappings,
                        ), mock.patch.object(
                            LOAD, "sudo_command", side_effect=lambda *args: list(args),
                        ), mock.patch.object(
                            LOAD, "run", side_effect=fake_dhcp_run,
                        ), mock.patch.object(
                            publisher, "_strict_yaml_load", side_effect=mutate_during_final_source_parse,
                        ):
                            expected = ("重新运行 load" if source_mutation is None
                                        else "import-configs.*root" if source_mutation == "alias-target"
                                        else "import-configs.*inventory")
                            with self.assertRaisesRegex(LOAD.LoadError, expected):
                                LOAD.mount_and_test_dhcp(parent_candidate=candidate)
                    self.assertEqual(2, len(syntax_checks))
                    self.assertFalse(candidate.committed)
                    self.assertEqual(parent_before, parent_path.read_bytes())
                    for destination in mappings.values():
                        self.assertEqual(
                            f"old:{destination.name}\n",
                            destination.read_text(encoding="utf-8"),
                        )
                    if source_mutation == "alias-target":
                        self.assertTrue(import_root.is_symlink())
                        self.assertEqual([], list((project / "operator-source").iterdir()))
                        held_source = project / "held-original-source" / source.name
                        self.assertEqual(source_before, {
                            entry.name: hashlib.sha256(entry.read_bytes()).hexdigest()
                            for entry in held_source.iterdir()
                        })
                    elif source_mutation == "unknown-member":
                        self.assertEqual(b"# foreign late member\n", (source / "unknown.yaml").read_bytes())
                finally:
                    LOAD.discard_prepared_release(candidate)


if __name__ == "__main__":
    unittest.main()
