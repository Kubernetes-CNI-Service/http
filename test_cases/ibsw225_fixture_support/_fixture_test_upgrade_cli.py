"""Desktop bundle regression: temporary inputs, no real SSH or upgrades."""
import base64
import contextlib
import csv
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import shutil
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
from test_cases.ibsw225_fixture_support.runtime_source_support import support
_runtime = support(unittest.TestCase())
app = _runtime.app
driver = _runtime.driver
observer = _runtime.observer
component = _runtime.component
executor = _runtime.executor

HEADER = "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,eth1_mac,lo_ip,bgp_asn,bgp_ports,bond_ports,bond_type,bond_mac,peerlink_ports,vrl".split(",")
GLOBAL = """schema_version: 2
common:
  mgmt:
    http:
      status: enabled
      address: 192.0.2.254
      port: 8088
      http_root: /var/www/html
switches:
- ib:
    version: '25.03.1010'
    upgrade:
      packages:
        os:
          files:
          - file: nvos-amd64-25.02.8008.bin
          - file: nvos-amd64-25.03.1010.bin
"""
OS_TABLE = b"             operational\n-----------  ----------------\nkernel       6.1\nbuild-date   2026-01-01\nimage        nvos-25.03.1010\nonie         2025.01\n"
HEALTH_TABLE = (ROOT/'test_cases/fixtures/nvos-system-health.txt').read_bytes()


class CliTests(unittest.TestCase):
    def parse(self, *args):
        with patch.object(Path, "home", return_value=Path("/synthetic/home")):
            return app._parse_cli(args)

    def test_no_arguments_defaults_to_readonly_admin_and_current_user_known_hosts(self):
        args = self.parse()
        self.assertTrue(args.inspect_only)
        self.assertFalse(args.upgrade)
        self.assertEqual(args.user, "admin")
        self.assertEqual(args.known_hosts, "/synthetic/home/.ssh/known_hosts")

    def test_dry_run_is_readonly_not_forwarded_as_execution_argument(self):
        args = self.parse("--dry-run", "--devices", "ew-spine01*")
        self.assertTrue(args.inspect_only)
        self.assertFalse(args.upgrade)
        self.assertEqual(args.prepare_args, ("--devices", "ew-spine01*"))

    def test_user_reported_inspection_commands_pass_syntax_without_explicit_hostfile(self):
        for args in (("--devices", "ew-spine01"),
                     ("--devices", "ew-spine01", "--inspect-only"),
                     ("--devices", "ew-spine01", "--inspect-only", "--user", "admin", "--password"),
                     ("--devices", "ew-spine01", "--inspect-only", "--user", "admin", "--password", "--method", "http")):
            with self.subTest(args=args):
                self.assertTrue(self.parse(*args).inspect_only)

    def test_modes_cannot_silently_promote_dry_run_to_upgrade(self):
        for args in (("--dry-run", "--upgrade", "--yes"), ("--inspect-only", "--upgrade", "--yes"),
                     ("--dry-run", "--scripts-only"), ("--upgrade",), ("--verify-only","--upgrade","--yes")):
            with self.subTest(args=args), self.assertRaises(app._InspectionHold):
                self.parse(*args)

    def test_explicit_key_roles_still_must_be_paired_and_absolute(self):
        for args in (("--identity", "/tmp/key"), ("--identity", "relative", "--management-public-key", "/tmp/key.pub")):
            with self.subTest(args=args), self.assertRaises(app._InspectionHold):
                self.parse(*args)

    def test_password_and_other_auth_values_are_never_in_persisted_prepare_arguments(self):
        args = self.parse("--user", "admin", "--password", "--known-hosts", "/tmp/known",
                          "--identity", "/tmp/key", "--management-public-key", "/tmp/key.pub", "--os")
        self.assertEqual(args.prepare_args, ("--os",))

    def test_argument_diagnostic_does_not_echo_untrusted_value(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = app.main(["--not-a-real-option=SECRET_TOKEN"])
        self.assertEqual(code, 2)
        self.assertIn("ARGUMENTS", err.getvalue())
        self.assertNotIn("SECRET_TOKEN", err.getvalue())

    def test_flat_bundle_imports_local_modules_without_foreign_tools(self):
        self.assertEqual(Path(app._fixed_driver().__file__).resolve(), ROOT / "ibsw_upgrade_driver.py")

    def test_component_template_uses_flat_bundle_sibling(self):
        self.assertEqual(component._TEMPLATE, ROOT / "upgrade-component.sh")

    def test_owned_runner_uses_flat_bundle_sibling(self):
        binding = {"run_id": "fixture", "node": {"hostname": "ew-spine01"}, "stage": "os-0000",
                   "component": "os", "script_sha256": "a" * 64}
        remote = "/home/admin/.ibsw-fixture-ew-spine01-os-0000-" + "b" * 32 + "/step.sh"
        payload = executor._owned_runner_bytes(binding, remote)
        self.assertIn(b"IBSW_OWNED_EXIT_V1", payload)

    def test_native_identity_failure_has_safe_specific_reason_code(self):
        leaf = SimpleNamespace(node=SimpleNamespace(hostname="ew-spine01", mac="02:00:00:00:00:01"))
        with self.assertRaises(observer._NativeObservationHold) as raised:
            observer._validate_identity(leaf, (b"wrong-host\n02:00:00:00:00:01\n", b"", 0, True))
        self.assertEqual(raised.exception.reason_code, "DEVICE_IDENTITY_MISMATCH")

    def test_auth_failure_code_does_not_reveal_native_exception_or_password(self):
        error = observer._NativeObservationHold(reason_code="SSH_AUTHENTICATION_FAILED")
        code, detail = app._failure_detail(error, "READONLY_OBSERVATION")
        self.assertEqual(code, "SSH_AUTHENTICATION_FAILED")
        self.assertIn("credentials", detail)

    def test_runtime_diagnostic_preserves_exact_pins_without_installing(self):
        with patch.object(app.metadata, "version", return_value="0.0"), self.assertRaises(app._InspectionHold) as raised:
            app._check_runtime()
        self.assertIn("paramiko expected=5.0.0 installed=0.0", str(raised.exception))
        self.assertIn("nothing was installed automatically", str(raised.exception))


class WorkflowTests(unittest.TestCase):
    def fixture(self, root):
        project = root / "project"
        project.mkdir(mode=0o700)
        (project / "01-global.yaml").write_text(GLOBAL)
        with (project / "02-devices_config.csv").open("w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(HEADER)
            for number in (1, 2):
                writer.writerow([f"ew-spine{number:02d}.example", "ib", "NA", f"192.0.2.{number}", "24", "192.0.2.254",
                                 f"02:00:00:00:00:{number:02x}"] + [""] * 12)
        home = root / "home"
        (home / ".ssh").mkdir(parents=True, mode=0o700)
        wire = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + b"x" * 32
        known = home / ".ssh/known_hosts"
        known.write_text("192.0.2.1 ssh-ed25519 " + base64.b64encode(wire).decode() + "\n")
        known.chmod(0o600)
        return project, home, known

    def invoke(self, project, home, *args):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(Path, "home", return_value=home), patch.object(app, "_check_runtime"), \
             patch.object(app, "_read_password", return_value="PRIVATE_TEST_PASSWORD") as password, \
             patch.object(socket, "socket", side_effect=AssertionError("No real network allowed")), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = app.main(["--project", str(project), "--os-only", *args])
        return code, out.getvalue(), err.getvalue(), password.call_count

    def test_real_input_prepare_scope_and_native_parser_readonly_flow(self):
        @contextlib.contextmanager
        def session(leaf, **kwargs):
            yield object(), 99999999999, (b"ew-spine01.example\n02:00:00:00:00:01\n", b"", 0), "password", "synthetic-pin"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            project, home, known = self.fixture(root)
            with patch.object(observer, "_signed_session", session), \
                 patch.object(observer, "_read_channel", side_effect=[(OS_TABLE, b"", 0, True), (HEALTH_TABLE, b"", 0, True)]):
                code, out, err, prompts = self.invoke(project, home, "--devices", "ew-spine01*", "--dry-run")
            self.assertEqual(code, 0, err)
            result = json.loads(out)
            self.assertEqual(result["state"], "READONLY_INSPECTION_DATA")
            self.assertEqual(result["execution_state"], "NOT_EXECUTED")
            self.assertEqual(result["targets"], [{"hostname": "ew-spine01.example"}])
            self.assertEqual(result['health_summary']['counts']['PASS'],1)
            self.assertEqual(prompts, 1)
            plans = list(project.glob("99-output-ib_nvl/bringup/xdr-upgrade-logs/*/plan.json"))
            self.assertEqual(len(plans), 1)
            self.assertNotIn("PRIVATE_TEST_PASSWORD", plans[0].read_text())
            self.assertNotIn("PRIVATE_TEST_PASSWORD", out + err)

    def test_no_match_has_explicit_hint_before_prompt_or_output_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = self.fixture(Path(directory).resolve())
            code, out, err, prompts = self.invoke(project, home, "--devices", "ew-spine01")
            self.assertEqual(code, 2)
            self.assertIn("DEVICE_SELECTION", err)
            self.assertIn("glob", err)
            self.assertEqual(prompts, 0)
            self.assertFalse((project / "99-output-ib_nvl").exists())

    def test_missing_default_known_hosts_is_actionable_and_does_not_prompt(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = self.fixture(Path(directory).resolve())
            known.unlink()
            code, out, err, prompts = self.invoke(project, home, "--devices", "ew-spine01*")
            self.assertEqual(code, 2)
            self.assertIn("KNOWN_HOSTS", err)
            self.assertIn("--known-hosts", err)
            self.assertEqual(prompts, 0)
            self.assertFalse((project / "99-output-ib_nvl").exists())

    def test_backend_private_exception_is_not_dumped_to_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = self.fixture(Path(directory).resolve())
            with patch.object(driver, "preflight_inventory_selection", side_effect=ValueError("PRIVATE_TEST_PASSWORD\x1b[31m")):
                code, out, err, prompts = self.invoke(project, home, "--devices", "ew-spine01*")
            self.assertEqual(code, 2)
            self.assertIn("INPUT_PREFLIGHT", err)
            self.assertNotIn("PRIVATE_TEST_PASSWORD", out + err)
            self.assertNotIn("\x1b", out + err)

    def test_runtime_failure_precedes_password_and_artifact_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = self.fixture(Path(directory).resolve())
            with patch.object(Path, "home", return_value=home), \
                 patch.object(app, "_check_runtime", side_effect=app._InspectionHold("SSH runtime unavailable")), \
                 patch.object(app, "_read_password") as prompt, contextlib.redirect_stderr(io.StringIO()) as err:
                code = app.main(["--project", str(project), "--os-only", "--devices", "ew-spine01*"])
            self.assertEqual(code, 2)
            self.assertIn("SSH_RUNTIME", err.getvalue())
            prompt.assert_not_called()
            self.assertFalse((project / "99-output-ib_nvl").exists())

    def test_canonical_tools_layout_generates_real_component_scripts_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            project, home, known = self.fixture(root)
            workspace = root / "workspace"
            tools = workspace / "tools"
            entry = workspace / "infiniband/bringup/xdr-upgrade"
            tools.mkdir(parents=True)
            entry.mkdir(parents=True)
            for source in ROOT.glob("*.py"):
                shutil.copy2(source, entry / source.name if source.name == "upgrade.py" else tools / source.name)
            for name in ("upgrade-component.sh", "upgrade-owned-runner.sh"):
                shutil.copy2(ROOT / name, entry / name)
            launcher = ("import runpy,sys,socket,subprocess\n"
                        "def blocked(*a,**k): raise AssertionError('No remote IO allowed')\n"
                        "socket.socket=blocked\nsubprocess.Popen=blocked\n"
                        "sys.argv=sys.argv[1:]\nrunpy.run_path(sys.argv[0],run_name='__main__')\n")
            result = subprocess.run([sys.executable, "-B", "-c", launcher, str(entry / "upgrade.py"),
                "--project", str(project), "--devices", "ew-spine01*", "--os-only", "--scripts-only", "--method", "http"],
                capture_output=True, text=True, cwd=root, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["execution_state"], "NOT_EXECUTED")
            scripts = list(project.glob("99-output-ib_nvl/bringup/xdr-upgrade-logs/*/ew-spine01.example/os-*/step.sh"))
            self.assertEqual(len(scripts), 2)
            self.assertTrue(all("nv action install system image" in path.read_text() for path in scripts))

    def test_connection_failure_is_not_misreported_as_bad_password(self):
        class RefusedSocket:
            def settimeout(self, value):
                pass
            def connect(self, value):
                raise OSError("SECRET_NATIVE_NETWORK_DETAILS")
            def close(self):
                pass
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = self.fixture(Path(directory).resolve())
            out, err = io.StringIO(), io.StringIO()
            with patch.object(Path, "home", return_value=home), patch.object(app, "_check_runtime"), \
                 patch.object(app, "_read_password", return_value="PRIVATE_TEST_PASSWORD"), \
                 patch.object(observer, "_fixed_sdk", return_value=object()), \
                 patch.object(socket, "socket", return_value=RefusedSocket()), \
                 contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = app.main(["--project", str(project), "--devices", "ew-spine01*", "--os-only", "--password"])
            self.assertEqual(code, 3)
            self.assertIn("SSH_CONNECT_FAILED", err.getvalue())
            self.assertEqual(json.loads(out.getvalue())["skipped_devices"][0]["state"], "SKIPPED_UNREACHABLE")
            self.assertNotIn("SECRET_NATIVE_NETWORK_DETAILS", out.getvalue() + err.getvalue())
            self.assertNotIn("PRIVATE_TEST_PASSWORD", out.getvalue() + err.getvalue())


class CurrentDirectoryInputTests(unittest.TestCase):
    def arguments(self, root, *args):
        with patch.object(app, "__file__", str(root / "upgrade.py")):
            return app._local_input_arguments(app._parse_cli(args), "/different/operator/cwd")

    def test_default_input_paths_are_script_directory_not_cwd(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.assertEqual(self.arguments(root),
                             ("--standalone-inputs", "--method", "http", "--ib-csv", str(root / "ib.csv"), "--global", str(root / "01-global.yaml")))

    def test_existing_01_global_is_compatible_when_global_yaml_is_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "01-global.yaml").write_text(GLOBAL)
            self.assertEqual(self.arguments(root)[-1], str(root / "01-global.yaml"))

    def test_global_alias_does_not_override_canonical_01_global(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "01-global.yaml").write_text(GLOBAL)
            (root / "global.yaml").symlink_to("missing-global.yaml")
            self.assertEqual(self.arguments(root)[-1], str(root / "01-global.yaml"))

    def test_explicit_files_are_not_replaced_by_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.assertEqual(self.arguments(root, "--ib-csv", "chosen.csv", "--global", "chosen.yaml"),
                             ("--ib-csv", "chosen.csv", "--global", "chosen.yaml", "--standalone-inputs", "--method", "http"))

    def test_explicit_project_keeps_project_defaults_not_cwd_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self.assertEqual(self.arguments(root, "--project", "/chosen/project"),
                             ("--project", "/chosen/project", "--standalone-inputs", "--method", "http"))

    def test_real_driver_honors_explicit_input_overrides_from_another_cwd(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            project, home, known = WorkflowTests().fixture(root)
            (project / "02-devices_config.csv").rename(project / "ib.csv")
            (project / "01-global.yaml").rename(project / "global.yaml")
            entry = root / "code"
            entry.mkdir()
            out, err = io.StringIO(), io.StringIO()
            with patch.object(app, "__file__", str(entry / "upgrade.py")), \
                 patch.object(app, "_fixed_driver", return_value=driver), \
                 patch.object(app.os, "getcwd", return_value=str(project)), \
                 patch.object(socket, "socket", side_effect=AssertionError("Offline declarations only")), \
                 contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = app.main(["--scripts-only", "--method", "http", "--os-only", "--devices", "ew-spine01*",
                                 "--ib-csv", "ib.csv", "--global", "global.yaml"])
            self.assertEqual(code, 0, err.getvalue())
            self.assertEqual(json.loads(out.getvalue())["execution_state"], "NOT_EXECUTED")
            plans = list(entry.glob("xdr-upgrade-logs/*/plan.json"))
            self.assertEqual(len(plans), 1)
            paths = json.loads(plans[0].read_text())["input_paths"]
            self.assertEqual(paths["csv_path"], str(project / "ib.csv"))
            self.assertEqual(paths["global_path"], str(project / "global.yaml"))


class ManagedDefaultWorkflowTests(unittest.TestCase):
    def fixture(self, root):
        old, home, known = WorkflowTests().fixture(root)
        workspace = root / "workspace"
        project = workspace / "DAY0-Prepare/demo"
        project.parent.mkdir(parents=True)
        old.rename(project)
        (project / "02-dhcp-subnet_config.csv").write_text("header\n")
        (project / "99-output-ztp").mkdir()
        output = project / "99-output-ib_nvl/bringup/xdr-upgrade-logs"
        output.mkdir(parents=True)
        entry = workspace / "infiniband/bringup/xdr-upgrade"
        entry.mkdir(parents=True)
        aliases = {
            "infiniband/01-global.yaml": project / "01-global.yaml",
            "infiniband/ib.csv": project / "02-devices_config.csv",
            "ztp/config/cumulus/template/01-global.yaml": project / "01-global.yaml",
            "ztp/config/cumulus/template/02-devices_config.csv": project / "02-devices_config.csv",
            "ztp/config/isc-dhcp-server/02-subnet_config.csv": project / "02-dhcp-subnet_config.csv",
            "ztp/status": project / "99-output-ztp",
            "infiniband/bringup/xdr-upgrade/xdr-upgrade-logs": output,
        }
        for relative, destination in aliases.items():
            link = workspace / relative
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to(os.path.relpath(destination, link.parent))
        (entry / "01-global.yaml").symlink_to("../../01-global.yaml")
        (entry / "ib.csv").symlink_to("../../ib.csv")
        members = [str(workspace / name) for name in aliases] + [str(entry / "01-global.yaml")]
        (workspace / "ztp/.setup_manifest").write_text("# setup manifest — proj: " + str(project) + "\n" + "\n".join(members) + "\n")
        known.write_text(known.read_text().replace("192.0.2.1 ", "192.0.2.2 ") + known.read_text())
        return project, home, entry, workspace

    def test_zero_argument_run_admits_existing_two_hop_links_and_preserves_project_output(self):
        @contextlib.contextmanager
        def session(leaf, **kwargs):
            yield object(), 99999999999, (b"synthetic identity", b"", 0), "password", "synthetic-pin"
        # A complete declaration is necessary when the user selected no phases.
        complete = GLOBAL.replace("          - file: nvos-amd64-25.03.1010.bin\n", """          - file: nvos-amd64-25.03.1010.bin
        bios:
          file: 0ACQF.cab
          version: '0ACQF_06.01.009'
        cpld:
          burn:
            file: FUI1_BURN_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme
          refresh:
            file: FUI1_REFRESH_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme
""")
        columns = ("Name", "Actual FW", "Part Number", "FW Source")
        firmware = "{:<9}  {:<23}  {:<15}  {}\n".format(*columns)
        firmware += "---------  -----------------------  ---------------  ---------\n"
        for row in (("BIOS", "0ACQF_06.01.009", "PN1", "internal"),
                    ("CPLD1", "CPLD000232_REV0900", "PN2", "internal"),
                    ("CPLD2", "CPLD000383_REV0800", "PN3", "internal"),
                    ("CPLD3", "CPLD000389_REV0600", "PN4", "internal")):
            firmware += "{:<9}  {:<23}  {:<15}  {}\n".format(*row)
        with tempfile.TemporaryDirectory() as directory:
            project, home, entry, workspace = self.fixture(Path(directory).resolve())
            (project / "01-global.yaml").write_text(complete)
            out, err = io.StringIO(), io.StringIO()
            with patch.object(Path, "home", return_value=home), patch.object(app, "__file__", str(entry / "upgrade.py")), \
                 patch.object(app.os, "getcwd", return_value=str(entry)), patch.object(app, "_fixed_driver", return_value=driver), \
                 patch.object(app, "_check_runtime"), patch.object(app, "_read_password", return_value="PRIVATE_TEST_PASSWORD"), \
                 patch.object(observer, "_signed_session", session), \
                 patch.object(observer, "_read_channel", side_effect=lambda _leaf,_transport,command,_deadline:
                    ({'nv show system version':OS_TABLE,'nv show platform firmware':firmware.encode(),
                      'nv show system health':HEALTH_TABLE}[command],b'',0,True)), \
                 patch.object(socket, "socket", side_effect=AssertionError("No real network allowed")), \
                 contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = app.main([])
            self.assertEqual(code, 0, err.getvalue())
            self.assertEqual(len(json.loads(out.getvalue())["targets"]), 2)
            self.assertEqual(json.loads(out.getvalue())["execution_state"], "NOT_EXECUTED")
            self.assertEqual(len(list(project.glob("99-output-ib_nvl/bringup/xdr-upgrade-logs/*/plan.json"))), 1)
            self.assertTrue((entry / "01-global.yaml").is_symlink())

    def test_cross_project_csv_through_existing_wrapper_is_rejected_before_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, entry, workspace = self.fixture(Path(directory).resolve())
            wrong = workspace / "infiniband/ib.csv"
            wrong.unlink()
            wrong.symlink_to("../DAY0-Prepare/foreign/02-devices_config.csv")
            args = ("--ib-csv", str(entry / "ib.csv"), "--global", str(entry / "01-global.yaml"), "--os-only")
            with self.assertRaises(ValueError):
                driver.preflight_device_selection(str(entry / "upgrade.py"), str(entry), args)
            self.assertEqual(list(project.glob("99-output-ib_nvl/bringup/xdr-upgrade-logs/*")), [])

    def test_original_outer_alias_change_is_not_hidden_by_canonical_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, entry, workspace = self.fixture(Path(directory).resolve())
            args = ("--ib-csv", str(entry / "ib.csv"), "--global", str(entry / "01-global.yaml"), "--os-only")
            plan = driver.parse_prepare_args(str(entry / "upgrade.py"), str(entry), args)
            with driver.open_managed_inputs(plan.paths) as scope:
                alias = entry / "ib.csv"
                alias.unlink()
                alias.symlink_to("../../foreign.csv")
                with self.assertRaises(ValueError):
                    scope.verify()


class InputDiagnosticsTests(unittest.TestCase):
    def invoke(self, project, *extra):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(app, "_read_password", side_effect=AssertionError("No prompt in input diagnostics")), \
             patch.object(app, "_check_runtime", side_effect=AssertionError("No SSH runtime check in input diagnostics")), \
             patch.object(socket, "socket", side_effect=AssertionError("No network in input diagnostics")), \
             patch.object(driver, "prepare_not_executed_run", side_effect=AssertionError("No local run artifacts in input diagnostics")), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = app.main(["--diagnose-inputs", "--project", str(project), "--os-only", *extra])
        return code, out.getvalue(), err.getvalue()

    def test_diagnostic_success_stops_after_real_preflight_without_auth_or_output(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = WorkflowTests().fixture(Path(directory).resolve())
            code, out, err = self.invoke(project, "--password")
            self.assertEqual(code, 0, err)
            result = json.loads(out)
            self.assertEqual(result["state"], "INPUT_PREFLIGHT_PASSED")
            self.assertEqual(result["selected_ib_count"], 2)
            self.assertFalse(result["ssh_attempted"])
            self.assertFalse(result["local_artifacts_created"])
            self.assertIn("ibsw_upgrade_inputs", result["loaded_modules"])
            self.assertRegex(result["loaded_modules"]["ibsw_upgrade_inputs"]["sha256"], r"^[0-9a-f]{64}$")
            self.assertFalse((project / "99-output-ib_nvl").exists())

    def test_missing_file_is_specific_not_a_generic_policy_or_ssh_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = WorkflowTests().fixture(Path(directory).resolve())
            (project / "02-devices_config.csv").unlink()
            code, out, err = self.invoke(project)
            self.assertEqual(code, 2)
            report = json.loads(out)
            self.assertEqual(report["error"]["code"], "INPUT_FILE_MISSING")
            self.assertTrue(any(row["kind"] == "missing" for row in report["inputs"]["csv"]))
            self.assertIn("INPUT_FILE_MISSING", err)
            self.assertIn("source", report["error"])

    def test_missing_manifest_member_reports_precise_rule_and_source(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, entry, workspace = ManagedDefaultWorkflowTests().fixture(Path(directory).resolve())
            manifest = workspace / "ztp/.setup_manifest"
            original = manifest.read_text()
            manifest.write_text(original.replace(str(entry / "01-global.yaml") + "\n", ""))
            args = ("--ib-csv", str(entry / "ib.csv"), "--global", str(entry / "01-global.yaml"), "--os-only")
            try:
                driver.preflight_device_selection(str(entry / "upgrade.py"), str(entry), args)
            except ValueError as error:
                code, message = app._failure_detail(error, "INPUT_PREFLIGHT")
                source = app._error_source(error)
            else:
                self.fail("An unregistered global alias must still be rejected")
            self.assertEqual(code, "INPUT_MANIFEST_INCOMPLETE")
            self.assertIn("manifest", message)
            self.assertEqual(source["module"], "ibsw_upgrade_inputs.py")
            self.assertEqual(source["function"], "_bind_managed")

    def test_invalid_yaml_reports_location_without_hash_or_error_snippet(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = WorkflowTests().fixture(Path(directory).resolve())
            (project / "01-global.yaml").write_text("schema_version: 2\nswitches: [$6$SECRET_HASH\n")
            code, out, err = self.invoke(project)
            self.assertEqual(code, 2)
            result = json.loads(out)
            self.assertEqual(result["error"]["code"], "GLOBAL_YAML_INVALID")
            self.assertNotIn("SECRET_HASH", out + err)
            self.assertIn("yaml_line", result["error"])

    def test_invalid_csv_header_is_distinguished_without_echoing_csv_values(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = WorkflowTests().fixture(Path(directory).resolve())
            (project / "02-devices_config.csv").write_text("hostname,PRIVATE_HEADER_SECRET\n")
            code, out, err = self.invoke(project)
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(out)["error"]["code"], "CSV_LAYOUT_INVALID")
            self.assertNotIn("PRIVATE_HEADER_SECRET", out + err)

    def test_duplicate_ib_identity_reports_rule_without_printing_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = WorkflowTests().fixture(Path(directory).resolve())
            csv_path = project / "02-devices_config.csv"
            lines = csv_path.read_text().splitlines()
            csv_path.write_text("\n".join([lines[0], lines[1], lines[1]]) + "\n")
            code, out, err = self.invoke(project)
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(out)["error"]["code"], "CSV_DUPLICATE_IDENTITY")
            self.assertIn("duplicate", err.lower())

    def test_invalid_declared_os_path_is_diagnosed_before_any_other_step(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = WorkflowTests().fixture(Path(directory).resolve())
            (project / "01-global.yaml").write_text(GLOBAL.replace("version: '25.03.1010'", "version: '25.03.1020'"))
            code, out, err = self.invoke(project)
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(out)["error"]["code"], "UPGRADE_POLICY")
            self.assertIn("OS last path node must equal ib.version", err)

    def test_diagnostic_cannot_be_combined_with_write_mode(self):
        with self.assertRaises(app._InspectionHold):
            app._parse_cli(("--diagnose-inputs", "--upgrade", "--yes"))

    def test_wrapped_unknown_error_has_code_location_but_not_raw_text(self):
        try:
            try:
                driver._absolute("bad\\path_PRIVATE_VALUE", "/tmp")
            except ValueError as error:
                raise RuntimeError("OUTER_PRIVATE_VALUE") from error
        except RuntimeError as error:
            code, message = app._failure_detail(error, "INPUT_PREFLIGHT")
            source = app._error_source(error)
        self.assertEqual(source["function"], "_absolute")
        self.assertNotIn("PRIVATE_VALUE", message)

    def test_symlink_loop_diagnostic_is_bounded_and_never_reads_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "a").symlink_to("b")
            (root / "b").symlink_to("a")
            rows = app._input_path_diagnostics(str(root / "a"))
            self.assertLessEqual(len(rows), 17)
            self.assertEqual(rows[-1]["kind"], "loop")


if __name__ == "__main__":
    unittest.main()
