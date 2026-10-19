"""Real compatibility shell to real Python CLI with a private actual guard.

These three workflows preserve both filename formats, complete scripts-only
generation, and invalid-option/no-fallback safety. No SSH/device/installer runs.
The helper is not a normal test module: existing BringupSafetyTests delegate
their three original methods here, avoiding duplicate suite execution.
"""
import csv
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]
ENTRY = "infiniband/bringup/xdr-upgrade/"
RUNTIME = (
    ENTRY + "upgrade.py", ENTRY + "upgrade.sh",
    ENTRY + "upgrade-component.sh", ENTRY + "upgrade-owned-runner.sh",
    ENTRY + "requirements.txt", "tools/ib_bringup_runtime_guard.py",
    "tools/project_contract.py", "tools/_package_common.py",
    "tools/ssh_key_preparation.py", "tools/ibsw_upgrade_contract.py",
    "tools/ibsw_upgrade_inputs.py", "tools/ibsw_upgrade_schedule.py",
    "tools/ibsw_upgrade_component.py", "tools/ibsw_upgrade_driver.py",
    "tools/ibsw_upgrade_executor.py", "tools/ibsw_upgrade_observer.py",
    "tools/ibsw_upgrade_access.py", "tools/ibsw_upgrade_pipeline.py",
)
HEADER = "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,eth1_mac,lo_ip,bgp_asn,bgp_ports,bond_ports,bond_type,bond_mac,peerlink_ports,vrl".split(",")

class LegacyShellCompatibilityWorkflowTests(unittest.TestCase):
    def bundle(self, root):
        flat = root / "flat"
        flat.mkdir()
        for relative in RUNTIME:
            shutil.copy2(ROOT / relative, flat / Path(relative).name)
        return flat

    def require_complete(self, flat):
        self.assertEqual(len(RUNTIME), 18)
        self.assertTrue(all((flat / Path(relative).name).is_file()
                            and not (flat / Path(relative).name).is_symlink()
                            and (flat / Path(relative).name).stat().st_size > 0
                            for relative in RUNTIME),
                        "The real compatibility shell fixture requires all18 actual runtime members")

    def project(self, root, names):
        project = root / "project"
        project.mkdir()
        global_text = """schema_version: 2
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
"""
        global_text += "".join("          - file: " + name + "\n" for name in names)
        (project / "01-global.yaml").write_text(global_text, encoding="utf-8")
        with (project / "02-devices_config.csv").open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(HEADER)
            writer.writerow(["EXAMPLE-IB01", "ib", "NA", "192.0.2.21", "24",
                             "192.0.2.254", "02:00:00:00:00:21"] + [""] * 12)
        return project

    def launcher(self, root, flat):
        binary = root / "bin"
        binary.mkdir()
        target = binary / "python3"
        program = "#!" + sys.executable + "\n" + """import importlib, os, pathlib, runpy, socket, subprocess, sys
sys.dont_write_bytecode = True
args = sys.argv[1:]
if args[:1] == ["-B"]:
    args = args[1:]
entry = pathlib.Path(args[0]).resolve()
expected = pathlib.Path(os.environ["IBSW_TEST_FLAT"]).resolve()
if entry != expected / "upgrade.py":
    raise AssertionError("Only the selected real copied entry may execute")
sys.path.insert(0, str(expected))
guard = importlib.import_module("ib_bringup_runtime_guard")
if pathlib.Path(guard.__file__).resolve() != expected / "ib_bringup_runtime_guard.py":
    raise AssertionError("Only the real fixed flat guard owner is admissible")
guard._RUNTIME_GUARD_PATH = pathlib.Path(os.environ["IBSW_TEST_PRIVATE_LOCK"])
def blocked(*args, **kwargs):
    raise AssertionError("Scripts-only/invalid CLI must not start remote IO or descendants")
socket.socket = blocked
subprocess.Popen = blocked
sys.argv = args
runpy.run_path(str(entry), run_name="__main__")
"""
        target.write_text(program, encoding="utf-8")
        target.chmod(0o700)
        return binary

    def invoke_shell(self, root, flat, *args):
        binary = self.launcher(root, flat)
        env = {
            "PATH": str(binary) + ":/usr/bin:/bin",
            "HOME": str(root),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONUTF8": "1",
            "PYTHONPATH": str(Path(yaml.__file__).resolve().parent.parent),
            "IBSW_TEST_FLAT": str(flat),
            "IBSW_TEST_PRIVATE_LOCK": str(root / "private-runtime.lock"),
        }
        return subprocess.run(["/bin/bash", "--noprofile", "--norc", "-p", str(flat / "upgrade.sh"), *args],
                              cwd=root, env=env, text=True, capture_output=True,
                              timeout=25, check=False)

    def test_both_literal_nvos_names_are_inferred_by_real_shell_cli(self):
        for label, name in (("modern", "nvos-amd64-25.03.1010.bin"),
                            ("legacy", "nvosv25-03-1010amd64.bin")):
            with self.subTest(label=label), tempfile.TemporaryDirectory(prefix="ibsw-shell-names-") as raw:
                root = Path(raw).resolve()
                flat = self.bundle(root)
                self.require_complete(flat)
                project = self.project(root, (name,))
                done = self.invoke_shell(root, flat, "--project", str(project), "--os-only",
                                         "--scripts-only", "--method", "http")
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(json.loads(done.stdout)["execution_state"], "NOT_EXECUTED")
                plans = list(project.glob("99-output-ib_nvl/bringup/xdr-upgrade-logs/*/plan.json"))
                self.assertEqual(len(plans), 1)
                policy = json.loads(plans[0].read_text())["policy"]
                self.assertEqual(policy["os"][0]["version"], "25.03.1010")
                self.assertEqual(policy["os"][0]["file"], name)

    def test_real_shell_generates_ordered_os_chain_and_final_install_script(self):
        with tempfile.TemporaryDirectory(prefix="ibsw-shell-scripts-") as raw:
            root = Path(raw).resolve()
            flat = self.bundle(root)
            self.require_complete(flat)
            names = ("nvos-amd64-25.02.8008.bin", "nvos-amd64-25.03.1010.bin")
            project = self.project(root, names)
            done = self.invoke_shell(root, flat, "--project", str(project), "--os-only",
                                     "--scripts-only", "--method", "http")
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(json.loads(done.stdout)["execution_state"], "NOT_EXECUTED")
            scripts = sorted(project.glob("99-output-ib_nvl/bringup/xdr-upgrade-logs/*/EXAMPLE-IB01/os-*/step.sh"))
            self.assertEqual(len(scripts), 2)
            self.assertEqual([path.parent.name for path in scripts], ["os-0000", "os-0001"])
            self.assertIn(names[0], scripts[0].read_text())
            final = scripts[1].read_text()
            self.assertIn("nvos-amd64-25.03.1010.bin", final)
            self.assertIn("nv action install system image files", final)
            self.assertFalse(list(project.glob("**/*-status.json")))

    def test_invalid_parallel_keeps_original_exit_and_unsupported_methods_never_fallback(self):
        cases = (
            (("--method", "local", "--scripts-only", "--parallel-limit", "not-a-number"), 1, "Invalid --parallel-limit"),
            (("--method", "local", "--scripts-only"), 2, None),
            (("--method", "https", "--scripts-only"), 2, None),
        )
        for args, code, diagnostic in cases:
            with self.subTest(args=args), tempfile.TemporaryDirectory(prefix="ibsw-shell-invalid-") as raw:
                root = Path(raw).resolve()
                flat = self.bundle(root)
                self.require_complete(flat)
                done = self.invoke_shell(root, flat, *args)
                self.assertEqual(done.returncode, code, done.stderr)
                if diagnostic is not None:
                    self.assertIn(diagnostic, done.stderr)
                self.assertFalse((root / "xdr-upgrade-logs").exists())
                self.assertFalse((flat / "xdr-upgrade-logs").exists())
                self.assertFalse(list(root.glob("**/plan.json")))
