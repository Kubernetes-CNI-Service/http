"""v3.1.1 WP-9c workflow: the fixed-name AIR json across setup, load, the producer and its readers, and the
readers that find the project through DAY0-Prepare/activate-project.

Each case runs real scripts in a temporary copy of the git-indexed workspace
(test_project_link_inputs_workflow.LinkedProjectSandbox): setup (DAY0-Prepare/01-a-setup.py) as a child
process, then 11-load.py's generation step driving the real P2P producer (b-xlsx_to_dot.py, a child process
in the copy) and the readers.  Inputs are synthetic; links to "outside" files point into the copy's Work/.

Expected values and their sources:
- R-016 详细设计 v1.1 §11 (R16-18): an AIR project's first load -- the AIR json is written by the producer, so
  the tree link setup made before it existed is how load finds it.  问题文档 I-031 and R16-04: the fixed name
  99-output-p2p/p2p-air.json, no pointer derived in the project; an older <workbook>-air.json is neither read
  nor deleted.  详细工作指导 O12: the document's name stays <workbook stem>-air.
- R-016 §3.4: the AIR json is optional; on a project without it the tree link dangles and readers treat it as
  absent without an error.  (What setup --status prints for it is WP-4's and is not asserted here.)
- R-016 §5.1, §5.2 (R16-06), §11 v1.1 补: with 02-devices_config.csv a user link to a file outside the project
  (需求文档 R-014 第 3 条), the readers that used to resolve a setup link and take its parent --
  c1-generate_dhcp.py's LOAD candidate, yaml-collect.py's AIR backup helper, feedback.py's sample discovery --
  still name the pointer's project.  That case needs setup to write the pointer (v3.1.1 WP-3).
"""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_cases import test_project_link_inputs_workflow as LINKED
from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
LOAD = load_script("activate_air_workflow_load", ROOT / "DAY0-Prepare/11-load.py")
GENERATOR = load_script(
    "activate_air_workflow_generator", ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
)
DIAGNOSTICS = load_script("activate_air_workflow_diagnostics", ROOT / "tools/collect-ztp-diagnostics.py")
BACKUP = load_script("activate_air_workflow_backup", ROOT / "ztp/backup/yaml-collect.py")
FEEDBACK = load_script("activate_air_workflow_feedback", ROOT / "ztp/optimize/feedback.py")

STEM = "Site P2P_v1.0"
AIR_LINK = "ztp/config/isc-dhcp-server/p2p-air.json"
# An AIR json an older producer left under the workbook's name: a real document a glob reader would pick.
OLDER_AIR = json.dumps({"content": {"nodes": {"AIR-OLDER01": {
    "os": "cumulus-vx-5.16.4", "management_interfaces": {"eth0": {"mac_address": "02:00:00:00:00:41"}},
}}, "links": []}, "name": f"{STEM}-air"}) + "\n"


class DhcpReached(Exception):
    """11-load reached its DHCP step: the producer step before it is complete."""


def write_air_workbook(path: Path) -> None:
    """One switch-to-switch row in the two-header-row layout the producer auto-detects."""
    from openpyxl import Workbook

    book = Workbook()
    book.remove(book.active)
    sheet = book.create_sheet("OOB LF-SP")
    sheet.cell(1, 5, "Source")
    sheet.cell(1, 11, "Dest")
    for column, label in ((7, "name"), (8, "HCA/port"), (13, "name"), (14, "port")):
        sheet.cell(2, column, label)
    sheet.cell(2, 23)
    for column, value in zip((7, 8, 13, 14), ("EXAMPLE-OOB-SPINE01", "1", "EXAMPLE-OOB-LEAF01", "49")):
        sheet.cell(3, column, value)
    book.save(path)
    book.close()


class AirJsonWorkflowTests(unittest.TestCase):
    def sandbox(self) -> LINKED.LinkedProjectSandbox:
        directory = tempfile.TemporaryDirectory(prefix="activate-air-workflow-")
        self.addCleanup(directory.cleanup)
        return LINKED.LinkedProjectSandbox(Path(directory.name).resolve())

    def prepared(self, *, outside_inventory: bool = False) -> LINKED.LinkedProjectSandbox:
        sandbox = self.sandbox()
        inventory = sandbox.project / "02-devices_config.csv"
        if outside_inventory:
            (sandbox.work / "devices.csv").write_bytes(sandbox.devices)
            inventory.symlink_to(sandbox.work / "devices.csv")
        else:
            inventory.write_bytes(sandbox.devices)
        write_air_workbook(sandbox.project / f"{STEM}.xlsx")
        older = sandbox.project / "99-output-p2p" / f"{STEM}-air.json"
        older.parent.mkdir()
        older.write_text(OLDER_AIR, encoding="utf-8")
        setup = sandbox.setup()
        self.assertEqual(0, setup.returncode, setup.stdout)
        return sandbox

    def run_generation(self, sandbox, deployment_scope: str) -> list[list[str]]:
        """11-load.py's generation step with its real P2P producer; it stops at the DHCP step."""
        commands = []

        def run(command, *, cwd=None, **_kwargs):
            commands.append(list(command))
            if command[1] != "b-xlsx_to_dot.py":
                raise DhcpReached()
            result = subprocess.run(
                command, cwd=cwd, env=sandbox.env(), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300, check=False,
            )
            self.assertEqual(0, result.returncode, result.stdout)

        with mock.patch.object(LOAD, "ZTP_DIR", sandbox.http / "ztp"), \
                mock.patch.object(LOAD, "run", side_effect=run), redirect_stdout(io.StringIO()), \
                self.assertRaises(DhcpReached):
            LOAD.generate_configs(
                frozenset({"eth"}), install_dhcp=False, eth_version="5.16.4",
                deployment_scope=deployment_scope,
            )
        self.assertEqual(["b-xlsx_to_dot.py", "c1-generate_dhcp.py"], [command[1] for command in commands])
        return commands

    def test_air_project_first_load_finds_the_producers_fixed_air_json(self):
        sandbox = self.prepared()
        project = sandbox.project.resolve()
        air_link = sandbox.http / AIR_LINK
        fixed = project / "99-output-p2p/p2p-air.json"
        # Before the first load: setup's optional row dangles (R-016 §3.4) and names the fixed file (I-031).
        self.assertTrue(air_link.is_symlink())
        self.assertFalse(air_link.exists())
        self.assertEqual(fixed, Path(os.path.realpath(air_link)))

        commands = self.run_generation(sandbox, "air")

        # R16-18: the producer wrote the fixed name and load saw it through setup's link, so the DHCP step
        # derives the AIR inventory.
        self.assertTrue(fixed.is_file())
        self.assertTrue(air_link.is_file())
        self.assertIn("--inventory-output", commands[1])
        self.assertEqual(f"{STEM}-air", json.loads(fixed.read_text(encoding="utf-8"))["name"])  # O12
        self.assertEqual(OLDER_AIR, (project / "99-output-p2p" / f"{STEM}-air.json").read_text(encoding="utf-8"))

        # The generator reads exactly that file, never the older one.
        output = sandbox.http / "ztp/config/cumulus/template/P2P/output-p2p"
        with mock.patch.multiple(GENERATOR, P2P_OUTPUT_DIR=str(output),
                                 P2P_INPUT_DIR=str(output.parent)):
            self.assertEqual([fixed], [Path(os.path.realpath(path))
                                       for path in GENERATOR._topology_air_json_files()])

    def test_non_air_project_dangling_air_link_is_absent_for_every_reader(self):
        sandbox = self.prepared()
        project = sandbox.project.resolve()
        air_link = sandbox.http / AIR_LINK
        commands = self.run_generation(sandbox, "prod")

        # R-016 §3.4: no AIR json; the link dangles and each reader treats it as absent.
        self.assertFalse(os.path.lexists(project / "99-output-p2p/p2p-air.json"))
        self.assertTrue(air_link.is_symlink())
        self.assertFalse(air_link.exists())
        self.assertNotIn("--inventory-output", commands[1])
        output = sandbox.http / "ztp/config/cumulus/template/P2P/output-p2p"
        with mock.patch.multiple(GENERATOR, P2P_OUTPUT_DIR=str(output),
                                 P2P_INPUT_DIR=str(output.parent)):
            self.assertEqual([], GENERATOR._topology_air_json_files())
        helper = subprocess.run(
            [sys.executable, "-B", os.fspath(sandbox.http / "ztp/dynamic_air_inventory.py"),
             "--inventory", os.fspath(project / "02-devices_config.csv"), "--leases", os.devnull,
             "--format", "pipe"],
            cwd=sandbox.http, env=sandbox.env(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=60, check=False,
        )
        self.assertEqual((0, ""), (helper.returncode, helper.stdout))
        staging = sandbox.base / "diagnostic-staging"
        builder = DIAGNOSTICS.BundleBuilder(staging, "air-absent")
        DIAGNOSTICS.collect_project_inputs(builder, project)
        self.assertEqual([], [entry["path"] for entry in builder.entries if "/p2p/" in entry["path"]])
        self.assertEqual([], [warning for warning in builder.warnings if "p2p-air" in warning])
        # I-031: the older file stays where the user left it.
        self.assertEqual(OLDER_AIR, (project / "99-output-p2p" / f"{STEM}-air.json").read_text(encoding="utf-8"))

    def test_readers_name_the_pointer_project_when_the_inventory_links_outside(self):
        sandbox = self.prepared(outside_inventory=True)
        project = sandbox.project.resolve()
        pointer = sandbox.http / "DAY0-Prepare/activate-project"
        # v3.1.1 WP-3 (R-016 §4.2 step 4): setup leaves the pointer behind.
        self.assertTrue(pointer.is_symlink(), "setup writes DAY0-Prepare/activate-project (WP-3)")
        self.assertEqual(sandbox.project.name, os.readlink(pointer))

        # c1-generate_dhcp.py: load's private DHCP candidate is accepted in the pointer's project.
        candidate = project / "99-output-dhcp/.load-dhcp-candidate-0123456789abcdef"
        candidate.mkdir(mode=0o700)
        dhcp = sandbox.run([
            sys.executable, "-B", os.fspath(sandbox.http / "ztp/config/isc-dhcp-server/c1-generate_dhcp.py"),
            "-y", "--preserve-input-csv", "--candidate-dir", os.fspath(candidate),
        ])
        self.assertEqual(0, dhcp.returncode, dhcp.stdout)
        self.assertTrue((candidate / "dhcpd.conf").is_file())

        # yaml-collect.py: the AIR backup reads the pointer project's AIR json, not one beside the outside file.
        (project / "99-output-p2p/p2p-air.json").write_text(json.dumps({"content": {"nodes": {
            "AIR-EXAMPLE-FW01": {"os": "cumulus-vx-5.16.4",
                                 "management_interfaces": {"eth0": {"mac_address": "02:00:00:00:00:51"}}},
        }}}), encoding="utf-8")
        leases = sandbox.base / "dhcpd.leases"
        leases.write_text(
            "lease 192.0.2.51 {\n  binding state active;\n  hardware ethernet 02:00:00:00:00:51;\n}\n",
            encoding="utf-8",
        )
        with mock.patch.object(BACKUP, "HTTP_ROOT", os.fspath(sandbox.http), create=True):
            resolved, warnings = BACKUP.load_dynamic_air_backup_devices(
                sandbox.http / "ztp/backup/02-devices_config.csv", leases,
            )
        self.assertEqual([("AIR-EXAMPLE-FW01", "192.0.2.51")],
                         [(item["hostname"], item["eth0_ip"]) for item in resolved])
        self.assertEqual([], warnings)

        # feedback.py: with no inputs, the sample project is the pointer's.
        with mock.patch.object(FEEDBACK, "__file__", os.fspath(sandbox.http / "ztp/optimize/feedback.py")):
            plan = FEEDBACK.discover_sample_inputs([])
        self.assertIsNotNone(plan.project, "R-016 §5.1: the pointer names the project")
        self.assertEqual(project, Path(plan.project))


if __name__ == "__main__":
    unittest.main()
