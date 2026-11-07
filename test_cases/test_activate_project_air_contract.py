"""v3.1.1 WP-9c direct contract: the fixed-name AIR json and the readers that find the project by the pointer.

Every expected value is written from the requirement text, never read back from the implementation:
- 问题文档 I-031 (owner 2026-11-03, 2026-11-07 更正) and R-016 详细设计 v1.1 R16-04: b-xlsx_to_dot.py writes the
  AIR json itself under the fixed name 99-output-p2p/p2p-air.json; setup no longer derives a pointer in the
  project; the tree link ztp/config/isc-dhcp-server/p2p-air.json is the optional table row (R-016 §3.4: dangling
  is normal); readers that found the AIR json by workbook name or glob (90-c2 _topology_air_json_files,
  dynamic_air_inventory.find_air_json) accept only the fixed name, so an older <workbook>-air.json left in the
  project is ignored and never deleted.
- v3.1.1 详细工作指导 O12 (owner 2026-11-07「同意你的建议。」): only the file name changes; the document's
  "name" stays <P2P workbook stem>-air, the name the AIR platform shows.
- R-016 §5.1, §5.2 (R16-06) and 详细工作指导 WP-9 class 6: a reader that resolved one setup link and took the
  parent directory as the project now asks project_contract.active_project_dir(); with a project input that is
  a user link to a file outside the project (需求文档 R-014 第 3 条, owner 2026-11-02) the old reading named the
  outside directory.  Covered here: b-xlsx_to_dot.py --mini, c1-generate_dhcp.py's LOAD candidate, the two
  yaml-collect.py AIR backup helpers and feedback.py's sample discovery without inputs.
"""

from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script
from test_cases.test_xlsx_zero_row_fail_closed import P2P as PRODUCER, invoke_main, prepare_runtime


ROOT = Path(__file__).resolve().parents[1]
P2P_DIR = ROOT / "ztp/config/cumulus/template/P2P"
SETUP = load_script("activate_air_contract_setup", ROOT / "DAY0-Prepare/01-a-setup.py")
GENERATOR = load_script(
    "activate_air_contract_generator", ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
)
DYNAMIC = load_script("activate_air_contract_dynamic", ROOT / "ztp/dynamic_air_inventory.py")
DHCP = load_script("activate_air_contract_dhcp", ROOT / "ztp/config/isc-dhcp-server/c1-generate_dhcp.py")
BACKUP = load_script("activate_air_contract_backup", ROOT / "ztp/backup/yaml-collect.py")
FEEDBACK = load_script("activate_air_contract_feedback", ROOT / "ztp/optimize/feedback.py")

PROJECT = "site"
STEM = "Site P2P_v1.0"
AIR_NODE = "AIR-EXAMPLE-FW01"
AIR_MAC = "02:00:00:00:00:51"
AIR_LEASE = "192.0.2.51"


def air_document(hostname: str = AIR_NODE, mac: str = AIR_MAC) -> dict:
    return {"content": {"nodes": {hostname: {
        "os": "cumulus-vx-5.16.4",
        "management_interfaces": {"eth0": {"mac_address": mac}},
    }}, "links": []}, "name": f"{STEM}-air"}


def write_air_workbook(path: Path) -> None:
    """One switch-to-switch row in the layout the producer auto-detects (two header rows)."""
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


def pointer_tree(root: Path, *, outside_inventory: bool = True) -> tuple[Path, Path]:
    """DAY0-Prepare/activate-project -> site, with the project's 02 a user link to a file outside it."""
    project = root / "DAY0-Prepare" / PROJECT
    project.mkdir(parents=True)
    work = root / "Work"
    work.mkdir()
    (project / "01-global.yaml").write_text("common: {}\n", encoding="utf-8")
    devices = "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac\n"
    if outside_inventory:
        (work / "devices.csv").write_text(devices, encoding="utf-8")
        (project / "02-devices_config.csv").symlink_to(work / "devices.csv")
    else:
        (project / "02-devices_config.csv").write_text(devices, encoding="utf-8")
    (root / "DAY0-Prepare/activate-project").symlink_to(PROJECT)
    return project.resolve(), work


def tree_link(root: Path, relative: str, project_name: str) -> Path:
    """A tree link written in the R-016 §2 canonical form, relative to the link's own directory."""
    link = root / relative
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(os.path.relpath(root / "DAY0-Prepare/activate-project" / project_name, link.parent))
    return link


class SetupAirLinkTests(unittest.TestCase):
    """I-031 / R16-04: setup builds the optional tree link to the fixed name and nothing in the project."""

    def test_setup_links_the_fixed_air_name_whatever_the_workbook_is_called(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            project = root / "DAY0-Prepare" / PROJECT
            (project / "99-output-p2p").mkdir(parents=True)
            workbook = project / f"{STEM}.xlsx"
            workbook.write_bytes(b"selected workbook\n")
            stale = project / "99-output-p2p" / f"{STEM}-air.json"
            stale.write_text("{}\n", encoding="utf-8")
            ztp = root / "ztp"
            (ztp / "config/isc-dhcp-server").mkdir(parents=True)
            air_link = root / "ztp/config/isc-dhcp-server/p2p-air.json"
            # Whichever text setup writes (direct until WP-3, then the pointer form), it must reach the project.
            (root / "DAY0-Prepare/activate-project").symlink_to(PROJECT)
            patches = dict(
                HTTP_BASE=str(root), HERE=str(root / "DAY0-Prepare"), ZTP=str(ztp),
                _DRY_RUN=False, _AUTO_YES=True, _LINK_ERRORS=0,
                P2P_INPUT_LINKS=[str(root / name) for name in SETUP.P2P_INPUT_PATHS],
                P2P_OUTPUT_LINKS=[str(root / name) for name in SETUP.P2P_OUTPUT_PATHS],
                P2P_AIR_JSON_LINK=str(air_link),
            )
            with ExitStack() as stack:
                stack.enter_context(mock.patch.multiple(SETUP, **patches))
                # _process_mapping's link_root default was bound to the real ztp/ at import time.
                defaults = SETUP._process_mapping.__defaults__
                stack.enter_context(mock.patch.object(
                    SETUP._process_mapping, "__defaults__", (*defaults[:-1], str(ztp)),
                ))
                stack.enter_context(redirect_stdout(io.StringIO()))
                SETUP._process_xlsx_files(str(project), str(workbook))
                errors = SETUP._LINK_ERRORS

            self.assertEqual(0, errors)
            self.assertTrue(air_link.is_symlink())
            # I-031: the fixed name, not <workbook stem>-air.json; R-016 §3.4: dangling until the producer runs.
            self.assertTrue(os.readlink(air_link).endswith("/99-output-p2p/p2p-air.json"), os.readlink(air_link))
            self.assertEqual(project / "99-output-p2p/p2p-air.json", Path(os.path.realpath(air_link)))
            self.assertFalse(os.path.lexists(project / "99-output-p2p/p2p-air.json"),
                             "R16-04: setup derives no AIR pointer in the project")
            self.assertEqual("{}\n", stale.read_text(encoding="utf-8"), "the older file is the user's; not deleted")


class ProducerFixedNameTests(unittest.TestCase):
    """I-031: b-xlsx_to_dot.py writes 99-output-p2p/p2p-air.json; O12: its name stays <stem>-air."""

    def run_producer(self, root: Path, argv: list[str]):
        paths = prepare_runtime(root, write_air_workbook)
        source = root / "rack-links.xlsx"
        renamed = root / f"{STEM}.xlsx"
        source.rename(renamed)
        (paths["p2p_dir"] / "p2p.xlsx").unlink()
        (paths["p2p_dir"] / "p2p.xlsx").symlink_to(renamed)
        for key, name in (("inventory", "01-inventory.log"), ("port_map", "02-port-mapping.log"),
                          ("air_template", "air-template-no-oob.json")):
            paths[key].write_bytes((P2P_DIR / name).read_bytes())
        older = paths["output"] / f"{STEM}-air.json"
        older.write_text('{"name": "kept"}\n', encoding="utf-8")
        caught, stdout, stderr = invoke_main(paths, argv)
        return paths, older, caught, stdout, stderr

    def test_producer_writes_the_fixed_name_and_keeps_the_workbook_name_inside(self):
        with tempfile.TemporaryDirectory() as directory:
            paths, older, caught, stdout, stderr = self.run_producer(
                Path(directory), ["-y", "--deployment-scope", "air", "--os-version", "5.16.4"],
            )
            self.assertTrue(caught is None or getattr(caught, "code", None) == 0, (caught, stdout, stderr))
            fixed = paths["output"] / "p2p-air.json"
            self.assertTrue(fixed.is_file(), sorted(item.name for item in paths["output"].iterdir()))
            document = json.loads(fixed.read_text(encoding="utf-8"))
            self.assertEqual(f"{STEM}-air", document["name"])  # O12
            self.assertTrue(document["content"]["nodes"])
            self.assertEqual('{"name": "kept"}\n', older.read_text(encoding="utf-8"),
                             "I-031: the producer neither writes nor deletes <stem>-air.json")
            # The DOT names keep the workbook stem; only the AIR json name is fixed.
            self.assertTrue((paths["output"] / f"{STEM}-air.dot").is_file())
            self.assertTrue((paths["output"] / f"{STEM}-lldpq.dot").is_file())

    def test_production_scope_writes_no_air_json(self):
        with tempfile.TemporaryDirectory() as directory:
            paths, _older, caught, stdout, stderr = self.run_producer(
                Path(directory), ["-y", "--deployment-scope", "prod"],
            )
            self.assertTrue(caught is None or getattr(caught, "code", None) == 0, (caught, stdout, stderr))
            self.assertFalse(os.path.lexists(paths["output"] / "p2p-air.json"))


class AirReaderFixedNameTests(unittest.TestCase):
    """I-031: the two readers that chose an AIR json by name or glob accept only the fixed name."""

    def output_dir(self, root: Path) -> Path:
        output = root / "DAY0-Prepare" / PROJECT / "99-output-p2p"
        output.mkdir(parents=True)
        return output

    def test_generator_topology_reads_only_the_fixed_name(self):
        with tempfile.TemporaryDirectory() as directory:
            output = self.output_dir(Path(directory))
            p2p_input = Path(directory) / "P2P"
            p2p_input.mkdir()
            (p2p_input / "p2p.xlsx").symlink_to(output.parent / f"{STEM}.xlsx")
            stale = output / f"{STEM}-air.json"
            stale.write_text(json.dumps(air_document("AIR-STALE01")), encoding="utf-8")
            bindings = dict(P2P_OUTPUT_DIR=str(output), P2P_INPUT_DIR=str(p2p_input))
            with mock.patch.multiple(GENERATOR, **bindings):
                self.assertEqual([], GENERATOR._topology_air_json_files())
                fixed = output / "p2p-air.json"
                fixed.write_text(json.dumps(air_document()), encoding="utf-8")
                os.utime(stale)  # the older file is newer: mtime must not choose it
                self.assertEqual([str(fixed)], [str(path) for path in GENERATOR._topology_air_json_files()])

    def test_dynamic_inventory_finds_only_the_fixed_name(self):
        with tempfile.TemporaryDirectory() as directory:
            output = self.output_dir(Path(directory))
            inventory = output.parent / "02-devices_config.csv"
            inventory.write_text("hostname,type\n", encoding="utf-8")
            stale = output / f"{STEM}-air.json"
            stale.write_text(json.dumps(air_document("AIR-STALE01")), encoding="utf-8")
            self.assertIsNone(DYNAMIC.find_air_json(inventory))
            fixed = output / "p2p-air.json"
            fixed.write_text(json.dumps(air_document()), encoding="utf-8")
            os.utime(stale)
            self.assertEqual(fixed, DYNAMIC.find_air_json(inventory))


class PointerReaderTests(unittest.TestCase):
    """R-016 §5.1 / R16-06: the project is the pointer's, also when a project input links outside it."""

    def test_mini_list_is_resolved_in_the_pointer_project(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            paths = prepare_runtime(root, write_air_workbook)
            project, _work = pointer_tree(root)
            # ztp/config/cumulus/02-devices_config.csv is setup's tree link to the project's (outside) 02.
            paths["devices"].unlink()
            tree_link(root, "ztp/config/cumulus/template/02-devices_config.csv", "02-devices_config.csv")
            for key, name in (("inventory", "01-inventory.log"), ("port_map", "02-port-mapping.log"),
                              ("air_template", "air-template-no-oob.json")):
                paths[key].write_bytes((P2P_DIR / name).read_bytes())
            customer = project / "customer-mini.txt"
            customer.write_text("EXAMPLE-OOB-SPINE01\n", encoding="utf-8")
            seen = []

            class Reached(Exception):
                pass

            def capture(*_args, **kwargs):
                seen.append(kwargs.get("mini_devices_file"))
                raise Reached()

            with mock.patch.object(PRODUCER, "generate_air_dot", side_effect=capture):
                caught, stdout, stderr = invoke_main(paths, [
                    "-y", "--deployment-scope", "air", "--os-version", "5.16.4", "--mini", str(customer),
                ])
            self.assertIsInstance(caught, Reached, (caught, stdout, stderr))
            self.assertEqual([str(customer)], [str(item) for item in seen])

    def test_mini_fallback_list_is_the_pointer_projects(self):
        from test_cases import test_air_retained_servers_contract as RETAINED

        producer = PRODUCER
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            project, work = pointer_tree(root)
            devices = tree_link(root, "ztp/config/cumulus/02-devices_config.csv", "02-devices_config.csv")
            source = root / "lldpq.dot"
            source.write_text("".join(
                f'"{left}":"{left_port}" -- "{right}":"{right_port}"\n'
                for left, left_port, right, right_port in RETAINED.SOURCE_EDGES
            ), encoding="utf-8")
            template = root / "air-template.json"
            template.write_text(json.dumps(RETAINED._template()), encoding="utf-8")
            policy_file = project / "03-air-topology-policy.json"
            policy_file.write_text(json.dumps(RETAINED._mini_policy()), encoding="utf-8")
            patterns, order = producer.load_inventory(RETAINED.INVENTORY)
            policy = producer.load_air_topology_policy(policy_file, project_root=project)
            with mock.patch.multiple(producer, HTTP_ROOT=root, DEVICES_CONFIG=str(devices)), \
                    redirect_stdout(io.StringIO()):
                producer.generate_air_dot(
                    source, root / "air.dot", patterns, order, template_file=template,
                    air_topology_policy=policy, mini=True, mini_devices_file=None,
                )
            self.assertTrue((project / "04-air-mini-devices.txt").is_file())
            self.assertFalse((work / "04-air-mini-devices.txt").exists())

    def dhcp_tree(self, root: Path):
        project, work = pointer_tree(root, outside_inventory=False)
        (project / "01-global.yaml").unlink()
        (work / "global.yaml").write_text("common: {}\n", encoding="utf-8")
        (project / "01-global.yaml").symlink_to(work / "global.yaml")
        output = project / "99-output-dhcp"
        output.mkdir()
        bindings = {"HTTP_ROOT": str(root)}
        for constant, name in (("GLOBAL_YAML", "01-global.yaml"),):
            bindings[constant] = str(tree_link(root, "ztp/config/isc-dhcp-server/" + name, name))
        for constant, name in (("OUTPUT_CONF", "dhcpd.conf"), ("OUTPUT_ETH", "dhcpd_eth.hosts"),
                               ("OUTPUT_IB", "dhcpd_ib.hosts"), ("OUTPUT_NVL", "dhcpd_nvl.hosts"),
                               ("OUTPUT_MANIFEST", "dhcp-release-manifest.json")):
            (output / name).write_text("fixture\n", encoding="utf-8")
            bindings[constant] = str(tree_link(root, "ztp/config/isc-dhcp-server/" + name, "99-output-dhcp/" + name))
        candidate = root / "DAY0-Prepare" / PROJECT / "99-output-dhcp/.load-dhcp-candidate-0123456789abcdef"
        candidate.mkdir(mode=0o700)
        return project, bindings, candidate

    def test_dhcp_candidate_belongs_to_the_pointer_project(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            project, bindings, candidate = self.dhcp_tree(root)
            with mock.patch.multiple(DHCP, **bindings):
                try:
                    located = DHCP._private_candidate_location(str(candidate))
                except ValueError as exc:
                    self.fail(f"R-016 §5.1: the pointer names the current project: {exc}")
                self.assertEqual((str(candidate), str(root / "DAY0-Prepare"), PROJECT, candidate.name), located)
                # R-016 §5.1: without the pointer there is no current project; an invalid one is an error.
                pointer = root / "DAY0-Prepare/activate-project"
                pointer.unlink()
                with self.assertRaisesRegex(ValueError, "current project"):
                    DHCP._private_candidate_location(str(candidate))
                pointer.symlink_to("template")
                with self.assertRaises(ValueError):
                    DHCP._private_candidate_location(str(candidate))

    def backup_tree(self, root: Path):
        project, work = pointer_tree(root)
        (project / "99-output-p2p").mkdir()
        (project / "99-output-p2p/p2p-air.json").write_text(json.dumps(air_document()), encoding="utf-8")
        inventory = tree_link(root, "ztp/backup/02-devices_config.csv", "02-devices_config.csv")
        leases = root / "dhcpd.leases"
        leases.write_text(
            f"lease {AIR_LEASE} {{\n  binding state active;\n  hardware ethernet {AIR_MAC};\n}}\n",
            encoding="utf-8",
        )
        return project, work, inventory, leases

    def test_backup_finds_the_air_json_of_the_pointer_project(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _project, work, inventory, leases = self.backup_tree(root)
            # The older layout's reading would look beside the outside inventory file.
            (work / "99-output-p2p").mkdir()
            (work / "99-output-p2p/p2p-air.json").write_text(
                json.dumps(air_document("AIR-OUTSIDE01", "02:00:00:00:00:61")), encoding="utf-8",
            )
            with mock.patch.object(BACKUP, "HTTP_ROOT", str(root), create=True):
                resolved, warnings = BACKUP.load_dynamic_air_backup_devices(inventory, leases)
            self.assertEqual([(AIR_NODE, AIR_LEASE)], [(item["hostname"], item["eth0_ip"]) for item in resolved])
            self.assertEqual([], warnings)

    def test_backup_static_lease_fallback_reads_the_pointer_project(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _project, work, inventory, leases = self.backup_tree(root)
            (work / "devices.csv").write_text(
                "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac\n"
                f"{AIR_NODE},air,fw,192.0.2.71,24,192.0.2.1,{AIR_MAC}\n", encoding="utf-8",
            )
            devices = [{"hostname": AIR_NODE, "fmt": "air", "eth0_ip": "192.0.2.71",
                        "eth0_mac": AIR_MAC, "alternate_ssh_ips": []}]
            with mock.patch.object(BACKUP, "HTTP_ROOT", str(root), create=True):
                BACKUP.apply_static_air_lease_fallbacks(devices, inventory, leases)
            self.assertEqual([AIR_LEASE], devices[0].get("transition_ssh_ips"))

    def test_backup_without_an_active_project_finds_no_air_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _project, _work, inventory, leases = self.backup_tree(root)
            (root / "DAY0-Prepare/activate-project").unlink()
            with mock.patch.object(BACKUP, "HTTP_ROOT", str(root), create=True):
                resolved, _warnings = BACKUP.load_dynamic_air_backup_devices(inventory, leases)
            self.assertEqual([], resolved)

    def test_feedback_without_inputs_discovers_the_pointer_project(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            project, _work = pointer_tree(root)
            (root / "ztp/optimize").mkdir(parents=True)
            with mock.patch.object(FEEDBACK, "__file__", str(root / "ztp/optimize/feedback.py")):
                plan = FEEDBACK.discover_sample_inputs([])
                self.assertIsNotNone(plan.project, "R-016 §5.1: the pointer names the project")
                self.assertEqual(project, Path(plan.project))
                (root / "DAY0-Prepare/activate-project").unlink()
                self.assertIsNone(FEEDBACK.discover_sample_inputs([]).project)



if __name__ == "__main__":
    unittest.main()
