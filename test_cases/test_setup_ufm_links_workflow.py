"""Workflow: setup creates every UFM input link in the tool's and the monitor's own directory, unsetup
removes them, and the contract tables know them (owner principle 1, 2026-10-22: a script's default
inputs are links in its own directory, created ahead by setup).

The expected link texts are the ones the owner's environment test used (UFM-环境测试-20261022
step0-links.sh), written out here independently of tools/project_contract.py."""

from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
import io
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
SETUP = load_script("ufm_links_setup_flow", ROOT / "DAY0-Prepare/01-a-setup.py")
UNSETUP = load_script("ufm_links_unsetup_flow", ROOT / "DAY0-Prepare/02-unsetup.py")
CONTRACT = SETUP.sys.modules["project_contract"]
PACKAGE = load_script("ufm_links_package_common", ROOT / "tools/_package_common.py")
AUDIT = load_script("ufm_links_public_audit", ROOT / "test_cases/audit_public_tree.py")

PROJECT = "site-a"
TOOL = "infiniband/bringup/ufm-setup-upgrade"
# link -> (exact link text, what it must resolve to: project-relative path, or "/image" for http/image)
EXPECTED_LINKS = {
    f"{TOOL}/ib.csv": ("../../ib.csv", "02-devices_config.csv"),
    f"{TOOL}/p2p.xlsx": ("../../p2p.xlsx", "p2p.xlsx"),
    f"{TOOL}/ufm-setup-upgrade-logs": (
        f"../../../DAY0-Prepare/{PROJECT}/99-output-ib_nvl/bringup/ufm-setup-upgrade-logs",
        "99-output-ib_nvl/bringup/ufm-setup-upgrade-logs"),
    f"{TOOL}/image": ("../../../image", "/image"),
    "infiniband/monitor/ufm-info": (
        f"../../DAY0-Prepare/{PROJECT}/99-output-monitor/infiniband/ufm-info",
        "99-output-monitor/infiniband/ufm-info"),
    "infiniband/monitor/ufm-ibdiagnet": (
        f"../../DAY0-Prepare/{PROJECT}/99-output-monitor/infiniband/ufm-ibdiagnet",
        "99-output-monitor/infiniband/ufm-ibdiagnet"),
    "infiniband/monitor/01-global.yaml": ("../01-global.yaml", "01-global.yaml"),
    "infiniband/monitor/99-output-p2p": (f"../../DAY0-Prepare/{PROJECT}/99-output-p2p", "99-output-p2p"),
    "ztp/config/nvos/template/P2P/02-devices_config.csv": (
        f"../../../../../DAY0-Prepare/{PROJECT}/02-devices_config.csv", "02-devices_config.csv"),
}
# Tracked repository bridges, like xdr-initial-setup's: never created or removed by setup/unsetup.
BRIDGES = {f"{TOOL}/01-global.yaml": "../../01-global.yaml", f"{TOOL}/publickey": "../../publickey"}


def build_tree(root: Path) -> Path:
    project = root / "DAY0-Prepare" / PROJECT
    (project / "99-output-p2p").mkdir(parents=True)
    (project / "01-global.yaml").write_bytes(b"servers:\n  - ufm:\n      vip: 192.0.2.10\n")
    (project / "02-devices_config.csv").write_bytes(b"hostname,type\nufm01.example.test,server_ufm\n")
    (project / "p2p.xlsx").write_bytes(b"fixture workbook\n")
    (root / "infra").mkdir()                      # unsetup's log-root gate expects a checkout layout
    (root / "image").mkdir()
    (root / "image/ufm.lic").write_bytes(b"fixture license\n")
    infiniband = root / "infiniband"
    (infiniband / "publickey").mkdir(parents=True)
    # The P2P input alias and the workspace global are made by other setup stages tested elsewhere.
    (infiniband / "p2p.xlsx").symlink_to(f"../DAY0-Prepare/{PROJECT}/p2p.xlsx")
    (infiniband / "01-global.yaml").symlink_to(f"../DAY0-Prepare/{PROJECT}/01-global.yaml")
    tool = root / TOOL
    tool.mkdir(parents=True)
    for name, text in BRIDGES.items():
        (root / name).symlink_to(text)
    (root / "ztp/config/nvos/template/P2P").mkdir(parents=True)
    return project


def setup_patches(root: Path) -> dict:
    """Every module-level table of 01-a-setup.py that was computed from the real checkout."""
    def under(pairs):
        return [(os.path.join(root, os.path.relpath(path, SETUP.HTTP_BASE)), target) for path, target in pairs]

    return dict(
        HTTP_BASE=str(root), HERE=str(root / "DAY0-Prepare"), ZTP=str(root / "ztp"),
        IMAGE_DIR=str(root / "image"), MANIFEST_FILE=str(root / "ztp/.setup_manifest"),
        _CSV_DIR=None, _DRY_RUN=False, _AUTO_YES=True, _LINK_ERRORS=0, _LINK_TRANSACTION=None,
        P2P_INPUT_LINKS=[str(root / name) for name in CONTRACT.P2P_INPUT_PATHS],
        P2P_OUTPUT_LINKS=[str(root / name) for name in CONTRACT.P2P_OUTPUT_PATHS],
        P2P_AIR_JSON_LINK=str(root / CONTRACT.P2P_AIR_PATH),
        BRINGUP_OUTPUT_MAPPINGS=under(SETUP.BRINGUP_OUTPUT_MAPPINGS),
        ANALYZER_INPUT_MAPPINGS=under(SETUP.ANALYZER_INPUT_MAPPINGS),
        ANALYZER_OUTPUT_MAPPINGS=under(SETUP.ANALYZER_OUTPUT_MAPPINGS),
        _NET_CSV_LINKS=under(SETUP._NET_CSV_LINKS),
    )


def run_setup_link_stages(root: Path, project: Path) -> None:
    with ExitStack() as stack:
        stack.enter_context(mock.patch.multiple(SETUP, **setup_patches(root)))
        # _process_mapping's link_root default was bound to the real ztp/ at import time.
        stack.enter_context(mock.patch.object(SETUP._process_mapping, "__defaults__", (None, str(root / "ztp"))))
        stack.enter_context(redirect_stdout(io.StringIO()))
        converter_inputs = [row for row in SETUP.MAPPINGS
                            if row[0] == "config/nvos/template/P2P/02-devices_config.csv"]
        if converter_inputs != [("config/nvos/template/P2P/02-devices_config.csv", "02-devices_config.csv",
                                 "file_csv")]:
            raise AssertionError(f"setup does not map the converter's devices input: {converter_inputs}")
        for ztp_rel, proj_rel, kind in converter_inputs:
            SETUP._process_mapping(str(project), ztp_rel, proj_rel, kind, link_root=str(root / "ztp"))
        SETUP._process_bringup_links(str(project))
        SETUP._process_bringup_input_links(str(project))
        SETUP._process_bringup_image_links()
        SETUP._process_net_csv_links(str(project))
        SETUP._process_monitor_links(str(project))
        if SETUP._LINK_ERRORS:
            raise AssertionError(f"setup reported {SETUP._LINK_ERRORS} link error(s)")


class SetupCreatesUfmInputLinksWorkflowTest(unittest.TestCase):
    def test_setup_links_every_ufm_input_and_unsetup_removes_them_but_not_the_bridges(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = build_tree(root)
            run_setup_link_stages(root, project)

            for name, (text, target) in EXPECTED_LINKS.items():
                link = root / name
                with self.subTest(link=name):
                    self.assertTrue(link.is_symlink(), name)
                    self.assertEqual(text, os.readlink(link))
                    expected = root / "image" if target == "/image" else project / target
                    self.assertEqual(expected.resolve(), link.resolve())
                    self.assertTrue(link.exists(), "the target exists after setup")
            self.assertEqual((root / TOOL / "image/ufm.lic").read_bytes(), b"fixture license\n")
            for name, text in BRIDGES.items():
                self.assertEqual(text, os.readlink(root / name))
            self.assertEqual((project / "01-global.yaml").resolve(), (root / TOOL / "01-global.yaml").resolve())

            with mock.patch.multiple(SETUP, **setup_patches(root)):
                expected_links = {os.path.relpath(path, root) for path in SETUP._collect_expected_links(str(project))}
            self.assertLessEqual(set(EXPECTED_LINKS), expected_links,
                                 "conflict detection and the setup manifest must know every UFM link")
            self.assertFalse(set(BRIDGES) & expected_links, "tracked bridges are not setup output")

            with mock.patch.multiple(
                UNSETUP, HTTP_BASE=str(root), HERE=str(root / "DAY0-Prepare"), ZTP=str(root / "ztp"),
                MANIFEST_FILE=str(root / "ztp/.setup_manifest"), _AUTO_YES=True, _DRY_RUN=False,
            ), redirect_stdout(io.StringIO()):
                result = UNSETUP._main_locked(SimpleNamespace(project=None))

            self.assertEqual(0, result)
            for name in EXPECTED_LINKS:
                with self.subTest(removed=name):
                    self.assertFalse(os.path.lexists(root / name), name)
            for name, text in BRIDGES.items():
                self.assertEqual(text, os.readlink(root / name), "unsetup keeps tracked bridges")
            self.assertEqual(b"fixture license\n", (root / "image/ufm.lic").read_bytes())
            self.assertTrue((project / "99-output-monitor/infiniband/ufm-ibdiagnet").is_dir(), "data stays")
            self.assertEqual(b"fixture workbook\n", (project / "p2p.xlsx").read_bytes())

    def test_without_a_shared_image_directory_the_image_link_is_skipped_not_dangling(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = build_tree(root)
            shutil.rmtree(root / "image")
            run_setup_link_stages(root, project)
            self.assertFalse(os.path.lexists(root / TOOL / "image"))
            self.assertTrue((root / TOOL / "ib.csv").is_symlink())


class UfmLinkContractTest(unittest.TestCase):
    def test_runtime_and_published_specs_name_every_ufm_link_with_its_exact_text(self):
        runtime = dict(CONTRACT.runtime_link_specs())
        for name, (text, target) in EXPECTED_LINKS.items():
            with self.subTest(name=name):
                if target == "/image":
                    # Shared and project independent: not a producer binding; the image build still
                    # denies it through the whole bringup subtree.
                    self.assertNotIn(name, runtime)
                    self.assertTrue(any(name.startswith(tree + "/")
                                        for tree in CONTRACT.IMAGE_HOST_STATE_SUBTREES), name)
                    continue
                self.assertEqual(text.replace(PROJECT, "{project}"), runtime[name])
                self.assertIn(name, CONTRACT.IMAGE_HOST_STATE_PATHS)
        published = {name: (target, project_target)
                     for name, target, project_target in CONTRACT.published_runtime_link_specs()}
        # The monitor runs inside the container too: Docker activation binds these four.
        for name in ("infiniband/monitor/ufm-info", "infiniband/monitor/ufm-ibdiagnet",
                     "infiniband/monitor/01-global.yaml", "infiniband/monitor/99-output-p2p"):
            text, target = EXPECTED_LINKS[name]
            with self.subTest(published=name):
                self.assertEqual((text.replace(PROJECT, "{project}"), target), published[name])
        for name in (f"{TOOL}/ib.csv", f"{TOOL}/p2p.xlsx", f"{TOOL}/image"):
            self.assertNotIn(name, published, "the deployment tool runs on the host only")

    def test_packaging_and_the_public_audit_know_the_tool_links(self):
        for name in (f"{TOOL}/ib.csv", f"{TOOL}/p2p.xlsx", f"{TOOL}/ufm-setup-upgrade-logs", f"{TOOL}/image",
                     *BRIDGES):
            self.assertIn(name, PACKAGE.STATIC_SETUP_MANAGED_LINKS)
        for name, text in BRIDGES.items():
            self.assertTrue((ROOT / name).is_symlink(), f"{name} is a repository bridge")
            self.assertEqual(text, os.readlink(ROOT / name))
            self.assertIn(name, AUDIT.SETUP_RUNTIME_BRIDGES)
            self.assertEqual(text, AUDIT.SETUP_RUNTIME_BRIDGES[name][0])


class SetupInventoryAcceptsServerTypesTest(unittest.TestCase):
    """Owner 2026-10-19: server_ufm uses only the first 7 columns; server_mgmt is the new name of server."""

    def write_project(self, directory: Path, rows: list[list[str]]) -> Path:
        shutil.copy2(ROOT / "DAY0-Prepare/template/01-global.yaml", directory / "01-global.yaml")
        header = (ROOT / "DAY0-Prepare/template/02-devices_config.csv").read_text(
            encoding="utf-8-sig").splitlines()[0]
        width = len(header.split(","))
        lines = [header] + [",".join(row + [""] * (width - len(row))) for row in rows]
        path = directory / "02-devices_config.csv"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def errors_for(self, rows):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_project(Path(directory), rows)
            with redirect_stdout(io.StringIO()):
                errors, _warnings = SETUP._validate_eth_csv(str(path))
        return errors

    UFM = ["ufm01.example.test", "server_ufm", "", "192.0.2.21", "24", "192.0.2.1", "02:00:00:00:00:21"]
    MGMT = ["mgmt01.example.test", "server_mgmt", "", "192.0.2.31", "24", "192.0.2.1", "02:00:00:00:00:31"]

    def test_server_ufm_and_server_mgmt_rows_with_only_seven_columns_are_valid(self):
        second = ["ufm02.example.test", "server_ufm", "", "192.0.2.22", "/24", "192.0.2.1", "02:00:00:00:00:22"]
        self.assertEqual([], self.errors_for([self.UFM, second, self.MGMT]))

    def test_server_ufm_rows_are_still_format_checked(self):
        cases = {
            "eth0_mac": self.UFM[:6] + ["not-a-mac"],
            "eth0_gw": self.UFM[:5] + ["", self.UFM[6]],
            "netmask": self.UFM[:4] + ["", *self.UFM[5:]],
            "eth0_ip": self.UFM[:3] + ["192.0.2.21/24", *self.UFM[4:]],
        }
        for field, row in cases.items():
            with self.subTest(field=field):
                errors = self.errors_for([row])
                self.assertTrue(any(field in error for error in errors), errors)
        duplicate = self.MGMT[:6] + [self.UFM[6]]
        errors = self.errors_for([self.UFM, duplicate])
        self.assertTrue(any("eth0_mac 重复" in error for error in errors), errors)

    def test_an_unknown_type_is_still_rejected(self):
        errors = self.errors_for([["ufm01.example.test", "ufm", "", "192.0.2.21", "24", "192.0.2.1",
                                   "02:00:00:00:00:21"]])
        self.assertTrue(any("type 无效" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
