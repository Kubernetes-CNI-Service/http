"""I-027, R-014 第 1、2 条 (v3.1.1 WP-2): setup's link reconcile engine and its one template completion.

Every expected value is written from the design, never read back from the implementation:
- R-016 详细设计 v1.1 §4.3, the four cases per position: nothing there -> temporary link + os.replace; a link
  whose text is already canonical -> untouched; any other link (elsewhere, absolute, roundabout) -> atomically
  replaced, the output naming old -> new; a real file or directory -> error, counted, not interrupted, never
  deleted (owner 2026-11-03).  "已正确" is judged by the link text only; leftover .<name>.tmp.* of any process go
  first.
- R-014 第 1 条 (owner 2026-11-02): 「如果发现需要创建的链接已经存在，那么可以先解开再创建」 -- no prompt.
- R-014 第 2 条 / I-027 (owner 2026-11-02): 「不向指向外部目录的链接里写东西」; I-027's message
  「跳过：<路径> 是指向项目外的链接」; project-internal links are allowed.  R-014 验收: a project whose p2p/ is a
  link to an outside directory passes setup without --force.
- R-016 §3.4: optional rows may dangle; the v3.1.1 详细工作指导 WP-1 rows that no older setup stage made.
- 详细工作指导 WP-2: one template completion (setup's): only missing items, conflicts reported and counted,
  laptop.pub never copied, .bin placeholders still copied (R-013 第 2 条), dry-run only prints; the setup entry and
  the load entry complete a project byte for byte alike.  WP-1's hint: one link per project key in each of the four
  public-key directories, only that link removed when the key goes, a real file there reported and kept.
- review S1, http dev 2026-11-08 (改法 (a)): load's configuration-only key preflight runs before setup and accepts
  only an empty regular laptop.pub placeholder (11-load.py::_prepare_pubkeys_without_management_injection); so the
  load entry, after the one completion, adds that 0-byte regular file where nothing is at laptop.pub, as the v3.1.0
  load (f741269) did, and leaves a link, a directory or any file there alone; setup itself still never copies it.
  Under dry-run it writes nothing.  The two entries therefore differ by that one placeholder only.
"""

from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
import io
import os
from pathlib import Path
import re
import stat
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
SETUP = load_script("setup_link_reconcile_setup", ROOT / "DAY0-Prepare/01-a-setup.py")
LOAD = load_script("setup_link_reconcile_load", ROOT / "DAY0-Prepare/11-load.py")
CONTRACT = load_script("setup_link_reconcile_project_contract", ROOT / "tools/project_contract.py")

PROJECT = "site-a"
OUTSIDE_MESSAGE = "指向项目外的链接"  # I-027: 「跳过：<路径> 是指向项目外的链接」
PUBLICKEY_DIRECTORIES = ("ztp/config/publickey", "ethernet/publickey", "infiniband/publickey", "nvlink/publickey")
# 详细工作指导 WP-1 rows written out (tree link -> exact text: since WP-3 the project rows go through
# DAY0-Prepare/activate-project, R-016 §2 / O4 left column; the repository aliases keep their text).
NEW_ROW_TEXTS = {
    "ethernet/01-global.yaml": "../DAY0-Prepare/activate-project/01-global.yaml",
    "nvlink/01-global.yaml": "../DAY0-Prepare/activate-project/01-global.yaml",
    "ethernet/monitor/01-global.yaml": "../01-global.yaml",
    "nvlink/monitor/01-global.yaml": "../01-global.yaml",
    "ethernet/monitor/99-output-p2p": "../../DAY0-Prepare/activate-project/99-output-p2p",
    "nvlink/monitor/99-output-p2p": "../../DAY0-Prepare/activate-project/99-output-p2p",
    "ethernet/02-devices_config.csv": "../DAY0-Prepare/activate-project/02-devices_config.csv",
    "infiniband/02-devices_config.csv": "../DAY0-Prepare/activate-project/02-devices_config.csv",
    "nvlink/02-devices_config.csv": "../DAY0-Prepare/activate-project/02-devices_config.csv",
    "ethernet/monitor/04-device-aliases.csv": "../../DAY0-Prepare/activate-project/04-device-aliases.csv",
    "infiniband/monitor/04-device-aliases.csv": "../../DAY0-Prepare/activate-project/04-device-aliases.csv",
    "nvlink/monitor/04-device-aliases.csv": "../../DAY0-Prepare/activate-project/04-device-aliases.csv",
    "ethernet/monitor/eth-status": "../../DAY0-Prepare/activate-project/99-output-monitor/ethernet/eth-status",
    "infiniband/monitor/ib-status": "../../DAY0-Prepare/activate-project/99-output-monitor/infiniband/ib-status",
    "infiniband/monitor/ufm-status": "../../DAY0-Prepare/activate-project/99-output-monitor/infiniband/ufm-status",
    "nvlink/monitor/nvsw-status": "../../DAY0-Prepare/activate-project/99-output-monitor/nvlink/nvsw-status",
    "infiniband/bringup/99-output-bringup": "../../DAY0-Prepare/activate-project/99-output-bringup",
    "infiniband/bringup/xdr-initial-setup/ib.csv": "../../ib.csv",
    "infiniband/bringup/xdr-initial-setup/p2p.xlsx": "../../p2p.xlsx",
}
# R-016 §3.4 "准备步骤负责建": the project directories behind the new prepared rows.
NEW_PREPARED_DIRECTORIES = (
    "99-output-monitor/ethernet/eth-status", "99-output-monitor/infiniband/ib-status",
    "99-output-monitor/infiniband/ufm-status", "99-output-monitor/nvlink/nvsw-status", "99-output-bringup",
)
# R-016 §3.4 "可选": the G14-1 alias tables may not exist.
OPTIONAL_ALIAS_ROWS = ("ethernet/monitor/04-device-aliases.csv", "infiniband/monitor/04-device-aliases.csv",
                       "nvlink/monitor/04-device-aliases.csv")


def engine():
    if not hasattr(SETUP, "_reconcile_links"):
        raise AssertionError("R-016 §4.3: setup has one link reconcile engine, _reconcile_links")
    return SETUP._reconcile_links


def build_tree(root: Path, *, template: dict[str, bytes] | None = None) -> Path:
    """A checkout-shaped root with one complete project and a synthetic template."""
    project = root / "DAY0-Prepare" / PROJECT
    project.mkdir(parents=True)
    for name, data in (("01-global.yaml", b"synthetic: global\n"),
                       ("02-devices_config.csv", b"hostname,type\nleaf-01,eth\n"),
                       ("02-dhcp-subnet_config.csv", b"shared_network,subnet\n"),
                       ("p2p.xlsx", b"synthetic workbook\n"),
                       ("laptop.pub", b"ssh-ed25519 AAAAsyntheticlaptop operator@laptop\n")):
        (project / name).write_bytes(data)
    template_dir = root / "DAY0-Prepare/template"
    template_dir.mkdir()
    for name, data in (template or {}).items():
        (template_dir / name).parent.mkdir(parents=True, exist_ok=True)
        (template_dir / name).write_bytes(data)
    (root / "infra").mkdir()
    for tool in ("tools/lldp-analyze-tool", "tools/ibdiagnet-analyze-tool"):
        (root / tool).mkdir(parents=True)
    return project


def setup_globals(root: Path) -> dict:
    """Every module-level path of 01-a-setup.py that was computed from the real checkout, re-rooted."""
    def under(pairs):
        return [(str(root / os.path.relpath(path, SETUP.HTTP_BASE)), target) for path, target in pairs]

    return dict(
        HTTP_BASE=str(root), HERE=str(root / "DAY0-Prepare"), ZTP=str(root / "ztp"),
        IMAGE_DIR=str(root / "image"), TEMPLATE_DIR=str(root / "DAY0-Prepare/template"),
        MANIFEST_FILE=str(root / "ztp/.setup_manifest"),
        _DRY_RUN=False, _AUTO_YES=False, _CONFIRM_PROJECT_SWITCH=False, _NO_UPGRADE=False,
        _LINK_ERRORS=0, _P2P_SOURCE=None, _INFRA_LOG_MIGRATION=None,
        P2P_INPUT_LINKS=[str(root / name) for name in SETUP.P2P_INPUT_PATHS],
        P2P_OUTPUT_LINKS=[str(root / name) for name in SETUP.P2P_OUTPUT_PATHS],
        P2P_AIR_JSON_LINK=str(root / SETUP.P2P_AIR_PATH),
        BRINGUP_OUTPUT_MAPPINGS=under(SETUP.BRINGUP_OUTPUT_MAPPINGS),
        ANALYZER_INPUT_MAPPINGS=under(SETUP.ANALYZER_INPUT_MAPPINGS),
        ANALYZER_OUTPUT_MAPPINGS=under(SETUP.ANALYZER_OUTPUT_MAPPINGS),
        _NET_CSV_LINKS=under(SETUP._NET_CSV_LINKS),
    )


def no_prompt(*_args, **_kwargs):
    raise AssertionError("R-014 第 1 条: setup never asks before replacing a managed link")


def run_setup(root: Path, project: Path) -> tuple[str, int, object]:
    """The real _setup_impl; only input validation, the operator key and the closing hints are inert.

    Returns (output, link errors, SystemExit code or None when setup ran to its end).
    """
    output = io.StringIO()
    exited = None
    with ExitStack() as stack:
        stack.enter_context(mock.patch.multiple(SETUP, **setup_globals(root)))
        for name, value in (("_require_r22_subnet_input", (False, False, "fixture")),
                            ("_r22_subnet_source_fingerprint", "fixture"),
                            ("_validate_project", True),
                            ("_select_p2p_source", str(project / "p2p.xlsx"))):
            stack.enter_context(mock.patch.object(SETUP, name, return_value=value))
        for name in ("_prepare_laptop_public_key", "_print_next_steps"):
            stack.enter_context(mock.patch.object(SETUP, name))
        stack.enter_context(mock.patch("builtins.input", side_effect=no_prompt))
        stack.enter_context(redirect_stdout(output))
        try:
            SETUP._setup_impl(str(project))
        except SystemExit as stop:
            exited = stop.code
        errors = SETUP._LINK_ERRORS
    return output.getvalue(), errors, exited


def listing(directory: Path) -> dict[str, bytes]:
    return {os.path.relpath(os.path.join(base, name), directory): Path(base, name).read_bytes()
            for base, _dirs, files in os.walk(directory) for name in files}


def snapshot(project: Path) -> dict[str, tuple]:
    """Type, bytes or link text, and mode of everything below project, never following a link."""
    result = {}
    for base, dirnames, filenames in os.walk(project, followlinks=False):
        for name in dirnames + filenames:
            path = os.path.join(base, name)
            metadata = os.lstat(path)
            relative = os.path.relpath(path, project)
            if stat.S_ISLNK(metadata.st_mode):
                result[relative] = ("link", os.readlink(path))
            elif stat.S_ISDIR(metadata.st_mode):
                result[relative] = ("dir", stat.S_IMODE(metadata.st_mode))
            else:
                result[relative] = ("file", Path(path).read_bytes(), stat.S_IMODE(metadata.st_mode))
    return result


class ReconcileEngineTest(unittest.TestCase):
    """R-016 §4.3: the four cases, one position at a time."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.project = self.root / "DAY0-Prepare" / PROJECT
        self.project.mkdir(parents=True)
        (self.project / "02-devices_config.csv").write_bytes(b"inventory\n")
        patches = mock.patch.multiple(SETUP, HTTP_BASE=str(self.root), HERE=str(self.root / "DAY0-Prepare"),
                                      ZTP=str(self.root / "ztp"), _DRY_RUN=False, _AUTO_YES=False,
                                      _CONFIRM_PROJECT_SWITCH=False, _LINK_ERRORS=0)
        patches.start()
        self.addCleanup(patches.stop)
        prompt = mock.patch("builtins.input", side_effect=no_prompt)
        prompt.start()
        self.addCleanup(prompt.stop)
        self.link = self.root / "ethernet/eth.csv"
        self.text = "../DAY0-Prepare/site-a/02-devices_config.csv"

    def reconcile(self, entries) -> str:
        output = io.StringIO()
        with redirect_stdout(output):
            engine()([(str(link), text) for link, text in entries])
        return output.getvalue()

    def test_an_absent_position_gets_the_exact_text_through_a_temporary_link_and_replace(self):
        replace = mock.Mock(wraps=os.replace)
        with mock.patch.object(SETUP.os, "replace", replace):
            self.reconcile([(self.link, self.text)])
        self.assertEqual(self.text, os.readlink(self.link))
        self.assertIn(str(self.link), [os.fspath(call.args[1]) for call in replace.call_args_list],
                      "R-016 §4.3: a new link lands by os.replace of a temporary link")
        self.assertEqual([], [name for name in os.listdir(self.link.parent) if ".tmp." in name])
        self.assertEqual(0, SETUP._LINK_ERRORS)

    def test_a_link_whose_text_is_already_canonical_is_left_alone(self):
        self.link.parent.mkdir(parents=True)
        self.link.symlink_to(self.text)
        before = os.lstat(self.link)
        self.reconcile([(self.link, self.text)])
        after = os.lstat(self.link)
        self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))
        self.assertEqual(0, SETUP._LINK_ERRORS)

    def test_any_other_text_is_replaced_atomically_without_a_prompt_and_reported_old_to_new(self):
        foreign = self.root / "DAY0-Prepare/site-b"
        foreign.mkdir()
        (foreign / "02-devices_config.csv").write_bytes(b"other project\n")
        cases = {
            "another project": "../DAY0-Prepare/site-b/02-devices_config.csv",
            # Same real file as the canonical text: the text alone decides (R-016 §4.3).
            "absolute path": str(self.project / "02-devices_config.csv"),
            "roundabout": "../ethernet/../DAY0-Prepare/site-a/02-devices_config.csv",
        }
        self.link.parent.mkdir(parents=True)
        for label, old in cases.items():
            with self.subTest(case=label):
                if os.path.lexists(self.link):
                    self.link.unlink()
                self.link.symlink_to(old)
                replace = mock.Mock(wraps=os.replace)
                removed = []
                real_remove = os.remove

                def remove(path, *args, **kwargs):
                    removed.append(os.fspath(path))
                    return real_remove(path, *args, **kwargs)

                with mock.patch.object(SETUP.os, "replace", replace), \
                        mock.patch.object(SETUP.os, "remove", side_effect=remove), \
                        mock.patch.object(SETUP.os, "unlink", side_effect=remove):
                    output = self.reconcile([(self.link, self.text)])
                self.assertEqual(self.text, os.readlink(self.link))
                self.assertNotIn(str(self.link), removed, "the old link is replaced, never removed first")
                self.assertIn(str(self.link), [os.fspath(call.args[1]) for call in replace.call_args_list])
                self.assertRegex(output, re.escape(old) + r"\s*(→|->)\s*" + re.escape(self.text),
                                 "R-014 第 1 条: the output names old -> new")
                self.assertEqual(0, SETUP._LINK_ERRORS)

    def test_a_real_file_or_directory_is_reported_counted_kept_and_later_rows_still_run(self):
        occupied_file = self.root / "infiniband/ib.csv"
        occupied_file.parent.mkdir(parents=True)
        occupied_file.write_bytes(b"operator-owned file\n")
        occupied_directory = self.root / "nvlink/nvsw.csv"
        (occupied_directory / "inner").mkdir(parents=True)
        output = self.reconcile([
            (occupied_file, "../DAY0-Prepare/site-a/02-devices_config.csv"),
            (occupied_directory, "../DAY0-Prepare/site-a/02-devices_config.csv"),
            (self.link, self.text),
        ])
        self.assertEqual(b"operator-owned file\n", occupied_file.read_bytes())
        self.assertTrue(occupied_directory.is_dir() and not occupied_directory.is_symlink())
        self.assertTrue((occupied_directory / "inner").is_dir())
        self.assertEqual(self.text, os.readlink(self.link), "the following row still runs")
        self.assertEqual(2, SETUP._LINK_ERRORS)
        self.assertIn(str(occupied_file), output)
        self.assertIn(str(occupied_directory), output)

    def test_leftover_temporary_links_of_any_process_are_removed_first(self):
        directory = self.link.parent
        directory.mkdir(parents=True)
        for case in ("already canonical", "absent"):
            with self.subTest(case=case):
                if os.path.lexists(self.link):
                    self.link.unlink()
                if case == "already canonical":
                    self.link.symlink_to(self.text)
                leftovers = [directory / f".eth.csv.tmp.{pid}" for pid in (1, os.getpid(), 999999)]
                for leftover in leftovers:
                    leftover.symlink_to("../DAY0-Prepare/site-b/02-devices_config.csv")
                self.reconcile([(self.link, self.text)])
                self.assertEqual(self.text, os.readlink(self.link))
                self.assertEqual([], [path.name for path in leftovers if os.path.lexists(path)])

    def test_dry_run_changes_nothing(self):
        wrong = self.root / "infiniband/ib.csv"
        wrong.parent.mkdir(parents=True)
        wrong.symlink_to("../DAY0-Prepare/site-b/02-devices_config.csv")
        with mock.patch.object(SETUP, "_DRY_RUN", True):
            self.reconcile([(self.link, self.text), (wrong, "../DAY0-Prepare/site-a/02-devices_config.csv")])
        self.assertFalse(os.path.lexists(self.link))
        self.assertEqual("../DAY0-Prepare/site-b/02-devices_config.csv", os.readlink(wrong))


class TableRowsTest(unittest.TestCase):
    """The engine walks every setup row of the G12 table, including the WP-1 rows no older stage made."""

    def test_setup_reconciles_every_setup_row_and_optional_rows_may_dangle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = build_tree(root)
            _output, errors, exited = run_setup(root, project)
            self.assertEqual((0, None), (errors, exited), "setup ran to its end")
            self.assertTrue((root / "ztp/.setup_manifest").is_file(), "setup completed")
            canonical = dict(CONTRACT.pointer_link_specs())
            rows = [row for row in CONTRACT.SETUP_LINK_SPECS if row.writer == "setup"]
            for row in rows:
                with self.subTest(row=row.path):
                    link = root / row.path
                    self.assertTrue(link.is_symlink(), "setup makes every setup row of the table")
                    self.assertEqual(canonical[row.path], os.readlink(link))
            for name, text in NEW_ROW_TEXTS.items():
                with self.subTest(new_row=name):
                    self.assertEqual(text, os.readlink(root / name))
            for name in NEW_PREPARED_DIRECTORIES:
                with self.subTest(prepared=name):
                    target = project / name
                    self.assertTrue(target.is_dir() and not target.is_symlink(), "the preparation step made it")
            for name in OPTIONAL_ALIAS_ROWS:
                with self.subTest(optional=name):
                    self.assertFalse((root / name).exists(), "an absent alias table dangles; not an error")

            identities = {row.path: os.lstat(root / row.path).st_ino for row in rows}
            _output, errors, exited = run_setup(root, project)
            self.assertEqual((0, None), (errors, exited))
            self.assertEqual(identities, {row.path: os.lstat(root / row.path).st_ino for row in rows},
                             "a second run leaves every canonical link alone")


class OutsideWritesTest(unittest.TestCase):
    """R-014 第 2 条 / I-027: nothing is written through a link that leaves the project."""

    TEMPLATE = {"p2p/README.txt": b"template guide\n", "99-output-p2p/.gitkeep": b"",
                "README.txt": b"project readme\n"}

    def outside(self, base: Path, name: str) -> Path:
        directory = base / name
        directory.mkdir()
        (directory / "owner-material.txt").write_bytes(b"owner material\n")
        return directory

    def test_an_external_p2p_directory_is_never_written_and_setup_still_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "http"
            project = build_tree(root, template=self.TEMPLATE)
            material = self.outside(base, "Work-material")
            (project / "p2p").symlink_to(material)
            output, errors, exited = run_setup(root, project)
            self.assertEqual({"owner-material.txt": b"owner material\n"}, listing(material))
            self.assertIn(OUTSIDE_MESSAGE, output)
            self.assertIn("p2p", output[output.index(OUTSIDE_MESSAGE) - 200:output.index(OUTSIDE_MESSAGE)])
            # R-014 验收: such a project passes setup without --force; the rest of the template still lands.
            self.assertEqual((0, None), (errors, exited))
            self.assertTrue((root / "ztp/.setup_manifest").is_file())
            self.assertEqual(b"project readme\n", (project / "README.txt").read_bytes())

    def test_external_p2p_and_99_output_p2p_directories_are_never_written(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "http"
            project = build_tree(root, template=self.TEMPLATE)
            material = self.outside(base, "Work-material")
            reports = self.outside(base, "shared-reports")
            (project / "p2p").symlink_to(material)
            (project / "99-output-p2p").symlink_to(reports)
            output, _errors, _exited = run_setup(root, project)
            self.assertEqual({"owner-material.txt": b"owner material\n"}, listing(material))
            self.assertEqual({"owner-material.txt": b"owner material\n"}, listing(reports))
            self.assertIn(OUTSIDE_MESSAGE, output)

    def test_the_setup_report_names_both_external_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "http"
            project = build_tree(root, template=self.TEMPLATE)
            (project / "p2p").symlink_to(self.outside(base, "Work-material"))
            (project / "99-output-p2p").symlink_to(self.outside(base, "shared-reports"))
            output = io.StringIO()
            with mock.patch.multiple(SETUP, **setup_globals(root)), redirect_stdout(output):
                SETUP._initialize_project_from_template(str(project))
            lines = [line for line in output.getvalue().splitlines() if OUTSIDE_MESSAGE in line]
            self.assertTrue(any("p2p" in line and "99-output" not in line for line in lines), lines)
            self.assertTrue(any("99-output-p2p" in line for line in lines), lines)

    def test_a_prepared_output_file_is_never_created_through_an_external_leaf_link(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "http"
            project = build_tree(root)
            outside = base / "elsewhere"
            outside.mkdir()
            (project / "99-output-dhcp").mkdir()
            (project / "99-output-dhcp/dhcpd.conf").symlink_to(outside / "dhcpd.conf")
            # v3.1.1 WP-3: setup's preparation step (R-016 §4.2 第 2 步) touches the table's prepared outputs.
            output, _errors, _exited = run_setup(root, project)
            self.assertEqual([], os.listdir(outside))
            self.assertIn(OUTSIDE_MESSAGE, output)

    def test_a_project_internal_link_is_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = build_tree(root, template=self.TEMPLATE)
            (project / "material/p2p").mkdir(parents=True)
            (project / "p2p").symlink_to("material/p2p")
            with mock.patch.multiple(SETUP, **setup_globals(root)), redirect_stdout(io.StringIO()):
                SETUP._initialize_project_from_template(str(project))
                self.assertEqual(0, SETUP._LINK_ERRORS)
            self.assertEqual(b"template guide\n", (project / "material/p2p/README.txt").read_bytes())


class PublicKeyLinksTest(unittest.TestCase):
    """WP-1's hint: one link per project key in each of the four real public-key directories."""

    def publish(self, root: Path, project: Path) -> int:
        # R16-13: the per-key links are refreshed after the switch, so the pointer names this project.
        pointer = root / "DAY0-Prepare/activate-project"
        if not pointer.is_symlink():
            pointer.symlink_to(project.name)
        with mock.patch.multiple(SETUP, HTTP_BASE=str(root), ZTP=str(root / "ztp"), _DRY_RUN=False,
                                 _AUTO_YES=False, _LINK_ERRORS=0), \
                mock.patch("builtins.input", side_effect=no_prompt), redirect_stdout(io.StringIO()):
            SETUP._process_pubkeys(str(project))
            return SETUP._LINK_ERRORS

    def test_a_key_added_or_removed_adds_or_removes_only_its_own_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare" / PROJECT
            project.mkdir(parents=True)
            for name in ("laptop.pub", "mgmt-server.pub"):
                (project / name).write_bytes(f"synthetic {name}\n".encode())
            self.assertEqual(0, self.publish(root, project))

            def links():
                return {f"{key_dir}/{name}": (os.readlink(root / key_dir / name), os.lstat(root / key_dir / name).st_ino)
                        for key_dir in PUBLICKEY_DIRECTORIES for name in sorted(os.listdir(root / key_dir))}

            first = links()
            self.assertEqual({f"{key_dir}/{name}" for key_dir in PUBLICKEY_DIRECTORIES
                              for name in ("laptop.pub", "mgmt-server.pub")}, set(first))
            for name, (text, _inode) in first.items():
                with self.subTest(link=name):
                    # R-016 §3.2: relpath(DAY0-Prepare/activate-project/<key>, the key directory).
                    self.assertEqual(CONTRACT.pointer_link_target(name, os.path.basename(name)), text)

            (project / "extra.pub").write_bytes(b"synthetic extra key\n")
            self.assertEqual(0, self.publish(root, project))
            second = links()
            self.assertEqual(set(first) | {f"{key_dir}/extra.pub" for key_dir in PUBLICKEY_DIRECTORIES}, set(second))
            self.assertEqual(first, {name: second[name] for name in first}, "the existing links are untouched")

            (project / "extra.pub").unlink()
            self.assertEqual(0, self.publish(root, project))
            self.assertEqual(first, links(), "only the removed key's link goes")

    def test_a_real_file_at_a_key_position_is_reported_counted_and_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare" / PROJECT
            project.mkdir(parents=True)
            (project / "laptop.pub").write_bytes(b"synthetic laptop key\n")
            occupied = root / "nvlink/publickey/laptop.pub"
            occupied.parent.mkdir(parents=True)
            occupied.write_bytes(b"operator-owned key\n")
            self.assertEqual(1, self.publish(root, project))
            self.assertFalse(occupied.is_symlink())
            self.assertEqual(b"operator-owned key\n", occupied.read_bytes())
            for key_dir in PUBLICKEY_DIRECTORIES[:3]:
                with self.subTest(directory=key_dir):
                    self.assertEqual((project / "laptop.pub").resolve(), (root / key_dir / "laptop.pub").resolve())


class TemplateCompletionTest(unittest.TestCase):
    """详细工作指导 WP-2: setup's _initialize_project_from_template is the only implementation."""

    def complete(self, template: Path, project: Path, *, dry_run=False) -> tuple[str, int]:
        output = io.StringIO()
        with mock.patch.multiple(SETUP, TEMPLATE_DIR=str(template), _DRY_RUN=dry_run, _LINK_ERRORS=0), \
                redirect_stdout(output):
            SETUP._initialize_project_from_template(str(project))
            return output.getvalue(), SETUP._LINK_ERRORS

    @staticmethod
    def template(root: Path) -> Path:
        template = root / "template"
        (template / "nested").mkdir(parents=True)
        (template / "required.txt").write_bytes(b"template\n")
        (template / "nested/inner.txt").write_bytes(b"inner\n")
        (template / "laptop.pub").write_bytes(b"")
        (template / "switch-image.bin").write_bytes(b"")
        (template / "ib.csv").symlink_to("02-devices_config.csv")
        (template / "occupied-by-directory").write_bytes(b"template file\n")
        (template / "occupied-by-file").mkdir()
        (template / "occupied-by-file/inside.txt").write_bytes(b"template\n")
        return template

    def test_only_missing_items_are_filled_and_conflicts_are_reported_and_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            template = self.template(root)
            project = root / PROJECT
            project.mkdir()
            (project / "required.txt").write_bytes(b"customer\n")
            (project / "occupied-by-directory").mkdir()
            (project / "occupied-by-file").write_bytes(b"customer file\n")
            output, errors = self.complete(template, project)
            self.assertEqual(b"customer\n", (project / "required.txt").read_bytes(), "never overwritten")
            self.assertEqual(b"inner\n", (project / "nested/inner.txt").read_bytes())
            self.assertFalse(os.path.lexists(project / "laptop.pub"), "ssh_key_preparation owns laptop.pub")
            self.assertEqual(b"", (project / "switch-image.bin").read_bytes(), "R-013 第 2 条: kept for now")
            self.assertEqual("02-devices_config.csv", os.readlink(project / "ib.csv"), "template links by text")
            self.assertTrue((project / "occupied-by-directory").is_dir())
            self.assertEqual(b"customer file\n", (project / "occupied-by-file").read_bytes())
            self.assertEqual(2, errors)
            self.assertIn("occupied-by-directory", output)
            self.assertIn("occupied-by-file", output)

    def test_dry_run_only_prints(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            template = self.template(root)
            project = root / PROJECT
            project.mkdir()
            output, _errors = self.complete(template, project, dry_run=True)
            self.assertEqual([], os.listdir(project))
            self.assertIn("required.txt", output)
            self.assertIn("nested", output)

    def test_setup_and_load_entries_complete_a_project_byte_for_byte_alike(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            projects = (root / "by-setup" / PROJECT, root / "by-load" / PROJECT)
            for project in projects:
                (project / "p2p").mkdir(parents=True)
                (project / "p2p/customer-P2P-v1.xlsx").write_bytes(b"customer workbook\n")
                (project / "01-global.yaml").write_bytes(b"customer: global\n")
            # The real template through each real entry point.
            with mock.patch.multiple(SETUP, TEMPLATE_DIR=str(ROOT / "DAY0-Prepare/template"), _DRY_RUN=False,
                                     _LINK_ERRORS=0), redirect_stdout(io.StringIO()):
                SETUP._initialize_project_from_template(str(projects[0]))
                self.assertEqual(0, SETUP._LINK_ERRORS)
            with redirect_stdout(io.StringIO()):
                LOAD.initialize_from_template(projects[1])
            by_setup, by_load = snapshot(projects[0]), snapshot(projects[1])
            # review S1 (http dev 2026-11-08, 改法 (a)): alike but for the load entry's empty laptop.pub placeholder.
            self.assertNotIn("laptop.pub", by_setup)
            self.assertIn("laptop.pub", by_load, "the load entry adds the empty placeholder")
            self.assertEqual(("file", b""), by_load["laptop.pub"][:2])
            self.assertEqual(by_setup, {name: item for name, item in by_load.items() if name != "laptop.pub"})
            self.assertTrue(any(name.endswith(".bin") for name in by_load), "R-013 第 2 条: .bin placeholders")
            self.assertEqual(("file", b"customer: global\n"), by_load["01-global.yaml"][:2])

    def test_the_load_entry_adds_an_empty_laptop_placeholder_only_where_nothing_is(self):
        # review S1, http dev 2026-11-08 (改法 (a)): only where nothing is at laptop.pub; a link (even a dangling
        # one), a directory or a file already there is left exactly as it is; dry-run writes nothing.
        def occupy(project: Path, kind: str) -> None:
            laptop = project / "laptop.pub"
            if kind == "link":
                (project / "keys").mkdir()
                (project / "keys/operator.pub").write_bytes(b"ssh-ed25519 AAAAsynthetic operator@laptop\n")
                laptop.symlink_to("keys/operator.pub")
            elif kind == "dangling link":
                laptop.symlink_to("missing-operator.pub")
            elif kind == "directory":
                laptop.mkdir()
            elif kind == "key":
                laptop.write_bytes(b"ssh-ed25519 AAAAsynthetic operator@laptop\n")
            elif kind == "empty file":
                laptop.write_bytes(b"")

        for kind in ("nothing", "link", "dangling link", "directory", "key", "empty file"):
            for dry_run in (False, True):
                with self.subTest(kind=kind, dry_run=dry_run), tempfile.TemporaryDirectory() as directory:
                    project = Path(directory) / PROJECT
                    project.mkdir()
                    (project / "01-global.yaml").write_bytes(b"customer: global\n")
                    occupy(project, kind)
                    before = snapshot(project)
                    identity = os.lstat(project / "laptop.pub") if kind != "nothing" else None
                    with redirect_stdout(io.StringIO()):
                        LOAD.initialize_from_template(project, dry_run=dry_run)
                    after = snapshot(project)
                    if dry_run:
                        self.assertEqual(before, after, "dry-run only prints")
                        continue
                    if kind == "nothing":
                        self.assertTrue(os.path.lexists(project / "laptop.pub"), "the empty placeholder is added")
                        metadata = os.lstat(project / "laptop.pub")
                        self.assertTrue(stat.S_ISREG(metadata.st_mode))
                        self.assertEqual((0, 1), (metadata.st_size, metadata.st_nlink))
                        continue
                    self.assertEqual(before, {name: item for name, item in after.items() if name in before})
                    self.assertEqual([], [name for name in set(after) - set(before)
                                          if name.startswith("laptop.pub" + os.sep)])
                    held = os.lstat(project / "laptop.pub")
                    self.assertEqual((identity.st_ino, identity.st_mode), (held.st_ino, held.st_mode))
                    self.assertFalse(os.path.lexists(project / "missing-operator.pub"), "never through a link")

    def test_the_load_entry_stops_on_a_template_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / PROJECT
            project.mkdir()
            (project / "p2p").write_bytes(b"customer file where the template has p2p/\n")
            with redirect_stdout(io.StringIO()), self.assertRaises(Exception) as caught:
                LOAD.initialize_from_template(project)
            # setup's rule (详细工作指导 WP-2): a conflict is an error; load stops at its template phase.
            self.assertIsInstance(caught.exception, LOAD.LoadError)
            self.assertEqual(b"customer file where the template has p2p/\n", (project / "p2p").read_bytes())

    def test_the_load_entry_never_writes_into_an_external_p2p_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            material = base / "Work-material"
            material.mkdir()
            (material / "owner-material.txt").write_bytes(b"owner material\n")
            project = base / PROJECT
            project.mkdir()
            (project / "p2p").symlink_to(material)
            output = io.StringIO()
            with redirect_stdout(output):
                LOAD.initialize_from_template(project)
            self.assertEqual({"owner-material.txt": b"owner material\n"}, listing(material))
            self.assertIn(OUTSIDE_MESSAGE, output.getvalue())
            self.assertTrue((project / "01-global.yaml").is_file(), "the rest of the template still lands")


if __name__ == "__main__":
    unittest.main()
