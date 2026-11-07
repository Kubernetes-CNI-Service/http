#!/usr/bin/env python3
"""R-016 AP-a workflow (v3.1.1 WP-3): DAY0-Prepare/activate-project across the real setup and load scripts.

Every case copies the git-indexed workspace into a temporary directory, runs the real scripts there as
subprocesses -- setup (DAY0-Prepare/01-a-setup.py) and load --dry-run (DAY0-Prepare/11-load.py) -- and reads the
outcome with the reader the other scripts share, tools/project_contract.py::active_project_dir.  All inputs are
synthetic; HOME is a temporary directory holding one synthetic operator key.

Expected values, written from the design:
- 详细工作指导 WP-3 「先写的测试」 (workflow): setup P -> load --dry-run -> setup Q -> the reader sees Q.
- R-016 详细设计 v1.1 §1 第 1、2 条, §2: tree links through the pointer never change with the project; switching
  replaces only DAY0-Prepare/activate-project.  §5.1: active_project_dir returns the real project directory.
- R-016 §4.2 第 1 步: a target that fails validation exits 2 and changes nothing -- the previous project stays
  active and load still plans against it.  Q4 (owner 2026-11-03 「好的」): -y switches without asking.
- 详细工作指导 WP-10 / R-016 §8 (DirectLayoutMigrationTests): the first setup on a tree an older setup left
  migrates it; a second run changes nothing.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
import shutil
import site
import struct
import subprocess
import sys
import tempfile
import unittest

import yaml

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/public-project"
CONTRACT = load_script("activate_project_workflow_project_contract", ROOT / "tools/project_contract.py")
FIRST, SECOND = "site-p", "site-q"
POINTER = "DAY0-Prepare/activate-project"
# Table rows whose text WP-3 left direct for the package owning their reader (详细工作指导 WP-9); empty since
# WP-9c (I-031) gave the AIR json its fixed name.
HANDED_ON: dict[str, str] = {}


def public_key(seed: int, comment: str) -> str:
    """A valid synthetic OpenSSH Ed25519 public line; no private key exists."""
    def field(value: bytes) -> bytes:
        return struct.pack(">I", len(value)) + value

    blob = field(b"ssh-ed25519") + field(bytes([seed]) * 32)
    return "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " " + comment + "\n"


def workbook(path: Path, text: str) -> None:
    import openpyxl

    book = openpyxl.Workbook()
    book.active["A1"] = text
    book.save(path)


def tree_links(root: Path) -> dict[str, str]:
    """Every symlink of the tree outside DAY0-Prepare's projects, by repository path."""
    links = {}
    for current, directories, files in os.walk(root):
        relative_dir = Path(current).relative_to(root)
        if relative_dir.parts[:1] == ("DAY0-Prepare",):
            directories[:] = []
        for name in (*directories, *files):
            path = Path(current) / name
            if path.is_symlink():
                links[path.relative_to(root).as_posix()] = os.readlink(path)
    return links


def snapshot(root: Path) -> dict[str, tuple[str, ...]]:
    state = {}
    for current, directories, files in os.walk(root):
        for name in (*directories, *files):
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                state[relative] = ("link", os.readlink(path))
            elif path.is_dir():
                state[relative] = ("dir",)
            else:
                state[relative] = ("file", path.read_bytes())
    return state


class Workspace:
    """One copied workspace with two synthetic projects."""

    def __init__(self, base: Path):
        self.base = base
        self.http = base / "http"
        listed = subprocess.run(
            ["git", "-C", os.fspath(ROOT), "ls-files", "--cached", "-z"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
        for entry in listed.split(b"\0"):
            relative = Path(os.fsdecode(entry)) if entry else None
            if relative is None or relative.parts[0] == "test_cases":
                continue
            source, target = ROOT / relative, self.http / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_symlink():
                target.symlink_to(os.readlink(source))
            elif source.is_file():
                shutil.copy2(source, target)
        self.home = base / "home"
        (self.home / ".ssh").mkdir(parents=True, mode=0o700)
        (self.home / ".ssh/id_ed25519.pub").write_text(public_key(41, "operator@laptop"), encoding="ascii")
        for name in (FIRST, SECOND):
            self.make_project(name)

    def make_project(self, name: str) -> None:
        project = self.http / "DAY0-Prepare" / name
        project.mkdir()
        document = yaml.safe_load((EXAMPLE / "01-global.yaml.example").read_text(encoding="utf-8"))
        document["common"]["mgmt"]["http"]["address"] = "192.0.2.10"
        document["switches"] = [item for item in document["switches"] if set(item) == {"eth"}]
        document["switches"][0]["eth"]["system"]["aaa"]["user"]["cumulus"]["hashed-password"] = (
            "$6$fixture$safe-value"
        )
        (project / "01-global.yaml").write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        shutil.copy2(EXAMPLE / "02-dhcp-subnet_config.csv.example", project / "02-dhcp-subnet_config.csv")
        header, eth_row = (EXAMPLE / "02-devices_config.csv.example").read_text(encoding="utf-8").splitlines()[:2]
        (project / "02-devices_config.csv").write_text(f"{header}\n{eth_row}\n", encoding="utf-8")
        workbook(project / "Site P2P_v1.0.xlsx", name)

    def project(self, name: str) -> Path:
        return self.http / "DAY0-Prepare" / name

    def run(self, argv: list[str]) -> subprocess.CompletedProcess:
        environment = dict(os.environ)
        environment["HOME"] = os.fspath(self.home)
        # The interpreter's user site (PyYAML, Jinja2, openpyxl) stays visible with HOME moved.
        environment["PYTHONUSERBASE"] = site.getuserbase()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            argv, cwd=self.http, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300, check=False,
        )

    def setup(self, name: str, *options: str) -> subprocess.CompletedProcess:
        return self.run([sys.executable, "-B", os.fspath(self.http / "DAY0-Prepare/01-a-setup.py"),
                         *options, "--host-role=workstation", "--no-upgrade", name])

    def load_dry_run(self, name: str) -> subprocess.CompletedProcess:
        return self.run([sys.executable, "-B", os.fspath(self.http / "DAY0-Prepare/11-load.py"),
                         name, "--dry-run", "--host-role=workstation", "--no-upgrade"])

    def pointer(self) -> str | None:
        path = self.http / POINTER
        return os.readlink(path) if path.is_symlink() else None


class ActivateProjectWorkflowTests(unittest.TestCase):
    def workspace(self) -> Workspace:
        directory = tempfile.TemporaryDirectory(prefix="activate-project-workflow-")
        self.addCleanup(directory.cleanup)
        return Workspace(Path(directory.name).resolve())

    def test_setup_p_load_dry_run_setup_q_and_the_reader_sees_q(self):
        space = self.workspace()
        first = space.setup(FIRST, "-y")
        self.assertEqual(0, first.returncode, first.stdout)
        self.assertEqual(FIRST, space.pointer())
        self.assertEqual(space.project(FIRST), CONTRACT.active_project_dir(space.http))
        links_with_first = tree_links(space.http)

        load = space.load_dry_run(FIRST)
        self.assertEqual(0, load.returncode, load.stdout)
        self.assertEqual(FIRST, space.pointer())

        second = space.setup(SECOND, "--yes")
        self.assertEqual(0, second.returncode, second.stdout)
        self.assertEqual(SECOND, space.pointer())
        self.assertEqual(space.project(SECOND), CONTRACT.active_project_dir(space.http))
        # R-016 §1 第 1、2 条: every project row reads through the pointer, so its link text never moved.
        links_with_second = tree_links(space.http)
        for row in CONTRACT.SETUP_LINK_SPECS:
            if row.base == "project" and row.path in links_with_first and row.path not in HANDED_ON:
                with self.subTest(link=row.path):
                    self.assertEqual(CONTRACT.pointer_link_target(row.path, row.target), links_with_second[row.path])
                    self.assertEqual(links_with_first[row.path], links_with_second[row.path])
        inventory = space.http / "ethernet/eth.csv"
        self.assertEqual((space.project(SECOND) / "02-devices_config.csv").resolve(), inventory.resolve(strict=True))

    def test_a_target_that_fails_validation_leaves_the_active_project_and_load_planning_alone(self):
        space = self.workspace()
        first = space.setup(FIRST, "-y")
        self.assertEqual(0, first.returncode, first.stdout)
        # A device row with an unknown type is an input error of _validate_eth_csv.
        devices = space.project(SECOND) / "02-devices_config.csv"
        header, row = devices.read_text(encoding="utf-8").splitlines()
        devices.write_text(header + "\n" + row.replace(",eth,", ",not-a-type,", 1) + "\n", encoding="utf-8")
        before = snapshot(space.http)

        second = space.setup(SECOND, "-y")
        self.assertEqual(2, second.returncode, second.stdout)
        self.assertEqual(before, snapshot(space.http))
        self.assertEqual(space.project(FIRST), CONTRACT.active_project_dir(space.http))

        load = space.load_dry_run(FIRST)
        self.assertEqual(0, load.returncode, load.stdout)
        self.assertEqual(FIRST, space.pointer())


# ── v3.1.1 WP-10 (R-016 §8): migration from the direct layout older setups left ──────────────────────────────
import glob  # noqa: E402
import io  # noqa: E402
import posixpath  # noqa: E402
import stat  # noqa: E402
from contextlib import redirect_stdout  # noqa: E402
from unittest import mock  # noqa: E402

DEPLOY_INFRA = load_script("activate_project_workflow_deploy_infra", ROOT / "infra/deploy_infra.py")
ROWS = {row.path: row for row in CONTRACT.SETUP_LINK_SPECS}
SETUP_SCRIPT = "DAY0-Prepare/01-a-setup.py"
MANIFEST = "ztp/.setup_manifest"
# The project's two keys; laptop.pub is HOME's key, as the older setup prepared it.
PROJECT_KEYS = {"laptop.pub": (41, "operator@laptop"), "mgmt-server.pub": (42, "mgmt@server")}
DROPPED_KEY = "retired-operator.pub"  # an older per-key link whose key the project no longer has
OPERATOR_KEY_FILE = "ztp/config/publickey/site-extra.pub"  # an operator's own real file in a key directory
# Measured on the v3.1.0 candidate f741269 (01-a-setup.py::_publickey_roots): v3.1.0 published keys into two
# directories; v3.1.1 WP-1 made them four (R-016 §3.2).
V310_KEY_DIRECTORIES = ("ztp/config/publickey", "infiniband/publickey")
OLD_LOGS = {
    "infra-setup-20260924_010203.log": b"pre-project infra-setup log\n",
    "archive/deploy_infra-20260901T000000Z-7.log": b"older deploy log\n",
}


def direct_text(path: str, project: str, target: str) -> str:
    """R-016 §3.2 「现在」 column and §8: the text setups before v3.1.1 wrote, relpath(DAY0-Prepare/<项目>/<目标>)."""
    return posixpath.relpath(f"DAY0-Prepare/{project}/{target}", posixpath.dirname(path))


def every_link(root: Path) -> dict[str, str]:
    """Every symlink of the whole tree -- DAY0-Prepare, the pointer and the projects included -- with its text."""
    links = {}
    for current, directories, files in os.walk(root):
        for name in (*directories, *files):
            path = Path(current) / name
            if path.is_symlink():
                links[path.relative_to(root).as_posix()] = os.readlink(path)
    return links


def lay_out_direct_tree(space: Workspace, name: str, *, v310: bool, infra_logs: str) -> None:
    """Turn the copied workspace into a tree an older setup left with project ``name`` active: no pointer.

    v310=False, the layout of the WP-10 dispatch: every setup row of the link table is a direct link, and each of
    the four key directories holds direct per-key links.  v310=True, the v3.1.0 tree as measured against f741269:
    the rows v3.1.0 had -- every current row except the 19 that v3.1.1 WP-1 added, which are exactly the rows
    without a legacy ``view`` -- plus monitor/99-output-ufm that R-013 then took out of the table, and per-key links
    in the two v3.1.0 key directories only.  Repository aliases keep their text (R-016 §2).
    Both: the key directories also hold a link for a key the project dropped and (ztp/config/publickey) an
    operator's real file; ztp/.setup_manifest is the old record, its first line naming the project with proj:.
    infra_logs "link": the direct link to the project's real 99-output-infra; "directory": a real log directory,
    as a tree had before REQ-19 bound it (pre-project infra logs).
    """
    root, project = space.http, space.project(name)
    made = []

    def link(path: str, text: str) -> None:
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).symlink_to(text)
        made.append(path)

    for row in CONTRACT.SETUP_LINK_SPECS:
        if row.writer != "setup" or row.path == "infra/logs" or (v310 and row.view is None):
            continue
        link(row.path, direct_text(row.path, name, row.target) if row.base == "project"
             else posixpath.relpath(row.target, posixpath.dirname(row.path)))
    if v310:
        for retired in CONTRACT.RETIRED_SETUP_LINKS:
            (project / posixpath.basename(retired)).mkdir()
            link(retired, direct_text(retired, name, posixpath.basename(retired)))
    for key, (seed, comment) in PROJECT_KEYS.items():
        (project / key).write_text(public_key(seed, comment), encoding="ascii")
    for directory in V310_KEY_DIRECTORIES if v310 else CONTRACT.PUBLICKEY_DIRECTORIES:
        for key in (*PROJECT_KEYS, DROPPED_KEY):
            link(f"{directory}/{key}", direct_text(f"{directory}/{key}", name, key))
    (root / OPERATOR_KEY_FILE).write_text(public_key(43, "operator@extra"), encoding="ascii")
    if infra_logs == "link":
        (project / "99-output-infra").mkdir()
        link("infra/logs", direct_text("infra/logs", name, "99-output-infra"))
    else:
        for relative, data in OLD_LOGS.items():
            (root / "infra/logs" / relative).parent.mkdir(parents=True, exist_ok=True)
            (root / "infra/logs" / relative).write_bytes(data)
    (root / MANIFEST).write_text(f"# setup manifest — proj: {project}\n"
                                 + "".join(f"{root / path}\n" for path in sorted(made)), encoding="utf-8")


class DirectLayoutMigrationTests(unittest.TestCase):
    """v3.1.1 WP-10: the first v3.1.1 setup migrates a tree an older setup left; a second run changes nothing.

    Acceptance tests over the real setup script, not red-first ones: the guide adds no migration code -- the reconcile
    engine (WP-2) and the switch (WP-3) do it -- so the evidence that they can fail is mutation runs (WP-10 report).
    Expected values, from the design and the owner's rulings only:
    - R-016 详细设计 v1.1 §8 第 1～5 条: the fixed links' direct text is atomically replaced by the canonical text
      (project_contract.pointer_link_specs); the pointer is made for the project being activated; the key
      directories stay real directories and their per-key links are rebuilt in the new text, only links removed;
      infra/logs, a real directory, moves by the existing receipt migration, and its link then has the new text;
      the manifest is rewritten in the new format -- §4.2 第 5 步 「首行 proj: <真实项目路径>，后面是固定清单」,
      the list being every link of the table, the shared and the dynamic section in place (Q5, review A8).
    - §8 and R16-09: every step repeats safely; a migration cut off midway is finished by running setup again.
    - §4.3 and §1 第 4 条 (owner 2026-11-03): a real file or directory at a link position is an error, kept, never
      deleted, and the following rows still run; §4.2 第 6 步: errors make setup exit 1 with the switch kept.
    - §4.2 第 4 步: the switch asks only when the pointer names another project, so migrating the active project
      needs no confirmation -- these runs pass neither -y nor --confirm-project-switch.
    - TC-REAL-ACTIVATE-PROJECT-002 in small: after the migration --status is clean and load still plans.
    - http dev 2026-11-08 (WP-8 待决 1, again for WP-10 P1): monitor/99-output-ufm, which R-013 took out of the
      table (project_contract.RETIRED_SETUP_LINKS), is handled like the four legacy names setup removes after the
      switch (R16-13): the link goes; a real file or directory there is only warned about (WP-3 D6), not counted
      as an error and not deleted.
    """

    def workspace(self) -> Workspace:
        directory = tempfile.TemporaryDirectory(prefix="activate-project-migration-")
        self.addCleanup(directory.cleanup)
        return Workspace(Path(directory.name).resolve())

    def assert_direct_layout(self, space: Workspace, name: str) -> None:
        """The fixture is really the old layout: no pointer, and every project link names the project directly."""
        self.assertIsNone(space.pointer())
        direct = [path for path, text in every_link(space.http).items()
                  if posixpath.normpath(posixpath.join(posixpath.dirname(path), text)).startswith(
                      f"DAY0-Prepare/{name}/")]
        self.assertGreater(len(direct), 50)
        self.assertFalse([path for path in direct if "activate-project" in every_link(space.http)[path]])

    def assert_migrated(self, space: Workspace, name: str, *, kept: frozenset[str] = frozenset()) -> None:
        root, project = space.http, space.project(name)
        # §8 第 2 条: the pointer names the activated project.
        self.assertEqual(name, space.pointer())
        self.assertEqual(project, CONTRACT.active_project_dir(root))
        # §8 第 1 条: every fixed link setup writes has the canonical text; ``kept`` are real files the test put there.
        for path, text in CONTRACT.pointer_link_specs():
            if ROWS[path].writer == "setup" and path not in kept:
                with self.subTest(fixed=path):
                    self.assertEqual(text, os.readlink(root / path))
        # No link outside the project still names it directly, except where R-016 §2 keeps the text: the
        # per-project ztp/optimize/<项目>-sample/* links.
        direct = sorted(
            path for path, text in every_link(root).items()
            if not path.startswith(f"DAY0-Prepare/{name}/")
            and not path.startswith(f"ztp/optimize/{name}-sample/")
            and posixpath.normpath(posixpath.join(posixpath.dirname(path), text)).startswith(f"DAY0-Prepare/{name}/"))
        self.assertEqual([], direct)
        # The retired links an older setup made are gone; ``kept`` names an operator's real entry there.
        for retired in CONTRACT.RETIRED_SETUP_LINKS:
            with self.subTest(retired=retired):
                self.assertFalse((root / retired).is_symlink())
                self.assertEqual(retired in kept, os.path.lexists(root / retired))
        # §8 第 3 条, §3.2: four real key directories, one canonical link per project key; only links removed.
        for directory in CONTRACT.PUBLICKEY_DIRECTORIES:
            with self.subTest(key_directory=directory):
                self.assertTrue(stat.S_ISDIR((root / directory).lstat().st_mode))
                self.assertEqual(
                    {key: CONTRACT.pointer_link_target(f"{directory}/{key}", key) for key in PROJECT_KEYS},
                    {path.name: os.readlink(path) for path in (root / directory).glob("*.pub") if path.is_symlink()})
        self.assertFalse((root / OPERATOR_KEY_FILE).is_symlink())
        self.assertEqual(public_key(43, "operator@extra"), (root / OPERATOR_KEY_FILE).read_text(encoding="ascii"))
        # §8 第 4 条: infra/logs reaches the project's log directory; no migration receipt or temp is left.
        self.assertEqual((project / "99-output-infra").resolve(), (root / "infra/logs").resolve(strict=True))
        self.assertEqual([], sorted(entry for entry in os.listdir(root / "infra") if entry.startswith(".logs-migration")))
        self.assertFalse(os.path.lexists(project / "99-output-infra/.logs-migration-source"))
        # §8 第 5 条: the manifest in the new format.
        lines = (root / MANIFEST).read_text(encoding="utf-8").splitlines()
        self.assertEqual("# setup manifest — proj: " + os.path.realpath(project), lines[0])
        recorded = {str(root / row.path) for row in CONTRACT.SETUP_LINK_SPECS if (root / row.path).is_symlink()}
        for pattern in (*(row.path for row in CONTRACT.SHARED_LINK_SPECS), *CONTRACT.setup_dynamic_link_patterns()):
            recorded.update(path for path in glob.glob(os.path.join(glob.escape(str(root)), pattern))
                            if os.path.islink(path))
        self.assertEqual(recorded, set(lines[1:]))
        self.assertEqual(len(recorded), len(lines) - 1)

    def assert_second_run_changes_nothing(self, space: Workspace, name: str, *, code: int = 0) -> None:
        links, manifest = every_link(space.http), (space.http / MANIFEST).read_bytes()
        again = space.setup(name)
        self.assertEqual(code, again.returncode, again.stdout)
        self.assertEqual(name, space.pointer())
        self.assertEqual(links, every_link(space.http))
        self.assertEqual(manifest, (space.http / MANIFEST).read_bytes())

    def test_first_setup_migrates_the_direct_layout_and_a_second_run_changes_nothing(self):
        space = self.workspace()
        lay_out_direct_tree(space, FIRST, v310=False, infra_logs="link")
        self.assert_direct_layout(space, FIRST)
        first = space.setup(FIRST)
        self.assertEqual(0, first.returncode, first.stdout)
        self.assert_migrated(space, FIRST)
        self.assert_second_run_changes_nothing(space, FIRST)
        # TC-REAL-ACTIVATE-PROJECT-002 in small: --status finds nothing wrong, and load plans against the tree.
        status = space.run([sys.executable, "-B", os.fspath(space.http / SETUP_SCRIPT), "--status"])
        self.assertEqual(0, status.returncode, status.stdout)
        links = every_link(space.http)
        load = space.load_dry_run(FIRST)
        self.assertEqual(0, load.returncode, load.stdout)
        self.assertEqual(links, every_link(space.http))

    def test_a_v310_tree_with_a_real_log_directory_migrates_it_by_the_receipt(self):
        space = self.workspace()
        lay_out_direct_tree(space, FIRST, v310=True, infra_logs="directory")
        self.assert_direct_layout(space, FIRST)
        identities = {relative: (space.http / "infra/logs" / relative).stat().st_ino for relative in OLD_LOGS}
        first = space.setup(FIRST)
        self.assertEqual(0, first.returncode, first.stdout)
        self.assert_migrated(space, FIRST)
        # REQ-19's receipt migration moves the very files (hard links, then the original directory goes).
        logs = space.project(FIRST) / "99-output-infra"
        for relative, data in OLD_LOGS.items():
            with self.subTest(log=relative):
                self.assertEqual(data, (logs / relative).read_bytes())
                self.assertEqual(identities[relative], (logs / relative).stat().st_ino)
                self.assertEqual(data, (space.http / "infra/logs" / relative).read_bytes())
        self.assert_second_run_changes_nothing(space, FIRST)

    def test_a_real_file_or_directory_at_a_link_position_is_reported_and_kept_while_the_rest_migrates(self):
        space = self.workspace()
        lay_out_direct_tree(space, FIRST, v310=False, infra_logs="link")
        operator_file, operator_directory = space.http / "ethernet/eth.csv", space.http / "ztp/status"
        for path in (operator_file, operator_directory):
            path.unlink()
        operator_file.write_bytes(b"an operator's own inventory copy\n")
        operator_directory.mkdir()
        (operator_directory / "note.txt").write_bytes(b"an operator's own status note\n")
        first = space.setup(FIRST)
        self.assertEqual(1, first.returncode, first.stdout)
        for path in (operator_file, operator_directory):
            self.assertIn(str(path), first.stdout)
        self.assertEqual(b"an operator's own inventory copy\n", operator_file.read_bytes())
        self.assertEqual(["note.txt"], os.listdir(operator_directory))
        self.assertFalse(operator_file.is_symlink() or operator_directory.is_symlink())
        self.assert_migrated(space, FIRST, kept=frozenset({"ethernet/eth.csv", "ztp/status"}))
        self.assert_second_run_changes_nothing(space, FIRST, code=1)
        self.assertEqual(b"an operator's own inventory copy\n", operator_file.read_bytes())
        self.assertEqual(["note.txt"], os.listdir(operator_directory))

    def test_a_real_directory_at_a_retired_link_position_is_warned_about_kept_and_not_an_error(self):
        space = self.workspace()
        lay_out_direct_tree(space, FIRST, v310=True, infra_logs="link")
        retired = CONTRACT.RETIRED_SETUP_LINKS[0]
        (space.http / retired).unlink()
        (space.http / retired).mkdir()
        (space.http / retired / "note.txt").write_bytes(b"an operator's own directory\n")
        first = space.setup(FIRST)
        self.assertEqual(0, first.returncode, first.stdout)
        named = [line for line in first.stdout.splitlines() if str(space.http / retired) in line]
        self.assertTrue(named, first.stdout)
        self.assertTrue(all("[WARN]" in line and "[ERROR]" not in line for line in named), named)
        self.assertEqual(["note.txt"], os.listdir(space.http / retired))
        self.assert_migrated(space, FIRST, kept=frozenset({retired}))
        self.assert_second_run_changes_nothing(space, FIRST)
        self.assertEqual(b"an operator's own directory\n", (space.http / retired / "note.txt").read_bytes())

    def test_a_migration_cut_off_midway_is_finished_by_the_next_setup(self):
        # R16-09: (a) inside step 3, no pointer yet, half the fixed links already in the new text; (b) after the
        # switch, before the per-key links, infra/logs and the manifest were redone.
        for cut in ("inside step 3", "after the switch"):
            with self.subTest(cut=cut):
                space = self.workspace()
                lay_out_direct_tree(space, FIRST, v310=False, infra_logs="link")
                rows = [row for row in CONTRACT.SETUP_LINK_SPECS
                        if row.writer == "setup" and row.base == "project" and row.path != "infra/logs"]
                for row in rows[: len(rows) // 2] if cut == "inside step 3" else rows:
                    (space.http / row.path).unlink()
                    (space.http / row.path).symlink_to(CONTRACT.pointer_link_target(row.path, row.target))
                if cut == "after the switch":
                    (space.http / POINTER).symlink_to(FIRST)
                first = space.setup(FIRST)
                self.assertEqual(0, first.returncode, first.stdout)
                self.assert_migrated(space, FIRST)
                self.assert_second_run_changes_nothing(space, FIRST)

    def test_after_the_migration_the_infra_writer_logs_beside_the_migrated_logs(self):
        # Depends on WP-9b: deploy_infra reads infra/logs through project_contract.managed_infra_log_project, which
        # accepts the pointer-form text only from WP-9b on.  RED until WP-9b lands.
        space = self.workspace()
        lay_out_direct_tree(space, FIRST, v310=True, infra_logs="directory")
        first = space.setup(FIRST)
        self.assertEqual(0, first.returncode, first.stdout)
        with mock.patch.object(DEPLOY_INFRA, "SCRIPT_DIR", space.http / "infra"), redirect_stdout(io.StringIO()):
            self.assertEqual(0, DEPLOY_INFRA.run_with_log("deploy_infra", lambda: 0))
        logs = space.project(FIRST) / "99-output-infra"
        self.assertEqual(1, len(list(logs.glob("deploy_infra-*.log"))))
        for relative, data in OLD_LOGS.items():
            self.assertEqual(data, (logs / relative).read_bytes())


if __name__ == "__main__":
    unittest.main()
