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


if __name__ == "__main__":
    unittest.main()
