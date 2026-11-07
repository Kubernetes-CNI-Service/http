"""Workflow (v3.1.1 WP-4, I-024): a project with UFM is activated the way load does it, then --status agrees.

Each case copies the git-indexed tree into a temporary workspace (no project data, runtime links or manifest),
adds one synthetic project with an Ethernet switch and a server_ufm row, a P2P workbook and a shared http/image
directory, and runs the real scripts as subprocesses:
  1. DAY0-Prepare/01-a-setup.py activates the project, then runs again on the same project (I-024's second run:
     the UFM image link must not count as a link of another project);
  2. DAY0-Prepare/11-load.py <project> --dry-run plans the activation; the setup command it plans is run as is
     (the load -> setup handoff);
  3. DAY0-Prepare/01-a-setup.py --status reads the result; --check-template checks the template.

Expected values and their sources (never read back from the implementation):
- I-024 (owner 2026-11-02 「同意记录，放进 M1，与 R-014 一起；setup 建链接与 --status 校验用同一张名单」;
  期望的修复「用有 UFM 的项目做 workflow 测试」): after setup of a UFM project with http/image present,
  --status returns 0 and never reports infiniband/bringup/ufm-setup-upgrade/image as escaping the project.
- R-016 §4.5: --status is read-only, reports the pointer DAY0-Prepare/activate-project and every fixed row;
  exit 0 when all is well.  §4.2 step 4: setup activates a project by pointing activate-project at it.
- R-016 §4.6 / R-013 acceptance (详细工作指导 WP-4, WP-8): --check-template on the repository template is 0.
- 详细工作指导 WP-4 「改什么」: shared links are right when they lead under http/image; 「现状」: _check_conflicts has
  I-024's mismatch on a second run whenever http/image exists, and takes its shared targets from the table's
  shared section after the fix.

Before v3.1.1 WP-3 lands, setup does not make the pointer, so the --status step is expected to fail here
(依赖 WP-3 才会变绿); the assertions state the target contract.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
import re
import shlex
import shutil
import site
import struct
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/public-project"
PROJECT = "site-ufm"
UFM_IMAGE = "infiniband/bringup/ufm-setup-upgrade/image"
# A server_ufm row: setup checks only the first seven columns (01-a-setup.py, owner 2026-10-19).
UFM_ROW = ("ufm01", "server_ufm", "NA", "198.51.100.31", "24", "198.51.100.1", "02:00:00:00:02:31")


def public_key(seed: int, comment: str) -> str:
    """A valid synthetic OpenSSH Ed25519 public line, built at run time; no private key exists."""
    def field(value: bytes) -> bytes:
        return struct.pack(">I", len(value)) + value

    blob = field(b"ssh-ed25519") + field(bytes([seed]) * 32)
    return "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " " + comment + "\n"


def copy_indexed_workspace(destination: Path) -> None:
    """Copy only git-indexed production paths: no project data, runtime links or manifest."""
    listed = subprocess.run(
        ["git", "-C", os.fspath(ROOT), "ls-files", "--cached", "-z"],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout
    for entry in listed.split(b"\0"):
        if not entry:
            continue
        relative = Path(os.fsdecode(entry))
        if relative.parts[0] == "test_cases":
            continue
        source = ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            target.symlink_to(os.readlink(source))
        elif source.is_file():
            shutil.copy2(source, target)


def tree_state(root: Path) -> dict[str, tuple[int, int, str | None]]:
    state = {}
    for current, directories, files in os.walk(root):
        for name in (*directories, *files):
            path = Path(current) / name
            info = path.lstat()
            state[str(path.relative_to(root))] = (
                info.st_mode, info.st_mtime_ns, os.readlink(path) if path.is_symlink() else None,
            )
    return state


class UfmProjectSandbox:
    """One copied workspace with a synthetic UFM project and a shared http/image directory."""

    def __init__(self, base: Path):
        import openpyxl

        self.http = base / "http"
        copy_indexed_workspace(self.http)
        self.home = base / "home"
        (self.home / ".ssh").mkdir(parents=True, mode=0o700)
        (self.home / ".ssh/id_ed25519.pub").write_text(public_key(43, "operator@laptop"), encoding="ascii")
        self.project = self.http / "DAY0-Prepare" / PROJECT
        self.project.mkdir()
        document = yaml.safe_load((EXAMPLE / "01-global.yaml.example").read_text(encoding="utf-8"))
        document["common"]["mgmt"]["http"]["address"] = "192.0.2.10"
        document["switches"] = [item for item in document["switches"] if set(item) == {"eth"}]
        document["switches"][0]["eth"]["system"]["aaa"]["user"]["cumulus"][
            "hashed-password"
        ] = "$6$fixture$safe-value"
        (self.project / "01-global.yaml").write_text(
            yaml.safe_dump(document, sort_keys=False), encoding="utf-8",
        )
        shutil.copy2(EXAMPLE / "02-dhcp-subnet_config.csv.example",
                     self.project / "02-dhcp-subnet_config.csv")
        header, eth_row = (EXAMPLE / "02-devices_config.csv.example").read_text(
            encoding="utf-8").splitlines()[:2]
        width = len(header.split(","))
        ufm_row = ",".join(UFM_ROW + ("NA",) * (width - len(UFM_ROW)))
        (self.project / "02-devices_config.csv").write_text(
            f"{header}\n{eth_row}\n{ufm_row}\n", encoding="utf-8")
        book = openpyxl.Workbook()
        book.active["A1"] = "fixture"
        book.save(self.project / "Site P2P_v1.0.xlsx")
        self.image = self.http / "image"
        self.image.mkdir()
        (self.image / "ufm.lic").write_bytes(b"fixture license\n")

    def run(self, argv: list[str]) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["HOME"] = os.fspath(self.home)
        env["PYTHONUSERBASE"] = site.getuserbase()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            argv, cwd=self.http, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300, check=False,
        )

    def setup(self, *arguments: str) -> subprocess.CompletedProcess:
        return self.run([sys.executable, "-B", os.fspath(self.http / "DAY0-Prepare/01-a-setup.py"),
                         *arguments])


class ActivateProjectStatusWorkflowTests(unittest.TestCase):
    def sandbox(self) -> UfmProjectSandbox:
        directory = tempfile.TemporaryDirectory(prefix="activate-project-status-")
        self.addCleanup(directory.cleanup)
        return UfmProjectSandbox(Path(directory.name).resolve())

    def test_ufm_project_activated_through_load_plan_has_a_clean_status_i024(self):
        sandbox = self.sandbox()
        first = sandbox.setup("-y", "--host-role=workstation", "--no-upgrade", PROJECT)
        self.assertEqual(0, first.returncode, first.stdout)
        self.assertTrue((sandbox.http / UFM_IMAGE).is_symlink(), first.stdout)
        # The same project again: the shared UFM image link is no other project's link (WP-4 「现状」).
        second = sandbox.setup("-y", "--host-role=workstation", "--no-upgrade", PROJECT)
        self.assertEqual(0, second.returncode, second.stdout)

        load = sandbox.run([
            sys.executable, "-B", os.fspath(sandbox.http / "DAY0-Prepare/11-load.py"),
            PROJECT, "--dry-run", "--host-role=workstation", "--no-upgrade",
        ])
        self.assertEqual(0, load.returncode, load.stdout)
        planned = [line for line in load.stdout.splitlines()
                   if line.startswith("[DRY] (") and "01-a-setup.py" in line]
        self.assertEqual(1, len(planned), load.stdout)
        activation = sandbox.run(shlex.split(re.sub(r"^\[DRY\] \(.*?\) ", "", planned[0])))
        self.assertEqual(0, activation.returncode, activation.stdout)

        # The I-024 trigger is present: setup linked the UFM tool's image/ to the shared http/image.
        ufm_image = sandbox.http / UFM_IMAGE
        self.assertTrue(ufm_image.is_symlink(), activation.stdout)
        self.assertEqual(os.path.relpath(sandbox.image, ufm_image.parent), os.readlink(ufm_image))
        self.assertEqual(sandbox.image.resolve(), ufm_image.resolve())
        # R-016 §4.2 step 4: setup points DAY0-Prepare/activate-project at the project (v3.1.1 WP-3).
        pointer = sandbox.http / "DAY0-Prepare/activate-project"
        self.assertTrue(pointer.is_symlink(), activation.stdout)
        self.assertEqual(PROJECT, os.readlink(pointer))

        before = tree_state(sandbox.http)
        status = sandbox.setup("--status")
        self.assertEqual(before, tree_state(sandbox.http), "--status writes nothing")
        self.assertEqual(0, status.returncode, status.stdout)
        self.assertIn("activate-project", status.stdout)
        self.assertIn(PROJECT, status.stdout)
        self.assertIn(UFM_IMAGE, status.stdout)
        self.assertNotIn("逃逸", status.stdout)
        self.assertNotIn("[ERROR]", status.stdout)

        template = sandbox.setup("--check-template")
        self.assertEqual(0, template.returncode, template.stdout)


if __name__ == "__main__":
    unittest.main()
