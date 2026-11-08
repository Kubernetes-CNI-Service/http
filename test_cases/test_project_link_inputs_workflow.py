#!/usr/bin/env python3
"""R-014 第 3 条 workflow：项目输入可以是用户链接，打包和同步把链接内容作为普通文件带走。

每个用例在一份按 git 索引复制的临时工作区里依次运行真实脚本：setup
（DAY0-Prepare/01-a-setup.py）、load --dry-run（DAY0-Prepare/11-load.py）、打包
（tools/_package_common.py::create_package）、服务器侧写前守卫落盘
（tools/deployment_prewrite_guard.py）和同步（tools/sync-code.py 的 rsync job，改为在本机目录之间
执行）。输入全部是合成数据；链接目标放在工作区外的 Work/ 目录，HOME 指向临时目录。

预期的出处：
- 需求文档 R-014 第 3 条（owner 2026-11-02 原话「setup应该允许用户在项目目录下创建自己的链接文件」，
  以及「同意你的建议。」——建议含「打包时把用户链接的内容复制成普通文件」）：setup、load 跟随链接、
  按真实文件校验；打包时把链接指向的内容复制成普通文件带过去，来源记录写真实路径和 sha256。
- v3.1.1 详细工作指导 WP-11：四个场景（02 链到项目外、laptop.pub 链接、p2p.xlsx → p2p/<工作簿>
  且 p2p/ 是外部目录链接、链接目标不存在时报错）；sync 只用单文件 --copy-links，不对整个项目
  job 用 --copy-unsafe-links；写前守卫要允许「链接 → 普通文件」的替换。
- R-014 第 2 条：不往指向项目外的链接里写。
"""

from __future__ import annotations

import argparse
import base64
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import site
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import yaml

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/public-project"
PACKAGE = load_script("project_link_inputs_package", ROOT / "tools/_package_common.py")
SYNC = load_script("project_link_inputs_sync", ROOT / "tools/sync-code.py")
GUARD = load_script("project_link_inputs_guard", ROOT / "tools/deployment_prewrite_guard.py")
PROJECT = "site"
RECEIPT = "03-linked-inputs.json"
REMOTE_ROOT = "/srv/http"


def public_key(seed: int, comment: str) -> str:
    """A valid synthetic OpenSSH Ed25519 public line; no private key exists."""
    def field(value: bytes) -> bytes:
        return struct.pack(">I", len(value)) + value

    blob = field(b"ssh-ed25519") + field(bytes([seed]) * 32)
    return "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " " + comment + "\n"


def workbook(path: Path, text: str) -> Path:
    import openpyxl

    book = openpyxl.Workbook()
    book.active["A1"] = text
    book.save(path)
    return path


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


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


class LinkedProjectSandbox:
    """One copied workspace, one synthetic project and an outside Work/ directory."""

    def __init__(self, base: Path):
        self.base = base
        self.http = base / "http"
        copy_indexed_workspace(self.http)
        self.work = base / "Work"
        self.work.mkdir()
        self.home = base / "home"
        (self.home / ".ssh").mkdir(parents=True, mode=0o700)
        (self.home / ".ssh/id_ed25519.pub").write_text(
            public_key(41, "operator@laptop"), encoding="ascii",
        )
        self.project = self.http / "DAY0-Prepare" / PROJECT
        self.project.mkdir()
        document = yaml.safe_load(
            (EXAMPLE / "01-global.yaml.example").read_text(encoding="utf-8")
        )
        document["common"]["mgmt"]["http"]["address"] = "192.0.2.10"
        document["switches"] = [item for item in document["switches"] if set(item) == {"eth"}]
        document["switches"][0]["eth"]["system"]["aaa"]["user"]["cumulus"][
            "hashed-password"
        ] = "$6$fixture$safe-value"
        (self.project / "01-global.yaml").write_text(
            yaml.safe_dump(document, sort_keys=False), encoding="utf-8",
        )
        shutil.copy2(
            EXAMPLE / "02-dhcp-subnet_config.csv.example",
            self.project / "02-dhcp-subnet_config.csv",
        )
        header, eth_row = (
            EXAMPLE / "02-devices_config.csv.example"
        ).read_text(encoding="utf-8").splitlines()[:2]
        self.devices = f"{header}\n{eth_row}\n".encode("utf-8")

    def env(self) -> dict[str, str]:
        result = dict(os.environ)
        result["HOME"] = os.fspath(self.home)
        # The interpreter's user site (PyYAML, Jinja2, openpyxl) stays visible
        # although HOME no longer points at the operator's home directory.
        result["PYTHONUSERBASE"] = site.getuserbase()
        result["PYTHONDONTWRITEBYTECODE"] = "1"
        return result

    def run(self, argv: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            argv, cwd=self.http, env=self.env(), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            timeout=300, check=False,
        )

    def setup(self) -> subprocess.CompletedProcess:
        return self.run([
            sys.executable, "-B", os.fspath(self.http / "DAY0-Prepare/01-a-setup.py"),
            "-y", "--host-role=workstation", "--no-upgrade", os.fspath(self.project),
        ])

    def load_dry_run(self) -> subprocess.CompletedProcess:
        return self.run([
            sys.executable, "-B", os.fspath(self.http / "DAY0-Prepare/11-load.py"),
            PROJECT, "--dry-run", "--host-role=workstation", "--no-upgrade",
        ])

    def package(self, output: Path) -> str:
        args = argparse.Namespace(
            project=os.fspath(self.project), output=output, force=False,
            max_file_size_mib=50, include_images=False, include_apps=False,
            apps_platform=None, apps_platforms=set(), include_firmware=False,
            exclude_project_images=False,
        )
        printed = io.StringIO()
        with mock.patch.multiple(
            PACKAGE, ROOT=self.http, DAY0=self.http / "DAY0-Prepare",
            MANIFEST=self.http / "ztp/.setup_manifest", TOOLS_DIR=self.http / "tools",
        ), redirect_stdout(printed):
            PACKAGE.create_package(args, day0_all=False, artifact_kind="upload")
        return printed.getvalue()

    def sync_jobs(self):
        with mock.patch.multiple(
            SYNC, ROOT=self.http, DAY0=self.http / "DAY0-Prepare",
        ), mock.patch.multiple(
            SYNC.project_contract, ROOT=self.http, DAY0=self.http / "DAY0-Prepare",
            MANIFEST=self.http / "ztp/.setup_manifest",
        ), redirect_stdout(io.StringIO()):
            return SYNC.build_jobs(self.project, REMOTE_ROOT)

    def sync_project(self, server: Path, labels=None) -> list[list[str]]:
        """Run the project's rsync jobs exactly as built, but into a local directory."""
        args = argparse.Namespace(
            runtime="native", dry_run=False, sudo=False, host="sync-target",
            port=22, identity=None,
        )
        executed = []
        for job in self.sync_jobs():
            if job.remote_dir != f"{REMOTE_ROOT}/DAY0-Prepare/{PROJECT}":
                continue
            if labels is not None and job.label not in labels:
                continue
            command = SYNC.rsync_command(job, args)
            transport = command.index("-e")
            del command[transport:transport + 2]
            destination = server / job.remote_dir.lstrip("/")
            destination.mkdir(parents=True, exist_ok=True)
            expected_destination = f"{args.host}:{job.remote_dir}/"
            if command[-1] != expected_destination:
                raise AssertionError(f"unexpected rsync destination: {command[-1]}")
            command[-1] = os.fspath(destination) + "/"
            subprocess.run(
                command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            executed.append(command)
        return executed


def archive_members(path: Path) -> dict[str, tarfile.TarInfo]:
    with tarfile.open(path, "r:gz") as archive:
        return {member.name: member for member in archive.getmembers()}


def archive_bytes(path: Path, name: str) -> bytes:
    with tarfile.open(path, "r:gz") as archive:
        stream = archive.extractfile(name)
        if stream is None:
            raise AssertionError(f"archive member is not a regular file: {name}")
        return stream.read()


class ProjectLinkInputsWorkflowTests(unittest.TestCase):
    def sandbox(self) -> LinkedProjectSandbox:
        directory = tempfile.TemporaryDirectory(prefix="project-link-inputs-")
        self.addCleanup(directory.cleanup)
        return LinkedProjectSandbox(Path(directory.name).resolve())

    def assert_receipt_entry(self, archive: Path, name: str, link: str,
                             real_path: Path, payload: bytes) -> None:
        member = f"./DAY0-Prepare/{PROJECT}/{RECEIPT}"
        receipt = json.loads(archive_bytes(archive, member))
        entries = {entry["name"]: entry for entry in receipt["inputs"]}
        self.assertEqual(
            {"name": name, "link": link, "real_path": os.fspath(real_path),
             "sha256": sha256_bytes(payload)},
            entries.get(name),
        )

    def assert_copy_links_jobs_are_single_file(self, sandbox, commands) -> None:
        # WP-11: never --copy-unsafe-links on the project job; --copy-links only
        # on jobs whose sources are individual files, so a linked p2p/ directory
        # can never be copied wholesale.
        for command in commands:
            self.assertNotIn("--copy-unsafe-links", command)
            if "--copy-links" in command:
                sources = [
                    token for token in command[1:-1]
                    if token.startswith(os.fspath(sandbox.http))
                ]
                self.assertTrue(sources)
                for source in sources:
                    self.assertFalse(source.endswith("/"), source)
                    self.assertTrue(Path(source).is_file(), source)

    def test_devices_csv_linked_outside_the_project_travels_as_a_regular_file(self):
        sandbox = self.sandbox()
        external = sandbox.work / "devices.csv"
        external.write_bytes(sandbox.devices)
        link = sandbox.project / "02-devices_config.csv"
        link.symlink_to(external)
        workbook(sandbox.project / "Site P2P_v1.0.xlsx", "selected")

        setup = sandbox.setup()
        self.assertEqual(0, setup.returncode, setup.stdout)
        self.assertTrue(link.is_symlink())
        self.assertEqual(sandbox.devices, external.read_bytes())
        # R-014 第 3 条：来源记录写真实路径和 sha256。
        self.assertIn(os.fspath(external), setup.stdout)
        self.assertIn(sha256_bytes(sandbox.devices), setup.stdout)

        load = sandbox.load_dry_run()
        self.assertEqual(0, load.returncode, load.stdout)

        archive = sandbox.base / "upload.tar.gz"
        sandbox.package(archive)
        members = archive_members(archive)
        member = f"./DAY0-Prepare/{PROJECT}/02-devices_config.csv"
        self.assertIn(member, members)
        self.assertTrue(members[member].isfile())
        self.assertEqual(sandbox.devices, archive_bytes(archive, member))
        self.assert_receipt_entry(
            archive, "02-devices_config.csv", os.readlink(link), external, sandbox.devices,
        )

        # The server may still hold the link an older transfer left behind;
        # the write-prewrite guard replaces that leaf with the regular file.
        server = sandbox.base / "server-html"
        server_project = server / "DAY0-Prepare" / PROJECT
        server_project.mkdir(parents=True)
        victim = sandbox.base / "server-victim.csv"
        victim.write_bytes(b"must stay untouched\n")
        (server_project / "02-devices_config.csv").symlink_to(victim)
        with redirect_stdout(io.StringIO()):
            GUARD.apply_archive_overlay(
                server, archive, sha256_bytes(archive.read_bytes()),
                lock_path=server / ".deployment.lock",
            )
        landed = server_project / "02-devices_config.csv"
        self.assertFalse(landed.is_symlink())
        self.assertTrue(landed.is_file())
        self.assertEqual(sandbox.devices, landed.read_bytes())
        self.assertEqual(b"must stay untouched\n", victim.read_bytes())

        target = sandbox.base / "sync-target"
        synced_project = target / REMOTE_ROOT.lstrip("/") / "DAY0-Prepare" / PROJECT
        synced_project.mkdir(parents=True)
        (synced_project / "02-devices_config.csv").symlink_to(victim)
        commands = sandbox.sync_project(target)
        synced = synced_project / "02-devices_config.csv"
        self.assertFalse(synced.is_symlink())
        self.assertEqual(sandbox.devices, synced.read_bytes())
        self.assertEqual(b"must stay untouched\n", victim.read_bytes())
        self.assert_copy_links_jobs_are_single_file(sandbox, commands)
        # WP-11: the project job itself excludes the link, so no sync ever puts
        # the operator's (dangling-on-server) link back over the regular file.
        sandbox.sync_project(target, labels={f"project:{PROJECT}"})
        self.assertFalse(synced.is_symlink())
        self.assertEqual(sandbox.devices, synced.read_bytes())

    def test_laptop_public_key_link_is_kept_by_setup_and_travels_as_a_regular_file(self):
        sandbox = self.sandbox()
        (sandbox.project / "02-devices_config.csv").write_bytes(sandbox.devices)
        workbook(sandbox.project / "Site P2P_v1.0.xlsx", "selected")
        key = public_key(42, "operator@desk").encode("ascii")
        external = sandbox.work / "operator.pub"
        external.write_bytes(key)
        link = sandbox.project / "laptop.pub"
        link.symlink_to(external)
        link_text = os.readlink(link)

        setup = sandbox.setup()
        self.assertEqual(0, setup.returncode, setup.stdout)
        # R-014 第 2、3 条：setup 只读用户链接，不换成本机 ~/.ssh 的 key，也不顺着链接写。
        self.assertTrue(link.is_symlink())
        self.assertEqual(link_text, os.readlink(link))
        self.assertEqual(key, external.read_bytes())
        self.assertIn(os.fspath(external), setup.stdout)
        self.assertIn(sha256_bytes(key), setup.stdout)

        archive = sandbox.base / "upload.tar.gz"
        sandbox.package(archive)
        members = archive_members(archive)
        member = f"./DAY0-Prepare/{PROJECT}/laptop.pub"
        self.assertIn(member, members)
        self.assertTrue(members[member].isfile())
        self.assertEqual(key, archive_bytes(archive, member))
        self.assert_receipt_entry(archive, "laptop.pub", link_text, external, key)

        target = sandbox.base / "sync-target"
        commands = sandbox.sync_project(target)
        synced = target / REMOTE_ROOT.lstrip("/") / "DAY0-Prepare" / PROJECT / "laptop.pub"
        self.assertFalse(synced.is_symlink())
        self.assertEqual(key, synced.read_bytes())
        self.assert_copy_links_jobs_are_single_file(sandbox, commands)

    def test_p2p_link_through_an_external_p2p_directory_passes_setup_load_and_package(self):
        sandbox = self.sandbox()
        (sandbox.project / "02-devices_config.csv").write_bytes(sandbox.devices)
        material = sandbox.work / "site-material"
        material.mkdir()
        selected = workbook(material / "Site P2P_v2.0.xlsx", "selected")
        workbook(material / "Other P2P_v9.0.xlsx", "never transferred")
        (sandbox.project / "p2p").symlink_to(material)
        canonical = sandbox.project / "p2p.xlsx"
        canonical.symlink_to("p2p/Site P2P_v2.0.xlsx")

        setup = sandbox.setup()
        self.assertEqual(0, setup.returncode, setup.stdout)
        # 用户自己建的链接优先（开发计划 G12 关于 I-021：「保留用户自己建的链接优先」）。
        self.assertEqual("p2p/Site P2P_v2.0.xlsx", os.readlink(canonical))

        load = sandbox.load_dry_run()
        self.assertEqual(0, load.returncode, load.stdout)
        # The setup child that load would run is a real step of the same flow.
        planned = [
            line for line in load.stdout.splitlines()
            if line.startswith("[DRY] (") and "01-a-setup.py" in line
        ]
        self.assertEqual(1, len(planned), load.stdout)
        planned_argv = shlex.split(re.sub(r"^\[DRY\] \(.*?\) ", "", planned[0]))
        child = sandbox.run(planned_argv)
        self.assertEqual(0, child.returncode, child.stdout)
        self.assertEqual("p2p/Site P2P_v2.0.xlsx", os.readlink(canonical))

        archive = sandbox.base / "upload.tar.gz"
        sandbox.package(archive)
        members = archive_members(archive)
        project_prefix = f"./DAY0-Prepare/{PROJECT}/"
        packaged = f"{project_prefix}{selected.name}"
        self.assertIn(packaged, members)
        self.assertTrue(members[packaged].isfile())
        p2p_receipt = json.loads(archive_bytes(archive, f"{project_prefix}03-selected-p2p.json"))
        self.assertEqual(selected.name, p2p_receipt["basename"])
        self.assertNotIn(f"{project_prefix}p2p.xlsx", members)
        self.assertEqual(
            [], [name for name in members if name.startswith(f"{project_prefix}p2p")],
        )
        self.assertEqual(
            [], [name for name, member in members.items()
                 if name.startswith(project_prefix) and member.issym()],
        )
        self.assert_receipt_entry(
            archive, "p2p.xlsx", "p2p/Site P2P_v2.0.xlsx", selected.resolve(),
            selected.read_bytes(),
        )

        target = sandbox.base / "sync-target"
        commands = sandbox.sync_project(target)
        synced_project = target / REMOTE_ROOT.lstrip("/") / "DAY0-Prepare" / PROJECT
        # Links into the operator's Work/ tree would dangle on the server, and
        # server setup cannot treat a dangling p2p as the template directory.
        self.assertFalse(os.path.lexists(synced_project / "p2p"))
        self.assertFalse((synced_project / "p2p.xlsx").is_symlink())
        self.assertEqual([], list(target.rglob("Other P2P_v9.0.xlsx")))
        self.assert_copy_links_jobs_are_single_file(sandbox, commands)

    def test_missing_link_target_is_an_error_before_any_write(self):
        sandbox = self.sandbox()
        target = sandbox.work / "devices.csv"
        (sandbox.project / "02-devices_config.csv").symlink_to(target)
        workbook(sandbox.project / "Site P2P_v1.0.xlsx", "selected")

        # The link names a file the operator has not provided yet.
        setup = sandbox.setup()
        self.assertNotEqual(0, setup.returncode, setup.stdout)
        self.assertIn("02-devices_config.csv", setup.stdout)
        # R-014 第 2 条：不往链接指向的项目外位置写任何东西。
        self.assertFalse(os.path.lexists(target))
        self.assertEqual([], list(sandbox.work.iterdir()))

        # Once provided, the same project passes setup; then the target moves
        # away (for example the Work/ directory is reorganised) before transfer.
        target.write_bytes(sandbox.devices)
        provided = sandbox.setup()
        self.assertEqual(0, provided.returncode, provided.stdout)
        target.rename(sandbox.base / "moved-devices.csv")

        output = sandbox.base / "not-created" / "upload.tar.gz"
        with self.assertRaisesRegex(ValueError, "02-devices_config.csv"):
            sandbox.package(output)
        self.assertFalse(output.parent.exists())

        with self.assertRaisesRegex(ValueError, "02-devices_config.csv"):
            sandbox.sync_jobs()
        self.assertFalse(os.path.lexists(target))


class LPLaptopKeyLinkLoadWorkflowTests(unittest.TestCase):
    """laptop.pub as the operator's own link passes real setup → load --dry-run → load's setup child.

    Expectations: 需求文档 R-014 第 3 条 lists ``laptop.pub → 自己的公钥`` as a supported user link and
    requires "setup、load 读取时跟随链接，按真实文件校验"; the workstation load is the step before
    upload/sync (手册 Runbook 2), so its key preflight must not stop such a project
    (agentWP11.report.md §6 第 5 条, §7 D1, option (a) assigned 2026-11-08).  R-014 第 2 条: nothing is
    written through the link.  A target that later disappears is still refused by load.
    """

    def test_laptop_key_link_passes_setup_load_dry_run_and_the_planned_setup_child(self):
        directory = tempfile.TemporaryDirectory(prefix="lp-laptop-link-load-")
        self.addCleanup(directory.cleanup)
        sandbox = LinkedProjectSandbox(Path(directory.name).resolve())
        (sandbox.project / "02-devices_config.csv").write_bytes(sandbox.devices)
        workbook(sandbox.project / "Site P2P_v1.0.xlsx", "selected")
        key = public_key(43, "operator@desk").encode("ascii")
        external = sandbox.work / "operator.pub"
        external.write_bytes(key)
        link = sandbox.project / "laptop.pub"
        link.symlink_to(external)
        link_text = os.readlink(link)
        home_key = (sandbox.home / ".ssh/id_ed25519.pub").read_bytes()

        setup = sandbox.setup()
        self.assertEqual(0, setup.returncode, setup.stdout)

        load = sandbox.load_dry_run()
        self.assertNotIn("项目公钥身份无效", load.stdout)
        self.assertEqual(0, load.returncode, load.stdout)
        # The key preflight accepted the linked key as the project's laptop key.
        self.assertRegex(load.stdout, r"输入检查通过：.*keys=laptop\.pub,mgmt-server\.pub")
        planned = [
            line for line in load.stdout.splitlines()
            if line.startswith("[DRY] (") and "01-a-setup.py" in line
        ]
        self.assertEqual(1, len(planned), load.stdout)
        child = sandbox.run(shlex.split(re.sub(r"^\[DRY\] \(.*?\) ", "", planned[0])))
        self.assertEqual(0, child.returncode, child.stdout)
        # The key the real load publishes (R-016 §3.2: a per-key link through the pointer) is the linked key.
        published = sandbox.http / "ztp/config/publickey/laptop.pub"
        self.assertTrue(published.is_symlink())
        self.assertEqual(key, published.read_bytes())

        # R-014 第 2、3 条：the link, its target and the operator's HOME key are untouched.
        self.assertTrue(link.is_symlink())
        self.assertEqual(link_text, os.readlink(link))
        self.assertEqual(key, external.read_bytes())
        self.assertEqual(["operator.pub"], sorted(item.name for item in sandbox.work.iterdir()))
        self.assertEqual(home_key, (sandbox.home / ".ssh/id_ed25519.pub").read_bytes())

        # The target moves away (for example Work/ is reorganised): load refuses it, writes nothing.
        external.rename(sandbox.base / "moved-operator.pub")
        moved = sandbox.load_dry_run()
        self.assertNotEqual(0, moved.returncode, moved.stdout)
        self.assertIn("laptop.pub", moved.stdout)
        self.assertEqual(link_text, os.readlink(link))
        self.assertEqual([], sorted(sandbox.work.iterdir()))


if __name__ == "__main__":
    unittest.main()
