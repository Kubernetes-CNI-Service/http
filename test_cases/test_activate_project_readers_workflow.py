#!/usr/bin/env python3
"""R-016 AP-a（v3.1.1 WP-9b）workflow：load、unload、打包、生成报告和 infra 读者都经指针认项目。

每个用例在一份按 git 索引复制的临时工作区里放两个合成项目 site-p、site-q，由夹具自己建
DAY0-Prepare/activate-project 和经指针的树链接，再依次运行真实脚本：load --dry-run
（DAY0-Prepare/11-load.py）、tar 预览（tools/tar-for-upload.py --dry-run）、sync 的 job 构建
（tools/sync-code.py）、tools/generation_report.py inspect、unload --dry-run（DAY0-Prepare/13-unload.py，
它再调 02-unsetup.py）、infra 的日志写者（infra/deploy_infra.py）和本机探针（infra/check_infra.py 的
真实 shell）。HOME 指向临时目录，输入全部是合成数据。

预期的出处（不从实现反推）：
- R-016 详细设计 v1.1 §5.1：读者一次运行开始时用 active_project_dir 解析指针一次；没有指针就是「没有激活
  的项目」，指针无效时报出原因；不再读 manifest 首行，也不从链接原文里截项目名。
- R-016 §2：树里指向项目文件的链接写成 relpath("DAY0-Prepare/activate-project/<固定名>", 链接所在目录)；
  切换只换指针，别的链接都不动。
- R-016 §3.2、§11（v1.1 补）：generation_report 校验经指针的逐把公钥链接。
- R-016 §11（v1.1 补）：原来用 realpath 取父目录认项目的读者，换成指针后要过两个夹具——
  「02-devices_config.csv → 外部文件」「ib.csv → p2p/x.csv」——认出的仍是指针选中的项目。
- R-016 §7：指针不进打包和同步。
- 详细工作指导 v3.1.1 WP-9（WP-9b 部分）：load、unload、打包、generation_report、infra 读者每类至少一个
  经指针的例子。

ReadersAfterRealSetupWorkflowTests 让真实 setup 建指针（R-016 §4.2 第 4 步），依赖 WP-3 落地；在只含
WP-9b 的提交上预期为红。
"""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import re
import site
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import yaml

from test_cases import test_project_link_inputs_workflow as linked_inputs
from test_cases.module_loader import load_script
from test_cases.test_generation_report_contract import parent_release
from test_cases.test_ssh_key_preparation_contract import public_line


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/public-project"
CONTRACT = load_script("readers_workflow_project_contract", ROOT / "tools/project_contract.py")
PROJECTS = ("site-p", "site-q")
REMOTE_ROOT = "/srv/http"


class ReaderSandbox:
    """One copied workspace with two synthetic projects; the test decides where the pointer goes."""

    def __init__(self, base: Path):
        self.base = base
        self.http = base / "http"
        linked_inputs.copy_indexed_workspace(self.http)
        self.day0 = self.http / "DAY0-Prepare"
        self.pointer = self.day0 / "activate-project"
        self.work = base / "Work"
        self.work.mkdir()
        self.home = base / "home"
        (self.home / ".ssh").mkdir(parents=True, mode=0o700)
        (self.home / ".ssh/id_ed25519.pub").write_bytes(public_line("ssh-ed25519", 41, "operator"))
        header, eth_row = (EXAMPLE / "02-devices_config.csv.example").read_text(
            encoding="utf-8").splitlines()[:2]
        self.devices = f"{header}\n{eth_row}\n".encode("utf-8")
        for seed, name in enumerate(PROJECTS):
            self.make_project(name, seed)

    def make_project(self, name: str, seed: int) -> None:
        project = self.day0 / name
        project.mkdir()
        document = yaml.safe_load((EXAMPLE / "01-global.yaml.example").read_text(encoding="utf-8"))
        document["common"]["mgmt"]["http"]["address"] = "192.0.2.10"
        document["switches"] = [item for item in document["switches"] if set(item) == {"eth"}]
        document["switches"][0]["eth"]["system"]["aaa"]["user"]["cumulus"][
            "hashed-password"] = "$6$fixture$safe-value"
        (project / "01-global.yaml").write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        (project / "02-dhcp-subnet_config.csv").write_bytes(
            (EXAMPLE / "02-dhcp-subnet_config.csv.example").read_bytes())
        (project / "02-devices_config.csv").write_bytes(self.devices)
        linked_inputs.workbook(project / f"{name} P2P_v1.0.xlsx", name)
        (project / "p2p.xlsx").symlink_to(f"{name} P2P_v1.0.xlsx")  # setup's P2P selection
        (project / "laptop.pub").write_bytes(public_line("ssh-ed25519", 50 + 2 * seed, name + "-laptop"))
        (project / "mgmt-server.pub").write_bytes(public_line("ssh-ed25519", 51 + 2 * seed, name + "-mgmt"))
        for output in ("99-output-infra", "99-output-ztp"):
            (project / output).mkdir(mode=0o700)

    def point(self, name: str | None) -> None:
        if os.path.lexists(self.pointer):
            self.pointer.unlink()
        if name is not None:
            self.pointer.symlink_to(name)

    def link(self, relative: str, fixed_name: str) -> Path:
        """A tree link in the R-016 §2 form, as setup's reconcile engine writes it."""
        path = self.http / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(CONTRACT.pointer_link_target(relative, fixed_name))
        return path

    def env(self) -> dict[str, str]:
        result = dict(os.environ)
        result["HOME"] = os.fspath(self.home)
        result["PYTHONUSERBASE"] = site.getuserbase()
        result["PYTHONDONTWRITEBYTECODE"] = "1"
        return result

    def run(self, argv: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            argv, cwd=self.http, env=self.env(), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300, check=False,
        )

    def script(self, relative: str, *arguments: str) -> subprocess.CompletedProcess:
        return self.run([sys.executable, "-B", os.fspath(self.http / relative), *arguments])

    def load_dry_run(self, project: str) -> subprocess.CompletedProcess:
        return self.script("DAY0-Prepare/11-load.py", project, "--dry-run",
                           "--host-role=workstation", "--no-upgrade")

    def upload_preview(self, project: str) -> subprocess.CompletedProcess:
        return self.script("tools/tar-for-upload.py", "--dry-run", project)

    def download_archive(self, output: Path) -> subprocess.CompletedProcess:
        # No project argument: tar-for-download packs the project the pointer selects.
        return self.script("tools/tar-for-download.py", "-o", os.fspath(output))

    def module(self, relative: str, name: str):
        return load_script(name, self.http / relative)


def preview_members(output: str) -> set[str]:
    return set(re.findall(r"^  \[[dfl]\] (\S+)", output, re.M))


def archive_projects(path: Path) -> set[str]:
    with tarfile.open(path, "r:gz") as archive:
        names = [name.removeprefix("./") for name in archive.getnames()]
    return {name.split("/")[1] for name in names if name.startswith("DAY0-Prepare/") and name.count("/") >= 1}


class PointerReadersWorkflowTests(unittest.TestCase):
    """The fixture builds the pointer and the pointer-form links; every reader follows the pointer."""

    def sandbox(self) -> ReaderSandbox:
        directory = tempfile.TemporaryDirectory(prefix="activate-readers-")
        self.addCleanup(directory.cleanup)
        return ReaderSandbox(Path(directory.name).resolve())

    def test_load_and_packaging_name_the_project_the_pointer_selects_even_with_linked_inputs(self):
        sandbox = self.sandbox()
        # R-016 §11 (v1.1): inputs that are links elsewhere must not move the project a reader names.
        site_q = sandbox.day0 / "site-q"
        external = sandbox.work / "devices.csv"
        external.write_bytes(sandbox.devices)
        (site_q / "02-devices_config.csv").unlink()
        (site_q / "02-devices_config.csv").symlink_to(external)
        (site_q / "p2p").mkdir()
        (site_q / "p2p/x.csv").write_bytes(sandbox.devices)
        (site_q / "ib.csv").symlink_to("p2p/x.csv")
        self.assertEqual(sandbox.work, (site_q / "02-devices_config.csv").resolve().parent)
        self.assertEqual(site_q / "p2p", (site_q / "ib.csv").resolve().parent)
        for relative, fixed in (("ztp/status", "99-output-ztp"), ("infra/logs", "99-output-infra"),
                                ("infiniband/ib.csv", "02-devices_config.csv")):
            sandbox.link(relative, fixed)

        sandbox.point("site-p")
        switching = sandbox.load_dry_run("site-q")
        self.assertEqual(0, switching.returncode, switching.stdout)
        self.assertIn("活动项目将从 site-p 切换到 site-q", switching.stdout)

        sandbox.point("site-q")
        same = sandbox.load_dry_run("site-q")
        self.assertEqual(0, same.returncode, same.stdout)
        self.assertIn("当前活动项目就是目标项目", same.stdout)
        archive = sandbox.base / "download.tar.gz"
        download = sandbox.download_archive(archive)
        self.assertEqual(0, download.returncode, download.stdout)
        self.assertEqual({"site-q"}, archive_projects(archive))
        preview = sandbox.upload_preview("site-q")
        self.assertEqual(0, preview.returncode, preview.stdout)
        members = preview_members(preview.stdout)
        self.assertIn("./DAY0-Prepare/site-q/01-global.yaml", members)
        self.assertIn("./DAY0-Prepare/site-q/02-devices_config.csv", members)
        self.assertFalse([name for name in members if name.startswith("./DAY0-Prepare/site-p")])
        # R-016 §7: neither the pointer nor setup's pointer-form links travel.
        for relative in ("DAY0-Prepare/activate-project", "ztp/status", "infra/logs", "infiniband/ib.csv"):
            self.assertNotIn("./" + relative, members)

        # An invalid pointer is reported with its reason; load leaves the repair to setup.
        sandbox.point("missing")
        repaired = sandbox.load_dry_run("site-p")
        self.assertEqual(0, repaired.returncode, repaired.stdout)
        self.assertIn("activate-project -> missing", repaired.stdout)
        self.assertIn("当前没有有效活动项目", repaired.stdout)
        refused = sandbox.download_archive(sandbox.base / "refused.tar.gz")
        self.assertNotEqual(0, refused.returncode)
        self.assertIn("activate-project -> missing", refused.stdout)
        self.assertFalse((sandbox.base / "refused.tar.gz").exists())

        # sync-code takes the project explicitly; its jobs still leave the pointer and the links out.
        sandbox.point("site-q")
        sync = sandbox.module("tools/sync-code.py", "readers_workflow_sync")
        with redirect_stdout(io.StringIO()):
            jobs = sync.build_jobs(site_q, REMOTE_ROOT)
        sources = {source for job in jobs for source in job.sources}
        self.assertNotIn(sandbox.pointer, sources)
        excluded = {(job.label, pattern) for job in jobs for pattern in job.excludes}
        for label, pattern in (("code:ztp", "/status"), ("code:infra", "/logs"), ("code:infiniband", "/ib.csv")):
            self.assertIn((label, pattern), excluded)

    def test_generation_report_reads_each_key_link_through_the_pointer(self):
        sandbox = self.sandbox()
        site_p = sandbox.day0 / "site-p"
        for name in ("laptop.pub", "mgmt-server.pub"):
            sandbox.link("ztp/config/publickey/" + name, name)
        parent = parent_release(site_p)
        (site_p / "99-output-ztp/current-release.json").write_text(
            json.dumps(parent, sort_keys=True) + "\n", encoding="utf-8")
        sandbox.point("site-p")
        report = sandbox.module("tools/generation_report.py", "readers_workflow_generation_report")
        published = sandbox.http / "ztp/config/publickey"
        built = report.build_report(site_p, parent, published_dir=published)
        report.commit_prepared_generation_report(report.prepare_generation_report(site_p, built))

        inspected = sandbox.script("tools/generation_report.py", "inspect", "DAY0-Prepare/site-p", "--json")
        self.assertEqual(0, inspected.returncode, inspected.stdout)
        self.assertEqual(built, json.loads(inspected.stdout))
        # The links did not change; the pointer did.  The keys they reach now belong to site-q.
        sandbox.point("site-q")
        foreign = sandbox.script("tools/generation_report.py", "inspect", "DAY0-Prepare/site-p")
        self.assertEqual(2, foreign.returncode)
        self.assertIn("another project", foreign.stdout)
        sandbox.point(None)
        absent = sandbox.script("tools/generation_report.py", "inspect", "DAY0-Prepare/site-p")
        self.assertEqual(2, absent.returncode)
        # load's same-project rollback admits the published key on the same terms (WP-9 class 1).
        load = sandbox.module("DAY0-Prepare/11-load.py", "readers_workflow_load")
        key = published / "laptop.pub"
        sandbox.point("site-p")
        self.assertEqual(site_p / "laptop.pub", load._runtime_key_source(key, site_p, os.readlink(key)))
        sandbox.point("site-q")
        with self.assertRaises(load.LoadError):
            load._runtime_key_source(key, site_p, os.readlink(key))

    def test_unload_and_infra_readers_follow_the_pointer_across_a_switch(self):
        sandbox = self.sandbox()
        infra = sandbox.http / "infra"
        sandbox.link("infra/logs", "99-output-infra")
        deploy = sandbox.module("infra/deploy_infra.py", "readers_workflow_deploy_infra")
        from test_cases import test_req19_infra_log_workflow as req19_flow
        check = sandbox.module("infra/check_infra.py", "readers_workflow_check_infra")

        def probe():
            with mock.patch.object(req19_flow, "CHECK", check):
                return req19_flow.hermetic_probe(infra, sandbox.base)

        written = {}
        for selected in PROJECTS:
            sandbox.point(selected)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(0, deploy.run_with_log("deploy_infra", lambda: 0))
            written = {name: sorted(path.name for path in (sandbox.day0 / name / "99-output-infra")
                                    .glob("deploy_infra-*.log")) for name in PROJECTS}
            self.assertIn(f"log.owner.project={selected}\n", probe())
        self.assertEqual(1, len(written["site-p"]))
        self.assertEqual(1, len(written["site-q"]))

        sandbox.point("site-q")
        unload = sandbox.script("DAY0-Prepare/13-unload.py", "--dry-run")
        self.assertEqual(0, unload.returncode, unload.stdout)
        handed = [line for line in unload.stdout.splitlines() if "02-unsetup.py" in line]
        self.assertTrue(handed, unload.stdout)
        self.assertTrue(handed[0].rstrip().endswith(os.fspath(sandbox.day0 / "site-q")), handed[0])

        sandbox.point(None)  # after unsetup (R-016 Q7): the fixed link stays and dangles
        with self.assertRaises(deploy.DeployError):
            with redirect_stdout(io.StringIO()):
                deploy.run_with_log("deploy_infra", lambda: 0)
        with self.assertRaises(subprocess.CalledProcessError) as refused:
            probe()
        self.assertIn("invalid infra log project", refused.exception.stderr)
        unload = sandbox.script("DAY0-Prepare/13-unload.py", "--dry-run")
        self.assertEqual(0, unload.returncode, unload.stdout)
        handed = [line for line in unload.stdout.splitlines() if "02-unsetup.py" in line]
        self.assertTrue(handed and handed[0].rstrip().endswith("--dry-run"), unload.stdout)


class ReadersAfterRealSetupWorkflowTests(unittest.TestCase):
    """Real setup builds the pointer (R-016 §4.2 step 4); depends on WP-3."""

    def test_the_project_setup_activates_is_the_one_every_reader_names(self):
        directory = tempfile.TemporaryDirectory(prefix="activate-readers-setup-")
        self.addCleanup(directory.cleanup)
        sandbox = ReaderSandbox(Path(directory.name).resolve())
        for name in PROJECTS:
            (sandbox.day0 / name / "laptop.pub").unlink()  # setup prepares it from HOME
        for selected in PROJECTS:
            setup = sandbox.script("DAY0-Prepare/01-a-setup.py", "-y", "--host-role=workstation",
                                   "--no-upgrade", os.fspath(sandbox.day0 / selected))
            self.assertEqual(0, setup.returncode, setup.stdout)
            self.assertTrue(sandbox.pointer.is_symlink(), "R-016 §4.2 step 4: setup switches the pointer")
            self.assertEqual(selected, os.readlink(sandbox.pointer))
            self.assertEqual("../DAY0-Prepare/activate-project/99-output-infra",
                             os.readlink(sandbox.http / "infra/logs"))
            load = sandbox.load_dry_run(selected)
            self.assertEqual(0, load.returncode, load.stdout)
            self.assertIn("当前活动项目就是目标项目", load.stdout)
            archive = sandbox.base / f"{selected}-download.tar.gz"
            download = sandbox.download_archive(archive)
            self.assertEqual(0, download.returncode, download.stdout)
            self.assertEqual({selected}, archive_projects(archive))


if __name__ == "__main__":
    unittest.main()
