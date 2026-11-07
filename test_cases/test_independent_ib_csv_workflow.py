#!/usr/bin/env python3
"""R-016 AP-c workflow：独立 ib.csv（v3.1.1 WP-12）。

ETH 走 ZTP、IB 用独立 ib.csv 的项目，每个用例在一份按 git 索引复制的临时工作区里依次运行真实脚本：
setup（DAY0-Prepare/01-a-setup.py 子进程）→ load --dry-run（DAY0-Prepare/11-load.py 子进程）→ 打包
（tools/_package_common.py::create_package，tar-for-upload 用的同一个函数）→ 服务器侧安装校验
（tools/deploy-upload-archive.py::verify_inputs）→ 同步（tools/sync-code.py 的 rsync job，改为在本机目录之间
执行）。读者（monitor/generate-monitor-html.py、monitor/switch_collection_gate.py）从复制出的工作区加载。
输入全部是合成数据；链接目标放在工作区外的 Work/ 目录，HOME 指向临时目录。

预期的出处（不从实现反推）：
- R-016 详细设计 v1.1 §10.2（owner 2026-11-04 决定 E「按照默认处理」）：IB/UFM 读者统一改读
  infiniband/ib.csv；打包带上 ib.csv，是链接时按 R-014 第 3 条把内容作为文件带走；不拆的项目用模板的
  ib.csv → 02-devices_config.csv 默认链接，行为与现在相同。
- 需求文档 R-016 的 11-05 一段（owner 原话「ib.csv会是devices_config.csv的子集，只是几台oob-leaf的type会
  变成eth_jump」「ib/eth/nvl.csv文件的使用方不会是load，只会是bringup系列的脚本」）：ib.csv 是总清单的子集；
  load 不读它，所以打包只绑字节、不做语义校验；「打包带上 ib.csv 不变」。
- 详细工作指导 v3.1.1 WP-12：规格表 infiniband/ib.csv、infiniband/monitor/ib.csv、
  infiniband/bringup/xdr-upgrade/ib.csv、infiniband/bringup/ufm-setup-upgrade/ib.csv 的项目目标改为 ib.csv，
  eth.csv、nvsw.csv 不变（owner 11-03：先不拆）；模板带 git 跟踪的 ib.csv → 02-devices_config.csv；项目里没有
  ib.csv 时复制默认链接，用户换成自己的文件或链接以后不再动它；PROJECT_MATERIALIZED_INPUTS 不并进
  PROJECT_DEPLOYMENT_INPUTS；ib.csv 不是必需成员（create_package 的 required、tar-for-upload 的必需检查、
  deploy-upload-archive 的 CORE_INPUTS 都不加），但 deploy-upload-archive 不能把它当未知文件拒绝；R22 绑定
  ib.csv 的字节快照，打包后被改动时拒绝；三种形态（普通文件、默认链接、ib.csv → p2p/x.csv 指向项目外）都能
  带进包；监控页的 IB 清单改读 infiniband/monitor/ib.csv，采集门禁里 ib 类型的行改从项目的 ib.csv 读。
- R-014 第 3 条（owner 2026-11-02，以及「同意你的建议。」）：用户链接的内容作为普通文件带走，回执记下来源。

本模块只断言 ib.csv 的内容和流向（realpath、字节），不断言 setup 写出的树链接原文：v3.1.1 WP-3 落地之前
setup 写的仍是直连原文，之后改为经 DAY0-Prepare/activate-project。项目里的默认链接原文
「02-devices_config.csv」是模板链接按原文复制的结果（WP-2），不是 setup 的树链接原文。
- R-016 §4.6（--check-template，B 方案）与详细工作指导 WP-12「--check-template：template 里有 ib.csv」：
  ib.csv 是规格表的必需固定名，template 带的默认链接就是它；拿掉以后 --check-template 以 1 退出并点名 ib.csv。
"""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import site
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml

from test_cases import test_project_link_inputs_workflow as LINK_INPUTS
from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/public-project"
PROJECT = LINK_INPUTS.PROJECT
RECEIPT = LINK_INPUTS.RECEIPT
REMOTE_ROOT = LINK_INPUTS.REMOTE_ROOT
PACKAGE = LINK_INPUTS.PACKAGE
# 详细工作指导 WP-12：这 4 条树链接改到项目的 ib.csv；O2（owner 2026-11-07）加的 xdr-initial-setup/ib.csv
# 是 infiniband/ib.csv 的仓库内别名，同样到达 ib.csv。
IB_INVENTORY_TREE_PATHS = (
    "infiniband/ib.csv",
    "infiniband/monitor/ib.csv",
    "infiniband/bringup/xdr-upgrade/ib.csv",
    "infiniband/bringup/ufm-setup-upgrade/ib.csv",
    "infiniband/bringup/xdr-initial-setup/ib.csv",
)
# 「eth.csv、nvsw.csv 不变」，以及 R-016 11-05 三个网络目录各一条指向总清单的 02 链接。
DEVICES_TREE_PATHS = (
    "ethernet/eth.csv", "nvlink/nvsw.csv", "ethernet/monitor/eth.csv", "nvlink/monitor/nvsw.csv",
    "ethernet/02-devices_config.csv", "infiniband/02-devices_config.csv", "nvlink/02-devices_config.csv",
)


class IbInventorySandbox(LINK_INPUTS.LinkedProjectSandbox):
    """One copied workspace with an ETH (ZTP) + IB project and an outside Work/ directory.

    02-devices_config.csv holds one OOB leaf (eth) and two IB leaves; the independent ib.csv is a strict
    subset: the OOB leaf as eth_jump (owner 11-05) and only the first IB leaf, so a reader that still read
    02 would also see the second IB leaf.
    """

    def __init__(self, base: Path):  # noqa: D401 - replaces the eth-only project of the base sandbox
        self.base = base
        self.http = base / "http"
        LINK_INPUTS.copy_indexed_workspace(self.http)
        self.work = base / "Work"
        self.work.mkdir()
        self.home = base / "home"
        (self.home / ".ssh").mkdir(parents=True, mode=0o700)
        (self.home / ".ssh/id_ed25519.pub").write_text(
            LINK_INPUTS.public_key(51, "operator@laptop"), encoding="ascii",
        )
        self.project = self.http / "DAY0-Prepare" / PROJECT
        self.project.mkdir()
        document = yaml.safe_load((EXAMPLE / "01-global.yaml.example").read_text(encoding="utf-8"))
        document["common"]["mgmt"]["http"]["address"] = "192.0.2.10"
        document["switches"] = [item for item in document["switches"] if set(item) & {"eth", "ib"}]
        for item in document["switches"]:
            if "eth" in item:
                item["eth"]["system"]["aaa"]["user"]["cumulus"]["hashed-password"] = "$6$fixture$safe-value"
            else:
                item["ib"]["system"]["aaa"] = {"user": {"admin": {"password": "$6$fixture$safe-value"}}}
        (self.project / "01-global.yaml").write_text(
            yaml.safe_dump(document, sort_keys=False), encoding="utf-8",
        )
        shutil.copy2(EXAMPLE / "02-dhcp-subnet_config.csv.example",
                     self.project / "02-dhcp-subnet_config.csv")
        lines = (EXAMPLE / "02-devices_config.csv.example").read_text(encoding="utf-8").splitlines()
        header = lines[0]
        oob_leaf = next(line for line in lines if line.startswith("EXAMPLE-OOB-Leaf01,eth,"))
        ib_leaf = next(line for line in lines if line.startswith("EXAMPLE-IB-Leaf01,ib,"))
        second_ib_leaf = ib_leaf
        for old, new in (("EXAMPLE-IB-Leaf01", "EXAMPLE-IB-Leaf02"), ("203.0.113.21", "203.0.113.31"),
                         ("203.0.113.22", "203.0.113.32"), ("02:00:00:00:01:21", "02:00:00:00:01:31"),
                         ("02:00:00:00:01:22", "02:00:00:00:01:32")):
            second_ib_leaf = second_ib_leaf.replace(old, new)
        self.devices = "\n".join((header, oob_leaf, ib_leaf, second_ib_leaf)).encode("utf-8") + b"\n"
        jump = oob_leaf.replace("EXAMPLE-OOB-Leaf01,eth,", "EXAMPLE-OOB-Leaf01,eth_jump,", 1)
        self.ib_inventory = "\n".join((header, jump, ib_leaf)).encode("utf-8") + b"\n"
        (self.project / "02-devices_config.csv").write_bytes(self.devices)
        LINK_INPUTS.workbook(self.project / "Site P2P_v1.0.xlsx", "selected")

    def env(self) -> dict[str, str]:
        result = dict(os.environ)
        result["HOME"] = os.fspath(self.home)
        result["PYTHONUSERBASE"] = site.getuserbase()
        result["PYTHONDONTWRITEBYTECODE"] = "1"
        return result

    def reader(self, relative: str, name: str):
        """Load one production reader from the copied workspace, so its paths are the sandbox's."""
        return load_script(f"independent_ib_{name}_{id(self)}", self.http / relative)

    def verify_upload(self, archive: Path):
        installer = load_script(f"independent_ib_installer_{id(self)}",
                                self.http / "tools/deploy-upload-archive.py")
        return installer.verify_inputs(
            archive, self.http / "tools/deploy-upload-archive.py", required_uid=os.getuid(),
        )


def archive_receipt_entries(archive: Path) -> dict:
    members = LINK_INPUTS.archive_members(archive)
    member = f"./DAY0-Prepare/{PROJECT}/{RECEIPT}"
    if member not in members:
        return {}
    receipt = json.loads(LINK_INPUTS.archive_bytes(archive, member))
    return {entry["name"]: entry for entry in receipt["inputs"]}


class IndependentIbInventoryWorkflowTests(unittest.TestCase):
    def sandbox(self) -> IbInventorySandbox:
        directory = tempfile.TemporaryDirectory(prefix="independent-ib-csv-")
        self.addCleanup(directory.cleanup)
        return IbInventorySandbox(Path(directory.name).resolve())

    def assert_ib_inventory_flow(self, sandbox: IbInventorySandbox, payload: bytes) -> None:
        """Every IB inventory path reaches the project's ib.csv; the 02 paths still reach 02."""
        inventory = (sandbox.project / "ib.csv").resolve(strict=True)
        for relative in IB_INVENTORY_TREE_PATHS:
            with self.subTest(ib_inventory_link=relative):
                path = sandbox.http / relative
                self.assertEqual(inventory, path.resolve(strict=True))
                self.assertEqual(payload, path.read_bytes())
        devices = (sandbox.project / "02-devices_config.csv").resolve(strict=True)
        for relative in DEVICES_TREE_PATHS:
            with self.subTest(devices_link=relative):
                self.assertEqual(devices, (sandbox.http / relative).resolve(strict=True))

    def package(self, sandbox: IbInventorySandbox) -> Path:
        archive = sandbox.base / "upload.tar.gz"
        sandbox.package(archive)
        return archive

    def assert_packaged_regular(self, archive: Path, payload: bytes) -> None:
        members = LINK_INPUTS.archive_members(archive)
        member = f"./DAY0-Prepare/{PROJECT}/ib.csv"
        self.assertIn(member, members)
        self.assertTrue(members[member].isfile(), "ib.csv travels as a regular file")
        self.assertEqual(payload, LINK_INPUTS.archive_bytes(archive, member))

    def assert_synced_regular(self, sandbox: IbInventorySandbox, payload: bytes) -> None:
        target = sandbox.base / "sync-target"
        sandbox.sync_project(target)
        synced = target / REMOTE_ROOT.lstrip("/") / "DAY0-Prepare" / PROJECT / "ib.csv"
        self.assertFalse(synced.is_symlink())
        self.assertEqual(payload, synced.read_bytes())

    def test_eth_ztp_project_with_its_own_ib_csv_reaches_readers_package_and_sync(self):
        sandbox = self.sandbox()
        own = sandbox.project / "ib.csv"
        own.write_bytes(sandbox.ib_inventory)

        setup = sandbox.setup()
        self.assertEqual(0, setup.returncode, setup.stdout)
        # 用户换成自己的文件以后，setup 不再动它（WP-12；R-016 §1 第 6 条：项目文件夹里的文件归用户）。
        self.assertFalse(own.is_symlink())
        self.assertEqual(sandbox.ib_inventory, own.read_bytes())
        self.assert_ib_inventory_flow(sandbox, sandbox.ib_inventory)

        load = sandbox.load_dry_run()
        self.assertEqual(0, load.returncode, load.stdout)

        # Readers see ib.csv: only the first IB leaf, never the second one 02 still lists.
        page = sandbox.reader("monitor/generate-monitor-html.py", "page")
        self.assertEqual(own.resolve(), page.IB_LOG.resolve(strict=True))
        with redirect_stdout(io.StringIO()):
            aligned = page.align_with_inventory([], page.IB_LOG, {"ib"}, "IB", "IB", "fixture-batch")
        self.assertEqual(["EXAMPLE-IB-Leaf01"], [device["hostname"] for device in aligned])
        gate = sandbox.reader("monitor/switch_collection_gate.py", "gate")
        for scope in ("prod", "all"):
            with self.subTest(gate_scope=scope):
                self.assertEqual({"EXAMPLE-OOB-Leaf01", "EXAMPLE-IB-Leaf01"},
                                 set(gate.project_inventory_targets(str(sandbox.project), scope)))
        self.assertEqual((), gate.project_inventory_targets(str(sandbox.project), "air"))

        archive = self.package(sandbox)
        self.assert_packaged_regular(archive, sandbox.ib_inventory)
        self.assertNotIn("ib.csv", archive_receipt_entries(archive), "the receipt records links only")
        # deploy-upload-archive accepts ib.csv in the project root (not an unknown file).
        verified = sandbox.verify_upload(archive)
        self.assertEqual(PROJECT, verified.project)
        self.assert_synced_regular(sandbox, sandbox.ib_inventory)

    def test_default_link_outside_link_and_absent_ib_csv_all_package_and_sync(self):
        # (form, prepare the project before setup) -> expected bytes behind ib.csv.
        with self.subTest(form="template default link"):
            sandbox = self.sandbox()
            self.assertFalse(os.path.lexists(sandbox.project / "ib.csv"))
            setup = sandbox.setup()
            self.assertEqual(0, setup.returncode, setup.stdout)
            link = sandbox.project / "ib.csv"
            # 项目里没有 ib.csv 时，模板补齐复制默认链接（模板链接按原文复制，WP-2）。
            self.assertTrue(link.is_symlink())
            self.assertEqual("02-devices_config.csv", os.readlink(link))
            self.assert_ib_inventory_flow(sandbox, sandbox.devices)
            load = sandbox.load_dry_run()
            self.assertEqual(0, load.returncode, load.stdout)
            page = sandbox.reader("monitor/generate-monitor-html.py", "page")
            with redirect_stdout(io.StringIO()):
                aligned = page.align_with_inventory([], page.IB_LOG, {"ib"}, "IB", "IB", "fixture-batch")
            # 不拆的项目：行为与现在相同（两台 IB 都来自 02）。
            self.assertEqual(["EXAMPLE-IB-Leaf01", "EXAMPLE-IB-Leaf02"],
                             [device["hostname"] for device in aligned])
            archive = self.package(sandbox)
            self.assert_packaged_regular(archive, sandbox.devices)
            self.assertEqual(
                {"name": "ib.csv", "link": "02-devices_config.csv",
                 "real_path": os.fspath((sandbox.project / "02-devices_config.csv").resolve()),
                 "sha256": LINK_INPUTS.sha256_bytes(sandbox.devices)},
                archive_receipt_entries(archive).get("ib.csv"),
            )
            self.assertEqual(PROJECT, sandbox.verify_upload(archive).project)
            self.assert_synced_regular(sandbox, sandbox.devices)

        with self.subTest(form="ib.csv -> p2p/x.csv, p2p/ outside the project"):
            sandbox = self.sandbox()
            material = sandbox.work / "site-material"
            material.mkdir()
            outside = material / "x.csv"
            outside.write_bytes(sandbox.ib_inventory)
            (sandbox.project / "p2p").symlink_to(material)
            link = sandbox.project / "ib.csv"
            link.symlink_to("p2p/x.csv")
            setup = sandbox.setup()
            self.assertEqual(0, setup.returncode, setup.stdout)
            self.assertEqual("p2p/x.csv", os.readlink(link), "setup keeps the user's own link")
            self.assertEqual(sandbox.ib_inventory, outside.read_bytes())
            self.assert_ib_inventory_flow(sandbox, sandbox.ib_inventory)
            load = sandbox.load_dry_run()
            self.assertEqual(0, load.returncode, load.stdout)
            archive = self.package(sandbox)
            self.assert_packaged_regular(archive, sandbox.ib_inventory)
            self.assertEqual(
                {"name": "ib.csv", "link": "p2p/x.csv", "real_path": os.fspath(outside.resolve()),
                 "sha256": LINK_INPUTS.sha256_bytes(sandbox.ib_inventory)},
                archive_receipt_entries(archive).get("ib.csv"),
            )
            self.assertEqual(PROJECT, sandbox.verify_upload(archive).project)
            self.assert_synced_regular(sandbox, sandbox.ib_inventory)

        with self.subTest(form="absent (a project packaged without it): not a required member"):
            sandbox = self.sandbox()
            setup = sandbox.setup()
            self.assertEqual(0, setup.returncode, setup.stdout)
            (sandbox.project / "ib.csv").unlink(missing_ok=True)
            archive = self.package(sandbox)
            members = LINK_INPUTS.archive_members(archive)
            self.assertNotIn(f"./DAY0-Prepare/{PROJECT}/ib.csv", members)
            self.assertEqual(PROJECT, sandbox.verify_upload(archive).project)
            upload = load_script(f"independent_ib_upload_{id(sandbox)}", sandbox.http / "tools/tar-for-upload.py")
            upload.validate_uploaded_archive_for_deploy(archive, sandbox.project)

    def test_r22_refuses_an_ib_csv_changed_after_it_was_bound(self):
        def changed_before_publication(sandbox, path):
            original = PACKAGE._recheck_package_project_inputs

            def recheck(*args, **kwargs):
                path.write_bytes(path.read_bytes() + b"EXAMPLE-IB-Leaf09,ib\n")
                return original(*args, **kwargs)
            return mock.patch.object(PACKAGE, "_recheck_package_project_inputs", recheck)

        def changed_while_archiving_then_restored(sandbox, path):
            original_strip, original_recheck = PACKAGE.strip_xlsx_images, PACKAGE._recheck_package_project_inputs
            bound = path.read_bytes()

            def strip(*args, **kwargs):
                path.write_bytes(bound + b"EXAMPLE-IB-Leaf09,ib\n")
                return original_strip(*args, **kwargs)

            def recheck(*args, **kwargs):
                path.write_bytes(bound)
                return original_recheck(*args, **kwargs)
            stack = mock.patch.multiple(PACKAGE, strip_xlsx_images=strip, _recheck_package_project_inputs=recheck)
            return stack

        cases = (
            ("own file, changed after the archive was written", "file", changed_before_publication),
            ("link out of the project, target changed after the archive was written", "link",
             changed_before_publication),
            ("own file, changed while the archive was written and restored before the recheck", "file",
             changed_while_archiving_then_restored),
        )
        for label, form, change in cases:
            with self.subTest(case=label):
                sandbox = self.sandbox()
                if form == "file":
                    path = sandbox.project / "ib.csv"
                    path.write_bytes(sandbox.ib_inventory)
                else:
                    path = sandbox.work / "x.csv"
                    path.write_bytes(sandbox.ib_inventory)
                    (sandbox.project / "ib.csv").symlink_to(path)
                setup = sandbox.setup()
                self.assertEqual(0, setup.returncode, setup.stdout)
                output = sandbox.base / "out" / "upload.tar.gz"
                with change(sandbox, path), self.assertRaisesRegex((ValueError, RuntimeError), "ib.csv"):
                    sandbox.package(output)
                self.assertFalse(output.exists(), "nothing is published")
                self.assertEqual([], [item.name for item in output.parent.iterdir()]
                                 if output.parent.exists() else [])


    def test_check_template_finds_the_default_ib_csv_link_and_misses_it_when_gone(self):
        sandbox = self.sandbox()
        checked = sandbox.run([sys.executable, "-B", os.fspath(sandbox.http / "DAY0-Prepare/01-a-setup.py"),
                               "--check-template"])
        self.assertEqual(0, checked.returncode, checked.stdout)
        self.assertRegex(checked.stdout, r"\[OK\] ib\.csv\b")
        link = sandbox.http / "DAY0-Prepare/template/ib.csv"
        link.rename(sandbox.base / "template-ib.csv.aside")
        missing = sandbox.run([sys.executable, "-B", os.fspath(sandbox.http / "DAY0-Prepare/01-a-setup.py"),
                               "--check-template"])
        self.assertEqual(1, missing.returncode, missing.stdout)
        self.assertRegex(missing.stdout, r"\[MISSING\] ib\.csv\b")


class IndependentIbInventoryDirectTests(unittest.TestCase):
    """Single-script facts of the same contract, without a copied workspace."""

    def test_template_holds_the_tracked_default_link(self):
        link = ROOT / "DAY0-Prepare/template/ib.csv"
        self.assertTrue(link.is_symlink())
        self.assertEqual("02-devices_config.csv", os.readlink(link))
        listed = subprocess.run(
            ["git", "-C", os.fspath(ROOT), "ls-files", "-s", "--", "DAY0-Prepare/template/ib.csv"],
            check=True, stdout=subprocess.PIPE, text=True,
        ).stdout.split()
        self.assertEqual("120000", listed[0] if listed else None, "git tracks the link itself")

    def test_packaging_lists_ib_csv_as_materialized_but_never_required(self):
        self.assertIn("ib.csv", PACKAGE.PROJECT_MATERIALIZED_INPUTS)
        self.assertNotIn("ib.csv", PACKAGE.PROJECT_DEPLOYMENT_INPUTS)
        installer = load_script("independent_ib_installer_direct", ROOT / "tools/deploy-upload-archive.py")
        self.assertNotIn("ib.csv", installer.CORE_INPUTS)

    def test_collection_gate_takes_ib_rows_from_ib_csv(self):
        gate = load_script("independent_ib_gate_direct", ROOT / "monitor/switch_collection_gate.py")
        with tempfile.TemporaryDirectory(prefix="independent-ib-gate-") as directory:
            project = Path(directory)
            (project / "02-devices_config.csv").write_text(
                "hostname,type\nLeaf01,eth\nIB01,ib\nIB02,ib\nNVL01,nvl\n", encoding="utf-8",
            )
            # Absent ib.csv: the template default (a link to 02) is what an absent file stands for.
            self.assertEqual({"Leaf01", "IB01", "IB02", "NVL01"},
                             set(gate.project_inventory_targets(str(project), "prod")))
            (project / "ib.csv").write_text("hostname,type\nLeaf01,eth_jump\nIB01,ib\n", encoding="utf-8")
            self.assertEqual({"Leaf01", "IB01", "NVL01"},
                             set(gate.project_inventory_targets(str(project), "prod")))
            (project / "ib.csv").write_text("type,hostname\nib,IB01\n", encoding="utf-8")
            with self.assertRaises(gate.CollectionGateError):
                gate.project_inventory_targets(str(project), "prod")

    def test_docker_activation_accepts_the_default_ib_csv_link_and_no_other_alias(self):
        # Docker frozen (开发计划 :112, owner 2026-11-06): activation only follows the table's new target. The
        # template default ib.csv -> 02-devices_config.csv (R-016 §10.2) is bound to 02; any other alias of
        # ib.csv inside the project stays refused, so no target is laundered through it.
        from test_cases import test_ztp_container_runtime as RUNTIME
        activate = load_script("independent_ib_activate_direct", ROOT / "infra/docker/activate.py")
        outcomes = {}
        for form in ("regular file", "default link", "other alias"):
            with tempfile.TemporaryDirectory(prefix="independent-ib-docker-") as temporary:
                http_root = Path(temporary) / "html"
                project = http_root / "DAY0-Prepare" / PROJECT
                (project / "p2p").mkdir(parents=True)
                (project / "02-dhcp-subnet_config.csv").write_text("network,netmask,interface\n", encoding="utf-8")
                (project / "02-devices_config.csv").write_text("hostname,type\n", encoding="utf-8")
                (project / "p2p/x.csv").write_text("hostname,type\n", encoding="utf-8")
                if form == "default link":
                    (project / "ib.csv").symlink_to("02-devices_config.csv")
                elif form == "other alias":
                    (project / "ib.csv").symlink_to("p2p/x.csv")
                (http_root / "DAY0-Prepare/activate-project").symlink_to(PROJECT)
                for relative, (text, resolved_name, kind) in RUNTIME.REQUIRED_PUBLISHED_LINKS.items():
                    resolved = project / resolved_name
                    if kind == "dir":
                        resolved.mkdir(parents=True, exist_ok=True)
                    elif not os.path.lexists(resolved):
                        resolved.parent.mkdir(parents=True, exist_ok=True)
                        resolved.write_text("fixture\n", encoding="utf-8")
                    link = http_root / relative
                    link.parent.mkdir(parents=True, exist_ok=True)
                    link.symlink_to(text)
                for relative, (text, resolved_name) in RUNTIME.REQUIRED_DYNAMIC_P2P_LINKS.items():
                    link = http_root / relative
                    link.parent.mkdir(parents=True, exist_ok=True)
                    link.symlink_to(text)
                    target = project / resolved_name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if target.suffix == ".xlsx":
                        (project / "fixture-p2p.xlsx").write_text("fixture workbook\n", encoding="utf-8")
                        target.symlink_to("fixture-p2p.xlsx")
                    else:
                        target.write_text("{}\n", encoding="utf-8")
                (http_root / "infiniband/01-global.yaml").symlink_to("../DAY0-Prepare/activate-project/01-global.yaml")
                settings = activate.Settings(project_name=PROJECT, scope="air", http_root=http_root)
                try:
                    outcomes[form] = activate.published_link_identity(settings)["infiniband/ib.csv"]["resolved"]
                except activate.ActivationError as exc:
                    outcomes[form] = f"refused: {exc}"
        self.assertEqual(f"DAY0-Prepare/{PROJECT}/ib.csv", outcomes["regular file"])
        self.assertEqual(f"DAY0-Prepare/{PROJECT}/02-devices_config.csv", outcomes["default link"])
        self.assertTrue(outcomes["other alias"].startswith("refused: "), outcomes["other alias"])

    def test_monitor_page_reads_the_ib_inventory_alias(self):
        page = load_script("independent_ib_page_direct", ROOT / "monitor/generate-monitor-html.py")
        self.assertEqual(ROOT / "infiniband/monitor/ib.csv", page.IB_LOG)


if __name__ == "__main__":
    unittest.main()
