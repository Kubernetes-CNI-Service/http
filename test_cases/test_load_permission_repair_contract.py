"""I-006 WP-6 (v3.1.2 M6): load checks and repairs the project's permissions for its operator.

Expectations come from the owner's decision, the issue, the design and the guide, never from the implementation:
- 问题文档 I-006: owner 2026-10-27 decided that load checks and repairs permissions at its start (:331, :407);
  scheme item 7.3 (:302): a wrong owner names the path, the actual and expected uid/gid and a chown command;
- design 设计/I-006与R-005实现计划.md §4.1 (root-private state in the project is system side), §4.4 (scope,
  remove group/other write, --dry-run lists, never replace a public key), §4.6 (a second run changes nothing),
  §6 #3 (never follow a link);
- v3.1.2 guide WP-6 (test table #1-#14) with O7 ③ (no link followed, never outside the project, a third-party
  owner lists everything and stops), O8 (the repair precedes the HTTP public-source gate, which stays read-only),
  O9 (only tighten, except the fixed modes: the project and its top-level *.pub, ~/.ssh 0700, the private key
  0600, the public key 0644; the group is the passwd primary group; Linux management server, systemd, outside
  --dry-run; dry-run lists; one [PERM] line per change), O10 ① (the project plus the operator's ~/.ssh,
  id_ed25519, id_ed25519.pub; never the code tree), O11 ③ (once more when load ends, success or failure); the
  owner accepted every default on 2026-11-07 (「同意你在v3.1.2里的默认建议」, relayed by http dev);
- http dev's WP-6 brief (2026-11-09): the operator is main's load_identity and None does nothing (the Docker
  supervisor stays v3.1.1's); root on its own project (方式 B) is repaired too, towards root; the exclusion list
  is 11-load's ROOT_PRIVATE_PROJECT_STATE (agentOP report 4.4); the release members belong to the operator before
  12-ztp-monitor restarts (the W12 boundary, agentW12 report section 7); what a rollback receipt binds with
  ctime (the five 99-output-dhcp publications, the project's top-level *.pub) is left alone while a failed load
  leaves its receipt for the next load (agentOP report 4.4, constraints 1-3);
- http dev 2026-11-09, c-16 (guide WP-6 :748 on O9 「dry-run 只列」, owner 2026-11-07 :225): the operator's own
  --dry-run without sudo (action "self") lists the [PERM] lines the sudo --dry-run lists and changes nothing.

Root is never real here.  These tests run as a regular user and play root through
operator_identity.resolve_operator on injected inputs (test_load_operator_contract's helpers).  The owners a
root load would meet are modelled in 11-load's own ``os`` view (OwnerModel): os.fchown records the call and
moves the modelled owner, nothing else changes; os.fchmod is real because every file belongs to the test user
(guide 2.2 #6: os.geteuid is never mocked).
"""

from __future__ import annotations

from contextlib import contextmanager, redirect_stdout
import io
import os
from pathlib import Path
import pwd
import stat
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases import test_load_collection_worker_contract as M3
from test_cases import test_load_operator_contract as L57
from test_cases.module_loader import load_script
from test_cases.test_ssh_key_preparation_contract import public_line


ROOT = Path(__file__).resolve().parents[1]
LOAD = load_script("load_permission_repair_contract_load", ROOT / "DAY0-Prepare/11-load.py")
REPAIR = LOAD.repair_project_permissions
ME = pwd.getpwuid(os.geteuid())
OP_UID = ME.pw_uid + 1          # a non-root operator who is not the test user: its owners are modelled
OP_GID = os.getegid() + 7       # its passwd primary group, deliberately not the running egid (O9)
THIRD_UID = ME.pw_uid + 2       # neither root nor the operator
SYSTEMD = SimpleNamespace(name="systemd")


def mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def key(path: Path) -> tuple[int, int]:
    metadata = os.lstat(path)
    return metadata.st_dev, metadata.st_ino


def perm_line(path: Path, before: tuple[int, int, int], after: tuple[int, int, int]) -> str:
    """Guide WP-6 / O9: ``[PERM] <路径> <原属主:组 原模式> -> <新属主:组 新模式>``."""
    return (f"[PERM] {path} {before[0]}:{before[1]} {before[2]:04o} "
            f"-> {after[0]}:{after[1]} {after[2]:04o}")


def perm_lines(output: str) -> list[str]:
    """The per-entry lines (an absolute path follows the tag); the summary line is not one of them."""
    return [line for line in output.splitlines() if line.startswith("[PERM] /")]


class OwnerModel:
    """11-load's own ``os`` view with modelled owners, keyed by inode.

    stat, lstat and fstat report the modelled uid:gid; os.fchown records (inode, uid, gid) and moves the model;
    os.fchmod records (inode, mode) and really runs.  ``forbid_path_calls`` makes chmod/chown by path fail the
    test: the repair changes only descriptors it holds (guide WP-6 two phases).
    """

    def __init__(self) -> None:
        self.owners: dict[tuple[int, int], tuple[int, int]] = {}
        self.chowns: list[tuple[tuple[int, int], int, int]] = []
        self.chmods: list[tuple[tuple[int, int], int]] = []

    def own(self, path: Path, uid: int, gid: int) -> None:
        self.owners[key(path)] = (uid, gid)

    def own_tree(self, top: Path, uid: int, gid: int) -> None:
        """``top`` and everything below it, links themselves included and never followed."""
        self.own(top, uid, gid)
        for directory, dirnames, filenames in os.walk(top):
            for name in (*dirnames, *filenames):
                self.own(Path(directory, name), uid, gid)

    def owner(self, path: Path) -> tuple[int, int]:
        metadata = os.lstat(path)
        return self.owners.get((metadata.st_dev, metadata.st_ino), (metadata.st_uid, metadata.st_gid))

    def changed(self) -> set[tuple[int, int]]:
        return {entry for entry, _uid, _gid in self.chowns} | {entry for entry, _mode in self.chmods}

    def _view(self, metadata):
        modelled = self.owners.get((metadata.st_dev, metadata.st_ino))
        if modelled is None:
            return metadata
        fields = {name: getattr(metadata, name) for name in dir(metadata) if name.startswith("st_")}
        fields["st_uid"], fields["st_gid"] = modelled
        return SimpleNamespace(**fields)

    @contextmanager
    def active(self, *, forbid_path_calls: bool = True):
        real_stat, real_lstat, real_fstat, real_fchmod = os.stat, os.lstat, os.fstat, os.fchmod
        namespace = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
        namespace.stat = lambda *args, **kwargs: self._view(real_stat(*args, **kwargs))
        namespace.lstat = lambda *args, **kwargs: self._view(real_lstat(*args, **kwargs))
        namespace.fstat = lambda descriptor: self._view(real_fstat(descriptor))

        def fchown(descriptor, uid, gid):
            metadata = real_fstat(descriptor)
            entry = (metadata.st_dev, metadata.st_ino)
            self.chowns.append((entry, uid, gid))
            self.owners[entry] = (uid, gid)

        def fchmod(descriptor, value):
            metadata = real_fstat(descriptor)
            self.chmods.append(((metadata.st_dev, metadata.st_ino), value))
            real_fchmod(descriptor, value)

        namespace.fchown, namespace.fchmod = fchown, fchmod
        if forbid_path_calls:
            for name in ("chown", "lchown", "chmod", "lchmod"):
                setattr(namespace, name, mock.Mock(side_effect=AssertionError(f"repair by path ({name})")))
        with mock.patch.object(LOAD, "os", namespace):
            yield self


def repair(project: Path, identity, ssh_dir: Path | None, **options) -> tuple[int, str]:
    values = dict(host_os="Linux", host_role="management-server", backend=SYSTEMD, dry_run=False)
    values.update(options)
    output = io.StringIO()
    with redirect_stdout(output):
        count = REPAIR(project, identity, ssh_dir, **values)
    return count, output.getvalue()


class PermissionRepairTests(M3.SystemdLoadMainFixture, unittest.TestCase):
    """问题文档 I-006 :331（owner 2026-10-27：load 开头检查并自动改正权限）；指导 WP-6；O7 ③、O8～O11。"""

    load_module = LOAD

    def setUp(self) -> None:
        self.base = L57.temporary_root(self)
        self.project = self.base / "DAY0-Prepare/demo"
        self.project.mkdir(parents=True)
        self.project.chmod(0o755)
        self.ssh = self.base / "home/.ssh"
        self.operator = L57.passwd_entry("opuser", OP_UID, OP_GID, self.base / "home")
        self.model = OwnerModel()
        self.model.own(self.project, 0, 0)
        self.expected_owner = (OP_UID, OP_GID)

    # ---- fixture helpers -------------------------------------------------------------------------------
    def identity(self):
        """sudo by the operator on the project the operator owns: root acts for the operator."""
        return L57.represent(self.project, self.operator, owner_uid=OP_UID)

    def write(self, relative: str, value: int, *, uid: int = 0, gid: int = 0, data: bytes = b"fixture\n") -> Path:
        path = self.project / relative
        for parent in reversed(list(path.relative_to(self.project).parents)[:-1]):
            directory = self.project / parent
            if not directory.exists():
                directory.mkdir()
                directory.chmod(0o755)
                self.model.own(directory, uid, gid)
        path.write_bytes(data)
        path.chmod(value)
        self.model.own(path, uid, gid)
        return path

    def mkdir(self, relative: str, value: int, *, uid: int = 0, gid: int = 0) -> Path:
        path = self.project / relative
        path.mkdir(parents=True)
        path.chmod(value)
        self.model.own(path, uid, gid)
        return path

    def run_repair(self, identity=None, **options) -> tuple[int, str]:
        with self.model.active():
            return repair(self.project, self.identity() if identity is None else identity, self.ssh, **options)

    # ---- guide WP-6 table #1-#13: the function ---------------------------------------------------------
    def test_private_project_dir_is_opened_to_0755_and_recorded(self) -> None:
        # #1 owner 2026-10-27（问题文档 :331）；设计 §4.4；O9：项目根固定 0755，每项一行 [PERM]。
        self.project.chmod(0o700)
        self.model.own(self.project, OP_UID, OP_GID)
        self.write("01-global.yaml", 0o644, uid=OP_UID, gid=OP_GID)
        count, output = self.run_repair()
        self.assertEqual(0o755, mode(self.project))
        self.assertEqual(
            [perm_line(self.project, (OP_UID, OP_GID, 0o700), (OP_UID, OP_GID, 0o755))], perm_lines(output),
        )
        self.assertEqual(1, count)

    def test_group_and_other_write_bits_are_removed(self) -> None:
        # #2 设计 §4.4；O9「其余只去组和其他人写」：不加任何位，也不去掉别的位。
        cases = {
            "a.csv": (0o666, 0o644), "b.txt": (0o664, 0o644), "c.txt": (0o620, 0o600),
            "run.sh": (0o700, 0o700), "d.txt": (0o646, 0o644),
        }
        for name, (before, _after) in cases.items():
            self.write(name, before)
        for name, before in (("99-output-eth", 0o777), ("99-output-eth/r1", 0o775)):
            self.mkdir(name, before)
        self.write("99-output-eth/r1/leaf-01.yaml", 0o664)
        self.run_repair()
        for name, (_before, after) in cases.items():
            self.assertEqual(after, mode(self.project / name), name)
        self.assertEqual(0o755, mode(self.project / "99-output-eth"))
        self.assertEqual(0o755, mode(self.project / "99-output-eth/r1"))
        self.assertEqual(0o644, mode(self.project / "99-output-eth/r1/leaf-01.yaml"))

    def test_existing_0600_secrets_stay_0600(self) -> None:
        # #3 O9「只收紧不放宽」：cre.json、auto.env 仍是 0600（只交给操作员）。
        secrets = (self.write("cre.json", 0o600),
                   self.write("99-output-ib_nvl/bringup/xdr-initial-setup-logs/auto.env", 0o600))
        self.run_repair()
        for path in secrets:
            self.assertEqual(0o600, mode(path), path)
            self.assertEqual(self.expected_owner, self.model.owner(path), path)

    def test_fixed_modes_for_pub_and_ssh_items(self) -> None:
        # #4 O9 固定清单：项目根的 *.pub 0644，~/.ssh 0700，私钥 0600，公钥 0644（_open_management_pair 的要求）；
        # O10 ① 只管 ~/.ssh 的这三项（I-014：~/.ssh 是共用目录，别的文件不动）。
        laptop = self.write("laptop.pub", 0o600)
        management = self.write("mgmt-server.pub", 0o664)
        nested = self.write("keys/extra.pub", 0o600)
        self.ssh.mkdir(parents=True)
        self.ssh.chmod(0o755)
        self.model.own(self.ssh, OP_UID, OP_GID)
        items = {}
        for name, before in (("id_ed25519", 0o644), ("id_ed25519.pub", 0o600), ("known_hosts", 0o666)):
            items[name] = self.ssh / name
            items[name].write_bytes(b"fixture\n")
            items[name].chmod(before)
            self.model.own(items[name], OP_UID, OP_GID)
        self.run_repair()
        self.assertEqual(0o644, mode(laptop))
        self.assertEqual(0o644, mode(management))
        self.assertEqual(0o600, mode(nested))        # not at the project root: only tightened
        self.assertEqual(0o700, mode(self.ssh))
        self.assertEqual(0o600, mode(items["id_ed25519"]))
        self.assertEqual(0o644, mode(items["id_ed25519.pub"]))
        self.assertEqual(0o666, mode(items["known_hosts"]))
        self.assertNotIn(key(items["known_hosts"]), self.model.changed())

    def test_symlinks_are_skipped_not_followed(self) -> None:
        # #5 设计 §6 第 3 条（不跟随）；O7 ③；指导 WP-6「遇到链接：跳过链接本身，不跟随、不改、不报错」：链接目标
        # 不看，所以目标属于第三方也不报错，--dry-run 也不列它。
        outside = self.base / "outside"
        outside.mkdir()
        outside.chmod(0o777)
        target = outside / "target.txt"
        target.write_bytes(b"outside\n")
        target.chmod(0o666)
        self.model.own_tree(outside, THIRD_UID, OP_GID)
        real = self.write("real.txt", 0o666)
        links = {
            "p2p": outside, "alias.txt": Path("real.txt"), "dangling": Path("missing"),
            "escape.pub": Path("../../outside/target.txt"),
        }
        for name, value in links.items():
            (self.project / name).symlink_to(value)
            self.model.own(self.project / name, 0, 0)
        self.ssh.mkdir(parents=True)
        self.ssh.chmod(0o700)
        self.model.own(self.ssh, OP_UID, OP_GID)
        (self.ssh / "id_ed25519.pub").symlink_to(target)
        before = {name: (key(self.project / name), os.readlink(self.project / name)) for name in links}
        _count, listed = self.run_repair(dry_run=True)
        self.assertEqual([perm_line(self.project, (0, 0, 0o755), (OP_UID, OP_GID, 0o755)),
                          perm_line(real, (0, 0, 0o666), (OP_UID, OP_GID, 0o644))], perm_lines(listed))
        self.run_repair()
        self.assertEqual(0o644, mode(real))
        self.assertEqual(0o777, mode(outside))
        self.assertEqual(0o666, mode(target))
        for path in (outside, target, self.ssh / "id_ed25519.pub", *(self.project / name for name in links)):
            self.assertNotIn(key(path), self.model.changed(), path)
        self.assertEqual(before, {name: (key(self.project / name), os.readlink(self.project / name))
                                  for name in links})

    def test_foreign_owner_lists_all_and_stops_before_any_change(self) -> None:
        # #6 O7 ③（第三方属主列出全部并停止，什么都不改）；问题文档 :302（路径、实际和期望的 uid/gid、chown 命令）。
        self.project.chmod(0o700)
        self.mkdir("sub", 0o755)
        foreign = (self.write("a.txt", 0o666, uid=THIRD_UID, gid=OP_GID),
                   self.write("sub/b.txt", 0o644, uid=THIRD_UID, gid=OP_GID))
        plain = self.write("c.txt", 0o666)
        with self.assertRaises(LOAD.LoadError) as caught:
            self.run_repair()
        message = str(caught.exception)
        for path in foreign:
            self.assertIn(os.fspath(path), message)
        self.assertEqual(2, message.count(f"{THIRD_UID}:{OP_GID}"), message)
        self.assertEqual(2, message.count(f"sudo chown {OP_UID}:{OP_GID} "), message)
        self.assertEqual(([], []), (self.model.chowns, self.model.chmods))
        self.assertEqual(0o700, mode(self.project))
        self.assertEqual(0o666, mode(plain))
        self.assertEqual(0o666, mode(foreign[0]))

    def test_dry_run_lists_and_changes_nothing(self) -> None:
        # #7 设计 §4.4；O9：--dry-run 只列。
        self.project.chmod(0o700)
        loose = self.write("a.csv", 0o666)
        count, output = self.run_repair(dry_run=True)
        self.assertEqual([
            perm_line(self.project, (0, 0, 0o700), (OP_UID, OP_GID, 0o755)),
            perm_line(loose, (0, 0, 0o666), (OP_UID, OP_GID, 0o644)),
        ], perm_lines(output))
        self.assertEqual(2, count)
        self.assertEqual(([], []), (self.model.chowns, self.model.chmods))
        self.assertEqual((0o700, 0o666), (mode(self.project), mode(loose)))

    def test_plain_user_dry_run_lists_what_the_sudo_run_would_change(self) -> None:
        # #7 c-16（http dev 2026-11-09 改落地；O9「dry-run 只列」，owner 11-07 已定，指导 :225、WP-6 :736、:748）：
        # Linux 管理服务器上 U 不加 sudo（动作 self）跑 --dry-run，逐项列出的 [PERM] 行与 U 经 sudo（represent）的
        # --dry-run 逐字相同，汇总是 dry-run 那一句，没有任何 fchown、fchmod；同样的输入不带 --dry-run 时仍是 0 项、
        # 没有输出（非 root 的正式 load 先被 WP-5 拒）。root 私有状态照样整棵跳过（指导 1.3、WP-6 排除清单）。
        self.project.chmod(0o700)
        self.model.own(self.project, OP_UID, OP_GID)
        loose = self.mkdir("sub", 0o775, uid=OP_UID, gid=OP_GID)
        self.mkdir("99-output-ztp", 0o755, uid=OP_UID, gid=OP_GID)
        root_written = self.write("99-output-ztp/ztp-monitor.pid", 0o644)
        self.write("99-output-ztp/generations/0123456789abcdef0123/current-release.json", 0o666)
        laptop = self.write("laptop.pub", 0o600, uid=OP_UID, gid=OP_GID)
        self.ssh.mkdir(parents=True)
        self.ssh.chmod(0o755)
        self.model.own(self.ssh, OP_UID, OP_GID)
        expected = sorted([
            perm_line(self.project, (OP_UID, OP_GID, 0o700), (OP_UID, OP_GID, 0o755)),
            perm_line(loose, (OP_UID, OP_GID, 0o775), (OP_UID, OP_GID, 0o755)),
            perm_line(root_written, (0, 0, 0o644), (OP_UID, OP_GID, 0o644)),
            perm_line(laptop, (OP_UID, OP_GID, 0o600), (OP_UID, OP_GID, 0o644)),
            perm_line(self.ssh, (OP_UID, OP_GID, 0o755), (OP_UID, OP_GID, 0o700)),
        ])
        plain = L57.resolution(self.project, euid=OP_UID, entries=(self.operator,), owner_uid=OP_UID)
        self.assertEqual(("self", OP_UID), (plain.action, plain.operator.uid))
        sudo_count, sudo_output = self.run_repair(dry_run=True)
        self.assertEqual(expected, sorted(perm_lines(sudo_output)))
        count, output = self.run_repair(plain, dry_run=True)
        self.assertEqual(expected, sorted(perm_lines(output)))
        self.assertEqual(sudo_output.splitlines(), output.splitlines())
        summary = [line for line in output.splitlines() if line not in perm_lines(output)]
        self.assertEqual(1, len(summary), output)
        self.assertTrue(summary[0].startswith(f"[PERM] dry-run：以上 {len(expected)} 项只列出，没有改动（"), summary)
        self.assertEqual((len(expected), len(expected)), (sudo_count, count))
        self.assertEqual(([], []), (self.model.chowns, self.model.chmods))
        self.assertEqual((0, ""), self.run_repair(plain))
        self.assertEqual(([], []), (self.model.chowns, self.model.chmods))
        self.assertEqual((0o700, 0o755, 0o775, 0o600), (mode(self.project), mode(self.ssh), mode(loose), mode(laptop)))
        self.assertEqual((0, 0), self.model.owner(root_written))

    def test_second_run_changes_nothing(self) -> None:
        # #8 设计 §4.6「改完再跑一次不再有改动」。
        self.project.chmod(0o700)
        self.write("a.csv", 0o666)
        self.mkdir("99-output-eth", 0o775)
        first, _output = self.run_repair()
        recorded = (list(self.model.chowns), list(self.model.chmods))
        second, output = self.run_repair()
        self.assertGreaterEqual(first, 3)
        self.assertEqual(0, second)
        self.assertEqual([], perm_lines(output))
        self.assertEqual(recorded, (self.model.chowns, self.model.chmods))

    def test_fchown_targets_operator_uid_and_primary_gid(self) -> None:
        # #9 O9：属主是操作员 uid，属组是 passwd 主组 pw_gid（sudo 下 egid 是 0，不能用）。
        self.assertNotEqual(os.getegid(), OP_GID)
        entries = (self.project, self.write("a.csv", 0o644), self.mkdir("99-output-ztp", 0o755),
                   self.write("99-output-ztp/.gitkeep", 0o644))
        self.run_repair()
        self.assertEqual({(OP_UID, OP_GID)}, {(uid, gid) for _entry, uid, gid in self.model.chowns})
        self.assertEqual({key(path) for path in entries}, {entry for entry, _uid, _gid in self.model.chowns})

    def test_root_private_state_is_excluded(self) -> None:
        # #10 设计 §4.1（系统侧）；指导 1.3、WP-6 排除清单；任务书第 3、7 条：复用 ROOT_PRIVATE_PROJECT_STATE
        # （agentOP 4.4 的 12 类），ztp-monitor.control（root:www-data 0664）不改。
        for pattern in ("99-output-ztp/manual-config-sync", "99-output-ztp/configuration-methods",
                        "99-output-dhcp/.load-dhcp-candidate-*", "99-output-ztp/ztp-monitor.control"):
            self.assertIn(pattern, LOAD.ROOT_PRIVATE_PROJECT_STATE)
        private_files = (
            "99-output-ztp/manual-config-sync/scope/.authority",
            "99-output-ztp/configuration-methods/method/.authority",
            "99-output-dhcp/.load-dhcp-candidate-a1/dhcpd.conf",
            ".load-inventory-b2/devices.csv",
            "99-output-backup/2026/leaf-01.yaml",
            ".99-output-backup.retention.lock",
            ".99-output-backup.retention.jsonl",
            ".99-output-backup.retention-migration.json",
            "99-output-ztp/.ztp-monitor.pid.lock",
            "99-output-ztp/..collection-attribution.json.lock",
            "99-output-ztp/generations/0123456789abcdef0123/current-release.json",
            "99-output-ztp/rollback-receipts/0123456789abcdef0123/receipt.json",
        )
        for name in private_files:
            self.write(name, 0o666)
        control = self.write("99-output-ztp/ztp-monitor.control", 0o664, gid=33)
        private_paths = [self.project / name for name in private_files]
        for name in private_files:
            for parent in list(Path(name).parents)[:-1]:
                if LOAD._root_private_project_state(parent.as_posix()):
                    (self.project / parent).chmod(0o777)
                    private_paths.append(self.project / parent)
        control_ok = self.write("99-output-ztp/.gitkeep", 0o666)
        (self.project / "99-output-dhcp").chmod(0o777)
        before = {path: mode(path) for path in private_paths}
        self.run_repair()
        for path in private_paths:
            self.assertNotIn(key(path), self.model.changed(), path)
            self.assertEqual(before[path], mode(path), path)
            self.assertEqual((0, 0), self.model.owner(path), path)
        self.assertNotIn(key(control), self.model.changed())
        self.assertEqual(((0, 33), 0o664), (self.model.owner(control), mode(control)))
        self.assertEqual((self.expected_owner, 0o644), (self.model.owner(control_ok), mode(control_ok)))
        self.assertEqual(0o755, mode(self.project / "99-output-dhcp"))

    def test_mgmt_pub_not_operator_key_is_reported_not_replaced(self) -> None:
        # #11 设计 §4.4 最后一条：mgmt-server.pub 不是操作员的 key 时按现有 mismatch 检查报错，不自动换。
        project = L57.public_project(self.base / "keys-project")
        management = project / "mgmt-server.pub"
        other_key = public_line("ssh-ed25519", 91, "not-the-operator")
        management.write_bytes(other_key)
        management.chmod(0o600)
        ssh = L57.service_pair(self.base / "keys-home/.ssh")
        operator = L57.passwd_entry(ME.pw_name, ME.pw_uid, ME.pw_gid, self.base / "keys-home")
        with self.model.active():
            count, _output = repair(project, L57.represent(project, operator), ssh)
        self.assertGreaterEqual(count, 1)
        self.assertEqual(0o644, mode(management))
        self.assertEqual(other_key, management.read_bytes())
        with self.assertRaisesRegex(LOAD.LoadError, "management public key mismatch"):
            LOAD.prepare_pubkeys(
                project, ssh_dir=ssh, dry_run=False, inject_management_key=True,
                allow_management_key_generation=False, identity=L57.runs_as_self(project),
            )
        self.assertEqual(other_key, management.read_bytes())

    def test_code_tree_pointer_and_links_untouched(self) -> None:
        # #12 设计 §4.1（系统侧）；指导 1.3（指针和树内链接由 root 建、不改属主）；O10 ①（代码树不碰）。
        tree = self.base
        day0 = tree / "DAY0-Prepare"
        day0.chmod(0o775)
        pointer = day0 / "activate-project"
        pointer.symlink_to("demo")
        publickey = tree / "ztp/config/publickey"
        publickey.mkdir(parents=True)
        publickey.chmod(0o775)
        published = publickey / "mgmt-server.pub"
        published.symlink_to("../../../DAY0-Prepare/activate-project/mgmt-server.pub")
        lock = tree / "ethernet/monitor/cron.lock"
        lock.parent.mkdir(parents=True)
        lock.write_bytes(b"")
        lock.chmod(0o666)
        code_tree = (tree, day0, pointer, tree / "ztp", tree / "ztp/config", publickey, published,
                     tree / "ethernet", tree / "ethernet/monitor", lock)
        for path in code_tree:
            self.model.own(path, 0, 0)
        self.write("mgmt-server.pub", 0o644)
        inside = self.write("x.txt", 0o666)
        before = {path: mode(path) for path in code_tree}
        self.run_repair()
        for path in code_tree:
            self.assertNotIn(key(path), self.model.changed(), path)
            self.assertEqual(before[path], mode(path), path)
        self.assertEqual((self.expected_owner, 0o644), (self.model.owner(inside), mode(inside)))

    def test_runs_only_on_linux_management_server_systemd(self) -> None:
        # #13 O9：只在 Linux、management-server、systemd、非 dry-run 时改；任务书第 4 条：load_identity 为 None
        # （Docker supervisor 或算出之前）什么都不做。非 root 运行（Linux 管理服务器上只可能是 --dry-run，
        # WP-5 root 检查，问题文档 :299-303）不改，dry-run 时逐项列出（c-16，见
        # test_plain_user_dry_run_lists_what_the_sudo_run_would_change；本条只测非 dry-run，断言不变）。
        # 方式 B（root 跑 root 的项目）照常改，期望属主是 root。
        self.project.chmod(0o700)
        loose = self.write("a.csv", 0o666)
        cases = {
            "macOS": dict(host_os="Darwin"),
            "workstation": dict(host_role="workstation"),
            "supervisor": dict(backend=SimpleNamespace(name="supervisor")),
            "no backend": dict(backend=None),
        }
        identities = {"identity None": None, "plain user": L57.runs_as_self(self.project)}
        for label, options in (*cases.items(), *((name, {}) for name in identities)):
            with self.subTest(label), self.model.active():
                identity = identities[label] if label in identities else self.identity()
                count, output = repair(self.project, identity, self.ssh, **options)
                self.assertEqual((0, ""), (count, output))
                self.assertEqual(([], []), (self.model.chowns, self.model.chmods))
                self.assertEqual((0o700, 0o666), (mode(self.project), mode(loose)))
        root_entry = L57.passwd_entry("root", 0, 0, self.base / "root-home")
        own_project = L57.resolution(self.project, euid=0, entries=(root_entry,), owner_uid=0)
        self.assertEqual(("self", 0), (own_project.action, own_project.operator.uid))
        count, _output = self.run_repair(own_project)
        self.assertEqual(2, count)
        self.assertEqual((0o755, 0o644), (mode(self.project), mode(loose)))
        self.assertEqual([], self.model.chowns)          # 方式 B: root's project stays root's
        count, _output = self.run_repair()
        self.assertEqual(2, count)                       # root acting for the operator: both handed over
        self.assertEqual({(OP_UID, OP_GID)}, {(uid, gid) for _entry, uid, gid in self.model.chowns})

    # ---- guide WP-6 table #14 and the call points through main() ------------------------------------
    def _main_operator(self) -> pwd.struct_passwd:
        """The operator for a main() run: the test user with a private home, so real owners are its own."""
        return L57.passwd_entry(ME.pw_name, ME.pw_uid, ME.pw_gid, self.base / "operator-home")

    def _recorded_repair(self, seen: list):
        def record(*args, **kwargs):
            seen.append(("repair", kwargs.get("receipt_bound", False)))
            return REPAIR(*args, **kwargs)
        return record

    def test_repair_precedes_http_prewrite_gate(self) -> None:
        # #14 O8（owner 2026-11-07「同意你在v3.1.2里的默认建议」，http dev 转述）：0700 的项目被改正、逐项记录、
        # 然后通过闸门，闸门本身只读；开工核对 P8-1：改正在 RV4 指针检查之后、任何监控停止和冻结之前。
        operator = self._main_operator()
        seen: list = []

        def private_project(_argument):
            project = LOAD.HTTP_ROOT / "DAY0-Prepare/demo"
            project.chmod(0o700)
            seen.append(("resolved", project.lstat()))
            return project

        def gate(project, **kwargs):
            seen.append(("gate", mode(project), kwargs.get("identity")))

        stop = mock.Mock(side_effect=lambda *_args: seen.append(("stop-monitor",)) or ())
        result = self.run_load_main(
            self.main_args(deployment_scope="prod", ssh_dir=self.base / "operator-home/.ssh"),
            self.main_inputs(http=True, dhcp=False),
            patches={
                "resolve_project": mock.Mock(side_effect=private_project),
                "_resolve_load_operator": mock.Mock(side_effect=lambda project: L57.represent(project, operator)),
                "repair_project_permissions": self._recorded_repair(seen),
                "require_http_project_source_access": mock.Mock(side_effect=gate),
                "stop_native_ztp_monitors": stop,
            },
        )
        self.assertEqual(0, result.rc, result.stderr)
        kinds = [event[0] for event in seen]
        self.assertEqual(["resolved", "repair", "gate", "stop-monitor"], kinds[:4])
        self.assertEqual(("repair", False), seen[1])
        self.assertEqual(0o755, seen[2][1])               # the gate saw the repaired project
        self.assertIsNotNone(seen[2][2])                  # and compared it with the operator
        before = seen[0][1]
        project = result.project
        self.assertIn(perm_line(project, (before.st_uid, before.st_gid, 0o700),
                                (ME.pw_uid, ME.pw_gid, 0o755)), perm_lines(result.stdout))

    def test_load_end_repair_runs_on_success_and_failure(self) -> None:
        # O11 ③ 与指导 WP-5 表（load 结束时成功或失败都再跑一次改正，L57 P6 交本包）；任务书第 5 条第 3 处：
        # 覆盖 setup 子进程以 root 新建的文件（M2 的 infra-neutral.conf）和 umask 002 下建成 0775 的中间目录。
        for outcome in ("success", "failure"):
            with self.subTest(outcome):
                model = OwnerModel()
                seen: list = []
                operator = self._main_operator()
                created: dict[str, Path] = {}

                def existing_project(_argument):
                    return LOAD.HTTP_ROOT / "DAY0-Prepare/demo"

                def setup_child(*_args, **_kwargs):
                    # the setup child runs as root under umask 002 (agentM2 report section 8; L57 P5)
                    project = LOAD.HTTP_ROOT / "DAY0-Prepare/demo"
                    tool_root = project / "infiniband/bringup/xdr-initial-setup"
                    tool_root.mkdir(parents=True)
                    for directory in (project / "infiniband", project / "infiniband/bringup", tool_root):
                        directory.chmod(0o775)
                        model.own(directory, 0, 0)
                    conf = tool_root / "infra-neutral.conf"
                    conf.write_bytes(b"NTP=192.0.2.1\n")
                    conf.chmod(0o644)
                    model.own(conf, 0, 0)
                    created["conf"] = conf
                    seen.append(("activate",))

                def late_root_file(*_args, **_kwargs):
                    # after the release-member handover: only the end-of-load repair can still reach it
                    project = LOAD.HTTP_ROOT / "DAY0-Prepare/demo"
                    output = project / "99-output-ztp"
                    output.mkdir()
                    output.chmod(0o775)
                    model.own(output, 0, 0)
                    late = output / "late.json"
                    late.write_bytes(b"{}\n")
                    late.chmod(0o664)
                    model.own(late, 0, 0)
                    created["late"] = late
                    seen.append(("late",))

                patches = {
                    "resolve_project": mock.Mock(side_effect=existing_project),
                    "_resolve_load_operator": mock.Mock(side_effect=lambda project: L57.represent(project, operator)),
                    "repair_project_permissions": self._recorded_repair(seen),
                    "activate_project": mock.Mock(side_effect=setup_child),
                    "reset_completion_handoff_state": mock.Mock(side_effect=late_root_file),
                }
                if outcome == "failure":
                    patches["generate_configs"] = mock.Mock(side_effect=LOAD.LoadError("fixture stop after setup"))
                with model.active(forbid_path_calls=False):
                    result = self.run_load_main(
                        self.main_args(deployment_scope="prod", ssh_dir=self.base / "operator-home/.ssh"),
                        self.main_inputs(http=False, dhcp=False), patches=patches,
                    )
                owner = (ME.pw_uid, ME.pw_gid)
                conf = created["conf"]
                self.assertEqual((owner, 0o644), (model.owner(conf), mode(conf)))
                for directory in (conf.parent, conf.parent.parent, conf.parent.parent.parent):
                    self.assertEqual((owner, 0o755), (model.owner(directory), mode(directory)), directory)
                repairs = [index for index, event in enumerate(seen) if event[0] == "repair"]
                if outcome == "success":
                    self.assertEqual(0, result.rc, result.stderr)
                    late = created["late"]
                    self.assertEqual((owner, 0o644), (model.owner(late), mode(late)))
                    self.assertGreater(repairs[-1], seen.index(("late",)))
                    self.assertEqual(3, len(repairs))
                else:
                    self.assertEqual(1, result.rc)
                    self.assertIn("fixture stop after setup", result.stderr)
                    self.assertNotIn("late", created)
                    self.assertEqual(2, len(repairs))
                self.assertGreater(repairs[-1], seen.index(("activate",)))

    def test_release_members_belong_to_operator_before_monitor_starts(self) -> None:
        # 任务书第 5 条第 4 处（W12 交界，agentW12 报告第 7 节）：release 成员（current-release.json、
        # 99-output-*/<release>/ 的 manifest、.published-complete、<host>.yaml）在 monitor 重启之前交给操作员，
        # 否则方式 A 下 12-ztp-monitor 的 _method_release_text 一律否决 F02 方法观察。提交之后已在回执窗口外：
        # 这时发布的 99-output-dhcp 五个文件也一起交出（agentOP 4.4 约束 1）。
        model = OwnerModel()
        seen: list = []
        at_monitor: dict[str, tuple[int, int]] = {}
        operator = self._main_operator()
        members = ("99-output-ztp/current-release.json", "99-output-eth/r1/release-manifest.json",
                   "99-output-eth/r1/.published-complete", "99-output-eth/r1/leaf-01.yaml")
        dhcp = tuple(f"99-output-dhcp/{name}" for name in sorted(LOAD._RUNTIME_DHCP_NAMES))
        projects: list[Path] = []

        def existing_project(_argument):
            project = LOAD.HTTP_ROOT / "DAY0-Prepare/demo"
            for name in ("99-output-ztp", "99-output-eth", "99-output-dhcp"):
                (project / name).mkdir()
                (project / name).chmod(0o755)
            projects.append(project)
            return project

        def root_writes(names):
            project = projects[0]
            for name in names:
                path = project / name
                if not path.parent.exists():
                    path.parent.mkdir()
                    path.parent.chmod(0o755)
                    model.own(path.parent, 0, 0)
                path.write_bytes(b"{}\n")
                path.chmod(0o644)
                model.own(path, 0, 0)

        def candidate_dir(project):
            directory = project / "99-output-dhcp/.load-dhcp-candidate-c1"
            directory.mkdir()
            model.own(directory, 0, 0)
            return directory

        candidate = SimpleNamespace(committed=False, directory_synced=True, precommit_check=None)

        def commit(prepared):
            root_writes(members)
            prepared.committed = True
            seen.append(("commit",))

        def publish_dhcp(_project, _directory, _scope):
            root_writes(dhcp)
            seen.append(("dhcp",))

        def monitor(project, **_kwargs):
            seen.append(("monitor",))
            for name in (*members, *dhcp, "99-output-eth/r1", "99-output-ztp", ""):
                at_monitor[name] = model.owner(project / name if name else project)

        report = SimpleNamespace(
            build_report=mock.Mock(return_value={}), prepare_generation_report=mock.Mock(return_value=None),
            commit_prepared_generation_report=mock.Mock(), discard_prepared_generation_report=mock.Mock(),
        )
        with model.active(forbid_path_calls=False):
            result = self.run_load_main(
                self.main_args(deployment_scope="prod", start_ztp_monitor=True,
                               ssh_dir=self.base / "operator-home/.ssh"),
                self.main_inputs(http=True, dhcp=True),
                patches={
                    "resolve_project": mock.Mock(side_effect=existing_project),
                    "_resolve_load_operator": mock.Mock(side_effect=lambda project: L57.represent(project, operator)),
                    "repair_project_permissions": self._recorded_repair(seen),
                    "_create_dhcp_candidate_dir": mock.Mock(side_effect=candidate_dir),
                    "validate_and_publish_release": mock.Mock(return_value={"schema_version": 1, "release_id": "r1"}),
                    "prepare_current_release": mock.Mock(return_value=candidate),
                    "commit_prepared_release": mock.Mock(side_effect=commit),
                    "publish_committed_dhcp_candidate": mock.Mock(side_effect=publish_dhcp),
                    "discard_prepared_release": mock.Mock(),
                    "generation_report": report,
                    "start_ztp_monitor": mock.Mock(side_effect=monitor),
                },
            )
        self.assertEqual(0, result.rc, result.stderr)
        owner = (ME.pw_uid, ME.pw_gid)
        self.assertEqual(set((*members, *dhcp, "99-output-eth/r1", "99-output-ztp", "")), set(at_monitor))
        self.assertEqual({name: owner for name in at_monitor}, at_monitor)
        # one handover between the DHCP publication (after the commit) and the monitor start, outside the
        # receipt window
        handovers = [event for event in seen[seen.index(("dhcp",)):seen.index(("monitor",))]
                     if event[0] == "repair"]
        self.assertEqual([("repair", False)], handovers)

    def test_unfinished_receipt_objects_untouched_by_end_repair(self) -> None:
        # 任务书第 6 条；agentOP 4.4 约束 1、2：load 失败、留下未完成回执由下一次 load 恢复时，load 结束时的改正
        # 不改回执带 ctime 绑定的两类对象（99-output-dhcp 的五个发布文件、发布成链接的项目 *.pub），其余照改。
        model = OwnerModel()
        seen: list = []
        operator = self._main_operator()
        dhcp = tuple(f"99-output-dhcp/{name}" for name in sorted(LOAD._RUNTIME_DHCP_NAMES))
        bound_names = (*dhcp, "mgmt-server.pub", "laptop.pub")
        projects: list[Path] = []

        def existing_project(_argument):
            project = LOAD.HTTP_ROOT / "DAY0-Prepare/demo"
            (project / "99-output-dhcp").mkdir()
            (project / "99-output-dhcp").chmod(0o755)
            # The receipt root exists whenever load holds an A receipt; v3.1.2 BF-9 keeps its restore-pending
            # marker there (guide BF-9: the marker path comes from the project and the selector id only).
            (project / "99-output-ztp/rollback-receipts").mkdir(parents=True)
            for name in bound_names:
                (project / name).write_bytes(b"published by A\n")
                (project / name).chmod(0o644)
            projects.append(project)
            return project

        def root_in_window(*_args, **_kwargs):
            # root writes inside the receipt window (after the capture, before the commit that never comes)
            project = projects[0]
            for name in bound_names:
                (project / name).chmod(0o664)
                model.own(project / name, 0, 0)
            control = project / "99-output-eth/x.yaml"
            control.parent.mkdir()
            control.parent.chmod(0o755)
            control.write_bytes(b"x\n")
            control.chmod(0o664)
            model.own(control.parent, 0, 0)
            model.own(control, 0, 0)
            seen.append(("window",))

        restore = mock.Mock(side_effect=lambda *_args, **_kwargs: seen.append(("restore",)))
        with model.active(forbid_path_calls=False):
            result = self.run_load_main(
                self.main_args(deployment_scope="prod", ssh_dir=self.base / "operator-home/.ssh"),
                self.main_inputs(http=False, dhcp=False),
                patches={
                    "resolve_project": mock.Mock(side_effect=existing_project),
                    "_resolve_load_operator": mock.Mock(side_effect=lambda project: L57.represent(project, operator)),
                    "repair_project_permissions": self._recorded_repair(seen),
                    "ensure_previous_generation_frozen": mock.Mock(return_value="generations/" + "a" * 20),
                    "prepare_active_runtime_rollback_receipt": mock.Mock(return_value=self.base / "receipt"),
                    "restore_runtime_rollback_receipt": restore,
                    "activate_project": mock.Mock(side_effect=root_in_window),
                    "generate_configs": mock.Mock(side_effect=LOAD.LoadError("fixture failure before the commit")),
                },
            )
        self.assertEqual(1, result.rc)
        self.assertIn("fixture failure before the commit", result.stderr)
        window = seen.index(("window",))
        end = [event for event in seen[window:] if event[0] == "repair"]
        self.assertEqual([("repair", True)], end)
        self.assertLess(seen.index(("restore",)), seen.index(end[0], window))
        project = projects[0]
        for name in bound_names:
            self.assertEqual(((0, 0), 0o664), (model.owner(project / name), mode(project / name)), name)
        control = project / "99-output-eth/x.yaml"
        self.assertEqual(((ME.pw_uid, ME.pw_gid), 0o644), (model.owner(control), mode(control)))

    def test_supervisor_load_never_repairs_permissions(self) -> None:
        # 任务书第 4 条与「测试」节：Docker（supervisor 后端）与 v3.1.1 逐字相同：改正函数不被调用，没有任何
        # fchown、fchmod（开发计划 :112，owner 2026-11-06「冻结 Docker 的功能」）。
        model = OwnerModel()
        wrapped = mock.Mock(wraps=REPAIR)
        resolve = mock.Mock(side_effect=AssertionError("Docker keeps the root authority"))
        loose: list[Path] = []

        def private_project(_argument):
            project = LOAD.HTTP_ROOT / "DAY0-Prepare/demo"
            project.chmod(0o700)
            path = project / "a.csv"
            path.write_bytes(b"x\n")
            path.chmod(0o666)
            loose.append(path)
            return project

        with mock.patch.dict(os.environ, {"HOME": "/root"}), model.active(forbid_path_calls=False):
            result = self.run_load_main(
                self.main_args(ssh_dir=None, deployment_scope="prod"),
                self.main_inputs(http=True, dhcp=False), backend="supervisor",
                patches={"repair_project_permissions": wrapped, "_resolve_load_operator": resolve,
                         "resolve_project": mock.Mock(side_effect=private_project)},
            )
        self.assertEqual(0, result.rc, result.stderr)
        wrapped.assert_not_called()
        resolve.assert_not_called()
        self.assertEqual(([], []), (model.chowns, model.chmods))
        self.assertEqual((0o700, 0o666), (mode(result.project), mode(loose[0])))
        self.assertNotIn("[PERM]", result.stdout)


if __name__ == "__main__":
    unittest.main()
