"""I-006 WP-5 and I-014 WP-7 (v3.1.2 M6): 11-load's operator identity and its ~/.ssh binding.

Expectations come from the issue, design and guide texts, never from the implementation:
- 问题文档 I-006, the scheme the owner approved on 2026-10-27 (:290-306): item 1 (the sudo invoker; the home
  comes from passwd), item 2 (project and key owners compare with the operator), item 3 (a missing management
  key: tell the user to run ssh-keygen, never generate it as root for them), item 4 (files written into the
  project belong to the real user), item 7 (check root before locking; the four lock failures are reported
  apart; a wrong owner names the path, the actual and expected uid/gid and a chown command);
- v3.1.2 guide WP-5 with O7, O9 and O11 (the gid compared is the passwd primary group; root-created project
  entries are handed to the operator; a sudo load creating a project hands it to SUDO_USER), the precheck
  addendum #1 (load's own template wrapper and its laptop.pub placeholder are covered) and agentOP report
  4.4 (root-private project state, the WP-6 exclusion list http dev adopted: never handed over);
- I-014 (问题文档 :906, owner 2026-11-01: 「我们的原则是输入文件和脚本用到的模块是不能改的，但是不要包括像
  known_hosts这样的共用文件」「ztp-server是一个共用设备，可能会有别的用户动～/.ssh。」) and guide WP-7: the
  operator's ~/.ssh no longer binds nlink, mtime or ctime; the key files and the DHCP runtime directory stay
  fully bound.

Root is never real here.  Tests run as a regular user, play root through
operator_identity.resolve_operator on injected inputs (euid, SUDO_*, passwd), replace load's root check
through the M3 systemd main fixture's ``patches`` and record os.fchown instead of changing owners
(guide 2.2 #6: never mock os.geteuid as a whole).
"""

from __future__ import annotations

from contextlib import contextmanager
import functools
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_cases import test_load_collection_worker_contract as M3
from test_cases.module_loader import load_script
from test_cases.test_ssh_key_preparation_contract import public_line


ROOT = Path(__file__).resolve().parents[1]
LOAD = load_script("load_operator_contract_load", ROOT / "DAY0-Prepare/11-load.py")
ROOT_CHECK = LOAD._require_root_for_load
RESOLVE = LOAD.operator_identity.resolve_operator
INITIALIZE = LOAD.initialize_from_template
ME = pwd.getpwuid(os.geteuid())
OTHER_UID = ME.pw_uid + 1


def passwd_entry(name: str, uid: int, gid: int, home: Path | str) -> pwd.struct_passwd:
    return pwd.struct_passwd((name, "x", uid, gid, "fixture", os.fspath(home), "/bin/sh"))


def resolution(project, *, euid: int, sudo: pwd.struct_passwd | None = None,
               entries=(), owner_uid: int | None = None):
    """operator_identity.resolve_operator on injected inputs: how these tests play root."""
    by_uid = {entry.pw_uid: entry for entry in entries}
    by_name = {entry.pw_name: entry for entry in entries}

    def getpwuid(uid):
        if uid not in by_uid:
            raise KeyError(uid)
        return by_uid[uid]

    def getpwnam(name):
        if name not in by_name:
            raise KeyError(name)
        return by_name[name]

    def stat_project(path):
        metadata = os.stat(path)          # FileNotFoundError: a project still to be created (O11 ④)
        return metadata if owner_uid is None else SimpleNamespace(st_uid=owner_uid)

    environ = {} if sudo is None else {"SUDO_USER": sudo.pw_name, "SUDO_UID": str(sudo.pw_uid)}
    return RESOLVE(project, euid=euid, environ=environ, getpwuid=getpwuid,
                   getpwnam=getpwnam, stat=stat_project)


def represent(project, operator: pwd.struct_passwd, *, owner_uid: int | None = None):
    """``sudo`` by ``operator`` on a project ``operator`` owns: root acts for the operator."""
    return resolution(project, euid=0, sudo=operator, entries=(operator,), owner_uid=owner_uid)


def runs_as_self(project, operator: pwd.struct_passwd = ME):
    """The operator runs load on its own project (方式 B is the same shape with root)."""
    return resolution(project, euid=operator.pw_uid, entries=(operator,))


def public_project(path: Path, *, laptop_seed: int = 70) -> Path:
    """A project as setup leaves it: marker, empty management placeholder and a laptop key, all 0644."""
    path.mkdir(parents=True)
    path.chmod(0o755)
    for name, payload in ((".management-pubkeys", b"mgmt-server.pub\n"), ("mgmt-server.pub", b""),
                          ("laptop.pub", public_line("ssh-ed25519", laptop_seed, "laptop"))):
        leaf = path / name
        leaf.write_bytes(payload)
        leaf.chmod(0o644)
    return path


def service_pair(ssh: Path) -> Path:
    """A real Ed25519 pair in a 0700 directory (load checks it with /usr/bin/ssh-keygen -y)."""
    ssh.mkdir(parents=True)
    ssh.chmod(0o700)
    subprocess.run(
        ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "fixture@management-server",
         "-f", os.fspath(ssh / "id_ed25519")], check=True, capture_output=True,
    )
    (ssh / "id_ed25519.pub").chmod(0o644)
    return ssh


def temporary_root(test: unittest.TestCase) -> Path:
    directory = tempfile.TemporaryDirectory()
    test.addCleanup(directory.cleanup)
    return Path(directory.name).resolve()


def entries_by_inode(project: Path) -> dict[int, str]:
    """Project-relative name of every entry (links included, never followed); "" is the project."""
    names = {project.lstat().st_ino: ""}
    for directory, dirnames, filenames in os.walk(project):
        for name in (*dirnames, *filenames):
            path = Path(directory, name)
            names[path.lstat().st_ino] = path.relative_to(project).as_posix()
    return names


@contextmanager
def recorded_fchown():
    """Record every os.fchown as (inode, uid, gid); nothing changes owner."""
    calls: list[tuple[int, int, int]] = []

    def record(descriptor, uid, gid):
        calls.append((os.fstat(descriptor).st_ino, uid, gid))

    with mock.patch.object(os, "fchown", side_effect=record):
        yield calls


def handed_names(project: Path, calls) -> dict[str, tuple[int, int]]:
    names = entries_by_inode(project)
    return {names[inode]: (uid, gid) for inode, uid, gid in calls}


@contextmanager
def linux_public_ancestors(root: Path):
    """Model only root's exterior ancestors as Linux root-owned 0755; the tree under root stays real.

    The gate also forbids any permission repair: chmod/chown of every flavour fails the test.
    """
    exterior = frozenset(root.parents)
    real_lstat, real_fstat, real_open, real_close = os.lstat, os.fstat, os.open, os.close
    exterior_fds: set[int] = set()

    def outside(path) -> bool:
        return isinstance(path, (str, os.PathLike)) and Path(path) in exterior

    def modelled(metadata):
        fields = {name: getattr(metadata, name) for name in dir(metadata) if name.startswith("st_")}
        fields.update(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
        return SimpleNamespace(**fields)

    def lstat(path, *args, **kwargs):
        value = real_lstat(path, *args, **kwargs)
        return modelled(value) if outside(path) else value

    def open_file(path, *args, **kwargs):
        descriptor = real_open(path, *args, **kwargs)
        if outside(path):
            exterior_fds.add(descriptor)
        else:
            exterior_fds.discard(descriptor)
        return descriptor

    def close_file(descriptor):
        exterior_fds.discard(descriptor)
        return real_close(descriptor)

    namespace = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
    namespace.lstat = lstat
    namespace.open = open_file
    namespace.close = close_file
    namespace.fstat = lambda fd: modelled(real_fstat(fd)) if fd in exterior_fds else real_fstat(fd)
    namespace.listxattr = lambda *_args, **_kwargs: []
    for name in ("chmod", "fchmod", "lchmod", "chown", "fchown", "lchown"):
        setattr(namespace, name, mock.Mock(side_effect=AssertionError(f"the gate never repairs ({name})")))
    with mock.patch.object(LOAD, "os", namespace):
        yield namespace


@contextmanager
def report_module_as_root(owned: dict[Path, int]):
    """generation_report's own ``os`` view: euid 0 and each ``owned`` path reporting the given owner.

    Only that module's namespace changes (never the os module itself): a regular user cannot own files as
    another uid, so this models a root load on a tree the operator owns.
    """
    report = LOAD.generation_report
    real_lstat, real_fstat, real_open, real_close = os.lstat, os.fstat, os.open, os.close
    fd_owner: dict[int, int] = {}

    def owner_of(path, kwargs):
        if kwargs.get("dir_fd") is not None or not isinstance(path, (str, os.PathLike)):
            return None
        return owned.get(Path(path))

    def with_owner(metadata, uid):
        fields = {name: getattr(metadata, name) for name in dir(metadata) if name.startswith("st_")}
        fields["st_uid"] = uid
        return SimpleNamespace(**fields)

    def lstat(path, *args, **kwargs):
        value, uid = real_lstat(path, *args, **kwargs), owner_of(path, kwargs)
        return value if uid is None else with_owner(value, uid)

    def open_file(path, *args, **kwargs):
        descriptor, uid = real_open(path, *args, **kwargs), owner_of(path, kwargs)
        if uid is None:
            fd_owner.pop(descriptor, None)
        else:
            fd_owner[descriptor] = uid
        return descriptor

    def close_file(descriptor):
        fd_owner.pop(descriptor, None)
        return real_close(descriptor)

    def fstat(descriptor):
        value = real_fstat(descriptor)
        return value if descriptor not in fd_owner else with_owner(value, fd_owner[descriptor])

    namespace = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
    namespace.geteuid = lambda: 0
    namespace.lstat, namespace.open, namespace.close, namespace.fstat = lstat, open_file, close_file, fstat
    with mock.patch.object(report, "os", namespace):
        yield report


def valid_report(project_name: str) -> dict:
    fingerprints = ("SHA256:" + "A" * 43, "SHA256:" + "B" * 43)
    return {
        "schema_version": 3, "record_type": LOAD.generation_report.RECORD_TYPE,
        "project": project_name, "release_id": "0123456789abcdef0123",
        "generated_at": "2026-11-08T12:00:00+00:00",
        "public_keys": [
            {"role": role, "name": name, "algorithm": "ssh-ed25519", "fingerprint": fingerprint}
            for (role, name), fingerprint in zip(LOAD.generation_report.ROLES, fingerprints)
        ],
    }


class LoadRootAndLockTests(M3.SystemdLoadMainFixture, unittest.TestCase):
    """问题文档 I-006 方案第 7 条：加锁前先查 root；加锁失败分四类报。"""

    load_module = LOAD

    def test_linux_management_server_non_root_refused_before_lock_with_sudo_hint(self) -> None:
        # 方案第 7 条（问题文档 :299-303）: a plain user is told to use sudo, never "another load".
        result = self.run_load_main(
            self.main_args(project="demo"), self.main_inputs(http=True, dhcp=False),
            patches={"_require_root_for_load": functools.partial(ROOT_CHECK, euid=OTHER_UID)},
        )
        self.assertEqual(1, result.rc)
        self.assertIn("Linux 管理服务器上 load 需要 root", result.stderr)
        self.assertIn(f"sudo {sys.executable} ", result.stderr)
        self.assertNotIn("另一个 load", result.stderr)
        result.mocks["acquire_deployment_lock"].assert_not_called()
        result.mocks["require_no_pending_dhcp_transaction"].assert_not_called()
        result.mocks["resolve_project"].assert_not_called()

    def test_dry_run_macos_and_workstation_skip_root_check(self) -> None:
        # Same scheme item; 13-unload precedent (:563-564「--dry-run 不要求 root」).
        for host_os, role, dry_run in (
            ("Linux", "management-server", True), ("Darwin", "workstation", False),
            ("Linux", "workstation", False),
        ):
            with self.subTest(host_os=host_os, role=role, dry_run=dry_run):
                self.assertIsNone(ROOT_CHECK(host_os, role, dry_run, ["demo"], euid=OTHER_UID))
        self.assertIsNone(ROOT_CHECK("Linux", "management-server", False, ["demo"], euid=0))
        result = self.run_load_main(
            self.main_args(dry_run=True), self.main_inputs(http=False, dhcp=False),
            patches={"_require_root_for_load": functools.partial(ROOT_CHECK, euid=OTHER_UID)},
        )
        self.assertEqual(0, result.rc, result.stderr)
        self.assertNotIn("需要 root", result.stdout + result.stderr)

    def _lock_path(self) -> Path:
        lock = temporary_root(self) / ".deployment.lock"
        for patcher in (mock.patch.object(LOAD, "DEPLOYMENT_LOCK", lock), mock.patch.dict(os.environ)):
            patcher.start()
            self.addCleanup(patcher.stop)
        os.environ.pop("HTTP_DEPLOYMENT_LOCK_FD", None)
        return lock

    def test_lock_busy_keeps_another_load_text(self) -> None:
        # Regression: test_global_deployment_lock_excludes_load_and_manual_operations keeps this text.
        self._lock_path()
        holder = LOAD.acquire_deployment_lock(exclusive=True)
        self.addCleanup(LOAD.release_deployment_lock, holder)
        with self.assertRaises(LOAD.LoadError) as caught:
            LOAD.acquire_deployment_lock(exclusive=True)
        self.assertEqual(
            "另一个 load 或人工 ZTP/重置操作正在使用部署 release；请等待其完成后重试",
            str(caught.exception),
        )

    def test_lock_permission_denied_reports_permission_and_cause(self) -> None:
        # 方案第 7 条（问题文档 :301）: an unopenable lock says so and carries the system error.
        lock = self._lock_path()
        lock.write_bytes(b"")
        lock.chmod(0)
        self.addCleanup(lock.chmod, 0o644)
        with self.assertRaises(LOAD.LoadError) as caught:
            LOAD.acquire_deployment_lock(exclusive=True)
        message = str(caught.exception)
        self.assertIn("无法打开部署锁", message)
        self.assertIn("没有权限", message)
        self.assertIn("Permission denied", message)
        self.assertIn(os.fspath(lock), message)
        self.assertNotIn("另一个 load", message)

    def test_lock_file_abnormal_reports_abnormal_lock(self) -> None:
        # 方案第 7 条: a lock that is not one single-link regular file is its own cause.
        lock = self._lock_path()
        lock.write_bytes(b"")
        os.link(lock, lock.with_name("second-name"))
        with self.assertRaises(LOAD.LoadError) as caught:
            LOAD.acquire_deployment_lock(exclusive=True)
        message = str(caught.exception)
        self.assertIn("部署锁文件异常", message)
        self.assertIn("exactly one hard link", message)
        self.assertNotIn("另一个 load", message)

    def test_lock_unfinished_finish_transaction_reports_it(self) -> None:
        # 方案第 7 条: a pending finish transaction is reported as such, with its own text.
        self._lock_path()
        locks = sys.modules[LOAD.deployment_lock.__module__]
        pending = locks.FinishStateError(
            "finish transaction is pending for project demo; owner=t1; "
            "use finish-project.py resume --transaction-id t1"
        )
        with mock.patch.object(locks, "assert_writer_allowed", side_effect=pending):
            with self.assertRaises(LOAD.LoadError) as caught:
                LOAD.acquire_deployment_lock(exclusive=True)
        message = str(caught.exception)
        self.assertIn("finish 事务尚未完成", message)
        self.assertIn("finish-project.py resume --transaction-id t1", message)
        self.assertNotIn("另一个 load", message)


class LoadOperatorKeyTests(M3.SystemdLoadMainFixture, unittest.TestCase):
    """问题文档 I-006 方案第 1、3、6 条：key 从操作员 passwd 家目录读；缺 key 时不替 root 生成。"""

    load_module = LOAD

    def _validated_ssh_dir(self, result) -> Path:
        validate = result.mocks["validate_inputs"]
        validate.assert_called_once()
        return validate.call_args.args[1].ssh_dir

    def test_linux_root_ssh_dir_defaults_to_operator_passwd_home(self) -> None:
        # 方案第 1 条（问题文档 :291）：家目录取 passwd，不依赖 HOME；设计 §4.3 load 行第 2 条。
        base = temporary_root(self)
        operator = passwd_entry(ME.pw_name, ME.pw_uid, ME.pw_gid, base / "operator-home")
        resolve = mock.Mock(side_effect=lambda project: represent(project, operator))
        with mock.patch.dict(os.environ, {"HOME": os.fspath(base / "not-the-operator")}):
            result = self.run_load_main(
                self.main_args(ssh_dir=None, deployment_scope="prod"),
                self.main_inputs(http=False, dhcp=False),
                patches={"_resolve_load_operator": resolve},
            )
        self.assertEqual(0, result.rc, result.stderr)
        self.assertEqual(base / "operator-home/.ssh", self._validated_ssh_dir(result))
        resolve.assert_called_once_with(result.project)
        # Guide WP-5 step 3: one identity line, printed once.
        banner = represent(result.project, operator).banner
        self.assertEqual(1, result.stdout.count(banner), result.stdout)

    def test_macos_and_non_root_keep_path_home(self) -> None:
        # Regression: macOS formal load runs as the user; tests isolate it with HOME
        # (test_macos_load_main_reaches_real_setup_with_two_empty_template_keys).
        base = temporary_root(self)
        operator = passwd_entry(ME.pw_name, ME.pw_uid, ME.pw_gid, base / "operator-home")
        with mock.patch.dict(os.environ, {"HOME": os.fspath(base / "home")}):
            linux_self = self.run_load_main(
                self.main_args(ssh_dir=None, deployment_scope="prod"),
                self.main_inputs(http=False, dhcp=False),
            )
            macos_sudo = self.run_load_main(
                self.main_args(ssh_dir=None, host_role="workstation"),
                self.main_inputs(http=False, dhcp=False),
                patches={
                    "runtime_os": mock.Mock(return_value="Darwin"),
                    "print_macos_client_requirements": mock.Mock(return_value=None),
                    "validate_macos_client_requirements": mock.Mock(),
                    "_resolve_load_operator": mock.Mock(
                        side_effect=lambda project: represent(project, operator)),
                },
            )
        for result in (linux_self, macos_sudo):
            self.assertEqual(0, result.rc, result.stderr)
            self.assertEqual(base / "home/.ssh", self._validated_ssh_dir(result))

    def test_explicit_ssh_dir_wins_and_supervisor_keeps_root_ssh(self) -> None:
        # Regression; 方案第 6 条（问题文档 :296-298）：Docker 仍用 /root/.ssh。
        base = temporary_root(self)
        operator = passwd_entry(ME.pw_name, ME.pw_uid, ME.pw_gid, base / "operator-home")
        explicit = self.run_load_main(
            self.main_args(ssh_dir=base / "explicit", deployment_scope="prod"),
            self.main_inputs(http=False, dhcp=False),
            patches={"_resolve_load_operator": mock.Mock(
                side_effect=lambda project: represent(project, operator))},
        )
        self.assertEqual(0, explicit.rc, explicit.stderr)
        self.assertEqual(base / "explicit", self._validated_ssh_dir(explicit))

        resolve = mock.Mock(side_effect=AssertionError("Docker keeps the root authority"))
        with mock.patch.dict(os.environ, {"HOME": "/root"}):
            supervisor = self.run_load_main(
                self.main_args(ssh_dir=None, deployment_scope="prod"),
                self.main_inputs(http=False, dhcp=True), backend="supervisor",
                patches={"_resolve_load_operator": resolve},
            )
        resolve.assert_not_called()
        supervisor.mocks["ensure_management_key"].assert_called_once()
        self.assertEqual(Path("/root/.ssh"),
                         supervisor.mocks["ensure_management_key"].call_args.args[0])
        self.assertEqual(Path("/root/.ssh"), self._validated_ssh_dir(supervisor))

        refused = self.run_load_main(
            self.main_args(ssh_dir=base / "explicit", deployment_scope="prod"),
            self.main_inputs(http=False, dhcp=True), backend="supervisor",
        )
        self.assertEqual(1, refused.rc)
        self.assertIn("Supervisor management SSH authority 固定为 /root/.ssh", refused.stderr)

    def test_supervisor_unknown_owner_keeps_v311_behavior(self) -> None:
        # http dev 11-09（M6 补充约束）；开发计划 :112：Docker 冻结。容器以 root 跑、项目属主 uid 常不在容器
        # passwd 里：supervisor 后端不算操作员，不拒绝、不 chown，key 与属主比较都照 v3.1.1。
        base = temporary_root(self)

        def unknown_owner(project):
            return resolution(project, euid=0, entries=(), owner_uid=OTHER_UID)

        self.assertEqual("refuse", unknown_owner(base).action)   # what the rule would say
        resolve = mock.Mock(side_effect=unknown_owner)
        with mock.patch.dict(os.environ, {"HOME": "/root"}), recorded_fchown() as calls:
            result = self.run_load_main(
                self.main_args(ssh_dir=None, deployment_scope="prod"),
                self.main_inputs(http=True, dhcp=False), backend="supervisor",
                patches={"_resolve_load_operator": resolve,
                         # v3.1.1 had no root check: the container is not refused even for a non-root euid.
                         "_require_root_for_load": functools.partial(ROOT_CHECK, euid=OTHER_UID)},
            )
        self.assertEqual(0, result.rc, result.stderr)
        resolve.assert_not_called()
        self.assertEqual([], calls)
        self.assertNotIn("操作员：", result.stdout)
        for name in ("ensure_management_key", "prepare_pubkeys"):
            self.assertEqual(Path("/root/.ssh"), result.mocks[name].call_args_list[0].args[0]
                             if name == "ensure_management_key"
                             else result.mocks[name].call_args.kwargs["ssh_dir"])
            self.assertIsNone(result.mocks[name].call_args.kwargs.get("identity"))
        self.assertIsNone(result.mocks["validate_inputs"].call_args.kwargs.get("identity"))
        for call in result.mocks["require_http_project_source_access"].call_args_list:
            self.assertIsNone(call.kwargs.get("identity"))
        # v3.1.1 took the supervisor default from HOME and refused anything but /root/.ssh.
        with mock.patch.dict(os.environ, {"HOME": os.fspath(base / "home")}):
            refused = self.run_load_main(
                self.main_args(ssh_dir=None, deployment_scope="prod"),
                self.main_inputs(http=True, dhcp=False), backend="supervisor",
            )
        self.assertEqual(1, refused.rc)
        self.assertIn("Supervisor management SSH authority 固定为 /root/.ssh", refused.stderr)

    def test_missing_operator_key_stops_with_keygen_command_and_generates_nothing(self) -> None:
        # 方案第 3 条（问题文档 :293）：提示用户自己执行 ssh-keygen，不替 root 生成。
        base = temporary_root(self)
        project = public_project(base / "project")
        operator = passwd_entry(ME.pw_name, ME.pw_uid, ME.pw_gid, base / "home")
        identity = represent(project, operator)
        empty = base / "home/.ssh"
        empty.mkdir(parents=True)
        empty.chmod(0o700)
        for ssh in (empty, base / "missing/.ssh"):
            with self.subTest(ssh=ssh), \
                    mock.patch.object(LOAD, "_generate_native_management_key") as generate:
                with self.assertRaises(LOAD.LoadError) as caught:
                    LOAD.ensure_management_key(
                        ssh, dry_run=False, allow_generation=True, identity=identity,
                    )
                message = str(caught.exception)
                self.assertIn("ssh-keygen -t ed25519", message)
                self.assertIn(os.fspath(ssh / "id_ed25519"), message)
                self.assertIn(operator.pw_name, message)
                self.assertIn("不加 sudo", message)
                generate.assert_not_called()
        self.assertEqual([], list(empty.iterdir()))
        self.assertFalse((base / "missing").exists())

    def test_operator_root_keeps_auto_generation(self) -> None:
        # 方案第 3 条只禁止替 root 生成真实用户的 key：操作员就是运行者（方式 B：root 跑 root 的项目）时照旧生成。
        base = temporary_root(self)
        project = public_project(base / "project")
        ssh = base / "ssh"
        ssh.mkdir()
        ssh.chmod(0o700)
        with mock.patch("builtins.print") as printed:
            published = LOAD.ensure_management_key(
                ssh, dry_run=False, allow_generation=True, identity=runs_as_self(project),
            )
        self.assertEqual(ssh / "id_ed25519.pub", published)
        self.assertTrue((ssh / "id_ed25519").is_file())
        self.assertTrue(any("已生成管理服务器专用 SSH key" in str(call) for call in printed.call_args_list))


class LoadOwnerComparisonTests(M3.SystemdLoadMainFixture, unittest.TestCase):
    """问题文档 I-006 方案第 2、7 条；O9：属主比较对象是操作员，gid 是 passwd 主组。"""

    load_module = LOAD

    def setUp(self) -> None:
        self.base = temporary_root(self)
        self.project = public_project(self.base / "project")
        self.ssh = service_pair(self.base / "home/.ssh")
        self.operator = passwd_entry(ME.pw_name, ME.pw_uid, ME.pw_gid, self.base / "home")

    def _prepare(self, identity=None, **extra):
        options = {} if identity is None else {"identity": identity}
        return LOAD.prepare_pubkeys(
            self.project, ssh_dir=self.ssh, dry_run=False, inject_management_key=True,
            allow_management_key_generation=False, **options, **extra,
        )

    @contextmanager
    def _recorded_directory_owners(self):
        calls: list[tuple[Path, object]] = []
        real = LOAD._open_management_directory

        def record(path, **kwargs):
            calls.append((Path(path), kwargs.get("owner")))
            return real(path, **kwargs)

        with mock.patch.object(LOAD, "_open_management_directory", side_effect=record):
            yield calls

    def test_operator_owned_project_passes_key_directory_and_leaf_checks(self) -> None:
        # 方案第 2 条（问题文档 :292）：项目目录和公钥的属主检查改成「等于操作员身份」。
        with self._recorded_directory_owners() as calls:
            self._prepare(represent(self.project, self.operator))
        self.assertEqual((self.ssh / "id_ed25519.pub").read_bytes(),
                         (self.project / "mgmt-server.pub").read_bytes())
        expected = (self.operator.pw_uid, self.operator.pw_gid)
        self.assertIn((self.project, expected), calls)
        self.assertIn((self.ssh, expected), calls)

    def test_operator_gid_is_passwd_primary_group(self) -> None:
        # O9：属组用操作员 passwd 主组 pw_gid，不用 egid（sudo 下 egid 是 0）。
        other_group = passwd_entry(ME.pw_name, ME.pw_uid, os.getegid() + 1, self.base / "home")
        with self.assertRaises(LOAD.LoadError) as caught:
            self._prepare(represent(self.project, other_group))
        message = str(caught.exception)
        self.assertIn("owner uid/gid 不安全", message)
        self.assertIn(f"{ME.pw_uid}:{os.getegid() + 1}", message)
        self.assertEqual(b"", (self.project / "mgmt-server.pub").read_bytes())

    def test_foreign_or_root_owned_project_refused_with_path_ids_and_chown_command(self) -> None:
        # 问题文档 :302（方案第 7 条第 3 点）；设计 §4.2：非 root 运行时操作员必须等于 euid（不放宽）。
        actual = self.project.lstat()
        with self.assertRaises(LOAD.LoadError) as caught:
            LOAD._open_management_directory(
                self.project, label="项目 SSH key directory", allowed_modes=(0o755,),
                owner=(OTHER_UID, ME.pw_gid),
            )
        message = str(caught.exception)
        for fragment in (os.fspath(self.project), f"{actual.st_uid}:{actual.st_gid}",
                         f"{OTHER_UID}:{ME.pw_gid}", f"sudo chown {OTHER_UID}:{ME.pw_gid} "):
            self.assertIn(fragment, message)
        leaf = self.project / "laptop.pub"
        with self.assertRaises(LOAD.LoadError) as caught:
            LOAD._validate_management_leaf_metadata(
                leaf.lstat(), label="项目公钥 laptop.pub", mode=0o644,
                uid=OTHER_UID, gid=ME.pw_gid, path=leaf,
            )
        message = str(caught.exception)
        for fragment in (os.fspath(leaf), f"{OTHER_UID}:{ME.pw_gid}", "sudo chown"):
            self.assertIn(fragment, message)

        root_entry = passwd_entry("root", 0, 0, "/var/root")
        stranger = passwd_entry("stranger", OTHER_UID, ME.pw_gid, self.base / "stranger")
        cases = (
            ("项目属于 root", dict(entries=(root_entry, ME), owner_uid=0)),
            ("当前用户不是项目属主", dict(entries=(stranger, ME), owner_uid=OTHER_UID)),
        )
        for reason, options in cases:
            with self.subTest(reason=reason):
                resolve = mock.Mock(side_effect=lambda project, options=options: resolution(
                    project, euid=ME.pw_uid, **options))
                result = self.run_load_main(
                    self.main_args(), self.main_inputs(http=True, dhcp=False),
                    patches={"_resolve_load_operator": resolve},
                )
                self.assertEqual(1, result.rc)
                self.assertIn(reason, result.stderr)
                for step in ("require_http_project_source_access", "initialize_from_template",
                             "validate_inputs", "stop_native_ztp_monitors"):
                    result.mocks[step].assert_not_called()

    def test_prepare_pubkeys_without_operator_falls_back_to_euid(self) -> None:
        # 开发计划 :112（Docker 冻结）：不传操作员时行为同现在（按 euid、egid）。
        with self._recorded_directory_owners() as calls:
            self._prepare()
        self.assertEqual((self.ssh / "id_ed25519.pub").read_bytes(),
                         (self.project / "mgmt-server.pub").read_bytes())
        self.assertEqual({None}, {owner for _path, owner in calls})

    def test_http_gate_accepts_operator_owned_project_and_stays_read_only(self) -> None:
        # 方案第 2 条；闸门 docstring「never a chmod」：只读，属主比较对象是操作员。
        root = self.base / "document-root"
        project = root / "DAY0-Prepare/demo"
        project.mkdir(parents=True)
        for path in (root, root / "DAY0-Prepare", project):
            path.chmod(0o755)
        for name in ("laptop.pub", "mgmt-server.pub"):
            (project / name).write_bytes(public_line("ssh-ed25519", 80 if name == "laptop.pub" else 81))
            (project / name).chmod(0o644)
        stranger = passwd_entry("stranger", OTHER_UID, ME.pw_gid, self.base / "stranger")
        accepted = represent(project, self.operator)
        foreign = represent(project, stranger, owner_uid=OTHER_UID)
        with linux_public_ancestors(root) as namespace:
            LOAD.require_http_project_source_access(
                project, http_root=root, ztp_dir=root / "ztp", identity=accepted,
            )
            with self.assertRaises(LOAD.LoadError) as caught:
                LOAD.require_http_project_source_access(
                    project, http_root=root, ztp_dir=root / "ztp", identity=foreign,
                )
            for name in ("chmod", "fchmod", "lchmod", "chown", "fchown", "lchown"):
                getattr(namespace, name).assert_not_called()
        message = str(caught.exception)
        for fragment in (os.fspath(project), f"{OTHER_UID}:{ME.pw_gid}", "sudo chown"):
            self.assertIn(fragment, message)
        self.assertEqual(0o755, stat.S_IMODE(project.lstat().st_mode))

    def test_generation_report_accepts_operator_owned_output_ztp(self) -> None:
        # 方案第 2 条：generation_report 对项目目录和 99-output-ztp 的属主比较按操作员（由项目目录定）；
        # 开发计划 :112 与 http dev 11-09 补充约束：Docker supervisor 不因操作员判定变化。
        project = self.base / "DAY0-Prepare/demo"
        output = project / "99-output-ztp"
        output.mkdir(parents=True)
        operator = passwd_entry("opuser", OTHER_UID, ME.pw_gid, self.base / "opuser")
        other = passwd_entry("other", OTHER_UID + 1, ME.pw_gid, self.base / "other")
        owned = {project: OTHER_UID, output: OTHER_UID}

        def run(resolved, backend=None):
            resolve = mock.Mock(side_effect=lambda path: represent(path, resolved, owner_uid=resolved.pw_uid))
            with mock.patch.dict(os.environ), \
                    mock.patch("tools.operator_identity.resolve_operator", resolve), \
                    report_module_as_root(owned) as report:
                os.environ.pop("HTTP_ZTP_RUNTIME_BACKEND", None)
                if backend is not None:
                    os.environ["HTTP_ZTP_RUNTIME_BACKEND"] = backend
                try:
                    candidate = report.prepare_generation_report(project, valid_report("demo"))
                    report.discard_prepared_generation_report(candidate)
                    return None, resolve
                except report.GenerationReportError as exc:
                    return str(exc), resolve

        error, resolve = run(operator)
        self.assertIsNone(error)
        resolve.assert_called()
        self.assertEqual([], list(output.iterdir()))
        error, _resolve = run(other)
        self.assertIn(f"expected {OTHER_UID + 1}", error)
        error, resolve = run(operator, "supervisor")
        self.assertIn("expected 0", error)
        resolve.assert_not_called()
        owned.update({project: 0, output: 0})
        error, resolve = run(other)
        self.assertIsNone(error)
        resolve.assert_not_called()

    def test_generation_report_owner_refusal_names_uid_gid_and_quoted_chown(self) -> None:
        # 问题文档 :302（方案第 7 条第 3 点）：属主不对时报出路径、实际和期望的 uid/gid，并给出 chown 命令；
        # 审核 c-7（指导第 8 节「随 BF 一起做：c-7」），与 11-load 的 _owner_fix 同口径：实际和期望都写 uid:gid，
        # 命令是 sudo chown <uid>:<gid> <加引号的路径>。期望的 gid：操作员分支是 passwd 主组 pw_gid（O9）；
        # euid 分支（supervisor）是 egid——两个后端共用这句提示，supervisor 只是随之做文字同步，功能不变
        # （开发计划 :112 Docker 冻结）。判定本身不变，仍只比 uid。
        site = self.base / "site root"                # 项目路径带空格：命令里的路径必须加引号
        project = site / "DAY0-Prepare/demo"
        output = project / "99-output-ztp"
        output.mkdir(parents=True)
        egid = os.getegid()
        operator_gid = egid + 2                       # 与 egid、目录的实际 gid 都不同：只能来自 pw_gid
        operator = passwd_entry("opuser", OTHER_UID, operator_gid, self.base / "opuser")
        stranger_uid = OTHER_UID + 1
        project_gid, output_gid = project.lstat().st_gid, output.lstat().st_gid
        self.assertNotIn(operator_gid, (project_gid, output_gid))
        self.assertNotIn("'", os.fspath(output))
        owned = {project: OTHER_UID, output: stranger_uid}

        def refusal(backend=None) -> str:
            resolve = mock.Mock(side_effect=lambda path: represent(path, operator, owner_uid=operator.pw_uid))
            with mock.patch.dict(os.environ), \
                    mock.patch("tools.operator_identity.resolve_operator", resolve), \
                    report_module_as_root(owned) as report:
                os.environ.pop("HTTP_ZTP_RUNTIME_BACKEND", None)
                if backend is not None:
                    os.environ["HTTP_ZTP_RUNTIME_BACKEND"] = backend
                with self.assertRaises(report.GenerationReportError) as caught:
                    report.prepare_generation_report(project, valid_report("demo"))
            return str(caught.exception)

        # 操作员分支：项目目录属于操作员（实际 gid 不是 pw_gid 也通过：只比 uid），99-output-ztp 属于第三方。
        message = refusal()
        for fragment in (f"{stranger_uid}:{output_gid}", f"expected {OTHER_UID}:{operator_gid}",
                         f"sudo chown {OTHER_UID}:{operator_gid} '{output}'"):
            with self.subTest(branch="operator", fragment=fragment):
                self.assertIn(fragment, message)
        # euid 分支：supervisor 不认操作员，属于操作员的项目目录对 euid 0 就是属主不对，期望 0:egid。
        message = refusal("supervisor")
        for fragment in (f"{OTHER_UID}:{project_gid}", f"expected 0:{egid}", f"sudo chown 0:{egid} '{project}'"):
            with self.subTest(branch="supervisor", fragment=fragment):
                self.assertIn(fragment, message)


class LoadRootCreatedFilesTests(M3.SystemdLoadMainFixture, unittest.TestCase):
    """O11 ②④；问题文档 I-006 方案第 4 条：root 在项目里新建的条目交给操作员；root 私有状态不动。"""

    load_module = LOAD

    def _real_template_fill(self, **patches):
        values = {"initialize_from_template": INITIALIZE}
        values.update(patches)
        return values

    def test_new_project_dir_is_chowned_to_sudo_user(self) -> None:
        # O11 ④：sudo load 新建项目时，操作员取 SUDO_USER，新项目目录 chown 给操作员。
        base = temporary_root(self)
        invoker = passwd_entry("opuser", OTHER_UID, ME.pw_gid, base / "home")
        fresh = []

        def fresh_project(_argument):
            fresh.append(LOAD.HTTP_ROOT / "DAY0-Prepare/fresh")
            return fresh[-1]

        with recorded_fchown() as calls:
            result = self.run_load_main(
                self.main_args(), self.main_inputs(http=False, dhcp=False),
                patches=self._real_template_fill(
                    resolve_project=mock.Mock(side_effect=fresh_project),
                    _resolve_load_operator=mock.Mock(side_effect=lambda project: resolution(
                        project, euid=0, sudo=invoker, entries=(invoker,))),
                ),
            )
        self.assertEqual(2, result.rc, result.stderr)
        handed = handed_names(fresh[0], calls)
        self.assertEqual((OTHER_UID, ME.pw_gid), handed.get(""))
        expected = {""}
        for directory, dirnames, filenames in os.walk(LOAD.TEMPLATE_DIR):
            relative = Path(directory).relative_to(LOAD.TEMPLATE_DIR)
            for name in (*dirnames, *filenames):
                # A template link (ib.csv) is copied as a link: links are skipped, never followed (guide WP-6).
                if not Path(directory, name).is_symlink():
                    expected.add((relative / name).as_posix())
        # agentOP 4.4 #5: 99-output-backup is yaml-collect's root-private tree.
        expected = {name for name in expected
                    if name != "99-output-backup" and not name.startswith("99-output-backup/")}
        self.assertEqual(expected, set(handed))
        self.assertEqual(len(handed), len(calls))   # a link is never followed to an entry handed already
        self.assertEqual({(OTHER_UID, ME.pw_gid)}, set(handed.values()))

    def test_template_fill_entries_are_handed_to_operator(self) -> None:
        # 方案第 4 条（问题文档 :294）；开工核对第 5 节第 1 条：load 的模板补齐包装（含 laptop.pub 空占位）
        # 在第二个调用点新建的条目交给操作员；原有条目、链接及链接后面的东西都不动。
        base = temporary_root(self)
        outside = base / "outside"
        outside.mkdir()
        operator = passwd_entry("opuser", OTHER_UID, ME.pw_gid, base / "home")
        prepared = []

        def existing_project(_argument):
            project = LOAD.HTTP_ROOT / "DAY0-Prepare/demo"
            (project / "99-output-ztp").mkdir()
            (project / "p2p").symlink_to(outside)
            prepared.append(project)
            return project

        with recorded_fchown() as calls:
            result = self.run_load_main(
                self.main_args(), self.main_inputs(http=False, dhcp=False),
                patches=self._real_template_fill(
                    resolve_project=mock.Mock(side_effect=existing_project),
                    _resolve_load_operator=mock.Mock(side_effect=lambda project: represent(
                        project, operator, owner_uid=OTHER_UID)),
                ),
            )
        self.assertEqual(0, result.rc, result.stderr)
        handed = handed_names(prepared[0], calls)
        for name in ("laptop.pub", "02-devices_config.csv", "99-output-ztp/.gitkeep",
                     "99-output-ib_nvl/bringup/xdr-upgrade-logs"):
            self.assertEqual((OTHER_UID, ME.pw_gid), handed.get(name), name)
        for name in ("", "01-global.yaml", "99-output-ztp", "p2p",
                     "99-output-backup", "99-output-backup/.gitkeep"):
            self.assertNotIn(name, handed)
        self.assertEqual([], list(outside.iterdir()))

    def test_root_private_state_is_never_handed_over(self) -> None:
        # agentOP 报告 4.4（http dev 采纳为 WP-6 排除清单）；派工：fchown 不得碰 generations、rollback-receipts。
        self.assertEqual((
            "99-output-ztp/manual-config-sync",
            "99-output-ztp/configuration-methods",
            "99-output-dhcp/.load-dhcp-candidate-*",
            ".load-inventory-*",
            "99-output-backup",
            ".99-output-backup.retention.lock",
            ".99-output-backup.retention.jsonl",
            ".99-output-backup.retention-migration.json",
            "99-output-ztp/.ztp-monitor.pid.lock",
            "99-output-ztp/..collection-attribution.json.lock",
            "99-output-ztp/generations",
            "99-output-ztp/rollback-receipts",
            "99-output-ztp/ztp-monitor.control",
        ), LOAD.ROOT_PRIVATE_PROJECT_STATE)
        base = temporary_root(self)
        template = base / "template"
        private = (
            "99-output-ztp/generations/g1/current-release.json",
            "99-output-ztp/rollback-receipts/r1.json",
            "99-output-ztp/manual-config-sync/a/.authority",
            "99-output-dhcp/.load-dhcp-candidate-x/dhcpd.conf",
            ".load-inventory-y/devices.csv",
            "99-output-backup/.gitkeep",
            "99-output-ztp/ztp-monitor.control",
        )
        for name in (*private, "99-output-ztp/.gitkeep", "notes.txt"):
            (template / name).parent.mkdir(parents=True, exist_ok=True)
            (template / name).write_bytes(b"fixture\n")
        invoker = passwd_entry("opuser", OTHER_UID, ME.pw_gid, base / "home")
        fresh = []

        def fresh_project(_argument):
            fresh.append(LOAD.HTTP_ROOT / "DAY0-Prepare/fresh")
            return fresh[-1]

        with recorded_fchown() as calls:
            result = self.run_load_main(
                self.main_args(), self.main_inputs(http=False, dhcp=False),
                patches=self._real_template_fill(
                    TEMPLATE_DIR=template,
                    resolve_project=mock.Mock(side_effect=fresh_project),
                    _resolve_load_operator=mock.Mock(side_effect=lambda project: resolution(
                        project, euid=0, sudo=invoker, entries=(invoker,))),
                ),
            )
        self.assertEqual(2, result.rc, result.stderr)
        self.assertTrue((fresh[0] / private[0]).is_file())
        self.assertEqual(
            {"", "notes.txt", "laptop.pub", "99-output-ztp", "99-output-ztp/.gitkeep", "99-output-dhcp"},
            set(handed_names(fresh[0], calls)),
        )


class ManagementSshDirIdentityTests(unittest.TestCase):
    """I-014（问题文档 :906、:917，owner 2026-11-01）；指导 WP-7。"""

    def setUp(self) -> None:
        self.base = temporary_root(self)
        self.project = public_project(self.base / "project")
        self.ssh = service_pair(self.base / "home/.ssh")
        self.identity = runs_as_self(self.project)

    def _prepare_with(self, during):
        stages = []

        def checkpoint(stage):
            stages.append(stage)
            if stage == "service-public-held":
                during()

        with mock.patch.object(LOAD, "_management_key_checkpoint", side_effect=checkpoint):
            result = LOAD.prepare_pubkeys(
                self.project, ssh_dir=self.ssh, dry_run=False, inject_management_key=True,
                allow_management_key_generation=False, identity=self.identity,
            )
        return result, stages

    def test_touch_or_unrelated_new_file_in_ssh_dir_does_not_abort(self) -> None:
        # owner 原话（问题文档 :906）；修法（:917）：~/.ssh 目录本身的 mtime、nlink、ctime 不再锁定。
        def other_user_activity():
            os.utime(self.ssh)
            (self.ssh / "known_hosts").write_bytes(b"")
            (self.ssh / "sockets").mkdir()       # nlink of ~/.ssh changes too

        _keys, stages = self._prepare_with(other_user_activity)
        self.assertIn("service-public-held", stages)
        self.assertEqual((self.ssh / "id_ed25519.pub").read_bytes(),
                         (self.project / "mgmt-server.pub").read_bytes())

    def test_key_content_change_still_aborts(self) -> None:
        # 问题文档 :904（owner 11-02）：私钥、管理公钥继续锁定。
        def rewrite_public():
            (self.ssh / "id_ed25519.pub").write_bytes(public_line("ssh-ed25519", 90, "swapped"))

        with self.assertRaisesRegex(LOAD.LoadError, "changed, drifted, or rebound"):
            self._prepare_with(rewrite_public)
        self.assertEqual(b"", (self.project / "mgmt-server.pub").read_bytes())

    def test_ssh_dir_replaced_still_aborts(self) -> None:
        # Regression: a different ~/.ssh inode is still refused.
        def replace_directory():
            self.ssh.rename(self.ssh.with_name("ssh-old"))
            service_pair(self.ssh)

        with self.assertRaisesRegex(LOAD.LoadError, "directory identity changed or rebound"):
            self._prepare_with(replace_directory)
        self.assertEqual(b"", (self.project / "mgmt-server.pub").read_bytes())

    def test_dhcp_runtime_dir_identity_unchanged(self) -> None:
        # Regression (guide WP-7 risk): the shared identity function keeps nlink, mtime and ctime.
        runtime = self.base / "dhcp"
        runtime.mkdir()
        real_scandir = os.scandir

        def scan_while_touched(target):
            os.utime(runtime, ns=(1, 1))
            return real_scandir(target)

        with mock.patch.object(os, "scandir", side_effect=scan_while_touched):
            with self.assertRaisesRegex(LOAD.LoadError, "DHCP runtime directory changed during scan"):
                LOAD.require_no_pending_dhcp_transaction(runtime)


if __name__ == "__main__":
    unittest.main()
