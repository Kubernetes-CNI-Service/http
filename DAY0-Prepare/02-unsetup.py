#!/usr/bin/env python3
"""撤销当前激活的项目：删除指针 DAY0-Prepare/activate-project；树里的链接保留，悬空表示没有激活的项目，再 setup 一次就恢复。

依据 R-016 §4.4 和 Q7。除指针外只删除（O14）：
  - ztp/.setup_manifest；
  - 4 个公钥目录里逐把公钥的链接（只删链接，目录里的普通文件不动）；
  - ztp/optimize/*-sample/* 的链接；
  - 旧版 setup 留下的 5 条旧名：99-output-ib、99-output-nvl、99-output-published、AIR/output-p2p，
    以及 monitor/99-output-ufm（它的位置上是真实文件或目录时报错、保留，其余照常进行，以 1 退出）。
撤销配置权威按指针所指的项目做；REQ10C 的 crontab 清理照旧。
操作员是指针所指项目目录的属主（I-006）：开头打印一行身份说明；以 root 运行、项目属于普通用户时，
清理的是该操作员的 crontab（crontab -u <操作员>）。身份核对不通过时不碰任何 crontab：有 REQ10C auto 状态要清理
就以 1 退出（指针和链接也不动），没有就打一条 WARN、其余照常（--dry-run 只提示）。

用法：
  python3 02-unsetup.py              # 撤销当前激活的项目
  python3 02-unsetup.py -y           # 自动删除，不询问
  python3 02-unsetup.py --dry-run    # 只显示，不实际删除
  python3 02-unsetup.py <项目>       # 只有当前激活的正是这个项目时才执行；激活的是别的项目时以 1 退出，
                                     # 没有激活的项目时以 0 退出，都不做任何改动
"""

import argparse
from contextlib import contextmanager, nullcontext
import fcntl
import os
import glob
import stat
import subprocess
import sys

HERE          = os.path.dirname(os.path.realpath(__file__))
HTTP_BASE     = os.path.normpath(os.path.join(HERE, ".."))
ZTP           = os.path.join(HTTP_BASE, "ztp")
MANIFEST_FILE = os.path.join(ZTP, ".setup_manifest")
TOOLS_DIR     = os.path.join(HTTP_BASE, "tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)
if HTTP_BASE not in sys.path:
    sys.path.insert(0, HTTP_BASE)
from ztp import config_sync_authority
from deployment_lock import DeploymentLockError, deployment_lock
from project_contract import (
    ACTIVE_PROJECT_POINTER, RETIRED_SETUP_LINKS, ActiveProjectPointerError, active_project_dir,
    infra_log_root_lock, managed_infra_log_project, setup_dynamic_link_patterns,
)
from ztp_service_runtime import RuntimeContractError, stop_native_ztp_monitors
import operator_identity

_AUTO_YES = False
_DRY_RUN  = False

RESET  = "\033[0m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
CYAN   = "\033[36m"


def _c(color, text):
    return f"{color}{text}{RESET}"


def _inside(path, root):
    """path 是否位于 root 内（使用规范化绝对路径，不跟随末端链接）。"""
    path_abs = os.path.abspath(path)
    root_abs = os.path.abspath(root)
    return path_abs == root_abs or path_abs.startswith(root_abs + os.sep)


# O14 (owner 2026-11-07 「同意你的建议。」 via http dev): names older setups created, relative to ztp/.
LEGACY_ZTP_LINKS = (
    "config/nvos/template/99-output-ib",
    "config/nvos/template/99-output-nvl",
    "config/nvos/template/99-output-published",
    "config/cumulus/template/AIR/output-p2p",
)


def _known_ztp_project_links():
    """ztp/ 下要删除的链接（O14）：4 条旧名，以及规格表动态一节在 ztp/ 下的逐个链接。

    规格表里的固定链接不在其中：unsetup 保留它们，悬空即「没有激活的项目」（Q7）。
    """
    paths = [os.path.join(ZTP, rel) for rel in LEGACY_ZTP_LINKS]
    for pattern in setup_dynamic_link_patterns():
        if pattern.startswith("ztp/"):
            paths.extend(glob.glob(os.path.join(ZTP, pattern[len("ztp/"):])))
    return [path for path in sorted(set(paths)) if os.path.islink(path)]


def _known_workspace_links():
    """ztp/ 之外要删除的链接（O14）：规格表动态一节的逐把公钥链接，以及已退役的 monitor/99-output-ufm。"""
    paths = [os.path.join(HTTP_BASE, name) for name in RETIRED_SETUP_LINKS]
    for pattern in setup_dynamic_link_patterns():
        if not pattern.startswith("ztp/"):
            paths.extend(glob.glob(os.path.join(HTTP_BASE, pattern)))
    return [path for path in sorted(paths) if os.path.islink(path)]


def _resolve_project(project):
    if not project:
        return None
    path = project if os.path.isabs(project) else os.path.join(HERE, project)
    path = os.path.realpath(path)
    if not os.path.isdir(path):
        print(_c(RED, f"[ERROR] 项目目录不存在：{path}"))
        sys.exit(1)
    if not _inside(path, HERE):
        print(_c(RED, f"[ERROR] 项目目录必须位于 {HERE} 内：{path}"))
        sys.exit(1)
    return path


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("project", nargs="?", help="只有当前激活的正是该 DAY0 项目时才执行")
    parser.add_argument("-y", "--yes", action="store_true", help="自动确认删除")
    parser.add_argument("--dry-run", action="store_true", help="仅显示将删除的链接")
    return parser.parse_args(argv)


@contextmanager
def _req10c_crontab_lock(state, operator=None):
    """Use the same persistent project lock inode as initial-setup.py.

    operator: the project owner root acts for (operator_identity "represent", I-006), else None.  The
    directory and the lock must belong to it instead of to the current user.
    """
    owner = os.geteuid() if operator is None else operator.uid
    if not all(hasattr(os, name) for name in ("O_DIRECTORY", "O_CLOEXEC", "O_NOFOLLOW")):
        raise OSError("REQ10C secure project crontab lock flags unavailable")
    try:
        directory_fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as exc:
        raise OSError(f"REQ10C project crontab lock directory open failed: {exc}") from exc
    try:
        directory_info = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or directory_info.st_uid != owner
            or directory_info.st_mode & 0o022
        ):
            raise OSError("REQ10C project crontab lock directory is not safely owned")
        try:
            fd = os.open(
                "auto-crontab.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600, dir_fd=directory_fd,
            )
        except OSError as exc:
            raise OSError(f"REQ10C project crontab lock open failed: {exc}") from exc
        try:
            info = os.fstat(fd)
            if (
                operator is not None and info.st_uid == os.geteuid()
                and stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_mode & 0o777 == 0o600
            ):
                # O11 ②: root made this lock in the operator's directory just now (the operator's own
                # initial-setup needs it as its 0600 file); hand it over before first use.  Only a
                # single-link regular file, so a planted hard link is never handed over.
                os.fchown(fd, operator.uid, operator.gid)
                info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != owner
                or info.st_mode & 0o777 != 0o600
            ):
                raise OSError("REQ10C project crontab lock is not an owned 0600 single-link file")
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                linked = os.stat(
                    "auto-crontab.lock", dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                if (linked.st_dev, linked.st_ino) != (info.st_dev, info.st_ino):
                    raise OSError("REQ10C project crontab lock pathname changed")
                current = os.stat(state)
                if (current.st_dev, current.st_ino) != (
                    directory_info.st_dev, directory_info.st_ino
                ):
                    raise OSError("REQ10C project crontab lock directory changed")
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)


def _cleanup_req10c_auto_watch(project_filter=None, operator=None, refusal=None):
    """Remove only our current-user watch, even when no setup links remain.

    operator: see _req10c_crontab_lock; with it the watch is the operator's (crontab -u <operator>).
    refusal: the operator rule refused this run; then no crontab is touched and no lock is made.  A watch to
    clean raises OSError (the run stops); without one there is nothing to do (review ruling D3).
    """
    if _DRY_RUN:
        return
    tool = os.path.join(HTTP_BASE, "infiniband", "bringup", "xdr-initial-setup")
    credentials = os.path.join(tool, "xdr-initial-setup-logs", "auto.env")
    marker = os.path.join(tool, "xdr-initial-setup-logs", "auto-watch.state")
    terminal = os.path.join(tool, "xdr-initial-setup-logs", "auto-terminal.json")
    if project_filter and not _inside(os.path.realpath(credentials), project_filter):
        return
    state = os.path.dirname(credentials)
    # The log link is a fixed link unsetup keeps (Q7): dangling, no project is active and no state is reachable.
    if not os.path.exists(state):
        return
    # D3: the same test _cleanup_req10c_auto_watch_locked uses to decide whether the crontab is touched.
    if refusal is not None and any(os.path.lexists(path) for path in (credentials, marker, terminal)):
        raise OSError(f"身份核对未通过，没有动 crontab 和 REQ10C 状态：{refusal}")
    if refusal is not None:
        return
    with _req10c_crontab_lock(state, operator):
        _cleanup_req10c_auto_watch_locked(tool, credentials, marker, terminal, operator)


def _read_req10c_crontab(operator=None):
    try:
        listing = subprocess.run(
            ["crontab", "-l"] if operator is None else ["crontab", "-u", operator.name, "-l"],
            capture_output=True, text=True,
            timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OSError(f"REQ10C crontab read failed: {exc}") from exc
    if listing.returncode == 0:
        return listing.stdout
    if listing.returncode == 1 and "no crontab" in listing.stderr.casefold():
        return ""
    raise OSError(f"REQ10C crontab read failed (exit {listing.returncode})")


def _read_stable_req10c_crontab(operator=None):
    """Return two identical snapshots or fail before replacing crontab."""
    first = _read_req10c_crontab(operator)
    second = _read_req10c_crontab(operator)
    if first != second:
        raise OSError(
            "REQ10C crontab changed during the protected read window; "
            "refusing to replace it"
        )
    return second


def _cleanup_req10c_auto_watch_locked(tool, credentials, marker, terminal, operator=None):
    if not any(os.path.lexists(path) for path in (credentials, marker, terminal)):
        return
    owner = os.geteuid() if operator is None else operator.uid
    existing = _read_stable_req10c_crontab(operator)

    def ours(line):
        if "# http-v3-req10c-auto" in line and os.path.join(tool, "initial-setup.py") in line:
            return True
        return (
            line.startswith("*/10 * * * * ")
            and "initial-setup.py --auto --apply --yes --credentials-file " in line
            and tool in line and credentials in line
        )

    retained = "".join(
        line for line in existing.splitlines(keepends=True) if not ours(line)
    )
    if retained != existing:
        try:
            result = subprocess.run(
                ["crontab", "-"] if operator is None else ["crontab", "-u", operator.name, "-"],
                input=retained, capture_output=True,
                text=True, timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise OSError(f"REQ10C crontab update failed: {exc}") from exc
        if result.returncode != 0:
            raise OSError(f"REQ10C crontab update failed (exit {result.returncode})")
    try:
        info = os.lstat(credentials)
    except FileNotFoundError:
        pass
    else:
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != owner
            or info.st_mode & 0o077
        ):
            raise OSError("REQ10C auto.env is not a safe owned regular secret; preserved")
        os.unlink(credentials)
    try:
        marker_info = os.lstat(marker)
    except FileNotFoundError:
        pass
    else:
        if (
            not stat.S_ISREG(marker_info.st_mode)
            or marker_info.st_nlink != 1
            or marker_info.st_uid != owner
            or marker_info.st_mode & 0o077
        ):
            raise OSError("REQ10C auto watch marker is not a safe owned file; preserved")
        os.unlink(marker)
    try:
        terminal_info = os.lstat(terminal)
    except FileNotFoundError:
        pass
    else:
        if (
            not stat.S_ISREG(terminal_info.st_mode)
            or terminal_info.st_nlink != 1
            or terminal_info.st_uid != owner
            or terminal_info.st_mode & 0o077
        ):
            raise OSError("REQ10C auto terminal state is not a safe owned file; preserved")
        os.unlink(terminal)


def _restore_deleted_links(deleted):
    failures = []
    for index, (path, target) in enumerate(reversed(deleted)):
        temporary = os.path.join(
            os.path.dirname(path),
            f".{os.path.basename(path)}.unsetup-rollback.{os.getpid()}.{index}",
        )
        try:
            if os.path.lexists(path):
                raise OSError(f"回滚目标已被占用：{path}")
            if os.path.lexists(temporary):
                os.remove(temporary)
            os.symlink(target, temporary)
            os.replace(temporary, path)
        except OSError as exc:
            failures.append(str(exc))
        finally:
            if os.path.lexists(temporary):
                os.remove(temporary)
    return failures


def _withdraw_project_configuration_authorities(project):
    """Withdraw the authorities of the project the pointer selected (R-016 §4.4, R16-20)."""
    if _DRY_RUN or project is None:
        return
    current = os.path.realpath(project)
    if not _inside(current, HERE) or current == os.path.realpath(HERE):
        raise config_sync_authority.AuthorityError("teardown project authority is outside the project scope")
    for relative, method in (("manual-config-sync", False), ("configuration-methods", True)):
        config_sync_authority.withdraw_all(os.path.join(current, "99-output-ztp", relative), method=method)


def _main_locked_impl(args):
    project_filter = _resolve_project(args.project) if args.project else None
    # R-016 §4.4: read the project from the pointer once, before the pointer goes.
    try:
        active_project = active_project_dir(HTTP_BASE)
    except ActiveProjectPointerError as exc:
        print(_c(RED, f"[ERROR] {exc}；unsetup 未做任何改动，请先重新运行 setup"))
        return 1
    # I-006 (v3.1.2 WP-8): the operator is the owner of the project read just above (no second pointer
    # read); no project means no identity check.  Root acting for a non-root owner cleans that owner's
    # watch.  Only that watch depends on the operator (review ruling D3): a refused identity stops the
    # run only when there is a watch to clean (_cleanup_req10c_auto_watch); the pointer and links do not.
    identity = operator_identity.resolve_operator(active_project)
    print(identity.banner)
    if project_filter:
        name = os.path.basename(project_filter)
        if active_project is None:
            print(_c(YELLOW, f"[INFO] 没有激活的项目（{ACTIVE_PROJECT_POINTER} 不存在），{name} 未激活；无需操作"))
            return 0
        if os.fspath(active_project) != project_filter:
            print(_c(RED, f"[ERROR] 当前激活的项目是 {active_project.name}，不是 {name}；unsetup 未做任何改动"))
            return 1
    try:
        _cleanup_req10c_auto_watch(
            project_filter, identity.operator if identity.action == "represent" else None, identity.refusal)
    except OSError as exc:
        print(_c(RED, f"[ERROR] REQ10C auto watch cleanup failed: {exc}"))
        return 1
    if identity.refusal:
        print(_c(YELLOW, "[WARN] 身份核对未通过，没有核实操作员；REQ10C 的 crontab 和状态都没有动"
                         f"（有要清理的 auto 状态时实际运行以 1 退出），其余照常：{identity.refusal}"))
    log_root = os.path.join(HTTP_BASE, "infra", "logs")
    # An interrupted setup still owns this link and its original directory
    # backup.  Removing the link would strand receipt-bound recovery even if
    # the lexical target currently looks like a valid project owner.
    receipt = os.path.join(HTTP_BASE, "infra", ".logs-migration.json")
    if os.path.lexists(receipt):
        print(_c(RED, f"[ERROR] 日志迁移凭据未结清，拒绝 unsetup：{receipt}"))
        return 1
    # A manifest entry or a symlink leaf alone cannot authorize deletion.
    # Reject the entire unsetup before touching any link when the log root is
    # foreign, chained, broken, or cyclic; preserve the manifest for recovery.
    if os.path.islink(log_root) and managed_infra_log_project(log_root, HERE) is None:
        print(_c(RED, f"[ERROR] infra/logs 不是规范 DAY0 项目日志链接：{log_root}"))
        return 1

    links = sorted({os.path.abspath(path)
                    for path in (*_known_ztp_project_links(), *_known_workspace_links())
                    if _inside(path, HTTP_BASE) and os.path.islink(path)})
    # Owner rule 2026-11-03: a same-named real file is reported, never replaced or deleted; the run goes on.
    occupied = [path for path in (os.path.join(HTTP_BASE, name) for name in RETIRED_SETUP_LINKS)
                if os.path.lexists(path) and not os.path.islink(path)]
    for path in occupied:
        print(_c(RED, f"[ERROR] 旧链接位置上是真实文件或目录，保留不删：{os.path.relpath(path, HTTP_BASE)}"))
    status = 1 if occupied else 0
    if active_project is None:
        print(_c(YELLOW, f"[INFO] 没有激活的项目（{ACTIVE_PROJECT_POINTER} 不存在）"))
    else:
        print(_c(CYAN, f"[INFO] 当前激活的项目：{active_project}"))
        # Unlinked first: from then on no project is active, whatever happens to the cleanup below.
        links.insert(0, os.path.join(HTTP_BASE, ACTIVE_PROJECT_POINTER))
    # Q5: the manifest is the derived record of the active project; it goes with the pointer.
    manifest = active_project is not None and os.path.isfile(MANIFEST_FILE)
    if not links and not manifest:
        print(_c(YELLOW, "\n未找到指针或 setup 的派生链接，无需操作。"))
        return status

    print(f"\n工作目录：{HTTP_BASE}")
    print(f"共找到 {len(links)} 个要删除的链接：\n")
    for path in links:
        print(f"  {os.path.relpath(path, HTTP_BASE)}  →  {os.readlink(path)}")
    if manifest:
        print(f"  {os.path.relpath(MANIFEST_FILE, HTTP_BASE)}（setup 清单）")
    print("树里的固定链接保留：删除指针后它们悬空，表示没有激活的项目；再 setup 一次就恢复。")

    if not _AUTO_YES and not _DRY_RUN:
        answer = input(f"\n删除以上 {len(links)} 个链接？[y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("已取消。")
            return

    deleted = []
    print()
    try:
        try:
            _withdraw_project_configuration_authorities(active_project)
        except (OSError, ValueError) as exc:
            print(_c(RED, f"[ERROR] 配置权威撤销失败，保留指针、链接和清单：{exc}"))
            return 1
        for path in links:
            rel_path = os.path.relpath(path, HTTP_BASE)
            target = os.readlink(path)
            if _DRY_RUN:
                print(_c(CYAN, f"  [DRY] 删除 {rel_path}  →  {target}"))
                continue
            os.remove(path)
            deleted.append((path, target))
            print(_c(GREEN, f"  [DEL] {rel_path}"))

        if _DRY_RUN:
            print(_c(CYAN, f"\n[DRY] 共 {len(links)} 个链接（未实际删除）"))
            return status

        if manifest:
            os.remove(MANIFEST_FILE)
            print(_c(CYAN, f"[INFO] 已删除清单文件：{MANIFEST_FILE}"))
        print(f"\n完成：已删除 {len(deleted)} 个链接")
        return status
    except OSError as exc:
        failures = _restore_deleted_links(deleted)
        detail = f"；回滚不完整：{' | '.join(failures)}" if failures else "；已回滚"
        print(_c(RED, f"[ERROR] unsetup 删除失败：{exc}{detail}"))
        return 1


def _main_locked(args):
    """Keep log-link removal serialized with setup and log writers."""
    lock = nullcontext() if _DRY_RUN else infra_log_root_lock(HTTP_BASE)
    with lock:
        return _main_locked_impl(args)


def main(argv=None):
    global _AUTO_YES, _DRY_RUN
    args = _parse_args(argv)
    _AUTO_YES = args.yes
    _DRY_RUN = args.dry_run
    try:
        with deployment_lock(HTTP_BASE, dry_run=_DRY_RUN):
            if not _DRY_RUN:
                stop_native_ztp_monitors(HTTP_BASE)
            return _main_locked(args)
    except (DeploymentLockError, RuntimeContractError, OSError) as exc:
        print(_c(RED, f"[ERROR] 部署/Monitor 写前保护失败：{exc}"))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
