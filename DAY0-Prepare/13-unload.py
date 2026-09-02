#!/usr/bin/env python3
"""撤销 11-load.py 创建的管理服务器 ZTP 运行态。

默认保留项目输入、99-output-* 生成结果、ZTP 状态历史、共享镜像以及 infra
安装的软件，方便完成一次验证后快速重新 load。只有显式指定 --clear-ztp-status
或 --teardown-infra 时才删除对应数据或回滚 infra。load 发布的自定义 ZTP URL
prefix 只有在 ownership marker 和目标软链接都通过严格校验后才会成对清理。
"""

from __future__ import annotations

import argparse
import filecmp
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time


HERE = Path(__file__).resolve().parent
HTTP_ROOT = HERE.parent
ZTP_DIR = HTTP_ROOT / "ztp"
TOOLS_DIR = HTTP_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from project_contract import (  # noqa: E402
    ZTP_PREFIX_PUBLICATION_MARKER,
    ztp_prefix_publication_relative,
)
from deployment_lock import (  # noqa: E402
    DeploymentLockError,
    deployment_lock,
    inherited_lock_subprocess_kwargs,
)

MANIFEST_FILE = ZTP_DIR / ".setup_manifest"
UNSETUP_SCRIPT = HERE / "02-unsetup.py"
INFRA_TEARDOWN = HTTP_ROOT / "infra/infra-teardown.sh"
MONITOR_SCRIPT_NAME = "12-ztp-monitor.py"
MONITOR_WORKERS = (
    (HTTP_ROOT / "monitor/status/switch-collection.pid", "switch-collection-worker.py"),
    (HTTP_ROOT / "monitor/status/manual-ztp.pid", "manual-ztp-worker.py"),
)
DHCP_FILES = (
    "dhcpd.conf",
    "dhcpd_eth.hosts",
    "dhcpd_ib.hosts",
    "dhcpd_nvl.hosts",
)
SERVICES = ("isc-dhcp-server", "apache2")


class UnloadError(RuntimeError):
    pass


def info(message: str) -> None:
    print(f"[INFO]  {message}")


def ok(message: str) -> None:
    print(f"[OK]    {message}")


def warn(message: str) -> None:
    print(f"[WARN]  {message}")


def run(
    command: list[str], *, dry_run: bool = False,
    inherited_lock_descriptor: int | None = None,
) -> None:
    display = " ".join(shlex_quote(item) for item in command)
    if dry_run:
        print(f"[DRY]   {display}")
        return
    info(f"Running: {display}")
    subprocess.run(
        command, check=True,
        **inherited_lock_subprocess_kwargs(inherited_lock_descriptor),
    )


def shlex_quote(value: str) -> str:
    import shlex
    return shlex.quote(value)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def active_project() -> Path | None:
    if not MANIFEST_FILE.is_file():
        return None
    for raw_line in MANIFEST_FILE.read_text(encoding="utf-8").splitlines():
        if raw_line.startswith("# setup manifest ") and "proj:" in raw_line:
            candidate = Path(raw_line.split("proj:", 1)[1].strip()).resolve()
            if candidate.is_dir() and _inside(candidate, HERE):
                return candidate
    return None


def resolve_project(argument: str | None) -> Path | None:
    if not argument:
        return active_project()
    candidate = Path(argument)
    if not candidate.is_absolute():
        # Accept the same project forms as setup/load: either a bare project
        # name or DAY0-Prepare/<project> from the workspace root.
        parts = candidate.parts
        if parts and parts[0] == HERE.name:
            candidate = Path(*parts[1:])
        candidate = HERE / candidate
    candidate = candidate.resolve()
    if not candidate.is_dir():
        raise UnloadError(f"项目目录不存在：{candidate}")
    if not _inside(candidate, HERE):
        raise UnloadError(f"项目必须位于 {HERE} 内：{candidate}")
    return candidate


def process_cmdline(pid: int) -> str | None:
    try:
        return (Path("/proc") / str(pid) / "cmdline").read_bytes().replace(
            b"\0", b" "
        ).decode("utf-8", errors="replace")
    except OSError:
        return None


def monitor_pid_files(project: Path | None) -> list[Path]:
    paths = [ZTP_DIR / "status/ztp-monitor.pid"]
    if project:
        paths.append(project / "99-output-ztp/ztp-monitor.pid")
    result: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        identity = path.resolve(strict=False)
        if identity not in seen:
            seen.add(identity)
            result.append(path)
    return result


def stop_monitor(project: Path | None, *, dry_run: bool) -> None:
    for pid_file in monitor_pid_files(project):
        if not pid_file.is_file():
            continue
        try:
            pid = int(pid_file.read_text(encoding="utf-8").strip())
            os.kill(pid, 0)
        except (ProcessLookupError, ValueError):
            if dry_run:
                print(f"[DRY]   删除失效 PID 文件：{pid_file}")
            else:
                pid_file.unlink(missing_ok=True)
                info(f"已删除失效 PID 文件：{pid_file}")
            continue
        except PermissionError as exc:
            raise UnloadError(f"无权检查 ZTP monitor PID={pid}：{exc}") from exc

        cmdline = process_cmdline(pid)
        expected = [MONITOR_SCRIPT_NAME]
        if project:
            expected.append(project.name)
        if cmdline is None:
            raise UnloadError(f"无法读取 PID={pid} 的命令行，拒绝终止未知进程")
        if not all(item in cmdline for item in expected):
            raise UnloadError(
                f"PID 文件指向非目标监控进程，拒绝终止 PID={pid}：{cmdline}"
            )
        if dry_run:
            print(f"[DRY]   SIGTERM ZTP monitor PID={pid}")
            continue

        info(f"停止 ZTP 后台监控：PID={pid}")
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except OSError:
                break
            time.sleep(0.1)
        else:
            raise UnloadError(f"ZTP monitor PID={pid} 在 5 秒内未退出；未强制杀死")
        pid_file.unlink(missing_ok=True)
        ok(f"ZTP monitor 已停止：PID={pid}")


def stop_monitor_workers(*, dry_run: bool) -> None:
    """Stop only worker processes named by their own validated PID files."""
    for pid_file, script_name in MONITOR_WORKERS:
        if not pid_file.is_file():
            continue
        try:
            pid = int(pid_file.read_text(encoding="utf-8").strip())
            os.kill(pid, 0)
        except (ProcessLookupError, ValueError):
            if not dry_run:
                pid_file.unlink(missing_ok=True)
            continue
        cmdline = process_cmdline(pid)
        if cmdline is None or script_name not in cmdline:
            raise UnloadError(
                f"{pid_file} 指向非 {script_name} 进程，拒绝终止 PID={pid}"
            )
        if dry_run:
            print(f"[DRY]   SIGTERM {script_name} PID={pid}")
            continue
        info(f"停止 {script_name}：PID={pid}")
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except OSError:
                break
            time.sleep(0.1)
        else:
            raise UnloadError(f"{script_name} PID={pid} 在 5 秒内未退出")
        pid_file.unlink(missing_ok=True)


def stop_services(*, dry_run: bool) -> None:
    systemctl = shutil.which("systemctl")
    if not systemctl:
        warn("未找到 systemctl，无法检查 Apache/DHCP")
        return
    for service in SERVICES:
        result = subprocess.run(
            [systemctl, "is-active", "--quiet", service],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            run([systemctl, "stop", service], dry_run=dry_run)
            ok(f"服务已停止：{service}" if not dry_run else f"将停止服务：{service}")
        else:
            info(f"服务未运行：{service}")


def remove_ztp_prefix_publication(*, dry_run: bool) -> None:
    """Remove only the custom prefix link provably owned by this load.

    The parent directories are deliberately retained. A missing leaf, an
    invalid marker, or any path/target conflict leaves both marker and leaf
    untouched so an operator can inspect the ownership mismatch.
    """
    marker = HTTP_ROOT / ZTP_PREFIX_PUBLICATION_MARKER
    try:
        relative = ztp_prefix_publication_relative(HTTP_ROOT)
    except (OSError, ValueError) as exc:
        raise UnloadError(
            f"自定义 ZTP prefix ownership 无效，拒绝清理且未触碰路径：{exc}"
        ) from exc
    if relative is None:
        info("没有 load 管理的自定义 ZTP URL prefix")
        return

    leaf = HTTP_ROOT.joinpath(*relative.parts)
    if not os.path.lexists(leaf):
        raise UnloadError(
            f"自定义 ZTP prefix marker 存在但软链接缺失，拒绝删除 marker：{leaf}"
        )
    # The shared validator already proved the target. Capture identities and
    # revalidate immediately before mutation so a concurrently replaced path
    # is treated as a conflict rather than adopted.
    try:
        marker_stat = marker.stat()
        marker_bytes = marker.read_bytes()
        leaf_stat = leaf.lstat()
        link_target = os.readlink(leaf)
        confirmed = ztp_prefix_publication_relative(HTTP_ROOT)
        current_marker_stat = marker.stat()
        current_leaf_stat = leaf.lstat()
    except (OSError, ValueError) as exc:
        raise UnloadError(
            f"自定义 ZTP prefix 在清理前发生变化，拒绝触碰：{exc}"
        ) from exc
    if confirmed != relative:
        raise UnloadError("自定义 ZTP prefix marker 在清理前发生变化，拒绝触碰")
    if (
        (marker_stat.st_dev, marker_stat.st_ino)
        != (current_marker_stat.st_dev, current_marker_stat.st_ino)
        or marker.read_bytes() != marker_bytes
        or (leaf_stat.st_dev, leaf_stat.st_ino)
        != (current_leaf_stat.st_dev, current_leaf_stat.st_ino)
        or not leaf.is_symlink()
        or leaf.resolve(strict=True) != ZTP_DIR.resolve(strict=True)
    ):
        raise UnloadError("自定义 ZTP prefix ownership 在清理前发生变化，拒绝触碰")

    if dry_run:
        print(f"[DRY]   删除自定义 ZTP prefix 软链接：{leaf}")
        print(f"[DRY]   删除自定义 ZTP prefix marker：{marker}")
        return

    leaf.unlink()
    try:
        if (
            marker.is_symlink()
            or not marker.is_file()
            or marker.read_bytes() != marker_bytes
        ):
            raise UnloadError(
                "自定义 ZTP prefix marker 在删除软链接后发生变化；已恢复软链接"
            )
        marker.unlink()
    except (OSError, UnloadError) as exc:
        try:
            if not os.path.lexists(leaf):
                leaf.symlink_to(link_target)
        except OSError as restore_exc:
            raise UnloadError(
                f"删除 marker 失败且无法恢复 prefix 软链接：{exc}；{restore_exc}"
            ) from restore_exc
        if isinstance(exc, UnloadError):
            raise
        raise UnloadError(f"删除自定义 ZTP prefix marker 失败；已恢复软链接：{exc}") from exc
    ok(f"已删除自定义 ZTP prefix 运行态：{leaf} 和 {marker.name}")


def dhcp_source(name: str) -> Path:
    return ZTP_DIR / "config/isc-dhcp-server" / name


def dhcp_file_is_load_managed(destination: Path, source: Path) -> bool:
    if destination.is_symlink():
        try:
            return _inside(destination.resolve(strict=False), HTTP_ROOT)
        except OSError:
            return False
    if not destination.is_file() or not source.is_file():
        return False
    try:
        return filecmp.cmp(destination, source.resolve(), shallow=False)
    except OSError:
        return False


def unmanaged_dhcp_runtime_files() -> list[Path]:
    unmanaged: list[Path] = []
    for name in DHCP_FILES:
        destination = Path("/etc/dhcp") / name
        if not destination.exists() and not destination.is_symlink():
            continue
        if not dhcp_file_is_load_managed(destination, dhcp_source(name)):
            unmanaged.append(destination)
    return unmanaged


def remove_dhcp_runtime_files(*, force: bool, dry_run: bool) -> list[Path]:
    retained: list[Path] = []
    for name in DHCP_FILES:
        destination = Path("/etc/dhcp") / name
        if not destination.exists() and not destination.is_symlink():
            info(f"DHCP 运行文件不存在：{destination}")
            continue
        source = dhcp_source(name)
        managed = dhcp_file_is_load_managed(destination, source)
        if not managed and not force:
            warn(
                f"内容与当前 load 输出不一致，保留 {destination}；"
                "确认无需保留后使用 --force-dhcp"
            )
            retained.append(destination)
            continue
        if dry_run:
            print(f"[DRY]   删除 DHCP 运行文件：{destination}")
        else:
            destination.unlink()
            ok(f"已删除 DHCP 运行文件：{destination}")
    return retained


def remove_project_links(
    project: Path | None, *, dry_run: bool,
    deployment_lock_descriptor: int | None = None,
) -> None:
    command = [sys.executable, str(UNSETUP_SCRIPT), "-y"]
    if dry_run:
        command.append("--dry-run")
    if project:
        command.append(str(project))
    # Even in outer dry-run mode, execute 02-unsetup.py with its own --dry-run
    # so it can enumerate the exact managed links without deleting them.
    run(
        command, dry_run=False,
        inherited_lock_descriptor=deployment_lock_descriptor,
    )


def clear_ztp_status(project: Path | None, *, dry_run: bool) -> None:
    if not project:
        raise UnloadError("--clear-ztp-status 需要活动项目或显式项目参数")
    status_dir = project / "99-output-ztp"
    if not status_dir.is_dir() or not _inside(status_dir, project):
        raise UnloadError(f"ZTP 状态目录无效：{status_dir}")
    for item in list(status_dir.iterdir()):
        if dry_run:
            print(f"[DRY]   删除 ZTP 状态：{item}")
        elif item.is_dir() and not item.is_symlink():
            shutil.rmtree(item)
        else:
            item.unlink()
    if not dry_run:
        ok(f"已清空 ZTP 状态历史：{status_dir}")


def teardown_infra(*, dry_run: bool) -> None:
    if dry_run:
        print(f"[DRY]   bash {INFRA_TEARDOWN} --non-interactive --yes")
        return
    if not INFRA_TEARDOWN.is_file():
        raise UnloadError(f"infra teardown 脚本不存在：{INFRA_TEARDOWN}")
    run(["bash", str(INFRA_TEARDOWN), "--non-interactive", "--yes"])


def confirm(args: argparse.Namespace, project: Path | None) -> bool:
    if args.yes or args.dry_run:
        return True
    print("\n即将撤销管理服务器 ZTP 运行态：")
    print("  - 停止 ZTP monitor、isc-dhcp-server 和 apache2")
    print("  - 删除 load 管理的 /etc/dhcp 配置副本")
    print("  - 安全删除 load 管理的自定义 ZTP URL prefix 软链接和 marker")
    print("  - 删除 01-a-setup.py 管理的当前项目软链接")
    print(f"  - 项目：{project or '未检测到活动项目'}")
    print("  - 默认保留项目输入、生成结果、状态历史、镜像和已安装软件")
    if args.clear_ztp_status:
        print("  - 额外清空当前项目 99-output-ztp（不可恢复）")
    if args.teardown_infra:
        print("  - 额外执行 infra 完整回滚并卸载其记录的软件")
    try:
        return input("\n输入 yes 继续 [no]：").strip().casefold() == "yes"
    except EOFError:
        return False


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", nargs="?", help="活动项目名/目录；默认读取 setup manifest")
    parser.add_argument("-y", "--yes", action="store_true", help="不询问，直接执行")
    parser.add_argument("--dry-run", action="store_true", help="只显示将执行的动作")
    parser.add_argument(
        "--force-dhcp", action="store_true",
        help="即使 /etc/dhcp 文件与当前输出不同也删除（可能删除非 load 配置）",
    )
    parser.add_argument(
        "--clear-ztp-status", action="store_true",
        help="清空当前项目 99-output-ztp 监控历史（不可恢复）",
    )
    parser.add_argument(
        "--teardown-infra", action="store_true",
        help="执行 infra-teardown.sh，回滚配置并卸载 infra 记录的软件",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        project = resolve_project(args.project)
        if not args.dry_run and os.geteuid() != 0:
            raise UnloadError("实际 unload 必须使用 root/sudo 执行；--dry-run 不要求 root")
        if not confirm(args, project):
            info("已取消，没有修改任何内容")
            return 0

        with deployment_lock(HTTP_ROOT, dry_run=args.dry_run) as lock_descriptor:
            if not args.dry_run:
                # Confirmation intentionally happens before locking; re-resolve
                # after acquisition so no stale active-project snapshot is used.
                project = resolve_project(args.project)
                unmanaged = unmanaged_dhcp_runtime_files()
                if unmanaged and not args.force_dhcp:
                    raise UnloadError(
                        "DHCP 运行文件与当前 load 输出不一致；"
                        "未停止服务也未删除任何文件："
                        + ", ".join(str(path) for path in unmanaged)
                    )

            stop_monitor(project, dry_run=args.dry_run)
            stop_monitor_workers(dry_run=args.dry_run)
            stop_services(dry_run=args.dry_run)
            remove_ztp_prefix_publication(dry_run=args.dry_run)
            retained = remove_dhcp_runtime_files(
                force=args.force_dhcp, dry_run=args.dry_run
            )
            remove_project_links(
                project, dry_run=args.dry_run,
                deployment_lock_descriptor=lock_descriptor,
            )
            if args.clear_ztp_status:
                clear_ztp_status(project, dry_run=args.dry_run)
            if args.teardown_infra:
                teardown_infra(dry_run=args.dry_run)
                # infra teardown may restart a retained pre-existing Apache.
                stop_services(dry_run=args.dry_run)

        if retained:
            raise UnloadError(
                "以下 DHCP 文件因内容不匹配而保留："
                + ", ".join(str(path) for path in retained)
            )
        if args.dry_run:
            ok("dry-run 完成；未修改管理服务器")
        else:
            ok("管理服务器 ZTP 运行态已卸载；项目数据和验证证据已保留")
        return 0
    except (
        DeploymentLockError, UnloadError, OSError, subprocess.SubprocessError,
    ) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
