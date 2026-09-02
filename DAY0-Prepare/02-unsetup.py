#!/usr/bin/env python3
"""删除 01-a-setup.py 在 http/ 工作目录中创建的项目相关软链接。

仓库内部的固定软链接（例如 monitor/cron.sh、monitor/sw-info.sh）不在管理范围内。

用法：
  python3 02-unsetup.py              # 使用清单并补充扫描已知管理位置
  python3 02-unsetup.py -y           # 自动删除，不询问
  python3 02-unsetup.py --dry-run    # 只显示，不实际删除
  python3 02-unsetup.py <项目>       # 只删除指向指定项目的链接
"""

import argparse
import os
import glob
import sys

HERE          = os.path.dirname(os.path.realpath(__file__))
HTTP_BASE     = os.path.normpath(os.path.join(HERE, ".."))
ZTP           = os.path.join(HTTP_BASE, "ztp")
MANIFEST_FILE = os.path.join(ZTP, ".setup_manifest")
TOOLS_DIR     = os.path.join(HTTP_BASE, "tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)
from deployment_lock import DeploymentLockError, deployment_lock

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


def _read_manifest():
    """返回 (清单路径列表, 清单记录的项目目录)；清单不存在时返回 (None, None)。"""
    if not os.path.isfile(MANIFEST_FILE):
        return None, None
    paths = []
    project = None
    with open(MANIFEST_FILE, encoding="utf-8") as stream:
        for raw_line in stream:
            line = raw_line.strip()
            if line.startswith("# setup manifest ") and "proj:" in line:
                project = line.split("proj:", 1)[1].strip()
            elif line and not line.startswith("#"):
                if _inside(line, HTTP_BASE):
                    paths.append(os.path.abspath(line))
                else:
                    print(_c(YELLOW, f"[WARN] 忽略工作目录之外的清单项：{line}"))
    return paths, project


def _known_ztp_project_links():
    """扫描 setup 明确管理的 ZTP 位置，不触碰其他用户自建软链接。"""
    relative_paths = [
        "backup/02-devices_config.csv",
        "backup/yaml-backup",
        "config/cumulus/latest_yaml",
        "config/cumulus/template/01-global.yaml",
        "config/cumulus/template/02-devices_config.csv",
        "config/cumulus/template/91-devices.yaml",
        "config/cumulus/template/99-output",
        "config/cumulus/template/P2P/output-p2p",
        "config/cumulus/template/P2P/p2p.xlsx",
        # 兼容清理由目录更名前的 setup 创建的旧链接。
        "config/cumulus/template/AIR/output-p2p",
        "config/nvos/latest_yaml",
        "config/nvos/template/01-global.yaml",
        "config/nvos/template/02-devices_config.csv",
        "config/nvos/template/99-output-ib_nvl",
        "config/nvos/template/P2P/output-p2p",
        "config/nvos/template/P2P/p2p.xlsx",
        # 兼容清理由旧版 setup 创建的两个目录链接。
        "config/nvos/template/99-output-ib",
        "config/nvos/template/99-output-nvl",
        "config/nvos/template/99-output-published",
        "config/isc-dhcp-server/01-global.yaml",
        "config/isc-dhcp-server/02-subnet_config.csv",
        "config/isc-dhcp-server/02-devices_config.csv",
        "config/isc-dhcp-server/p2p-air.json",
        "config/isc-dhcp-server/dhcp-release-manifest.json",
        "config/isc-dhcp-server/dhcpd.conf",
        "config/isc-dhcp-server/dhcpd_eth.hosts",
        "config/isc-dhcp-server/dhcpd_ib.hosts",
        "config/isc-dhcp-server/dhcpd_nvl.hosts",
    ]
    paths = [os.path.join(ZTP, rel) for rel in relative_paths]
    patterns = [
        os.path.join(ZTP, "image", "cumulus", "*.bin"),
        os.path.join(ZTP, "image", "nvos", "*.bin"),
        os.path.join(ZTP, "config", "publickey", "*.pub"),
        os.path.join(ZTP, "config", "cumulus", "template", "P2P", "*.xlsx"),
        os.path.join(ZTP, "config", "nvos", "template", "P2P", "*.xlsx"),
        os.path.join(ZTP, "config", "cumulus", "template", "AIR", "*.xlsx"),
    ]
    for pattern in patterns:
        paths.extend(glob.glob(pattern))
    return [path for path in sorted(set(paths)) if os.path.islink(path)]


def _known_workspace_links():
    """返回 ZTP 之外由 setup 管理的固定链接位置。"""
    paths = [
        os.path.join(HTTP_BASE, "infra", "01-global.yaml"),
        os.path.join(HTTP_BASE, "infra", "02-devices_config.csv"),
        os.path.join(HTTP_BASE, "monitor", "01-global.yaml"),
        os.path.join(HTTP_BASE, "ethernet", "eth.csv"),
        os.path.join(HTTP_BASE, "ethernet", "p2p.xlsx"),
        os.path.join(HTTP_BASE, "infiniband", "ib.csv"),
        os.path.join(HTTP_BASE, "infiniband", "p2p.xlsx"),
        os.path.join(HTTP_BASE, "nvlink", "nvsw.csv"),
        os.path.join(HTTP_BASE, "nvlink", "p2p.xlsx"),
        os.path.join(HTTP_BASE, "infiniband", "bringup", "ndr", "ndr-upgrade-logs"),
        os.path.join(HTTP_BASE, "infiniband", "bringup", "xdr-initial-setup", "xdr-initial-setup-logs"),
        os.path.join(HTTP_BASE, "infiniband", "bringup", "xdr-upgrade", "xdr-upgrade-logs"),
        os.path.join(ZTP, "config", "cumulus", "template", "P2P", "eth-info"),
        os.path.join(ZTP, "config", "nvos", "template", "P2P", "ib-info"),
        os.path.join(HTTP_BASE, "monitor", "99-output-p2p"),
        os.path.join(HTTP_BASE, "tools", "lldp-analyze-tool", "99-output-p2p"),
        os.path.join(HTTP_BASE, "tools", "lldp-analyze-tool", "99-output-monitor"),
        os.path.join(HTTP_BASE, "tools", "ibdiagnet-analyze-tool", "99-output-p2p"),
        os.path.join(HTTP_BASE, "monitor", "02-devices_config.csv"),
        os.path.join(ZTP, "status"),
        os.path.join(HTTP_BASE, "monitor", "ztp-status"),
    ]
    specs = [
        ("ethernet", "eth-info", "spx-link"),
        ("infiniband", "ib-info", "ib-link"),
        ("nvlink", "nvsw-info", "nvsw-link"),
    ]
    for net_type, first_output, second_output in specs:
        monitor_dir = os.path.join(HTTP_BASE, net_type, "monitor")
        paths.extend([
            os.path.join(monitor_dir, first_output),
            os.path.join(monitor_dir, second_output),
            os.path.join(monitor_dir, "cronjob.log"),
            os.path.join(HTTP_BASE, "monitor", net_type),
        ])
    paths.extend(glob.glob(os.path.join(ZTP, "optimize", "*-sample", "*")))
    return [path for path in paths if os.path.islink(path)]


def _project_monitor_csv_links(project_dir):
    """兼容清理旧版 setup 在项目 99-output-monitor 内创建的三个 CSV 链接。"""
    specs = (("ethernet", "eth.csv"), ("infiniband", "ib.csv"),
             ("nvlink", "nvsw.csv"))
    paths = [os.path.join(project_dir, "99-output-monitor", net_type, csv_name)
             for net_type, csv_name in specs]
    return [path for path in paths if os.path.islink(path)]


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


def _belongs_to_project(link_path, project_dir):
    """链接位于项目内，或其最终目标位于项目内。"""
    return (_inside(link_path, project_dir)
            or _inside(os.path.realpath(link_path), project_dir))


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("project", nargs="?", help="只删除指向该 DAY0 项目的链接")
    parser.add_argument("-y", "--yes", action="store_true", help="自动确认删除")
    parser.add_argument("--dry-run", action="store_true", help="仅显示将删除的链接")
    return parser.parse_args(argv)


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


def _main_locked(args):
    project_filter = _resolve_project(args.project) if args.project else None
    manifest, manifest_project = _read_manifest()
    manifest_matches_filter = bool(
        project_filter and manifest_project and os.path.isdir(manifest_project)
        and os.path.realpath(manifest_project) == project_filter
    )

    candidates = []
    if manifest is not None:
        print(_c(CYAN, f"[INFO] 使用 setup 清单：{MANIFEST_FILE}"))
        candidates.extend(manifest)
    else:
        print(_c(YELLOW, f"[WARN] 未找到 setup 清单：{MANIFEST_FILE}"))

    # 清单可能来自旧版 setup，因此始终补充扫描当前所有已知管理位置。
    candidates.extend(_known_ztp_project_links())
    candidates.extend(_known_workspace_links())

    active_project = project_filter
    if active_project is None and manifest_project and os.path.isdir(manifest_project):
        active_project = os.path.realpath(manifest_project)
    if active_project:
        candidates.extend(_project_monitor_csv_links(active_project))

    links = sorted({os.path.abspath(path) for path in candidates
                    if _inside(path, HTTP_BASE) and os.path.islink(path)})
    if project_filter:
        links = [path for path in links if _belongs_to_project(path, project_filter)]
        print(f"项目过滤：{project_filter}")

    if not links:
        print(_c(YELLOW, "\n未找到任何由 setup 管理的软链接，无需操作。"))
        if (not _DRY_RUN and manifest is not None and manifest_matches_filter
                and os.path.isfile(MANIFEST_FILE)):
            os.remove(MANIFEST_FILE)
            print(_c(CYAN, f"[INFO] 已删除当前项目的失效清单：{MANIFEST_FILE}"))
        return

    print(f"\n工作目录：{HTTP_BASE}")
    print(f"共找到 {len(links)} 个项目相关软链接：\n")
    for path in links:
        print(f"  {os.path.relpath(path, HTTP_BASE)}  →  {os.readlink(path)}")

    if not _AUTO_YES and not _DRY_RUN:
        answer = input(f"\n删除以上 {len(links)} 个链接？[y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("已取消。")
            return

    deleted = []
    print()
    try:
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
            return 0

        if (manifest is not None and (not project_filter or manifest_matches_filter)
                and os.path.isfile(MANIFEST_FILE)):
            os.remove(MANIFEST_FILE)
            print(_c(CYAN, f"[INFO] 已删除清单文件：{MANIFEST_FILE}"))
        print(f"\n完成：已删除 {len(deleted)} 个链接")
        return 0
    except OSError as exc:
        failures = _restore_deleted_links(deleted)
        detail = f"；回滚不完整：{' | '.join(failures)}" if failures else "；已回滚"
        print(_c(RED, f"[ERROR] unsetup 删除失败：{exc}{detail}"))
        return 1


def main(argv=None):
    global _AUTO_YES, _DRY_RUN
    args = _parse_args(argv)
    _AUTO_YES = args.yes
    _DRY_RUN = args.dry_run
    try:
        with deployment_lock(HTTP_BASE, dry_run=_DRY_RUN):
            return _main_locked(args)
    except (DeploymentLockError, OSError) as exc:
        print(_c(RED, f"[ERROR] 部署锁不可用：{exc}"))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
