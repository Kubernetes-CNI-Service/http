#!/usr/bin/env python3
"""
在 http/ 工作目录下创建指向部署项目文件夹的软链接，让 ZTP、设备工具和监控脚本
能正常读写当前项目的输入/输出文件。

用法：
  python3 01-a-setup.py <项目文件夹名>        # 在 DAY0-Prepare/ 下查找
  python3 01-a-setup.py <项目文件夹绝对路径>
  python3 01-a-setup.py -y <项目文件夹名>    # 自动覆盖已有链接，不询问
  python3 01-a-setup.py --dry-run <...>      # 只显示操作，不实际创建
  python3 01-a-setup.py --strict --dry-run <...>  # 部署前严格校验占位文件
  python3 01-a-setup.py --p2p-file=<文件名> <...> # 多个 P2P XLSX 时明确选择 P2P 源

映射规则（输入文件用文件链接，输出目录用目录链接，输出文件先在项目中创建空文件再链接）。
"""

import argparse
import base64
import csv
import glob
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import tempfile

OPTIMIZE_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "ztp", "optimize"))
if OPTIMIZE_DIR not in sys.path:
    sys.path.insert(0, OPTIMIZE_DIR)
from sample_links import (
    LINK_NAMES,
    prepare_comparison_output,
    sample_directory,
    sample_link_targets,
)

# ── 路径 ──────────────────────────────────────────────────────────────────────

HERE         = os.path.dirname(os.path.realpath(__file__))   # DAY0-Prepare/
HTTP_BASE    = os.path.normpath(os.path.join(HERE, ".."))    # http/
TOOLS_DIR    = os.path.join(HTTP_BASE, "tools")
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)
from project_contract import GLOBAL_SCHEMA_VERSION, validate_ztp_url_prefix
from deployment_lock import DeploymentLockError, deployment_lock
ZTP          = os.path.normpath(os.path.join(HERE, "..", "ztp"))
TEMPLATE_DIR = os.path.join(HERE, "template")                # DAY0-Prepare/template/
IMAGE_DIR    = os.path.join(HTTP_BASE, "image")               # 项目无关的共享系统镜像

# ── 固定映射：(ztp相对路径, 项目相对路径, 类型) ──────────────────────────────
# 类型：
#   "file"       - 源文件必须存在，建文件符号链接
#   "file_opt"   - 源文件不存在时只警告，不报错
#   "dir"        - 源目录必须存在（会自动创建），建目录符号链接
#   "output"     - 输出文件：在项目中创建空文件（若不存在），然后建文件符号链接

MAPPINGS = [
    # Cumulus（eth）
    ("config/cumulus/template/01-global.yaml",       "01-global.yaml",                "file"),
    ("config/cumulus/template/02-devices_config.csv","02-devices_config.csv",          "file_csv"),
    ("config/cumulus/template/91-devices.yaml",      "99-output-eth/91-devices.yaml", "output"),
    ("config/cumulus/template/99-output",            "99-output-eth",                  "dir"),

    # NVOS（ib + nvl）
    ("config/nvos/template/01-global.yaml",          "01-global.yaml",                "file"),
    ("config/nvos/template/02-devices_config.csv",   "02-devices_config.csv",          "file_csv"),
    ("config/nvos/template/99-output-ib_nvl",        "99-output-ib_nvl",               "dir"),

    # DHCP 配置输入
    ("config/isc-dhcp-server/01-global.yaml",              "01-global.yaml",               "file"),
    ("config/isc-dhcp-server/02-subnet_config.csv",        "02-dhcp-subnet_config.csv",     "file"),
    ("config/isc-dhcp-server/02-devices_config.csv",       "02-devices_config.csv",         "file_csv"),

    # DHCP 输出文件（写到项目的 99-output-dhcp/ 下）
    ("config/isc-dhcp-server/dhcpd_eth.hosts",       "99-output-dhcp/dhcpd_eth.hosts","output"),
    ("config/isc-dhcp-server/dhcpd_ib.hosts",        "99-output-dhcp/dhcpd_ib.hosts", "output"),
    ("config/isc-dhcp-server/dhcpd_nvl.hosts",       "99-output-dhcp/dhcpd_nvl.hosts","output"),
    ("config/isc-dhcp-server/dhcpd.conf",            "99-output-dhcp/dhcpd.conf",     "output"),
    ("config/isc-dhcp-server/dhcp-release-manifest.json",
                                                     "99-output-dhcp/dhcp-release-manifest.json",
                                                                                       "output"),

    # yaml-collect.py 输入 CSV
    ("backup/02-devices_config.csv",                 "02-devices_config.csv",          "file_csv"),

    # yaml-collect.py 输出目录（写到项目的 99-output-backup/ 下）
    ("backup/yaml-backup",                           "99-output-backup",               "dir"),
]

# ZTP 目录之外、同样随当前部署项目切换的输入链接。
WORKSPACE_INPUT_MAPPINGS = [
    ("infra/01-global.yaml",        "01-global.yaml",         "file"),
    ("infra/02-devices_config.csv", "02-devices_config.csv", "file_csv"),
    ("monitor/01-global.yaml",      "01-global.yaml",         "file"),
]

# 所有 P2P 消费工具只使用固定文件名 p2p.xlsx；setup 将同一个项目源文件
# 挂载到以下五个输入入口，并让两个转换流程共享同一个输出目录。
P2P_INPUT_LINKS = [
    os.path.join(ZTP, "config", "cumulus", "template", "P2P", "p2p.xlsx"),
    os.path.join(ZTP, "config", "nvos", "template", "P2P", "p2p.xlsx"),
    os.path.join(HTTP_BASE, "ethernet", "p2p.xlsx"),
    os.path.join(HTTP_BASE, "infiniband", "p2p.xlsx"),
    os.path.join(HTTP_BASE, "nvlink", "p2p.xlsx"),
]
P2P_OUTPUT_LINKS = [
    os.path.join(ZTP, "config", "cumulus", "template", "P2P", "output-p2p"),
    os.path.join(ZTP, "config", "nvos", "template", "P2P", "output-p2p"),
]
P2P_AIR_JSON_LINK = os.path.join(
    ZTP, "config", "isc-dhcp-server", "p2p-air.json"
)

# InfiniBand bringup 工具的项目归档目录。工具仍使用自己目录下的固定名称，
# setup 负责将其切换到当前项目的统一 IB/NVLink 输出树。
BRINGUP_OUTPUT_MAPPINGS = [
    (os.path.join(HTTP_BASE, "infiniband", "bringup", "ndr", "ndr-upgrade-logs"),
     os.path.join("99-output-ib_nvl", "bringup", "ndr-upgrade-logs")),
    (os.path.join(HTTP_BASE, "infiniband", "bringup", "xdr-initial-setup", "xdr-initial-setup-logs"),
     os.path.join("99-output-ib_nvl", "bringup", "xdr-initial-setup-logs")),
    (os.path.join(HTTP_BASE, "infiniband", "bringup", "xdr-upgrade", "xdr-upgrade-logs"),
     os.path.join("99-output-ib_nvl", "bringup", "xdr-upgrade-logs")),
]

# P2P 校验工具读取当前项目监控采集原始数据的固定入口。
ANALYZER_INPUT_MAPPINGS = [
    (os.path.join(ZTP, "config", "cumulus", "template", "P2P", "eth-info"),
     os.path.join("99-output-monitor", "ethernet", "eth-info")),
    (os.path.join(ZTP, "config", "nvos", "template", "P2P", "ib-info"),
     os.path.join("99-output-monitor", "infiniband", "ib-info")),
]
ANALYZER_OUTPUT_MAPPINGS = [
    (os.path.join(HTTP_BASE, "monitor", "99-output-p2p"), "99-output-p2p"),
    (os.path.join(HTTP_BASE, "tools", "lldp-analyze-tool", "99-output-p2p"),
     "99-output-p2p"),
    (os.path.join(HTTP_BASE, "tools", "lldp-analyze-tool", "99-output-monitor"),
     "99-output-monitor"),
    (os.path.join(HTTP_BASE, "tools", "ibdiagnet-analyze-tool", "99-output-p2p"),
     "99-output-p2p"),
]

# ── 辅助 ──────────────────────────────────────────────────────────────────────

_AUTO_YES = False
_DRY_RUN  = False
_FORCE    = False  # --force：忽略校验错误强行继续（独立于 -y）
_STRICT   = False  # --strict：把空公钥/xlsx/共享镜像占位文件视为错误
_CSV_DIR  = None   # --csv-dir 指定的 devices_config.csv 所在目录
_P2P_FILE = None   # --p2p-file 指定的项目根目录 XLSX
_P2P_SOURCE = None # 本次 setup 选定的唯一 P2P 源
_LINK_ERRORS = 0   # 本次 setup 中所有固定/动态链接错误数
_LINK_TRANSACTION = None  # 当前 setup 的整批链接回滚快照

MANIFEST_FILE = os.path.join(ZTP, ".setup_manifest")  # setup 创建的链接清单

RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW= "\033[33m"
RED   = "\033[31m"
CYAN  = "\033[36m"

def _c(color, s): return f"{color}{s}{RESET}"

def _confirm_overwrite(link_path):
    if _AUTO_YES:
        return True
    cur = os.readlink(link_path)
    print(_c(YELLOW, f"  [已存在] {link_path}"))
    print(f"         当前指向：{cur}")
    if not sys.stdin.isatty():
        print(_c(YELLOW, "  [SKIP] 非交互终端不覆盖；请使用 -y 明确确认"))
        return False
    try:
        ans = input("  覆盖？[y/N] ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


def _init_from_template(src_path, proj_rel):
    """从 TEMPLATE_DIR 复制对应文件到 src_path（只当 src_path 不存在时调用）。
    返回 True 表示成功（含 dry-run），False 表示模板中也没有。"""
    tmpl_path = os.path.join(TEMPLATE_DIR, proj_rel)
    if not os.path.isfile(tmpl_path):
        return False
    if _DRY_RUN:
        print(_c(CYAN, f"  [DRY] 从模板创建 {proj_rel}"))
        return True
    parent = os.path.dirname(src_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    shutil.copy2(tmpl_path, src_path)
    print(_c(GREEN, f"  [INIT] {os.path.relpath(src_path, HERE)} ← 从模板复制"))
    return True


def _populate_dir_from_template(dest_dir, proj_rel):
    """若模板目录中对应子目录含有文件，将缺失文件复制到 dest_dir（不递归，不覆盖）。"""
    tmpl_sub = os.path.join(TEMPLATE_DIR, proj_rel)
    if not os.path.isdir(tmpl_sub):
        return
    for fname in sorted(os.listdir(tmpl_sub)):
        tmpl_file = os.path.join(tmpl_sub, fname)
        dest_file = os.path.join(dest_dir, fname)
        if not os.path.isfile(tmpl_file):
            continue
        if os.path.exists(dest_file):
            continue
        if _DRY_RUN:
            print(_c(CYAN, f"  [DRY] 从模板创建 {proj_rel}/{fname}"))
        else:
            shutil.copy2(tmpl_file, dest_file)
            print(_c(GREEN, f"  [INIT] {os.path.relpath(dest_file, HERE)} ← 从模板复制"))


def _make_link(link_path, target_path):
    """创建符号链接 link_path → target_path（相对路径）。"""
    global _LINK_ERRORS
    link_dir   = os.path.dirname(link_path)
    rel_target = os.path.relpath(target_path, link_dir)

    if _DRY_RUN:
        print(_c(CYAN, f"  [DRY] {os.path.relpath(link_path, HTTP_BASE)}  →  {rel_target}"))
        return "dry"

    if os.path.islink(link_path):
        if os.path.realpath(link_path) == os.path.realpath(target_path):
            print(f"  [SKIP] {os.path.relpath(link_path, HTTP_BASE)} 已正确指向目标")
            return "skipped"
        if not _confirm_overwrite(link_path):
            print(f"  [SKIP] 保留原链接")
            return "skipped"
        os.remove(link_path)
    elif os.path.exists(link_path):
        print(_c(RED, f"  [ERROR] {link_path} 是实际文件/目录，跳过（请手动处理）"))
        _LINK_ERRORS += 1
        return "error"

    os.makedirs(link_dir, exist_ok=True)
    os.symlink(rel_target, link_path)
    print(_c(GREEN, f"  [LINK] {os.path.relpath(link_path, HTTP_BASE)}  →  {rel_target}"))
    return "linked"


def _make_exact_link(link_path, target_path, canonical=False):
    """Create an exact relative link even when an old link resolves identically.

    This is used for stable publication pointers: their link text is part of the
    layout contract, not merely an equivalent destination.
    """
    global _LINK_ERRORS
    link_dir = os.path.dirname(link_path)
    if canonical:
        # macOS exposes /var through /private/var.  Compute both sides in the
        # same canonical namespace so a direct link made from a temp/workspace
        # path cannot accidentally resolve to /private/private/....
        rel_target = os.path.relpath(
            os.path.realpath(target_path), os.path.realpath(link_dir)
        )
    else:
        rel_target = os.path.relpath(target_path, link_dir)
    if _DRY_RUN:
        print(_c(CYAN, f"  [DRY] {os.path.relpath(link_path, HTTP_BASE)}  →  {rel_target}"))
        return "dry"
    if os.path.islink(link_path):
        if os.readlink(link_path) == rel_target:
            print(f"  [SKIP] {os.path.relpath(link_path, HTTP_BASE)} 已正确指向目标")
            return "skipped"
        if not _confirm_overwrite(link_path):
            print("  [SKIP] 保留原链接")
            return "skipped"
    elif os.path.lexists(link_path):
        print(_c(RED, f"  [ERROR] {link_path} 是实际文件/目录，跳过（请手动处理）"))
        _LINK_ERRORS += 1
        return "error"
    os.makedirs(link_dir, exist_ok=True)
    temp_link = os.path.join(link_dir, f".{os.path.basename(link_path)}.tmp.{os.getpid()}")
    try:
        if os.path.lexists(temp_link):
            os.remove(temp_link)
        os.symlink(rel_target, temp_link)
        os.replace(temp_link, link_path)
    finally:
        if os.path.lexists(temp_link):
            os.remove(temp_link)
    print(_c(GREEN, f"  [LINK] {os.path.relpath(link_path, HTTP_BASE)}  →  {rel_target}"))
    return "linked"


def _process_mapping(proj_dir, link_rel, proj_rel, kind, src_base=None, link_root=ZTP):
    link_path = os.path.join(link_root, link_rel)
    # file_csv：优先使用 --csv-dir 目录；未指定时回退到 proj_dir
    if kind == "file_csv":
        base = src_base or proj_dir
        src_path = os.path.join(base, proj_rel)
        kind = "file"
    else:
        src_path = os.path.join(proj_dir, proj_rel)

    if kind == "dir":
        if not os.path.exists(src_path):
            if _DRY_RUN:
                print(_c(CYAN, f"  [DRY] mkdir {src_path}"))
            else:
                os.makedirs(src_path, exist_ok=True)
                print(f"  [MKDIR] {os.path.relpath(src_path, HERE)}")
        _populate_dir_from_template(src_path, proj_rel)
        return _make_link(link_path, src_path)

    if kind == "output":
        out_dir = os.path.dirname(src_path)
        if not os.path.exists(out_dir):
            if _DRY_RUN:
                print(_c(CYAN, f"  [DRY] mkdir {out_dir}"))
            else:
                os.makedirs(out_dir, exist_ok=True)
                print(f"  [MKDIR] {os.path.relpath(out_dir, HERE)}")
        if not os.path.exists(src_path):
            if _DRY_RUN:
                print(_c(CYAN, f"  [DRY] touch {src_path}"))
            else:
                open(src_path, "a").close()
                print(f"  [TOUCH] {os.path.relpath(src_path, HERE)}")
        return _make_link(link_path, src_path)

    # file / file_opt
    if not os.path.exists(src_path):
        if _init_from_template(src_path, proj_rel):
            pass  # 模板初始化成功，继续创建链接
        elif kind == "file_opt":
            print(_c(YELLOW, f"  [MISS] {proj_rel} 不存在，跳过（可选文件）"))
            return "missing"
        else:
            print(_c(RED,    f"  [ERROR] {proj_rel} 不存在，跳过"))
            return "missing"
    return _make_link(link_path, src_path)


def _copy_glob_from_template(proj_dir, pattern):
    """把模板目录中匹配 pattern 的文件复制到 proj_dir（只补缺失文件）。
    返回实际复制（或 dry-run 模拟）的文件数。"""
    count = 0
    for tmpl_file in sorted(glob.glob(os.path.join(TEMPLATE_DIR, pattern))):
        fname = os.path.basename(tmpl_file)
        dest  = os.path.join(proj_dir, fname)
        if os.path.exists(dest):
            continue
        count += 1
        if _DRY_RUN:
            print(_c(CYAN, f"  [DRY] 从模板创建 {fname}"))
        else:
            shutil.copy2(tmpl_file, dest)
            print(_c(GREEN, f"  [INIT] {os.path.relpath(dest, HERE)} ← 从模板复制"))
    return count


def _initialize_project_from_template(proj_dir):
    """递归同步完整项目模板：创建所有目录并复制缺失文件，绝不覆盖项目已有内容。"""
    global _LINK_ERRORS

    def _create_symlink(src, dest, rel_path):
        if os.path.lexists(dest):
            return
        target = os.readlink(src)
        if _DRY_RUN:
            print(_c(CYAN, f"  [DRY] 从模板创建链接 {rel_path} → {target}"))
        else:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            os.symlink(target, dest)
            print(_c(GREEN, f"  [INIT] {rel_path} → {target}（模板链接）"))

    for src_root, dirnames, filenames in os.walk(TEMPLATE_DIR, topdown=True, followlinks=False):
        rel_root = os.path.relpath(src_root, TEMPLATE_DIR)
        rel_root = "" if rel_root == "." else rel_root
        dest_root = os.path.join(proj_dir, rel_root)

        if os.path.lexists(dest_root) and not os.path.isdir(dest_root):
            label = rel_root or "."
            print(_c(RED, f"  [ERROR] 模板目录 {label}/ 与项目中的非目录路径冲突"))
            _LINK_ERRORS += 1
            dirnames[:] = []
            continue
        if not os.path.isdir(dest_root):
            if _DRY_RUN:
                print(_c(CYAN, f"  [DRY] 从模板创建目录 {rel_root or '.'}/"))
            else:
                os.makedirs(dest_root, exist_ok=True)
                if rel_root:
                    print(_c(GREEN, f"  [INIT] {rel_root}/ ← 模板目录"))

        # os.walk 不跟随目录软链接；在目标项目中复制链接本身。
        for dirname in list(dirnames):
            src = os.path.join(src_root, dirname)
            if not os.path.islink(src):
                continue
            dirnames.remove(dirname)
            rel_path = os.path.join(rel_root, dirname) if rel_root else dirname
            _create_symlink(src, os.path.join(dest_root, dirname), rel_path)

        for filename in filenames:
            src = os.path.join(src_root, filename)
            dest = os.path.join(dest_root, filename)
            rel_path = os.path.join(rel_root, filename) if rel_root else filename
            if os.path.lexists(dest):
                if os.path.isdir(dest) and not os.path.islink(dest):
                    print(_c(RED, f"  [ERROR] 模板文件 {rel_path} 与项目目录冲突"))
                    _LINK_ERRORS += 1
                continue
            if os.path.islink(src):
                _create_symlink(src, dest, rel_path)
            elif _DRY_RUN:
                print(_c(CYAN, f"  [DRY] 从模板复制 {rel_path}"))
            else:
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                shutil.copy2(src, dest)
                print(_c(GREEN, f"  [INIT] {rel_path} ← 模板文件"))


def _image_platform(filename):
    """按明确的文件名关键字识别共享镜像平台，未知镜像不做猜测。"""
    lower = filename.lower()
    if "cumulus" in lower:
        return "cumulus"
    if "nvos" in lower:
        return "nvos"
    return None


def _shared_image_pairs():
    """返回 (ZTP 链接路径, http/image 源文件)；忽略无法识别的平台文件。"""
    pairs = []
    for src in sorted(glob.glob(os.path.join(IMAGE_DIR, "*.bin"))):
        platform = _image_platform(os.path.basename(src))
        if platform:
            pairs.append((os.path.join(ZTP, "image", platform, os.path.basename(src)), src))
    return pairs


def _process_bin_files():
    """把 http/image/ 中的共享镜像链接到 ztp/image/cumulus|nvos/。"""
    bins = sorted(glob.glob(os.path.join(IMAGE_DIR, "*.bin")))
    if not bins:
        print(_c(YELLOW, f"  [MISS] {IMAGE_DIR}/ 下未找到 .bin 镜像文件"))
        return
    for src in bins:
        fname = os.path.basename(src)
        platform = _image_platform(fname)
        if not platform:
            print(_c(YELLOW, f"  [WARN] 无法识别镜像平台，跳过：image/{fname}"))
            continue
        img_dir = os.path.join(ZTP, "image", platform)
        if not _DRY_RUN:
            os.makedirs(img_dir, exist_ok=True)
        _make_link(os.path.join(img_dir, fname), src)


def _select_p2p_source(proj_dir):
    """从文件名含 p2p 的 XLSX 中选出唯一 P2P 源。

    自动发现忽略大小写和 Excel 临时文件；空模板 p2p.xlsx 不会遮蔽
    唯一的非空真实 P2P 文件。--p2p-file 是显式人工选择，不受命名约束。
    """
    if _P2P_FILE:
        source = _P2P_FILE if os.path.isabs(_P2P_FILE) else os.path.join(proj_dir, _P2P_FILE)
        source = os.path.abspath(source)
        allowed_root = os.path.abspath(proj_dir)
        allowed_versions = os.path.join(allowed_root, "p2p")
        if os.path.dirname(source) not in {allowed_root, allowed_versions}:
            print(_c(RED, "[ERROR] --p2p-file 必须位于项目根目录或 p2p/ 目录"))
            return None
        if not source.lower().endswith(".xlsx") or not os.path.isfile(source):
            print(_c(RED, f"[ERROR] --p2p-file 不存在或不是 XLSX：{source}"))
            return None
        return source

    version_dir = os.path.join(proj_dir, "p2p")
    version_candidates = sorted(
        entry.path for entry in os.scandir(version_dir)
        if entry.is_file()
        and not entry.name.startswith(("~$", "._"))
        and entry.name.lower().endswith(".xlsx")
        and "p2p" in entry.name.lower()
        and os.path.getsize(entry.path) > 0
    ) if os.path.isdir(version_dir) else []
    if version_candidates:
        return max(
            version_candidates,
            key=lambda path: (os.stat(path).st_mtime_ns, os.path.basename(path).casefold()),
        )

    candidates = sorted(
        entry.path for entry in os.scandir(proj_dir)
        if entry.is_file()
        # Ignore Excel lock files and macOS AppleDouble metadata files.
        and not entry.name.startswith(("~$", "._"))
        and entry.name.lower().endswith(".xlsx")
        and "p2p" in entry.name.lower()
    )
    canonical = os.path.join(proj_dir, "p2p.xlsx")
    if os.path.isfile(canonical) and os.path.getsize(canonical) > 0:
        return canonical

    nonempty = [path for path in candidates if os.path.getsize(path) > 0]
    if len(nonempty) == 1:
        return nonempty[0]
    if len(nonempty) > 1:
        names = ", ".join(os.path.basename(path) for path in nonempty)
        print(_c(RED, f"[ERROR] 项目根目录有多个文件名含 P2P 的非空 XLSX：{names}"))
        print("        请用 --p2p-file=<文件名> 明确选择一个 P2P 源")
        return None
    if os.path.isfile(canonical):
        return canonical
    print(_c(RED, "[ERROR] 项目根目录未找到文件名含 P2P 的 XLSX 文件"))
    return None


def _ensure_project_p2p_link(proj_dir, source):
    """Make project/p2p.xlsx the stable pointer to the selected real workbook."""
    canonical = os.path.join(proj_dir, "p2p.xlsx")
    if os.path.abspath(source) == os.path.abspath(canonical):
        return source
    relative = os.path.relpath(source, proj_dir)
    if os.path.islink(canonical):
        if os.path.realpath(canonical) == os.path.realpath(source):
            print(f"  [SKIP] p2p.xlsx 已指向 {relative}")
            return canonical
        if _DRY_RUN:
            print(_c(CYAN, f"  [DRY] 更新 p2p.xlsx → {relative}"))
            return canonical
        os.remove(canonical)
    elif os.path.exists(canonical):
        if os.path.isfile(canonical) and os.path.getsize(canonical) == 0:
            if _DRY_RUN:
                print(_c(CYAN, f"  [DRY] 用链接替换空 p2p.xlsx → {relative}"))
                return canonical
            os.remove(canonical)
        else:
            print(_c(RED, "[ERROR] 非空实际文件 p2p.xlsx 与选定 P2P 源冲突；请先归档或明确处理"))
            return None
    if not _DRY_RUN:
        temporary = canonical + f".tmp.{os.getpid()}"
        try:
            if os.path.lexists(temporary):
                os.remove(temporary)
            os.symlink(relative, temporary)
            os.replace(temporary, canonical)
        finally:
            if os.path.lexists(temporary):
                os.remove(temporary)
    print(_c(CYAN if _DRY_RUN else GREEN, f"  [{'DRY' if _DRY_RUN else 'LINK'}] p2p.xlsx → {relative}"))
    return canonical


def _remove_legacy_p2p_links():
    """清理由旧版 setup 创建的非 p2p.xlsx 输入链接，不触碰实际文件。"""
    for directory in (
        os.path.join(ZTP, "config", "cumulus", "template", "P2P"),
        os.path.join(ZTP, "config", "nvos", "template", "P2P"),
    ):
        for path in glob.glob(os.path.join(directory, "*.xlsx")):
            if os.path.basename(path) == "p2p.xlsx" or not os.path.islink(path):
                continue
            if _DRY_RUN:
                print(_c(CYAN, f"  [DRY] 删除旧 P2P 链接 {os.path.relpath(path, HTTP_BASE)}"))
            else:
                os.remove(path)
                print(_c(GREEN, f"  [DEL] 旧 P2P 链接 {os.path.relpath(path, HTTP_BASE)}"))


def _process_xlsx_files(proj_dir, source):
    """挂载 P2P 输入、输出目录和 DHCP 使用的 AIR JSON 固定入口。"""
    _remove_legacy_p2p_links()
    print(f"  P2P 源：{os.path.relpath(source, proj_dir)}")
    for link_path in P2P_INPUT_LINKS:
        _make_link(link_path, source)
    for link_path in P2P_OUTPUT_LINKS:
        rel = os.path.relpath(link_path, ZTP)
        _process_mapping(proj_dir, rel, "99-output-p2p", "dir")
    source_stem = os.path.splitext(os.path.basename(os.path.realpath(source)))[0]
    air_json = os.path.join(
        proj_dir, "99-output-p2p", f"{source_stem}-air.json"
    )
    _make_link(P2P_AIR_JSON_LINK, air_json)


def _bringup_link_pairs(proj_dir):
    """返回 InfiniBand bringup 的 (固定工作链接, 当前项目归档目录)。"""
    return [(link_path, os.path.join(proj_dir, project_rel))
            for link_path, project_rel in BRINGUP_OUTPUT_MAPPINGS]


def _process_bringup_links(proj_dir):
    """创建 bringup 项目归档目录，并将三个工具输出入口切换到当前项目。"""
    for link_path, target_path in _bringup_link_pairs(proj_dir):
        if _DRY_RUN:
            if not os.path.isdir(target_path):
                print(_c(CYAN, f"  [DRY] mkdir {os.path.relpath(target_path, HERE)}/"))
        else:
            os.makedirs(target_path, exist_ok=True)
        _make_link(link_path, target_path)


def _analyzer_input_pairs(proj_dir):
    """返回拓扑分析器的 (固定输入链接, 当前项目监控采集目录)。"""
    return [(link_path, os.path.join(proj_dir, project_rel))
            for link_path, project_rel in ANALYZER_INPUT_MAPPINGS]


def _analyzer_output_pairs(proj_dir):
    """返回监控页面的 (固定拓扑报告入口, 当前项目 P2P 输出目录)。"""
    pairs = []
    tools_root = os.path.join(HTTP_BASE, "tools") + os.sep
    for link_path, project_rel in ANALYZER_OUTPUT_MAPPINGS:
        # Offline analyzers are deliberately excluded from deployment
        # packages. Do not recreate an otherwise absent tool directory on a
        # management server; manage the link whenever the local tool exists.
        if link_path.startswith(tools_root) and not os.path.isdir(os.path.dirname(link_path)):
            continue
        pairs.append((link_path, os.path.join(proj_dir, project_rel)))
    return pairs


def _process_analyzer_links(proj_dir):
    """切换拓扑分析采集输入和监控页面的项目报告入口。"""
    pairs = _analyzer_input_pairs(proj_dir) + _analyzer_output_pairs(proj_dir)
    for link_path, target_path in pairs:
        if _DRY_RUN:
            if not os.path.isdir(target_path):
                print(_c(CYAN, f"  [DRY] mkdir {os.path.relpath(target_path, HERE)}/"))
        else:
            os.makedirs(target_path, exist_ok=True)
        _make_link(link_path, target_path)


MANAGEMENT_PUBKEY_MARKER = ".management-pubkeys"


def _unused_empty_pubkeys(proj_dir):
    """Return legacy empty placeholders that are not part of the active key pair.

    ``11-load.py`` records injected management keys in ``.management-pubkeys``.
    Once the project has at least two non-empty keys and one of them is marked
    as the management key, any other unmarked empty ``*.pub`` is an obsolete
    placeholder and must not fail strict setup or be published at runtime.
    """
    marker = os.path.join(proj_dir, MANAGEMENT_PUBKEY_MARKER)
    try:
        with open(marker, encoding="utf-8") as stream:
            managed_names = {
                line.strip() for line in stream
                if line.strip().endswith(".pub")
            }
    except FileNotFoundError:
        managed_names = set()
    pubs = sorted(glob.glob(os.path.join(proj_dir, "*.pub")))
    nonempty = [path for path in pubs if os.path.getsize(path) > 0]
    has_static_key = any(
        os.path.basename(path) not in managed_names for path in nonempty
    )
    if not managed_names or not has_static_key:
        return set()
    return {
        path for path in pubs
        if os.path.getsize(path) == 0
        and os.path.basename(path) not in managed_names
    }


def _process_pubkeys(proj_dir):
    """将项目中的 .pub 公钥链接到 config/publickey/。"""
    pubs = glob.glob(os.path.join(proj_dir, "*.pub"))
    if not pubs:
        inited = _copy_glob_from_template(proj_dir, "*.pub")
        pubs = glob.glob(os.path.join(proj_dir, "*.pub"))
        if not pubs and not inited:
            print(_c(YELLOW, "  [MISS] 未找到 .pub 公钥文件"))
            return
        if not pubs:  # dry-run: 模板文件已记录，跳过后续链接
            return
    # Empty files are preparation placeholders, never deployable keys. Linux
    # load injects the management key before setup, so required keys are
    # non-empty by the time they are published.
    pubs = [path for path in pubs if os.path.getsize(path) > 0]
    key_dir = os.path.join(ZTP, "config", "publickey")
    if not _DRY_RUN:
        os.makedirs(key_dir, exist_ok=True)
    expected_names = {os.path.basename(src) for src in pubs}
    # Public-key links project only active keys. Remove setup-managed links for
    # obsolete placeholders, but never touch a real operator-managed file.
    for old in sorted(glob.glob(os.path.join(key_dir, "*.pub"))):
        if not os.path.islink(old) or os.path.basename(old) in expected_names:
            continue
        if _DRY_RUN:
            print(_c(CYAN, f"  [DRY] 删除旧公钥链接 {os.path.relpath(old, HTTP_BASE)}"))
        else:
            os.remove(old)
            print(_c(GREEN, f"  [DEL] 旧公钥链接 {os.path.relpath(old, HTTP_BASE)}"))
    for src in sorted(pubs):
        fname = os.path.basename(src)
        _make_link(os.path.join(key_dir, fname), src)


def _latest_cumulus_publish_dir(parent):
    """返回最新的、由 hostname2mac 完成发布的 Cumulus 合并目录。

    生成过程中的 ``<timestamp>``、``*_with_desc`` 和 ``*_air`` 目录都不
    包含完整的生产/AIR MAC 映射，不能作为 ``latest_yaml`` 的目标。只认
    带有发布完成标记的 ``*_combine``，避免再次运行 setup/load 时把已
    发布链接回退到一个较新的中间目录。
    """
    candidates = []
    pattern = re.compile(r"^(\d{8}_\d{6})_combine$")
    for path in glob.glob(os.path.join(parent, "*")):
        if not os.path.isdir(path) or os.path.islink(path):
            continue
        match = pattern.match(os.path.basename(path))
        if match and os.path.isfile(os.path.join(path, ".published-complete")):
            candidates.append((match.group(1), path))
    return max(candidates, default=(None, None))[1]


def _latest_nvos_publish_dir(parent):
    """返回最新的、已完成的 NVOS 发布目录，忽略尚未合并完成的批次。"""
    candidates = []
    pattern = re.compile(r"^(\d{8}_\d{6})-(ib|nvl|combine)$")
    for path in glob.glob(os.path.join(parent, "*")):
        if not os.path.isdir(path) or os.path.islink(path):
            continue
        match = pattern.match(os.path.basename(path))
        if match and os.path.isfile(os.path.join(path, ".published-complete")):
            # 同一时间戳优先恢复 combine，避免退回只包含单一类型的目录。
            priority = 1 if match.group(2) == "combine" else 0
            candidates.append((match.group(1), priority, path))
    return max(candidates, default=(None, -1, None))[2]


# 网络类型目录下的 CSV 链接：(symlink路径, 项目中源文件名)
_NET_CSV_LINKS = [
    (os.path.join(HTTP_BASE, "ethernet",   "eth.csv"),  "02-devices_config.csv"),
    (os.path.join(HTTP_BASE, "infiniband", "ib.csv"),   "02-devices_config.csv"),
    (os.path.join(HTTP_BASE, "nvlink",     "nvsw.csv"), "02-devices_config.csv"),
]

# 监控类型：(类型目录, CSV 文件名, 采集输出目录...)
_MONITOR_SPECS = [
    ("ethernet",   "eth.csv",  "eth-info",  "spx-link"),
    ("infiniband", "ib.csv",   "ib-info",   "ib-link"),
    ("nvlink",     "nvsw.csv", "nvsw-info", "nvsw-link"),
]


def _process_net_csv_links(proj_dir):
    """在 ethernet/、infiniband/、nvlink/ 目录下创建 CSV 符号链接，指向项目 CSV 文件。"""
    csv_base = _CSV_DIR or proj_dir
    src_csv  = os.path.join(csv_base, "02-devices_config.csv")
    if not os.path.exists(src_csv) and not _DRY_RUN:
        print(_c(YELLOW, f"  [WARN] {src_csv} 不存在，跳过网络 CSV 链接"))
        return
    for link_path, _fname in _NET_CSV_LINKS:
        _make_link(link_path, src_csv)


def _monitor_link_paths(proj_dir):
    """返回监控相关的 (链接路径, 目标路径)，不包含仓库内部固定链接。"""
    csv_base = _CSV_DIR or proj_dir
    src_csv = os.path.join(csv_base, "02-devices_config.csv")
    monitor_root = os.path.join(proj_dir, "99-output-monitor")
    # HTML 汇总只需要一份统一设备清单，再按 type 过滤 eth/eth_spx/spx、ib、nvl。
    ztp_status = os.path.join(ZTP, "status")
    project_ztp_status = os.path.join(proj_dir, "99-output-ztp")
    pairs = [
        (os.path.join(HTTP_BASE, "monitor", "02-devices_config.csv"), src_csv),
        # 采集脚本固定写 ztp/status；项目切换时数据仍归档到项目目录。
        (ztp_status, project_ztp_status),
        # HTML 汇总通过 monitor/ztp-status 读取同一份数据。
        (os.path.join(HTTP_BASE, "monitor", "ztp-status"), ztp_status),
    ]
    for net_type, _csv_name, *output_names in _MONITOR_SPECS:
        project_net_dir = os.path.join(monitor_root, net_type)
        # 采集脚本从各类型 monitor/ 目录读写当前项目的输出。
        for output_name in output_names:
            pairs.append((os.path.join(HTTP_BASE, net_type, "monitor", output_name),
                          os.path.join(project_net_dir, output_name)))
        pairs.append((os.path.join(HTTP_BASE, net_type, "monitor", "cronjob.log"),
                      os.path.join(project_net_dir, "cronjob.log")))
        # 汇总页面通过 http/monitor/<type> 访问三个项目监控目录。
        pairs.append((os.path.join(HTTP_BASE, "monitor", net_type), project_net_dir))
    return pairs


def _legacy_project_monitor_csv_links(proj_dir):
    """返回旧版 setup 在项目监控子目录内创建的三个冗余 CSV 链接。"""
    monitor_root = os.path.join(proj_dir, "99-output-monitor")
    return [os.path.join(monitor_root, net_type, csv_name)
            for net_type, csv_name, *_outputs in _MONITOR_SPECS]


def _process_monitor_links(proj_dir):
    """创建当前项目的监控目录、日志和所有项目相关监控链接。"""
    monitor_root = os.path.join(proj_dir, "99-output-monitor")
    ztp_status = os.path.join(proj_dir, "99-output-ztp")
    if _DRY_RUN:
        if not os.path.isdir(ztp_status):
            print(_c(CYAN, f"  [DRY] mkdir {os.path.relpath(ztp_status, HERE)}/"))
    else:
        os.makedirs(ztp_status, exist_ok=True)
    for net_type, _csv_name, *output_names in _MONITOR_SPECS:
        project_net_dir = os.path.join(monitor_root, net_type)
        paths = [project_net_dir] + [os.path.join(project_net_dir, n) for n in output_names]
        for path in paths:
            if _DRY_RUN:
                if not os.path.isdir(path):
                    print(_c(CYAN, f"  [DRY] mkdir {os.path.relpath(path, HERE)}/"))
            else:
                os.makedirs(path, exist_ok=True)
        log_path = os.path.join(project_net_dir, "cronjob.log")
        if _DRY_RUN:
            if not os.path.exists(log_path):
                print(_c(CYAN, f"  [DRY] touch {os.path.relpath(log_path, HERE)}"))
        elif not os.path.exists(log_path):
            open(log_path, "a").close()

    for link_path, target_path in _monitor_link_paths(proj_dir):
        _make_link(link_path, target_path)


def _process_latest_yaml(_proj_dir):
    """
    恢复两级发布指针：
      项目输出/latest → 最新且带 .published-complete 的发布目录
      cumulus/latest_yaml → template/99-output/latest
      nvos/latest_yaml    → template/99-output-ib_nvl/latest

    有完整发布目录时 ``latest_yaml`` 保持固定入口；没有对应设备或发布结果时
    删除 setup 管理的旧入口，避免留下指向不存在 ``latest`` 的断链。
    """
    pairs = [
        (os.path.join(ZTP, "config", "cumulus"), "99-output", _latest_cumulus_publish_dir),
        (os.path.join(ZTP, "config", "nvos"), "99-output-ib_nvl", _latest_nvos_publish_dir),
    ]
    for ztp_dir, output_name, resolver in pairs:
        out_base = os.path.join(ztp_dir, "template", output_name)
        latest = resolver(out_base)
        output_latest = os.path.join(out_base, "latest")
        if latest:
            _make_exact_link(output_latest, latest)
            _make_exact_link(os.path.join(ztp_dir, "latest_yaml"), output_latest)
            continue

        label = os.path.relpath(out_base, ZTP)
        print(_c(YELLOW, f"  [WARN] {label}/ 暂无完整发布目录，不创建 latest_yaml"))
        for stale in (output_latest, os.path.join(ztp_dir, "latest_yaml")):
            if not os.path.islink(stale):
                continue
            if _DRY_RUN:
                print(_c(CYAN, f"  [DRY] 删除无效发布链接 {os.path.relpath(stale, HTTP_BASE)}"))
            else:
                os.remove(stale)
                print(_c(GREEN, f"  [DEL] 无效发布链接 {os.path.relpath(stale, HTTP_BASE)}"))


def _process_optimize_sample(proj_dir):
    """Create <project>-sample and its managed comparison/input links."""
    sample = sample_directory(os.path.join(ZTP, "optimize"), proj_dir)
    prepare_comparison_output(
        sample,
        proj_dir,
        dry_run=_DRY_RUN,
        report=lambda message: print(_c(CYAN, f"  {message}")),
    )
    if _DRY_RUN:
        if not sample.is_dir():
            print(_c(CYAN, f"  [DRY] mkdir {os.path.relpath(sample, HTTP_BASE)}/"))
    else:
        sample.mkdir(parents=True, exist_ok=True)
        managed_names = set(LINK_NAMES.values())
        for old in sample.iterdir():
            if old.is_symlink() and old.name not in managed_names:
                old.unlink()
                print(_c(GREEN, f"  [DEL] 旧 sample 链接 {old.name}"))
    for name, target in sample_link_targets(proj_dir).items():
        link = sample / name
        if target is None:
            print(_c(YELLOW, f"  [WARN] {name}: 当前项目没有可用目标"))
            if not _DRY_RUN and link.is_symlink():
                link.unlink()
                print(_c(GREEN, f"  [DEL] 失效 sample 链接 {name}"))
            continue
        _make_exact_link(str(link), str(target), canonical=True)


def _remove_legacy_nvos_output_links():
    """移除旧版 setup 创建的 NVOS 输出链接；不删除项目中的真实旧数据。"""
    template_dir = os.path.join(ZTP, "config", "nvos", "template")
    for name in ("99-output-ib", "99-output-nvl", "99-output-published"):
        path = os.path.join(template_dir, name)
        if os.path.islink(path):
            if _DRY_RUN:
                print(_c(CYAN, f"  [DRY] 删除旧链接 {os.path.relpath(path, HTTP_BASE)}"))
            else:
                os.remove(path)
                print(_c(GREEN, f"  [DEL] 旧链接 {os.path.relpath(path, HTTP_BASE)}"))
        elif os.path.exists(path):
            print(_c(YELLOW, f"  [WARN] 旧路径是实际文件或目录，未删除：{path}"))


# ── 合法性检查 ────────────────────────────────────────────────────────────────

def _vna(val):
    """判断 CSV 字段是否为空 / NA。"""
    return not val or val.strip().lower() in ("na", "n/a", "none", "-", "")


def _valid_ip(s, allow_prefix=False):
    """校验 IP 地址；allow_prefix=True 时允许 1.2.3.4/24 形式。"""
    s = s.strip()
    if allow_prefix and "/" in s:
        parts = s.split("/", 1)
        try:
            address = ipaddress.ip_address(parts[0])
            prefix = int(parts[1])
            return 0 <= prefix <= address.max_prefixlen
        except Exception:
            return False
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


def _valid_ip_prefix(s):
    """校验 IP/前缀长度，必须包含 /。"""
    s = s.strip()
    if "/" not in s:
        return False
    return _valid_ip(s, allow_prefix=True)


def _valid_mask(s):
    """校验 netmask：纯整数 1-32 或点分十进制。"""
    s = s.strip()
    if s.isdigit():
        return 1 <= int(s) <= 32
    try:
        network = ipaddress.IPv4Network(f"0.0.0.0/{s}")
        return str(network.netmask) == s
    except Exception:
        return False


def _valid_mac(s):
    """校验 MAC 地址（xx:xx:xx:xx:xx:xx 或 xx-xx-xx-xx-xx-xx）。"""
    s = s.strip().lower()
    return bool(re.fullmatch(r'[0-9a-f]{2}([:][0-9a-f]{2}){5}', s)
                or re.fullmatch(r'[0-9a-f]{2}([-][0-9a-f]{2}){5}', s))


def _valid_asn(s):
    """校验 BGP ASN (1–4294967295)。"""
    try:
        return 1 <= int(s.strip()) <= 4294967295
    except Exception:
        return False


def _valid_vlan(s):
    """校验 VLAN 单值、范围或 /、, 分隔组合 (1–4094)。"""
    return _valid_numeric_selector(s, 1, 4094)


def _valid_vni(s):
    """校验 VNI 单值、范围或 /、, 分隔组合。"""
    return _valid_numeric_selector(s, 1, 16777215)


def _valid_numeric_selector(s, minimum, maximum):
    try:
        for token in re.split(r'[/,]', s.strip()):
            match = re.fullmatch(r'(\d+)(?:-(\d+))?', token.strip())
            if not match:
                return False
            start = int(match.group(1))
            end = int(match.group(2) or start)
            if start > end or start < minimum or end > maximum:
                return False
        return True
    except Exception:
        return False


# 设备 CSV 每行的列位置
_COL_HOSTNAME   = 0
_COL_TYPE       = 1
_COL_TEMPLATE   = 2
_COL_ETH0_IP    = 3
_COL_ETH0_NM    = 4
_COL_ETH0_GW    = 5
_COL_ETH0_MAC   = 6
_COL_ETH1_IP    = 7
_COL_ETH1_NM    = 8
_COL_ETH1_GW    = 9
_COL_ETH1_MAC   = 10
_COL_LO_IP      = 11
_COL_VRF_DEF    = 12
_COL_VLAN_ID    = 13
_COL_SVI_IP     = 14
_COL_SVI_NM     = 15
_COL_VRR_IP     = 16
_COL_VRR_MAC    = 17
_COL_VLAN_PORTS = 18
_COL_BGP_ASN    = 19
_COL_BGP_PORTS  = 20
_COL_BOND_PORTS = 21
_COL_BOND_TYPE  = 22
_COL_BOND_MAC   = 23
_COL_PEERLINK   = 24
# Optional column 25 is ``vrl``; the first EVPN group is located from header so
# projects created before route-leaking support remain valid.
_EVPN_COLUMNS = (
    "evpn_vrf", "evpn_l3vni", "evpn_l3vlan", "dhcp_relay",
    "evpn_l2vni", "evpn_l2vlan", "svi_ip", "netmask", "vrr_ip",
    "vrr_mac", "vlan_ports",
)
_EVPN_MAX_GROUPS  = 4

_VALID_BOND_TYPES = {"localbond", "evpnbond", "evpn_multihoming", "mlagbond", "mlag"}


def _is_matching_production_air_pair(left_hostname, left_type,
                                     right_hostname, right_type,
                                     production_hostnames=None):
    """Allow one production/AIR pair to intentionally share eth0_ip."""
    left_type = str(left_type).strip().casefold()
    right_type = str(right_type).strip().casefold()
    left_air = left_type == "air"
    right_air = right_type == "air"
    if left_air == right_air:
        return False
    production_types = {"eth", "eth_spx", "spx"}
    if left_air and right_type not in production_types:
        return False
    if right_air and left_type not in production_types:
        return False

    air_hostname = left_hostname if left_air else right_hostname
    if not str(air_hostname).strip().casefold().startswith("air-"):
        return False

    air_base = str(air_hostname).strip()[4:].casefold()
    production_hostname = right_hostname if left_air else left_hostname
    production_key = str(production_hostname).strip().casefold()
    candidates = [
        str(name).strip().casefold() for name in (production_hostnames or [])
        if str(name).strip()
    ]
    if not candidates:
        return air_base == production_key

    exact = [name for name in candidates if name == air_base]
    matches = exact or [
        name for name in candidates
        if air_base.endswith(name) or name.endswith(air_base)
    ]
    # Site-prefix matching is allowed only when it resolves to one Production
    # identity, matching the DHCP generator's inheritance contract.
    return len(set(matches)) == 1 and matches[0] == production_key


def _validate_eth_csv(path):
    """逐行校验统一设备 CSV；server/air 仅校验各自消费流程所需字段。"""
    errors, warnings = [], []

    # ETH 设备类型集合
    _ETH_TYPES  = {"eth", "eth_spx", "spx"}
    _NVOS_TYPES = {"ib", "nvl"}
    _SERVER_TYPES = {"server"}
    _AIR_TYPES = {"air"}
    _SUPPORTED_TYPES = _ETH_TYPES | _NVOS_TYPES | _SERVER_TYPES | _AIR_TYPES

    def e(row_n, hn, msg):
        errors.append(f"  行{row_n} [{hn}] {msg}")

    def w(row_n, hn, msg):
        warnings.append(f"  行{row_n} [{hn}] {msg}")

    try:
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if header is None:
                errors.append("  文件为空（无 header 行）")
                return errors, warnings

            h_lower = [c.strip().lower() for c in header]

            # 动态计算 EVPN 组数：找 metadata 列开始位置
            _METADATA_COLS = {"source_yaml_b64", "source_yaml_sha256", "source_fields_sha256"}
            meta_start = next((i for i, h in enumerate(h_lower) if h in _METADATA_COLS),
                              len(h_lower))
            vrl_col = h_lower.index("vrl") if "vrl" in h_lower else None
            if vrl_col is not None and vrl_col != 25:
                errors.append("  CSV header 的可选 vrl 列必须紧跟 peerlink_ports")
                return errors, warnings
            try:
                evpn_start = h_lower.index("evpn_vrf", 25)
            except ValueError:
                errors.append("  CSV header 缺少 EVPN 字段组")
                return errors, warnings
            evpn_headers = tuple(h_lower[evpn_start:meta_start])
            evpn_group_width = len(_EVPN_COLUMNS)
            if (not evpn_headers
                    or len(evpn_headers) % evpn_group_width != 0
                    or not all(
                        evpn_headers[offset:offset + evpn_group_width] == _EVPN_COLUMNS
                        for offset in range(0, len(evpn_headers), evpn_group_width)
                    )):
                errors.append(
                    "  CSV header 的 EVPN 列结构无效："
                    "每组必须为 11 列，dhcp_relay 同时用于选择 server-group"
                )
                return errors, warnings
            evpn_group_count = len(evpn_headers) // evpn_group_width

            # type 列索引（不存在时视作 eth）
            type_col = h_lower.index("type") if "type" in h_lower else None

            data_rows = list(reader)
            production_hostnames = []
            for candidate in data_rows:
                if not candidate or len(candidate) <= _COL_HOSTNAME:
                    continue
                candidate_type = (
                    candidate[type_col].strip().casefold()
                    if type_col is not None and len(candidate) > type_col else "eth"
                )
                if candidate_type in _ETH_TYPES and candidate[_COL_HOSTNAME].strip():
                    production_hostnames.append(candidate[_COL_HOSTNAME].strip())

            # 大小写不敏感的 hostname 重复检测
            seen_hosts, seen_eth0_mac = {}, {}
            # IP -> [(row, hostname, type)]. One matching production/AIR pair
            # may intentionally share an address; every other duplicate stays
            # invalid, including a third row using the same address.
            seen_eth0_addr = {}
            seen_lo_ip = {}

            for row_n, row in enumerate(data_rows, start=2):
                if not row or all(_vna(c) for c in row):
                    continue

                hn = row[_COL_HOSTNAME].strip() if len(row) > _COL_HOSTNAME else ""
                if not hn:
                    e(row_n, "?", "hostname 为空")
                    continue

                # 大小写不敏感重复检测
                hn_key = hn.lower()
                if hn_key in seen_hosts:
                    e(row_n, hn, f"hostname 重复（首次在行{seen_hosts[hn_key]}，大小写不敏感）")
                else:
                    seen_hosts[hn_key] = row_n

                # 确定设备类型
                row_type = row[type_col].strip().lower() if (type_col is not None and len(row) > type_col) else "eth"
                if row_type not in _SUPPORTED_TYPES:
                    e(row_n, hn, f"type 无效：'{row_type}'（仅支持 eth/eth_spx/spx/ib/nvl/server/air）")
                    continue
                is_nvos  = row_type in _NVOS_TYPES
                is_server = row_type in _SERVER_TYPES
                is_air = row_type in _AIR_TYPES

                # ── 共有字段校验（eth0、eth1 管理接口、MAC）────────────────────
                if len(row) < _COL_ETH0_IP + 1:
                    e(row_n, hn, f"列数不足（{len(row)} < {_COL_ETH0_IP+1}）")
                    continue

                eth0_ip_raw = row[_COL_ETH0_IP].strip()
                eth0_nm     = row[_COL_ETH0_NM].strip()  if len(row) > _COL_ETH0_NM  else ""
                eth0_gw     = row[_COL_ETH0_GW].strip()  if len(row) > _COL_ETH0_GW  else ""
                eth0_mac    = row[_COL_ETH0_MAC].strip() if len(row) > _COL_ETH0_MAC else ""

                # 所有静态管理地址按实际 IP 去重，不因前缀写法不同而漏检。
                if not _vna(eth0_ip_raw) and eth0_ip_raw.lower() != "dhcp-client":
                    try:
                        parsed_eth0 = ipaddress.ip_interface(eth0_ip_raw).ip
                        eth0_addr = str(parsed_eth0)
                        previous = seen_eth0_addr.setdefault(eth0_addr, [])
                        allowed_pair = (
                            len(previous) == 1
                            and _is_matching_production_air_pair(
                                previous[0][1], previous[0][2], hn, row_type,
                                production_hostnames,
                            )
                        )
                        if previous and not allowed_pair:
                            e(
                                row_n, hn,
                                f"eth0_ip 重复（{eth0_addr}，首次行{previous[0][0]}）",
                            )
                        previous.append((row_n, hn, row_type))
                    except ValueError:
                        pass  # 各设备类型分支负责输出更具体的格式错误。

                if is_server:
                    # infra/deploy_infra.py 以 eth0_ip 登录 server；允许裸 IPv4 或 CIDR。
                    if _vna(eth0_ip_raw):
                        e(row_n, hn, "eth0_ip 为空（server 必填）")
                    else:
                        try:
                            server_ip = ipaddress.ip_interface(eth0_ip_raw).ip
                            if not isinstance(server_ip, ipaddress.IPv4Address):
                                e(row_n, hn, f"eth0_ip 目前只支持 IPv4：'{eth0_ip_raw}'")
                        except ValueError:
                            e(row_n, hn, f"eth0_ip 无效：'{eth0_ip_raw}'")
                    if not _vna(eth0_mac):
                        if not _valid_mac(eth0_mac):
                            e(row_n, hn, f"eth0_mac 无效：'{eth0_mac}'")
                        else:
                            key = eth0_mac.lower().replace("-", ":")
                            if key in seen_eth0_mac:
                                e(row_n, hn, f"eth0_mac 重复（首次行{seen_eth0_mac[key]}）")
                            else:
                                seen_eth0_mac[key] = row_n
                    continue

                if is_air:
                    # AIR 行由 DHCP 生成器从 p2p-air.json 同步，不参与交换机配置生成。
                    if _vna(eth0_ip_raw):
                        e(row_n, hn, "eth0_ip 为空（AIR 设备必填）")
                    elif "/" in eth0_ip_raw or not _valid_ip(eth0_ip_raw):
                        e(row_n, hn, f"eth0_ip 无效（应为不含前缀的 IPv4）：'{eth0_ip_raw}'")
                    if _vna(eth0_nm):
                        e(row_n, hn, "netmask 为空（AIR 设备必填）")
                    elif not _valid_mask(eth0_nm):
                        e(row_n, hn, f"netmask 无效：'{eth0_nm}'")
                    if _vna(eth0_mac):
                        e(row_n, hn, "eth0_mac 为空（AIR 设备必填）")
                    elif not _valid_mac(eth0_mac):
                        e(row_n, hn, f"eth0_mac 无效：'{eth0_mac}'")
                    else:
                        key = eth0_mac.lower().replace("-", ":")
                        if key in seen_eth0_mac:
                            e(row_n, hn, f"eth0_mac 重复（首次行{seen_eth0_mac[key]}）")
                        else:
                            seen_eth0_mac[key] = row_n
                    continue

                if is_nvos:
                    # NVOS 设备：eth0_ip / netmask / eth0_gw 均为必填
                    if _vna(eth0_ip_raw):
                        e(row_n, hn, "eth0_ip 为空（NVOS 设备必填）")
                    elif not _valid_ip(eth0_ip_raw):
                        e(row_n, hn, f"eth0_ip 无效：'{eth0_ip_raw}'")
                    if _vna(eth0_nm):
                        e(row_n, hn, "netmask 为空（NVOS 设备必填）")
                    elif not _valid_mask(eth0_nm):
                        e(row_n, hn, f"netmask 无效：'{eth0_nm}'")
                    if _vna(eth0_gw):
                        e(row_n, hn, "eth0_gw 为空（NVOS 设备必填）")
                    elif not _valid_ip(eth0_gw):
                        e(row_n, hn, f"eth0_gw 无效：'{eth0_gw}'")
                else:
                    # ETH/SPX 设备
                    if len(row) < _COL_PEERLINK + 1:
                        e(row_n, hn, f"列数不足（{len(row)} < {_COL_PEERLINK+1}）")
                        continue
                    if not _vna(eth0_ip_raw):
                        if eth0_ip_raw.lower() == "dhcp-client":
                            pass  # 合法
                        elif "/" in eth0_ip_raw:
                            e(row_n, hn, f"eth0_ip 不应含前缀长度（放到 netmask 列）：'{eth0_ip_raw}'")
                        elif not _valid_ip(eth0_ip_raw):
                            e(row_n, hn, f"eth0_ip 无效：'{eth0_ip_raw}'")
                        if not _vna(eth0_nm) and not _valid_mask(eth0_nm):
                            e(row_n, hn, f"netmask(eth0) 无效：'{eth0_nm}'")
                    if not _vna(eth0_gw) and not _valid_ip(eth0_gw):
                        e(row_n, hn, f"eth0_gw 无效：'{eth0_gw}'")

                # eth0_mac（共有）
                if not _vna(eth0_mac):
                    if not _valid_mac(eth0_mac):
                        e(row_n, hn, f"eth0_mac 无效：'{eth0_mac}'")
                    else:
                        key = eth0_mac.lower().replace("-", ":")
                        if key in seen_eth0_mac:
                            e(row_n, hn, f"eth0_mac 重复（首次行{seen_eth0_mac[key]}）")
                        else:
                            seen_eth0_mac[key] = row_n

                # eth1（可选三元组）
                eth1_ip  = row[_COL_ETH1_IP].strip()  if len(row) > _COL_ETH1_IP  else ""
                eth1_nm  = row[_COL_ETH1_NM].strip()  if len(row) > _COL_ETH1_NM  else ""
                eth1_gw  = row[_COL_ETH1_GW].strip()  if len(row) > _COL_ETH1_GW  else ""
                eth1_mac = row[_COL_ETH1_MAC].strip()  if len(row) > _COL_ETH1_MAC else ""
                if not _vna(eth1_ip):
                    if not _valid_ip(eth1_ip):
                        e(row_n, hn, f"eth1_ip 无效：'{eth1_ip}'")
                    if not _vna(eth1_nm) and not _valid_mask(eth1_nm):
                        e(row_n, hn, f"netmask(eth1) 无效：'{eth1_nm}'")
                    if not _vna(eth1_gw) and not _valid_ip(eth1_gw):
                        e(row_n, hn, f"eth1_gw 无效：'{eth1_gw}'")
                if not _vna(eth1_mac) and not _valid_mac(eth1_mac):
                    e(row_n, hn, f"eth1_mac 无效：'{eth1_mac}'")

                # ── ETH/SPX 专属字段（NVOS 设备跳过）────────────────────────
                if is_nvos:
                    continue

                # lo_ip
                lo_raw = row[_COL_LO_IP].strip() if len(row) > _COL_LO_IP else ""
                if not _vna(lo_raw):
                    lo_check = lo_raw if "/" in lo_raw else f"{lo_raw}/32"
                    if not _valid_ip_prefix(lo_check):
                        e(row_n, hn, f"lo_ip 无效：'{lo_raw}'")
                    else:
                        if lo_check in seen_lo_ip:
                            e(row_n, hn, f"lo_ip 重复（首次行{seen_lo_ip[lo_check]}）")
                        else:
                            seen_lo_ip[lo_check] = row_n

                # vlan_id
                vlan_id_raw = row[_COL_VLAN_ID].strip() if len(row) > _COL_VLAN_ID else ""
                if not _vna(vlan_id_raw) and not _valid_vlan(vlan_id_raw):
                    e(row_n, hn, f"vlan_id 无效：'{vlan_id_raw}'")

                # svi_ip / vrr_ip / vrr_mac（主 VRF）
                svi_nm_main = row[_COL_SVI_NM].strip() if len(row) > _COL_SVI_NM else ""
                for col, label in ((_COL_SVI_IP, "svi_ip"), (_COL_VRR_IP, "vrr_ip")):
                    val = row[col].strip() if len(row) > col else ""
                    if not _vna(val):
                        combined = f"{val}/{svi_nm_main}" if not _vna(svi_nm_main) else val
                        if not _valid_ip_prefix(combined):
                            e(row_n, hn, f"{label} 无效：'{val}/{svi_nm_main}'")
                vrr_mac_main = row[_COL_VRR_MAC].strip() if len(row) > _COL_VRR_MAC else ""
                if not _vna(vrr_mac_main) and not _valid_mac(vrr_mac_main):
                    e(row_n, hn, f"vrr_mac(主) 无效：'{vrr_mac_main}'")

                # bgp_asn
                bgp_asn = row[_COL_BGP_ASN].strip() if len(row) > _COL_BGP_ASN else ""
                if not _vna(bgp_asn) and not _valid_asn(bgp_asn):
                    e(row_n, hn, f"bgp_asn 无效：'{bgp_asn}'")

                # bond_type
                bond_type = row[_COL_BOND_TYPE].strip().lower() if len(row) > _COL_BOND_TYPE else ""
                if not _vna(bond_type) and bond_type not in _VALID_BOND_TYPES:
                    w(row_n, hn, f"bond_type 未知：'{bond_type}'（允许：{', '.join(sorted(_VALID_BOND_TYPES))}）")

                # bond_mac
                bond_mac = row[_COL_BOND_MAC].strip() if len(row) > _COL_BOND_MAC else ""
                if not _vna(bond_mac) and not _valid_mac(bond_mac):
                    e(row_n, hn, f"bond_mac 无效：'{bond_mac}'")

                if vrl_col is not None:
                    vrl_value = row[vrl_col].strip().casefold() if len(row) > vrl_col else ""
                    if vrl_value not in {
                        "", "na", "n/a", "false", "0", "no", "n",
                        "true", "1", "yes", "y",
                    }:
                        e(row_n, hn, "vrl 只允许 true/false/na/空")

                # EVPN groups（动态组数）
                for gi in range(evpn_group_count):
                    base = evpn_start + gi * evpn_group_width
                    if base >= len(row):
                        break
                    evpn_vrf = row[base].strip() if len(row) > base else ""
                    if _vna(evpn_vrf):
                        continue
                    l3vni  = row[base+1].strip() if len(row) > base+1 else ""
                    l3vlan = row[base+2].strip() if len(row) > base+2 else ""
                    l2vni_offset = 4
                    l2vlan_offset = 5
                    svi_offset = 6
                    netmask_offset = 7
                    vrr_offset = 8
                    vrr_mac_offset = 9
                    l2vni  = row[base+l2vni_offset].strip() if len(row) > base+l2vni_offset else ""
                    l2vlan = row[base+l2vlan_offset].strip() if len(row) > base+l2vlan_offset else ""
                    if not _vna(l3vni)  and not _valid_vni(l3vni):
                        e(row_n, hn, f"EVPN[{gi}].l3vni 无效：'{l3vni}'")
                    if not _vna(l3vlan) and not _valid_vlan(l3vlan):
                        e(row_n, hn, f"EVPN[{gi}].l3vlan 无效：'{l3vlan}'")
                    if not _vna(l2vni)  and not _valid_vni(l2vni):
                        e(row_n, hn, f"EVPN[{gi}].l2vni 无效：'{l2vni}'")
                    if not _vna(l2vlan) and not _valid_vlan(l2vlan):
                        e(row_n, hn, f"EVPN[{gi}].l2vlan 无效：'{l2vlan}'")
                    evpn_nm  = row[base+netmask_offset].strip() if len(row) > base+netmask_offset else ""
                    evpn_svi = row[base+svi_offset].strip() if len(row) > base+svi_offset else ""
                    evpn_vrr = row[base+vrr_offset].strip() if len(row) > base+vrr_offset else ""
                    evpn_vrm = row[base+vrr_mac_offset].strip() if len(row) > base+vrr_mac_offset else ""
                    for val, label in ((evpn_svi, f"EVPN[{gi}].svi_ip"),
                                       (evpn_vrr, f"EVPN[{gi}].vrr_ip")):
                        if not _vna(val):
                            combined = f"{val}/{evpn_nm}" if not _vna(evpn_nm) else val
                            if not _valid_ip_prefix(combined):
                                e(row_n, hn, f"{label} 无效：'{val}/{evpn_nm}'")
                    if not _vna(evpn_vrm) and not _valid_mac(evpn_vrm):
                        e(row_n, hn, f"EVPN[{gi}].vrr_mac 无效：'{evpn_vrm}'")

    except Exception as ex:
        errors.append(f"  读取失败：{ex}")

    return errors, warnings


def _validate_subnet_csv(path):
    """校验 DHCP subnet CSV。"""
    errors, warnings = [], []
    seen_networks = {}
    profile_services = {}
    nvos_service = None
    required_cols = {"shared_network", "subnet", "netmask", "range_start",
                     "range_end", "routers", "ztp_service_ip",
                     "cumulus_profile", "nvos_ztp"}
    legacy_cols = {"bootfile_name", "cumulus_provision_url"}
    try:
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            fields = [str(item or "").strip() for item in (reader.fieldnames or [])]
            if len(fields) != len(set(fields)):
                errors.append("  CSV 存在重复列名")
                return errors, warnings
            found_legacy = sorted(
                field for field in fields if field.casefold() in legacy_cols
            )
            if found_legacy:
                errors.append(
                    f"  包含已废弃 URL 列：{found_legacy}；"
                    "请改用 ztp_service_ip,cumulus_profile,nvos_ztp"
                )
                return errors, warnings
            missing = required_cols - set(fields)
            if missing:
                errors.append(f"  缺少列：{sorted(missing)}")
                return errors, warnings
            reader.fieldnames = fields
            for row_n, row in enumerate(reader, start=2):
                if not any(str(value or "").strip() for value in row.values()):
                    continue
                shared_network = row.get("shared_network", "").strip()
                subnet  = row.get("subnet", "").strip()
                netmask = row.get("netmask", "").strip()
                rs      = row.get("range_start", "").strip()
                re_     = row.get("range_end",   "").strip()
                routers = row.get("routers",     "").strip()
                if not shared_network:
                    errors.append(f"  行{row_n} shared_network 为空")
                elif shared_network in seen_networks:
                    errors.append(
                        f"  行{row_n} shared_network='{shared_network}' 重复"
                        f"（首次行{seen_networks[shared_network]}）；每个三层 subnet "
                        "必须使用独立名称"
                    )
                else:
                    seen_networks[shared_network] = row_n
                if not _valid_ip(subnet):
                    errors.append(f"  行{row_n} subnet 无效：'{subnet}'")
                if not _valid_mask(netmask):
                    errors.append(f"  行{row_n} netmask 无效：'{netmask}'")
                for label, val in (("range_start", rs), ("range_end", re_)):
                    if val and not _valid_ip(val):
                        errors.append(f"  行{row_n} {label} 无效：'{val}'")
                if routers and not _valid_ip(routers):
                    errors.append(f"  行{row_n} routers 无效：'{routers}'")
                profile = str(row.get("cumulus_profile") or "").strip().casefold()
                nvos_ztp = str(row.get("nvos_ztp") or "").strip().casefold()
                service_ip = str(row.get("ztp_service_ip") or "").strip()
                if profile not in {"oob", "oobofoob", "none"}:
                    errors.append(
                        f"  行{row_n} cumulus_profile='{profile}' 无效；"
                        "只允许 oob/oobofoob/none"
                    )
                if nvos_ztp not in {"yes", "no"}:
                    errors.append(
                        f"  行{row_n} nvos_ztp='{nvos_ztp}' 无效；只允许 yes/no"
                    )
                service_address = None
                if service_ip:
                    try:
                        service_address = ipaddress.IPv4Address(service_ip)
                        service_ip = str(service_address)
                    except ipaddress.AddressValueError:
                        errors.append(
                            f"  行{row_n} ztp_service_ip='{service_ip}' 不是有效 IPv4"
                        )
                if (profile in {"oob", "oobofoob"} or nvos_ztp == "yes") and not service_ip:
                    errors.append(
                        f"  行{row_n} 启用了平台 ZTP，但 ztp_service_ip 为空"
                    )
                if profile == "none" and nvos_ztp == "no" and service_ip:
                    errors.append(
                        f"  行{row_n} 未启用任何平台 ZTP，ztp_service_ip 必须为空"
                    )
                if service_address is not None and (
                    service_address.is_unspecified or service_address.is_multicast
                ):
                    errors.append(
                        f"  行{row_n} ztp_service_ip={service_address} 不是可用单播地址"
                    )
                if service_ip and profile in {"oob", "oobofoob"}:
                    previous = profile_services.setdefault(profile, (service_ip, row_n))
                    if previous[0] != service_ip:
                        errors.append(
                            f"  行{row_n} profile={profile} 使用 {service_ip}，"
                            f"但行{previous[1]} 使用 {previous[0]}"
                        )
                if service_ip and nvos_ztp == "yes":
                    if nvos_service is None:
                        nvos_service = (service_ip, row_n)
                    elif nvos_service[0] != service_ip:
                        errors.append(
                            f"  行{row_n} NVOS 使用 {service_ip}，但行"
                            f"{nvos_service[1]} 使用 {nvos_service[0]}"
                        )
                try:
                    network = ipaddress.IPv4Network(f"{subnet}/{netmask}", strict=True)
                    start = ipaddress.IPv4Address(rs)
                    end = ipaddress.IPv4Address(re_)
                    router = ipaddress.IPv4Address(routers)
                    if start not in network or end not in network or start > end:
                        errors.append(f"  行{row_n} 动态 range 不属于 {network} 或起止颠倒")
                    if router not in network:
                        errors.append(f"  行{row_n} routers={router} 不属于 {network}")
                    elif start <= router <= end:
                        errors.append(f"  行{row_n} routers={router} 落入动态 range")
                    if service_address is not None and service_address in network:
                        if service_address in (network.network_address, network.broadcast_address):
                            errors.append(
                                f"  行{row_n} ztp_service_ip={service_address} 不是可用主机地址"
                            )
                        elif start <= service_address <= end:
                            errors.append(
                                f"  行{row_n} ztp_service_ip={service_address} 落入动态 range"
                            )
                except ValueError:
                    # The field-specific checks above already provide the useful error.
                    pass
    except Exception as ex:
        errors.append(f"  读取失败：{ex}")
    return errors, warnings


def _validate_global_yaml(path, section_key="eth"):
    """YAML 语法检查 + 必要 key 存在性校验。

    section_key: "eth"（Cumulus）、"ib" 或 "nvl"（NVOS）。
    """
    errors, warnings = [], []
    try:
        import yaml
    except ImportError:
        warnings.append("  PyYAML 未安装，跳过 YAML 语法检查（pip install pyyaml）")
        return errors, warnings
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if data is None:
            warnings.append("  文件为空或仅含注释，跳过内容校验")
            return errors, warnings
        if not isinstance(data, dict):
            errors.append("  YAML 根节点应为 mapping，实际为其他类型")
            return errors, warnings
        schema_version = data.get("schema_version")
        if schema_version is None:
            warnings.append("  缺少 schema_version；按旧版 schema 1 兼容校验")
        elif isinstance(schema_version, bool) or not isinstance(schema_version, int):
            errors.append("  schema_version 必须是整数")
        elif schema_version != GLOBAL_SCHEMA_VERSION:
            errors.append(
                f"  不支持的 schema_version={schema_version}；"
                f"当前脚本仅支持 schema {GLOBAL_SCHEMA_VERSION}"
            )
        try:
            prefix = str(
                data["common"]["mgmt"]["ztp"]["ztp_url_prefix"]
            ).strip().rstrip("/")
        except (KeyError, TypeError):
            errors.append("  缺少 common.mgmt.ztp.ztp_url_prefix")
        else:
            try:
                validate_ztp_url_prefix(prefix)
            except ValueError as exc:
                errors.append(f"  {exc}")
        # Support merged format: switches list with eth/ib/nvl sections
        if "switches" in data:
            section = next((s[section_key] for s in data["switches"]
                            if isinstance(s, dict) and section_key in s), None)
            if section is None:
                errors.append(f"  合并格式缺少 '{section_key}' 部分")
                return errors, warnings
            common = data.get("common", {}).get("switch", {})
            if common:
                import copy
                def _deep_merge(base, ov):
                    r = dict(base)
                    for k, v in ov.items():
                        r[k] = _deep_merge(r[k], v) if k in r and isinstance(r[k], dict) and isinstance(v, dict) else v
                    return r
                data = _deep_merge(common, section)
            else:
                data = section
        if section_key == "eth":
            # Cumulus(eth) 全局配置必须包含 bridge 和 system
            for key in ("bridge", "system"):
                if key not in data:
                    errors.append(f"  缺少顶层 key：'{key}'")
            sys_node = data.get("system", {})
            if isinstance(sys_node, dict):
                for key in ("aaa", "ntp", "dns"):
                    if key not in sys_node:
                        warnings.append(f"  system.{key} 缺失")
        else:
            # NVOS（ib / nvl）全局配置至少需要 system
            if "system" not in data:
                errors.append("  缺少顶层 key：'system'")
            sys_node = data.get("system", {})
            if isinstance(sys_node, dict) and "aaa" not in sys_node:
                warnings.append("  system.aaa 缺失")
    except Exception as ex:
        errors.append(f"  YAML 语法错误：{ex}")
    return errors, warnings


def _validate_pubkey(path):
    """校验 SSH 公钥文件：格式前缀、严格 base64 解码，并尝试 ssh-keygen -l -f 验证。"""
    errors, warnings = [], []
    _PUB_PREFIXES = ("ssh-rsa", "ssh-ed25519", "ssh-dss",
                     "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
                     "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com",
                     "sk-ecdsa-sha2-nistp256@openssh.com")
    try:
        with open(path, encoding="utf-8") as f:
            first = f.readline().strip()
        if not first:
            errors.append("  文件为空")
            return errors, warnings
        parts = first.split()
        if not any(first.startswith(p) for p in _PUB_PREFIXES):
            errors.append(f"  不是有效的 SSH 公钥格式（首行：{first[:60]}）")
            return errors, warnings
        if len(parts) < 2:
            errors.append("  SSH 公钥缺少 base64 部分")
            return errors, warnings
        # 严格 base64 解码（validate=True 拒绝非法字符）
        try:
            decoded = base64.b64decode(parts[1], validate=True)
            if len(decoded) < 20:
                errors.append("  SSH 公钥 base64 数据过短（可能被截断）")
        except Exception:
            errors.append("  SSH 公钥 base64 部分无效（含非法字符或无法解码）")
            return errors, warnings
        # 用 ssh-keygen -l -f 做完整格式验证（有则用，无则跳过）
        try:
            r = subprocess.run(
                ["ssh-keygen", "-l", "-f", path],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode != 0:
                errors.append(f"  ssh-keygen 校验失败：{r.stderr.strip()[:120]}")
        except FileNotFoundError:
            warnings.append("  ssh-keygen 未找到，跳过完整公钥验证")
        except subprocess.TimeoutExpired:
            warnings.append("  ssh-keygen 超时，跳过完整公钥验证")
    except Exception as ex:
        errors.append(f"  读取失败：{ex}")
    return errors, warnings


def _validate_xlsx(path):
    """检查 xlsx 文件能否被正常打开（需要 openpyxl）。"""
    errors, warnings = [], []
    try:
        import openpyxl
        wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
        if not wb.sheetnames:
            warnings.append("  xlsx 无工作表")
        wb.close()
    except ImportError:
        warnings.append("  openpyxl 未安装，跳过 xlsx 检查（pip install openpyxl）")
    except Exception as ex:
        errors.append(f"  xlsx 读取失败：{ex}")
    return errors, warnings


def _validate_project(proj_dir):
    """
    在创建软链接前对项目文件做合法性检查。
    返回 True 表示可继续（错误为 0），False 表示有错误。
    用户可以选择忽略错误强行继续（-y 模式下自动继续）。
    """
    all_errors   = []
    all_warnings = []

    def _run(label, path, fn):
        if not os.path.exists(path):
            return  # 文件不存在由 _process_mapping 报告
        errs, warns = fn(path)
        if errs or warns:
            print(_c(YELLOW if not errs else RED, f"  {label}"))
            for msg in errs:
                print(_c(RED, f"  [ERR]{msg}"))
            for msg in warns:
                print(_c(YELLOW, f"  [WRN]{msg}"))
        else:
            print(f"  [OK]  {label}")
        all_errors.extend(errs)
        all_warnings.extend(warns)

    print("── 文件合法性检查 ────────────────────────────────────────────")

    # 先读取 CSV 中存在的设备类型，按需校验对应的全局配置区段
    csv_path = os.path.join(_CSV_DIR or proj_dir, "02-devices_config.csv")
    types_in_csv = set()
    if os.path.isfile(csv_path):
        try:
            with open(csv_path, newline="", encoding="utf-8-sig") as _f:
                _rdr = csv.DictReader(_f)
                for _row in _rdr:
                    _t = _row.get("type", "").strip().lower()
                    if _t:
                        types_in_csv.add(_t)
        except Exception:
            pass

    # YAML 全局配置（合并格式），按 CSV 中出现的类型决定校验哪些区段
    _run("01-global.yaml (eth)",
         os.path.join(proj_dir, "01-global.yaml"),
         _validate_global_yaml)  # section_key="eth" by default
    if "ib" in types_in_csv:
        _run("01-global.yaml (ib)",
             os.path.join(proj_dir, "01-global.yaml"),
             lambda p: _validate_global_yaml(p, section_key="ib"))
    if "nvl" in types_in_csv:
        _run("01-global.yaml (nvl)",
             os.path.join(proj_dir, "01-global.yaml"),
             lambda p: _validate_global_yaml(p, section_key="nvl"))

    # 设备 CSV（eth/eth_spx/spx/ib/nvl/server 共用一个文件，按 type 列区分）
    _run("02-devices_config.csv", csv_path, _validate_eth_csv)

    # DHCP subnet CSV
    _run("02-dhcp-subnet_config.csv",
         os.path.join(proj_dir, "02-dhcp-subnet_config.csv"), _validate_subnet_csv)

    def _empty_artifact(label, kind="占位文件"):
        message = f"{label} 大小为 0（{kind}）"
        if _STRICT:
            all_errors.append(message)
            print(_c(RED, f"  [ERR] {message}"))
        else:
            all_warnings.append(message)
            print(_c(YELLOW, f"  [WRN] {message}"))

    # SSH 公钥
    unused_empty_pubkeys = _unused_empty_pubkeys(proj_dir)
    for pub in sorted(glob.glob(os.path.join(proj_dir, "*.pub"))):
        label = os.path.basename(pub)
        if os.path.getsize(pub) == 0:
            if pub in unused_empty_pubkeys:
                message = f"{label} 大小为 0（未使用的旧占位文件，跳过发布）"
                all_warnings.append(message)
                print(_c(YELLOW, f"  [WRN] {message}"))
            else:
                _empty_artifact(label)
        else:
            _run(label, pub, _validate_pubkey)

    # 只校验 setup 选定的唯一 P2P 源；其他项目 XLSX 不会被运行时脚本读取。
    if _P2P_SOURCE:
        label = f"p2p.xlsx → {os.path.basename(_P2P_SOURCE)}"
        if os.path.getsize(_P2P_SOURCE) == 0:
            _empty_artifact(label)
        else:
            _run(label, _P2P_SOURCE, _validate_xlsx)

    # 共享系统镜像：http/image/ 是唯一来源，不再读取项目目录中的旧 .bin 文件。
    shared_bins = sorted(glob.glob(os.path.join(IMAGE_DIR, "*.bin")))
    if not shared_bins:
        message = f"共享镜像目录 {IMAGE_DIR}/ 下没有 .bin 文件"
        all_warnings.append(message)
        print(_c(YELLOW, f"  [WRN] {message}"))
    for bn in shared_bins:
        size = os.path.getsize(bn)
        label = f"image/{os.path.basename(bn)}"
        if not _image_platform(os.path.basename(bn)):
            message = f"{label} 无法按文件名识别为 Cumulus 或 NVOS 镜像"
            all_warnings.append(message)
            print(_c(YELLOW, f"  [WRN] {message}"))
            continue
        if size == 0:
            _empty_artifact(label, "可能是占位文件")
        else:
            print(f"  [OK]  {label}（{size:,} 字节）")

    # 汇总
    nerr  = len(all_errors)
    nwarn = len(all_warnings)
    if nerr == 0 and nwarn == 0:
        print(_c(GREEN, "  校验通过，未发现问题"))
        return True

    print()
    if nerr:
        print(_c(RED, f"  共 {nerr} 个错误，{nwarn} 个警告"))
    else:
        print(_c(YELLOW, f"  共 {nwarn} 个警告（无错误）"))

    if nerr == 0:
        return True  # 只有警告，继续

    if _FORCE:
        print(_c(YELLOW, "  --force 模式：忽略错误，强行继续…"))
        return True

    if _DRY_RUN:
        print(_c(RED, "  --dry-run 校验失败：请修复错误，或明确使用 --force 绕过"))
        return False

    if _AUTO_YES:
        # -y 仅自动确认无害操作；校验错误必须用 --force 才能绕过
        print(_c(RED, "  -y 模式不忽略校验错误，请加 --force 强行继续或修复后重试"))
        return False

    if not sys.stdin.isatty():
        print(_c(RED, "  非交互终端拒绝绕过校验；请修复输入或显式使用 --force"))
        return False
    try:
        ans = input("  发现错误，仍要继续创建软链接？[y/N] ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


# ── 清理上一个项目 ────────────────────────────────────────────────────────────

def _managed_ztp_link_candidates():
    """返回 setup 明确管理的 ZTP 链接，避免扫描并误删用户自建链接。"""
    paths = [os.path.join(ZTP, ztp_rel) for ztp_rel, _proj_rel, _kind in MAPPINGS]
    paths.extend(os.path.join(HTTP_BASE, rel) for rel, _proj_rel, _kind in WORKSPACE_INPUT_MAPPINGS)
    paths.extend([
        os.path.join(ZTP, "config", "cumulus", "latest_yaml"),
        os.path.join(ZTP, "config", "nvos", "latest_yaml"),
        os.path.join(ZTP, "config", "cumulus", "template", "P2P", "output-p2p"),
        os.path.join(ZTP, "config", "nvos", "template", "P2P", "output-p2p"),
        # 兼容清理由目录更名前的 setup 创建的旧链接。
        os.path.join(ZTP, "config", "cumulus", "template", "AIR", "output-p2p"),
        os.path.join(ZTP, "config", "nvos", "template", "99-output-ib"),
        os.path.join(ZTP, "config", "nvos", "template", "99-output-nvl"),
        os.path.join(ZTP, "config", "nvos", "template", "99-output-published"),
    ])
    paths.extend(P2P_INPUT_LINKS)
    paths.extend(link_path for link_path, _project_rel in BRINGUP_OUTPUT_MAPPINGS)
    paths.extend(link_path for link_path, _project_rel in ANALYZER_INPUT_MAPPINGS)
    paths.extend(link_path for link_path, _project_rel in ANALYZER_OUTPUT_MAPPINGS)
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
    paths.extend(glob.glob(os.path.join(ZTP, "optimize", "*-sample", "*")))
    return sorted({path for path in paths if os.path.islink(path)})


def _unsetup_previous(proj_dir):
    """
    在 setup 之前清理遗留链接：
      1. setup 管理范围内所有指向其他 DAY0-Prepare 项目（非 proj_dir）的软链接
    """
    proj_real = os.path.realpath(proj_dir)
    here_real = os.path.realpath(HERE)   # DAY0-Prepare/
    to_del = []

    # 1. ZTP 动态链接 + 工作目录中的固定管理位置。
    candidates = _managed_ztp_link_candidates()
    candidates.extend(lp for lp, _ in _monitor_link_paths(proj_dir))
    candidates.extend(lp for lp, _ in _bringup_link_pairs(proj_dir))
    candidates.extend(lp for lp, _ in _analyzer_input_pairs(proj_dir))
    candidates.extend(lp for lp, _ in _analyzer_output_pairs(proj_dir))
    legacy_monitor_csv = set(_legacy_project_monitor_csv_links(proj_dir))
    candidates.extend(legacy_monitor_csv)
    candidates.extend(lp for lp, _ in _NET_CSV_LINKS)
    for lp in sorted(set(candidates)):
        if not os.path.islink(lp):
            continue
        target_real = os.path.realpath(lp)
        # 只关心指向 DAY0-Prepare/ 下的链接
        if not (target_real == here_real or target_real.startswith(here_real + os.sep)):
            continue
        # 旧版镜像链接即使指向当前项目也必须移除；镜像现由 http/image/ 统一提供。
        image_root = os.path.join(ZTP, "image") + os.sep
        if os.path.abspath(lp).startswith(image_root):
            to_del.append(lp)
            continue
        # 旧版项目监控 CSV 已由 monitor/02-devices_config.csv 取代。
        if lp in legacy_monitor_csv:
            to_del.append(lp)
            continue
        # 当前项目的链接保留
        if target_real == proj_real or target_real.startswith(proj_real + os.sep):
            continue
        to_del.append(lp)

    # 去重（同一路径可能来自多个固定管理集合）
    seen = set(); to_del = [lp for lp in to_del if not (lp in seen or seen.add(lp))]

    if not to_del:
        return

    print(_c(YELLOW, f"\n── 清理上一个项目遗留链接（共 {len(to_del)} 个）────────────────────"))
    for lp in to_del:
        rel = os.path.relpath(lp, HTTP_BASE)
        print(f"  {rel}  →  {os.readlink(lp)}")

    if _DRY_RUN or _AUTO_YES:
        if not _DRY_RUN:
            print(_c(YELLOW, "自动删除（-y 模式）…"))
    else:
        if not sys.stdin.isatty():
            print(_c(YELLOW, "非交互终端不删除遗留链接；请使用 -y 明确确认"))
            return
        try:
            ans = input(f"\n删除以上 {len(to_del)} 个遗留链接？[Y/n] ").strip().lower()
        except EOFError:
            print(_c(YELLOW, "未获得确认，保留遗留链接"))
            return
        if ans in ("n", "no"):
            print(_c(YELLOW, "已跳过清理，继续 setup…"))
            return

    for lp in to_del:
        rel = os.path.relpath(lp, HTTP_BASE)
        if _DRY_RUN:
            print(_c(CYAN,  f"  [DRY] 删除 {rel}"))
        else:
            os.remove(lp)
            print(_c(GREEN, f"  [DEL] {rel}"))


# ── 冲突检测 ──────────────────────────────────────────────────────────────────

def _collect_expected_links(proj_dir):
    """
    收集所有预期会创建的软链接路径（link_path），不包含目标值。
    用于冲突检测和清单：覆盖 ZTP、网络工具及监控路径。
    """
    links = []

    # 固定映射
    for ztp_rel, _proj_rel, _kind in MAPPINGS:
        links.append(os.path.join(ZTP, ztp_rel))
    for workspace_rel, _proj_rel, _kind in WORKSPACE_INPUT_MAPPINGS:
        links.append(os.path.join(HTTP_BASE, workspace_rel))

    # 项目无关的共享镜像
    links.extend(link_path for link_path, _src in _shared_image_pairs())

    # P2P 输入统一使用固定名称，两个生成器共享同一输出目录。
    links.extend(P2P_INPUT_LINKS)
    links.extend(P2P_OUTPUT_LINKS)
    links.append(P2P_AIR_JSON_LINK)
    links.extend(link_path for link_path, _target in _bringup_link_pairs(proj_dir))
    links.extend(link_path for link_path, _target in _analyzer_input_pairs(proj_dir))
    links.extend(link_path for link_path, _target in _analyzer_output_pairs(proj_dir))

    # .pub 公钥
    key_dir = os.path.join(ZTP, "config", "publickey")
    for src in glob.glob(os.path.join(proj_dir, "*.pub")):
        if os.path.getsize(src) > 0:
            links.append(os.path.join(key_dir, os.path.basename(src)))

    # latest_yaml
    for sub in ("cumulus", "nvos"):
        links.append(os.path.join(ZTP, "config", sub, "latest_yaml"))
    sample = sample_directory(os.path.join(ZTP, "optimize"), proj_dir)
    links.extend(str(sample / name) for name in LINK_NAMES.values())

    # 网络类型 CSV 链接
    for link_path, _ in _NET_CSV_LINKS:
        links.append(link_path)

    # 项目监控归档、采集目录和汇总页面链接
    links.extend(link_path for link_path, _ in _monitor_link_paths(proj_dir))

    return links


def _check_conflicts(proj_dir):
    """
    扫描全部预期软链接路径，找出已存在且指向其他项目文件夹的链接。
    若发现冲突，列出并询问用户是否先删除；-y 模式自动删除。
    返回 False 表示用户拒绝处理冲突，主流程应退出。
    """
    proj_real = os.path.realpath(proj_dir)
    shared_images = {link: os.path.realpath(src) for link, src in _shared_image_pairs()}
    conflicts = []

    for link_path in _collect_expected_links(proj_dir):
        if not os.path.islink(link_path):
            continue
        target_real = os.path.realpath(link_path)
        # 共享镜像不属于任何项目；正确指向 http/image/ 时不是项目冲突。
        if shared_images.get(link_path) == target_real:
            continue
        # 如果链接目标在 proj_dir 下（或本身就是 proj_dir），不算冲突
        if target_real == proj_real or target_real.startswith(proj_real + os.sep):
            continue
        # 链接目标与当前项目无关 → 冲突
        conflicts.append((link_path, os.readlink(link_path), target_real))

    if not conflicts:
        return True

    print(_c(YELLOW, f"\n发现 {len(conflicts)} 个链接指向其他项目："))
    for link_path, cur_target, _ in conflicts:
        print(f"  {os.path.relpath(link_path, HTTP_BASE)}")
        print(f"      → {cur_target}")

    if _DRY_RUN or _AUTO_YES:
        if not _DRY_RUN:
            print(_c(YELLOW, "自动删除（-y 模式）…"))
        do_delete = True
    else:
        if not sys.stdin.isatty():
            print(_c(RED, "非交互终端不删除冲突链接；请使用 -y 明确确认"))
            return False
        try:
            ans = input("\n是否先删除这些链接再为当前项目创建新链接？[Y/n] ").strip().lower()
        except EOFError:
            print(_c(RED, "未获得确认，已取消"))
            return False
        do_delete = ans not in ("n", "no")

    if not do_delete:
        print(_c(RED, "已取消，请手动处理冲突链接后重新运行 setup.py"))
        return False

    for link_path, _, _ in conflicts:
        if not _DRY_RUN:
            os.remove(link_path)
        print(_c(CYAN if _DRY_RUN else GREEN,
                 f"  {'[DRY] 删除' if _DRY_RUN else '[DEL]'} {os.path.relpath(link_path, HTTP_BASE)}"))
    return True


# 项目下需要预先创建的输出目录（99- 前缀，用户一般不会手动建）
OUTPUT_DIRS = [
    "99-output-eth",
    "99-output-ib_nvl",
    "99-output-dhcp",
    "99-output-backup",
    "99-output-p2p",
    "99-output-monitor",
    "99-output-ztp",
]


class _SetupLinkTransaction:
    """Snapshot every managed link and restore the whole set on failure."""

    def __init__(self, paths):
        self.states = {}
        for path in sorted(set(map(os.path.abspath, paths))):
            if os.path.islink(path):
                self.states[path] = ("link", os.readlink(path))
            elif os.path.lexists(path):
                self.states[path] = ("other", None)
            else:
                self.states[path] = ("missing", None)
        if os.path.isfile(MANIFEST_FILE):
            with open(MANIFEST_FILE, "rb") as stream:
                self.manifest = stream.read()
        else:
            self.manifest = None
        self.active = True

    @staticmethod
    def _restore_link(path, target):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        temporary = os.path.join(
            os.path.dirname(path), f".{os.path.basename(path)}.rollback.{os.getpid()}"
        )
        try:
            if os.path.lexists(temporary):
                os.remove(temporary)
            os.symlink(target, temporary)
            os.replace(temporary, path)
        finally:
            if os.path.lexists(temporary):
                os.remove(temporary)

    def rollback(self):
        if not self.active or _DRY_RUN:
            return
        print(_c(YELLOW, "\n── setup 失败，回滚全部链接切换 ────────────────────────────────"))
        failures = []
        for path, (kind, target) in self.states.items():
            try:
                if kind == "link":
                    if os.path.lexists(path) and not os.path.islink(path):
                        failures.append(f"{path} 已变成实际文件/目录")
                        continue
                    self._restore_link(path, target)
                elif kind == "missing" and os.path.islink(path):
                    os.remove(path)
                # Existing real files/directories are never setup mutations.
            except OSError as exc:
                failures.append(f"{path}: {exc}")
        try:
            if self.manifest is None:
                if os.path.isfile(MANIFEST_FILE):
                    os.remove(MANIFEST_FILE)
            else:
                os.makedirs(os.path.dirname(MANIFEST_FILE), exist_ok=True)
                temporary = MANIFEST_FILE + f".rollback.{os.getpid()}"
                with open(temporary, "wb") as stream:
                    stream.write(self.manifest)
                os.replace(temporary, MANIFEST_FILE)
        except OSError as exc:
            failures.append(f"{MANIFEST_FILE}: {exc}")
        self.active = False
        if failures:
            print(_c(RED, "  [ERROR] 回滚不完整：" + "；".join(failures)))
        else:
            print(_c(GREEN, "  [ROLLBACK] 已恢复 setup 前的全部链接和 manifest"))

    def commit(self):
        self.active = False


def _setup_transaction_paths(proj_dir):
    paths = set(_managed_ztp_link_candidates())
    paths.update(_collect_expected_links(proj_dir))
    paths.add(os.path.join(proj_dir, "p2p.xlsx"))
    return paths


# ── 主流程 ────────────────────────────────────────────────────────────────────

def _setup_impl(proj_dir):
    global _LINK_ERRORS, _P2P_SOURCE, _LINK_TRANSACTION
    _LINK_ERRORS = 0
    print(f"\n项目目录：{proj_dir}")
    print(f"ZTP 目录：{ZTP}\n")

    _initialize_project_from_template(proj_dir)
    _P2P_SOURCE = _select_p2p_source(proj_dir)
    if not _P2P_SOURCE:
        sys.exit(1)
    if not _validate_project(proj_dir):
        sys.exit(1)
    print()

    _LINK_TRANSACTION = _SetupLinkTransaction(_setup_transaction_paths(proj_dir))
    canonical_p2p = _ensure_project_p2p_link(proj_dir, _P2P_SOURCE)
    if not canonical_p2p:
        sys.exit(1)
    _unsetup_previous(proj_dir)

    if not _check_conflicts(proj_dir):
        sys.exit(1)

    print("── 创建输出目录 ──────────────────────────────────────────────────")
    for d in OUTPUT_DIRS:
        path = os.path.join(proj_dir, d)
        if os.path.exists(path):
            print(f"  [OK]    {d}/")
        elif _DRY_RUN:
            print(_c(CYAN, f"  [DRY] mkdir {d}/"))
        else:
            os.makedirs(path, exist_ok=True)
            print(_c(GREEN, f"  [MKDIR] {d}/"))

    linked = skipped = missing = errors = 0

    print("\n── 固定映射 ──────────────────────────────────────────────────────")
    _remove_legacy_nvos_output_links()
    if _CSV_DIR:
        print(_c(CYAN, f"  CSV 目录：{_CSV_DIR}"))
    for ztp_rel, proj_rel, kind in MAPPINGS:
        result = _process_mapping(proj_dir, ztp_rel, proj_rel, kind, src_base=_CSV_DIR)
        if result == "linked":   linked  += 1
        elif result == "skipped":skipped += 1
        elif result == "missing":missing += 1
        elif result == "error":  pass  # 由 _make_link 统一计数，避免动态链接漏报

    print("\n── Infra 部署输入 ─────────────────────────────────────────────────")
    for workspace_rel, proj_rel, kind in WORKSPACE_INPUT_MAPPINGS:
        result = _process_mapping(
            proj_dir, workspace_rel, proj_rel, kind,
            src_base=_CSV_DIR, link_root=HTTP_BASE,
        )
        if result == "linked":   linked += 1
        elif result == "skipped": skipped += 1
        elif result == "missing": missing += 1

    print("\n── 共享镜像文件（http/image）────────────────────────────────────")
    _process_bin_files()

    print("\n── P2P 文件（AIR / LLDPq / CVT 共用）────────────────────────────")
    # Every consumer sees the stable project-level name.  If the project keeps
    # versioned workbooks under p2p/, this link resolves to the selected latest
    # source while downstream scripts remain independent of customer filenames.
    _process_xlsx_files(proj_dir, canonical_p2p)

    print("\n── InfiniBand bringup 输出链接 ──────────────────────────────────")
    _process_bringup_links(proj_dir)

    print("\n── P2P 拓扑分析输入和报告链接 ──────────────────────────────────")
    _process_analyzer_links(proj_dir)

    print("\n── 公钥文件 ─────────────────────────────────────────────────────")
    _process_pubkeys(proj_dir)

    print("\n── 最新发布链接（latest_yaml / optimize）────────────────────────")
    _process_latest_yaml(proj_dir)

    print("\n── Optimize 配置比较样例链接 ───────────────────────────────────")
    _process_optimize_sample(proj_dir)

    print("\n── 网络类型 CSV 链接（ethernet / infiniband / nvlink）────────────")
    _process_net_csv_links(proj_dir)

    print("\n── 监控输出链接（采集目录 / 日志 / 汇总页面）────────────────────")
    _process_monitor_links(proj_dir)

    errors = _LINK_ERRORS
    print(f"\n完成：固定映射创建 {linked} 个、跳过 {skipped} 个、"
          f"缺失 {missing} 个、错误 {errors} 个；动态文件和监控链接已逐项处理")
    if missing:
        print(_c(YELLOW, "提示：缺失的可选文件可后续补充后重新运行 setup.py"))
    if errors:
        print(_c(RED, "提示：有错误项需手动处理"))

    if not _DRY_RUN and not errors:
        _write_manifest(proj_dir)
        _print_next_steps(proj_dir)
        _LINK_TRANSACTION.commit()
        _LINK_TRANSACTION = None
    elif errors:
        print(_c(RED, "setup 未完成：未写入成功清单，请处理错误后重试"))
        sys.exit(1)
    else:
        # dry-run never mutates links, so no rollback/commit work is required.
        _LINK_TRANSACTION = None


def setup(proj_dir):
    """Run setup as one link transaction; any failure restores prior state."""
    global _LINK_TRANSACTION
    try:
        return _setup_impl(proj_dir)
    except BaseException:
        if _LINK_TRANSACTION is not None:
            _LINK_TRANSACTION.rollback()
            _LINK_TRANSACTION = None
        raise


def _write_manifest(proj_dir):
    """只记录本项目实际创建成功的链接，避免清单与文件系统状态不一致。"""
    expected = sorted(set(_collect_expected_links(proj_dir)))
    links = [lp for lp in expected if os.path.islink(lp)]
    manifest_dir = os.path.dirname(MANIFEST_FILE)
    os.makedirs(manifest_dir, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=".setup_manifest.", dir=manifest_dir, text=True
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as f:
            f.write(f"# setup manifest — proj: {proj_dir}\n")
            for lp in links:
                f.write(lp + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, MANIFEST_FILE)
        print(_c(CYAN, f"  [MANIFEST] 已写入 {MANIFEST_FILE}（{len(links)} 条实际链接）"))
    except BaseException:
        if os.path.lexists(temporary):
            os.remove(temporary)
        raise


# 文件名关键字 → 说明（用于 size-0 文件提示）
_FILE_HINTS = [
    ("id_rsa",   ".pub", "SSH 公钥（将部署到交换机 authorized_keys）"),
    (".pub",     "",     "SSH 公钥文件（将部署到交换机 authorized_keys）"),
    (".xlsx",    "",     "P2P 拓扑 Excel 文件（AIR、LLDPq、CVT 共用）"),
]


def _file_hint(fname):
    """根据文件名返回操作提示。"""
    fl = fname.lower()
    for key, ext, hint in _FILE_HINTS:
        if key.startswith("."):
            if fl.endswith(key):
                return hint
        else:
            if key in fl and (not ext or fl.endswith(ext)):
                return hint
    return "请提供真实文件内容（当前为占位空文件）"


def _print_next_steps(proj_dir):
    """setup 完成后扫描项目目录，提示用户需要填写的文件。"""
    need_edit  = []   # 01*.yaml / 02*.csv
    need_fill  = []   # 其他 size-0 文件
    unused_empty_pubkeys = _unused_empty_pubkeys(proj_dir)

    for fname in sorted(os.listdir(proj_dir)):
        fpath = os.path.join(proj_dir, fname)
        if not os.path.isfile(fpath) or os.path.islink(fpath):
            continue
        fl = fname.lower()
        if fl == "02-air-devices_config.csv":
            # Derived and maintained by c1-generate_dhcp.py from p2p-air.json;
            # users should not be told to populate it manually.
            continue
        if (fl.startswith("01") and fl.endswith(".yaml")) or \
           (fl.startswith("02") and fl.endswith(".csv")):
            need_edit.append(fname)
        elif fl.endswith(".bin"):
            continue  # 兼容旧项目遗留文件；共享镜像只从 http/image/ 读取
        elif fl.endswith(".xlsx") and _P2P_SOURCE and \
                os.path.realpath(fpath) != os.path.realpath(_P2P_SOURCE):
            continue  # 非选定 XLSX 不参与当前运行时流程，不提示填写。
        elif os.path.getsize(fpath) == 0 and fpath not in unused_empty_pubkeys:
            need_fill.append(fname)

    if not need_edit and not need_fill:
        return

    print("\n── 后续操作提示 ─────────────────────────────────────────────────")

    if need_edit:
        print(_c(YELLOW, "  以下文件需要填入本项目的实际配置信息："))
        for fname in need_edit:
            print(f"    {fname}")

    if need_fill:
        print(_c(YELLOW, "  以下文件当前为空（占位），请提供真实内容："))
        for fname in need_fill:
            hint = _file_hint(fname)
            print(f"    {fname}")
            print(f"      → {hint}")

    if need_edit or need_fill:
        print(_c(CYAN, "\n  填写完成后，请再次执行 01-a-setup.py 确保所有项目文件被正确链接。"))


def _parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="校验并激活一个 DAY0 项目，创建全套运行时软链接。"
    )
    parser.add_argument("project", help="DAY0-Prepare 下的项目名或项目绝对路径")
    parser.add_argument("-y", action="store_true", dest="auto_yes",
                        help="自动确认覆盖或删除 setup 管理的旧链接")
    parser.add_argument("--force", action="store_true",
                        help="忽略输入校验错误继续（独立于 -y）")
    parser.add_argument("--strict", action="store_true",
                        help="把空公钥、XLSX 和共享镜像占位视为错误")
    parser.add_argument("--dry-run", action="store_true",
                        help="只显示操作，不创建项目、文件、目录或链接")
    parser.add_argument("--csv-dir",
                        help="从指定目录读取 devices_config.csv")
    parser.add_argument("--p2p-file",
                        help="明确选择项目根目录或 p2p/ 下的 P2P XLSX")
    return parser.parse_args(argv)


def _main_locked(args):
    global _CSV_DIR, _P2P_FILE
    if args.csv_dir:
        _CSV_DIR = os.path.realpath(args.csv_dir)
        if not os.path.isdir(_CSV_DIR):
            print(f"[ERROR] --csv-dir 目录不存在：{_CSV_DIR}")
            return 1
    _P2P_FILE = args.p2p_file

    proj = args.project
    if os.path.isabs(proj):
        proj_dir = proj
    else:
        # 去掉用户误带的 "DAY0-Prepare/" 前缀，避免二次拼接
        here_name = os.path.basename(HERE)
        if proj.startswith(here_name + os.sep) or proj.startswith(here_name + "/"):
            proj = proj[len(here_name) + 1:]
        proj_dir = os.path.join(HERE, proj)

    proj_dir = os.path.realpath(proj_dir)
    if not os.path.isdir(proj_dir):
        if _DRY_RUN:
            print(_c(CYAN, f"  [DRY] mkdir {proj_dir}"))
            print(_c(YELLOW, "  [DRY] 项目目录不存在，跳过文件校验"))
            return 0
        else:
            os.makedirs(proj_dir, exist_ok=True)
            print(_c(GREEN, f"[MKDIR] 项目目录已创建：{proj_dir}"))

    setup(proj_dir)
    return 0


def main(argv=None):
    global _AUTO_YES, _DRY_RUN, _FORCE, _STRICT

    args = _parse_args(argv)
    _DRY_RUN = args.dry_run
    _AUTO_YES = args.auto_yes
    _FORCE = args.force
    _STRICT = args.strict
    try:
        with deployment_lock(HTTP_BASE, dry_run=_DRY_RUN):
            return _main_locked(args)
    except DeploymentLockError as exc:
        print(_c(RED, f"[ERROR] 部署锁不可用：{exc}"))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
