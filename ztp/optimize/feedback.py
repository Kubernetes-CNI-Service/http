#!/usr/bin/env python3
"""
从 yaml-collect.py 采集结果反向解析，按 02-devices_config-eth.csv 格式填写。

用法：
    python3 feedback.py [INPUT]
    python3 feedback.py SOURCE1 SOURCE2 [SOURCE3] [SOURCE4] [SOURCE5]
    python3 feedback.py COMPARISON_DIRECTORY

INPUT 可以是单个 YAML、包含 YAML 的目录，或 tar/zip 打包文件。
两到五个来源会生成各自的 CSV 和带时间戳的 Markdown 分析报告。报告会
读取上一份报告，跟踪已修复、仍存在和新发现的问题。目录参数下包含两个
到五个配置来源时自动进入比较模式。
项目/sample 模式默认分别生成 Production 与 AIR 两份独立报告；使用
--type prod、--type air、--prod 或 --air 可只处理一个环境。
默认 INPUT = 当前目录下最新的 *-backup/ 子目录。
"""

import argparse
import base64
import copy
import csv
from datetime import datetime
import glob
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile
import tempfile
import zipfile
import yaml

SCRIPT_IMPORT_DIR = str(Path(__file__).resolve().parent)
if SCRIPT_IMPORT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_IMPORT_DIR)
HTTP_ROOT_IMPORT_DIR = str(Path(__file__).resolve().parents[2])
if HTTP_ROOT_IMPORT_DIR not in sys.path:
    sys.path.insert(0, HTTP_ROOT_IMPORT_DIR)
from sample_links import (
    LINK_NAMES,
    is_air_comparison_source,
    project_from_sample_path,
    update_sample_links,
)
from ztp.nvue_normalizer import (
    deep_merge_nvue as _deep_merge,
    expand_nvue_selector as _expand_nvue_selector,
    normalize_nvue_selectors,
)
from tools.project_contract import (
    DEVICE_BASE_COLUMNS,
    DEVICE_FIXED_COLUMNS,
    DEVICE_SOURCE_METADATA_COLUMNS,
    DEVICE_V2_OPTIONAL_POLICY_COLUMNS,
    DEVICE_V2_EVPN_COLUMNS,
    DEVICE_V2_VLAN_COLUMNS,
    detect_global_schema_version,
    normalize_v2_mlag_policy,
    parse_device_csv_layout,
    safe_load_yaml_preserving_mac,
)

NA = "NA"
EVPN_COLS = 12            # 内部 EVPN group 含 dhcp_server，共 12 列
FIXED_COLS = 26           # hostname…peerlink_ports + vrl 共 26 列
SOURCE_YAML_COL = "source_yaml_b64"
SOURCE_SHA256_COL = "source_yaml_sha256"
SOURCE_FIELDS_SHA256_COL = "source_fields_sha256"
METADATA_COLS = (SOURCE_YAML_COL, SOURCE_SHA256_COL, SOURCE_FIELDS_SHA256_COL)
assert METADATA_COLS == DEVICE_SOURCE_METADATA_COLUMNS
SOURCE_YAML_GZIP_PREFIX = "gzip+base64:"
# Excel 单元格最多容纳 32767 个字符；保留少量余量，避免不同导入器在边界处拆列。
MAX_SPREADSHEET_CELL_CHARS = 32_000
YAML_DEVICE_TYPES = {"eth", "spx", "eth_spx", "air"}
MAX_ARCHIVE_FILES = 20_000
MAX_ARCHIVE_BYTES = 4 * 1024 * 1024 * 1024

# CSV_HEADER 和 MAX_EVPN_GROUPS 在 main() 中从格式文件动态读取

# ── 工具函数 ──────────────────────────────────────────────────────────────────

def load_yaml(path):
    """加载 NVUE startup.yaml，返回 set 段的 dict。"""
    with open(path) as f:
        doc = safe_load_yaml_preserving_mac(f)   # 文件是 YAML list，不是多文档
    if isinstance(doc, list):
        for item in doc:
            if isinstance(item, dict) and "set" in item:
                return normalize_nvue_selectors(item["set"])
    return {}


def _has_vrf_route_leaking(cfg):
    """Return true when any VRF has an IPv4 from-vrf route-import."""
    for vrf in (cfg.get("vrf") or {}).values():
        route_import = (
            (((vrf or {}).get("router") or {}).get("bgp") or {})
            .get("address-family", {}).get("ipv4-unicast", {})
            .get("route-import")
        )
        if isinstance(route_import, dict) and route_import.get("from-vrf"):
            return True
    return False


def encode_source_yaml(source_bytes, hostname):
    """以可被表格软件安全承载的压缩 Base64 保存原始 YAML。"""
    compressed = gzip.compress(source_bytes, compresslevel=9, mtime=0)
    encoded = SOURCE_YAML_GZIP_PREFIX + base64.b64encode(compressed).decode("ascii")
    if len(encoded) > MAX_SPREADSHEET_CELL_CHARS:
        _conversion_error(
            f"{hostname}: 压缩后的 {SOURCE_YAML_COL} 仍有 {len(encoded)} 个字符，"
            f"超过表格兼容上限 {MAX_SPREADSHEET_CELL_CHARS}；"
            "请缩小单台设备 YAML，避免生成会被表格软件拆列的 CSV"
        )
    return encoded


def _safe_archive_path(name):
    """校验归档成员路径，拒绝绝对路径、反斜线和 ``..`` 穿越。"""
    if not name or "\\" in name:
        raise ValueError(f"归档成员路径无效: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"归档成员越界: {name!r}")
    parts = tuple(part for part in path.parts if part not in ("", "."))
    if not parts:
        return None
    return Path(*parts)


def _check_archive_limits(file_count, total_bytes):
    if file_count > MAX_ARCHIVE_FILES:
        raise ValueError(f"归档文件过多（>{MAX_ARCHIVE_FILES}）")
    if total_bytes > MAX_ARCHIVE_BYTES:
        raise ValueError(f"归档解压后过大（>{MAX_ARCHIVE_BYTES} bytes）")


def extract_archive(archive_path, destination):
    """安全解包 tar/zip，仅接受普通文件和目录，返回解包根目录。"""
    archive_path = Path(archive_path)
    destination = Path(destination)
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise ValueError(f"解包目标不是安全的实际目录: {destination}")
    destination.mkdir(parents=True, exist_ok=True)

    if tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path, "r:*") as archive:
            members = archive.getmembers()
            _check_archive_limits(
                len(members),
                sum(member.size for member in members if member.isfile()),
            )
            for member in members:
                relative = _safe_archive_path(member.name)
                if relative is None:
                    continue
                target = destination / relative
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise ValueError(f"归档包含不支持的链接或特殊文件: {member.name}")
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError(f"无法读取归档成员: {member.name}")
                with source, target.open("wb") as output:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        output.write(chunk)
        return destination

    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            _check_archive_limits(
                len(members),
                sum(member.file_size for member in members if not member.is_dir()),
            )
            for member in members:
                relative = _safe_archive_path(member.filename)
                if relative is None:
                    continue
                target = destination / relative
                mode = (member.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise ValueError(f"归档包含不支持的软链接: {member.filename}")
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source, target.open("wb") as output:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        output.write(chunk)
        return destination

    raise ValueError(f"不支持的打包文件（支持 tar/tar.gz/tgz/tar.xz/zip）: {archive_path}")


def extract_info_command(path, command):
    """从 sw-info.sh 的 ``.info`` 中读取一个命令的原始输出文本。"""
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    marker = f"# Execute Command: {command}"
    try:
        index = next(i for i, line in enumerate(lines) if line.strip() == marker)
    except StopIteration:
        return None
    index += 1
    while index < len(lines) and (
        not lines[index].strip() or set(lines[index].strip()) == {"#"}
    ):
        index += 1
    collected = []
    while index < len(lines):
        line = lines[index]
        if line.strip() and set(line.strip()) == {"#"}:
            break
        collected.append(line)
        index += 1
    return "\n".join(collected).rstrip() + "\n"


def extract_yaml_from_info(path):
    """从 sw-info.sh 的 ``.info`` 中提取 ``nv config show`` YAML。"""
    text = extract_info_command(path, "nv config show")
    if text is None:
        return None
    payload = text.encode("utf-8")
    try:
        document = safe_load_yaml_preserving_mac(payload)
    except yaml.YAMLError as exc:
        raise ValueError(f"{path}: nv config show YAML 无效: {exc}") from exc
    if not isinstance(document, list) or not any(
        isinstance(item, dict) and isinstance(item.get("set"), dict)
        for item in document
    ):
        raise ValueError(f"{path}: nv config show 中没有有效 set 段")
    return payload


def extract_info_metadata(path):
    """提取 .info 中不属于 startup YAML、但可可靠识别的 eth0 信息。"""
    metadata = {}
    platform = extract_info_command(path, "nv show platform") or ""
    match = re.search(
        r"(?mi)^serial-number\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s*$",
        platform,
    )
    if match:
        metadata["eth0_mac"] = match.group(1).lower()

    interfaces = extract_info_command(path, "nv show interface") or ""
    lines = interfaces.splitlines()
    for index, line in enumerate(lines):
        if not re.match(r"^eth0\s", line):
            continue
        block = [line]
        for following in lines[index + 1:]:
            if following and not following[0].isspace():
                break
            block.append(following)
        match = re.search(
            r"IPv4 Address:\s*((?:\d{1,3}\.){3}\d{1,3}/\d{1,2})",
            "\n".join(block),
        )
        if match:
            ip, netmask = split_cidr(match.group(1))
            metadata["eth0_ip"] = ip
            metadata["netmask"] = netmask
        break
    return metadata


def discover_info_metadata(root, single_info=None):
    if single_info is not None:
        candidates = [Path(single_info)]
    else:
        candidates = sorted(
            path for path in Path(root).rglob("*.info")
            if path.is_file() and not path.is_symlink()
        )
    return {path.stem: extract_info_metadata(path) for path in candidates}


def discover_yaml_files(
        root, single_yaml=None, single_info=None, info_output_dir=None,
        allowed_hostnames=None, hostname_aliases=None):
    """递归发现 YAML 或 .info 内嵌 YAML，并按 hostname 去重。

    ``allowed_hostnames`` 用于比较模式的权威 inventory 边界。
    ``hostname_aliases`` 是可选的 ``源 YAML stem -> inventory hostname``
    映射，供显式数据迁移使用；正常 AIR/Production 流程使用各自真实文件名。
    """
    allowed_hostnames = (set(allowed_hostnames)
                         if allowed_hostnames is not None else None)
    hostname_aliases = dict(hostname_aliases or {})
    if hostname_aliases:
        allowed_hostnames = set(hostname_aliases)
    if single_yaml is not None:
        candidates = [Path(single_yaml)]
        if (allowed_hostnames is not None
                and candidates[0].stem not in allowed_hostnames):
            candidates = []
    else:
        root = Path(root)
        candidates = [
            path for path in root.rglob("*")
            if path.is_file() and not path.is_symlink()
            and path.suffix.casefold() in {".yaml", ".yml"}
            and (allowed_hostnames is None or path.stem in allowed_hostnames)
        ]

    def priority(path):
        folded = [part.casefold() for part in path.parts]
        in_eth = "eth" in folded
        output_hostname = hostname_aliases.get(path.stem, path.stem)
        alias_penalty = 0 if path.stem == output_hostname else 1
        return (alias_penalty, 0 if in_eth else 1,
                len(path.parts), str(path).casefold())

    selected = {}
    for path in sorted(candidates, key=priority):
        hostname = hostname_aliases.get(path.stem, path.stem)
        previous = selected.get(hostname)
        if previous is not None and previous.read_bytes() != path.read_bytes():
            print(f"[WARN] 重复 YAML hostname={hostname}，保留 {previous}，跳过 {path}")
            continue
        selected.setdefault(hostname, path)

    if single_info is not None:
        info_candidates = [Path(single_info)]
        if (allowed_hostnames is not None
                and info_candidates[0].stem not in allowed_hostnames):
            info_candidates = []
    else:
        info_candidates = sorted(
            path for path in Path(root).rglob("*.info")
            if path.is_file() and not path.is_symlink()
            and (allowed_hostnames is None or path.stem in allowed_hostnames)
        )
    if info_candidates:
        if info_output_dir is None:
            raise ValueError("发现 .info 文件但没有提供临时 YAML 输出目录")
        info_output_dir = Path(info_output_dir)
        info_output_dir.mkdir(parents=True, exist_ok=True)
    for path in info_candidates:
        hostname = hostname_aliases.get(path.stem, path.stem)
        if hostname in selected:
            continue
        payload = extract_yaml_from_info(path)
        if payload is None:
            print(f"[WARN] {path}: 未找到 nv config show，跳过")
            continue
        output = info_output_dir / f"{hostname}.yaml"
        output.write_bytes(payload)
        selected[hostname] = output
        print(f"[INFO] {hostname}: 从 {path.name} 提取 nv config show YAML")
    return selected


def split_cidr(cidr_str):
    """'192.0.2.3/26' → ('192.0.2.3', '26')"""
    try:
        net = ipaddress.ip_interface(str(cidr_str))
        return str(net.ip), str(net.network.prefixlen)
    except Exception:
        return str(cidr_str), NA


def _consec_ranges(sorted_nums):
    """将有序整数列表归并为 [(start, end), ...] 的连续段列表。"""
    if not sorted_nums:
        return []
    ranges, start, end = [], sorted_nums[0], sorted_nums[0]
    for n in sorted_nums[1:]:
        if n == end + 1:
            end = n
        else:
            ranges.append((start, end))
            start = end = n
    ranges.append((start, end))
    return ranges


def _minor_suffix_str(minpfx, sorted_mnums):
    """将同一 minorPrefix 下的有序 minor 数字列表转为后缀字符串列表。
    e.g. s,[0,1,2,3] → ['s0-3']   s,[0,2,3] → ['s0','s2-3']"""
    parts = []
    for s, e in _consec_ranges(sorted_mnums):
        parts.append(f"{minpfx}{s}" if s == e else f"{minpfx}{s}-{e}")
    return parts


def compress_ports(names):
    """
    两级压缩：
      1) 同一 major 内压缩连续 minor（bond27s0/s2/s3 → bond27s0/bond27s2-3）
      2) 签名相同的连续 major 合并（bond1-9s0-1 代替 bond1s0-1/.../bond9s0-1）

    无 minor 的简单端口仍按连续 major 压缩（bond1-48）。
    """
    if not names:
        return NA

    simple_by_pfx = {}   # prefix → set of majors
    # (prefix, major) → {minorPfx: set of minorNums}
    suf_by_major  = {}
    compound_bonds = []  # bond49bond51: one bond with multiple members

    for n in names:
        m = re.match(r'^([a-zA-Z]+)(\d+)([a-zA-Z]+)(\d+)$', n)
        if m:
            key = (m.group(1), int(m.group(2)))
            suf_by_major.setdefault(key, {}).setdefault(m.group(3), set()).add(int(m.group(4)))
            continue
        m2 = re.match(r'^([a-zA-Z]+)(\d+)$', n)
        if m2:
            simple_by_pfx.setdefault(m2.group(1), set()).add(int(m2.group(2)))
            continue
        compound = re.fullmatch(r'(bond)(\d+)(?:bond\d+)+', n)
        if compound:
            compound_bonds.append((compound.group(1), int(compound.group(2)), n))

    tokens = list(compound_bonds)   # (pfx, sort_major, token_str)

    # ── 简单端口：连续 major 压缩 ────────────────────────────────────────
    for pfx, majors in simple_by_pfx.items():
        for s, e in _consec_ranges(sorted(majors)):
            t = f"{pfx}{s}" if s == e else f"{pfx}{s}-{e}"
            tokens.append((pfx, s, t))

    # ── 带后缀端口：两级压缩 ─────────────────────────────────────────────
    # 按 prefix 分组
    pfx_set = set(pfx for pfx, _ in suf_by_major)
    for pfx in sorted(pfx_set):
        # 该 prefix 下所有 major 及其 minor 信息
        entries = {major: mp for (p, major), mp in suf_by_major.items() if p == pfx}

        # 计算每个 major 的"签名"：frozenset{(minpfx, minnum), ...}
        def sig(mp):
            s = set()
            for mpfx, mnums in mp.items():
                for mn in mnums:
                    s.add((mpfx, mn))
            return frozenset(s)

        major_list = sorted(entries.keys())

        # 连续 major 且签名相同的归为一组
        groups = []   # [(sig, [major, ...]), ...]
        for major in major_list:
            s = sig(entries[major])
            if groups and groups[-1][0] == s and major == groups[-1][1][-1] + 1:
                groups[-1][1].append(major)
            else:
                groups.append([s, [major]])

        for gsig, gmajors in groups:
            ms, me = gmajors[0], gmajors[-1]
            major_str = f"{pfx}{ms}" if ms == me else f"{pfx}{ms}-{me}"

            # 将签名按 minorPfx 展开并排序，生成后缀列表
            mp_merged = {}
            for mpfx, mn in sorted(gsig):
                mp_merged.setdefault(mpfx, []).append(mn)

            for mpfx, mnums in sorted(mp_merged.items()):
                for suf in _minor_suffix_str(mpfx, sorted(mnums)):
                    tokens.append((pfx, ms, f"{major_str}{suf}"))

    tokens.sort(key=lambda x: (x[0], x[1]))
    return "/".join(t[2] for t in tokens)


def expand_port_token(token):
    """将单个压缩端口名展开为原始名列表。

      bond1-9s0-1  → [bond1s0, bond1s1, bond2s0, ..., bond9s1]
      bond1-48     → [bond1, bond2, ..., bond48]
      bond27s0     → [bond27s0]
      bond27s2-3   → [bond27s2, bond27s3]
    """
    # 带 minor：prefixMAJOR[-MAJOR2]minorPfxMINOR[-MINOR2]
    m = re.match(r'^([a-zA-Z]+)(\d+)(?:-(\d+))?([a-zA-Z]+)(\d+)(?:-(\d+))?$', token)
    if m:
        pfx    = m.group(1)
        maj_s  = int(m.group(2));  maj_e  = int(m.group(3)) if m.group(3) else maj_s
        minpfx = m.group(4)
        min_s  = int(m.group(5));  min_e  = int(m.group(6)) if m.group(6) else min_s
        return [f"{pfx}{maj}{minpfx}{mn}"
                for maj in range(maj_s, maj_e + 1)
                for mn  in range(min_s, min_e + 1)]
    # 无 minor：prefixMAJOR[-MAJOR2]
    m2 = re.match(r'^([a-zA-Z]+)(\d+)(?:-(\d+))?$', token)
    if m2:
        pfx = m2.group(1)
        maj_s = int(m2.group(2));  maj_e = int(m2.group(3)) if m2.group(3) else maj_s
        return [f"{pfx}{maj}" for maj in range(maj_s, maj_e + 1)]
    return [token]   # 无法解析则原样返回


def compress_port_string(s):
    """将已压缩的端口字符串进一步合并简化。

      'bond1s0-1/bond2s0-1/.../bond9s0-1'  →  'bond1-9s0-1'
      'bond9/bond15-18'                     →  'bond9/bond15-18'（已是最简）

    适用于外部字符串输入（而非端口名列表）。
    """
    if not s or s == NA:
        return s
    expanded = []
    for tok in s.split('/'):
        tok = tok.strip()
        if tok:
            expanded.extend(expand_port_token(tok))
    return compress_ports(expanded)


def _port_num(name):
    m = re.search(r'\d+', name)
    return int(m.group()) if m else 0


def member_to_bond_name(member):
    """
    将 swp member 名转为 bond 输出名：
      swp1   → bond1
      swp3s0 → bond3s0
    """
    suffix = re.sub(r'^swp', '', member)
    return f"bond{suffix}"


def bond_output_name(bond_cfg):
    """
    用 bond 的全部 member 派生输出名；没有 member 则返回 None。

    NVUE 会把 ``swp49,51`` 或 ``swp49-50`` 规范化成多个 member key。
    CSV 使用连续 bond 名表达“同一个 bond 的多个成员”，例如：
      swp49 + swp51 -> bond49bond51
      swp49 + swp50 -> bond49bond50
    """
    members = list(bond_cfg.get("bond", {}).get("member", {}).keys())
    if not members:
        return None
    return "".join(member_to_bond_name(member) for member in members)


def bond_vlan_set(bond_cfg):
    """返回该 bond 所属的所有 VLAN ID 集合（int）。
    同时考虑：
      - bridge.domain.br_default.access（access port，单 VLAN）
      - bridge.domain.br_default.untagged
      - bridge.domain.br_default.vlan 的 key（可能是 '1101,1121' 这种逗号分隔字符串）
    """
    br = bond_cfg.get("bridge", {}).get("domain", {}).get("br_default", {})
    vlans = set()
    access = br.get("access")
    if access is not None:
        try:
            vlans.add(int(access))
        except (ValueError, TypeError):
            pass
    untagged = br.get("untagged")
    if untagged is not None:
        vlans.add(int(untagged))
    for key in (br.get("vlan") or {}).keys():
        for part in str(key).split(","):
            part = part.strip()
            if part.isdigit():
                vlans.add(int(part))
    return vlans


def dhcp_relay_info(cfg, vrf_name, vlan_id=None):
    """返回指定 VRF/VLAN 的 ``(enabled, server-group-name)``。"""
    relay = (cfg.get("service", {}).get("dhcp-relay", {}).get(vrf_name) or {})
    if not relay:
        return "FALSE", NA
    if vlan_id is not None:
        downstream = relay.get("downstream-interface") or {}
        vlan = downstream.get(f"vlan{vlan_id}") or {}
        group = vlan.get("server-group-name")
        return ("TRUE", str(group)) if group else ("FALSE", NA)
    groups = list((relay.get("server-group") or {}).keys())
    return "TRUE", str(groups[0]) if groups else NA


def svi_vrr_info(svi_cfg, cfg, vlan_id):
    """
    从 SVI 接口配置中提取 svi_ip、vrr_ip、vrr_mac。

    优先级：
      svi_ip  = ipv4.address（设备自身 IP）
      vrr_ip  = ipv4.vrr.address（若有 vrr 字段）；否则 NA
      vrr_mac = ipv4.vrr.mac-address（若有）；否则读取 SVI link.mac-address，
                再兼容 ifupdown2_eni snippet 的 hwaddress

    例：
      vlan106:
        ipv4:
          address:
            192.0.2.251/25: {}
          vrr:
            address:
              192.0.2.254/25: {}
            mac-address: 00:00:5e:00:01:06
    """
    ip4 = svi_cfg.get("ipv4", {})

    # svi_ip
    svi_addrs = list(ip4.get("address", {}).keys())
    svi_ip, svi_nm = split_cidr(svi_addrs[0]) if svi_addrs else (NA, NA)

    # vrr_ip
    vrr_cfg = ip4.get("vrr", {})
    vrr_addrs = list(vrr_cfg.get("address", {}).keys())
    vrr_ip, _ = split_cidr(vrr_addrs[0]) if vrr_addrs else (NA, NA)

    # vrr_mac：依次兼容普通 VRR、Cumulus 5.18+ SVI link MAC 和旧版 snippet。
    vrr_mac = vrr_cfg.get("mac-address", NA)
    if not vrr_mac or vrr_mac == NA:
        vrr_mac = (svi_cfg.get("link") or {}).get("mac-address", NA)
    if not vrr_mac or vrr_mac == NA:
        snippet = (cfg.get("system", {})
                      .get("config", {})
                      .get("snippet", {})
                      .get("ifupdown2_eni", {}))
        raw = snippet.get(f"vlan{vlan_id}", "")
        m = re.search(r'([0-9a-fA-F:]{17})', str(raw))
        vrr_mac = m.group(1) if m else NA

    return svi_ip, svi_nm, vrr_ip, vrr_mac


def vlan_to_l2vni(cfg, vlan_id):
    """从任意 bridge domain 的 VLAN 定义读取 L2 VNI。"""
    for domain in (cfg.get("bridge", {}).get("domain", {}) or {}).values():
        vlans = (domain or {}).get("vlan", {})
        vni_dict = vlans.get(str(vlan_id), vlans.get(int(vlan_id), {}))
        vni_keys = [k for k in (vni_dict or {}).get("vni", {}).keys() if k is not None]
        if vni_keys:
            return str(vni_keys[0])
    return NA


def compress_numeric_ids(values):
    """Compress integer selectors as ``11-20/100-200`` without project rules."""
    parts = []
    for start, end in _consec_ranges(sorted(set(values))):
        parts.append(str(start) if start == end else f"{start}-{end}")
    return "/".join(parts) if parts else NA


# ── 核心解析 ──────────────────────────────────────────────────────────────────

def _simple_cols(cfg, ifaces, non_default_vrfs):
    """Return [vlan_id, svi_ip, netmask, vrr_ip, vrr_mac, vlan_ports] for col13-18.

    Populated only when the device has NO non-default VRFs (OOBofOOB-Leaf style):
    - vlan_id: first vlan key in bridge.domain.br_default.vlan
    - svi_ip/nm/vrr_ip/vrr_mac: from vlan{id} interface in default VRF
    - vlan_ports: swp interfaces with bridge.domain.br_default.access == vlan_id
    All other cases return 6 NA values.
    """
    if non_default_vrfs:
        return [NA, NA, NA, NA, NA, NA]

    br_vlans = (cfg.get("bridge", {})
                   .get("domain", {})
                   .get("br_default", {})
                   .get("vlan", {}))
    if not br_vlans:
        return [NA, NA, NA, NA, NA, NA]

    # Use the first (and usually only) VLAN
    vlan_id_str = str(next(iter(br_vlans)))
    if not vlan_id_str.isdigit():
        return [NA, NA, NA, NA, NA, NA]
    vlan_id = int(vlan_id_str)

    # SVI info
    svi_key = f"vlan{vlan_id}"
    svi_cfg = ifaces.get(svi_key, {})
    svi_ip, svi_nm, vrr_ip, vrr_mac = svi_vrr_info(svi_cfg, cfg, vlan_id) if svi_cfg else (NA, NA, NA, NA)

    # vlan_ports: swp interfaces with bridge.domain.br_default.access == vlan_id
    vp_swps = []
    for iname, ival in ifaces.items():
        if not iname.startswith("swp"):
            continue
        br = ival.get("bridge", {}).get("domain", {}).get("br_default", {})
        if br.get("access") == vlan_id or br.get("access") == str(vlan_id):
            vp_swps.append(iname)
    vlan_ports_str = compress_ports(vp_swps) if vp_swps else NA

    return [str(vlan_id), svi_ip, svi_nm, vrr_ip, vrr_mac, vlan_ports_str]


def parse_device(cfg, hostname, type_, eth_info):
    """
    从 NVUE cfg dict + 基础信息，返回 CSV 行 dict。
    eth_info: {template, eth0_ip, netmask, eth0_gw, eth0_mac,
               eth1_ip, eth1_nm, eth1_gw, eth1_mac}
    """
    configured_hostname = str(
        (cfg.get("system") or {}).get("hostname") or hostname
    ).strip()
    hostname = configured_hostname or hostname
    ifaces = cfg.get("interface", {})

    # ── eth0 / eth1：从 YAML 读取 IP 和 gateway，与 CSV 比对（如有）──
    eth0_cfg = ifaces.get("eth0", {})
    eth0_ipv4 = eth0_cfg.get("ipv4") or {}
    eth0_dhcp = (eth0_ipv4.get("dhcp-client") or {}).get("state") == "enabled"
    eth0_addrs = list(eth0_ipv4.get("address", {}).keys())
    eth0_gw_keys = list(eth0_ipv4.get("gateway", {}).keys())
    if eth0_dhcp:
        eth0_ip_yaml, eth0_nm_yaml = "dhcp-client", NA
        eth0_gw_yaml = NA
    else:
        eth0_ip_yaml, eth0_nm_yaml = split_cidr(eth0_addrs[0]) if eth0_addrs else (NA, NA)
        eth0_gw_yaml = eth0_gw_keys[0] if eth0_gw_keys else NA

    eth1_cfg = ifaces.get("eth1", {})
    eth1_addrs = list((eth1_cfg.get("ipv4") or {}).get("address", {}).keys())
    eth1_gw_keys = list((eth1_cfg.get("ipv4") or {}).get("gateway", {}).keys())
    eth1_ip_yaml, eth1_nm_yaml = split_cidr(eth1_addrs[0]) if eth1_addrs else (NA, NA)
    eth1_gw_yaml = eth1_gw_keys[0] if eth1_gw_keys else NA

    def _merge_eth(field, yaml_val, csv_val):
        """Prefer configured YAML state; inventory is only a missing-value fallback.

        Comparison output must describe the configuration being compared.  Using
        an inventory address over a configured DHCP client or a different static
        address hid real production/generated drift in the report.
        """
        if yaml_val == NA or not yaml_val:
            return csv_val
        if csv_val == NA or not csv_val:
            return yaml_val
        if yaml_val != csv_val:
            print(f"  [WARN] {hostname}: {field} 不一致 — YAML={yaml_val!r} CSV={csv_val!r}，以 YAML 为准")
        return yaml_val

    eth0_ip  = _merge_eth("eth0_ip",  eth0_ip_yaml,  eth_info.get("eth0_ip",  NA))
    eth0_nm  = _merge_eth("eth0_nm",  eth0_nm_yaml,  eth_info.get("netmask",  NA))
    eth0_gw  = _merge_eth("eth0_gw",  eth0_gw_yaml,  eth_info.get("eth0_gw",  NA))
    eth1_ip  = _merge_eth("eth1_ip",  eth1_ip_yaml,  eth_info.get("eth1_ip",  NA))
    eth1_nm  = _merge_eth("eth1_nm",  eth1_nm_yaml,  eth_info.get("eth1_nm",  NA))
    eth1_gw  = _merge_eth("eth1_gw",  eth1_gw_yaml,  eth_info.get("eth1_gw",  NA))
    if eth0_dhcp:
        # A DHCP lease observed in .info is operational state, not a static
        # netmask/gateway configuration.  Keep the CSV round-trip declarative.
        eth0_ip, eth0_nm, eth0_gw = "dhcp-client", NA, NA
    eth0_mac = eth_info.get("eth0_mac", NA)  # MAC 只能来自 CSV
    eth1_mac = eth_info.get("eth1_mac", NA)

    # ── lo ──
    lo_cfg = ifaces.get("lo", {})
    lo_addrs = list(lo_cfg.get("ipv4", {}).get("address", {}).keys())
    lo_ip = lo_addrs[0] if lo_addrs else NA   # 保留 /32

    # ── bonds ──：按 NVUE 结构识别，不依赖 bondN/agg/uplink 等命名习惯。
    bonds = {
        k: v for k, v in ifaces.items()
        if isinstance(v, dict) and isinstance(v.get("bond"), dict)
           and v.get("type") != "peerlink"
    }

    # Preserve mixed bond profiles with aligned ``|`` groups.  A device can
    # legitimately contain local bonds and only a small EVPN-MH subset; the old
    # device-wide bond_type silently promoted every bond to the strongest type.
    bond_profiles = {}
    for bond_cfg in bonds.values():
        output_name = bond_output_name(bond_cfg)
        if not output_name:
            continue
        segment = ((bond_cfg.get("evpn") or {}).get("multihoming") or {}).get("segment") or {}
        if segment:
            profile_type = "evpn_multihoming"
            profile_mac = str(segment.get("mac-address", NA))
        elif (bond_cfg.get("bond") or {}).get("mlag"):
            profile_type = "mlagbond"
            profile_mac = NA
        else:
            profile_type = "localbond"
            profile_mac = NA
        bond_profiles.setdefault((profile_type, profile_mac), []).append(output_name)

    profile_priority = {"localbond": 0, "mlagbond": 1, "evpn_multihoming": 2}
    ordered_profiles = sorted(
        bond_profiles.items(),
        key=lambda item: (
            profile_priority.get(item[0][0], 99),
            _port_num(sorted(item[1], key=_port_num)[0]),
            item[0][1],
        ),
    )
    if ordered_profiles:
        bond_ports = "|".join(
            compress_ports(sorted(names, key=_port_num))
            for _, names in ordered_profiles
        )
        bond_type = "|".join(profile[0] for profile, _ in ordered_profiles)
        bond_mac = "|".join(profile[1] for profile, _ in ordered_profiles)
    else:
        bond_ports = bond_type = bond_mac = NA

    # bondN_iface → out_name 映射，供 vlan_ports 使用
    bond_iface_to_out = {}
    for bname, bval in bonds.items():
        out = bond_output_name(bval)
        if out:
            bond_iface_to_out[bname] = out

    # ── peerlink ──
    peerlink_ports = NA
    peerlink_ifaces = [k for k in ifaces if "peerlink" in k.lower()]
    if peerlink_ifaces:
        members = []
        for pl in peerlink_ifaces:
            members.extend(ifaces[pl].get("bond", {}).get("member", {}).keys())
        peerlink_ports = compress_ports(members) if members else NA

    # ── BGP ──
    bgp_default = cfg.get("vrf", {}).get("default", {}).get("router", {}).get("bgp", {})
    _asn = bgp_default.get("autonomous-system")
    bgp_asn = str(_asn) if _asn is not None else NA

    # BGP 直连 swp 邻居（evpn_multihoming uplink 或直接 swp）
    raw_neighbors = list((bgp_default.get("neighbor") or {}).keys())
    # 过滤掉 bond 和非接口 neighbors
    bgp_swp = [n for n in raw_neighbors if re.match(r'^swp', n)]
    bgp_ports = compress_ports(bgp_swp) if bgp_swp else NA

    # ── VRFs & EVPN groups ──
    vrf_cfg = cfg.get("vrf", {})
    non_default_vrfs = {k: v for k, v in vrf_cfg.items() if k not in ("default", "mgmt")}

    # 每个 VLAN（L2VNI）独占一个 EVPN group slot，同 VRF 的多个 VLAN 分开填写
    # 排序：VRF 名 → VLAN ID；最多填 4 个 slot
    evpn_groups = []
    for vrf_name, vrf_val in sorted(non_default_vrfs.items()):
        l3vni_keys = [k for k in (vrf_val.get("evpn") or {}).get("vni", {}).keys() if k is not None]
        l3vni = str(l3vni_keys[0]) if l3vni_keys else NA
        l3vlan = str(vrf_val.get("evpn", {}).get("vlan", NA))

        # 收集该 VRF 下所有 SVI，按 VLAN ID 排序
        vrf_svis = []
        for interface_name, interface_value in ifaces.items():
            if not isinstance(interface_value, dict) or interface_value.get("vrf") != vrf_name:
                continue
            raw_vlan = interface_value.get("vlan")
            if raw_vlan is None:
                match = re.fullmatch(r"vlan(\d+)", interface_name)
                raw_vlan = match.group(1) if match else None
            try:
                vlan_id = int(raw_vlan)
            except (TypeError, ValueError):
                continue
            if interface_value.get("type") not in (None, "svi", "sub"):
                continue
            vrf_svis.append((vlan_id, interface_name, interface_value))
        vrf_svis.sort(key=lambda item: (item[0], item[1]))

        if not vrf_svis:
            dhcp_relay, dhcp_server = dhcp_relay_info(cfg, vrf_name)
            evpn_groups.append([vrf_name, l3vni, l3vlan, dhcp_relay, dhcp_server,
                                 NA, NA, NA, NA, NA, NA, NA])
            continue

        for vlan_id, svi_name, svi_cfg in vrf_svis:
            dhcp_relay, dhcp_server = dhcp_relay_info(cfg, vrf_name, vlan_id)
            svi_ip, svi_nm, vrr_ip, vrr_mac = svi_vrr_info(svi_cfg, cfg, vlan_id)
            l2vni = vlan_to_l2vni(cfg, vlan_id)

            vlan_out_names = sorted(
                filter(None, (
                    bond_iface_to_out.get(bname)
                    for bname, b in bonds.items()
                    if vlan_id in bond_vlan_set(b)
                )),
                key=_port_num
            )
            for interface_name, interface_cfg in ifaces.items():
                if (interface_name.startswith("swp") and
                        vlan_id in bond_vlan_set(interface_cfg)):
                    vlan_out_names.append(interface_name)
            base_interface = svi_cfg.get("base-interface")
            if base_interface in bond_iface_to_out:
                vlan_out_names.append(bond_iface_to_out[base_interface])
            vlan_out_names = sorted(set(vlan_out_names), key=_port_num)
            vlan_ports_str = compress_ports(vlan_out_names) if vlan_out_names else NA

            evpn_groups.append([
                vrf_name, l3vni, l3vlan, dhcp_relay, dhcp_server,
                l2vni, str(vlan_id), svi_ip, svi_nm,
                vrr_ip, vrr_mac, vlan_ports_str
            ])

    # Preserve bridge-only VLANs that have no SVI.  Runtime NVUE does not
    # encode a VRF relationship for such VLANs, so report VRF as NA instead of
    # guessing from a project CSV, hostname, or template.
    bridge_vlans = {}
    for domain in (cfg.get("bridge", {}).get("domain", {}) or {}).values():
        bridge_vlans.update((domain or {}).get("vlan", {}) or {})
    svi_vlan_ids = set()
    for interface_name, interface_cfg in ifaces.items():
        if not isinstance(interface_cfg, dict):
            continue
        raw_vlan = interface_cfg.get("vlan")
        if raw_vlan is None:
            match = re.fullmatch(r"vlan(\d+)", interface_name)
            raw_vlan = match.group(1) if match else None
        try:
            svi_vlan_ids.add(int(raw_vlan))
        except (TypeError, ValueError):
            pass
    bridge_only = []
    for raw_vlan in bridge_vlans:
        try:
            vlan_id = int(raw_vlan)
        except (TypeError, ValueError):
            continue
        if vlan_id not in svi_vlan_ids:
            bridge_only.append(vlan_id)

    bridge_only_groups = {}
    for vlan_id in bridge_only:
        port_names = []
        for bname, bcfg in bonds.items():
            if vlan_id in bond_vlan_set(bcfg):
                output_name = bond_iface_to_out.get(bname)
                if output_name:
                    port_names.append(output_name)
        for interface_name, interface_cfg in ifaces.items():
            if (interface_name.startswith("swp") and
                    vlan_id in bond_vlan_set(interface_cfg)):
                port_names.append(interface_name)
        ports = tuple(sorted(set(port_names), key=_port_num))
        l2vni = vlan_to_l2vni(cfg, vlan_id)
        bridge_only_groups.setdefault((l2vni, ports), []).append(vlan_id)

    for (l2vni, ports), vlan_ids in sorted(
            bridge_only_groups.items(), key=lambda item: min(item[1])):
        evpn_groups.append([
            NA, NA, NA, "FALSE", NA,
            l2vni, compress_numeric_ids(vlan_ids), NA, NA, NA, NA,
            compress_ports(list(ports)) if ports else NA,
        ])

    # ── 组装行（EVPN group 数由调用方传入）──
    row = [
        hostname,
        type_,
        eth_info.get("template", NA),
        eth0_ip,
        eth0_nm,
        eth0_gw,
        eth0_mac,
        eth1_ip,
        eth1_nm,
        eth1_gw,
        eth1_mac,
        lo_ip,
        NA,                           # vrf_default
        # vlan_id / svi_ip / vlan_ports (SIMPLE_TEMPLATES col 13-18)
        # Populated when device has no non-default VRFs (OOBofOOB-Leaf style)
        *_simple_cols(cfg, ifaces, non_default_vrfs),
        bgp_asn,
        bgp_ports,
        bond_ports,
        bond_type,
        bond_mac,
        peerlink_ports,
        "TRUE" if _has_vrf_route_leaking(cfg) else "FALSE",
    ]
    return row, evpn_groups          # 返回固定列 + 未截断的 evpn_groups


def _selector_vlan_ids(value):
    """Return VLAN IDs from normalized or compact NVUE selector keys."""
    result = set()
    for token in re.split(r"[,/]", str(value or "")):
        token = token.strip()
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", token)
        if not match:
            continue
        start = int(match.group(1))
        end = int(match.group(2) or start)
        if 1 <= start <= end <= 4094:
            result.update(range(start, end + 1))
    return result


def _bridge_attachment(interface_cfg, vlan_id):
    """Return ``(member, untagged)`` for one runtime bridge attachment."""
    bridge = (
        ((interface_cfg or {}).get("bridge") or {})
        .get("domain", {}).get("br_default", {})
    )
    access = bridge.get("access")
    untagged = bridge.get("untagged")
    member_ids = set()
    member_ids.update(_selector_vlan_ids(access))
    member_ids.update(_selector_vlan_ids(untagged))
    for selector in (bridge.get("vlan") or {}):
        member_ids.update(_selector_vlan_ids(selector))
    if vlan_id not in member_ids:
        return False, False
    native = vlan_id in _selector_vlan_ids(access)
    native = native or vlan_id in _selector_vlan_ids(untagged)
    return True, native


def _compress_v2_interface_names(names):
    """Compress ports without dropping compact multi-member bond names."""
    conventional = []
    opaque = []
    for name in sorted(set(names), key=_natural_key):
        if (re.fullmatch(r"[A-Za-z]+\d+(?:[A-Za-z]+\d+)?", name)
                or re.fullmatch(r"bond\d+(?:bond\d+)+", name)):
            conventional.append(name)
        else:
            opaque.append(name)
    tokens = []
    compressed = compress_ports(conventional)
    if compressed != NA:
        tokens.extend(compressed.split("/"))
    tokens.extend(opaque)
    return "/".join(sorted(tokens, key=_natural_key)) if tokens else NA


def _v2_vlan_attachment(cfg, ifaces, bonds, vlan_id, base_interface=None):
    """Return one representable v2 ``(vlan_ports, native)`` attachment.

    A v2 row applies ``/native`` to every interface named in that VLAN group.
    Runtime state with the same VLAN tagged on one port and native on another
    therefore has no lossless row representation and must fail closed.
    """
    attachments = []
    for name, interface_cfg in bonds.items():
        member, native = _bridge_attachment(interface_cfg, vlan_id)
        if member:
            attachments.append((name, native))
    for name, interface_cfg in ifaces.items():
        if not str(name).startswith("swp"):
            continue
        member, native = _bridge_attachment(interface_cfg, vlan_id)
        if member:
            attachments.append((name, native))
    if base_interface in bonds and not any(
            name == base_interface for name, _native in attachments):
        attachments.append((base_interface, False))
    native_values = {native for _name, native in attachments}
    if len(native_values) > 1:
        raise ValueError(
            f"VLAN {vlan_id} 的 native 状态无法写回 v2："
            "有的端口承载 untagged，有的端口只承载 tagged"
        )
    return (
        _compress_v2_interface_names(name for name, _native in attachments),
        bool(native_values and True in native_values),
    )


def _v2_bond_columns(bonds, mlag_mac=None):
    """Return aligned v2 bond_ports/bond_type/bond_mac columns."""
    profiles = {}
    priority = {"local": 0, "mlag": 1, "evpn": 2}
    for name, bond_cfg in bonds.items():
        segment = (
            ((bond_cfg.get("evpn") or {}).get("multihoming") or {})
            .get("segment") or {}
        )
        if segment:
            bond_type = "evpn"
            bond_mac = str(segment.get("mac-address") or NA)
        elif (bond_cfg.get("bond") or {}).get("mlag"):
            bond_type = "mlag"
            bond_mac = str(mlag_mac or NA)
        else:
            bond_type = "local"
            bond_mac = NA
        profiles.setdefault((bond_type, bond_mac), []).append(str(name))
    ordered = sorted(
        profiles.items(),
        key=lambda item: (
            priority[item[0][0]],
            _natural_key(sorted(item[1], key=_natural_key)[0]),
            item[0][1],
        ),
    )
    if not ordered:
        return NA, NA, NA
    ports = "|".join(
        _compress_v2_interface_names(names) for _profile, names in ordered
    )
    types = "|".join(profile[0] for profile, _names in ordered)
    macs = "|".join(profile[1] for profile, _names in ordered)
    return ports, types, macs


def parse_device_v2(cfg, hostname, type_, eth_info):
    """Project normalized runtime NVUE into schema-v2 CSV components.

    Per-device VRR fields deliberately do not exist in this projection; VRR
    IP/MAC are derived from the global v2 policy.  The protected source YAML
    remains available to comparison code for checking the actual derived VRR
    runtime state.
    """
    legacy_fixed, _legacy_evpn = parse_device(cfg, hostname, type_, eth_info)
    base = legacy_fixed[:len(DEVICE_BASE_COLUMNS)]
    ifaces = cfg.get("interface") or {}
    bonds = {
        str(name): value for name, value in ifaces.items()
        if isinstance(value, dict) and isinstance(value.get("bond"), dict)
        and value.get("type") != "peerlink"
    }
    bond_ports, bond_type, bond_mac = _v2_bond_columns(
        bonds, _path_get(cfg, "mlag", "mac-address"),
    )
    fixed = [
        legacy_fixed[19], legacy_fixed[20], bond_ports, bond_type, bond_mac,
        legacy_fixed[24], legacy_fixed[25],
    ]

    bridge_vlan_ids = set()
    for domain in (cfg.get("bridge", {}).get("domain", {}) or {}).values():
        for selector in ((domain or {}).get("vlan") or {}):
            bridge_vlan_ids.update(_selector_vlan_ids(selector))

    svi_by_vlan = {}
    for interface_name, interface_cfg in ifaces.items():
        if not isinstance(interface_cfg, dict):
            continue
        raw_vlan = interface_cfg.get("vlan")
        if raw_vlan is None:
            match = re.fullmatch(r"vlan(\d+)", str(interface_name))
            raw_vlan = match.group(1) if match else None
        try:
            vlan_id = int(raw_vlan)
        except (TypeError, ValueError):
            continue
        if not 1 <= vlan_id <= 4094:
            continue
        if interface_cfg.get("type") not in (None, "svi", "sub"):
            continue
        if vlan_id in svi_by_vlan:
            raise ValueError(f"VLAN {vlan_id} 存在多个 SVI，无法写回 v2")
        svi_by_vlan[vlan_id] = (str(interface_name), interface_cfg)
        bridge_vlan_ids.add(vlan_id)

    ordinary = []
    evpn = []
    represented_vrfs = set()
    for vlan_id in sorted(svi_by_vlan):
        _interface_name, svi_cfg = svi_by_vlan[vlan_id]
        vrf_name = str(svi_cfg.get("vrf") or "default")
        svi_ip, svi_nm, _vrr_ip, _vrr_mac = svi_vrr_info(
            svi_cfg, cfg, vlan_id,
        )
        ports, native = _v2_vlan_attachment(
            cfg, ifaces, bonds, vlan_id, svi_cfg.get("base-interface"),
        )
        selector = f"{vlan_id}/native" if native else str(vlan_id)
        l2vni = vlan_to_l2vni(cfg, vlan_id)
        is_evpn = vrf_name not in {"default", "mgmt"} or l2vni != NA
        if not is_evpn:
            ordinary.append([selector, svi_ip, svi_nm, ports])
            continue
        vrf_cfg = (cfg.get("vrf") or {}).get(vrf_name) or {}
        l3vni_keys = [
            key for key in ((vrf_cfg.get("evpn") or {}).get("vni") or {})
            if key is not None
        ]
        l3vni = str(l3vni_keys[0]) if l3vni_keys else NA
        l3vlan = str((vrf_cfg.get("evpn") or {}).get("vlan") or NA)
        relay_enabled, relay_group = dhcp_relay_info(cfg, vrf_name, vlan_id)
        relay = relay_group if relay_enabled == "TRUE" else NA
        evpn.append([
            vrf_name, l3vni, l3vlan, relay, l2vni, selector,
            svi_ip, svi_nm, ports,
        ])
        represented_vrfs.add(vrf_name)

    bridge_only = sorted(bridge_vlan_ids - set(svi_by_vlan))
    ordinary_bridge = []
    for vlan_id in bridge_only:
        ports, native = _v2_vlan_attachment(cfg, ifaces, bonds, vlan_id)
        l2vni = vlan_to_l2vni(cfg, vlan_id)
        if l2vni != NA:
            raise ValueError(
                f"VLAN {vlan_id} 有 L2 VNI {l2vni}，但运行配置没有可确认的 VRF/SVI；"
                "无法无损写回 v2 EVPN 组"
            )
        if native:
            ordinary.append([f"{vlan_id}/native", NA, NA, ports])
        else:
            ordinary_bridge.append((vlan_id, ports))

    # Compact only consecutive bridge-only VLANs with the exact same ports.
    # Native VLANs are emitted separately because /native is single-VLAN only.
    by_ports = {}
    for vlan_id, ports in ordinary_bridge:
        by_ports.setdefault(ports, []).append(vlan_id)
    for ports, vlan_ids in sorted(
            by_ports.items(), key=lambda item: min(item[1])):
        ordinary.append([compress_numeric_ids(vlan_ids), NA, NA, ports])

    for vrf_name, vrf_cfg in sorted((cfg.get("vrf") or {}).items()):
        if vrf_name in {"default", "mgmt"} or vrf_name in represented_vrfs:
            continue
        evpn_cfg = (vrf_cfg or {}).get("evpn") or {}
        l3vni_keys = [key for key in (evpn_cfg.get("vni") or {}) if key is not None]
        if not l3vni_keys and evpn_cfg.get("vlan") is None:
            continue
        relay_enabled, relay_group = dhcp_relay_info(cfg, vrf_name)
        relay = relay_group if relay_enabled == "TRUE" else NA
        evpn.append([
            vrf_name,
            str(l3vni_keys[0]) if l3vni_keys else NA,
            str(evpn_cfg.get("vlan") or NA),
            relay, NA, NA, NA, NA, NA,
        ])

    ordinary.sort(key=lambda group: min(_selector_vlan_ids(group[0]) or {4095}))
    evpn.sort(key=lambda group: (_natural_key(group[0]),
                                 min(_selector_vlan_ids(group[5]) or {4095})))
    return base, ordinary, fixed, evpn


# ── 主流程 ───────────────────────────────────────────────────────────────────

def find_backup_dir(base):
    candidates = sorted(glob.glob(os.path.join(base, "*-backup")), reverse=True)
    return candidates[0] if candidates else None


EVPN_GROUP_COLS = ["evpn_vrf","evpn_l3vni","evpn_l3vlan","dhcp_relay",
                   "evpn_l2vni","evpn_l2vlan","svi_ip","netmask",
                   "vrr_ip","vrr_mac","vlan_ports"]
EVPN_GROUP_COLS_DUAL = ["evpn_vrf","evpn_l3vni","evpn_l3vlan","dhcp_relay","dhcp_server",
                        "evpn_l2vni","evpn_l2vlan","svi_ip","netmask",
                        "vrr_ip","vrr_mac","vlan_ports"]

FIXED_HEADER = ["hostname","type","template","eth0_ip","netmask","eth0_gw","eth0_mac",
                "eth1_ip","netmask","eth1_gw","eth1_mac",
                "lo_ip","vrf_default","vlan_id","svi_ip","netmask","vrr_ip","vrr_mac","vlan_ports",
                "bgp_asn","bgp_ports","bond_ports","bond_type","bond_mac","peerlink_ports","vrl"]


def read_format_header(script_dir, format_path=None):
    """从格式文件读取列头；依次查找脚本目录和上级目录，文件不存在则返回仅含固定列的默认头。"""
    if format_path:
        fmt_path = os.path.abspath(format_path)
        if not os.path.isfile(fmt_path):
            raise FileNotFoundError(f"格式文件不存在: {fmt_path}")
    else:
        for search_dir in [script_dir, os.path.dirname(script_dir)]:
            fmt_path = os.path.join(search_dir, "02-devices_config-eth.csv")
            if os.path.isfile(fmt_path):
                break
        else:
            return list(FIXED_HEADER), 0
    with open(fmt_path) as f:
        rows = list(csv.reader(f))
    if not rows:
        return list(FIXED_HEADER), 0
    hdr = [col for col in rows[0] if col not in METADATA_COLS]
    if "vrl" not in hdr:
        try:
            hdr.insert(hdr.index("peerlink_ports") + 1, "vrl")
        except ValueError:
            raise ValueError("格式文件缺少 peerlink_ports，无法插入 vrl 列")
    n_groups = hdr.count("evpn_vrf")
    return hdr, n_groups


def read_v2_format_header(format_path=None, devices_config_path=None):
    """Read and validate the authoritative schema-v2 comparison layout."""
    source = format_path or devices_config_path
    if source:
        path = Path(source).expanduser().absolute()
        if not path.is_file():
            raise FileNotFoundError(f"v2 格式文件不存在: {path}")
        with path.open(newline="", encoding="utf-8-sig") as stream:
            rows = list(csv.reader(stream))
        if not rows:
            raise ValueError(f"v2 格式文件为空: {path}")
        header = [str(column).strip() for column in rows[0]]
    else:
        header = (
            list(DEVICE_BASE_COLUMNS)
            + list(DEVICE_FIXED_COLUMNS)
            + list(DEVICE_V2_OPTIONAL_POLICY_COLUMNS)
        )
    try:
        layout = parse_device_csv_layout(header, 2)
    except ValueError as exc:
        raise ValueError(f"Feedback v2 CSV 格式无效: {exc}") from exc
    return (
        header[:layout.metadata_start],
        len(layout.vlan_group_starts),
        len(layout.evpn_group_starts),
    )


def read_project_schema_version(global_config_path):
    """Read the explicit global schema; only a missing key defaults to v1."""
    if not global_config_path:
        return 1
    path = Path(global_config_path)
    try:
        with path.open(encoding="utf-8") as stream:
            document = safe_load_yaml_preserving_mac(stream)
    except yaml.YAMLError as exc:
        raise ValueError(f"全局 YAML 语法错误: {path}: {exc}") from exc
    try:
        return detect_global_schema_version(document)
    except ValueError as exc:
        raise ValueError(f"全局 schema 无效: {path}: {exc}") from exc


def find_devices_config(backup_dir, explicit_path=None):
    """Find inventory data in a collection or its nearby project ancestors."""
    if explicit_path:
        path = Path(explicit_path).expanduser().absolute()
        if not path.is_file():
            raise FileNotFoundError(f"设备 CSV 不存在: {path}")
        return path

    matches = sorted(
        path for path in Path(backup_dir).rglob("*devices_config*.csv")
        if path.is_file() and not path.is_symlink()
    )
    if matches:
        return matches[0]

    # A published ztp_latest target normally lives below
    # <project>/99-output-eth/<timestamp>_combine.  Search only nearby
    # ancestors instead of scanning or hard-coding the workspace.
    current = Path(backup_dir).resolve()
    for _ in range(5):
        nearby = sorted(
            path for path in current.glob("*devices_config*.csv")
            if path.is_file() and not path.is_symlink()
        )
        if nearby:
            return nearby[0]
        if current.parent == current:
            break
        current = current.parent
    return None


def find_global_config(backup_dir, explicit_path=None):
    """Find the project global YAML used as the reverse-conversion baseline."""
    if explicit_path:
        path = Path(explicit_path).expanduser().absolute()
        if not path.is_file():
            raise FileNotFoundError(f"全局 YAML 不存在: {path}")
        return path

    current = Path(backup_dir).resolve()
    for _ in range(5):
        for name in ("01-global.yaml", "global.yaml"):
            path = current / name
            if path.is_file():
                return path
        if current.parent == current:
            break
        current = current.parent
    return None


def _path_get(mapping, *parts):
    value = mapping
    for part in parts:
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _path_set(mapping, parts, value):
    current = mapping
    for part in parts[:-1]:
        current = current.setdefault(part, {})
    current[parts[-1]] = copy.deepcopy(value)


def _is_global_placeholder(value):
    """``{}`` (also inside a list) explicitly requests reverse filling."""
    return value == {} or (
        isinstance(value, list) and bool(value)
        and all(_is_global_placeholder(item) for item in value)
    )


def _path_can_fill(mapping, parts):
    current = mapping
    for part in parts:
        if not isinstance(current, dict) or part not in current:
            return True
        current = current[part]
    return _is_global_placeholder(current)


def _set_inferred(mapping, parts, value):
    """Fill an absent/placeholder field without overwriting a real baseline."""
    if value is not None and _path_can_fill(mapping, parts):
        _path_set(mapping, parts, value)
        return True
    return False


def _fill_global_placeholders(target, candidate, path=()):
    """Fill only explicit ``{}`` placeholders and return changed YAML paths."""
    if isinstance(target, dict) and isinstance(candidate, dict):
        changed = []
        for key in list(target):
            if key not in candidate:
                continue
            target_value = target[key]
            candidate_value = candidate[key]
            if _is_global_placeholder(target_value):
                if not _is_global_placeholder(candidate_value):
                    target[key] = copy.deepcopy(candidate_value)
                    changed.append(".".join(str(part) for part in path + (key,)))
            else:
                changed.extend(_fill_global_placeholders(
                    target_value, candidate_value, path + (key,),
                ))
        return changed
    if isinstance(target, list) and isinstance(candidate, list):
        changed = []
        for index, (target_value, candidate_value) in enumerate(
                zip(target, candidate)):
            if _is_global_placeholder(target_value):
                if not _is_global_placeholder(candidate_value):
                    target[index] = copy.deepcopy(candidate_value)
                    changed.append(".".join(str(part) for part in path + (index,)))
            else:
                changed.extend(_fill_global_placeholders(
                    target_value, candidate_value, path + (index,),
                ))
        return changed
    return []


def _natural_key(value):
    return [int(part) if part.isdigit() else part.casefold()
            for part in re.split(r"(\d+)", str(value))]


def _consensus(configs, parts, transform=None):
    """Return a value only when all devices exposing a path agree on it."""
    values = []
    fingerprints = set()
    for cfg in configs:
        value = _path_get(cfg, *parts)
        if value is None:
            continue
        if transform:
            value = transform(value)
        fingerprint = json.dumps(value, sort_keys=True, ensure_ascii=False)
        fingerprints.add(fingerprint)
        values.append(value)
    return copy.deepcopy(values[0]) if values and len(fingerprints) == 1 else None


def _server_names(value):
    if isinstance(value, dict):
        return sorted((str(key) for key in value), key=_natural_key)
    if isinstance(value, list):
        return sorted((str(item) for item in value), key=_natural_key)
    return value


def _collect_server_names(configs, parts):
    servers = set()
    for cfg in configs:
        value = _path_get(cfg, *parts)
        if isinstance(value, dict):
            servers.update(str(key) for key in value)
        elif isinstance(value, list):
            servers.update(str(item) for item in value if not _is_global_placeholder(item))
    return sorted(servers, key=_natural_key) or None


def _collect_dhcp_relay_global(configs):
    """Convert NVUE DHCP relay mappings into the compact global.yaml shape."""
    collected = {}
    for cfg in configs:
        relays = _path_get(cfg, "service", "dhcp-relay") or {}
        if not isinstance(relays, dict):
            continue
        for vrf, relay in relays.items():
            runtime_groups = (relay.get("server-group", {})
                              if isinstance(relay, dict) else {})
            if not isinstance(runtime_groups, dict):
                continue
            for group_name, runtime_group in runtime_groups.items():
                runtime_servers = (runtime_group.get("server", {})
                                   if isinstance(runtime_group, dict) else {})
                if not isinstance(runtime_servers, dict) or not runtime_servers:
                    continue
                key = (str(vrf), str(group_name))
                collected.setdefault(key, set()).update(
                    str(server) for server in runtime_servers
                )
    if not collected:
        return None
    result = {}
    for vrf, group_name in sorted(
            collected, key=lambda item: (_natural_key(item[0]), _natural_key(item[1]))):
        relay = result.setdefault(vrf, {"server_group": []})
        relay["server_group"].append({
            "group": group_name,
            "servers": sorted(collected[(vrf, group_name)], key=_natural_key),
        })
    return result


def _eth_global_section(document):
    switches = document.setdefault("switches", [])
    if not isinstance(switches, list):
        switches = []
        document["switches"] = switches
    for entry in switches:
        if isinstance(entry, dict) and isinstance(entry.get("eth"), dict):
            return entry["eth"]
    entry = {"eth": {}}
    switches.insert(0, entry)
    return entry["eth"]


def build_global_document(configs, baseline=None):
    """Build global.yaml-shaped data, using the project file for missing values."""
    document = copy.deepcopy(baseline) if isinstance(baseline, dict) else {}
    document.setdefault("common", {}).setdefault("switch", {})
    eth = _eth_global_section(document)
    schema_version = detect_global_schema_version(document)
    v2_mlag_policy = None
    if schema_version == 2:
        # Validate the authoritative v2 shape before inferring runtime values.
        # In particular, an old positional ``pairs`` block must never be
        # silently retained while Feedback emits the new MAC-keyed contract.
        v2_mlag_policy = normalize_v2_mlag_policy(eth)

    mappings = (
        (("system", "config", "auto-save", "state"),
         ("common", "switch", "system", "config", "auto-save", "state"), None),
        (("system", "date-time", "timezone"),
         ("common", "switch", "system", "date-time", "timezone"), None),
    )
    for source, destination, transform in mappings:
        value = _consensus(configs, source, transform)
        _set_inferred(document, destination, value)

    for source, destination in (
        (("system", "dns", "server"),
         ("common", "switch", "system", "dns", "server")),
        (("system", "ntp", "server"),
         ("common", "switch", "system", "ntp", "server")),
    ):
        _set_inferred(document, destination, _collect_server_names(configs, source))

    _set_inferred(
        eth, ("services", "dhcp_relay"),
        _collect_dhcp_relay_global(configs),
    )

    eth_mappings = (
        (("bridge", "domain", "br_default", "stp", "priority"),
         ("bridge", "domain", "br_default", "stp", "priority")),
        (("system", "ntp", "vrf"), ("system", "ntp", "vrf")),
        (("router", "bfd", "profile"),
         ("vrf", "default", "router", "bfd", "profile")),
    )
    for source, destination in eth_mappings:
        value = _consensus(configs, source)
        _set_inferred(eth, destination, value)

    # AAA is compared one user/field at a time: an extra local account must not
    # prevent stable global credentials from being recovered.
    users = sorted({
        str(user)
        for cfg in configs
        for user in (_path_get(cfg, "system", "aaa", "user") or {})
    }, key=_natural_key)
    for user in users:
        fields = sorted({
            str(field)
            for cfg in configs
            for field in ((_path_get(cfg, "system", "aaa", "user", user) or {}))
        }, key=_natural_key)
        for field in fields:
            value = _consensus(configs, ("system", "aaa", "user", user, field))
            _set_inferred(eth, ("system", "aaa", "user", user, field), value)

    # global.yaml uses a compact list shape for DHCP relay groups, while NVUE
    # stores them as mappings. A placeholder server list is populated only from
    # the same VRF/group; using an unrelated group would silently inject an
    # incorrect DHCP destination.
    relay_baseline = _path_get(eth, "services", "dhcp_relay") or {}
    if isinstance(relay_baseline, dict):
        for vrf, relay in relay_baseline.items():
            groups = relay.get("server_group", []) if isinstance(relay, dict) else []
            for index, group in enumerate(groups if isinstance(groups, list) else []):
                if not isinstance(group, dict):
                    continue
                destination = ("services", "dhcp_relay", vrf,
                               "server_group", index, "servers")
                if not _is_global_placeholder(group.get("servers")):
                    continue
                group_name = str(group.get("group", ""))
                exact = set()
                for cfg in configs:
                    runtime_groups = _path_get(
                        cfg, "service", "dhcp-relay", vrf, "server-group"
                    ) or {}
                    if not isinstance(runtime_groups, dict):
                        continue
                    for runtime_name, runtime_group in runtime_groups.items():
                        runtime_servers = (runtime_group.get("server", {})
                                           if isinstance(runtime_group, dict) else {})
                        if isinstance(runtime_servers, dict):
                            if str(runtime_name) == group_name:
                                exact.update(str(server) for server in runtime_servers)
                servers = sorted(exact, key=_natural_key)
                if servers:
                    group["servers"] = servers

    mlag_configs = [cfg for cfg in configs if isinstance(cfg.get("mlag"), dict)]
    if mlag_configs:
        init_delay = _consensus(mlag_configs, ("mlag", "init-delay"))
        _set_inferred(eth, ("mlag", "init-delay"), init_delay)
        priorities = sorted({
            _path_get(cfg, "mlag", "priority") for cfg in mlag_configs
            if _path_get(cfg, "mlag", "priority") is not None
        }, key=lambda value: (isinstance(value, str), str(value)))
        if priorities:
            _set_inferred(eth, ("mlag", "priority"), priorities)

        if schema_version == 2:
            shared_by_mac = dict(v2_mlag_policy["shared_addresses"])
            mac_by_shared = {
                address: mac for mac, address in shared_by_mac.items()
            }
            for cfg in mlag_configs:
                shared = _path_get(
                    cfg, "nve", "vxlan", "mlag", "shared-address",
                )
                if shared is None:
                    continue
                mlag_mac = _path_get(cfg, "mlag", "mac-address")
                if not mlag_mac:
                    raise ValueError(
                        "schema v2 无法反推 MLAG shared-address："
                        "运行配置缺少 mlag.mac-address"
                    )
                normalized = normalize_v2_mlag_policy({
                    "mlag": {"shared-addresses": [{
                        "bond-mac": str(mlag_mac),
                        "anycast-ip": str(shared),
                    }]},
                })["shared_addresses"]
                normalized_mac, normalized_ip = next(iter(normalized.items()))

                previous_ip = shared_by_mac.get(normalized_mac)
                if previous_ip is not None and previous_ip != normalized_ip:
                    raise ValueError(
                        "schema v2 MLAG shared-address 冲突：bond-mac "
                        f"{normalized_mac} 同时对应 {previous_ip} 和 {normalized_ip}"
                    )
                previous_mac = mac_by_shared.get(normalized_ip)
                if previous_mac is not None and previous_mac != normalized_mac:
                    raise ValueError(
                        "schema v2 MLAG shared-address 冲突：anycast-ip "
                        f"{normalized_ip} 同时对应 {previous_mac} 和 {normalized_mac}"
                    )
                shared_by_mac[normalized_mac] = normalized_ip
                mac_by_shared[normalized_ip] = normalized_mac

            if shared_by_mac:
                eth.setdefault("mlag", {})["shared-addresses"] = [
                    {"bond-mac": mac, "anycast-ip": shared_by_mac[mac]}
                    for mac in sorted(shared_by_mac, key=_natural_key)
                ]
        else:
            # Schema v1 retains its positional pair representation, including
            # optional per-device system MAC recovery.
            pairs = {}
            for cfg in mlag_configs:
                shared = _path_get(
                    cfg, "nve", "vxlan", "mlag", "shared-address",
                )
                if shared is None:
                    continue
                pair = pairs.setdefault(str(shared), {
                    "shared-addresses": [shared],
                    "system-mac": set(),
                    "mac-address": set(),
                })
                system_mac = _path_get(cfg, "system", "global", "system-mac")
                mlag_mac = _path_get(cfg, "mlag", "mac-address")
                if system_mac:
                    pair["system-mac"].add(str(system_mac))
                if mlag_mac:
                    pair["mac-address"].add(str(mlag_mac))
            if pairs:
                if not _path_can_fill(eth, ("mlag", "pairs")):
                    return document
                rendered_by_shared = {}
                baseline_pairs = _path_get(eth, "mlag", "pairs") or []
                for item in baseline_pairs:
                    if not isinstance(item, dict) or not item.get("shared-addresses"):
                        continue
                    rendered_by_shared[str(item["shared-addresses"][0])] = copy.deepcopy(item)
                for shared in sorted(pairs, key=_natural_key):
                    pair = pairs[shared]
                    item = {"shared-addresses": pair["shared-addresses"]}
                    if pair["system-mac"]:
                        item["system-mac"] = sorted(
                            pair["system-mac"], key=_natural_key,
                        )
                    if pair["mac-address"]:
                        item["mac-address"] = sorted(
                            pair["mac-address"], key=_natural_key,
                        )
                    rendered_by_shared[shared] = item
                rendered = [
                    rendered_by_shared[key]
                    for key in sorted(rendered_by_shared, key=_natural_key)
                ]
                _path_set(eth, ("mlag", "pairs"), rendered)
    return document


def write_global_yaml(csv_path, configs, global_config_path=None,
                      update_global_config=True):
    """Write ``<csv-stem>-global.yaml`` next to the generated CSV."""
    baseline = None
    if global_config_path:
        with Path(global_config_path).open(encoding="utf-8") as stream:
            baseline = safe_load_yaml_preserving_mac(stream)
        if baseline is not None and not isinstance(baseline, dict):
            raise ValueError(f"全局 YAML 顶层必须是 mapping: {global_config_path}")
    document = build_global_document(configs, baseline)
    output = Path(csv_path).with_name(f"{Path(csv_path).stem}-global.yaml")
    with output.open("w", encoding="utf-8") as stream:
        yaml.safe_dump(document, stream, allow_unicode=True, sort_keys=False, width=120)
    if update_global_config and global_config_path and isinstance(baseline, dict):
        changed = _fill_global_placeholders(baseline, document)
        if changed:
            # Opening the path follows the sample symlink and updates the
            # project file; replacing the path would incorrectly replace the
            # symlink itself.
            with Path(global_config_path).open("w", encoding="utf-8") as stream:
                yaml.safe_dump(baseline, stream, allow_unicode=True,
                               sort_keys=False, width=120)
            print(f"[UPDATE] 全局基线回填 {len(changed)} 个字段 → {global_config_path}")
            for item in changed:
                print(f"         {item}")
    unresolved = []
    def find_unresolved(value, path=()):
        if value == {}:
            unresolved.append(".".join(str(part) for part in path))
        elif isinstance(value, dict):
            for key, child in value.items():
                find_unresolved(child, path + (key,))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                find_unresolved(child, path + (index,))
    find_unresolved(document)
    if unresolved:
        preview = ", ".join(unresolved[:5])
        suffix = " ..." if len(unresolved) > 5 else ""
        print(f"[WARN] 全局信息仍有 {len(unresolved)} 个未回填 {{}}: {preview}{suffix}")
    return output


def build_header(base_hdr, n_groups):
    """
    确保 base_hdr 有足够的 EVPN group 列。
    如果 n_groups 超出当前列数，在末尾追加新的 group 列。
    """
    current = base_hdr.count("evpn_vrf")
    hdr = list(base_hdr)
    group_columns = (EVPN_GROUP_COLS_DUAL
                     if "dhcp_server" in hdr[FIXED_COLS:]
                     else EVPN_GROUP_COLS)
    for _ in range(n_groups - current):
        hdr.extend(group_columns)
    return hdr


def format_evpn_group(group, has_dhcp_server):
    """Project the 12-column internal group into dual- or single-field CSV."""
    if has_dhcp_server:
        return list(group)
    relay = group[4] if group[3] == "TRUE" and group[4] not in ("", NA) else NA
    return list(group[:3]) + [relay] + list(group[5:])


def _conversion_error(message):
    raise ValueError(message)


def convert_one(input_value=None, output_value=None, format_path=None,
                devices_config_path=None, yaml_only=False,
                global_config_path=None, environment_scope=None):
    """Convert one YAML collection and return the generated CSV path."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if input_value:
        input_location = Path(input_value).expanduser().absolute()
    else:
        latest = find_backup_dir(script_dir)
        if not latest:
            _conversion_error(f"找不到 backup 目录（在 {script_dir}）")
        input_location = Path(latest).absolute()

    if not input_location.exists():
        _conversion_error(f"输入不存在或软链接目标无效: {input_location}")
    input_path = input_location.resolve()

    temporary = None
    single_yaml = None
    single_info = None
    if input_path.is_dir():
        backup_dir = input_path
        input_kind = "目录"
    elif input_path.is_file() and input_path.suffix.casefold() in {".yaml", ".yml"}:
        backup_dir = input_path.parent
        single_yaml = input_path
        input_kind = "YAML"
    elif input_path.is_file() and input_path.suffix.casefold() == ".info":
        backup_dir = input_path.parent
        single_info = input_path
        input_kind = "采集 INFO"
    elif input_path.is_file():
        temporary = tempfile.TemporaryDirectory(prefix="yaml-to-csv-")
        try:
            backup_dir = extract_archive(input_path, temporary.name)
        except (OSError, tarfile.TarError, zipfile.BadZipFile, ValueError) as exc:
            temporary.cleanup()
            _conversion_error(str(exc))
        input_kind = "归档"
    else:
        _conversion_error(f"输入既不是普通文件也不是目录: {input_path}")

    print(f"输入参数    : {input_location}（{input_kind}）")
    if input_location.is_symlink():
        print(f"链接目标    : {input_path}")
    print(f"扫描目录    : {backup_dir}")

    # 读 devices_config.csv（采集到的基础信息）
    try:
        collected_csv = find_devices_config(
            backup_dir, explicit_path=devices_config_path,
        )
    except FileNotFoundError as exc:
        _conversion_error(str(exc))
    base_info = {}
    if collected_csv:
        print(f"基础信息   : {collected_csv}")
        with open(collected_csv, encoding="utf-8-sig") as f:
            lines = list(csv.reader(f))
        raw_hdr = lines[0]
        normalized_header = [
            str(column or "").strip().casefold() for column in raw_hdr
        ]
        terminal_l2_ports_index = (
            normalized_header.index("terminal_l2_ports")
            if normalized_header.count("terminal_l2_ports") == 1 else None
        )
        for line in lines[1:]:
            row = dict(zip(raw_hdr, line))
            # 两个 netmask 列：第5列(index4)=eth0 netmask, 第9列(index8)=eth1 netmask
            h = row.get("hostname", "")
            row_type = str(row.get("type") or "eth").strip().casefold()
            if environment_scope == "air" and row_type != "air":
                continue
            if environment_scope == "prod" and row_type == "air":
                continue
            nm_vals = [line[i] for i, c in enumerate(raw_hdr) if c == "netmask"]
            base_info[h] = {
                "type":     row_type,
                "template": (row.get("template") or NA).strip(),
                "eth0_ip":  row.get("eth0_ip", NA),
                "netmask":  nm_vals[0] if nm_vals else NA,
                "eth0_gw":  row.get("eth0_gw", NA),
                "eth0_mac": row.get("eth0_mac", NA),
                "eth1_ip":  row.get("eth1_ip", NA),
                "eth1_nm":  nm_vals[1] if len(nm_vals) > 1 else NA,
                "eth1_gw":  row.get("eth1_gw", NA),
                "eth1_mac": row.get("eth1_mac", NA),
                "terminal_l2_ports": (
                    line[terminal_l2_ports_index]
                    if (terminal_l2_ports_index is not None
                        and terminal_l2_ports_index < len(line)) else NA
                ),
            }
    else:
        inventory_logs = sorted(
            path for path in Path(backup_dir).rglob("hostname-ip-mac.log")
            if path.is_file() and not path.is_symlink()
        )
        inventory_log = inventory_logs[0] if inventory_logs else None
        if inventory_log:
            with open(inventory_log, newline="", encoding="utf-8") as f:
                for line in csv.reader(f):
                    if len(line) < 3:
                        continue
                    hostname, eth0_ip, eth0_mac = (value.strip() for value in line[:3])
                    if not hostname or hostname.lower().startswith("ib"):
                        continue
                    base_info[hostname] = {
                        "type": "eth", "template": NA, "eth0_ip": eth0_ip or NA,
                        "netmask": NA, "eth0_gw": NA, "eth0_mac": eth0_mac or NA,
                        "eth1_ip": NA, "eth1_nm": NA, "eth1_gw": NA, "eth1_mac": NA,
                    }
            print(f"基础信息   : {inventory_log}（hostname/ip/mac）")
        else:
            print(f"[INFO] 未找到 *devices_config*.csv 或 hostname-ip-mac.log，eth 相关信息填 NA")

    v2_policy_columns = ()
    try:
        collected_global = find_global_config(
            backup_dir, explicit_path=global_config_path,
        )
    except FileNotFoundError as exc:
        _conversion_error(str(exc))
    if collected_global:
        print(f"全局基线   : {collected_global}")
    else:
        print("[INFO] 未找到 01-global.yaml/global.yaml，将仅输出可从设备配置反推的全局信息")

    try:
        schema_version = read_project_schema_version(collected_global)
        if schema_version == 2:
            base_header, existing_vlan_groups, existing_groups = (
                read_v2_format_header(format_path, collected_csv)
            )
            v2_policy_columns = parse_device_csv_layout(
                base_header, 2,
            ).policy_columns
            print(
                "格式文件   : schema v2，现有普通 VLAN groups="
                f"{existing_vlan_groups}，EVPN groups={existing_groups}"
            )
        else:
            base_header, existing_groups = read_format_header(
                script_dir, format_path,
            )
            existing_vlan_groups = 0
            print(f"格式文件   : schema v1，现有 EVPN groups={existing_groups}")
    except (FileNotFoundError, ValueError) as exc:
        _conversion_error(str(exc))

    info_temporary = tempfile.TemporaryDirectory(prefix="yaml-to-csv-info-")
    # Managed monitor/backup links already carry authoritative AIR/Production
    # scope in their source name.  Do not discard a device merely because the
    # observed hostname has a site prefix that differs from today's inventory;
    # the comparison layer can correlate it by management IP/MAC and report the
    # hostname delta.  The generated source can contain both environments, so
    # it must retain the strict inventory hostname filter.
    allowed_yaml_hostnames = inventory_hostname_filter(
        input_location, yaml_only, base_info,
    )
    yaml_files = discover_yaml_files(
        backup_dir,
        single_yaml=single_yaml,
        single_info=single_info,
        info_output_dir=info_temporary.name,
        allowed_hostnames=allowed_yaml_hostnames,
    )
    if not yaml_files:
        info_temporary.cleanup()
        _conversion_error(f"输入中没有找到 YAML 或含 nv config show 的 .info: {input_path}")
    print(f"YAML 配置   : {len(yaml_files)} 个")

    if yaml_only:
        base_info = {hostname: info for hostname, info in base_info.items()
                     if hostname in yaml_files}

    # .info 还可提供 DHCP 当前地址以及形如 MAC 的平台 serial-number。
    for hostname, metadata in discover_info_metadata(
        backup_dir, single_info=single_info
    ).items():
        info = base_info.setdefault(hostname, {
            "type": "eth", "template": NA,
            "eth0_ip": NA, "netmask": NA, "eth0_gw": NA, "eth0_mac": NA,
            "eth1_ip": NA, "eth1_nm": NA, "eth1_gw": NA, "eth1_mac": NA,
        })
        for field, value in metadata.items():
            if info.get(field) in (None, "", NA):
                info[field] = value

    inventory_global_hosts = {
        hostname for hostname, info in base_info.items()
        if info.get("type", "eth") in YAML_DEVICE_TYPES
        and hostname in yaml_files
    }

    # 没有 devices_config.csv 时，从 yaml 文件名推断 hostname 列表，eth 信息全填 NA
    # In comparison mode the inventory is the authoritative scope. Re-adding
    # every YAML here pulled IB/NVLink backups into Ethernet-only comparisons.
    if not base_info:
        for hostname in yaml_files:
            base_info.setdefault(hostname, {
                "type": "eth", "template": NA,
                "eth0_ip": NA, "netmask": NA, "eth0_gw": NA, "eth0_mac": NA,
                "eth1_ip": NA, "eth1_nm": NA, "eth1_gw": NA, "eth1_mac": NA,
            })

    # 解析可编辑字段，并保留原始 YAML 作为完整性受保护的无损回环数据。
    parsed = []
    global_configs = []
    for hostname, info in sorted(base_info.items()):
        type_ = info.get("type", "eth")
        yaml_path = yaml_files.get(hostname)

        source_b64 = NA
        source_sha256 = NA
        if yaml_path and type_ in YAML_DEVICE_TYPES:
            with open(yaml_path, "rb") as source_file:
                source_bytes = source_file.read()
            source_b64 = encode_source_yaml(source_bytes, hostname)
            source_sha256 = hashlib.sha256(source_bytes).hexdigest()

        base_values = [
            hostname, type_, info.get("template", NA), info["eth0_ip"],
            info["netmask"], info["eth0_gw"], info["eth0_mac"],
            info["eth1_ip"], info["eth1_nm"], info["eth1_gw"],
            info["eth1_mac"], NA,
        ]
        if not yaml_path or type_ not in YAML_DEVICE_TYPES:
            if schema_version == 2:
                parsed.append({
                    "base": base_values, "ordinary": [],
                    "fixed": [NA] * len(DEVICE_FIXED_COLUMNS), "evpn": [],
                    "policy": [
                        info.get(column, NA) for column in v2_policy_columns
                    ],
                    "source_b64": source_b64, "source_sha256": source_sha256,
                })
            else:
                fixed = base_values[:-1]
                fixed += [NA] * (FIXED_COLS - len(fixed))
                parsed.append({
                    "fixed_v1": fixed, "evpn_v1": [],
                    "source_b64": source_b64, "source_sha256": source_sha256,
                })
            print(f"  {hostname}: 无 yaml（type={type_}），基础信息填写")
            continue

        try:
            cfg = load_yaml(yaml_path)
            if schema_version == 2:
                base, ordinary, fixed, groups = parse_device_v2(
                    cfg, hostname, type_, info,
                )
                parsed.append({
                    "base": base, "ordinary": ordinary, "fixed": fixed,
                    "policy": [
                        info.get(column, NA) for column in v2_policy_columns
                    ],
                    "evpn": groups, "source_b64": source_b64,
                    "source_sha256": source_sha256,
                })
                print(
                    f"  {hostname}: 解析完成，{len(ordinary)} 个普通 VLAN group，"
                    f"{len(groups)} 个 EVPN group"
                )
            else:
                fixed, groups = parse_device(cfg, hostname, type_, info)
                parsed.append({
                    "fixed_v1": fixed, "evpn_v1": groups,
                    "source_b64": source_b64,
                    "source_sha256": source_sha256,
                })
                print(f"  {hostname}: 解析完成，{len(groups)} 个 EVPN group")
            if hostname in inventory_global_hosts:
                global_configs.append(cfg)
        except Exception as exc:
            if schema_version == 2:
                _conversion_error(
                    f"{hostname}: 无法安全转换成 schema v2 CSV: {exc}"
                )
            print(f"  {hostname}: 解析失败 ({exc})，基础信息填写")
            fixed = base_values[:-1]
            fixed += [NA] * (FIXED_COLS - len(fixed))
            parsed.append({
                "fixed_v1": fixed, "evpn_v1": [],
                "source_b64": source_b64, "source_sha256": source_sha256,
            })

    output_rows = []
    if schema_version == 2:
        data_vlan_max = max((len(item["ordinary"]) for item in parsed), default=0)
        data_evpn_max = max((len(item["evpn"]) for item in parsed), default=0)
        n_vlan_groups = max(existing_vlan_groups, data_vlan_max)
        n_groups = max(existing_groups, data_evpn_max)
        if data_vlan_max > existing_vlan_groups or data_evpn_max > existing_groups:
            print(
                "动态扩展   : schema v2 数据需要普通 VLAN groups="
                f"{data_vlan_max}、EVPN groups={data_evpn_max}；"
                f"输出使用 {n_vlan_groups}/{n_groups}"
            )
        data_header = (
            list(DEVICE_BASE_COLUMNS)
            + list(DEVICE_V2_VLAN_COLUMNS) * n_vlan_groups
            + list(DEVICE_FIXED_COLUMNS)
            + list(v2_policy_columns)
            + list(DEVICE_V2_EVPN_COLUMNS) * n_groups
        )
        header = data_header + list(METADATA_COLS)
        for item in parsed:
            row = list(item["base"])
            for group in item["ordinary"]:
                row.extend(group)
            row.extend(
                [NA] * (n_vlan_groups - len(item["ordinary"]))
                * len(DEVICE_V2_VLAN_COLUMNS)
            )
            row.extend(item["fixed"])
            row.extend(item["policy"])
            for group in item["evpn"]:
                row.extend(group)
            row.extend(
                [NA] * (n_groups - len(item["evpn"]))
                * len(DEVICE_V2_EVPN_COLUMNS)
            )
            fields_sha256 = hashlib.sha256(json.dumps(
                row, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")).hexdigest()
            row.extend([
                item["source_b64"], item["source_sha256"], fields_sha256,
            ])
            output_rows.append(row)
    else:
        data_max = max((len(item["evpn_v1"]) for item in parsed), default=0)
        n_groups = max(existing_groups, data_max)
        if data_max > existing_groups:
            print(
                f"动态扩展   : 数据需要 {data_max} 个 EVPN group，"
                f"格式文件有 {existing_groups} 个 → 自动追加 "
                f"{data_max - existing_groups} 个"
            )
        data_header = build_header(base_header, n_groups)
        output_has_dhcp_server = "dhcp_server" in data_header[FIXED_COLS:]
        output_group_width = (
            len(EVPN_GROUP_COLS_DUAL) if output_has_dhcp_server
            else len(EVPN_GROUP_COLS)
        )
        data_cols = len(data_header)
        header = data_header + list(METADATA_COLS)
        for item in parsed:
            row = list(item["fixed_v1"])
            for group in item["evpn_v1"]:
                row.extend(format_evpn_group(group, output_has_dhcp_server))
            while len(row) < data_cols:
                row.extend([NA] * output_group_width)
            row = row[:data_cols]
            fields_sha256 = hashlib.sha256(json.dumps(
                row, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")).hexdigest()
            row.extend([
                item["source_b64"], item["source_sha256"], fields_sha256,
            ])
            output_rows.append(row)
    total_cols = len(header)

    folder_name = input_location.name
    for suffix in (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".tar", ".yaml", ".yml", ".info"):
        if folder_name.casefold().endswith(suffix):
            folder_name = folder_name[:-len(suffix)]
            break
    folder_name = re.sub(r"[^A-Za-z0-9._-]+", "_", folder_name).strip("._-") or "yaml-input"
    if output_value:
        out_path = Path(output_value).expanduser().absolute()
        if out_path.suffix.casefold() != ".csv":
            out_path = out_path.with_suffix(".csv")
    else:
        out_path = input_location.with_name(f"{folder_name}.csv")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(output_rows)

    print(f"已写入 {len(output_rows)} 行，{n_groups} 个 EVPN group，{total_cols} 列 → {out_path}")
    global_path = write_global_yaml(out_path, global_configs, collected_global)
    print(f"全局信息   : {len(global_configs)} 台设备参与反推 → {global_path}")
    info_temporary.cleanup()
    if temporary is not None:
        temporary.cleanup()
    return out_path


ARCHIVE_SUFFIXES = (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".tar")


def source_label(path):
    """Return a stable filename-safe label for one comparison source."""
    name = Path(path).name
    for suffix in ARCHIVE_SUFFIXES + (".yaml", ".yml", ".info", ".csv"):
        if name.casefold().endswith(suffix):
            name = name[:-len(suffix)]
            break
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._-") or "yaml-input"


def _contains_yaml_source(directory):
    # pathlib.rglob does not descend through a directory symlink on all Python
    # versions; comparison samples intentionally use such links.
    directory = Path(directory).resolve()
    return any(path.is_file() for pattern in ("*.yaml", "*.yml", "*.info")
               for path in directory.rglob(pattern))


def discover_comparison_sources(directory):
    """Discover two to five immediate config collections in a directory.

    A directory containing YAML/INFO files directly remains a single collection.
    Comparison containers can hold archives, symlinks to collections, or child
    directories containing YAML/INFO files. Generated CSV files are ignored.
    """
    directory = Path(directory).expanduser().absolute()
    if any(path.is_file() and path.suffix.casefold() in {".yaml", ".yml", ".info"}
           and path.name not in {"01-global.yaml", "global.yaml"}
           and not path.name.endswith("-global.yaml")
           for path in directory.iterdir()):
        return []

    raw_sources = []
    csv_sources = []
    for path in sorted(directory.iterdir(), key=lambda item: item.name.casefold()):
        if path.name.startswith(".") or not path.exists():
            continue
        lower = path.name.casefold()
        resolved_lower = path.resolve().name.casefold()
        if (path.is_file()
                and (lower.endswith(ARCHIVE_SUFFIXES)
                     or resolved_lower.endswith(ARCHIVE_SUFFIXES))):
            raw_sources.append(path)
        elif path.is_dir() and _contains_yaml_source(path):
            raw_sources.append(path)
        elif (path.is_file() and path.suffix.casefold() == ".csv"
              and path.name not in {
                  "02-devices_config.csv",
              }
              and not re.match(r"^compare-.*-(details|summary)\.csv$", path.name)):
            csv_sources.append(path)

    # A previously generated <source>.csv is an output, not an extra dataset.
    # It becomes a valid fallback only when the original source is unavailable.
    raw_labels = {source_label(path) for path in raw_sources}
    if len(raw_sources) >= 2:
        return raw_sources
    sources = list(raw_sources)
    sources.extend(path for path in csv_sources if source_label(path) not in raw_labels)
    return sources


def comparison_source_scope(path):
    """Classify one managed optimize sample source as prod, air, or generated."""
    path = Path(path)
    names = {path.name.casefold()}
    try:
        names.add(path.resolve().name.casefold())
    except OSError:
        pass
    joined = " ".join(names)
    if "generated" in joined:
        return "generated"
    if is_air_comparison_source(path):
        return "air"
    if "monitor-prod" in joined or "config-backup-prod" in joined:
        return "prod"
    return None


def inventory_hostname_filter(source, yaml_only, base_info):
    """Return the strict generated-source hostname boundary, when required.

    Managed monitor/backup sources describe one authoritative environment and
    must retain observed hostname drift for comparison. Generic/generated
    sources still need the inventory filter to prevent AIR/Production mixing.
    """
    if not yaml_only or not base_info:
        return None
    if comparison_source_scope(source) in {"air", "prod"}:
        return None
    return set(base_info)


def select_managed_comparison_sources(sources, requested_type):
    """Select the three standard Production or AIR sample data sources.

    Generic comparison containers remain untouched. Filtering is activated
    only when at least one managed optimize source name is present.
    """
    classified = [(source, comparison_source_scope(source)) for source in sources]
    if not any(scope is not None for _, scope in classified):
        return list(sources)
    return [
        source for source, scope in classified
        if scope in {requested_type, "generated"}
    ]


def _semantic_headers(header):
    """Give repeated devices_config columns stable comparison field names."""
    try:
        layout = parse_device_csv_layout(header, 2)
    except ValueError:
        layout = None
    if layout is not None:
        result = [None] * len(header)
        counts = {}
        for index, column in enumerate(header[:len(DEVICE_BASE_COLUMNS)]):
            counts[column] = counts.get(column, 0) + 1
            occurrence = counts[column]
            result[index] = (
                column if occurrence == 1 else f"{column}[{occurrence}]"
            )
        for group_index, start in enumerate(
                layout.vlan_group_starts, start=1):
            for offset, column in enumerate(DEVICE_V2_VLAN_COLUMNS):
                result[start + offset] = f"vlan[{group_index}].{column}"
        for column, index in layout.fixed_indices.items():
            result[index] = column
        for column, index in layout.policy_indices.items():
            result[index] = column
        for group_index, start in enumerate(
                layout.evpn_group_starts, start=1):
            for offset, column in enumerate(DEVICE_V2_EVPN_COLUMNS):
                result[start + offset] = f"evpn[{group_index}].{column}"
        return result

    result = []
    fixed_counts = {}
    evpn_group = 0
    for index, column in enumerate(header):
        if column in METADATA_COLS:
            result.append(None)
            continue
        if index >= FIXED_COLS:
            if column == "evpn_vrf":
                evpn_group += 1
            result.append(f"evpn[{max(evpn_group, 1)}].{column}")
            continue
        fixed_counts[column] = fixed_counts.get(column, 0) + 1
        occurrence = fixed_counts[column]
        result.append(column if occurrence == 1 else f"{column}[{occurrence}]")
    return result


def _normalize_compare_value(value):
    value = "" if value is None else str(value).strip()
    if value.casefold() in {"", "na", "n/a", "none", "null"}:
        return NA
    if value.casefold() in {"true", "false"}:
        return value.upper()
    return value


def _decode_source_config(value):
    """Decode the protected source YAML stored in a generated comparison CSV."""
    value = str(value or "").strip()
    if not value or value == NA:
        return {}
    try:
        if value.startswith(SOURCE_YAML_GZIP_PREFIX):
            payload = base64.b64decode(value[len(SOURCE_YAML_GZIP_PREFIX):])
            payload = gzip.decompress(payload)
        else:
            payload = base64.b64decode(value)
        document = safe_load_yaml_preserving_mac(payload.decode("utf-8"))
    except (ValueError, OSError, UnicodeDecodeError, yaml.YAMLError):
        return {}
    items = document if isinstance(document, list) else [document]
    merged = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("set"), dict):
            continue
        _deep_merge(merged, normalize_nvue_selectors(item["set"]))
    return merged


def _bond_member_groups(cfg):
    groups = []
    for name, interface in (cfg.get("interface") or {}).items():
        if not isinstance(interface, dict) or interface.get("type") == "peerlink":
            continue
        members = sorted(
            ((interface.get("bond") or {}).get("member") or {}).keys(),
            key=_natural_key,
        )
        if members:
            groups.append("+".join(members))
    return "/".join(sorted(groups, key=_natural_key)) if groups else NA


def _vrr_runtime_signature(cfg):
    """Return stable per-VLAN runtime VRR evidence for semantic comparison.

    Schema v2 deliberately removes VRR IP/MAC from every device row because
    those values are derived from global policy.  The comparison still has to
    detect a switch whose derived runtime value drifted, so this signature is
    computed from the protected source YAML rather than reintroducing editable
    per-device columns.
    """
    entries = []
    for interface_name, interface_cfg in (cfg.get("interface") or {}).items():
        if not isinstance(interface_cfg, dict):
            continue
        raw_vlan = interface_cfg.get("vlan")
        if raw_vlan is None:
            match = re.fullmatch(r"vlan(\d+)", str(interface_name))
            raw_vlan = match.group(1) if match else None
        try:
            vlan_id = int(raw_vlan)
        except (TypeError, ValueError):
            continue
        _svi_ip, svi_prefix, vrr_ip, vrr_mac = svi_vrr_info(
            interface_cfg, cfg, vlan_id,
        )
        if vrr_ip == NA and vrr_mac == NA:
            continue
        vrr_cidr = (
            f"{vrr_ip}/{svi_prefix}"
            if vrr_ip != NA and svi_prefix != NA else vrr_ip
        )
        entries.append(
            f"vlan{vlan_id}:vrr={vrr_cidr};mac={str(vrr_mac).lower()}"
        )
    return "|".join(sorted(entries, key=_natural_key)) if entries else NA


def _mlag_runtime_signature(cfg):
    """Return the normalized device-level MLAG/VXLAN identity contract.

    These values are derived or device-level in schema v2, so equal editable
    CSV columns are not sufficient evidence that the running redundancy
    identity still matches.  Explicit missing markers make a partial runtime
    configuration compare different from a complete one.
    """
    paths = (
        ("mlag.mac-address", ("mlag", "mac-address"), "mac"),
        (
            "nve.vxlan.mlag.shared-address",
            ("nve", "vxlan", "mlag", "shared-address"),
            "ip",
        ),
        (
            "system.global.anycast-mac",
            ("system", "global", "anycast-mac"),
            "mac",
        ),
    )
    observed = [(_path_get(cfg, *path), kind) for _label, path, kind in paths]
    if not any(value not in (None, "") for value, _kind in observed):
        return NA

    entries = []
    for (label, _path, _kind), (value, kind) in zip(paths, observed):
        if value in (None, ""):
            normalized = "<missing>"
        else:
            normalized = str(value).strip()
            if kind == "mac":
                normalized = normalized.casefold().replace("-", ":")
            elif kind == "ip":
                try:
                    normalized = str(ipaddress.ip_address(normalized))
                except ValueError:
                    # Preserve invalid runtime evidence verbatim so comparison
                    # reports it instead of normalizing it away.
                    pass
        entries.append(f"{label}={normalized}")
    return "|".join(entries)


def _vrf_reference_integrity(cfg):
    """Validate internal VRF references while allowing VRF names to differ."""
    declared = set((cfg.get("vrf") or {}).keys()) | {"default", "mgmt"}
    unresolved = []
    for name, interface in (cfg.get("interface") or {}).items():
        if not isinstance(interface, dict):
            continue
        vrf = interface.get("vrf")
        if vrf and vrf not in declared:
            unresolved.append(f"interface.{name}={vrf}")
    system = cfg.get("system") or {}
    ntp_vrf = (system.get("ntp") or {}).get("vrf")
    if ntp_vrf and ntp_vrf not in declared:
        unresolved.append(f"system.ntp={ntp_vrf}")
    docker_vrf = (system.get("docker") or {}).get("vrf")
    if docker_vrf and docker_vrf not in declared:
        unresolved.append(f"system.docker={docker_vrf}")
    for server, attributes in ((system.get("dns") or {}).get("server") or {}).items():
        vrf = attributes.get("vrf") if isinstance(attributes, dict) else None
        if vrf and vrf not in declared:
            unresolved.append(f"system.dns.{server}={vrf}")
    return "OK" if not unresolved else ";".join(sorted(unresolved, key=_natural_key))


def read_comparison_csv(path):
    """Return hostname rows and ordered semantic fields from a generated CSV."""
    with Path(path).open(newline="", encoding="utf-8-sig") as stream:
        rows = list(csv.reader(stream))
    if not rows:
        raise ValueError(f"CSV 为空: {path}")
    semantic = _semantic_headers(rows[0])
    try:
        parse_device_csv_layout(rows[0], 2)
    except ValueError:
        schema_v2 = False
    else:
        schema_v2 = True
    try:
        hostname_index = rows[0].index("hostname")
    except ValueError as exc:
        raise ValueError(f"CSV 缺少 hostname 列: {path}") from exc

    devices = {}
    ordered_fields = [field for field in semantic if field and field != "hostname"]
    synthetic_fields = [
        "bond_member_groups", "vrf_reference_integrity",
        "vrr_runtime_signature",
    ]
    if schema_v2:
        synthetic_fields.append("mlag_runtime_signature")
    for synthetic in synthetic_fields:
        if synthetic not in ordered_fields:
            ordered_fields.append(synthetic)
    source_index = (rows[0].index(SOURCE_YAML_COL)
                    if SOURCE_YAML_COL in rows[0] else None)
    for raw in rows[1:]:
        raw += [""] * (len(rows[0]) - len(raw))
        hostname = raw[hostname_index].strip()
        if not hostname:
            continue
        fields = {
            field: _normalize_compare_value(raw[index])
            for index, field in enumerate(semantic)
            if field and field != "hostname"
        }
        # VRF and bond labels are project-local names. Their semantics are
        # compared through vrf_reference_integrity and bond_member_groups.
        for field in fields:
            if re.fullmatch(r"evpn\[\d+\]\.evpn_vrf", field):
                fields[field] = "<ignored-name>"
            elif field == "bond_ports":
                fields[field] = "<ignored-name>"
        cfg = _decode_source_config(raw[source_index]) if source_index is not None else {}
        fields["bond_member_groups"] = _bond_member_groups(cfg) if cfg else NA
        fields["vrf_reference_integrity"] = _vrf_reference_integrity(cfg) if cfg else NA
        fields["vrr_runtime_signature"] = _vrr_runtime_signature(cfg) if cfg else NA
        if schema_v2:
            fields["mlag_runtime_signature"] = (
                _mlag_runtime_signature(cfg) if cfg else NA
            )
        devices[hostname] = fields
    return devices, ordered_fields


def _device_aliases(hostname, fields):
    aliases = [("hostname", hostname.casefold())]
    mac = str(fields.get("eth0_mac", NA)).strip().casefold()
    if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        aliases.insert(0, ("eth0_mac", mac))

    # DHCP is an address-acquisition mode, not a device identity.  Treating
    # every "dhcp-client" row as the same eth0_ip merges unrelated devices and
    # hides their differences in the comparison report.
    address = str(fields.get("eth0_ip", NA)).strip().casefold()
    try:
        ip = (ipaddress.ip_interface(address).ip
              if "/" in address else ipaddress.ip_address(address))
    except ValueError:
        pass
    else:
        aliases.insert(0, ("eth0_ip", str(ip)))
    return aliases


def build_device_groups(datasets):
    """Align renamed devices by eth0 MAC, then eth0 IP, then hostname."""
    groups = []
    alias_to_group = {}
    for dataset_index, dataset in enumerate(datasets):
        for hostname, fields in dataset.items():
            aliases = _device_aliases(hostname, fields)
            matching = {alias_to_group[alias] for alias in aliases
                        if alias in alias_to_group}
            if matching:
                group_index = min(matching)
                # Alias collisions are unusual, but merge safely if a MAC and
                # IP independently connected two previously created groups.
                for old_index in sorted(matching - {group_index}, reverse=True):
                    groups[group_index].update(groups[old_index])
                    groups[old_index].clear()
                    for alias, index in list(alias_to_group.items()):
                        if index == old_index:
                            alias_to_group[alias] = group_index
            else:
                group_index = len(groups)
                groups.append({})
            groups[group_index][dataset_index] = (hostname, fields)
            for alias in aliases:
                alias_to_group[alias] = group_index
    return [group for group in groups if group]


def analyze_comparison(csv_paths, labels):
    """Return N-way device summaries and raw field comparisons without files."""
    datasets = []
    field_order = []
    seen_fields = set()
    for path in csv_paths:
        devices, fields = read_comparison_csv(path)
        datasets.append(devices)
        for field in fields:
            if field not in seen_fields:
                seen_fields.add(field)
                field_order.append(field)

    detail_rows = []
    summary_rows = []
    groups = build_device_groups(datasets)
    groups.sort(key=lambda group: next(iter(group.values()))[0].casefold())
    for group in groups:
        hostname = next(
            (group[index][0] for index in range(len(datasets)) if index in group),
            next(iter(group.values()))[0],
        )
        identity = hostname.casefold()
        for identity_field in ("eth0_mac", "eth0_ip"):
            candidate = next((entry[1].get(identity_field, NA)
                              for entry in group.values()
                              if entry[1].get(identity_field, NA) != NA), None)
            if candidate:
                identity = f"{identity_field}:{candidate.casefold()}"
                break
        missing = [labels[index] for index in range(len(datasets)) if index not in group]
        dataset_hostnames = [group[index][0] if index in group else "MISSING"
                             for index in range(len(datasets))]
        same_count = different_count = 0
        present_count = len(group)
        if present_count == 1:
            values = ["PRESENT" if index in group else "MISSING"
                      for index in range(len(datasets))]
            detail_rows.append({
                "hostname": hostname, "field": "__device__",
                "identity": identity, "status": "missing_device",
                "values": dict(zip(labels, values)),
            })
            overall = "missing_device"
        else:
            if len(set(value for value in dataset_hostnames if value != "MISSING")) > 1:
                detail_rows.append({
                    "hostname": hostname, "field": "hostname",
                    "identity": identity,
                    "status": "partial_different" if missing else "different",
                    "values": dict(zip(labels, dataset_hostnames)),
                })
                different_count += 1
            for field in field_order:
                values = [group[index][1].get(field, NA) if index in group else "MISSING"
                          for index in range(len(datasets))]
                present_values = [value for value in values if value != "MISSING"]
                if all(value == NA for value in present_values):
                    continue
                equal = len(set(present_values)) == 1
                if missing:
                    status = "partial_same" if equal else "partial_different"
                else:
                    status = "same" if equal else "different"
                if equal:
                    same_count += 1
                else:
                    different_count += 1
                detail_rows.append({
                    "hostname": hostname, "field": field, "identity": identity,
                    "status": status,
                    "values": dict(zip(labels, values)),
                })
            if missing:
                overall = "partial_different" if different_count else "partial_same"
            else:
                overall = "different" if different_count else "same"
        summary_rows.append({
            "hostname": hostname, "overall": overall,
            "same_fields": same_count, "different_fields": different_count,
            "missing_datasets": missing,
            "dataset_hostnames": dict(zip(labels, dataset_hostnames)),
        })
    return {"labels": list(labels), "details": detail_rows, "summary": summary_rows}


REPORT_STATE_BEGIN = "<!-- YAML_COMPARE_STATE_BEGIN"
REPORT_STATE_END = "YAML_COMPARE_STATE_END -->"


def _issue_suggestion(field):
    field_lower = field.casefold()
    if field == "__device__":
        return "确认设备是否应生成专用 YAML；若设计上使用 default.yaml，应在项目策略中明确标记为 Warning。"
    if field == "hostname":
        return "核对 inventory、设备 YAML 与备份命名；如只是环境前缀变化，可保留管理 IP/MAC 对齐并统一命名规则。"
    if (field_lower.startswith("evpn[")
            and any(token in field_lower for token in ("svi", "vrr", "l2", "vlan_ports", "netmask"))):
        return "核对 VLAN 范围展开、SVI/VRR 成对校验和设备级字段；重新生成后检查对应 NVUE interface/vlan。"
    if any(token in field_lower for token in ("svi", "vrr", "vlan")):
        return "核对 VLAN 范围展开、SVI/VRR 成对校验和设备级字段；重新生成后检查对应 NVUE interface/vlan。"
    if any(token in field_lower for token in ("eth0_", "netmask", "gateway")):
        return "核对 02-devices_config.csv、DHCP 地址和管理接口生成逻辑，避免管理连接或 ZTP 地址漂移。"
    if field == "bond_member_groups":
        return "bond 名称已忽略；请核对 02-devices_config.csv 的 bond_ports 及实际 YAML 成员口，确保每组成员完全一致。"
    if "bond" in field_lower or "peerlink" in field_lower:
        return "核对 bond_type、成员端口及模板覆盖优先级；multihoming 设备不应残留 MLAG 配置。"
    if any(token in field_lower for token in ("evpn", "bgp", "vrf")):
        return "核对 01-global.yaml 与 devices_config 的 VRF/VNI/BGP 字段，并检查同名 VRF 一致性校验。"
    if "template" in field_lower:
        return "确认所有 eth/spx 设备已指定正确模板，并检查设备级配置是否按预期覆盖模板默认值。"
    return "回到对应 YAML 路径定位生成来源，核对 global、devices_config 和模板优先级后重新生成验证。"


def _issue_severity(field):
    lower = field.casefold()
    if field == "__device__" or any(token in lower for token in ("eth0_", "svi", "vrr", "evpn", "bgp", "bond")):
        return "high"
    if field == "hostname" or "template" in lower:
        return "medium"
    return "low"


def comparison_issues(analysis):
    """Convert current differences into stable issues for cross-run tracking."""
    issues = []
    for detail in analysis["details"]:
        if detail["status"] in {"same", "partial_same"}:
            continue
        identity = detail.get("identity", detail["hostname"].casefold())
        stable = json.dumps(
            [identity, detail["field"]],
            ensure_ascii=False, separators=(",", ":"),
        )
        issue_id = hashlib.sha256(stable.encode("utf-8")).hexdigest()[:16]
        issues.append({
            "id": issue_id, "hostname": detail["hostname"],
            "identity": identity, "field": detail["field"],
            "status": detail["status"], "severity": _issue_severity(detail["field"]),
            "values": detail["values"], "suggestion": _issue_suggestion(detail["field"]),
        })
    return sorted(issues, key=_issue_sort_key)


def _issue_sort_key(issue):
    """Sort report issues by natural hostname, severity, then field."""
    severity_order = {"high": 0, "medium": 1, "low": 2}
    return (
        _natural_key(issue.get("hostname", "")),
        severity_order.get(str(issue.get("severity", "")).casefold(), 99),
        _natural_key(issue.get("field", "")),
        issue.get("id", ""),
    )


def load_previous_report(output_dir, report_type=None):
    pattern = f"report-{report_type}-*.md" if report_type else "report-*.md"
    reports = sorted(Path(output_dir).glob(pattern))
    if not reports:
        return None, {"issues": []}
    path = reports[-1]
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(
        re.escape(REPORT_STATE_BEGIN) + r"\s*(.*?)\s*" + re.escape(REPORT_STATE_END),
        text, re.S,
    )
    if not match:
        return path, {"issues": []}
    try:
        state = json.loads(match.group(1))
    except json.JSONDecodeError:
        state = {"issues": []}
    return path, state


def _md(value):
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def write_report(analysis, csv_paths, sources, output_dir, report_type=None):
    """Write a timestamped Markdown report and embed state for the next run."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    tracker_index = Path(__file__).resolve().parent / "issue-tracker" / "README.md"
    previous_path, previous_state = load_previous_report(output_dir, report_type)
    current_issues = comparison_issues(analysis)
    previous_by_id = {issue["id"]: issue for issue in previous_state.get("issues", [])}
    current_by_id = {issue["id"]: issue for issue in current_issues}
    fixed = sorted(
        (previous_by_id[key] for key in previous_by_id.keys() - current_by_id.keys()),
        key=_issue_sort_key,
    )
    remaining = sorted(
        (current_by_id[key] for key in current_by_id.keys() & previous_by_id.keys()),
        key=_issue_sort_key,
    )
    new = sorted(
        (current_by_id[key] for key in current_by_id.keys() - previous_by_id.keys()),
        key=_issue_sort_key,
    )

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    report_prefix = f"report-{report_type}" if report_type else "report"
    report_path = output_dir / f"{report_prefix}-{timestamp}.md"
    counter = 2
    while report_path.exists():
        report_path = output_dir / f"{report_prefix}-{timestamp}-{counter}.md"
        counter += 1

    lines = [
        f"# YAML 配置比较报告 — {timestamp}", "",
        f"- 数据类型：{report_type.upper()}" if report_type else "- 数据类型：自定义",
        f"- 比较方式：{len(analysis['labels'])} 方比较",
        f"- 上次报告：`{previous_path}`" if previous_path else "- 上次报告：无（本次建立基线）",
        f"- 当前问题：{len(current_issues)}",
        f"- 上次以来已修复：{len(fixed)}",
        f"- 仍然存在：{len(remaining)}",
        f"- 本次新发现：{len(new)}",
        f"- Issue tracker：`{tracker_index}`", "",
        "## 原始数据", "",
        "| 数据集 | 输入 | 生成的 CSV |", "|---|---|---|",
    ]
    for label, source, csv_path in zip(analysis["labels"], sources, csv_paths):
        lines.append(f"| {_md(label)} | `{_md(source)}` | `{_md(csv_path)}` |")

    def add_issue_section(title, entries, fixed_section=False):
        lines.extend(["", f"## {title}", ""])
        if not entries:
            lines.append("无。")
            return
        lines.extend(["| ID | 严重性 | 设备 | 字段 | 各数据集原值 | 建议修复方案 |",
                      "|---|---|---|---|---|---|"])
        for issue in entries:
            values = " ; ".join(f"{key}={value}" for key, value in issue.get("values", {}).items())
            recommendation = ("无需继续修改；保留该项作为后续回归检查依据。"
                              if fixed_section else issue.get("suggestion", ""))
            lines.append(
                f"| `{issue['id']}` | {_md(issue.get('severity', ''))} | "
                f"{_md(issue.get('hostname', ''))} | `{_md(issue.get('field', ''))}` | "
                f"{_md(values)} | {_md(recommendation)} |"
            )

    add_issue_section("已修复问题", fixed, fixed_section=True)
    add_issue_section("仍然存在的问题", remaining)
    add_issue_section("本次新发现的问题", new)

    lines.extend(["", "## 设备对齐与比较汇总", "",
                  "| 设备 | 总体状态 | 相同字段 | 不同字段 | 缺少的数据集 | 各数据集 hostname |",
                  "|---|---|---:|---:|---|---|"])
    for row in analysis["summary"]:
        mapped = " ; ".join(f"{key}={value}" for key, value in row["dataset_hostnames"].items())
        lines.append(
            f"| {_md(row['hostname'])} | {_md(row['overall'])} | {row['same_fields']} | "
            f"{row['different_fields']} | {_md(', '.join(row['missing_datasets']))} | {_md(mapped)} |"
        )

    lines.extend(["", "## 原始差异数据", "",
                  "上方列出的各来源 CSV 保存完整提取数据；下表保留每一个不同字段的原始值。", "",
                  "| 设备 | 字段 | 状态 | " + " | ".join(map(_md, analysis["labels"])) + " |",
                  "|---|---|---|" + "---|" * len(analysis["labels"])])
    for detail in analysis["details"]:
        if detail["status"] in {"same", "partial_same"}:
            continue
        values = [detail["values"].get(label, "MISSING") for label in analysis["labels"]]
        lines.append(
            f"| {_md(detail['hostname'])} | `{_md(detail['field'])}` | {_md(detail['status'])} | "
            + " | ".join(_md(value) for value in values) + " |"
        )

    state = {
        "version": 1, "timestamp": timestamp, "labels": analysis["labels"],
        "report_type": report_type, "issues": current_issues,
    }
    lines.extend(["", REPORT_STATE_BEGIN,
                  json.dumps(state, ensure_ascii=False, indent=2), REPORT_STATE_END, ""])
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path, {"fixed": fixed, "remaining": remaining, "new": new,
                         "current": current_issues, "previous": previous_path}


def _unique_labels(sources):
    labels = []
    counts = {}
    for source in sources:
        base = source_label(source)
        counts[base] = counts.get(base, 0) + 1
        labels.append(base if counts[base] == 1 else f"{base}-{counts[base]}")
    return labels


def sample_inventory_for_source(
        prepared_sample, source, explicit_path=None, requested_type="prod"):
    """Select the unified inventory; conversion filters it by requested type."""
    if explicit_path:
        return explicit_path
    if not prepared_sample:
        return None
    candidate = Path(prepared_sample) / "02-devices_config.csv"
    return str(candidate) if candidate.is_file() else None


def prepare_sample_inputs(raw_inputs):
    """Refresh the applicable sample directory before conversion/comparison."""
    http_base = Path(__file__).resolve().parents[2]
    day0_prepare = http_base / "DAY0-Prepare"
    optimize_dir = Path(__file__).resolve().parent
    candidates = [Path(value).expanduser().absolute() for value in raw_inputs]
    project = None
    selected = candidates[0] if len(candidates) == 1 else None
    for path in candidates:
        project = project_from_sample_path(path, day0_prepare)
        if project:
            break
        if ((path / "02-devices_config.csv").is_file()
                and (path / "99-output-eth").is_dir()):
            project = path.resolve()
            break
        resolved = path.resolve()
        current = resolved if resolved.is_dir() else resolved.parent
        for directory in (current, *current.parents):
            if ((directory / "02-devices_config.csv").is_file()
                    and (directory / "99-output-eth").is_dir()):
                project = directory.resolve()
                break
        if project:
            break
    if project is None and not candidates:
        active_output = http_base / "ztp" / "config" / "cumulus" / "template" / "99-output"
        if active_output.is_dir():
            resolved = active_output.resolve()
            possible_project = resolved.parent
            if (possible_project / "02-devices_config.csv").is_file():
                project = possible_project
    if project is None:
        return candidates, None

    print(f"准备比较样例: {project.name}")
    sample = update_sample_links(optimize_dir, project)
    if not candidates or (selected and (
            selected.resolve() == project.resolve()
            or selected.name == f"{project.name}-sample")):
        candidates = [sample.absolute()]
    return candidates, sample


def main(argv=None):
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(
        description=("将 NVUE YAML/采集归档转换成 CSV；也可对目录中的2到5个"
                     "配置来源执行逐设备、逐字段比较")
    )
    parser.add_argument(
        "inputs", nargs="*", metavar="INPUT",
        help=("一个 YAML/INFO/目录/归档用于转换；2到5个来源用于比较；"
              "包含2到5个来源的目录会自动进入比较模式"),
    )
    parser.add_argument(
        "-o", "--output",
        help="单来源模式的输出 CSV；比较模式请使用 --output-dir",
    )
    parser.add_argument(
        "--output-dir",
        help="比较模式的来源 CSV 和时间戳报告输出目录；默认使用比较目录",
    )
    parser.add_argument("--compare", action="store_true",
                        help="强制按比较容器解析单个目录参数")
    parser.add_argument(
        "--air", action="store_true",
        help=("比较 AIR 数据：config-backup-air、monitor-air 和 generated；"
              "等价于 --type air"),
    )
    parser.add_argument(
        "--prod", action="store_true",
        help="只处理 Production 数据；等价于 --type prod",
    )
    parser.add_argument(
        "--type", choices=("all", "prod", "air"), dest="comparison_type",
        help=("自动比较的数据类型；sample/项目模式默认 all，分别生成 Production "
              "与 AIR 报告；prod/air 只处理指定环境"),
    )
    parser.add_argument("--format", dest="format_path", help="显式指定 CSV 格式文件")
    parser.add_argument(
        "--devices-config", dest="devices_config_path",
        help="显式指定用于补全 hostname/type/管理地址/MAC 的 devices_config CSV",
    )
    parser.add_argument(
        "--global-config", dest="global_config_path",
        help="显式指定用于补全缺失全局字段的 01-global.yaml/global.yaml",
    )
    args = parser.parse_args(raw_argv)
    if args.air and args.comparison_type not in {None, "air"}:
        parser.error("--air 不能与 --type prod 同时使用")
    if args.prod and args.comparison_type not in {None, "prod"}:
        parser.error("--prod 不能与 --type air 同时使用")
    if args.air and args.prod:
        parser.error("--air 与 --prod 不能同时使用")
    requested_type = (
        "air" if args.air else "prod" if args.prod else (args.comparison_type or "all")
    )

    try:
        inputs, prepared_sample = prepare_sample_inputs(args.inputs)
    except (OSError, ValueError) as exc:
        parser.error(f"准备 sample 链接失败: {exc}")
    if requested_type == "all" and prepared_sample:
        base_output = (Path(args.output_dir).expanduser().absolute()
                       if args.output_dir
                       else prepared_sample / LINK_NAMES["comparison_output"])
        forwarded = []
        index = 0
        while index < len(raw_argv):
            token = raw_argv[index]
            if token in {"--air", "--prod"} or token.startswith("--type="):
                index += 1
                continue
            if token == "--type":
                index += 2
                continue
            if token.startswith("--output-dir="):
                index += 1
                continue
            if token == "--output-dir":
                index += 2
                continue
            forwarded.append(token)
            index += 1
        statuses = []
        for environment in ("prod", "air"):
            print(f"\n{'=' * 20} {environment.upper()} 独立比较 {'=' * 20}\n")
            statuses.append(main(
                forwarded + ["--type", environment, "--output-dir",
                             str(base_output / environment)]
            ))
        return max(statuses)
    if requested_type == "all":
        # A standalone YAML/archive has no second inventory. Preserve the
        # useful one-source conversion behavior and treat it as Production.
        requested_type = "prod"
    discovered_container = None
    if len(inputs) == 1 and inputs[0].is_dir():
        discovered = discover_comparison_sources(inputs[0])
        discovered = select_managed_comparison_sources(discovered, requested_type)
        if args.compare or len(discovered) >= 2:
            inputs = discovered
            discovered_container = Path(args.inputs[0]).expanduser().absolute()
        elif prepared_sample and len(discovered) == 1:
            # A sample directory can legitimately expose only one available
            # source. Convert that source directly instead of scanning the
            # sample container (rglob does not traverse directory symlinks).
            inputs = discovered
    elif args.compare:
        parser.error("--compare 配合单个目录使用，或直接提供2到5个来源")

    comparison_mode = len(inputs) >= 2
    if comparison_mode:
        if args.output:
            parser.error("比较模式不使用 -o/--output，请改用 --output-dir")
        if not 2 <= len(inputs) <= 5:
            parser.error(f"比较模式要求 2 到 5 个来源，实际发现 {len(inputs)} 个")
        missing = [str(path) for path in inputs if not path.exists()]
        if missing:
            parser.error("输入不存在或软链接失效: " + ", ".join(missing))
        labels = _unique_labels(inputs)
        effective_global_config = args.global_config_path
        if not effective_global_config and prepared_sample:
            sample_global = prepared_sample / "01-global.yaml"
            if sample_global.is_file():
                effective_global_config = str(sample_global)
        if args.output_dir:
            output_dir = Path(args.output_dir).expanduser().absolute()
        elif prepared_sample:
            output_dir = (
                prepared_sample / LINK_NAMES["comparison_output"] / requested_type
            )
        elif discovered_container:
            output_dir = discovered_container
        elif len({path.parent for path in inputs}) == 1:
            output_dir = inputs[0].parent
        else:
            output_dir = Path.cwd()
        output_dir.mkdir(parents=True, exist_ok=True)

        print(f"比较模式    : {len(inputs)} 方")
        generated = []
        try:
            for label, source in zip(labels, inputs):
                destination = output_dir / f"{label}.csv"
                source_devices_config = sample_inventory_for_source(
                    prepared_sample, source, args.devices_config_path,
                    requested_type=requested_type,
                )
                print(f"\n── 数据集 {label} ─────────────────────────────────────────────")
                if source.suffix.casefold() == ".csv":
                    if source.resolve() != destination.resolve():
                        shutil.copy2(source, destination)
                        print(f"复用 CSV     : {source} → {destination}")
                    else:
                        print(f"复用 CSV     : {source}")
                    source_global = source.with_name(f"{source.stem}-global.yaml")
                    destination_global = destination.with_name(
                        f"{destination.stem}-global.yaml"
                    )
                    if source_global.is_file():
                        if source_global.resolve() != destination_global.resolve():
                            shutil.copy2(source_global, destination_global)
                        print(f"复用全局信息 : {source_global} → {destination_global}")
                    else:
                        generated_global = write_global_yaml(
                            destination, [], effective_global_config,
                        )
                        print(f"全局信息   : CSV 无设备 YAML，使用 global 基线 → {generated_global}")
                    generated.append(destination)
                else:
                    generated.append(convert_one(
                        source, destination, args.format_path,
                        source_devices_config, yaml_only=True,
                        global_config_path=effective_global_config,
                        environment_scope=requested_type,
                    ))
            analysis = analyze_comparison(generated, labels)
            report, lifecycle = write_report(
                analysis, generated, inputs, output_dir,
                report_type=requested_type,
            )
        except ValueError as exc:
            parser.error(str(exc))
        print(f"\n比较报告    : {report}")
        print(f"问题状态    : 已修复 {len(lifecycle['fixed'])}，"
              f"仍存在 {len(lifecycle['remaining'])}，新增 {len(lifecycle['new'])}")
        return 0

    if args.compare:
        parser.error("目录中未发现2到5个可比较的配置来源")
    if len(inputs) > 1:
        parser.error("只能提供一个转换来源，或者两个/三个比较来源")
    try:
        effective_global_config = args.global_config_path
        effective_devices_config = sample_inventory_for_source(
            prepared_sample, inputs[0] if inputs else None,
            args.devices_config_path,
            requested_type=requested_type,
        )
        if not effective_global_config and prepared_sample:
            sample_global = prepared_sample / "01-global.yaml"
            if sample_global.is_file():
                effective_global_config = str(sample_global)
        single_output = args.output
        single_output_dir = None
        if not single_output and args.output_dir and inputs:
            # ``all`` recursively supplies an environment-specific output-dir.
            # A scope with only one available source is still a comparison
            # artifact; keep its CSV/global YAML in comparison/<scope>/ rather
            # than recreating duplicate files beside the sample symlink.
            single_output_dir = Path(args.output_dir).expanduser().absolute()
        elif not single_output and prepared_sample and inputs:
            single_output_dir = (
                prepared_sample / LINK_NAMES["comparison_output"] / requested_type
            )
        if single_output_dir is not None:
            single_output_dir.mkdir(parents=True, exist_ok=True)
            single_output = str(
                single_output_dir / f"{source_label(inputs[0])}.csv"
            )
        convert_one(
            inputs[0] if inputs else None,
            single_output, args.format_path, effective_devices_config,
            global_config_path=effective_global_config,
            environment_scope=requested_type,
        )
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
