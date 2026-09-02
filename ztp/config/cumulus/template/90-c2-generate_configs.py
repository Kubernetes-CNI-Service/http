#!/usr/bin/env python3
"""
合并脚本：根据脚本所在路径自动判断分支，生成 ETH 或 IB 交换机的 NVUE/NVOS YAML 配置。

ETH 分支（cumulus/template/）：
  读取 02-devices_config.csv + 01-global.yaml，经由 Jinja2 模板生成每台 eth 设备的 YAML，
  中间产物 91-devices.yaml，支持 EVPN/MLAG/bond 解析、patch_descriptions、air_configs。

IB 分支（nvos/template/）：
  读取 02-devices_config.csv + 01-global.yaml，直接构建 NVOS YAML（无 Jinja2），
  处理 type==ib 和 type==nvl 的行。

用法：
  python3 90-c2-generate_configs.py [-y] [--csv=PATH] [--verify] [--ref-dir=DIR]
                                  [--fail-on-diff] [HOSTNAME]

输出目录：
  ETH  → 99-output/<timestamp>/
  NVOS → 99-output-ib_nvl/<timestamp>-{ib,nvl}/
"""

# ── Imports (union of both scripts) ──────────────────────────────────────────
import base64
import binascii
import copy
import csv
import difflib
import fnmatch
import glob
import gzip
import hashlib
import ipaddress
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import shutil
import sys
import yaml
from datetime import datetime

try:
    from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateNotFound
    _HAS_JINJA2 = True
except ImportError:
    _HAS_JINJA2 = False

# 兼容旧版未压缩 source_yaml_b64；新文件使用 gzip+Base64 并限制单元格长度。
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

# ── Common constants ──────────────────────────────────────────────────────────

_AUTO_YES = False  # 由 -y 参数设置
_EXCLUDED_CONFIG_TYPES = frozenset({"air"})
_SAFE_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
_SAFE_AAA_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_EXPECTED_DEVICE_HEADER_PREFIX = (
    "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw",
    "eth0_mac", "eth1_ip", "netmask", "eth1_gw", "eth1_mac",
)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _parse_branch(argv):
    """Return an explicit/inferred network branch and argv without that option."""
    remaining = []
    explicit = None
    index = 0
    while index < len(argv):
        value = argv[index]
        if value.startswith("--branch="):
            explicit = value.split("=", 1)[1]
        elif value == "--branch":
            index += 1
            if index >= len(argv):
                raise SystemExit("[ERROR] --branch requires eth or ib")
            explicit = argv[index]
        else:
            remaining.append(value)
        index += 1
    if explicit is not None:
        if explicit not in {"eth", "ib"}:
            raise SystemExit(f"[ERROR] unsupported --branch={explicit!r}; use eth or ib")
        return explicit, remaining
    normalized = SCRIPT_DIR.replace(os.sep, "/").rstrip("/")
    if normalized.endswith("/config/cumulus/template"):
        return "eth", remaining
    if normalized.endswith("/config/nvos/template"):
        return "ib", remaining
    raise SystemExit(
        "[ERROR] cannot infer generator branch outside config/cumulus/template or "
        "config/nvos/template; pass --branch eth|ib"
    )


_BRANCH, _SCRIPT_ARGS = _parse_branch(sys.argv[1:])
P2P_INPUT_DIR = os.path.join(SCRIPT_DIR, "P2P")
P2P_OUTPUT_DIR = os.path.join(P2P_INPUT_DIR, "output-p2p")

_CSV_FILE    = os.path.join(SCRIPT_DIR, "02-devices_config.csv")
_GLOBAL_FILE = os.path.join(SCRIPT_DIR, "01-global.yaml")
_TS          = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_DIR     = os.path.join(SCRIPT_DIR, "99-output",     _TS)
OUTPUT_IB_NVL_ROOT = os.path.join(SCRIPT_DIR, "99-output-ib_nvl")
OUTPUT_IB_DIR  = os.path.join(OUTPUT_IB_NVL_ROOT, f"{_TS}-ib")
OUTPUT_NVL_DIR = os.path.join(OUTPUT_IB_NVL_ROOT, f"{_TS}-nvl")

# ETH-only constants
DEVICES_FILE  = os.path.join(SCRIPT_DIR, "91-devices.yaml")
TEMPLATES_DIR = os.path.join(SCRIPT_DIR, "03-templates-j2")


# ── Common helpers ────────────────────────────────────────────────────────────

def _timed_input(prompt, timeout=10, default=""):
    """Print prompt and wait up to timeout seconds for input.
    Returns default if no input arrives within the timeout.
    -y 模式下直接返回 default，不等待。
    """
    if _AUTO_YES:
        sys.stdout.write(prompt + f"{default}（-y 模式自动确认）\n")
        sys.stdout.flush()
        return default
    sys.stdout.write(prompt)
    sys.stdout.flush()
    try:
        ready, _, _ = select.select([sys.stdin], [], [], timeout)
    except (OSError, ValueError):
        print(f"\n（{timeout}s 内无输入，使用默认值：{default!r}）")
        return default
    if ready:
        try:
            line = sys.stdin.readline()
            return line.rstrip("\n") if line else default
        except EOFError:
            return default
    print(f"\n（{timeout}s 内无输入，使用默认值：{default!r}）")
    return default


def _deep_merge(base, override):
    """递归合并两个 dict，override 的值优先；非 dict 值直接覆盖。"""
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def _exclude_config_type(device_type):
    """Return True for CSV rows that must never produce device configs."""
    return (device_type or "").strip().casefold() in _EXCLUDED_CONFIG_TYPES


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate keys instead of overwriting."""


def _construct_unique_mapping(loader, node, deep=False):
    seen = {}
    for key_node, _value_node in node.value:
        # YAML merge keys have their own override rules.  Literal keys in the
        # source mapping are still checked before SafeLoader expands merges.
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
        key = loader.construct_object(key_node, deep=deep)
        try:
            first_mark = seen.get(key)
        except TypeError:
            first_mark = None
        if first_mark is not None:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}; first defined at line "
                f"{first_mark.line + 1}",
                key_node.start_mark,
            )
        try:
            seen[key] = key_node.start_mark
        except TypeError:
            # Let SafeLoader produce its standard error for unhashable keys.
            pass
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _load_generated_yaml(text):
    """Parse generated YAML safely and fail on any same-level duplicate key."""
    return yaml.load(text, Loader=_UniqueKeyLoader)


def _validate_yaml_directory(directory):
    """Strictly validate every generated YAML file before publishing it."""
    errors = []
    for path in sorted(glob.glob(os.path.join(directory, "*.yaml"))):
        try:
            with open(path, encoding="utf-8") as stream:
                _load_generated_yaml(stream.read())
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            errors.append(f"{os.path.basename(path)}: {exc}")
    return errors


def _validate_final_yaml_outputs(*directories):
    """Validate final (including patched) output directories or abort safely."""
    failures = []
    checked = 0
    for directory in directories:
        if not directory or not os.path.isdir(directory):
            continue
        checked += 1
        for detail in _validate_yaml_directory(directory):
            failures.append((directory, detail))
    if failures:
        for directory, detail in failures:
            print(
                f"[ERROR] 最终 YAML 严格校验失败 "
                f"({os.path.basename(directory)})：{detail}"
            )
        for directory in {item[0] for item in failures}:
            shutil.rmtree(directory, ignore_errors=True)
            print(f"[CLEAN] 已删除无效输出目录：{directory}")
        raise ValueError("最终 YAML 存在重复 key 或语法错误，拒绝保留和发布")
    if checked:
        print(f"[OK] 最终 YAML 严格校验通过：{checked} 个输出目录")


def load_global(section_key=None):
    """加载 01-global.yaml，支持合并格式（switches 列表），按 section_key 提取对应区段。

    section_key 默认根据分支自动判断（eth 分支 → "eth"，ib 分支 → "ib"）。
    IB 分支可显式传入 "ib" 或 "nvl" 以加载对应区段。
    """
    try:
        with open(_GLOBAL_FILE, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"[ERROR] 找不到配置文件: {_GLOBAL_FILE}"); sys.exit(1)
    except yaml.YAMLError as e:
        print(f"[ERROR] {_GLOBAL_FILE} YAML 语法错误: {e}"); sys.exit(1)

    if isinstance(data, dict) and "switches" in data:
        if section_key is None:
            section_key = "eth" if _BRANCH == "eth" else "ib"
        section = next((s[section_key] for s in data["switches"]
                        if isinstance(s, dict) and section_key in s), None)
        if section is None:
            print(f"[ERROR] 合并格式 {_GLOBAL_FILE} 缺少 '{section_key}' 部分"); sys.exit(1)
        common = data.get("common", {}).get("switch", {})
        return _deep_merge(common, section) if common else section
    return data


def _refresh_cumulus_defaults_from_global():
    """在生成配置前，用当前项目 global 同步服务端 default*.yaml。

    default YAML 的规范化和原子写入统一由 d-hostname2mac.py 实现，避免
    load、配置生成和最终发布采用三套不同的密码同步规则。
    """
    service_dir = os.path.dirname(SCRIPT_DIR)
    helper_file = os.path.join(service_dir, "d-hostname2mac.py")
    if not os.path.isfile(helper_file):
        raise ValueError(f"未找到默认配置同步模块：{helper_file}")
    spec = importlib.util.spec_from_file_location(
        "cumulus_default_sync_for_generate_configs", helper_file
    )
    if spec is None or spec.loader is None:
        raise ValueError(f"无法加载默认配置同步模块：{helper_file}")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper._refresh_cumulus_defaults(
        service_dir=service_dir,
        global_file=_GLOBAL_FILE,
    )


# ══════════════════════════════════════════════════════════════════════════════
# ETH-only: csv parsing, EVPN, MLAG, template matching
# ══════════════════════════════════════════════════════════════════════════════

_SOURCE_YAML_COL         = "source_yaml_b64"
_SOURCE_SHA256_COL       = "source_yaml_sha256"
_SOURCE_FIELDS_SHA256_COL = "source_fields_sha256"
_SOURCE_YAML_GZIP_PREFIX = "gzip+base64:"

_SIMPLE_TEMPLATES = {"oobofoob-leaf", "oobofoob-spine", "tan-cp-1gleaf"}
_BOND_MARKERS     = {"bond", "mlagbond", "evpnbond"}
_EVPN_COLUMNS = (
    "evpn_vrf", "evpn_l3vni", "evpn_l3vlan", "dhcp_relay",
    "evpn_l2vni", "evpn_l2vlan", "svi_ip", "netmask", "vrr_ip",
    "vrr_mac", "vlan_ports",
)


def _load_devices_template(csv_file):
    """加载低优先级模板默认值；devices_config.csv 中的显式值始终优先。"""
    csv_dir = os.path.dirname(os.path.abspath(csv_file))
    matches = sorted(
        path for path in glob.glob(os.path.join(csv_dir, "*devices_template*.csv"))
        if "deprecated" not in os.path.basename(path).casefold()
    )
    if not matches:
        print(f"[INFO] 未找到 *devices_template*.csv（查找目录: {csv_dir}），"
              f"将使用 CSV 中 template 列的值")
        return {}
    tmpl_file = matches[0]
    print("[WARN] devices_template 独立输入已废弃；请把 template 列合并到 "
          "02-devices_config.csv")
    print(f"[INFO] 加载设备模板映射: {tmpl_file}")
    mapping = {}
    with open(tmpl_file, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            hn = (row.get("hostname") or "").strip()
            tmpl = (row.get("template") or "").strip()
            if hn and tmpl:
                mapping[hn.lower()] = tmpl
    return mapping


def _select_device_template(csv_template, mapped_template):
    """Return the explicit per-device template, falling back to the defaults map."""
    if csv_template and not _csv_na(csv_template):
        return csv_template.strip()
    if mapped_template:
        return mapped_template.strip()
    return None


def _csv_na(val):
    return not val or val.strip().upper() == "NA"

def _csv_to_int(val):
    return int(val.strip())

def _csv_combine_ip(ip, prefix):
    ip = ip.strip(); prefix = prefix.strip()
    if _csv_na(ip) or ip.lower() == "dhcp-client" or _csv_na(prefix):
        return ip
    return f"{ip}/{prefix}"

def _csv_expand_prefixed(spec, prefix, context="", errors=None):
    if _csv_na(spec):
        return []
    items = []
    for group in spec.strip().split("/"):
        group = group.strip()
        if not group:
            continue
        if group == "peerlink.4094" or re.match(r'^(bond\d+)+$', group):
            items.append(group)
            continue
        m = re.match(rf"^{prefix}(\d+)(?:-(\d+))?(?:s(\d+)(?:-(\d+))?)?$", group)
        if m:
            p_start = int(m.group(1)); p_end = int(m.group(2)) if m.group(2) else p_start
            s_start = int(m.group(3)) if m.group(3) else None
            s_end   = int(m.group(4)) if m.group(4) else s_start
            for p in range(p_start, p_end + 1):
                if s_start is not None:
                    for s in range(s_start, s_end + 1):
                        items.append(f"{prefix}{p}s{s}")
                else:
                    items.append(f"{prefix}{p}")
        else:
            msg = (f"  {context}: 无法识别的端口表达式 {group!r} "
                   f"(期望格式: {prefix}N 或 {prefix}N-M 或 {prefix}NsP-Q)")
            if errors is not None:
                errors.append(msg)
            items.append(group)
    return items

def _csv_expand_ports(spec, context="", errors=None):
    return _csv_expand_prefixed(spec, "swp", context, errors)

def _csv_normalize_bond_type(value):
    value = (value or "").strip().lower()
    if value in ("mlag", "mlagbond"):
        return "mlag"
    if value == "localbond":
        return "localbond"
    if value == "evpn_multihoming":
        return "evpn_multihoming"
    raise ValueError(
        f"无法识别的 bond_type {value!r}（支持 localbond、mlagbond、evpn_multihoming）"
    )


def _csv_parse_bond_groups(bond_ports, bond_types, macs, context="", errors=None):
    """Parse aligned ``|``-separated bond profiles.

    A single bond_type/bond_mac remains backward compatible and applies to
    every bond_ports group.  Multiple values must align one-to-one so a device
    can faithfully represent a mix of local, MLAG, and EVPN-MH bonds.
    """
    if _csv_na(bond_ports):
        return []
    port_specs = [part.strip() for part in bond_ports.strip().split("|") if part.strip()]
    type_specs = [part.strip() for part in str(bond_types or "").split("|")]
    mac_specs = [part.strip() for part in str(macs or "").split("|")]
    if len(type_specs) not in (1, len(port_specs)):
        raise ValueError(
            f"bond_type 有 {len(type_specs)} 个分组，bond_ports 有 {len(port_specs)} 个分组"
        )
    if len(mac_specs) not in (1, len(port_specs)):
        raise ValueError(
            f"bond_mac 有 {len(mac_specs)} 个分组，bond_ports 有 {len(port_specs)} 个分组"
        )
    groups = []
    for index, spec in enumerate(port_specs):
        btype = _csv_normalize_bond_type(
            type_specs[index] if len(type_specs) > 1 else type_specs[0]
        )
        mac = mac_specs[index] if len(mac_specs) > 1 else mac_specs[0]
        bl = _csv_expand_prefixed(spec, "bond", context, errors)
        bi = {"type": btype, "bond_list": bl}
        # LACP bypass is the project-wide default for every bond type.  This
        # keeps a host-facing link usable while its peer has not formed LACP.
        bi["lacp-bypass"] = "enabled"
        if not _csv_na(mac):
            bi["mac-address"] = mac
        groups.append(bi)
    return groups

def _csv_to_int_opt(val):
    return None if _csv_na(val) else int(val.strip())


def _csv_parse_numeric_selector(val, *, field, minimum, maximum):
    """Parse one number, ranges, or slash/comma-separated selectors."""
    if _csv_na(val):
        return None, "", []
    values = []
    for token in re.split(r'[/,]', val.strip()):
        token = token.strip()
        match = re.fullmatch(r'(\d+)(?:-(\d+))?', token)
        if not match:
            raise ValueError(
                f"{field} 格式无效：{val!r}（支持单值、范围及 / 或 , 分隔组合）"
            )
        start = int(match.group(1))
        end = int(match.group(2) or start)
        if start > end:
            raise ValueError(f"{field} 范围起点大于终点：{token!r}")
        if start < minimum or end > maximum:
            raise ValueError(f"{field} 超出有效范围 {minimum}-{maximum}：{token!r}")
        values.extend(range(start, end + 1))
    values = sorted(set(values))
    spec = _compress_vlan_ids(values)
    value = values[0] if len(values) == 1 else None
    return value, spec, values


def _csv_parse_vlan_selector(val):
    return _csv_parse_numeric_selector(
        val, field="evpn_l2vlan", minimum=1, maximum=4094,
    )


def _csv_parse_vni_selector(val):
    return _csv_parse_numeric_selector(
        val, field="evpn_l2vni", minimum=1, maximum=16777215,
    )


def _csv_parse_evpn_group(cols):
    if len(cols) < 6 or _csv_na(cols[0]):
        return None
    l2vni_idx = 4
    l2vlan_idx = 5
    svi_idx = 6
    netmask_idx = 7
    vrr_idx = 8
    vrr_mac_idx = 9
    ports_idx = 10
    svi_nm = cols[netmask_idx].strip() if len(cols) > netmask_idx else ""
    vlan_id, vlan_spec, vlan_ids = _csv_parse_vlan_selector(cols[l2vlan_idx])
    vni_id, vni_spec, vni_ids = _csv_parse_vni_selector(cols[l2vni_idx])
    relay_value = cols[3].strip() if len(cols) > 3 else ""
    relay_folded = relay_value.casefold()
    enabled_values = {"true", "yes", "1"}
    disabled_values = {"false", "no", "0"}
    if _csv_na(relay_value) or relay_folded in disabled_values:
        relay_enabled = False
        relay_server = ""
    elif relay_folded in enabled_values:
        # TRUE enables relay and selects the first server group for the VRF.
        relay_enabled = True
        relay_server = ""
    else:
        # A non-boolean value selects a named server group directly.
        relay_enabled = True
        relay_server = relay_value

    g = {
        "vrf":        cols[0],
        "l3vni":      _csv_to_int_opt(cols[1]),
        "l3vlan":     _csv_to_int_opt(cols[2]),
        "l2vni":      vni_id,
        "l2vni_spec": vni_spec,
        "l2vni_ids":  vni_ids,
        "l2vlan":     vlan_id,
        "l2vlan_spec": vlan_spec,
        "l2vlan_ids": vlan_ids,
        "dhcp_server": relay_server,
        "svi_ip":     (_csv_combine_ip(cols[svi_idx], svi_nm)
                       if len(cols) > svi_idx and not _csv_na(cols[svi_idx]) else ""),
        "vrr_ip":     (_csv_combine_ip(cols[vrr_idx], svi_nm)
                       if len(cols) > vrr_idx and not _csv_na(cols[vrr_idx]) else ""),
        "vrr_mac":    (cols[vrr_mac_idx].strip()
                       if len(cols) > vrr_mac_idx and not _csv_na(cols[vrr_mac_idx]) else ""),
        "vlan_ports": cols[ports_idx].strip() if len(cols) > ports_idx else "",
    }
    if relay_enabled:
        g["dhcp_relay"] = True
    return g

def _csv_build_vrfs(groups, bond_groups=None):
    seen = {}; order = []; bond_idx = 0
    multi = bond_groups and len(bond_groups) > 1
    l3vni_by_vrf = {}
    l3vlan_by_vrf = {}
    for g in groups:
        if g.get("l3vni") is not None:
            l3vni_by_vrf.setdefault(g["vrf"], set()).add(g["l3vni"])
        if g.get("l3vlan") is not None:
            l3vlan_by_vrf.setdefault(g["vrf"], set()).add(g["l3vlan"])
    for field, values_by_vrf in (
            ("evpn_l3vni", l3vni_by_vrf),
            ("evpn_l3vlan", l3vlan_by_vrf)):
        for vrf_name, values in values_by_vrf.items():
            if len(values) > 1:
                raise ValueError(
                    f"evpn_vrf={vrf_name} 存在冲突的 {field}："
                    + ", ".join(map(str, sorted(values)))
                )
    inherited_l3vni = {name: next(iter(values)) for name, values in l3vni_by_vrf.items()}
    inherited_l3vlan = {name: next(iter(values)) for name, values in l3vlan_by_vrf.items()}
    for g in groups:
        vlan_ids = g.get("l2vlan_ids")
        if vlan_ids is None:
            vlan_ids = [g["l2vlan"]] if g.get("l2vlan") is not None else []
        vlan_spec = g.get("l2vlan_spec") or (
            _compress_vlan_ids(vlan_ids) if vlan_ids else ""
        )
        vni_ids = g.get("l2vni_ids")
        if vni_ids is None:
            vni_ids = [g["l2vni"]] if g.get("l2vni") is not None else []
        vn = g["vrf"]
        if vn not in seen:
            entry = {
                "evpn_vrf": vn,
                "evpn_l3vni": g["l3vni"] or inherited_l3vni.get(vn),
                "evpn_l3vlan": g["l3vlan"] or inherited_l3vlan.get(vn),
                "l2vlans": [],
            }
            seen[vn] = entry; order.append(vn)
        else:
            if seen[vn].get("evpn_l3vni") is None:
                seen[vn]["evpn_l3vni"] = g["l3vni"] or inherited_l3vni.get(vn)
            if seen[vn].get("evpn_l3vlan") is None and g.get("l3vlan") is not None:
                seen[vn]["evpn_l3vlan"] = g["l3vlan"]
        # A row can describe an L3-only VRF (L3 VNI present, all L2 fields
        # empty).  Do not turn that row into vlanNone or consume a bond group.
        has_l2 = bool(vlan_ids) or any(g.get(field) not in (None, "", []) for field in (
            "l2vni", "svi_ip", "vrr_ip", "vrr_mac"
        )) or not _csv_na(g.get("vlan_ports", ""))
        if not has_l2:
            continue
        vp_raw = g.get("vlan_ports", "").strip()
        vp_spec = vp_raw.lower()
        is_exact_marker = vp_spec in _BOND_MARKERS or _csv_na(vp_spec)
        if bond_groups and is_exact_marker:
            if multi and bond_idx >= len(bond_groups):
                raise ValueError(
                    f"bond_ports 中有 {len(bond_groups)} 个分组，但 EVPN 组引用了第 {bond_idx + 1} 个"
                )
            bi = bond_groups[bond_idx] if multi else bond_groups[0]
            if multi:
                bond_idx += 1
            ports = [{"bonds": copy.deepcopy(bi)}]
        elif not _csv_na(vp_spec):
            bond_tokens = []
            direct_tokens = []
            for token in (part.strip() for part in vp_raw.split("/") if part.strip()):
                if token.casefold().startswith("bond"):
                    bond_tokens.append(token)
                else:
                    direct_tokens.append(token)
            expanded = []
            for token in bond_tokens:
                expanded.extend(_csv_expand_prefixed(token, "bond"))
            ports = []
            for token in direct_tokens:
                ports.extend(_csv_expand_ports(token))
            if expanded and not bond_groups:
                # Preserve legacy parsing so the later schema validations can
                # report the more specific SVI/VNI error first. Project input
                # should normally define bond_ports/bond_type for these names.
                ports.extend(expanded)
                expanded = []
            if expanded and len(bond_groups) == 1:
                # Backward compatibility: a single device-wide profile applies
                # to explicit EVPN bond ranges even when bond_ports is narrower.
                profile = bond_groups[0]
                ports.append({"bonds": {
                    "type":        profile["type"],
                    "bond_list":   expanded,
                    "lacp-bypass": profile.get("lacp-bypass", "enabled"),
                    "mac-address": profile.get("mac-address", ""),
                }})
            elif expanded:
                assigned = set()
                for profile in bond_groups:
                    selected = [name for name in expanded if name in profile["bond_list"]]
                    if not selected:
                        continue
                    assigned.update(selected)
                    ports.append({"bonds": {
                        "type":        profile["type"],
                        "bond_list":   selected,
                        "lacp-bypass": profile.get("lacp-bypass", "enabled"),
                        "mac-address": profile.get("mac-address", ""),
                    }})
                unmatched = [name for name in expanded if name not in assigned]
                if unmatched:
                    raise ValueError(
                        "EVPN vlan_ports 中的 bond 未在 bond_ports 分组定义："
                        + "/".join(unmatched)
                    )
        else:
            ports = []
        if vni_ids and not vlan_ids:
            raise ValueError("evpn_l2vni 已填写，但 evpn_l2vlan 为空")
        if vni_ids and len(vni_ids) != len(vlan_ids):
            raise ValueError(
                f"evpn_l2vlan={vlan_spec} 与 evpn_l2vni="
                f"{g.get('l2vni_spec') or _compress_vlan_ids(vni_ids)} 数量不一致："
                f"{len(vlan_ids)} != {len(vni_ids)}"
            )
        if len(vlan_ids) > 1 and any((
                bool(g["svi_ip"]), bool(g["vrr_ip"]), bool(g["vrr_mac"]))):
            raise ValueError(
                f"evpn_l2vlan={vlan_spec} 是 VLAN 范围，不能同时指定单值 "
                "svi_ip/vrr_ip/vrr_mac；请为需要三层 SVI 的 VLAN 单独建组"
            )
        if g["vrr_ip"] and not g["vrr_mac"]:
            raise ValueError(
                f"evpn_l2vlan={vlan_spec or g.get('l2vlan')} 的 "
                "vrr_ip 出现时必须同时指定 vrr_mac"
            )
        if g["vrr_mac"] and not (g["vrr_ip"] or g["svi_ip"]):
            raise ValueError(
                f"evpn_l2vlan={vlan_spec or g.get('l2vlan')} 的 "
                "vrr_mac 必须与 svi_ip 或 vrr_ip 一起使用"
            )
        if g["svi_ip"] and g["vrr_ip"]:
            svi_addr = str(g["svi_ip"]).split("/", 1)[0]
            vrr_addr = str(g["vrr_ip"]).split("/", 1)[0]
            if svi_addr == vrr_addr:
                raise ValueError(
                    f"evpn_l2vlan={vlan_spec or g.get('l2vlan')} 的 "
                    f"svi_ip 与 vrr_ip 不能相同：{svi_addr}"
                )
        # Only selector ranges need to be expanded into one item per VLAN.
        # A single VLAN/VNI pair must keep its SVI/VRR fields; treating any
        # non-empty pair list as a range used to erase those fields from every
        # normal EVPN SVI.
        needs_expand = (
            len(vlan_ids) > 1
            and (bool(vni_ids) or bool(g.get("dhcp_relay")))
        )
        if needs_expand:
            expanded_vnis = vni_ids if vni_ids else [None] * len(vlan_ids)
            l2_items = [{
                "vlan_id": vlan_id, "vlan_spec": str(vlan_id),
                "vlan_ids": [vlan_id], "vni": vni_id,
                "emit_svi": not g.get("bridge_only", False),
                "svi_ip": "", "vrr_ip": "", "vrr_mac": "",
            } for vlan_id, vni_id in zip(vlan_ids, expanded_vnis)]
        else:
            l2_items = [{
                "vlan_id": g["l2vlan"], "vlan_spec": vlan_spec,
                "vlan_ids": vlan_ids, "vni": g["l2vni"],
                "emit_svi": (len(vlan_ids) <= 1
                             and not g.get("bridge_only", False)),
                "svi_ip": g["svi_ip"], "vrr_ip": g["vrr_ip"],
                "vrr_mac": g["vrr_mac"],
            }]
        for l2 in l2_items:
            l2["dhcp_relay"] = bool(g.get("dhcp_relay"))
            l2["dhcp_server"] = g.get("dhcp_server", "")
            if ports:
                l2["vlan_ports"] = copy.deepcopy(ports)
            seen[vn]["l2vlans"].append(l2)
    return [seen[v] for v in order]


def _csv_collect_evpn_groups(
        row, group_count, hostname, errors, base=25, width=11):
    """Parse all EVPN groups and append selector failures to CSV errors."""
    groups = []
    invalid = False
    last_vrf = None
    for group_idx in range(group_count):
        start = base + group_idx * width
        group_cols = list(row[start:start + width])
        # A later group can describe an L2-only VLAN/bond attachment and leave
        # evpn_vrf blank. Attach it to the preceding VRF internally; the VLAN
        # and port semantics do not depend on the user-visible VRF name.
        inherited_l2_only = (
            group_cols and _csv_na(group_cols[0])
            and any(not _csv_na(value) for value in group_cols[4:])
        )
        if inherited_l2_only:
            group_cols[0] = last_vrf or "default"
        try:
            group = _csv_parse_evpn_group(group_cols)
        except ValueError as exc:
            errors.append(f"  {hostname}: EVPN 组 {group_idx + 1}: {exc}")
            invalid = True
            continue
        if group is not None:
            if inherited_l2_only:
                group["bridge_only"] = True
            groups.append(group)
            last_vrf = group["vrf"]
            vlan_spec = group.get("l2vlan_spec") or group.get("l2vlan") or "NA"
            vlan_ids = group.get("l2vlan_ids") or []
            if len(vlan_ids) > 1 and any(group.get(field) for field in (
                    "svi_ip", "vrr_ip", "vrr_mac")):
                errors.append(
                    f"  {hostname}: EVPN 组 {group_idx + 1}: evpn_l2vlan={vlan_spec} "
                    "是 VLAN 范围，svi_ip/vrr_ip/vrr_mac 必须全部为空/NA"
                )
                invalid = True
            if group.get("vrr_ip") and not group.get("vrr_mac"):
                errors.append(
                    f"  {hostname}: EVPN 组 {group_idx + 1}: evpn_l2vlan={vlan_spec} "
                    "的 vrr_ip 出现时必须同时指定 vrr_mac"
                )
                invalid = True
            if (group.get("vrr_mac") and
                    not (group.get("vrr_ip") or group.get("svi_ip"))):
                errors.append(
                    f"  {hostname}: EVPN 组 {group_idx + 1}: evpn_l2vlan={vlan_spec} "
                    "的 vrr_mac 必须与 svi_ip 或 vrr_ip 一起使用"
                )
                invalid = True
            if group.get("svi_ip") and group.get("vrr_ip"):
                svi_addr = group["svi_ip"].split("/", 1)[0]
                vrr_addr = group["vrr_ip"].split("/", 1)[0]
                if svi_addr == vrr_addr:
                    errors.append(
                        f"  {hostname}: EVPN 组 {group_idx + 1}: evpn_l2vlan={vlan_spec} "
                        f"的 svi_ip 与 vrr_ip 不能相同：{svi_addr}"
                    )
                    invalid = True
    return None if invalid else groups


def _csv_build_vrfs_checked(groups, bond_groups, hostname, errors):
    """Build VRFs and append cross-field range failures to CSV errors."""
    try:
        return _csv_build_vrfs(groups, bond_groups or None)
    except ValueError as exc:
        errors.append(f"  {hostname}: EVPN 配置: {exc}")
        return None


def _detect_evpn_schema(header, start, end):
    """Return (width, group_count) for the single supported EVPN schema."""
    columns = tuple(item.strip().lower() for item in header[start:end])
    width = len(_EVPN_COLUMNS)
    if (columns and len(columns) % width == 0
            and all(columns[offset:offset + width] == _EVPN_COLUMNS
                    for offset in range(0, len(columns), width))):
        return width, len(columns) // width
    raise ValueError(
        "固定列后必须重复使用 EVPN 字段组：" +
        ",".join(_EVPN_COLUMNS)
    )


def _normalize_dhcp_server_groups(global_data):
    """Validate global DHCP relay server groups while preserving list order."""
    services = global_data.get("services") or {}
    raw = services.get("dhcp_relay")
    if raw in (None, {}):
        return {}
    if not isinstance(raw, dict):
        raise ValueError("services.dhcp_relay 必须是按 VRF 命名的 mapping")
    result = {}
    for vrf_name, vrf_config in raw.items():
        if not isinstance(vrf_config, dict):
            raise ValueError(f"services.dhcp_relay.{vrf_name} 必须是 mapping")
        configured = vrf_config.get("server_group")
        if not isinstance(configured, list) or not configured:
            raise ValueError(
                f"services.dhcp_relay.{vrf_name}.server_group 必须是非空列表"
            )
        groups = {}
        for index, item in enumerate(configured, 1):
            if not isinstance(item, dict):
                raise ValueError(
                    f"services.dhcp_relay.{vrf_name}.server_group[{index}] 必须是 mapping"
                )
            name = str(item.get("group") or "").strip()
            servers = item.get("servers")
            if not name:
                raise ValueError(
                    f"services.dhcp_relay.{vrf_name}.server_group[{index}] 缺少 group"
                )
            if name in groups:
                raise ValueError(
                    f"services.dhcp_relay.{vrf_name} 重复 server group：{name}"
                )
            if not isinstance(servers, list) or not servers:
                raise ValueError(
                    f"services.dhcp_relay.{vrf_name}.{name}.servers 必须是非空列表"
                )
            normalized_servers = []
            for server in servers:
                text = str(server).strip()
                try:
                    ipaddress.ip_address(text)
                except ValueError as exc:
                    raise ValueError(
                        f"services.dhcp_relay.{vrf_name}.{name} 包含无效地址：{text!r}"
                    ) from exc
                if text not in normalized_servers:
                    normalized_servers.append(text)
            upstream = str(item.get("upstream_interface") or "").strip()
            if upstream and not re.fullmatch(r"vlan\d+(?:_l3)?", upstream):
                raise ValueError(
                    f"services.dhcp_relay.{vrf_name}.{name}.upstream_interface "
                    f"格式无效：{upstream!r}"
                )
            groups[name] = {
                "servers": normalized_servers,
                "upstream_interface": upstream,
            }
        result[str(vrf_name)] = groups
    return result


def _csv_vrl_enabled(value):
    """Parse the optional per-device VRL flag without silently accepting typos."""
    normalized = (value or "").strip().casefold()
    if normalized in ("", "na", "n/a", "false", "0", "no", "n"):
        return False
    if normalized in ("true", "1", "yes", "y"):
        return True
    raise ValueError("vrl 只允许 true/false/na/空")


def _normalize_vrl_config(global_data):
    """Validate global VRF route-leaking input and build template-ready data.

    Each entry defines exactly one VRF pair.  Each side owns one named prefix
    list; that list may contain one subnet (the documented form) or a subnet
    list.  Routes originating in one VRF are imported by the other VRF through
    the originating side's route-map.
    """
    raw_blocks = global_data.get("vrl")
    if raw_blocks in (None, []):
        return {"prefix_lists": [], "route_maps": [], "imports": [], "vrfs": []}
    if not isinstance(raw_blocks, list):
        raise ValueError("vrl 必须是列表")

    prefix_lists = {}
    route_maps = {}
    imports = {}
    target_imports = {}
    all_vrfs = set()
    control_keys = {"min-prefix-len", "max-prefix-len"}

    for block_index, block in enumerate(raw_blocks, 1):
        context = f"vrl[{block_index}]"
        if not isinstance(block, dict):
            raise ValueError(f"{context} 必须是 mapping")
        raw_pair = block.get("leaking_vrfs")
        if isinstance(raw_pair, dict):
            pair = [str(name).strip() for name in raw_pair]
        elif isinstance(raw_pair, (list, tuple)):
            pair = [str(name).strip() for name in raw_pair]
        elif isinstance(raw_pair, str):
            pair = [name.strip() for name in raw_pair.split(",") if name.strip()]
        else:
            raise ValueError(f"{context}.leaking_vrfs 必须是两个 VRF 的列表或 mapping")
        if len(pair) != 2 or len(set(pair)) != 2 or not all(pair):
            raise ValueError(f"{context}.leaking_vrfs 必须且只能包含两个不同的 VRF")

        side_route_maps = {}
        for vrf_name in pair:
            configured = block.get(vrf_name)
            if not isinstance(configured, list) or len(configured) != 1:
                raise ValueError(
                    f"{context}.{vrf_name} 必须是只含一个命名前缀列表的列表"
                )
            item = configured[0]
            if not isinstance(item, dict):
                raise ValueError(f"{context}.{vrf_name}[0] 必须是 mapping")
            names = [name for name in item if name not in control_keys]
            if len(names) != 1:
                raise ValueError(
                    f"{context}.{vrf_name}[0] 必须且只能定义一个 prefix-list 名称"
                )
            list_name = str(names[0]).strip()
            if not list_name or not re.fullmatch(r"[A-Za-z0-9_.:-]+", list_name):
                raise ValueError(f"{context}.{vrf_name} 的 prefix-list 名称无效：{list_name!r}")
            raw_subnets = item[names[0]]
            subnets = raw_subnets if isinstance(raw_subnets, list) else [raw_subnets]
            if not subnets:
                raise ValueError(f"{context}.{vrf_name}.{list_name} 不能为空")

            min_len = item.get("min-prefix-len")
            max_len = item.get("max-prefix-len")
            for label, value in (("min-prefix-len", min_len), ("max-prefix-len", max_len)):
                if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
                    raise ValueError(f"{context}.{vrf_name}.{label} 必须是整数")

            rules = []
            for subnet in subnets:
                try:
                    network = ipaddress.ip_network(str(subnet).strip(), strict=True)
                except ValueError as exc:
                    raise ValueError(
                        f"{context}.{vrf_name}.{list_name} 子网无效：{subnet!r} ({exc})"
                    ) from exc
                if network.version != 4:
                    raise ValueError(f"{context}.{vrf_name}.{list_name} 当前只支持 IPv4")
                minimum = network.prefixlen if min_len is None else min_len
                maximum = network.prefixlen if max_len is None else max_len
                if not network.prefixlen <= minimum <= maximum <= 32:
                    raise ValueError(
                        f"{context}.{vrf_name}.{list_name} 要求 subnet prefix <= "
                        "min-prefix-len <= max-prefix-len <= 32"
                    )
                rules.append({
                    "subnet": str(network),
                    "min_prefix_len": min_len,
                    "max_prefix_len": max_len,
                })

            definition = {"name": list_name, "rules": rules}
            previous = prefix_lists.get(list_name)
            if previous is not None and previous != definition:
                raise ValueError(f"prefix-list {list_name!r} 被重复定义且内容不一致")
            prefix_lists[list_name] = definition
            route_maps[list_name] = {"name": list_name, "prefix_list": list_name}
            side_route_maps[vrf_name] = list_name
            all_vrfs.add(vrf_name)

        for target_vrf, source_vrf in ((pair[0], pair[1]), (pair[1], pair[0])):
            key = (target_vrf, source_vrf)
            definition = {
                "vrf": target_vrf,
                "from_vrf": source_vrf,
                "route_map": side_route_maps[source_vrf],
            }
            previous = imports.get(key)
            if previous is not None and previous != definition:
                raise ValueError(
                    f"{target_vrf} 从 {source_vrf} 的 route-import 被重复定义且不一致"
                )
            previous_target = target_imports.get(target_vrf)
            if previous_target is not None and previous_target != definition:
                raise ValueError(
                    f"VRF {target_vrf!r} 出现在多个 leaking pair 中；"
                    "NVUE 每个 VRF 只能绑定一个 from-vrf route-map"
                )
            imports[key] = definition
            target_imports[target_vrf] = definition

    grouped_imports = {}
    for route_import in imports.values():
        grouped_imports.setdefault(route_import["vrf"], []).append(route_import)
    return {
        "prefix_lists": list(prefix_lists.values()),
        "route_maps": list(route_maps.values()),
        "imports": [
            {"vrf": vrf_name, "sources": sources}
            for vrf_name, sources in grouped_imports.items()
        ],
        "vrfs": sorted(all_vrfs),
    }


def _resolve_device_dhcp_relays(dev, server_catalog):
    """Build one render-ready DHCP relay entry per VRF."""
    resolved = []
    for vrf in dev.get("vrfs", []):
        relay_l2 = [
            l2 for l2 in vrf.get("l2vlans", []) if l2.get("dhcp_relay")
        ]
        if not relay_l2:
            continue
        vrf_name = vrf["evpn_vrf"]
        available = server_catalog.get(vrf_name)
        if not available:
            raise ValueError(
                f"evpn_vrf={vrf_name} 启用了 dhcp_relay，但 global 没有对应 server_group"
            )
        default_group = next(iter(available))
        downstream = {}
        used_groups = []
        relay_modes = set()
        ifupdown_snippets = {}
        for l2 in relay_l2:
            vlan_id = l2.get("vlan_id")
            if vlan_id is None:
                raise ValueError(
                    f"evpn_vrf={vrf_name} 的 dhcp_relay 缺少可生成接口的 evpn_l2vlan"
                )
            group_name = l2.get("dhcp_server") or default_group
            if group_name not in available:
                raise ValueError(
                    f"evpn_vrf={vrf_name} vlan{vlan_id} 引用了未知 dhcp_server="
                    f"{group_name!r}（可用：{', '.join(available)}）"
                )
            interface = f"vlan{vlan_id}"
            previous = downstream.get(interface)
            if previous and previous != group_name:
                raise ValueError(
                    f"evpn_vrf={vrf_name} {interface} 同时引用 {previous} 和 {group_name}"
                )
            downstream[interface] = group_name
            if group_name not in used_groups:
                used_groups.append(group_name)

            has_svi = bool(l2.get("svi_ip"))
            has_vrr = bool(l2.get("vrr_ip"))
            has_mac = bool(l2.get("vrr_mac"))
            combination = (has_svi, has_vrr, has_mac)
            if combination == (True, True, True):
                relay_modes.add("giaddress")
            elif combination == (True, False, True):
                relay_modes.add("gateway")
                ifupdown_snippets[interface] = (
                    f"hwaddress {l2['vrr_mac']}\n"
                )
            elif combination == (False, True, True):
                raise ValueError(
                    f"evpn_vrf={vrf_name} {interface} 使用已废弃的方案 2："
                    "配置了 vrr_ip+vrr_mac，但缺少每台设备唯一的 svi_ip；"
                    "VRR 虚拟接口 vlan*-v0 不能替代普通 SVI 完成可靠的主动 ARP。"
                    "请补充 svi_ip 改用方案 1，或删除 vrr_ip 并补充 svi_ip 改用方案 3"
                )
            else:
                present = ", ".join(
                    name for name, enabled in zip(
                        ("svi_ip", "vrr_ip", "vrr_mac"), combination,
                    ) if enabled
                ) or "全部为空"
                raise ValueError(
                    f"evpn_vrf={vrf_name} {interface} 启用了 dhcp_relay，"
                    f"但 SVI/VRR 组合不受支持（当前：{present}）；合法组合为 "
                    "方案 1（svi_ip+vrr_ip+vrr_mac）或方案 3（svi_ip+vrr_mac）"
                )
        if len(relay_modes) != 1:
            raise ValueError(
                f"evpn_vrf={vrf_name} 的下联 VLAN 混用了 giaddress 与 "
                "gateway-interface relay 模式；同一 VRF 必须使用同一种模式"
            )
        relay_mode = next(iter(relay_modes))
        loopback_address = ""
        gateway_address = ""
        if relay_mode == "gateway":
            raw_lo = str(dev.get("lo_ip") or "").strip()
            try:
                lo_interface = ipaddress.ip_interface(raw_lo)
            except ValueError as exc:
                raise ValueError(
                    f"evpn_vrf={vrf_name} 使用 gateway-interface relay 时，"
                    "设备必须提供合法的 lo_ip/32"
                ) from exc
            if lo_interface.version != 4 or lo_interface.network.prefixlen != 32:
                raise ValueError(
                    f"evpn_vrf={vrf_name} 使用 gateway-interface relay 时，"
                    f"lo_ip 必须是 IPv4 /32，当前为 {raw_lo!r}"
                )
            loopback_address = str(lo_interface)
            gateway_address = str(lo_interface.ip)
        l3vni = vrf.get("evpn_l3vni")
        local_interfaces = {}
        for l2 in vrf.get("l2vlans", []):
            vlan_id = l2.get("vlan_id")
            raw_svi = str(l2.get("svi_ip") or "").strip()
            if vlan_id is None or not raw_svi:
                continue
            try:
                local_interfaces[f"vlan{vlan_id}"] = ipaddress.ip_interface(raw_svi).network
            except ValueError as exc:
                raise ValueError(
                    f"evpn_vrf={vrf_name} vlan{vlan_id} 的 svi_ip 无效：{raw_svi!r}"
                ) from exc
        fallback_interface = f"vlan{l3vni}_l3" if l3vni is not None else ""
        rendered_groups = []
        for name in used_groups:
            definition = available[name]
            servers = definition["servers"]
            explicit = definition.get("upstream_interface") or ""
            valid_interfaces = set(local_interfaces)
            if fallback_interface:
                valid_interfaces.add(fallback_interface)
            if explicit:
                if explicit not in valid_interfaces:
                    raise ValueError(
                        f"evpn_vrf={vrf_name} server group {name} 指定 "
                        f"upstream_interface={explicit}，但设备没有该接口"
                    )
            # The L3VNI interface is the default routed upstream for every
            # server group. Add every local SVI containing at least one server
            # address. NVUE permits multiple upstream interfaces per group.
            # An explicit interface supplements these paths; it does not
            # replace the L3VNI interface.
            upstream_interfaces = []
            if fallback_interface:
                upstream_interfaces.append(fallback_interface)
            for interface, network in local_interfaces.items():
                if any(ipaddress.ip_address(server) in network for server in servers):
                    if interface not in upstream_interfaces:
                        upstream_interfaces.append(interface)
            if explicit and explicit not in upstream_interfaces:
                upstream_interfaces.append(explicit)
            if not upstream_interfaces:
                raise ValueError(
                    f"evpn_vrf={vrf_name} server group {name} 无法解析 upstream interface；"
                    "请配置 L3VNI、本地 SVI 或显式填写 upstream_interface"
                )
            rendered_groups.append({
                "name": name,
                "servers": servers,
                "upstream_interfaces": upstream_interfaces,
            })
        resolved.append({
            "vrf": vrf_name,
            "mode": relay_mode,
            "downstream_interfaces": [
                {"interface": interface, "server_group": group_name}
                for interface, group_name in downstream.items()
            ],
            "server_groups": rendered_groups,
            "gateway_address": gateway_address,
            "loopback_address": loopback_address,
            "ifupdown_snippets": ifupdown_snippets,
        })
    return resolved


def _resolve_device_svi_vrr_support(dev):
    """Build VRF/system support from SVI/VRR fields, independent of relay.

    A gateway-style SVI needs the device loopback installed in the tenant VRF.
    When ``svi_ip`` and ``vrr_mac`` exist but ``vrr_ip`` does not, NVUE must
    not receive an incomplete ``ipv4.vrr`` object; ifupdown2 owns the VLAN MAC
    through a snippet instead.  These interface requirements apply even when
    DHCP relay itself is disabled for the VLAN.
    """
    resolved = []
    raw_lo = str(dev.get("lo_ip") or "").strip()
    lo_interface = None

    for vrf in dev.get("vrfs", []):
        snippets = {}
        needs_loopback = False
        for l2 in vrf.get("l2vlans", []):
            has_svi = bool(l2.get("svi_ip"))
            has_vrr = bool(l2.get("vrr_ip"))
            has_mac = bool(l2.get("vrr_mac"))
            combination = (has_svi, has_vrr, has_mac)
            if combination == (False, True, True):
                vlan_id = l2.get("vlan_id")
                interface = f"vlan{vlan_id}" if vlan_id is not None else "未知 VLAN"
                raise ValueError(
                    f"evpn_vrf={vrf['evpn_vrf']} {interface} 使用已废弃的方案 2："
                    "配置了 vrr_ip+vrr_mac，但缺少每台设备唯一的 svi_ip；"
                    "请补充 svi_ip 改用方案 1，或删除 vrr_ip 并补充 svi_ip 改用方案 3"
                )
            elif combination == (True, False, True):
                vlan_id = l2.get("vlan_id")
                if vlan_id is None:
                    raise ValueError(
                        f"evpn_vrf={vrf['evpn_vrf']} 的 svi_ip+vrr_mac "
                        "组合缺少 evpn_l2vlan"
                    )
                needs_loopback = True
                snippets[f"vlan{vlan_id}"] = (
                    f"hwaddress {l2['vrr_mac']}\n"
                )

        if not needs_loopback:
            continue
        if lo_interface is None:
            try:
                lo_interface = ipaddress.ip_interface(raw_lo)
            except ValueError as exc:
                raise ValueError(
                    "gateway-interface SVI/VRR 模式要求设备提供合法的 lo_ip/32"
                ) from exc
            if (lo_interface.version != 4
                    or lo_interface.network.prefixlen != 32):
                raise ValueError(
                    "gateway-interface SVI/VRR 模式要求 lo_ip 为 IPv4 /32，"
                    f"当前为 {raw_lo!r}"
                )
        resolved.append({
            "vrf": vrf["evpn_vrf"],
            "loopback_address": str(lo_interface),
            "ifupdown_snippets": snippets,
        })
    return resolved


def _validate_and_inherit_project_vrfs(devices):
    """Require one L3 VNI/VLAN value for every same-named VRF project-wide.

    Missing values inherit the sole explicit value used by another device.
    Conflicting explicit values are returned as CSV validation errors.
    """
    catalogs = {"evpn_l3vni": {}, "evpn_l3vlan": {}}
    for hostname, dev in devices.items():
        if dev.get("source_yaml_b64"):
            continue
        for vrf in dev.get("vrfs", []):
            name = vrf.get("evpn_vrf")
            if not name:
                continue
            for field in catalogs:
                value = vrf.get(field)
                if value is not None:
                    catalogs[field].setdefault(name, {}).setdefault(value, []).append(hostname)

    errors = []
    inherited = {"evpn_l3vni": {}, "evpn_l3vlan": {}}
    for field, by_vrf in catalogs.items():
        for vrf_name, values in by_vrf.items():
            if len(values) > 1:
                details = "; ".join(
                    f"{value}: {', '.join(hosts)}"
                    for value, hosts in sorted(values.items())
                )
                errors.append(
                    f"  evpn_vrf={vrf_name} 跨设备存在冲突的 {field}：{details}"
                )
            else:
                inherited[field][vrf_name] = next(iter(values))

    if errors:
        return errors
    for dev in devices.values():
        if dev.get("source_yaml_b64"):
            continue
        for vrf in dev.get("vrfs", []):
            name = vrf.get("evpn_vrf")
            for field in inherited:
                if vrf.get(field) is None and name in inherited[field]:
                    vrf[field] = inherited[field][name]
    return []


def _validate_project_svi_vrr(devices):
    """Validate cross-device SVI uniqueness and per-VLAN anycast identity."""
    vlan_svi_ips = {}
    vlan_vrr_pairs = {}
    for hostname, dev in devices.items():
        l2_items = [
            l2
            for vrf in dev.get("vrfs", [])
            for l2 in vrf.get("l2vlans", [])
        ]
        if not l2_items and dev.get("vlan_id") is not None:
            l2_items = [{
                "vlan_id": dev["vlan_id"],
                "svi_ip": dev.get("svi_ip", ""),
                "vrr_ip": dev.get("vrr_ip", ""),
                "vrr_mac": dev.get("vrr_mac", ""),
            }]
        for l2 in l2_items:
            vlan_id = l2.get("vlan_id")
            if vlan_id is None:
                continue
            svi_ip = (l2.get("svi_ip") or "").split("/", 1)[0]
            vrr_ip = (l2.get("vrr_ip") or "").split("/", 1)[0]
            vrr_mac = (l2.get("vrr_mac") or "").lower()
            if svi_ip:
                vlan_svi_ips.setdefault(vlan_id, {}).setdefault(svi_ip, []).append({
                    "hostname": hostname,
                    "vrr_mac": vrr_mac,
                    "has_vrr_ip": bool(vrr_ip),
                })
            if vrr_ip and vrr_mac:
                vlan_vrr_pairs.setdefault(vlan_id, {}).setdefault(
                    (vrr_ip, vrr_mac), []
                ).append(hostname)

    errors = []
    for vlan_id, ip_claims in sorted(vlan_svi_ips.items()):
        for svi_ip, claims in ip_claims.items():
            unique_hosts = sorted({claim["hostname"] for claim in claims})
            if len(unique_hosts) > 1:
                macs = {claim["vrr_mac"] for claim in claims if claim["vrr_mac"]}
                missing_mac = any(not claim["vrr_mac"] for claim in claims)
                has_vrr_ip = any(claim["has_vrr_ip"] for claim in claims)
                if has_vrr_ip:
                    errors.append(
                        f"  vlan{vlan_id} 已配置 vrr_ip，svi_ip={svi_ip!r} "
                        "不能被多台设备重复使用：" + ", ".join(unique_hosts)
                    )
                elif missing_mac or len(macs) != 1:
                    details = "; ".join(
                        f"{claim['hostname']}:{claim['vrr_mac'] or '缺少 vrr_mac'}"
                        for claim in claims
                    )
                    errors.append(
                        f"  vlan{vlan_id} 重复 svi_ip={svi_ip!r} 时，所有设备必须使用"
                        f"同一个 vrr_mac：{details}"
                    )
    for vlan_id, pair_hosts in sorted(vlan_vrr_pairs.items()):
        if len(pair_hosts) > 1:
            details = "; ".join(
                f"{ip}/{mac}: {', '.join(sorted(set(hosts)))}"
                for (ip, mac), hosts in sorted(pair_hosts.items())
            )
            errors.append(
                f"  vlan{vlan_id} 的 vrr_ip/vrr_mac 在设备间不一致：{details}"
            )
    return errors

def _csv_valid_ip(val, allow_dhcp=False):
    if allow_dhcp and val == "dhcp-client":
        return True
    try:
        ipaddress.ip_interface(val); return True
    except ValueError:
        return False

def _csv_valid_mac(val):
    return bool(re.fullmatch(r'[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}', val))

def _csv_valid_asn(val):
    try:
        return 1 <= int(val) <= 4294967295
    except (TypeError, ValueError):
        return False


def _decode_source_yaml(source_b64, expected_sha256):
    """校验并解码 yaml_to_csv.py 写入的无损 NVUE YAML，兼容新旧编码。"""
    compressed = source_b64.startswith(_SOURCE_YAML_GZIP_PREFIX)
    payload = (source_b64[len(_SOURCE_YAML_GZIP_PREFIX):]
               if compressed else source_b64)
    try:
        source_bytes = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"source_yaml_b64 无效: {exc}") from exc
    if compressed:
        try:
            source_bytes = gzip.decompress(source_bytes)
        except (gzip.BadGzipFile, EOFError, OSError) as exc:
            raise ValueError(f"source_yaml_b64 的 gzip 数据无效: {exc}") from exc

    expected_sha256 = (expected_sha256 or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("source_yaml_sha256 缺失或不是 64 位十六进制")
    actual_sha256 = hashlib.sha256(source_bytes).hexdigest()
    if actual_sha256 != expected_sha256:
        raise ValueError(
            f"source YAML SHA-256 不一致: expected={expected_sha256}, actual={actual_sha256}"
        )

    try:
        source_text = source_bytes.decode("utf-8")
        source_doc = yaml.safe_load(source_text)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"source YAML 无法解析: {exc}") from exc
    if not (isinstance(source_doc, list) and any(
            isinstance(item, dict) and isinstance(item.get("set"), dict)
            for item in source_doc)):
        raise ValueError("source YAML 必须是包含 set mapping 的 NVUE YAML list")
    return source_text


# ── ETH: csv_to_yaml main function ───────────────────────────────────────────

def _generate_devices_yaml():
    """Read 02-devices_config.csv + 01-global.yaml and write 91-devices.yaml."""
    _tmpl_map = _load_devices_template(_CSV_FILE)
    global_data = load_global()  # handles merged format extraction
    try:
        _refresh_cumulus_defaults_from_global()
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"[ERROR] Cumulus 默认配置同步失败：{exc}")
        sys.exit(1)
    try:
        dhcp_server_catalog = _normalize_dhcp_server_groups(global_data)
    except ValueError as exc:
        print(f"[ERROR] 01-global.yaml DHCP relay 配置无效：{exc}")
        sys.exit(1)
    try:
        global_data["vrl_render"] = _normalize_vrl_config(global_data)
    except ValueError as exc:
        print(f"[ERROR] 01-global.yaml VRF route-leaking 配置无效：{exc}")
        sys.exit(1)

    devices_data = {}
    _dup_errs = []
    _port_errors = []
    _mac_map = {}   # eth0_mac → [hostname, ...]（CSV col 5，解析时收集）
    _hostname_owners = {}

    try:
        _csv_f = open(_CSV_FILE, newline="", encoding="utf-8")
    except FileNotFoundError:
        print(f"[ERROR] 找不到配置文件: {_CSV_FILE}"); sys.exit(1)

    skipped_excluded = 0
    with _csv_f as f:
        reader   = csv.reader(f)
        header   = next(reader, [])
        h_lower  = [c.strip().lower() for c in header]
        if tuple(h_lower[:len(_EXPECTED_DEVICE_HEADER_PREFIX)]) != _EXPECTED_DEVICE_HEADER_PREFIX:
            print(
                "[ERROR] 02-devices_config.csv 前 11 列顺序必须为："
                + ",".join(_EXPECTED_DEVICE_HEADER_PREFIX)
            )
            sys.exit(1)
        _type_col = h_lower.index("type") if "type" in h_lower else None

        _source_yaml_col = h_lower.index(_SOURCE_YAML_COL) if _SOURCE_YAML_COL in h_lower else None
        _source_sha256_col = h_lower.index(_SOURCE_SHA256_COL) if _SOURCE_SHA256_COL in h_lower else None
        _source_fields_sha256_col = (h_lower.index(_SOURCE_FIELDS_SHA256_COL)
                                     if _SOURCE_FIELDS_SHA256_COL in h_lower else None)
        _metadata_positions = [i for i in (
            _source_yaml_col, _source_sha256_col, _source_fields_sha256_col
        ) if i is not None]
        _vrl_col = h_lower.index("vrl") if "vrl" in h_lower else None
        if _vrl_col is not None and _vrl_col != 25:
            print("[ERROR] 02-devices_config.csv 的可选 vrl 列必须紧跟 peerlink_ports")
            sys.exit(1)
        try:
            _evpn_base = h_lower.index("evpn_vrf", 25)
        except ValueError:
            print("[ERROR] 02-devices_config.csv 缺少 EVPN 字段组")
            sys.exit(1)
        _evpn_end = min(_metadata_positions) if _metadata_positions else len(header)
        try:
            _evpn_width, _evpn_group_count = (
                _detect_evpn_schema(h_lower, _evpn_base, _evpn_end)
            )
        except ValueError as exc:
            print(f"[ERROR] {_CSV_FILE} EVPN 列结构无效：{exc}")
            sys.exit(1)

        def _row_type(row):
            if _type_col is not None and len(row) > _type_col:
                return row[_type_col].strip().lower()
            return "ib" if row[0].strip().lower().startswith("ib") else "eth"

        for raw in reader:
            row = [c.strip() for c in raw]
            if len(row) < len(header):
                row.extend([""] * (len(header) - len(row)))
            row.extend([""] * 47)
            row_type = _row_type(row)
            if _exclude_config_type(row_type):
                skipped_excluded += 1
                continue
            if row_type not in ("eth", "eth_spx", "spx"):
                continue
            hostname = row[0]; csv_template = row[2]
            if not hostname:
                if not csv_template:
                    continue
                _dup_errs.append(f"  行缺少必填字段: hostname={hostname!r}")
                continue
            if not _SAFE_HOSTNAME_RE.fullmatch(hostname):
                _dup_errs.append(
                    f"  hostname 含不安全字符，不能作为 YAML 文件名: {hostname!r}"
                )
                continue
            hostname_key = hostname.casefold()
            if hostname_key in _hostname_owners:
                _dup_errs.append(f"  重复 hostname: {hostname!r}"); continue
            _hostname_owners[hostname_key] = hostname

            csv_has   = csv_template and not _csv_na(csv_template)
            mapped    = _tmpl_map.get(hostname.lower())
            tmpl_has  = bool(mapped)

            template = _select_device_template(csv_template, mapped)
            if (csv_has and tmpl_has and
                    csv_template.strip().lower() != mapped.strip().lower()):
                print(
                    f"  [INFO] {hostname}: devices_config.csv 模板 {csv_template!r} "
                    f"覆盖 devices_template 默认值 {mapped!r}"
                )

            if not template:
                _dup_errs.append(
                    f"  {hostname}: type={row_type} 必须在 devices_config.csv "
                    "或 devices_template 中显式指定模板，已禁止按 hostname 自动猜测"
                )
                continue

            if template:
                resolved_tmpl_file, is_exact = _best_template(template, hostname)
                if not is_exact:
                    _dup_errs.append(
                        f"  {hostname}: 指定模板 '{template}.yaml.j2' 不存在"
                        + (f"（最接近: {resolved_tmpl_file[:-len('.yaml.j2')]}）" if resolved_tmpl_file else "")
                    )
                    continue
            else:
                resolved_tmpl_file, is_exact = _best_template(hostname, hostname)
                if not resolved_tmpl_file:
                    _dup_errs.append(
                        f"  {hostname}: 无法确定模板（devices_config.csv 和 devices_template 均未指定，"
                        f"且 hostname 无法匹配任何模板）"
                    )
                    continue
                if not is_exact:
                    print(f"  [INFO] {hostname}: 自动匹配模板 "
                          f"'{resolved_tmpl_file[:-len('.yaml.j2')]}'（未在 CSV/devices_template 中指定）")
            template = resolved_tmpl_file[: -len(".yaml.j2")]
            # vrfs 表示非 default/mgmt 的业务 VRF。没有业务 VRF 的设备也保持
            # 稳定的空列表数据结构，供模板安全遍历。
            dev = {"template": template, "hostname": hostname, "vrfs": []}
            try:
                dev["vrl"] = _csv_vrl_enabled(
                    row[_vrl_col] if _vrl_col is not None else ""
                )
            except ValueError as exc:
                _dup_errs.append(f"  {hostname}: {exc}")
                continue
            if _source_yaml_col is not None and not _csv_na(row[_source_yaml_col]):
                source_sha256 = (row[_source_sha256_col]
                                  if _source_sha256_col is not None else "")
                source_fields_sha256 = (row[_source_fields_sha256_col]
                                         if _source_fields_sha256_col is not None else "")
                actual_fields_sha256 = hashlib.sha256(json.dumps(
                    row[:_evpn_end], ensure_ascii=False, separators=(",", ":")
                ).encode("utf-8")).hexdigest()
                if (not re.fullmatch(r"[0-9a-fA-F]{64}", source_fields_sha256)
                        or source_fields_sha256.lower() != actual_fields_sha256):
                    _dup_errs.append(
                        f"  {hostname}: CSV 可编辑字段已变化或 source_fields_sha256 无效；"
                        f"若要改用模板生成，请删除该行的 source_yaml_* 元数据"
                    )
                    continue
                try:
                    _decode_source_yaml(row[_source_yaml_col], source_sha256)
                except ValueError as exc:
                    _dup_errs.append(f"  {hostname}: {exc}")
                    continue
                dev["source_yaml_b64"] = row[_source_yaml_col]
                dev["source_yaml_sha256"] = source_sha256.lower()
                dev["source_fields_sha256"] = source_fields_sha256.lower()
                devices_data[hostname] = dev
                continue
            dev["eth0_ip"]  = _csv_combine_ip(row[3], row[4])
            dev["eth0_gw"]  = row[5]
            eth0_mac_raw = row[6]
            if eth0_mac_raw and eth0_mac_raw.upper() != "NA":
                _mac_map.setdefault(eth0_mac_raw.lower(), []).append(hostname)
            eth1_valid = (not _csv_na(row[7]) and not _csv_na(row[8])
                          and not _csv_na(row[9]))
            dev["has_eth1"] = eth1_valid
            if eth1_valid:
                dev["eth1_ip"] = _csv_combine_ip(row[7], row[8])
                dev["eth1_gw"] = row[9]
            eth1_mac_raw = row[10] if not _csv_na(row[10]) else ""
            if eth1_mac_raw:
                _mac_map.setdefault(eth1_mac_raw.lower(), []).append(hostname)
            lo_ip = row[11]
            if _csv_na(lo_ip):
                dev["lo_ip"] = lo_ip
            elif "/" not in lo_ip:
                dev["lo_ip"] = f"{lo_ip}/32"
            else:
                ip_part = lo_ip.split("/")[0]
                dev["lo_ip"] = lo_ip if not _csv_na(ip_part) else ip_part
            if template in _SIMPLE_TEMPLATES:
                if not _csv_na(row[13]):
                    try:
                        vlan_id, vlan_spec, vlan_ids = _csv_parse_vlan_selector(row[13])
                    except ValueError as exc:
                        _dup_errs.append(f"  {hostname}: vlan_id: {exc}")
                        continue
                    dev["vlan_id"] = vlan_id
                    dev["vlan_spec"] = vlan_spec
                    dev["vlan_ids"] = vlan_ids
                dev["svi_ip"]  = _csv_combine_ip(row[14], row[15]) if not _csv_na(row[14]) else ""
                dev["vrr_ip"]  = _csv_combine_ip(row[16], row[15]) if not _csv_na(row[16]) else ""
                dev["vrr_mac"] = row[17].strip() if not _csv_na(row[17]) else ""
                if len(dev.get("vlan_ids", [])) > 1 and any((
                        dev["svi_ip"], dev["vrr_ip"], dev["vrr_mac"])):
                    _dup_errs.append(
                        f"{hostname}: vlan_id={dev['vlan_spec']} 是 VLAN 范围，不能同时指定单值 "
                        "svi_ip/vrr_ip/vrr_mac"
                    )
                    continue
                if dev["vrr_ip"] and not dev["vrr_mac"]:
                    _dup_errs.append(
                        f"  {hostname}: vlan_id={dev.get('vlan_spec') or dev.get('vlan_id')} "
                        "的 vrr_ip 出现时必须同时指定 vrr_mac"
                    )
                    continue
                if dev["vrr_mac"] and not (dev["vrr_ip"] or dev["svi_ip"]):
                    _dup_errs.append(
                        f"  {hostname}: vlan_id={dev.get('vlan_spec') or dev.get('vlan_id')} "
                        "的 vrr_mac 必须与 svi_ip 或 vrr_ip 一起使用"
                    )
                    continue
                if (dev["svi_ip"] and dev["vrr_ip"] and
                        dev["svi_ip"].split("/", 1)[0] == dev["vrr_ip"].split("/", 1)[0]):
                    _dup_errs.append(
                        f"  {hostname}: vlan_id={dev.get('vlan_spec') or dev.get('vlan_id')} "
                        "的 svi_ip 与 vrr_ip 不能相同"
                    )
                    continue
                vp = row[18]
                dev.setdefault("vlan_ports", [])
                if not _csv_na(vp) and "bond" not in vp.lower():
                    dev["vlan_ports"] = _csv_expand_ports(vp)
                elif not _csv_na(vp):
                    dev["legacy_vlan_bonds"] = _csv_expand_prefixed(
                        vp, "bond", f"{hostname}.vlan_ports", _port_errors
                    )
            dev["bgp_asn"] = _csv_to_int(row[19]) if not _csv_na(row[19]) else None
            if not _csv_na(row[20]):
                dev["bgp_neighbors"] = _csv_expand_ports(row[20], f"{hostname}.bgp_ports", _port_errors)
            bond_groups = []
            if not _csv_na(row[21]) and not _csv_na(row[22]):
                try:
                    bond_groups = _csv_parse_bond_groups(
                        row[21], row[22], row[23],
                        f"{hostname}.bond_ports", _port_errors,
                    )
                except ValueError as exc:
                    _dup_errs.append(f"  {hostname}: {exc}")
                    continue
            if template in _SIMPLE_TEMPLATES and bond_groups:
                dev["bond_groups"] = bond_groups
            if not _csv_na(row[24]):
                dev["peerlink_ports"] = row[24].strip()
            groups = _csv_collect_evpn_groups(
                row, _evpn_group_count, hostname, _dup_errs,
                base=_evpn_base, width=_evpn_width,
            )
            if groups is None:
                continue
            if groups:
                vrfs = _csv_build_vrfs_checked(
                    groups, bond_groups, hostname, _dup_errs,
                )
                if vrfs is None:
                    continue
                dev["vrfs"] = vrfs
            if template in _SIMPLE_TEMPLATES and dev.get("vrfs"):
                first_l2 = dev["vrfs"][0].get("l2vlans", [])
                if first_l2:
                    l2 = first_l2[0]
                    if "vlan_id" not in dev and l2.get("vlan_id") is not None:
                        dev["vlan_id"] = l2["vlan_id"]
                    if "vlan_spec" not in dev and l2.get("vlan_spec"):
                        dev["vlan_spec"] = l2["vlan_spec"]
                    if not dev.get("svi_ip") and l2.get("svi_ip"):
                        dev["svi_ip"] = l2["svi_ip"]
            devices_data[hostname] = dev

    if skipped_excluded:
        print(f"[INFO] 已忽略 {skipped_excluded} 行 type=air 设备，不生成配置")

    # Same-named VRFs are a project-wide object: validate their explicit L3
    # identifiers and fill omissions before resolving DHCP upstream interfaces.
    _dup_errs.extend(_validate_and_inherit_project_vrfs(devices_data))
    if not _dup_errs:
        for hostname, dev in devices_data.items():
            if dev.get("source_yaml_b64"):
                continue
            if dev.get("vrl"):
                vrl_render = global_data["vrl_render"]
                if not vrl_render["imports"]:
                    _dup_errs.append(
                        f"  {hostname}: vrl=true，但 01-global.yaml 未配置 vrl"
                    )
                    continue
                device_vrfs = {
                    vrf.get("evpn_vrf") for vrf in dev.get("vrfs", [])
                    if vrf.get("evpn_vrf")
                }
                missing_vrfs = sorted(set(vrl_render["vrfs"]) - device_vrfs)
                if missing_vrfs:
                    _dup_errs.append(
                        f"  {hostname}: vrl=true，但设备缺少参与 leaking 的 VRF："
                        + ", ".join(missing_vrfs)
                    )
                    continue
            try:
                dev["svi_vrr_support"] = _resolve_device_svi_vrr_support(dev)
                dev["dhcp_relays"] = _resolve_device_dhcp_relays(
                    dev, dhcp_server_catalog,
                )
            except ValueError as exc:
                _dup_errs.append(f"  {hostname}: SVI/VRR/DHCP relay 配置: {exc}")
                continue
    # MLAG attributes
    mlag_global   = global_data.get("mlag") or {}
    mlag_pairs    = mlag_global.get("pairs", [])
    mlag_priority = mlag_global.get("priority", [])

    def _is_mlag_dev(d):
        if any(isinstance(p, dict) and p.get("bonds", {}).get("type") == "mlag"
               for vrf in d.get("vrfs", [])
               for l2 in vrf.get("l2vlans", [])
               for p in l2.get("vlan_ports", [])):
            return True
        return any(bg.get("type") == "mlag" for bg in d.get("bond_groups", []))

    mlag_hosts = [h for h, d in devices_data.items() if _is_mlag_dev(d)]
    for i, hostname in enumerate(mlag_hosts):
        pair_idx = i // 2; role_idx = i % 2
        peer = mlag_hosts[i ^ 1] if (i ^ 1) < len(mlag_hosts) else None
        if peer:
            devices_data[hostname]["mlag_backup"] = devices_data[peer]["eth0_ip"].split("/")[0]
        if mlag_priority and role_idx < len(mlag_priority):
            devices_data[hostname]["mlag_priority"] = mlag_priority[role_idx]
        if pair_idx < len(mlag_pairs):
            pair = mlag_pairs[pair_idx]
            sys_macs = pair.get("system-mac", [])
            if role_idx < len(sys_macs):
                devices_data[hostname]["system_mac"] = sys_macs[role_idx]
            shared = pair.get("shared-addresses", [])
            if shared:
                devices_data[hostname]["mlag_shared_address"] = shared[0]
            mlag_mac = pair.get("mac-address", [])
            if mlag_mac:
                devices_data[hostname]["mlag_mac_address"] = mlag_mac[0]

    # ── 重复值检查 ────────────────────────────────────────────────────────────
    _dup_val_errs = []

    def _collect_dup(field_name, value_map):
        for val, hosts in value_map.items():
            if len(hosts) > 1:
                _dup_val_errs.append(
                    f"  重复 {field_name}={val!r}：{', '.join(hosts)}"
                )

    _eth0_ip_map = {}
    _lo_ip_map   = {}
    _svi_vrrmac  = {}
    _vrr_vrrmac  = {}

    def _record_vrrmac(ip_map, ip_val, mac_val, label):
        if ip_val and not _csv_na(ip_val) and mac_val and not _csv_na(mac_val):
            ip_map.setdefault(ip_val, {}).setdefault(mac_val, []).append(label)

    for hn, dev in devices_data.items():
        v = dev.get("eth0_ip", "")
        if v and not _csv_na(v) and v.lower() != 'dhcp-client':
            _eth0_ip_map.setdefault(v, []).append(hn)

        v = dev.get("lo_ip", "")
        if v and not _csv_na(v):
            _lo_ip_map.setdefault(v, []).append(hn)

        for vrf in dev.get("vrfs", []):
            for l2 in vrf.get("l2vlans", []):
                vlan_id = l2.get("vlan_id")
                label = f"{hn}(vlan{vlan_id if vlan_id is not None else '?'})"
                svi_ip  = (l2.get("svi_ip")  or "").split("/")[0]
                vrr_ip  = (l2.get("vrr_ip")  or "").split("/")[0]
                vrr_mac = (l2.get("vrr_mac", "") or "").lower()
                _record_vrrmac(_svi_vrrmac, svi_ip, vrr_mac, label)
                _record_vrrmac(_vrr_vrrmac, vrr_ip, vrr_mac, label)

    _collect_dup("eth0_ip",  _eth0_ip_map)
    _collect_dup("eth0_mac", _mac_map)
    _collect_dup("lo_ip",    _lo_ip_map)

    for svi_ip, mac_hosts in _svi_vrrmac.items():
        if len(mac_hosts) > 1:
            details = "; ".join(f"{m}:[{', '.join(hs)}]" for m, hs in mac_hosts.items())
            _dup_val_errs.append(
                f"  svi_ip={svi_ip!r} 对应多个 vrr_mac：{details}"
            )
    for vrr_ip, mac_hosts in _vrr_vrrmac.items():
        if len(mac_hosts) > 1:
            details = "; ".join(f"{m}:[{', '.join(hs)}]" for m, hs in mac_hosts.items())
            _dup_val_errs.append(
                f"  vrr_ip={vrr_ip!r} 对应多个 vrr_mac：{details}"
            )

    _dup_val_errs.extend(_validate_project_svi_vrr(devices_data))

    if _dup_val_errs:
        print("[ERROR] 02-devices_config.csv 中存在重复值，请修正后重新运行：")
        for e in _dup_val_errs:
            print(e)
        sys.exit(1)

    # Validation
    _errs = []
    def _chk(ok, hostname, field, val):
        if not ok:
            _errs.append(f"  {hostname}: {field}={val!r}")

    for hostname, dev in devices_data.items():
        if dev.get("source_yaml_b64"):
            continue
        _chk(_csv_valid_ip(dev.get("eth0_ip", ""), allow_dhcp=True), hostname, "eth0_ip", dev.get("eth0_ip"))
        if not _csv_na(dev.get("eth0_gw", "")):
            _chk(_csv_valid_ip(dev.get("eth0_gw", ""), allow_dhcp=True), hostname, "eth0_gw", dev.get("eth0_gw"))
        lo_ip = dev.get("lo_ip", "")
        if not (_csv_na(lo_ip) or not lo_ip):
            _chk(_csv_valid_ip(lo_ip), hostname, "lo_ip", lo_ip)
        if dev.get("svi_ip"):
            _chk(_csv_valid_ip(dev["svi_ip"]),       hostname, "svi_ip",   dev["svi_ip"])
        if dev.get("bgp_asn") is not None:
            _chk(_csv_valid_asn(dev["bgp_asn"]),     hostname, "bgp_asn",  dev["bgp_asn"])
        for mac_field in ("system_mac", "mlag_mac_address"):
            if dev.get(mac_field):
                _chk(_csv_valid_mac(dev[mac_field]),  hostname, mac_field,  dev[mac_field])
        if dev.get("mlag_shared_address"):
            _chk(_csv_valid_ip(dev["mlag_shared_address"]), hostname, "mlag_shared_address",
                 dev["mlag_shared_address"])
        for vrf in dev.get("vrfs", []):
            for l2 in vrf.get("l2vlans", []):
                if l2.get("svi_ip"):
                    _chk(_csv_valid_ip(l2["svi_ip"]),  hostname, f"vlan{l2['vlan_id']}.svi_ip",  l2["svi_ip"])
                if l2.get("vrr_ip"):
                    _chk(_csv_valid_ip(l2["vrr_ip"]),  hostname, f"vlan{l2['vlan_id']}.vrr_ip",  l2["vrr_ip"])
                if l2.get("vrr_mac"):
                    _chk(_csv_valid_mac(l2["vrr_mac"]), hostname, f"vlan{l2['vlan_id']}.vrr_mac", l2["vrr_mac"])
        for bg in dev.get("bond_groups", []):
            if bg.get("mac-address"):
                _chk(_csv_valid_mac(bg["mac-address"]), hostname, "bond_mac", bg["mac-address"])
        for vlan_id in dev.get("vlan_ids", ([dev["vlan_id"]]
                              if dev.get("vlan_id") is not None else [])):
            _chk(1 <= vlan_id <= 4094, hostname, "vlan_id", vlan_id)
        for vrf in dev.get("vrfs", []):
            if vrf.get("evpn_l3vni") is not None:
                _chk(1 <= vrf["evpn_l3vni"] <= 16777215, hostname, "evpn_l3vni", vrf["evpn_l3vni"])
            if vrf.get("evpn_l3vlan") is not None:
                _chk(1 <= vrf["evpn_l3vlan"] <= 4094,    hostname, "evpn_l3vlan", vrf["evpn_l3vlan"])
            for l2 in vrf.get("l2vlans", []):
                for vlan_id in l2.get("vlan_ids", ([l2["vlan_id"]]
                                  if l2.get("vlan_id") is not None else [])):
                    _chk(1 <= vlan_id <= 4094, hostname, "l2vlan", vlan_id)
                if l2.get("vni") is not None:
                    _chk(1 <= l2["vni"] <= 16777215,         hostname, "l2vni",   l2["vni"])

    if len(mlag_hosts) % 2 != 0:
        _errs.append(f"  MLAG 设备数量为奇数 ({len(mlag_hosts)})，无法配对: {mlag_hosts}")
    _errs.extend(_dup_errs)
    _errs.extend(_port_errors)

    if _errs:
        print("[ERROR] 02-devices_config.csv 中存在格式错误，请修正后重新运行：")
        for e in _errs:
            print(e)
        sys.exit(1)

    output = {"global": global_data, "devices": devices_data}
    # DEVICES_FILE is normally a setup-managed symlink into the active project.
    # Atomic replacement must happen beside the target, otherwise os.replace()
    # replaces the symlink itself and breaks project isolation.
    output_path = os.path.realpath(DEVICES_FILE) if os.path.islink(DEVICES_FILE) else DEVICES_FILE
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    tmp_path = f"{output_path}.tmp.{os.getpid()}"
    with open(tmp_path, "w", encoding="utf-8") as f:
        yaml.dump(output, f, default_flow_style=False, allow_unicode=True,
                  sort_keys=False, width=120)
    os.replace(tmp_path, output_path)
    print(f"Generated {DEVICES_FILE}: {len(global_data)} global keys, {len(devices_data)} devices")


# ── ETH: config generation (Jinja2) ──────────────────────────────────────────

EVPN_UPLINK_TEMPLATE_CONFIG = {
    "tan-su-leaf":  "all",
    "tan-cp-leaf":  "all",
    "tan-hps-leaf": "all",
    "tan-spine":    {"swp41", "swp42"},
}


def _bond_sort_key(name: str) -> list:
    return [int(x) for x in re.findall(r'\d+', name)]


def _expand_swp_range(spec: str) -> list:
    """Expand 'swp31-32' → ['swp31','swp32'], or 'swp31' → ['swp31']."""
    spec = spec.strip()
    m = re.match(r'^swp(\d+)-(\d+)$', spec)
    if m:
        return [f"swp{i}" for i in range(int(m.group(1)), int(m.group(2)) + 1)]
    return [spec] if spec else []


def _bond_id(name: str) -> int:
    """Concatenate all digit groups from bond name: bond1s0 → 10, bond29 → 29."""
    return int(''.join(re.findall(r'\d+', name)))


def _bond_member(name: str) -> str:
    return name.replace('bond', 'swp', 1)


def _compress_vlan_ids(vlan_ids) -> str:
    """Compress only consecutive VLAN IDs, preserving gaps as comma lists."""
    values = sorted(set(int(vlan_id) for vlan_id in vlan_ids))
    ranges = []
    start = end = values[0]
    for vlan_id in values[1:]:
        if vlan_id == end + 1:
            end = vlan_id
            continue
        ranges.append(str(start) if start == end else f'{start}-{end}')
        start = end = vlan_id
    ranges.append(str(start) if start == end else f'{start}-{end}')
    return ','.join(ranges)


def _breakout_info(max_sub: int) -> tuple:
    """Return a valid 2/4/8-way mode for the highest configured sub-port.

    Device input may list only lanes that are actually used. Round up to a
    supported hardware mode instead of emitting invalid 1x/3x/5x breakouts.
    """
    if not 0 <= max_sub <= 7:
        raise ValueError(f"breakout sub-port index must be 0..7, got {max_sub}")
    count = 2 if max_sub < 2 else 4 if max_sub < 4 else 8
    return count, 8 // count


def preprocess_device(dev: dict) -> dict:
    """Compute computed_bonds / parent_swps / member_swps from bond_list data."""
    bond_vlans: dict = {}
    bond_attrs: dict = {}
    direct_port_vlans: dict = {}

    for vrf in dev.get('vrfs', []):
        for l2 in vrf.get('l2vlans', []):
            vlan_ids = l2.get('vlan_ids')
            if vlan_ids is None:
                vlan_ids = [l2['vlan_id']] if l2.get('vlan_id') is not None else []
            if not vlan_ids:
                continue
            for port in l2.get('vlan_ports', []):
                if isinstance(port, str):
                    direct_port_vlans.setdefault(port, [])
                    for vid in vlan_ids:
                        if vid not in direct_port_vlans[port]:
                            direct_port_vlans[port].append(vid)
                    continue
                if not isinstance(port, dict) or 'bonds' not in port:
                    continue
                bd = port['bonds']
                btype = bd.get('type', 'evpn_multihoming')
                for bn in bd.get('bond_list', []):
                    bond_vlans.setdefault(bn, [])
                    for vid in vlan_ids:
                        if vid not in bond_vlans[bn]:
                            bond_vlans[bn].append(vid)
                    if bn not in bond_attrs:
                        bond_attrs[bn] = {
                            'type':        btype,
                            'mac_address': bd.get('mac-address', ''),
                            'lacp_bypass': bd.get('lacp-bypass', 'enabled') == 'enabled',
                        }

    legacy_vlan_ids = dev.get('vlan_ids')
    if legacy_vlan_ids is None:
        legacy_vlan_ids = [dev['vlan_id']] if dev.get('vlan_id') is not None else []
    legacy_vlan_bonds = set(dev.get('legacy_vlan_bonds', []))
    for port in dev.get('vlan_ports', []):
        direct_port_vlans.setdefault(port, [])
        for vlan_id in legacy_vlan_ids:
            if vlan_id not in direct_port_vlans[port]:
                direct_port_vlans[port].append(vlan_id)
    for bg in dev.get('bond_groups', []):
        btype = bg.get('type', 'localbond')
        for bn in bg.get('bond_list', []):
            bond_vlans.setdefault(bn, [])
            # vlan_id is a legacy single-VLAN compatibility field.  Explicit
            # vlan_ports assignments are authoritative.  If legacy vlan_ports
            # names bonds, apply the selector only to those bonds; otherwise
            # retain the old fallback for otherwise unassigned bonds.
            use_legacy = (bn in legacy_vlan_bonds if legacy_vlan_bonds
                          else not bond_vlans[bn])
            if use_legacy:
                for vlan_id in legacy_vlan_ids:
                    if vlan_id not in bond_vlans[bn]:
                        bond_vlans[bn].append(vlan_id)
            if bn not in bond_attrs:
                bond_attrs[bn] = {
                    'type':        btype,
                    'mac_address': bg.get('mac-address', ''),
                    'lacp_bypass': bg.get('lacp-bypass', 'enabled') == 'enabled',
                }

    dev = dict(dev)
    dev.setdefault('bgp_neighbors', [])
    dev['computed_vlan_ports'] = []
    for port in sorted(direct_port_vlans, key=_bond_sort_key):
        vlans = sorted(direct_port_vlans[port])
        if not vlans:
            continue
        dev['computed_vlan_ports'].append({
            'name': port,
            'vlan_mode': 'access' if len(vlans) == 1 else 'trunk',
            'vlan_access': vlans[0] if len(vlans) == 1 else None,
            'vlan_trunk_range': (_compress_vlan_ids(vlans)
                                 if len(vlans) > 1 else None),
        })
    dev['computed_vlan_port_names'] = {
        item['name'] for item in dev['computed_vlan_ports']
    }
    if not bond_vlans:
        dev.setdefault('computed_bonds', [])
        direct_parent_maxsub = {}
        for port in direct_port_vlans:
            match = re.match(r'^swp(\d+)s(\d+)$', port)
            if match:
                swp_name = f"swp{match.group(1)}"
                sub = int(match.group(2))
                direct_parent_maxsub[swp_name] = max(
                    direct_parent_maxsub.get(swp_name, 0), sub
                )
        dev['parent_swps'] = {}
        for swp_name in sorted(direct_parent_maxsub, key=_bond_sort_key):
            count, lanes = _breakout_info(direct_parent_maxsub[swp_name])
            dev['parent_swps'][swp_name] = {
                'breakout': count,
                'lanes': lanes,
                'subs': list(range(count)),
            }
        dev.setdefault('member_swps', [])
        dev['bgp_plain_uplinks']  = []
        dev['bgp_uplink_parents'] = {}
        dev['peerlink_member_list'] = []
        bgp_parent_maxsub: dict = {}
        for nbr in dev.get('bgp_neighbors', []):
            if nbr == 'peerlink.4094':
                continue
            m = re.match(r'^swp(\d+)s(\d+)$', nbr)
            if m:
                parent = f"swp{m.group(1)}"
                sub = int(m.group(2))
                bgp_parent_maxsub[parent] = max(bgp_parent_maxsub.get(parent, 0), sub)
            else:
                dev['bgp_plain_uplinks'].append(nbr)
        template = dev.get('template', '')
        evpn_cfg = EVPN_UPLINK_TEMPLATE_CONFIG.get(template)
        for swp_name in sorted(bgp_parent_maxsub.keys(), key=_bond_sort_key):
            count, lanes = _breakout_info(bgp_parent_maxsub[swp_name])
            is_evpn = (evpn_cfg == "all") or (isinstance(evpn_cfg, set) and swp_name in evpn_cfg)
            dev['bgp_uplink_parents'][swp_name] = {
                'breakout': count, 'lanes': lanes,
                'subs': list(range(count)), 'evpn_uplink': is_evpn,
            }
        pp = dev.get('peerlink_ports', '') or ''
        dev['peerlink_member_list'] = _expand_swp_range(pp) if pp else []
        return dev

    computed_bonds = []
    parent_swp_maxsub: dict = {}
    member_swps: list = []

    # Direct VLAN breakout children need the parent breakout declaration too.
    # Previously only bond members contributed to parent_swps, so a rendered
    # swp3s0 could be referenced without first creating swp3 in breakout mode.
    for port in direct_port_vlans:
        match = re.match(r'^swp(\d+)s(\d+)$', port)
        if match:
            swp_name = f"swp{match.group(1)}"
            sub = int(match.group(2))
            parent_swp_maxsub[swp_name] = max(
                parent_swp_maxsub.get(swp_name, 0), sub
            )

    for bn in sorted(bond_vlans.keys(), key=_bond_sort_key):
        attrs = bond_attrs[bn]
        btype = attrs['type']
        vlans = sorted(bond_vlans[bn])

        if len(vlans) == 1:
            vlan_mode, vlan_access, vlan_trunk_range = 'access', vlans[0], None
        else:
            vlan_mode, vlan_access = 'trunk', None
            vlan_trunk_range = _compress_vlan_ids(vlans)

        if btype == 'localbond':
            if re.match(r'^bond\d+[a-zA-Z]\d+$', bn):
                members = [_bond_member(bn)]
            else:
                nums = re.findall(r'\d+', bn)
                members = [f'swp{n}' for n in nums]
            computed_bonds.append({
                'name':             bn,
                'members':          members,
                'type':             btype,
                'vlan_mode':        vlan_mode,
                'vlan_access':      vlan_access,
                'vlan_trunk_range': vlan_trunk_range,
            })
        else:
            member = _bond_member(bn)
            bid = _bond_id(bn)
            computed_bonds.append({
                'name':             bn,
                'member':           member,
                'id':               bid,
                'type':             btype,
                'mac_address':      attrs['mac_address'],
                'lacp_bypass':      attrs['lacp_bypass'],
                'vlan_mode':        vlan_mode,
                'vlan_access':      vlan_access,
                'vlan_trunk_range': vlan_trunk_range,
            })
            m = re.match(r'^swp(\d+)s(\d+)$', member)
            if m:
                swp_name = f"swp{m.group(1)}"
                sub = int(m.group(2))
                parent_swp_maxsub[swp_name] = max(parent_swp_maxsub.get(swp_name, 0), sub)
            else:
                if member not in member_swps:
                    member_swps.append(member)

    parent_swps = {}
    for swp_name in sorted(parent_swp_maxsub.keys(), key=_bond_sort_key):
        count, lanes = _breakout_info(parent_swp_maxsub[swp_name])
        parent_swps[swp_name] = {
            'breakout': count,
            'lanes':    lanes,
            'subs':     list(range(count)),
        }

    dev['computed_bonds'] = computed_bonds
    dev['parent_swps']    = parent_swps
    dev['member_swps']    = member_swps

    bgp_plain_uplinks: list = []
    bgp_parent_maxsub: dict = {}
    for nbr in dev.get('bgp_neighbors', []):
        if nbr == 'peerlink.4094':
            continue
        m = re.match(r'^swp(\d+)s(\d+)$', nbr)
        if m:
            parent = f"swp{m.group(1)}"
            sub = int(m.group(2))
            bgp_parent_maxsub[parent] = max(bgp_parent_maxsub.get(parent, 0), sub)
        else:
            bgp_plain_uplinks.append(nbr)

    template = dev.get('template', '')
    evpn_cfg = EVPN_UPLINK_TEMPLATE_CONFIG.get(template)
    bgp_uplink_parents: dict = {}
    for swp_name in sorted(bgp_parent_maxsub.keys(), key=_bond_sort_key):
        count, lanes = _breakout_info(bgp_parent_maxsub[swp_name])
        is_evpn = (evpn_cfg == "all") or (isinstance(evpn_cfg, set) and swp_name in evpn_cfg)
        bgp_uplink_parents[swp_name] = {
            'breakout':    count,
            'lanes':       lanes,
            'subs':        list(range(count)),
            'evpn_uplink': is_evpn,
        }

    dev['bgp_plain_uplinks']  = bgp_plain_uplinks
    dev['bgp_uplink_parents'] = bgp_uplink_parents

    pp = dev.get('peerlink_ports', '') or ''
    dev['peerlink_member_list'] = _expand_swp_range(pp) if pp else []

    return dev


def load_devices():
    with open(DEVICES_FILE, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("global", {}), data.get("devices", {})


def _subnet_last_usable(ip_cidr: str) -> str:
    """Return the last usable host IP in the subnet. e.g. 192.0.2.5/25 → 192.0.2.126"""
    net = ipaddress.ip_interface(ip_cidr).network
    return str(net.broadcast_address - 1)


def _vrr_gateway(vrr_ip: str) -> str:
    """Return the gateway IP: vrr_ip's last octet + 3. e.g. 192.0.2.131/29 → 192.0.2.134"""
    ip = vrr_ip.split('/')[0]
    prefix, last = ip.rsplit('.', 1)
    return f"{prefix}.{int(last) + 3}"


def _legacy_yaml_scalar_string(value, field):
    """Return the string represented by a legacy template scalar.

    Existing project files may wrap password values in an extra YAML quote
    pair because older templates emitted them verbatim.  Decode only that
    explicit wrapper; ordinary strings are preserved exactly and are quoted
    safely by ``_yaml_string`` at render time.
    """
    if not isinstance(value, str):
        raise ValueError(f"AAA {field} 必须是字符串")
    text = value.strip()
    if not text:
        raise ValueError(f"AAA {field} 不能为空")
    if len(text) >= 2 and text[0] in {"'", '"'} and text[-1] == text[0]:
        try:
            decoded = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError(f"AAA {field} 引号格式无效") from exc
        if not isinstance(decoded, str):
            raise ValueError(f"AAA {field} 必须解析为字符串")
        return decoded
    return text


def _extra_aaa_users(global_vars):
    """Validate and normalize non-cumulus AAA users for Jinja templates.

    Usernames are deliberately limited to portable Linux/NVUE account names.
    This both catches configuration mistakes early and prevents a mapping key
    from injecting additional YAML nodes into a generated switch config.
    """
    try:
        users = global_vars["system"]["aaa"]["user"]
    except (KeyError, TypeError):
        return []
    if not isinstance(users, dict):
        raise ValueError("AAA user 必须是 mapping")

    normalized = []
    for username in sorted(users, key=lambda item: str(item)):
        if username == "cumulus":
            continue
        if (not isinstance(username, str)
                or not _SAFE_AAA_USERNAME_RE.fullmatch(username)):
            raise ValueError(
                f"AAA username 不安全或不受支持: {username!r}; "
                "仅允许小写字母、数字、下划线和连字符，最长 32 字符"
            )
        account = users[username]
        if not isinstance(account, dict):
            raise ValueError(f"AAA user {username!r} 配置必须是 mapping")
        if "hashed-password" not in account or "role" not in account:
            raise ValueError(
                f"AAA user {username!r} 必须同时配置 hashed-password 和 role"
            )
        full_name = account.get("full-name")
        if full_name is not None and not isinstance(full_name, str):
            raise ValueError(f"AAA user {username!r} full-name 必须是字符串")
        normalized.append({
            "username": username,
            "full_name": full_name,
            "hashed_password": _legacy_yaml_scalar_string(
                account["hashed-password"], f"user {username!r} hashed-password"
            ),
            "role": _legacy_yaml_scalar_string(
                account["role"], f"user {username!r} role"
            ),
        })
    return normalized


def _yaml_string(value):
    """Quote a validated string as a JSON scalar, which is valid YAML too."""
    if not isinstance(value, str):
        raise ValueError("YAML 字符串过滤器只接受字符串")
    return json.dumps(value, ensure_ascii=False)


def build_env():
    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters['vrr_gateway'] = _vrr_gateway
    env.filters['subnet_last_usable'] = _subnet_last_usable
    env.filters['yaml_string'] = _yaml_string
    env.globals['extra_aaa_users'] = _extra_aaa_users
    return env


def _tokenize(s):
    tokens = set()
    for part in re.split(r'[\-_\s]+', s.lower()):
        for sub in re.findall(r'[a-z]+|\d+', part):
            if sub and not sub.isdigit():
                tokens.add(sub)
    return tokens


def _best_template(template_hint, hostname):
    """在 TEMPLATES_DIR 中查找最匹配的模板文件。"""
    exact = f"{template_hint}.yaml.j2"
    if os.path.isfile(os.path.join(TEMPLATES_DIR, exact)):
        return exact, True

    available = sorted(
        os.path.basename(p) for p in glob.glob(os.path.join(TEMPLATES_DIR, "*.yaml.j2"))
    )
    if not available:
        raise FileNotFoundError(f"模板目录 {TEMPLATES_DIR} 中未找到任何 .yaml.j2 文件")

    query_tokens = _tokenize(hostname) | _tokenize(template_hint)
    hint_tokens  = _tokenize(template_hint)

    best_score = (-1, 0, -1)
    best_file  = available[0]
    for fname in available:
        base  = fname[: -len(".yaml.j2")]
        ftoks = _tokenize(base)
        hit      = len(ftoks & query_tokens)
        extra    = len(ftoks - query_tokens)
        hint_hit = len(ftoks & hint_tokens)
        score = (hit, -extra, hint_hit)
        if score > best_score:
            best_score = score
            best_file  = fname

    return best_file, False


def render(env, global_vars, device_name, device_vars):
    source_b64 = device_vars.get("source_yaml_b64")
    if source_b64:
        return _decode_source_yaml(source_b64, device_vars.get("source_yaml_sha256"))

    device_vars   = preprocess_device(device_vars)
    template_hint = device_vars.get('template', '')

    template_name, is_exact = _best_template(template_hint, device_name)
    resolved_base = template_name[: -len(".yaml.j2")]

    if not is_exact:
        print(f"  [TMPL] {device_name}: '{template_hint}' 无精确匹配，"
              f"使用最佳匹配模板 '{resolved_base}'")

    try:
        tmpl = env.get_template(template_name)
    except TemplateNotFound:
        raise FileNotFoundError(f"模板不存在: 03-templates-j2/{template_name}")

    return tmpl.render(d=device_vars, global_=global_vars, g=global_vars)


def _nvue_null_paths(value, path="$"):
    """Return null placeholders that NVUE rejects inside a generated document.

    Jinja renders a Python ``None`` used in a scalar expression as the literal
    string ``None``. YAML loads that as a normal string, but NVUE still rejects
    values such as ``autonomous-system: None``.
    """
    errors = []
    if value is None:
        return [path]
    if isinstance(value, str) and value.strip().casefold() in {"none", "null"}:
        return [path]
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            if key is None or key_text.casefold() in {"none", "null", "vlannone"}:
                errors.append(f"{path}.<key:{key_text}>")
            errors.extend(_nvue_null_paths(child, f"{path}.{key_text}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(_nvue_null_paths(child, f"{path}[{index}]"))
    return errors


def _merge_vrl_mapping(target, addition, path="set"):
    """Merge VRL config without overwriting a different existing NVUE value."""
    for key, value in addition.items():
        key_path = f"{path}.{key}"
        if key not in target:
            target[key] = copy.deepcopy(value)
        elif isinstance(target[key], dict) and isinstance(value, dict):
            _merge_vrl_mapping(target[key], value, key_path)
        elif target[key] != value:
            raise ValueError(f"VRL 配置与现有配置冲突：{key_path}")


def _merge_dhcp_relay_mapping(target, addition, path="set"):
    """Merge relay support nodes without creating duplicate top-level keys."""
    for key, value in addition.items():
        key_path = f"{path}.{key}"
        if key not in target:
            target[key] = copy.deepcopy(value)
        elif isinstance(target[key], dict) and isinstance(value, dict):
            _merge_dhcp_relay_mapping(target[key], value, key_path)
        elif target[key] != value:
            raise ValueError(f"DHCP relay 配置与现有配置冲突：{key_path}")


def _inject_dhcp_relay_support(document, device_vars):
    """Merge SVI/VRR loopbacks and ifupdown snippets into one ``set``.

    Templates already own the top-level ``system`` and ``vrf`` mappings.  A
    second mapping with the same YAML key would either fail strict parsing or
    be silently ignored by a permissive loader, so the scenario-3 support
    nodes are merged into the parsed document before it is published.
    """
    support = device_vars.get("svi_vrr_support")
    if support is None:
        # Compatibility for direct callers/tests created before SVI/VRR
        # support was deliberately decoupled from DHCP relay enablement.
        support = [
            relay for relay in device_vars.get("dhcp_relays", [])
            if relay.get("mode") == "gateway"
        ]
    if not support or device_vars.get("source_yaml_b64"):
        return False
    set_operations = [
        item["set"] for item in document
        if isinstance(item, dict) and isinstance(item.get("set"), dict)
    ] if isinstance(document, list) else []
    if len(set_operations) != 1:
        raise ValueError(
            "DHCP relay 设备的生成 YAML 必须且只能包含一个 set，"
            f"实际为 {len(set_operations)} 个"
        )

    vrfs = {}
    snippets = {}
    for item in support:
        vrfs[item["vrf"]] = {"loopback": {"ip": {"address": {
            item["loopback_address"]: {},
        }}}}
        for interface, value in item.get("ifupdown_snippets", {}).items():
            previous = snippets.get(interface)
            if previous is not None and previous != value:
                raise ValueError(
                    f"DHCP relay {interface} 需要两个不同的 ifupdown2_eni 配置"
                )
            snippets[interface] = value

    addition = {"vrf": vrfs}
    if snippets:
        addition["system"] = {"config": {"snippet": {
            "ifupdown2_eni": snippets,
        }}}
    _merge_dhcp_relay_mapping(set_operations[0], addition)
    return True


def _inject_vrl_into_document(document, device_vars, global_vars):
    """Merge route-leaking into the document's existing, single ``set``.

    NVUE ``nv config replace`` consumes one set operation from these generated
    files.  A second top-level ``- set`` may be accepted syntactically but is
    ignored, so VRL must be merged into the original operation.
    """
    if not device_vars.get("vrl") or device_vars.get("source_yaml_b64"):
        return False
    set_operations = [
        item["set"] for item in document
        if isinstance(item, dict) and isinstance(item.get("set"), dict)
    ] if isinstance(document, list) else []
    if len(set_operations) != 1:
        raise ValueError(
            f"VRL 设备的生成 YAML 必须且只能包含一个 set，实际为 {len(set_operations)} 个"
        )

    vrl = global_vars.get("vrl_render") or {}
    prefix_lists = {}
    for prefix_list in vrl.get("prefix_lists", []):
        rules = {}
        for index, rule in enumerate(prefix_list["rules"], 1):
            match_options = {}
            if rule["max_prefix_len"] is not None:
                match_options["max-prefix-len"] = rule["max_prefix_len"]
            if rule["min_prefix_len"] is not None:
                match_options["min-prefix-len"] = rule["min_prefix_len"]
            rules[str(index)] = {
                "action": "permit",
                "match": {rule["subnet"]: match_options},
            }
        rules[str(len(rules) + 1)] = {"action": "deny", "match": {"any": {}}}
        prefix_lists[prefix_list["name"]] = {"rule": rules}

    route_maps = {}
    for route_map in vrl.get("route_maps", []):
        route_maps[route_map["name"]] = {"rule": {
            "1": {
                "action": {"permit": {}},
                "match": {
                    "ip-prefix-list": route_map["prefix_list"],
                    "type": "ipv4",
                },
            },
            "2": {
                "action": {"deny": {}},
                "match": {"type": "ipv4"},
            },
        }}

    vrfs = {}
    for target in vrl.get("imports", []):
        source = target["sources"][0]
        vrfs[target["vrf"]] = {"router": {"bgp": {"address-family": {
            "ipv4-unicast": {"route-import": {"from-vrf": {
                "list": {source["from_vrf"]: {}},
                "route-map": source["route_map"],
                "state": "enabled",
            }}}
        }}}}

    addition = {
        "router": {"policy": {
            "prefix-list": prefix_lists,
            "route-map": route_maps,
        }},
        "vrf": vrfs,
    }
    _merge_vrl_mapping(set_operations[0], addition)
    return True


_DROP_NVUE_NODE = object()


def _prune_nvue_nulls(value):
    """Drop null placeholder operations while preserving explicit empty mappings."""
    if value is None:
        return _DROP_NVUE_NODE, 1
    if isinstance(value, dict):
        if not value:
            return {}, 0
        cleaned = {}
        removed = 0
        for key, child in value.items():
            key_text = str(key)
            if key is None or key_text.casefold() in {"none", "null", "vlannone"}:
                removed += 1
                continue
            new_child, child_removed = _prune_nvue_nulls(child)
            removed += child_removed
            if new_child is not _DROP_NVUE_NODE:
                cleaned[key] = new_child
        if not cleaned:
            return _DROP_NVUE_NODE, removed
        return cleaned, removed
    if isinstance(value, list):
        cleaned = []
        removed = 0
        for child in value:
            new_child, child_removed = _prune_nvue_nulls(child)
            removed += child_removed
            if new_child is not _DROP_NVUE_NODE:
                cleaned.append(new_child)
        return cleaned, removed
    return value, 0


def _build_ref_index(ref_dir: str) -> dict:
    """Build a case-insensitive name→path index of .yaml files under ref_dir."""
    index = {}
    for path in glob.glob(os.path.join(ref_dir, "**", "*.yaml"), recursive=True):
        index[os.path.splitext(os.path.basename(path))[0].casefold()] = path
    return index


def generate_all(target=None, verify=False, ref_dir=None, fail_on_diff=False):
    global_vars, devices = load_devices()
    env = build_env()

    if target:
        match = next((k for k in devices if k.lower() == target.lower()), None)
        if match is None:
            print(f"[ERROR] 设备 '{target}' 不在 91-devices.yaml 中")
            sys.exit(1)
        devices = {match: devices[match]}

    ref_index = _build_ref_index(ref_dir) if ref_dir else {}

    staging_dir = OUTPUT_DIR + ".tmp"
    if not verify:
        if os.path.exists(staging_dir):
            shutil.rmtree(staging_dir)
        os.makedirs(staging_dir, exist_ok=True)

    ok = skipped = errors = diffs = 0

    for name, device_vars in devices.items():
        try:
            rendered = render(env, global_vars, name, device_vars)
        except Exception as e:
            print(f"[ERROR] {name}: {e}")
            errors += 1
            continue

        try:
            rendered_doc = _load_generated_yaml(rendered)
        except yaml.YAMLError as e:
            print(f"[ERROR] {name}: 生成的 YAML 语法无效: {e}")
            errors += 1
            continue
        try:
            dhcp_relay_injected = _inject_dhcp_relay_support(
                rendered_doc, device_vars,
            )
            vrl_injected = _inject_vrl_into_document(
                rendered_doc, device_vars, global_vars,
            )
        except ValueError as e:
            print(f"[ERROR] {name}: {e}")
            errors += 1
            continue
        rendered_doc, removed_nulls = _prune_nvue_nulls(rendered_doc)
        if rendered_doc is _DROP_NVUE_NODE:
            print(f"[ERROR] {name}: 删除 null 占位后配置为空")
            errors += 1
            continue
        if removed_nulls:
            print(f"  [CLEAN] {name}: 已省略 {removed_nulls} 个 null NVUE 空操作")
        if vrl_injected:
            print(f"  [VRL] {name}: 已合并到原有单一 set 操作")
        if dhcp_relay_injected:
            print(f"  [SVI/VRR] {name}: 已合并 VRF loopback/ifupdown2 辅助配置")
        if removed_nulls or vrl_injected or dhcp_relay_injected:
            rendered = yaml.safe_dump(
                rendered_doc, allow_unicode=True, sort_keys=False, width=120
            )
        null_paths = _nvue_null_paths(rendered_doc)
        if null_paths:
            print(
                f"[ERROR] {name}: 生成的 NVUE YAML 包含 null："
                + ", ".join(null_paths[:8])
            )
            errors += 1
            continue
        reference_errors = _interface_vrf_errors(rendered_doc)
        if reference_errors:
            print(
                f"[ERROR] {name}: 生成的接口引用无效："
                + ", ".join(reference_errors[:8])
            )
            errors += 1
            continue

        if verify:
            ref_path = ref_index.get(name.casefold())
            if ref_path:
                with open(ref_path, encoding="utf-8") as f:
                    ref = f.read()
                diff = list(difflib.unified_diff(
                    ref.splitlines(keepends=True),
                    rendered.splitlines(keepends=True),
                    fromfile=f"reference/{name}.yaml",
                    tofile=f"generated/{name}.yaml",
                ))
                if diff:
                    diffs += 1
                    print(f"[DIFF] {name}:")
                    print("".join(diff[:40]))
                    if len(diff) > 40:
                        print(f"  ... (共 {len(diff)} 行差异)")
                else:
                    print(f"[MATCH] {name}: 与参考文件一致")
            else:
                print(f"[SKIP] {name}: 无参考文件可比对")
                skipped += 1
            ok += 1
        else:
            out_file = os.path.join(staging_dir, f"{name}.yaml")
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(rendered)
            ok += 1

    print(f"\n完成：生成 {ok} 台，跳过 {skipped} 台，差异 {diffs} 台，错误 {errors} 台")

    if not verify:
        if errors == 0:
            directory_errors = _validate_yaml_directory(staging_dir)
            if directory_errors:
                errors += len(directory_errors)
                for detail in directory_errors:
                    print(f"[ERROR] 生成的 YAML 校验失败：{detail}")
        if errors == 0:
            if os.path.exists(OUTPUT_DIR):
                shutil.rmtree(OUTPUT_DIR)
            os.rename(staging_dir, OUTPUT_DIR)
            print(f"输出目录：{OUTPUT_DIR}")
        else:
            shutil.rmtree(staging_dir, ignore_errors=True)
            print(f"[ABORT] 存在错误，未写入输出目录")
            sys.exit(1)
    else:
        if errors > 0 or (fail_on_diff and (diffs > 0 or skipped > 0)):
            sys.exit(1)


# ── ETH: patch_descriptions ───────────────────────────────────────────────────

_DOT_LINE_RE  = re.compile(r'"([^"]+)":"([^"]+)"\s+--\s+"([^"]+)":"([^"]+)"')
_SWP_KEY_RE   = re.compile(r'^(\s+)(swp\S+):\s*$')
_SWP_CHILD_RE = re.compile(r'^(swp\d+)s\d+$')
_SWP_PLAIN_RE = re.compile(r'^swp(\d+)$')
_SWP_SUB_RE   = re.compile(r'^(swp\d+)s(\d+)$')
_NO_DESC_SKIP_RE = re.compile(r'oobofoob.*leaf|oob.*leaf|tor|tan.*1gleaf', re.IGNORECASE)


def _compress_ports(ports):
    plain = {}
    sub   = {}
    for p in ports:
        m = _SWP_PLAIN_RE.match(p)
        if m:
            plain[int(m.group(1))] = True
            continue
        m = _SWP_SUB_RE.match(p)
        if m:
            sub.setdefault(m.group(1), []).append(int(m.group(2)))

    def make_ranges(nums):
        if not nums:
            return []
        nums = sorted(nums)
        s = e = nums[0]
        ranges = []
        for n in nums[1:]:
            if n == e + 1:
                e = n
            else:
                ranges.append((s, e)); s = e = n
        ranges.append((s, e))
        return ranges

    result = []
    for s, e in make_ranges(list(plain)):
        if s == e:             result.append(f"swp{s}")
        elif e == s + 1:       result.extend([f"swp{s}", f"swp{e}"])
        else:                  result.append(f"swp{s}-{e}")
    for prefix in sorted(sub, key=lambda p: int(re.search(r'\d+', p).group())):
        for s, e in make_ranges(sub[prefix]):
            if s == e:         result.append(f"{prefix}s{s}")
            elif e == s + 1:   result.extend([f"{prefix}s{s}", f"{prefix}s{e}"])
            else:              result.append(f"{prefix}s{s}-s{e}")
    return result


def _load_dot_lines(dot_file):
    with open(dot_file, encoding="utf-8") as f:
        return f.readlines()


def _load_dot_devices(dot_lines):
    devs = set()
    for line in dot_lines:
        m = _DOT_LINE_RE.match(line.strip())
        if m:
            devs.add(m.group(1).lower())
            devs.add(m.group(3).lower())
    return devs


def _grep_dot_descriptions(dot_lines, hostname):
    host_lower = hostname.lower()
    desc      = {}
    conflicts = set()
    for lineno, line in enumerate(dot_lines, 1):
        if host_lower not in line.lower():
            continue
        m = _DOT_LINE_RE.match(line.strip())
        if not m:
            continue
        src_dev, src_port, dst_dev, dst_port = m.group(1), m.group(2), m.group(3), m.group(4)
        for (dev, port), (peer_dev, peer_port) in [
            ((src_dev, src_port), (dst_dev, dst_port)),
            ((dst_dev, dst_port), (src_dev, src_port)),
        ]:
            dev_lower = dev.lower()
            # A site prefix is allowed (for example SITE01-OOB-Leaf01), but a
            # bare suffix match is unsafe: OOBofOOB-Leaf01 also ends with
            # OOB-Leaf01.  Require either the exact hostname or a real
            # hyphen-delimited prefix boundary.
            if dev_lower != host_lower and not dev_lower.endswith(f"-{host_lower}"):
                continue
            val = f"To:----{peer_dev}-----{peer_port}"
            if port in desc and desc[port] != val:
                print(f"[WARNING] dot 文件第 {lineno} 行发现重复连接（端口已有不同对端，将跳过 patch）："
                      f" {dev} {port}  旧对端={desc[port]}  新对端={val}", file=sys.stderr)
                conflicts.add(port)
            desc[port] = val
    for port in conflicts:
        del desc[port]
    return desc


def _load_csv_hostnames():
    csv_path = _CSV_FILE
    if not os.path.isfile(csv_path):
        return set()
    hosts = set()
    with open(csv_path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            # AIR rows deliberately reuse the production device's complete
            # YAML and therefore are not expected to appear in the production
            # LLDP dot used to add interface descriptions.
            if (row.get("type") or "").strip().lower() == "air":
                continue
            h = (row.get("hostname") or "").strip().lower()
            if h:
                hosts.add(h)
    return hosts


def _patch_yaml(filepath, host_descriptions):
    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()

    all_swp_ports = set()
    in_iface = False
    for line in lines:
        s = line.rstrip("\n\r")
        if re.match(r'^    interface:\s*$', s):
            in_iface = True; continue
        if in_iface and s.strip() and len(s) - len(s.lstrip()) <= 4:
            in_iface = False
        if not in_iface:
            continue
        m = _SWP_KEY_RE.match(s)
        if m and len(m.group(1)) == 6:
            all_swp_ports.add(m.group(2))

    patched = False
    result  = []
    in_interface_block   = False
    interface_swp_indent = 6
    missing_in_dot       = []

    for i, line in enumerate(lines):
        stripped = line.rstrip("\n\r")
        if re.match(r'^    interface:\s*$', stripped):
            in_interface_block = True
            result.append(line); continue
        if in_interface_block and stripped.strip():
            if len(stripped) - len(stripped.lstrip()) <= 4:
                in_interface_block = False
        result.append(line)
        if not in_interface_block:
            continue
        m = _SWP_KEY_RE.match(stripped)
        if not m or len(m.group(1)) != interface_swp_indent:
            continue
        indent, port = m.group(1), m.group(2)
        if port in host_descriptions:
            result.append(f"{indent}  description: {host_descriptions[port]}\n")
            patched = True
        else:
            next_stripped = lines[i + 1].rstrip("\n\r") if i + 1 < len(lines) else ""
            if re.match(r'^\s+description:', next_stripped):
                continue
            has_child = any(
                _SWP_CHILD_RE.match(p) and _SWP_CHILD_RE.match(p).group(1) == port
                for p in all_swp_ports
            )
            if not has_child:
                missing_in_dot.append(port)

    if patched:
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(result)
    return patched, missing_in_dot, all_swp_ports


def _port_sort_key(p):
    return [int(c) if c.isdigit() else c for c in re.split(r'(\d+)', p)]


def _run_patch_descriptions(dot_file, output_dir):
    """Inline equivalent of patch_descriptions.main()."""
    dest_dir = output_dir + "_with_desc"
    if os.path.exists(dest_dir):
        shutil.rmtree(dest_dir)
    shutil.copytree(output_dir, dest_dir)

    dot_lines   = _load_dot_lines(dot_file)
    dot_devices = _load_dot_devices(dot_lines)
    csv_hosts   = _load_csv_hostnames()
    print(f"Loaded dot file: {dot_file}")

    if csv_hosts:
        absent = sorted(
            h for h in csv_hosts
            if not any(d.endswith(h) for d in dot_devices)
        )
        if absent:
            print(f"\n[INFO] 以下 {len(absent)} 台设备在 CSV 中有配置，但在 dot 文件中无任何连接记录：")
            for h in absent:
                print(f"  {h}")

    patched_count    = 0
    skipped_count    = 0
    no_desc          = {}
    no_desc_skipped  = []
    yaml_swp_ports   = {}
    host_dot_ports   = {}

    for fname in sorted(os.listdir(dest_dir)):
        if not fname.endswith(".yaml"):
            continue
        hostname     = fname[:-5]
        fpath        = os.path.join(dest_dir, fname)
        host_descs   = _grep_dot_descriptions(dot_lines, hostname)
        patched, missing, swp_ports = _patch_yaml(fpath, host_descs)
        yaml_swp_ports[hostname.lower()] = swp_ports
        host_dot_ports[hostname.lower()] = set(host_descs.keys())
        if patched:
            patched_count += 1
        else:
            skipped_count += 1
        if missing:
            if _NO_DESC_SKIP_RE.search(hostname):
                access  = [p for p in missing
                           if _SWP_PLAIN_RE.match(p) and 1 <= int(_SWP_PLAIN_RE.match(p).group(1)) <= 48]
                uplinks = [p for p in missing if p not in access]
                if access:
                    no_desc_skipped.append(hostname)
                if uplinks:
                    no_desc[hostname] = uplinks
            else:
                no_desc[hostname] = missing

    extra_in_dot = {}
    for host_lower, dot_ports in host_dot_ports.items():
        if host_lower not in yaml_swp_ports:
            continue
        for port in dot_ports:
            if not re.match(r'^swp\d', port):
                continue
            if port not in yaml_swp_ports[host_lower]:
                extra_in_dot.setdefault(host_lower, []).append(port)

    print(f"\nPatched:  {patched_count} files")
    print(f"Skipped:  {skipped_count} files (no matching descriptions)")
    print(f"Output:   {dest_dir}")

    if no_desc_skipped:
        print(f"\n[已忽略] swp1-48（1G 接入口）有部分未在 dot 文件中出现（端口未使用），已跳过（共 {len(no_desc_skipped)} 台）：")
        for h in sorted(no_desc_skipped):
            print(f"  {h}")

    if no_desc:
        print("\n[WARNING] yaml 中有此接口但 dot 中无连接记录，未添加 description：")
        for hostname, ports in sorted(no_desc.items()):
            if not any(d.endswith(hostname.lower()) for d in dot_devices):
                print(f"  {hostname}: （设备在 dot 文件中无任何连接记录）")
                continue
            compressed = _compress_ports(sorted(ports, key=_port_sort_key))
            print(f"  {hostname}: {', '.join(compressed)}")

    if extra_in_dot:
        print("\n[WARNING] dot 中有连接记录但 yaml 中无此接口，无法 patch（请检查 CSV 是否已同步 xlsx 新增线路）：")
        for host_lower, ports in sorted(extra_in_dot.items()):
            compressed = _compress_ports(sorted(ports, key=_port_sort_key))
            print(f"  {host_lower}: {', '.join(compressed)}")


def _topology_dot_files(suffix):
    """优先使用固定输入 p2p.xlsx 所指真实文件名对应的 DOT。"""
    candidates = sorted(glob.glob(os.path.join(P2P_OUTPUT_DIR, f"*-{suffix}.dot")))
    input_file = os.path.realpath(os.path.join(P2P_INPUT_DIR, "p2p.xlsx"))
    input_stem = os.path.splitext(os.path.basename(input_file))[0]
    expected = os.path.join(P2P_OUTPUT_DIR, f"{input_stem}-{suffix}.dot")
    return [expected] if os.path.isfile(expected) else candidates


def _topology_air_json_files():
    """Return AIR JSON exports, preferring the file for the active P2P XLSX."""
    candidates = sorted(glob.glob(os.path.join(P2P_OUTPUT_DIR, "*-air.json")))
    input_file = os.path.realpath(os.path.join(P2P_INPUT_DIR, "p2p.xlsx"))
    input_stem = os.path.splitext(os.path.basename(input_file))[0]
    expected = os.path.join(P2P_OUTPUT_DIR, f"{input_stem}-air.json")
    return [expected] if os.path.isfile(expected) else candidates


def prompt_patch_descriptions(output_dir):
    """Ask whether to patch swp descriptions using DOT files in P2P/output-p2p."""
    try:
        answer = _timed_input("\n是否要 patch swp 接口 description？[Y/n] ", default="y").strip().lower()
    except EOFError:
        return
    if answer not in ("y", "yes"):
        return

    dot_files = _topology_dot_files("lldpq")

    if not dot_files:
        print(f"[WARN] P2P 输出目录 {P2P_OUTPUT_DIR} 下未找到 *-lldpq.dot 文件，跳过 patch")
        return

    if len(dot_files) == 1:
        dot_file = dot_files[0]
        confirm = _timed_input(f"使用 dot 文件：{dot_file}\n确认？[Y/n] ", default="y").strip().lower()
        if confirm in ("n", "no"):
            print("已取消。")
            return
    else:
        print("P2P 输出目录下找到以下 lldpq dot 文件：")
        for i, f in enumerate(dot_files, 1):
            print(f"  [{i}] {os.path.basename(f)}")
        choice = _timed_input(f"请选择 [1-{len(dot_files)}]，或回车取消：", default="1").strip()
        if not choice:
            print("已取消。")
            return
        try:
            idx = int(choice) - 1
            if not (0 <= idx < len(dot_files)):
                raise ValueError
        except ValueError:
            print("[WARN] 无效选择，跳过 patch")
            return
        dot_file = dot_files[idx]

    dot_base = re.sub(r'-lldpq$', '', os.path.splitext(os.path.basename(dot_file))[0])
    selected_xlsx = os.path.realpath(os.path.join(P2P_INPUT_DIR, "p2p.xlsx"))
    selected_stem = os.path.splitext(os.path.basename(selected_xlsx))[0]
    xlsx_file = selected_xlsx if selected_stem == dot_base else ""
    if os.path.isfile(xlsx_file):
        dot_mtime  = os.path.getmtime(dot_file)
        xlsx_mtime = os.path.getmtime(xlsx_file)
        if xlsx_mtime > dot_mtime:
            dot_t  = datetime.fromtimestamp(dot_mtime).strftime("%Y-%m-%d %H:%M:%S")
            xlsx_t = datetime.fromtimestamp(xlsx_mtime).strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n[WARNING] xlsx 文件比 dot 文件新，dot 文件可能已过期！")
            print(f"  dot  修改时间：{dot_t}")
            print(f"  xlsx 修改时间：{xlsx_t}")
            print(f"  建议先重新运行 P2P/b-xlsx_to_dot.py 生成新的 dot 文件。")
            cont = _timed_input("是否仍然使用此 dot 文件继续 patch？[Y/n] ", default="y").strip().lower()
            if cont not in ("y", "yes"):
                print("已取消。")
                return

    _run_patch_descriptions(dot_file, output_dir)


# ── ETH: air_configs ──────────────────────────────────────────────────────────

_AIR_NODE_RE = re.compile(r'"([^"]+)"\s+\[.*mgmt_ip="([^"]+)"')
_IP_CIDR_RE  = re.compile(r'^(\s+)(\d+\.\d+\.\d+\.\d+)(/\d+):\s*\{\}\s*$')
_IP_GW_RE    = re.compile(r'^(\s+)(\d+\.\d+\.\d+\.\d+):\s*\{\}\s*$')
_AIR_HOST_PREFIX = "AIR-"
_AIR_MGMT_PREFIX = 24
_AIR_MGMT_GATEWAY = "192.168.200.1"


def _load_air_info(air_file):
    """Return AIR node names, ports and management IPs from an AIR dot file."""
    info = {}
    with open(air_file, encoding="utf-8") as f:
        for line in f:
            m = _AIR_NODE_RE.search(line)
            if m:
                key = m.group(1).lower()
                info.setdefault(key, {
                    "hostname": m.group(1), "ports": set(), "mgmt_ip": None
                })
                info[key]["hostname"] = m.group(1)
                info[key]["mgmt_ip"] = m.group(2)
                continue
            m = _DOT_LINE_RE.match(line.strip())
            if m:
                for dev, port in [(m.group(1), m.group(2)), (m.group(3), m.group(4))]:
                    key = dev.lower()
                    info.setdefault(key, {
                        "hostname": dev, "ports": set(), "mgmt_ip": None
                    })
                    info[key]["ports"].add(port)
    return info


def _air_hostname(hostname):
    """Return the AIR hostname without adding the prefix more than once."""
    if hostname.casefold().startswith(_AIR_HOST_PREFIX.casefold()):
        return hostname
    return f"{_AIR_HOST_PREFIX}{hostname}"


def _lookup_air_device(air_info, hostname):
    """Match a production hostname to one unambiguous AIR DOT node.

    AIR nodes may add both the ``AIR-`` prefix and a site prefix (for example,
    ``AIR-SITE01-OOB-Leaf01``). Prefer an exact name after removing ``AIR-``;
    only then fall back to a site-prefix suffix match.  A plain first-match
    suffix lookup is unsafe because ``OOBofOOB-Leaf01`` also ends with
    ``OOB-Leaf01``.
    """
    host_key = hostname.casefold()
    prefix = _AIR_HOST_PREFIX.casefold()

    direct = air_info.get(host_key)
    if direct is not None:
        return direct

    exact = []
    suffix = []
    for key, value in air_info.items():
        normalized = key[len(prefix):] if key.startswith(prefix) else key
        if normalized == host_key:
            exact.append(value)
        elif normalized.endswith(f"-{host_key}"):
            suffix.append(value)

    candidates = exact or suffix
    if not candidates:
        return None
    if len(candidates) > 1:
        names = ", ".join(sorted(item["hostname"] for item in candidates))
        raise ValueError(
            f"AIR 设备名匹配不唯一：{hostname} 可匹配 {names}；"
            "请调整 *-air.dot 中的设备名"
        )
    return candidates[0]


def _replace_air_hostname(lines, hostname):
    """Replace the generated NVUE YAML system.hostname value."""
    result = []
    in_system = False
    system_indent = None
    replaced = 0

    for line in lines:
        stripped = line.rstrip("\n\r")
        indent = len(stripped) - len(stripped.lstrip()) if stripped.strip() else None

        system_match = re.match(r'^(\s*)system:\s*$', stripped)
        if system_match:
            in_system = True
            system_indent = len(system_match.group(1))
            result.append(line)
            continue

        if in_system and indent is not None and indent <= system_indent:
            in_system = False
            system_indent = None

        hostname_match = re.match(r'^(\s+)hostname:\s*.*$', stripped) if in_system else None
        if hostname_match:
            result.append(f"{hostname_match.group(1)}hostname: {hostname}\n")
            replaced += 1
            continue

        result.append(line)

    if replaced != 1:
        raise ValueError(
            f"expected exactly one system.hostname entry, found {replaced}"
        )
    return result


def _filter_air_yaml(filepath, air_ports, mgmt_ip=None, hostname=None):
    """Filter AIR ports/address and optionally replace system.hostname."""
    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()

    SWP_INDENT = 6
    result = []
    in_interface = False
    skip_port = False
    in_eth0 = False
    in_eth0_ipv4 = False
    in_eth0_addr = False
    in_eth0_gw   = False

    for line in lines:
        s = line.rstrip("\n\r")

        if re.match(r"^    interface:\s*$", s):
            in_interface = True
            skip_port = False
            in_eth0 = in_eth0_ipv4 = in_eth0_addr = in_eth0_gw = False
            result.append(line)
            continue

        if not in_interface:
            result.append(line)
            continue

        if s.strip() and len(s) - len(s.lstrip()) <= 4:
            in_interface = False
            skip_port = False
            in_eth0 = in_eth0_ipv4 = in_eth0_addr = in_eth0_gw = False
            result.append(line)
            continue

        _iface_key = re.match(r'^(\s{6})(\S+):\s*$', s)
        if _iface_key:
            port = _iface_key.group(2)
            in_eth0 = (port == "eth0")
            in_eth0_ipv4 = in_eth0_addr = in_eth0_gw = False
            if port == "eth0":
                skip_port = False
                result.append(line)
            elif port.startswith("swp") and air_ports:
                skip_port = port not in air_ports
                if not skip_port:
                    result.append(line)
            else:
                # Non-front-panel interfaces (bond, vlan, lo, peerlink, ...)
                # must not inherit the skip state of the preceding swp.
                skip_port = False
                result.append(line)
            continue

        if skip_port:
            continue

        if in_eth0 and mgmt_ip:
            cur_indent = len(s) - len(s.lstrip()) if s.strip() else None

            if re.match(r"^\s{8}ipv4:\s*$", s):
                in_eth0_ipv4 = True
                in_eth0_addr = in_eth0_gw = False
                result.append(line)
                continue

            if in_eth0_ipv4:
                if re.match(r"^\s{10}address:\s*$", s):
                    in_eth0_addr = True
                    in_eth0_gw   = False
                    result.append(line)
                    continue
                if re.match(r"^\s{10}gateway:\s*$", s):
                    in_eth0_gw   = True
                    in_eth0_addr = False
                    result.append(line)
                    continue
                if cur_indent is not None and cur_indent <= 8:
                    in_eth0_ipv4 = in_eth0_addr = in_eth0_gw = False

            if in_eth0_addr:
                mm = _IP_CIDR_RE.match(s)
                if mm:
                    result.append(
                        f"{mm.group(1)}{mgmt_ip}/{_AIR_MGMT_PREFIX}: {{}}\n"
                    )
                    continue

            if in_eth0_gw:
                mm = _IP_GW_RE.match(s)
                if mm:
                    result.append(
                        f"{mm.group(1)}{_AIR_MGMT_GATEWAY}: {{}}\n"
                    )
                    continue

        result.append(line)

    if hostname is not None:
        result = _replace_air_hostname(result, hostname)

    # Validate before replacing the original file.  This checks the complete
    # post-filter document, including the rewritten hostname.
    filtered_doc = _load_generated_yaml("".join(result))
    removed_dependencies = _filter_air_interface_dependencies(filtered_doc, air_ports)
    null_paths = _nvue_null_paths(filtered_doc)
    if null_paths:
        raise ValueError("AIR NVUE YAML 包含 null: " + ", ".join(null_paths[:8]))
    dependency_errors = _air_dependency_errors(filtered_doc, air_ports)
    if dependency_errors:
        raise ValueError("AIR 接口依赖无效: " + ", ".join(dependency_errors[:8]))
    if result == lines and not removed_dependencies:
        return False
    with open(filepath, "w", encoding="utf-8") as f:
        if removed_dependencies:
            yaml.safe_dump(
                filtered_doc, f, allow_unicode=True, sort_keys=False, width=120
            )
        else:
            f.writelines(result)
    return True


def _filter_air_interface_dependencies(document, air_ports):
    """Remove bonds/subinterfaces whose production members do not exist in AIR."""
    if not air_ports:
        return 0
    removed = 0
    docs = document if isinstance(document, list) else [document]
    for item in docs:
        if not isinstance(item, dict):
            continue
        block = item.get("set") if isinstance(item.get("set"), dict) else item
        interfaces = block.get("interface") if isinstance(block, dict) else None
        if not isinstance(interfaces, dict):
            continue

        removed_interfaces = set()
        for ifname in list(interfaces):
            if ifname.startswith("swp") and ifname not in air_ports:
                del interfaces[ifname]
                removed_interfaces.add(ifname)
                removed += 1
        for ifname, config in list(interfaces.items()):
            if not isinstance(config, dict):
                continue
            bond = config.get("bond")
            members = bond.get("member") if isinstance(bond, dict) else None
            if not isinstance(members, dict) or not members:
                continue
            kept = {name: value for name, value in members.items() if name in air_ports}
            if not kept:
                del interfaces[ifname]
                removed_interfaces.add(ifname)
                removed += 1
            elif len(kept) != len(members):
                bond["member"] = kept
                removed += len(members) - len(kept)

        # Subinterfaces based on a removed bond/peerlink cannot be applied.
        for ifname, config in list(interfaces.items()):
            if not isinstance(config, dict):
                continue
            if config.get("base-interface") in removed_interfaces:
                del interfaces[ifname]
                removed += 1

        # Remove interface-based BGP neighbors whose production links were
        # filtered out. IP-address neighbors and peer groups are unaffected.
        def clean_neighbors(value):
            nonlocal removed
            if isinstance(value, dict):
                for key, child in list(value.items()):
                    if key == "neighbor" and isinstance(child, dict):
                        for neighbor in list(child):
                            if (re.fullmatch(
                                    r"(?:swp\d+(?:s\d+)?|bond\d+(?:s\d+)?|peerlink(?:\.4094)?)",
                                    str(neighbor),
                                ) and neighbor not in interfaces):
                                del child[neighbor]
                                removed += 1
                        if not child:
                            del value[key]
                            removed += 1
                            continue
                    clean_neighbors(child)
            elif isinstance(value, list):
                for child in value:
                    clean_neighbors(child)

        clean_neighbors(block)
    return removed


def _interface_vrf_errors(document):
    """Return interfaces that reference undefined non-system VRFs."""
    errors = []
    docs = document if isinstance(document, list) else [document]
    for item in docs:
        if not isinstance(item, dict):
            continue
        block = item.get("set") if isinstance(item.get("set"), dict) else item
        interfaces = block.get("interface") if isinstance(block, dict) else None
        if not isinstance(interfaces, dict):
            continue
        configured_vrfs = (
            block.get("vrf") if isinstance(block.get("vrf"), dict) else {}
        )
        vrfs = set(configured_vrfs) | {"default", "mgmt"}
        for ifname, config in interfaces.items():
            if not isinstance(config, dict):
                continue
            vrf_name = config.get("vrf")
            if vrf_name and vrf_name not in vrfs:
                errors.append(f"{ifname} 引用的 VRF {vrf_name} 不存在")
    return errors


def _air_dependency_errors(document, air_ports):
    """Validate AIR physical ports and interface references after filtering."""
    # AIR DOT intentionally keeps network management links (eth0/mgmt/bmc),
    # while production NVUE YAML only models the switch-side front-panel ports
    # for topology trimming. Management endpoints therefore are not synthetic
    # production ports and must not participate in the strict swp dependency
    # gate.
    air_front_panel_ports = {
        str(port) for port in air_ports if str(port).startswith("swp")
    }
    errors = _interface_vrf_errors(document)
    docs = document if isinstance(document, list) else [document]
    for item in docs:
        if not isinstance(item, dict):
            continue
        block = item.get("set") if isinstance(item.get("set"), dict) else item
        interfaces = block.get("interface") if isinstance(block, dict) else None
        if not isinstance(interfaces, dict):
            continue
        names = set(interfaces)
        bridge = block.get("bridge") if isinstance(block.get("bridge"), dict) else {}
        bridge_domains = (
            bridge.get("domain") if isinstance(bridge.get("domain"), dict) else {}
        )
        valid_base_interfaces = names | set(bridge_domains)
        for missing in sorted(air_front_panel_ports - names, key=_bond_sort_key):
            errors.append(f"AIR DOT 端口 {missing} 在生产 YAML 中不存在")
        for ifname, config in interfaces.items():
            if ifname.startswith("swp") and ifname not in air_front_panel_ports:
                errors.append(f"{ifname} 不在 AIR DOT")
            if not isinstance(config, dict):
                errors.append(f"{ifname} 配置为空")
                continue
            bond = config.get("bond")
            members = bond.get("member") if isinstance(bond, dict) else None
            if isinstance(members, dict):
                for member in members:
                    if member not in air_front_panel_ports or member not in names:
                        errors.append(f"{ifname} 成员 {member} 不可用")
            base = config.get("base-interface")
            if base and base not in valid_base_interfaces:
                errors.append(f"{ifname} base-interface {base} 不存在")

        def check_neighbors(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key == "neighbor" and isinstance(child, dict):
                        for neighbor in child:
                            if (re.fullmatch(
                                    r"(?:swp\d+(?:s\d+)?|bond\d+(?:s\d+)?|peerlink(?:\.4094)?)",
                                    str(neighbor),
                                ) and neighbor not in names):
                                errors.append(f"BGP neighbor {neighbor} 接口不存在")
                    check_neighbors(child)
            elif isinstance(value, list):
                for child in value:
                    check_neighbors(child)

        check_neighbors(block)
    return errors


def prompt_air_configs(output_dir):
    """Ask user whether to generate an AIR config folder filtered by *-air.dot."""
    answer = _timed_input("\n是否要生成 AIR 配置文件夹（根据 *-air.dot 过滤接口）？[Y/n] ", default="y").strip().lower()
    if answer not in ("y", "yes"):
        return

    air_files = _topology_dot_files("air")

    if not air_files:
        print(f"[WARN] P2P 输出目录 {P2P_OUTPUT_DIR} 下未找到 *-air.dot 文件，跳过")
        return

    if len(air_files) == 1:
        air_file = air_files[0]
        confirm = _timed_input(f"使用 dot 文件：{air_file}\n确认？[Y/n] ", default="y").strip().lower()
        if confirm in ("n", "no"):
            print("已取消。")
            return
    else:
        print("P2P 输出目录下找到以下 air dot 文件：")
        for i, f in enumerate(air_files, 1):
            print(f"  [{i}] {os.path.basename(f)}")
        choice = _timed_input(f"请选择 [1-{len(air_files)}]，或回车取消：", default="1").strip()
        if not choice:
            print("已取消。")
            return
        try:
            idx = int(choice) - 1
            if not (0 <= idx < len(air_files)):
                raise ValueError
        except ValueError:
            print("[WARN] 无效选择，跳过")
            return
        air_file = air_files[idx]

    air_info = _load_air_info(air_file)
    print(f"已加载 {len(air_info)} 台设备的信息（来自 {os.path.basename(air_file)}）")

    def _air_lookup(hostname):
        return _lookup_air_device(air_info, hostname)

    # AIR is a strict derivative of production YAML: it may rename the host,
    # rewrite management addressing and remove interfaces/dependencies that do
    # not exist in AIR, but it must never synthesize a port missing from the
    # production configuration.  Validate this before creating/replacing the
    # AIR output directory so an invalid partial directory cannot be published.
    missing_from_production = []
    source_yaml_files = sorted(
        fname for fname in os.listdir(output_dir) if fname.endswith(".yaml")
    )
    for fname in source_yaml_files:
        hostname = fname[:-5]
        dev_info = _air_lookup(hostname)
        if dev_info is None:
            continue
        with open(os.path.join(output_dir, fname), encoding="utf-8") as stream:
            document = _load_generated_yaml(stream.read())
        docs = document if isinstance(document, list) else [document]
        configured = set()
        for item in docs:
            block = item.get("set") if isinstance(item, dict) else None
            interfaces = block.get("interface") if isinstance(block, dict) else None
            if isinstance(interfaces, dict):
                configured.update(name for name in interfaces if str(name).startswith("swp"))
        required_front_panel_ports = {
            str(port) for port in dev_info["ports"]
            if str(port).startswith("swp")
        }
        missing = sorted(
            required_front_panel_ports - configured, key=_bond_sort_key
        )
        if missing:
            missing_from_production.append((hostname, missing))
    if missing_from_production:
        details = "; ".join(
            f"{hostname}: {','.join(ports)}" for hostname, ports in missing_from_production
        )
        raise ValueError(
            "AIR 标准裁剪失败：AIR DOT 端口必须先存在于生产 YAML；" + details
        )

    dest_dir = output_dir + "_air"
    if os.path.exists(dest_dir):
        shutil.rmtree(dest_dir)
    shutil.copytree(output_dir, dest_dir)
    print(f"已拷贝配置文件夹：{dest_dir}")

    modified = 0
    unchanged = 0
    renamed = 0
    not_in_dot = []

    yaml_files = source_yaml_files
    rename_targets = {}
    for fname in yaml_files:
        hostname = fname[:-5]
        dev_info = _air_lookup(hostname)
        if dev_info is None:
            continue
        target_hostname = dev_info["hostname"]
        target = f"{target_hostname}.yaml"
        target_key = target.casefold()
        if target_key in rename_targets and rename_targets[target_key] != fname:
            raise ValueError(
                f"AIR 配置文件名冲突：{rename_targets[target_key]} 和 {fname} -> {target}"
            )
        rename_targets[target_key] = fname

    for fname in yaml_files:
        hostname = fname[:-5]
        fpath = os.path.join(dest_dir, fname)
        dev_info = _air_lookup(hostname)
        if dev_info is None:
            not_in_dot.append(hostname)
            os.remove(fpath)
            continue
        # Use the complete node name from *-air.dot (for example
        # AIR-SITE01-OOB-Leaf01), rather than merely adding AIR- locally.
        air_hostname = dev_info["hostname"]
        air_ports = dev_info["ports"]
        mgmt_ip = dev_info["mgmt_ip"]

        if _filter_air_yaml(fpath, air_ports, mgmt_ip=mgmt_ip,
                            hostname=air_hostname):
            modified += 1
        else:
            unchanged += 1

        target_path = os.path.join(dest_dir, f"{air_hostname}.yaml")
        if os.path.normcase(fpath) != os.path.normcase(target_path):
            if os.path.exists(target_path):
                raise ValueError(f"AIR 配置文件已存在，无法重命名：{target_path}")
            os.rename(fpath, target_path)
            renamed += 1

    print(f"\nAIR 配置完成：{modified} 台修改，{unchanged} 台无变化，"
          f"{renamed} 个文件改用 AIR DOT 节点名")
    if not_in_dot:
        print(f"[INFO] 以下 {len(not_in_dot)} 台设备不在 air dot 中，"
              "已从 AIR 输出中删除：")
        for h in sorted(not_in_dot):
            print(f"  {h}")
    print(f"输出目录：{dest_dir}")


def generate_air_hostname_configs(source_dir, output_dir):
    """Create the complete AIR YAML set from the authoritative AIR JSON.

    A node matching a Production hostname receives the Production full config
    with only ``set.system.hostname`` changed (``replace`` mode).  An AIR-only
    Cumulus node receives the effective version/global default plus hostname
    (``patch`` mode).  The latter deliberately contains no synthesized static
    management address.
    """
    inventory_path = os.path.join(SCRIPT_DIR, "02-devices_config.csv")
    inventory_hosts = set()
    if os.path.isfile(inventory_path):
        with open(inventory_path, newline="", encoding="utf-8-sig") as stream:
            reader = csv.DictReader(stream)
            for row in reader:
                hostname = str(row.get("hostname") or "").strip()
                dev_type = str(row.get("type") or "").strip().casefold()
                if hostname and dev_type == "air":
                    inventory_hosts.add(hostname.casefold())

    air_json_files = _topology_air_json_files()
    if not air_json_files:
        if inventory_hosts:
            raise ValueError(
                f"AIR inventory 有 {len(inventory_hosts)} 台设备，但未找到 *-air.json；"
                "请先运行 P2P b-xlsx_to_dot.py"
            )
        print("[INFO] 当前项目没有 AIR inventory/*-air.json，不生成 AIR YAML")
        return None
    air_json = max(air_json_files, key=os.path.getmtime)
    try:
        document = json.loads(Path(air_json).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"无法读取 AIR JSON {air_json}: {exc}") from exc
    container = document.get("content", document) if isinstance(document, dict) else None
    nodes = container.get("nodes") if isinstance(container, dict) else None
    if not isinstance(nodes, dict):
        raise ValueError(f"AIR JSON 缺少 object 类型 content.nodes: {air_json}")

    air_info = {}
    mac_owners = {}
    for hostname, node in nodes.items():
        if not isinstance(node, dict):
            continue
        os_name = str(node.get("os") or "").strip().casefold()
        if not (os_name.startswith("cumulus") or os_name == "oob-mgmt-switch"):
            continue
        hostname = str(hostname).strip()
        if not _SAFE_HOSTNAME_RE.fullmatch(hostname):
            raise ValueError(
                f"AIR JSON hostname 含不安全字符，不能作为 YAML 文件名: {hostname!r}"
            )
        interfaces = node.get("management_interfaces")
        eth0 = interfaces.get("eth0", {}) if isinstance(interfaces, dict) else {}
        raw_mac = str(
            eth0.get("mac_address") or eth0.get("mac") or ""
        ).strip().lower()
        if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", raw_mac):
            raise ValueError(f"AIR 节点 {hostname} 缺少有效 eth0 MAC: {raw_mac!r}")
        mac_plain = raw_mac.replace(":", "")
        owner = mac_owners.get(mac_plain)
        if owner is not None:
            raise ValueError(f"AIR JSON MAC 冲突: {raw_mac} 同时属于 {owner} / {hostname}")
        mac_owners[mac_plain] = hostname
        key = hostname.casefold()
        if key in air_info:
            raise ValueError(f"AIR JSON hostname 冲突: {hostname}")
        air_info[key] = {
            "hostname": hostname,
            "mac": raw_mac,
            "ports": set(),
            "mgmt_ip": None,
        }

    json_hosts = set(air_info)
    missing_inventory = sorted(inventory_hosts - json_hosts)
    if missing_inventory:
        raise ValueError(
            "02-devices_config.csv 中的 AIR 设备不在 AIR JSON: "
            + ", ".join(missing_inventory)
        )

    eth_global = load_global("eth")
    target_version = str(eth_global.get("version") or "").strip()
    service_dir = os.path.dirname(SCRIPT_DIR)
    version_default = os.path.join(service_dir, f"default_{target_version}.yaml")
    default_file = version_default if target_version and os.path.isfile(version_default) else os.path.join(service_dir, "default.yaml")
    if not os.path.isfile(default_file):
        raise ValueError(f"找不到 AIR baseline 默认配置: {default_file}")
    default_text = Path(default_file).read_text(encoding="utf-8")
    default_document = _load_generated_yaml(default_text)
    if not isinstance(default_document, list):
        raise ValueError(f"AIR baseline 默认配置顶层必须是 list: {default_file}")
    for item in default_document:
        block = item.get("set") if isinstance(item, dict) else None
        system = block.get("system") if isinstance(block, dict) else None
        if isinstance(system, dict) and "hostname" in system:
            raise ValueError(
                f"AIR baseline 默认配置不得预设 hostname: {default_file}"
            )
        interfaces = block.get("interface") if isinstance(block, dict) else None
        if isinstance(interfaces, dict):
            for interface_name in ("eth0", "mgmt"):
                interface = interfaces.get(interface_name)
                ip_block = interface.get("ip") if isinstance(interface, dict) else None
                if isinstance(ip_block, dict) and ip_block.get("address"):
                    raise ValueError(
                        f"AIR baseline 默认配置不得预设 {interface_name} 静态地址: "
                        f"{default_file}"
                    )
    default_sha256 = hashlib.sha256(default_text.encode("utf-8")).hexdigest()

    def baseline_document(hostname):
        result = copy.deepcopy(default_document)
        systems = []
        for item in result:
            block = item.get("set") if isinstance(item, dict) else None
            system = block.get("system") if isinstance(block, dict) else None
            if isinstance(system, dict):
                systems.append(system)
        if len(systems) != 1:
            raise ValueError(
                f"{default_file}: 期望一个 set.system，实际 {len(systems)}"
            )
        systems[0]["hostname"] = hostname
        return result

    temporary = f"{output_dir}.tmp.{os.getpid()}"
    if os.path.lexists(temporary):
        shutil.rmtree(temporary)
    os.makedirs(temporary)
    generated = 0
    targets = set()
    manifest_devices = []
    try:
        for source in sorted(glob.glob(os.path.join(source_dir, "*.yaml"))):
            if os.path.islink(source):
                continue
            production_hostname = os.path.splitext(os.path.basename(source))[0]
            device = _lookup_air_device(air_info, production_hostname)
            if device is None:
                continue
            air_hostname = device["hostname"]
            target_name = f"{air_hostname}.yaml"
            target_key = air_hostname.casefold()
            if target_key in targets:
                raise ValueError(f"AIR 配置文件名冲突：{target_name}")
            targets.add(target_key)
            text = Path(source).read_text(encoding="utf-8")
            rewritten = "".join(_replace_air_hostname(text.splitlines(True), air_hostname))
            if rewritten == text:
                raise ValueError(
                    f"{production_hostname}.yaml 未找到 system.hostname，无法生成 {target_name}"
                )
            Path(temporary, target_name).write_text(rewritten, encoding="utf-8")
            shutil.copymode(source, Path(temporary, target_name))
            manifest_devices.append({
                "hostname": air_hostname,
                "mac": air_info[target_key]["mac"],
                "profile": "full",
                "apply_mode": "replace",
                "source_hostname": production_hostname,
            })
            generated += 1

        for target_key in sorted(json_hosts - targets):
            device = air_info[target_key]
            target_name = f"{device['hostname']}.yaml"
            baseline = baseline_document(device["hostname"])
            target_path = Path(temporary, target_name)
            target_path.write_text(
                yaml.safe_dump(
                    baseline, allow_unicode=True, sort_keys=False,
                    default_flow_style=False, width=120,
                ),
                encoding="utf-8",
            )
            shutil.copymode(default_file, target_path)
            manifest_devices.append({
                "hostname": device["hostname"],
                "mac": device["mac"],
                "profile": "baseline",
                "apply_mode": "patch",
                "source_default": os.path.basename(default_file),
                "source_default_sha256": default_sha256,
            })
            targets.add(target_key)
            generated += 1

        missing = sorted(json_hosts - targets)
        unexpected = sorted(targets - json_hosts)
        if missing or unexpected:
            raise ValueError(
                "AIR JSON/生成 YAML hostname 集合不一致："
                f"缺少={missing or '无'}，多余={unexpected or '无'}"
            )
        validation_errors = _validate_yaml_directory(temporary)
        if validation_errors:
            raise ValueError("AIR YAML 严格校验失败: " + "; ".join(validation_errors))
        manifest = {
            "schema_version": 1,
            "environment": "air",
            "source_json": os.path.basename(air_json),
            "target_cumulus_version": target_version,
            "effective_default": os.path.basename(default_file),
            "effective_default_sha256": default_sha256,
            "devices": sorted(manifest_devices, key=lambda item: item["hostname"].casefold()),
        }
        Path(temporary, "air-config-manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        backup = None
        if os.path.exists(output_dir):
            backup = f"{output_dir}.old.{os.getpid()}"
            if os.path.lexists(backup):
                shutil.rmtree(backup)
            os.replace(output_dir, backup)
        try:
            os.replace(temporary, output_dir)
        except Exception:
            if backup and os.path.exists(backup) and not os.path.exists(output_dir):
                os.replace(backup, output_dir)
            raise
        if backup:
            shutil.rmtree(backup)
    finally:
        if os.path.lexists(temporary):
            shutil.rmtree(temporary)
    print(
        f"[OK] AIR 配置：{generated} 份（full="
        f"{sum(item['profile'] == 'full' for item in manifest_devices)}，baseline="
        f"{sum(item['profile'] == 'baseline' for item in manifest_devices)}），"
        f"inventory={os.path.basename(air_json)} → {output_dir}"
    )
    return output_dir


# ══════════════════════════════════════════════════════════════════════════════
# IB-only: csv parsing, yaml generation
# ══════════════════════════════════════════════════════════════════════════════

# IB CSV column indices
_IB_COL_HOSTNAME = 0
_IB_COL_ETH0_IP  = 3
_IB_COL_ETH0_PFX = 4
_IB_COL_ETH0_GW  = 5
_IB_COL_ETH0_MAC = 6
_IB_COL_ETH1_IP  = 7
_IB_COL_ETH1_PFX = 8
_IB_COL_ETH1_GW  = 9
_IB_COL_ETH1_MAC = 10
_IB_NCOLS        = 11


def _na_ib(val):
    return not val or val.strip().upper() == "NA"

def _valid_ip_ib(val):
    try:
        ipaddress.ip_interface(val)
        return True
    except ValueError:
        return False

def _valid_mac_ib(val):
    return bool(re.fullmatch(r'[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}', val))


def _row_type_ib(row, type_col):
    """按 type 列判断设备类型；无 type 列时按主机名兜底。"""
    if type_col is not None and len(row) > type_col:
        return row[type_col].strip().lower()
    return "ib" if row[_IB_COL_HOSTNAME].strip().lower().startswith("ib") else "eth"


def _load_csv_ib():
    """读取 CSV，返回 ib/nvl 设备列表和错误列表。"""
    devices = []
    errors  = []
    skipped_excluded = 0

    try:
        f = open(_CSV_FILE, newline="", encoding="utf-8")
    except FileNotFoundError:
        print(f"[ERROR] 找不到配置文件：{_CSV_FILE}")
        sys.exit(1)

    with f:
        reader = csv.reader(f)
        header   = next(reader, [])
        h_lower  = [c.strip().lower() for c in header]
        if tuple(h_lower[:len(_EXPECTED_DEVICE_HEADER_PREFIX)]) != _EXPECTED_DEVICE_HEADER_PREFIX:
            errors.append(
                "  02-devices_config.csv 前 11 列顺序必须为："
                + ",".join(_EXPECTED_DEVICE_HEADER_PREFIX)
            )
            return devices, errors
        type_col = h_lower.index("type") if "type" in h_lower else None

        for lineno, raw in enumerate(reader, start=2):
            row = [c.strip() for c in raw]
            if not any(row):
                continue
            dev_type = _row_type_ib(row, type_col)
            if _exclude_config_type(dev_type):
                skipped_excluded += 1
                continue
            if dev_type not in ("ib", "nvl"):
                continue
            if len(row) < _IB_NCOLS:
                errors.append(f"  第 {lineno} 行列数不足（{len(row)} < {_IB_NCOLS}）：{raw}")
                continue
            eth1_valid = (not _na_ib(row[_IB_COL_ETH1_IP])
                          and not _na_ib(row[_IB_COL_ETH1_PFX])
                          and not _na_ib(row[_IB_COL_ETH1_GW]))
            devices.append({
                "type":       dev_type,
                "hostname":   row[_IB_COL_HOSTNAME],
                "eth0_ip":    row[_IB_COL_ETH0_IP],
                "eth0_pfx":   row[_IB_COL_ETH0_PFX],
                "eth0_gw":    row[_IB_COL_ETH0_GW],
                "eth0_mac":   row[_IB_COL_ETH0_MAC].lower(),
                "eth1_ip":    row[_IB_COL_ETH1_IP]  if eth1_valid else "",
                "eth1_pfx":   row[_IB_COL_ETH1_PFX] if eth1_valid else "",
                "eth1_gw":    row[_IB_COL_ETH1_GW]  if eth1_valid else "",
                "eth1_mac":   row[_IB_COL_ETH1_MAC].lower() if not _na_ib(row[_IB_COL_ETH1_MAC]) else "",
                "has_eth1":   eth1_valid,
            })

    if skipped_excluded:
        print(f"[INFO] 已忽略 {skipped_excluded} 行 type=air 设备，不生成配置")
    return devices, errors


def _check_duplicates_ib(devices):
    """检查关键字段的重复值（跳过空值和 NA），返回错误列表。"""
    fields = ("hostname", "eth0_ip", "eth0_mac", "eth1_ip", "eth1_mac")
    seen   = {f: {} for f in fields}
    errors = []

    for dev in devices:
        for field in fields:
            val = dev[field]
            if _na_ib(val):
                continue
            identity = val.casefold() if field in {"hostname", "eth0_mac", "eth1_mac"} else val
            seen[field].setdefault(identity, []).append(dev["hostname"])

    for field, val_map in seen.items():
        for val, hosts in val_map.items():
            if len(hosts) > 1:
                errors.append(f"  重复 {field}={val!r}：{', '.join(hosts)}")

    return errors


def _validate_fields_ib(devices):
    """逐字段格式校验，返回错误列表。"""
    errors = []

    def chk(ok, hostname, field, val):
        if not ok:
            errors.append(f"  {hostname}: {field}={val!r} 格式无效")

    for dev in devices:
        hn = dev["hostname"]
        if not hn:
            errors.append(f"  hostname 为空")
            continue
        if not _SAFE_HOSTNAME_RE.fullmatch(hn):
            errors.append(
                f"  hostname 含不安全字符，不能作为 YAML 文件名: {hn!r}"
            )
            continue
        chk(_valid_ip_ib(f"{dev['eth0_ip']}/{dev['eth0_pfx']}"), hn, "eth0_ip/prefix",
            f"{dev['eth0_ip']}/{dev['eth0_pfx']}")
        chk(_valid_ip_ib(dev["eth0_gw"]),  hn, "eth0_gw",  dev["eth0_gw"])
        chk(_valid_mac_ib(dev["eth0_mac"]) if dev["eth0_mac"] else True,
            hn, "eth0_mac", dev["eth0_mac"])
        if dev["has_eth1"]:
            chk(_valid_ip_ib(f"{dev['eth1_ip']}/{dev['eth1_pfx']}"), hn, "eth1_ip/prefix",
                f"{dev['eth1_ip']}/{dev['eth1_pfx']}")
            chk(_valid_ip_ib(dev["eth1_gw"]),  hn, "eth1_gw",  dev["eth1_gw"])
        if dev["eth1_mac"]:
            chk(_valid_mac_ib(dev["eth1_mac"]), hn, "eth1_mac", dev["eth1_mac"])

    return errors


def _build_system_ib(hostname, global_cfg):
    sys_block = copy.deepcopy(global_cfg.get("system", {}))
    for key in ("ntp", "dns"):
        block = sys_block.get(key, {})
        if isinstance(block.get("server"), list):
            block["server"] = {s: {} for s in block["server"]}
    sys_block["hostname"] = hostname
    return sys_block


def _build_yaml_ib(dev, global_cfg):
    """根据设备参数和全局配置构建 YAML 数据结构。"""
    eth0_cidr = f"{dev['eth0_ip']}/{dev['eth0_pfx']}"

    ifaces = {
        "eth0": {
            "ipv4": {
                "address": {eth0_cidr: {}},
                "gateway": {dev["eth0_gw"]: {}},
            },
            "type": "eth",
        },
    }
    if dev["has_eth1"]:
        eth1_cidr = f"{dev['eth1_ip']}/{dev['eth1_pfx']}"
        ifaces["eth1"] = {
            "ipv4": {
                "address": {eth1_cidr: {}},
                "gateway": {dev["eth1_gw"]: {}},
            },
            "type": "eth",
        }
    ifaces["lo"] = {
        "acl": {
            "acl-default-loopback": {
                "inbound": {"control-plane": {}}
            },
            "acl-default-loopback-ipv6": {
                "inbound": {"control-plane": {}}
            },
        },
        "type": "loopback",
    }

    doc = {
        "set": {
            "interface": ifaces,
            "system":    _build_system_ib(dev["hostname"], global_cfg),
        }
    }
    return [doc]


def _write_yaml_ib(data, path):
    tmp = path + ".tmp"
    rendered = yaml.dump(
        data,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        width=120,
    )
    _load_generated_yaml(rendered)
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(rendered)
    os.replace(tmp, path)


def _generate_group_ib(devices, global_cfg, out_dir, target=None):
    """为一组同类型设备生成 YAML，写入 out_dir/<timestamp>/。

    返回 (generated, errors) 计数。out_dir 的最后一级即时间戳目录。
    """
    if target:
        devices = [d for d in devices if d["hostname"].lower() == target.lower()]
    if not devices:
        return 0, 0

    staging_dir = out_dir + ".tmp"
    if os.path.exists(staging_dir):
        shutil.rmtree(staging_dir)
    # 99-output-ib_nvl 可能是 setup 创建的软链接目录。
    os.makedirs(os.path.dirname(out_dir), exist_ok=True)
    os.makedirs(staging_dir, exist_ok=True)

    generated = errors = 0
    for dev in devices:
        hostname = dev["hostname"]
        out_path = os.path.join(staging_dir, f"{hostname}.yaml")
        try:
            data = _build_yaml_ib(dev, global_cfg)
            yaml.dump(data)
            _write_yaml_ib(data, out_path)
            eth1_info = f"  eth1={dev['eth1_ip']}/{dev['eth1_pfx']}" if dev["has_eth1"] else ""
            print(f"[OK] {hostname}.yaml  (eth0={dev['eth0_ip']}/{dev['eth0_pfx']}{eth1_info})")
            generated += 1
        except Exception as e:
            print(f"[ERROR] {hostname}：{e}")
            errors += 1

    if errors == 0:
        directory_errors = _validate_yaml_directory(staging_dir)
        if directory_errors:
            errors += len(directory_errors)
            for detail in directory_errors:
                print(f"[ERROR] 生成的 YAML 校验失败：{detail}")
    if errors == 0:
        if os.path.exists(out_dir):
            shutil.rmtree(out_dir)
        os.rename(staging_dir, out_dir)
        print(f"输出目录：{out_dir}")
    else:
        shutil.rmtree(staging_dir, ignore_errors=True)
        dir_label = os.path.basename(os.path.dirname(out_dir))
        print(f"[ABORT] {dir_label} 存在 {errors} 个错误，未写入输出目录")

    return generated, errors


def _generate_all_ib(target=None):
    devices, parse_errors = _load_csv_ib()

    if parse_errors:
        print("[ERROR] CSV 格式错误，请修正后重新运行：")
        for e in parse_errors:
            print(e)
        sys.exit(1)

    ib_devices  = [d for d in devices if d["type"] == "ib"]
    nvl_devices = [d for d in devices if d["type"] == "nvl"]

    # 按类型独立校验，互不干扰
    ib_errors  = _validate_fields_ib(ib_devices)  + _check_duplicates_ib(ib_devices)
    nvl_errors = _validate_fields_ib(nvl_devices) + _check_duplicates_ib(nvl_devices)

    if ib_errors:
        print("[ERROR] IB 设备 CSV 存在问题，请修正后重新运行：")
        for e in ib_errors:
            print(e)
    if nvl_errors:
        print("[ERROR] NVL 设备 CSV 存在问题，请修正后重新运行：")
        for e in nvl_errors:
            print(e)
    if target:
        all_devices = ib_devices + nvl_devices
        matched = [d for d in all_devices if d["hostname"].lower() == target.lower()]
        if not matched:
            print(f"[ERROR] 设备 '{target}' 不在 CSV 中")
            sys.exit(1)
        ib_devices  = [d for d in matched if d["type"] == "ib"]
        nvl_devices = [d for d in matched if d["type"] == "nvl"]

    total_gen = total_err = 0

    if ib_devices and not ib_errors:
        global_ib = load_global("ib")
        print(f"\n── 生成 IB 配置（{len(ib_devices)} 台）" + "─" * 40)
        gen, err = _generate_group_ib(ib_devices, global_ib, OUTPUT_IB_DIR, target)
        total_gen += gen
        total_err += err

    if nvl_devices and not nvl_errors:
        global_nvl = load_global("nvl")
        print(f"\n── 生成 NVL 配置（{len(nvl_devices)} 台）" + "─" * 39)
        gen, err = _generate_group_ib(nvl_devices, global_nvl, OUTPUT_NVL_DIR, target)
        total_gen += gen
        total_err += err

    print(f"\n完成：共生成 {total_gen} 台")
    if total_err:
        print(f"[WARN] 共 {total_err} 台生成失败")
    if ib_errors or nvl_errors:
        print("[WARN] 部分设备因 CSV 校验失败而未生成")
    if total_err or ib_errors or nvl_errors:
        sys.exit(1)
    return total_gen


def _print_info_block_ib():
    ts = _TS
    W  = 72

    def _dlen(s):
        return sum(2 if ord(c) > 0x7F else 1 for c in s)

    def row(text=""):
        return f"║  {text}{' ' * max(0, W - 2 - _dlen(text))}║"

    generated_kinds = [
        kind for kind, path in (("ib", OUTPUT_IB_DIR), ("nvl", OUTPUT_NVL_DIR))
        if os.path.isdir(path)
    ]
    continued = len(generated_kinds) > 0
    publish_steps = [row("   python3 d-hostname2mac.py -y" + (" \\" if continued else ""))]
    for index, kind in enumerate(generated_kinds):
        suffix = " \\" if index < len(generated_kinds) - 1 else ""
        publish_steps.append(row(f"     template/99-output-ib_nvl/{ts}-{kind}{suffix}"))
    if len(generated_kinds) == 2:
        publish_steps.append(row(f"   两类完成后自动合并为 {ts}-combine/"))
    elif generated_kinds:
        publish_steps.append(row(f"   完成后直接发布 {ts}-{generated_kinds[0]}/"))

    lines = [
        "╔" + "═" * W + "╗",
        row("后续操作步骤"),
        "╠" + "═" * W + "╣",
        row("1. 执行共用 d-hostname2mac.py 生成 MAC 链接并完成发布"),
        row("   （在 nvos/ 目录下执行；两个目录放在同一条命令中）："),
        *publish_steps,
        row("   并原子更新 99-output-ib_nvl/latest；未完成时保留上一版本"),
        row(),
        row("2. 准备 ZTP 服务器的 DHCP 配置，"),
        row("   完成后重启 isc-dhcp-server 服务："),
        row("   sudo systemctl restart isc-dhcp-server"),
        row(),
        row("3. 开始 ZTP 流程，Provision IB/NVL 交换机"),
        "╚" + "═" * W + "╝",
    ]
    print("\n" + "\n".join(lines) + "\n")


# ══════════════════════════════════════════════════════════════════════════════
# main
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if _BRANCH == "eth":
        # ── ETH argument parsing and main flow ──
        _args = list(_SCRIPT_ARGS)
        if "-h" in _args or "--help" in _args:
            print("""usage: 90-c2-generate_configs.py [--branch eth] [-y] [--csv=PATH] [--verify]
                              [--ref-dir=DIR] [--fail-on-diff] [HOSTNAME]

从 CSV 生成 NVUE YAML（ETH 分支）。带 source_yaml_b64/source_yaml_sha256/source_fields_sha256
元数据的 yaml_to_csv.py 输出会进行完整性校验并采用无损回环；普通 CSV 继续使用 Jinja 模板。""")
            sys.exit(0)
        if not _HAS_JINJA2:
            print("[ERROR] ETH 分支依赖 Jinja2，请先执行 pip install jinja2")
            sys.exit(1)
        if "-y" in _args:
            _AUTO_YES = True
            _args = [a for a in _args if a != "-y"]
        _csv_override = next((a.split("=", 1)[1] for a in _args if a.startswith("--csv=")), None)
        if _csv_override:
            _CSV_FILE = os.path.abspath(_csv_override)
            _args = [a for a in _args if not a.startswith("--csv=")]
            print(f"[INFO] 使用指定 CSV: {_CSV_FILE}")
        _generate_devices_yaml()
        args = _args
        verify       = "--verify" in args
        fail_on_diff = "--fail-on-diff" in args
        ref_dir = next((a.split("=", 1)[1] for a in args if a.startswith("--ref-dir=")), None)
        args = [a for a in args if not a.startswith("--")]
        target = args[0] if args else None
        generate_all(target=target, verify=verify, ref_dir=ref_dir, fail_on_diff=fail_on_diff)
        if not verify:
            prompt_patch_descriptions(OUTPUT_DIR)

            ts            = os.path.basename(OUTPUT_DIR)
            with_desc_dir = OUTPUT_DIR + "_with_desc"
            has_patch     = os.path.isdir(with_desc_dir)
            try:
                _validate_final_yaml_outputs(
                    OUTPUT_DIR, with_desc_dir if has_patch else None,
                )
                air_source_dir = with_desc_dir if has_patch else OUTPUT_DIR
                generate_air_hostname_configs(air_source_dir, OUTPUT_DIR + "_air")
            except ValueError as exc:
                print(f"[ABORT] {exc}")
                sys.exit(1)

            W = 72
            def _display_len(s):
                n = 0
                for c in s:
                    n += 2 if ord(c) > 0x7F else 1
                return n
            def row(text=""):
                pad = W - 2 - _display_len(text)
                return f"║  {text}{' ' * max(0, pad)}║"

            lines = [
                "╔" + "═" * W + "╗",
                row("后续操作步骤"),
                "╠" + "═" * W + "╣",
            ]
            lines.extend([
                row(f"1. 执行 d-hostname2mac.py 生成 MAC 软链接并发布"),
                row(f"   （在 cumulus/ 目录下执行）："),
                row(f"   python3 d-hostname2mac.py template/99-output/{ts}"),
                row(f"   自动优先使用 patch：{'是' if has_patch else '否'}"),
                row(f"   Production/AIR 各自链接到独立 YAML；两份配置仅 hostname 不同"),
            ])
            lines.extend([
                row(f"   发布目录：{ts}_combine/；AIR 输入为 {ts}_air/"),
                row(f"   源目录归档为 {ts}_combine_sources.tar.gz 后删除"),
            ])
            lines.extend([
                row(),
                row(f"2. 准备 ZTP 服务器的 DHCP 配置（DSCP），"),
                row(f"   完成后重启 isc-dhcp-server 服务："),
                row(f"   sudo systemctl restart isc-dhcp-server"),
                row(),
                row(f"3. 开始 ZTP 流程，Provision 以太交换机"),
                "╚" + "═" * W + "╝",
            ])
            print("\n" + "\n".join(lines) + "\n")

    else:
        # ── IB argument parsing and main flow ──
        args = list(_SCRIPT_ARGS)
        if "-h" in args or "--help" in args:
            print("""usage: 90-c2-generate_configs.py [--branch ib] [-y] [HOSTNAME]

从 CSV 生成 NVOS YAML（IB 分支）。处理 type==ib 和 type==nvl 的行。""")
            sys.exit(0)
        if "-y" in args:
            _AUTO_YES = True
            args = [a for a in args if a != "-y"]

        target = args[0] if args else None
        n = _generate_all_ib(target=target)
        if n > 0:
            _print_info_block_ib()
