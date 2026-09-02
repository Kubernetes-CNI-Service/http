#!/usr/bin/env python3
"""
将 yaml 配置目录中的主机名文件创建 MAC 地址软链接，并更新两级发布指针。
支持 eth/eth_spx/spx/air/ib/nvl；NVOS 输出统一位于 99-output-ib_nvl，目录名带网络类型。

用法（在 cumulus/ 或 nvos/ 目录下执行，两处均可，nvos/d-hostname2mac.py 是软链接）：
  python3 d-hostname2mac.py [-y] <yaml目录>
  python3 d-hostname2mac.py [-y] <时间戳-ib目录> <同时间戳-nvl目录>

输出：
  <yaml目录>/<mac>.yaml  → <hostname>.yaml  软链接
  template/99-output/latest          → Cumulus 当前发布目录
  cumulus/latest_yaml                → template/99-output/latest（固定）
  template/99-output-ib_nvl/latest   → NVOS 当前发布目录
  nvos/latest_yaml                   → template/99-output-ib_nvl/latest（固定）

Cumulus 规则：同时间戳存在 _with_desc 时优先使用；Production 与 AIR 分别使用
独立 YAML，AIR 文件仅允许 system.hostname 与配对的 Production 文件不同。最终发布为
*_combine，生成源目录归档为 *_combine_sources.tar.gz 后删除。

CSV 格式（含表头，11 列）：
  hostname, type, template, eth0_ip, netmask, eth0_gw, eth0_mac,
  eth1_ip,  netmask, eth1_gw, eth1_mac
"""

import csv
import copy
import glob
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import shutil
import stat
import sys
import tarfile
import tempfile

try:
    import yaml
except ImportError:
    print("[ERROR] 缺少依赖：请先执行 pip install pyyaml")
    sys.exit(1)


class _StrictSafeLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of overwriting them."""


def _construct_strict_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark,
                "found an unhashable key", key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark,
                f"found duplicate key {key!r}", key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_strict_mapping
)


def _strict_yaml_load(stream):
    return yaml.load(stream, Loader=_StrictSafeLoader)

# CSV 列索引
_COL_HOSTNAME = 0
# col 1 = type, col 2 = template（均跳过）
_COL_ETH0_IP  = 3
_COL_ETH0_PFX = 4
_COL_ETH0_GW  = 5
_COL_ETH0_MAC = 6
_COL_ETH1_IP  = 7
_COL_ETH1_PFX = 8
_COL_ETH1_GW  = 9
_COL_ETH1_MAC = 10
_NCOLS        = 11
_EXPECTED_HEADER_PREFIX = (
    "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw",
    "eth0_mac", "eth1_ip", "netmask", "eth1_gw", "eth1_mac",
)

_AUTO_YES  = False
_CONFIRM_TIMEOUT = 15
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))  # 保留通过软链接调用时的逻辑位置
_HTTP_ROOT = Path(_SCRIPT_DIR).resolve().parents[2]
_DAY0_ROOT = _HTTP_ROOT / "DAY0-Prepare"
_OPTIMIZE_DIR = _HTTP_ROOT / "ztp" / "optimize"
_SAFE_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")


# ── 交互 ──────────────────────────────────────────────────────────────────────

def _confirm(path):
    print(f"找到 CSV 文件：{path}")
    if _AUTO_YES:
        print("是否使用？[Y/n] y（-y 模式自动确认）")
        return True
    print(f"是否使用？[Y/n]（{_CONFIRM_TIMEOUT} 秒后自动确认）", end=" ", flush=True)
    ready, _, _ = select.select([sys.stdin], [], [], _CONFIRM_TIMEOUT)
    if ready:
        ans = sys.stdin.readline().strip().lower()
        return ans not in ("n", "no")
    print("y")
    return True


def find_csv(explicit=None, yaml_dir=None):
    """
    查找设备 CSV 文件。
    1. 若 explicit 不为 None，直接返回（来自 --csv 参数）。
    2. 否则从脚本目录的 template/ 子目录搜索 *devices_config*.csv。
    """
    if explicit is not None:
        return explicit

    # 优先从 yaml 输出目录对应的 template/ 查找，兼容共享脚本处理 NVOS 输出。
    search_dirs = []
    if yaml_dir:
        output_root = os.path.dirname(os.path.abspath(yaml_dir))
        if os.path.basename(output_root).startswith("99-output"):
            search_dirs.append(os.path.dirname(output_root))
    search_dirs.append(os.path.join(_SCRIPT_DIR, "template"))

    candidates = []
    for search_dir in search_dirs:
        preferred = os.path.join(search_dir, "02-devices_config.csv")
        matches = ([preferred] if os.path.isfile(preferred) else
                   sorted(glob.glob(os.path.join(search_dir, "*devices_config*.csv"))))
        for candidate in matches:
            if candidate not in candidates:
                candidates.append(candidate)
    for candidate in candidates:
        if _confirm(candidate):
            return candidate

    path = input("请输入 CSV 文件路径：").strip()
    if not path:
        print("[ERROR] 未指定 CSV 文件，退出")
        sys.exit(1)
    return path


# ── CSV 解析 ──────────────────────────────────────────────────────────────────

def _na(val):
    return not val or val.strip().upper() == "NA"

def _row_type(row, type_col):
    """按 type 列判断设备类型；无 type 列时按主机名兜底。"""
    if type_col is not None and len(row) > type_col:
        return row[type_col].strip().lower()
    return "ib" if row[_COL_HOSTNAME].strip().lower().startswith("ib") else "eth"

def load_csv(csv_file):
    """返回 {hostname.lower(): {...}}，eth 和 ib 设备均加载。"""
    devices = {}
    with open(csv_file, newline="", encoding="utf-8") as f:
        reader  = csv.reader(f)
        header  = next(reader, [])
        h_lower = [c.strip().lower() for c in header]
        if tuple(h_lower[:_NCOLS]) != _EXPECTED_HEADER_PREFIX:
            raise ValueError(
                "devices_config.csv 前 11 列顺序必须为："
                + ",".join(_EXPECTED_HEADER_PREFIX)
            )
        type_col = h_lower.index("type") if "type" in h_lower else None

        for lineno, raw in enumerate(reader, start=2):
            row = [c.strip() for c in raw]
            if not any(row):
                continue
            if len(row) < _NCOLS:
                raise ValueError(
                    f"第 {lineno} 行列数不足（{len(row)} < {_NCOLS}）"
                )
            dev_type = _row_type(row, type_col)
            if dev_type == "server":
                continue
            if dev_type not in {"eth", "eth_spx", "spx", "air", "ib", "nvl"}:
                raise ValueError(f"第 {lineno} 行 type={dev_type!r} 无效")
            hostname = row[_COL_HOSTNAME]
            eth0_ip  = row[_COL_ETH0_IP]
            eth0_pfx = row[_COL_ETH0_PFX]
            if not hostname or _na(eth0_ip) or _na(eth0_pfx):
                raise ValueError(
                    f"第 {lineno} 行缺少必填字段（hostname/eth0_ip/netmask）"
                )
            if not _SAFE_HOSTNAME_RE.fullmatch(hostname):
                raise ValueError(
                    f"第 {lineno} 行 hostname 含不安全字符：{hostname!r}"
                )
            hostname_key = hostname.casefold()
            if hostname_key in devices:
                raise ValueError(f"第 {lineno} 行 hostname 重复：{hostname!r}")
            eth0_mac = "" if _na(row[_COL_ETH0_MAC]) else row[_COL_ETH0_MAC].lower()
            identity_pending = not eth0_mac
            if identity_pending and dev_type not in {"eth", "eth_spx", "spx", "ib", "nvl"}:
                print(f"[WARN] 第 {lineno} 行 {dev_type} 设备 eth0_mac 为空，跳过")
                continue
            if identity_pending:
                print(
                    f"[PENDING] 第 {lineno} 行 {hostname} 暂无 eth0_mac；"
                    "保留 hostname YAML，但不发布 MAC 链接"
                )
            eth1_valid = (not _na(row[_COL_ETH1_IP])
                          and not _na(row[_COL_ETH1_PFX])
                          and not _na(row[_COL_ETH1_GW]))
            eth1_mac = row[_COL_ETH1_MAC].lower() if not _na(row[_COL_ETH1_MAC]) else ""
            devices[hostname_key] = {
                "hostname":     hostname,
                "dev_type":     dev_type,
                "template":     row[2],
                "eth0_ip_cidr": f"{eth0_ip}/{eth0_pfx}",
                "eth0_gw":      row[_COL_ETH0_GW],
                "eth0_mac":     eth0_mac,
                "has_eth1":     eth1_valid,
                "eth1_ip_cidr": f"{row[_COL_ETH1_IP]}/{row[_COL_ETH1_PFX]}" if eth1_valid else "",
                "eth1_gw":      row[_COL_ETH1_GW] if eth1_valid else "",
                "eth1_mac":     eth1_mac,
                "identity_pending": identity_pending,
            }
    return devices


# ── Cumulus 默认配置同步 ──────────────────────────────────────────────────────

def _deep_merge(base, override):
    """递归合并 mapping；override 中的值优先。"""
    result = dict(base) if isinstance(base, dict) else {}
    for key, value in (override.items() if isinstance(override, dict) else []):
        if isinstance(result.get(key), dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _eth_global_system(global_data):
    """从合并格式 01-global.yaml 提取 common.switch + switches.eth 的 system。"""
    if not isinstance(global_data, dict):
        raise ValueError("01-global.yaml 顶层必须是 mapping")

    if "switches" not in global_data:
        system = global_data.get("system")
        if not isinstance(system, dict):
            raise ValueError("01-global.yaml 缺少 system 配置")
        return system

    common = global_data.get("common", {}).get("switch", {})
    eth = next(
        (item["eth"] for item in global_data.get("switches", [])
         if isinstance(item, dict) and isinstance(item.get("eth"), dict)),
        None,
    )
    if eth is None:
        raise ValueError("01-global.yaml 的 switches 中缺少 eth 配置")
    merged = _deep_merge(common, eth)
    system = merged.get("system")
    if not isinstance(system, dict):
        raise ValueError("01-global.yaml 的 ETH 配置缺少 system")
    return system


def _normalize_default_system(base_system, global_system):
    """合并 system，并把全局 DNS/NTP server 列表转换为 NVUE mapping。"""
    result = _deep_merge(base_system, global_system)

    global_dns = global_system.get("dns", {})
    if isinstance(global_dns, dict) and isinstance(global_dns.get("server"), list):
        vrf = global_dns.get("vrf")
        result.setdefault("dns", {})["server"] = {
            str(server): ({"vrf": vrf} if vrf else {})
            for server in global_dns["server"]
        }
        # NVUE DNS 的 vrf 属于每个 server，而不是 dns 顶层。
        result["dns"].pop("vrf", None)

    global_ntp = global_system.get("ntp", {})
    if isinstance(global_ntp, dict) and isinstance(global_ntp.get("server"), list):
        result.setdefault("ntp", {})["server"] = {
            str(server): {} for server in global_ntp["server"]
        }

    return result


def _default_document_with_global(default_data, global_system):
    """返回更新后的 default YAML 文档，不修改输入对象。"""
    if not isinstance(default_data, list):
        raise ValueError("default YAML 顶层必须是 list")
    updated = copy.deepcopy(default_data)
    for doc in updated:
        if not isinstance(doc, dict) or not isinstance(doc.get("set"), dict):
            continue
        system = doc["set"].get("system")
        if isinstance(system, dict):
            doc["set"]["system"] = _normalize_default_system(system, global_system)
            return updated
    raise ValueError("default YAML 缺少 set.system")


def _atomic_write_yaml(path, data):
    """在原目录生成临时文件并原子替换，保留原文件权限。"""
    mode = stat.S_IMODE(os.stat(path).st_mode)
    fd, tmp_path = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.",
                                    suffix=".tmp", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            yaml.safe_dump(data, stream, allow_unicode=True, sort_keys=False,
                           default_flow_style=False, width=120)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp_path, mode)
        # 写入后再次解析，确认不会用损坏文件替换现有默认配置。
        with open(tmp_path, encoding="utf-8") as stream:
            _strict_yaml_load(stream)
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def _refresh_cumulus_defaults(service_dir=None, global_file=None):
    """根据 01-global.yaml 同步 default*.yaml，以实际内容而非时间判定。"""
    service_dir = os.path.abspath(service_dir or _SCRIPT_DIR)
    global_file = os.path.abspath(
        global_file or os.path.join(service_dir, "template", "01-global.yaml")
    )
    defaults = sorted(glob.glob(os.path.join(service_dir, "default*.yaml")))
    if not defaults:
        raise ValueError(f"未找到默认配置：{service_dir}/default*.yaml")
    if not os.path.isfile(global_file):
        raise ValueError(f"未找到全局配置：{global_file}")

    with open(global_file, encoding="utf-8") as stream:
        global_data = _strict_yaml_load(stream)
    global_system = _eth_global_system(global_data)
    for default_file in defaults:
        with open(default_file, encoding="utf-8") as stream:
            default_data = _strict_yaml_load(stream)
        updated = _default_document_with_global(default_data, global_system)
        if updated == default_data:
            print(f"[OK] 默认配置已是最新：{default_file}")
            continue
        _atomic_write_yaml(default_file, updated)
        print(f"[UPDATE] 已根据 {global_file} 更新：{default_file}")


# ── YAML 验证 ─────────────────────────────────────────────────────────────────

def validate_yaml(yaml_path):
    try:
        with open(yaml_path, encoding="utf-8") as f:
            data = _strict_yaml_load(f)
        invalid = []

        def walk(value, path="$"):
            if value is None:
                invalid.append(path)
                return
            if isinstance(value, dict):
                for key, child in value.items():
                    key_text = str(key)
                    if key is None or key_text.casefold() in {"none", "null", "vlannone"}:
                        invalid.append(f"{path}.<key:{key_text}>")
                    walk(child, f"{path}.{key_text}")
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    walk(child, f"{path}[{index}]")

        walk(data)
        if invalid:
            return False, data, "NVUE 不允许 null：" + ", ".join(invalid[:8])
        return True, data, ""
    except yaml.YAMLError as e:
        return False, None, str(e)


def _get_iface_ip(data, iface):
    for doc in (data if isinstance(data, list) else [data]):
        try:
            block = doc.get("set") or doc
            addr_dict = block["interface"][iface]["ipv4"]["address"]
            if addr_dict:
                return next(iter(addr_dict))
        except (KeyError, TypeError, AttributeError):
            continue
    return None


def _get_iface_gw(data, iface):
    for doc in (data if isinstance(data, list) else [data]):
        try:
            block = doc.get("set") or doc
            gw_dict = block["interface"][iface]["ipv4"]["gateway"]
            if gw_dict:
                return next(iter(gw_dict))
        except (KeyError, TypeError, AttributeError):
            continue
    return None


def _ips_match(csv_cidr, yaml_cidr):
    def norm(s):
        parts = s.replace(" ", "").split("/")
        return parts[0], parts[1] if len(parts) > 1 else ""
    return norm(csv_cidr) == norm(yaml_cidr)


def _check_iface(data, basename, iface, csv_ip_cidr, csv_gw):
    yaml_ip = _get_iface_ip(data, iface)
    if yaml_ip is None:
        print(f"[WARN] {basename} 中未找到 {iface} IP 地址，跳过")
        return False
    if not _ips_match(csv_ip_cidr, yaml_ip):
        print(f"[IP不符] {basename} {iface}：CSV={csv_ip_cidr.replace(' ','')}  YAML={yaml_ip}")
        return False
    if _na(csv_gw):
        return True
    yaml_gw = _get_iface_gw(data, iface)
    if yaml_gw is None:
        print(f"[WARN] {basename} 中未找到 {iface} gateway，跳过")
        return False
    if csv_gw.strip() != (yaml_gw or "").strip():
        print(f"[GW不符] {basename} {iface}：CSV={csv_gw}  YAML={yaml_gw}")
        return False
    return True


def _make_symlink(yaml_dir, mac, host_name, iface, ip_cidr):
    mac_plain       = mac.replace(":", "").replace("-", "").lower()
    link            = os.path.join(yaml_dir, f"{mac_plain}.yaml")
    expected_target = f"{host_name}.yaml"
    if os.path.islink(link):
        existing_target = os.readlink(link)
        if existing_target == expected_target:
            print(f"[SKIP] {os.path.basename(link)} 已存在（→ {existing_target}）")
            return "skipped"
        print(f"[WARN] {os.path.basename(link)} 已存在但目标不符："
              f" 当前={existing_target}  期望={expected_target}")
        return "warned"
    if os.path.lexists(link):
        print(f"[WARN] {os.path.basename(link)} 已存在且不是软链接，无法创建 MAC 链接")
        return "warned"
    os.symlink(expected_target, link)
    print(f"[LINK] {os.path.basename(link)} -> {expected_target}  ({iface} {ip_cidr.replace(' ','')})")
    return "linked"


def _effective_cumulus_type(dev, devices):
    """Return eth/eth_spx/spx for production and AIR devices without hostname rules.

    AIR YAML names are derived from the original production hostname (for
    example AIR-SITE01-TAN-Leaf01 ends with TAN-Leaf01).  Prefer the longest
    matching original hostname so overlapping short names remain unambiguous.
    """
    dev_type = dev.get("dev_type", "")
    if dev_type != "air":
        return dev_type
    air_hostname = dev.get("hostname", "").casefold()
    matches = []
    for candidate in devices.values():
        production_name = candidate.get("hostname", "").casefold()
        if candidate.get("dev_type") not in {"eth", "eth_spx", "spx"}:
            continue
        if not production_name or not air_hostname.endswith(production_name):
            continue
        prefix = air_hostname[:-len(production_name)]
        if prefix.startswith("air-") and prefix.endswith(("-", "_")):
            matches.append(candidate)
    if not matches:
        return "air"
    matches.sort(key=lambda item: len(item.get("hostname", "")), reverse=True)
    longest = len(matches[0].get("hostname", ""))
    best = [item for item in matches if len(item.get("hostname", "")) == longest]
    types = {item.get("dev_type") for item in best}
    return types.pop() if len(types) == 1 else "air"


def _production_for_air_device(air_dev, devices):
    """Return the one production device represented by an AIR CSV row.

    AIR node names may be ``AIR-<production>`` or include a site prefix such
    as ``AIR-SITE01-<production>``. Prefer the longest suffix match and reject
    ambiguity instead of silently linking an AIR MAC to the wrong full YAML.
    """
    air_hostname = str(air_dev.get("hostname", "")).casefold()
    matches = [
        candidate for candidate in devices.values()
        if candidate.get("dev_type") in {"eth", "eth_spx", "spx"}
        and air_hostname.endswith(candidate.get("hostname", "").casefold())
    ]
    if not matches:
        raise ValueError(
            f"AIR 设备 {air_dev.get('hostname')} 找不到对应 production 设备"
        )
    longest = max(len(item.get("hostname", "")) for item in matches)
    best = [item for item in matches if len(item.get("hostname", "")) == longest]
    if len(best) != 1:
        names = ", ".join(sorted(item.get("hostname", "") for item in best))
        raise ValueError(
            f"AIR 设备 {air_dev.get('hostname')} 对应多个 production 设备：{names}"
        )
    return best[0]


def _sync_spx_marker(yaml_dir, mac, host_name, effective_type):
    """Publish a per-MAC marker consumed by bootstrap before installing AR."""
    mac_plain = mac.replace(":", "").replace("-", "").lower()
    marker = os.path.join(yaml_dir, f"{mac_plain}.spx")
    if effective_type in {"eth_spx", "spx"}:
        expected = f"{effective_type} {host_name}\n"
        current = ""
        if os.path.isfile(marker) and not os.path.islink(marker):
            with open(marker, encoding="utf-8") as stream:
                current = stream.read()
        if current != expected:
            with open(marker, "w", encoding="utf-8") as stream:
                stream.write(expected)
            print(f"[SPX] {os.path.basename(marker)} -> {host_name}")
    elif os.path.lexists(marker):
        os.unlink(marker)
        print(f"[CLEAN] 删除非 SPX 设备的旧标记：{os.path.basename(marker)}")


def _atomic_symlink(link_path, target, label):
    """Atomically create or replace one relative symlink."""
    if os.path.lexists(link_path) and not os.path.islink(link_path):
        print(f"[ERROR] {label} 是实际文件或目录，无法更新软链接")
        return False
    if os.path.islink(link_path) and os.readlink(link_path) == target:
        print(f"[SKIP] {label} 已指向 {target}")
        return True

    tmp_link = os.path.join(
        os.path.dirname(link_path), f".{os.path.basename(link_path)}.tmp.{os.getpid()}"
    )
    try:
        if os.path.lexists(tmp_link):
            os.remove(tmp_link)
        os.symlink(target, tmp_link)
        os.replace(tmp_link, link_path)
    finally:
        if os.path.lexists(tmp_link):
            os.remove(tmp_link)
    print(f"[LINK] {label} -> {target}")
    return True


def _day0_project_for_cumulus_publish(target_dir, day0_root=None):
    """Return the DAY0 project owning a physical 99-output-eth publish path."""
    published = Path(target_dir).resolve()
    output_root = published.parent
    root = Path(day0_root or _DAY0_ROOT).resolve()
    project = output_root.parent
    if output_root.name != "99-output-eth" or project.parent != root:
        return None
    return project


def _refresh_optimize_sample_links(target_dir):
    """Refresh <project>-sample links after a successful Cumulus publish."""
    project = _day0_project_for_cumulus_publish(target_dir)
    if project is None:
        return True  # NVOS or a standalone/test output outside DAY0-Prepare.

    module_path = _OPTIMIZE_DIR / "sample_links.py"
    if not module_path.is_file():
        print(f"[ERROR] 已发布配置，但找不到 optimize 链接模块：{module_path}")
        return False
    try:
        spec = importlib.util.spec_from_file_location(
            "hostname2mac_sample_links", module_path
        )
        module = importlib.util.module_from_spec(spec)
        if spec.loader is None:
            raise ImportError(f"无法加载 {module_path}")
        spec.loader.exec_module(module)
        sample = module.update_sample_links(_OPTIMIZE_DIR, project)
    except (ImportError, OSError, ValueError) as exc:
        print(f"[ERROR] 配置已发布，但刷新 optimize sample 链接失败：{exc}")
        return False
    print(f"[OK] optimize sample 链接已刷新：{sample}")
    return True


def _set_latest_yaml(service_dir, target_dir):
    """Publish through a project-local ``latest`` and stable HTTP entry.

    ``template/99-output*`` is the logical link to the active project's output
    root.  Keep ``service/latest_yaml`` fixed on ``template/99-output*/latest``
    and atomically move only the project-local ``latest`` pointer.
    """
    service_dir = os.path.abspath(service_dir)
    target_dir = os.path.abspath(target_dir)
    output_root = os.path.dirname(target_dir)
    marker = os.path.join(target_dir, ".published-complete")
    if not os.path.isfile(marker):
        print(f"[ERROR] 发布目录缺少 .published-complete：{target_dir}")
        return False

    output_latest = os.path.join(output_root, "latest")
    target_name = os.path.basename(target_dir)
    service_latest = os.path.join(service_dir, "latest_yaml")
    for path, label in (
        (output_latest, os.path.relpath(output_latest, service_dir)),
        (service_latest, "latest_yaml"),
    ):
        if os.path.lexists(path) and not os.path.islink(path):
            print(f"[ERROR] {label} 是实际文件或目录，无法更新软链接")
            return False
    if not _atomic_symlink(output_latest, target_name, os.path.relpath(output_latest, service_dir)):
        return False

    stable_target = os.path.relpath(output_latest, service_dir)
    if not _atomic_symlink(service_latest, stable_target, "latest_yaml"):
        return False
    return _refresh_optimize_sample_links(target_dir)


def _update_latest_yaml(yaml_dir):
    """更新项目输出的 latest，并保证 latest_yaml 使用固定入口。"""
    abs_yaml_dir = os.path.abspath(yaml_dir)
    output_root = os.path.dirname(abs_yaml_dir)
    if os.path.basename(output_root) in ("99-output", "99-output-ib_nvl"):
        service_dir = os.path.dirname(os.path.dirname(output_root))
        logical_target = abs_yaml_dir
    else:
        # 调用方可能传入项目真实的 99-output-* 路径。发布指针仍必须写入
        # 当前服务的 template/99-output* 逻辑入口，不能让 latest_yaml 直接
        # 指向项目物理路径。
        service_dir = _SCRIPT_DIR
        output_name = (
            "99-output-ib_nvl" if os.path.basename(service_dir) == "nvos"
            else "99-output"
        )
        logical_root = os.path.join(service_dir, "template", output_name)
        if os.path.realpath(logical_root) != os.path.realpath(output_root):
            print(
                "[ERROR] 指定目录不属于当前活动项目输出根："
                f"{abs_yaml_dir}（当前：{logical_root}）"
            )
            return False
        logical_target = os.path.join(logical_root, os.path.basename(abs_yaml_dir))
    return _set_latest_yaml(service_dir, logical_target)


def _mac_filename(mac):
    return mac.replace(":", "").replace("-", "").lower() + ".yaml"


def _nvos_dir_context(yaml_dir):
    """识别 template/99-output-ib_nvl/<timestamp>-{ib,nvl} 输入目录。"""
    abs_yaml_dir = os.path.abspath(yaml_dir)
    output_root = os.path.dirname(abs_yaml_dir)
    if os.path.basename(output_root) != "99-output-ib_nvl":
        return None
    match = re.fullmatch(r"(\d{8}_\d{6})-(ib|nvl)", os.path.basename(abs_yaml_dir))
    if not match:
        return None
    timestamp, kind = match.groups()
    template_dir = os.path.dirname(output_root)
    return {
        "path": abs_yaml_dir,
        "kind": kind,
        "timestamp": timestamp,
        "template_dir": template_dir,
        "service_dir": os.path.dirname(template_dir),
        "published_root": output_root,
        "combine_dir": os.path.join(output_root, f"{timestamp}-combine"),
    }


def _cumulus_dir_context(yaml_dir):
    """识别 99-output/<timestamp>、_with_desc 和 _air 输入目录。"""
    abs_yaml_dir = os.path.abspath(yaml_dir)
    output_root = os.path.dirname(abs_yaml_dir)
    if os.path.basename(output_root) != "99-output":
        return None
    match = re.fullmatch(
        r"(\d{8}_\d{6})(?:_(with_desc|air))?",
        os.path.basename(abs_yaml_dir),
        re.IGNORECASE,
    )
    if not match:
        return None
    timestamp, suffix = match.groups()
    kind = "air" if suffix and suffix.lower() == "air" else "production"
    return {
        "path": abs_yaml_dir,
        "kind": kind,
        "timestamp": timestamp,
        "service_dir": os.path.dirname(os.path.dirname(output_root)),
        "published_root": output_root,
        "combine_dir": os.path.join(output_root, f"{timestamp}_combine"),
    }


def _preferred_cumulus_contexts(contexts):
    """Return the effective Cumulus publish inputs for one timestamp.

    A confirmed description patch takes precedence over the plain production
    directory. Include the matching AIR hostname-only directory when present.
    """
    valid = [ctx for ctx in contexts if ctx is not None]
    if not valid:
        return contexts
    timestamps = {ctx["timestamp"] for ctx in valid}
    roots = {ctx["published_root"] for ctx in valid}
    if len(timestamps) != 1 or len(roots) != 1:
        return contexts

    timestamp = valid[0]["timestamp"]
    output_root = valid[0]["published_root"]
    base_path = os.path.join(output_root, timestamp)
    patched_path = os.path.join(output_root, f"{timestamp}_with_desc")
    production_path = patched_path if os.path.isdir(patched_path) else base_path

    air_path = os.path.join(output_root, f"{timestamp}_air")
    if os.path.isdir(production_path):
        selected = _cumulus_dir_context(production_path)
        if valid[0]["path"] != selected["path"]:
            print(f"[INFO] 检测到 patch 配置，改用：{production_path}")
        if os.path.isdir(air_path):
            return [selected, _cumulus_dir_context(air_path)]
        return [selected]
    return contexts


def _normalized_cumulus_without_hostname(path):
    """Return canonical YAML after removing the sole allowed environment delta."""
    with open(path, encoding="utf-8") as stream:
        document = _strict_yaml_load(stream)
    normalized = copy.deepcopy(document)
    replaced = 0
    for item in normalized if isinstance(normalized, list) else [normalized]:
        block = item.get("set") if isinstance(item, dict) else None
        system = block.get("system") if isinstance(block, dict) else None
        if isinstance(system, dict) and "hostname" in system:
            del system["hostname"]
            replaced += 1
    if replaced != 1:
        raise ValueError(f"{path}: 期望一个 set.system.hostname，实际 {replaced}")
    return yaml.safe_dump(normalized, sort_keys=True, allow_unicode=True)


def _canonical_yaml(path):
    """Return one strict, canonical representation used by release gates."""
    with open(path, encoding="utf-8") as stream:
        document = _strict_yaml_load(stream)
    return yaml.safe_dump(document, sort_keys=True, allow_unicode=True)


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _target_cumulus_version(global_file):
    with open(global_file, encoding="utf-8") as stream:
        data = _strict_yaml_load(stream)
    if not isinstance(data, dict):
        raise ValueError(f"{global_file}: 顶层必须是 mapping")
    if "switches" not in data:
        return str(data.get("version") or "").strip()
    eth = next(
        (item.get("eth") for item in data.get("switches", [])
         if isinstance(item, dict) and isinstance(item.get("eth"), dict)),
        None,
    )
    if eth is None:
        raise ValueError(f"{global_file}: switches 中缺少 eth")
    return str(eth.get("version") or "").strip()


def _effective_cumulus_default(service_dir):
    """Select exactly the same version/default fallback used by bootstrap."""
    global_file = os.path.join(service_dir, "template", "01-global.yaml")
    version = _target_cumulus_version(global_file)
    version_path = os.path.join(service_dir, f"default_{version}.yaml")
    default_path = os.path.join(service_dir, "default.yaml")
    selected = version_path if version and os.path.isfile(version_path) else default_path
    if not os.path.isfile(selected):
        raise ValueError(f"未找到有效 Cumulus default YAML: {selected}")
    return selected, version


def _load_air_generation_manifest(air_context):
    """Load identities/profile modes produced atomically with the AIR YAML set."""
    path = os.path.join(air_context["path"], "air-config-manifest.json")
    try:
        with open(path, encoding="utf-8") as stream:
            manifest = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"AIR 配置缺少有效 air-config-manifest.json: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError("AIR 配置 manifest schema_version 必须为 1")
    rows = manifest.get("devices")
    if not isinstance(rows, list) or not rows:
        raise ValueError("AIR 配置 manifest.devices 必须是非空 list")
    by_host = {}
    mac_owners = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("AIR 配置 manifest.devices 元素必须是 object")
        hostname = str(row.get("hostname") or "").strip()
        profile = str(row.get("profile") or "").strip().lower()
        mode = str(row.get("apply_mode") or "").strip().lower()
        mac = str(row.get("mac") or "").strip().lower()
        if not hostname or profile not in {"full", "baseline"}:
            raise ValueError(f"AIR manifest 设备字段无效: {row!r}")
        if not _SAFE_HOSTNAME_RE.fullmatch(hostname):
            raise ValueError(f"AIR manifest hostname 含不安全字符: {hostname!r}")
        expected_mode = "replace" if profile == "full" else "patch"
        if mode != expected_mode:
            raise ValueError(
                f"AIR manifest {hostname}: profile={profile} 必须使用 {expected_mode}"
            )
        if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac):
            raise ValueError(f"AIR manifest {hostname}: eth0 MAC 无效 {mac!r}")
        key = hostname.casefold()
        mac_key = mac.replace(":", "")
        if key in by_host:
            raise ValueError(f"AIR manifest hostname 重复: {hostname}")
        if mac_key in mac_owners:
            raise ValueError(
                f"AIR manifest MAC 重复: {mac} 属于 {mac_owners[mac_key]} / {hostname}"
            )
        mac_owners[mac_key] = hostname
        normalized = dict(row)
        normalized.update({
            "hostname": hostname, "profile": profile,
            "apply_mode": mode, "mac": mac,
        })
        by_host[key] = normalized
    return manifest, by_host


def _configured_cumulus_hostname(path):
    with open(path, encoding="utf-8") as stream:
        document = _strict_yaml_load(stream)
    values = []
    for item in document if isinstance(document, list) else [document]:
        block = item.get("set") if isinstance(item, dict) else None
        system = block.get("system") if isinstance(block, dict) else None
        if isinstance(system, dict) and "hostname" in system:
            values.append(str(system["hostname"]))
    if len(values) != 1:
        raise ValueError(f"{path}: 期望一个 set.system.hostname，实际 {len(values)}")
    return values[0]


def _validate_air_production_yaml_pairs(staging_dir, devices, profiles=None):
    """Require every AIR YAML to equal its Production pair except hostname."""
    checked = 0
    air_devices = sorted(
        (dev for dev in devices.values() if dev.get("dev_type") == "air"),
        key=lambda dev: dev["hostname"].casefold(),
    )
    for air_dev in air_devices:
        profile = (profiles or {}).get(air_dev["hostname"].casefold())
        if profile is not None and profile.get("profile") != "full":
            continue
        if profile and profile.get("source_hostname"):
            production = devices.get(str(profile["source_hostname"]).casefold())
            if production is None or production.get("dev_type") not in {"eth", "eth_spx", "spx"}:
                raise ValueError(
                    f"AIR 设备 {air_dev['hostname']} 的 source_hostname 无效: "
                    f"{profile['source_hostname']}"
                )
        else:
            production = _production_for_air_device(air_dev, devices)
        air_path = os.path.join(staging_dir, f"{air_dev['hostname']}.yaml")
        production_path = os.path.join(staging_dir, f"{production['hostname']}.yaml")
        if not os.path.isfile(air_path) or not os.path.isfile(production_path):
            raise ValueError(
                f"配置配对缺失：{production['hostname']}.yaml / {air_dev['hostname']}.yaml"
            )
        for path, expected in (
            (production_path, production["hostname"]),
            (air_path, air_dev["hostname"]),
        ):
            configured = _configured_cumulus_hostname(path)
            if configured.casefold() != expected.casefold():
                raise ValueError(
                    f"{path}: set.system.hostname={configured!r}，应为 {expected!r}"
                )
        if (_normalized_cumulus_without_hostname(air_path)
                != _normalized_cumulus_without_hostname(production_path)):
            raise ValueError(
                f"AIR 配置除 hostname 外发生漂移：{air_dev['hostname']}.yaml "
                f"!= {production['hostname']}.yaml"
            )
        checked += 1
    return checked


def _validate_air_baselines(staging_dir, profiles, default_path):
    """Require every baseline YAML to equal effective default plus hostname."""
    canonical_default = _canonical_yaml(default_path)
    checked = 0
    for profile in sorted(profiles.values(), key=lambda item: item["hostname"].casefold()):
        if profile.get("profile") != "baseline":
            continue
        path = os.path.join(staging_dir, f"{profile['hostname']}.yaml")
        if not os.path.isfile(path):
            raise ValueError(f"AIR baseline 配置缺失: {profile['hostname']}.yaml")
        configured = _configured_cumulus_hostname(path)
        if configured.casefold() != profile["hostname"].casefold():
            raise ValueError(
                f"{path}: set.system.hostname={configured!r}，应为 {profile['hostname']!r}"
            )
        if _normalized_cumulus_without_hostname(path) != canonical_default:
            raise ValueError(
                f"AIR baseline 除 hostname 外发生漂移: {profile['hostname']}.yaml "
                f"!= {os.path.basename(default_path)}"
            )
        checked += 1
    return checked


def _archive_combined_sources(contexts):
    """Archive successful Cumulus publish inputs, then remove the directories."""
    sources = [os.path.abspath(ctx["path"]) for ctx in contexts]
    if not sources or len(sources) > 2 or len(set(sources)) != len(sources):
        raise ValueError("combine 归档必须包含一到两个不同的源目录")
    output_root = os.path.abspath(contexts[0]["published_root"])
    if any(os.path.dirname(path) != output_root for path in sources):
        raise ValueError("combine 源目录必须直接位于同一个 99-output 目录")
    if any(not os.path.isdir(path) or os.path.islink(path) for path in sources):
        raise ValueError("combine 源目录不存在或不是实际目录")

    archive_path = os.path.join(
        output_root, f"{contexts[0]['timestamp']}_combine_sources.tar.gz"
    )
    fd, temp_path = tempfile.mkstemp(
        prefix=f".{contexts[0]['timestamp']}_combine_sources.",
        suffix=".tar.gz.tmp",
        dir=output_root,
    )
    os.close(fd)
    try:
        with tarfile.open(temp_path, "w:gz", dereference=False) as archive:
            for source in sources:
                archive.add(source, arcname=os.path.basename(source))
        expected_roots = {os.path.basename(path) for path in sources}
        with tarfile.open(temp_path, "r:gz") as archive:
            archived_roots = {
                member.name.split("/", 1)[0] for member in archive.getmembers()
            }
        if not expected_roots.issubset(archived_roots):
            raise ValueError("combine 源目录归档校验失败")
        os.replace(temp_path, archive_path)
        for source in sources:
            shutil.rmtree(source)
            print(f"[CLEAN] 已归档并删除 combine 源目录：{source}")
        print(f"[OK] combine 源目录归档：{archive_path}")
        return archive_path
    finally:
        if os.path.lexists(temp_path):
            os.unlink(temp_path)


def _remove_superseded_cumulus_base(contexts):
    """Delete the unpatched base after a patched production publish succeeds."""
    production = next(
        (ctx for ctx in contexts if ctx and ctx.get("kind") == "production"), None
    )
    if production is None or not production["path"].endswith("_with_desc"):
        return False
    base_path = os.path.join(
        production["published_root"], production["timestamp"]
    )
    if not os.path.lexists(base_path):
        return False
    if os.path.islink(base_path) or not os.path.isdir(base_path):
        raise ValueError(f"patch 原配置路径不是实际目录，拒绝删除：{base_path}")
    shutil.rmtree(base_path)
    print(f"[CLEAN] patch 已取代原配置，直接删除且不归档：{base_path}")
    return True


def _validate_publish_names(devices):
    """跨 IB/NVL 检查 published 目录中的 hostname/MAC 文件名冲突。"""
    owners = {}
    errors = []
    for dev in devices.values():
        if dev["dev_type"] not in ("ib", "nvl"):
            continue
        names = [f"{dev['hostname']}.yaml"]
        if dev["eth0_mac"]:
            names.append(_mac_filename(dev["eth0_mac"]))
        if dev["eth1_mac"]:
            names.append(_mac_filename(dev["eth1_mac"]))
        for name in names:
            key = name.lower()
            owner = owners.get(key)
            if owner and owner.lower() != dev["hostname"].lower():
                errors.append(
                    f"发布文件名冲突：{name} 同时属于 {owner} 和 {dev['hostname']}"
                )
            else:
                owners[key] = dev["hostname"]
    return errors


def _process_yaml_files(yaml_dir, devices, allowed_types=None, profiles=None):
    """验证目录中的主机配置并创建 MAC 链接，返回 (ok, counters, hosts)。"""
    counters = {
        "linked": 0, "skipped": 0, "pending": 0,
        "warned": 0, "yaml_error": 0,
    }
    hosts = set()
    hostname_yamls = [
        p for p in sorted(glob.glob(os.path.join(yaml_dir, "*.yaml")))
        if not os.path.islink(p)
    ]
    for yaml_path in hostname_yamls:
        basename = os.path.basename(yaml_path)
        host_name = os.path.splitext(basename)[0]
        dev = devices.get(host_name.lower())
        if dev is None:
            print(f"[WARN] {basename} 在 CSV 中未找到对应记录")
            counters["warned"] += 1
            continue
        if allowed_types and dev["dev_type"] not in allowed_types:
            print(f"[WARN] {basename} 类型为 {dev['dev_type']}，与输入目录类型不符")
            counters["warned"] += 1
            continue
        hosts.add(host_name.lower())
        ok, data, err = validate_yaml(yaml_path)
        if not ok:
            print(f"[YAML错误] {basename}：{err}")
            counters["yaml_error"] += 1
            continue
        profile = (profiles or {}).get(host_name.lower(), {})
        if profile.get("profile") == "baseline":
            configured = _configured_cumulus_hostname(yaml_path)
            if configured.casefold() != host_name.casefold():
                print(
                    f"[HOSTNAME不符] {basename}: YAML={configured!r} 期望={host_name!r}"
                )
                counters["warned"] += 1
                continue
            result = _make_symlink(
                yaml_dir, dev["eth0_mac"], host_name, "eth0", "dynamic"
            )
            counters[result] += 1
            continue
        if not dev.get("eth0_mac"):
            # Hostname YAML remains part of the atomic release so it is ready
            # as soon as inventory learns the MAC.  Until then it must never
            # acquire an empty-name `.yaml` link.
            if not _check_iface(
                data, basename, "eth0", dev["eth0_ip_cidr"], dev["eth0_gw"]
            ):
                counters["warned"] += 1
                continue
            counters["pending"] += 1
            print(f"[PENDING] {basename}: identity_pending，未创建 MAC 链接")
            continue
        checks = [("eth0", dev["eth0_mac"], dev["eth0_ip_cidr"], dev["eth0_gw"])]
        if dev["eth1_mac"]:
            checks.append(("eth1", dev["eth1_mac"], dev["eth1_ip_cidr"], dev["eth1_gw"]))
        for iface, mac, ip_cidr, gateway in checks:
            if not _check_iface(data, basename, iface, ip_cidr, gateway):
                counters["warned"] += 1
                continue
            result = _make_symlink(yaml_dir, mac, host_name, iface, ip_cidr)
            counters[result] += 1
            if result in {"linked", "skipped"}:
                _sync_spx_marker(
                    yaml_dir, mac, host_name,
                    _effective_cumulus_type(dev, devices),
                )
    ok = counters["warned"] == 0 and counters["yaml_error"] == 0
    return ok, counters, hosts


def _write_cumulus_mode_sidecars(yaml_dir, devices, profiles):
    """Write one tiny, MAC-addressed apply-mode file beside every YAML link."""
    written = 0
    for hostname_key, profile in sorted(profiles.items()):
        dev = devices.get(hostname_key)
        if dev is None:
            raise ValueError(f"apply mode 找不到设备: {profile.get('hostname')}")
        mode = profile.get("apply_mode")
        if mode not in {"replace", "patch"}:
            raise ValueError(f"{dev['hostname']}: 无效 apply mode {mode!r}")
        macs = [dev.get("eth0_mac"), dev.get("eth1_mac")]
        for mac in (value for value in macs if value):
            mac_plain = mac.replace(":", "").replace("-", "").lower()
            yaml_link = os.path.join(yaml_dir, f"{mac_plain}.yaml")
            if not os.path.islink(yaml_link):
                raise ValueError(f"{dev['hostname']}: MAC YAML 链接缺失 {mac_plain}.yaml")
            if os.readlink(yaml_link) != f"{dev['hostname']}.yaml":
                raise ValueError(f"{dev['hostname']}: MAC YAML 链接目标错误 {yaml_link}")
            mode_path = os.path.join(yaml_dir, f"{mac_plain}.mode")
            with open(mode_path, "w", encoding="ascii") as stream:
                stream.write(mode + "\n")
            written += 1
    return written


def _missing_expected_hosts(devices, kinds, hosts):
    return sorted(
        dev["hostname"] for dev in devices.values()
        if dev["dev_type"] in kinds and dev["hostname"].lower() not in hosts
    )


def _confirm_replace(path):
    if not os.path.exists(path):
        return True
    if _AUTO_YES:
        print(f"[REPLACE] {path} 已存在，-y 模式将替换")
        return True
    print(f"发布目录已存在：{path}")
    print(f"是否替换？[y/N]（{_CONFIRM_TIMEOUT} 秒后默认不替换）", end=" ", flush=True)
    ready, _, _ = select.select([sys.stdin], [], [], _CONFIRM_TIMEOUT)
    answer = sys.stdin.readline().strip().lower() if ready else ""
    if not ready:
        print("n")
    return answer in ("y", "yes")


def _write_nvos_release_manifest(directory, timestamp, devices, hosts, kinds):
    release_devices = []
    for hostname_key in sorted(hosts):
        dev = devices[hostname_key]
        if dev.get("dev_type") not in kinds:
            continue
        config_path = os.path.join(directory, f"{dev['hostname']}.yaml")
        release_devices.append({
            "hostname": dev["hostname"],
            "type": dev["dev_type"],
            "config": os.path.basename(config_path),
            "config_sha256": _sha256_file(config_path),
            "macs": [
                mac for mac in (dev.get("eth0_mac"), dev.get("eth1_mac")) if mac
            ],
            "identity_state": (
                "identity_pending" if dev.get("identity_pending") else "managed"
            ),
        })
    pending = sum(
        item["identity_state"] == "identity_pending" for item in release_devices
    )
    manifest = {
        "schema_version": 1,
        "release_id": f"{timestamp}-nvos",
        "types": sorted(kinds),
        "identity_pending": pending,
        "devices": release_devices,
    }
    with open(
        os.path.join(directory, "release-manifest.json"),
        "w", encoding="utf-8",
    ) as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return pending


def _publish_single_nvos(ctx, devices):
    print(f"处理目录：{ctx['path']}\n")
    ok, counters, hosts = _process_yaml_files(ctx["path"], devices, {ctx["kind"]})
    missing = _missing_expected_hosts(devices, {ctx["kind"]}, hosts)
    if missing:
        print(f"[ERROR] 缺少 {len(missing)} 台 {ctx['kind'].upper()} 设备配置：")
        for hostname in missing:
            print(f"  {hostname}.yaml")
        ok = False
    _print_process_summary(counters)
    if not ok:
        print("[ERROR] 输入目录校验失败，latest_yaml 保持不变")
        return False
    pending = _write_nvos_release_manifest(
        ctx["path"], ctx["timestamp"], devices, hosts, {ctx["kind"]}
    )
    marker = os.path.join(ctx["path"], ".published-complete")
    with open(marker, "w", encoding="utf-8") as f:
        f.write(
            f"{ctx['timestamp']} {ctx['kind']}\n"
            f"identity_pending={pending}\n"
        )
    print(f"[OK] NVOS {ctx['kind'].upper()} 发布完整：{len(hosts)} 台设备")
    return _set_latest_yaml(ctx["service_dir"], ctx["path"])


def _publish_combined_nvos(contexts, devices):
    timestamps = {ctx["timestamp"] for ctx in contexts}
    kinds = {ctx["kind"] for ctx in contexts}
    roots = {ctx["published_root"] for ctx in contexts}
    if len(timestamps) != 1:
        print("[ERROR] 两个输入目录的时间戳必须完全相同")
        return False
    if kinds != {"ib", "nvl"}:
        print("[ERROR] 两个输入目录必须分别为 -ib 和 -nvl，不能重复")
        return False
    if len(roots) != 1:
        print("[ERROR] 两个输入目录必须位于同一个 99-output-ib_nvl 目录")
        return False
    name_errors = _validate_publish_names(devices)
    if name_errors:
        print("[ERROR] NVOS 合并发布文件名检查失败：")
        for error in name_errors:
            print(f"  {error}")
        return False

    timestamp = contexts[0]["timestamp"]
    final_dir = contexts[0]["combine_dir"]
    staging_dir = os.path.join(contexts[0]["published_root"], f".{timestamp}-combine.tmp.{os.getpid()}")
    if os.path.lexists(staging_dir):
        shutil.rmtree(staging_dir)
    os.makedirs(staging_dir)
    try:
        copied_hosts = set()
        for ctx in sorted(contexts, key=lambda item: item["kind"]):
            print(f"复制 {ctx['kind'].upper()} 配置：{ctx['path']}")
            for src in sorted(glob.glob(os.path.join(ctx["path"], "*.yaml"))):
                if os.path.islink(src):
                    continue
                basename = os.path.basename(src)
                hostname = os.path.splitext(basename)[0]
                dev = devices.get(hostname.lower())
                if dev is None or dev["dev_type"] != ctx["kind"]:
                    print(f"[ERROR] {src} 在 CSV 中不存在或类型与目录不符")
                    return False
                dest = os.path.join(staging_dir, basename)
                if os.path.lexists(dest):
                    print(f"[ERROR] 两个输入目录存在同名配置：{basename}")
                    return False
                shutil.copy2(src, dest)
                copied_hosts.add(hostname.lower())

        missing = _missing_expected_hosts(devices, kinds, copied_hosts)
        if missing:
            print(f"[ERROR] 合并输入缺少 {len(missing)} 台设备配置：")
            for hostname in missing:
                print(f"  {hostname}.yaml")
            return False

        print(f"\n在合并目录中校验配置并创建 MAC 链接：{staging_dir}\n")
        ok, counters, processed_hosts = _process_yaml_files(staging_dir, devices, kinds)
        _print_process_summary(counters)
        if not ok or processed_hosts != copied_hosts:
            print("[ERROR] 合并目录校验失败，latest_yaml 保持不变")
            return False

        pending = _write_nvos_release_manifest(
            staging_dir, timestamp, devices, processed_hosts, kinds
        )
        with open(os.path.join(staging_dir, ".published-complete"), "w", encoding="utf-8") as f:
            f.write(
                f"{timestamp} combine\n"
                f"identity_pending={pending}\n"
            )
        if not _confirm_replace(final_dir):
            print("[SKIP] 保留现有发布目录和 latest_yaml")
            return False

        backup_dir = None
        if os.path.exists(final_dir):
            backup_dir = f"{final_dir}.old.{os.getpid()}"
            if os.path.lexists(backup_dir):
                shutil.rmtree(backup_dir)
            os.replace(final_dir, backup_dir)
        try:
            os.replace(staging_dir, final_dir)
        except Exception:
            if backup_dir and os.path.exists(backup_dir) and not os.path.exists(final_dir):
                os.replace(backup_dir, final_dir)
            raise
        if backup_dir:
            shutil.rmtree(backup_dir)
        print(f"[OK] 合并发布目录：{final_dir}（{len(processed_hosts)} 台设备）")
        return _set_latest_yaml(contexts[0]["service_dir"], final_dir)
    finally:
        if os.path.lexists(staging_dir):
            shutil.rmtree(staging_dir)


def _publish_combined_cumulus(contexts, devices):
    """Stage and atomically publish Production/full and AIR full/baseline YAML."""
    timestamps = {ctx["timestamp"] for ctx in contexts}
    kinds = {ctx["kind"] for ctx in contexts}
    roots = {ctx["published_root"] for ctx in contexts}
    if len(timestamps) != 1:
        print("[ERROR] Cumulus 与 AIR 输入目录的时间戳必须完全相同")
        return False
    if kinds != {"production", "air"}:
        print("[ERROR] 两个 Cumulus 输入目录必须分别为普通目录和 _air 目录")
        return False
    if len(roots) != 1:
        print("[ERROR] 两个 Cumulus 输入目录必须位于同一个 99-output 目录")
        return False

    timestamp = contexts[0]["timestamp"]
    service_dir = contexts[0]["service_dir"]
    air_context = next(ctx for ctx in contexts if ctx["kind"] == "air")
    try:
        _refresh_cumulus_defaults(service_dir=service_dir)
        default_path, target_version = _effective_cumulus_default(service_dir)
        generation_manifest, air_profiles = _load_air_generation_manifest(air_context)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"[ERROR] Cumulus release 输入校验失败：{exc}")
        return False

    expected_default_hash = str(
        generation_manifest.get("effective_default_sha256") or ""
    ).strip().lower()
    current_default_hash = _sha256_file(default_path)
    if expected_default_hash != current_default_hash:
        print(
            "[ERROR] AIR baseline 生成后 effective default 已变化；"
            "请重新运行配置生成器再发布\n"
            f"        manifest={expected_default_hash or 'missing'}\n"
            f"        current ={current_default_hash} ({default_path})"
        )
        return False
    manifest_version = str(
        generation_manifest.get("target_cumulus_version") or ""
    ).strip()
    if manifest_version != target_version:
        print(
            f"[ERROR] AIR manifest 目标版本 {manifest_version!r} 与当前 "
            f"{target_version!r} 不一致"
        )
        return False

    publish_devices = copy.deepcopy(devices)
    profiles = {}
    for dev in publish_devices.values():
        if dev.get("dev_type") in {"eth", "eth_spx", "spx"}:
            profiles[dev["hostname"].casefold()] = {
                "hostname": dev["hostname"],
                "environment": "production",
                "profile": "full",
                "apply_mode": "replace",
                "source_hostname": dev["hostname"],
            }
    for hostname_key, profile in air_profiles.items():
        existing = publish_devices.get(hostname_key)
        if existing is not None:
            if existing.get("dev_type") != "air":
                print(f"[ERROR] AIR manifest hostname 与非 AIR CSV 行冲突: {profile['hostname']}")
                return False
            if existing.get("eth0_mac", "").lower() != profile["mac"]:
                print(
                    f"[ERROR] AIR manifest/CSV MAC 不一致: {profile['hostname']} "
                    f"manifest={profile['mac']} CSV={existing.get('eth0_mac')}"
                )
                return False
        else:
            # AIR-only identities are authoritative in AIR JSON and intentionally
            # have no synthetic static management address.
            publish_devices[hostname_key] = {
                "hostname": profile["hostname"],
                "dev_type": "air",
                "template": "default",
                "eth0_ip_cidr": "dynamic",
                "eth0_gw": "",
                "eth0_mac": profile["mac"],
                "has_eth1": False,
                "eth1_ip_cidr": "",
                "eth1_gw": "",
                "eth1_mac": "",
            }
        normalized = dict(profile)
        normalized["environment"] = "air"
        profiles[hostname_key] = normalized

    final_dir = contexts[0]["combine_dir"]
    staging_dir = os.path.join(
        contexts[0]["published_root"], f".{timestamp}_combine.tmp.{os.getpid()}"
    )
    if os.path.lexists(staging_dir):
        shutil.rmtree(staging_dir)
    os.makedirs(staging_dir)
    allowed_by_kind = {"production": {"eth", "eth_spx", "spx"}, "air": {"air"}}
    expected_types = {"eth", "eth_spx", "spx", "air"}
    try:
        copied_hosts = set()
        for ctx in sorted(contexts, key=lambda item: item["kind"]):
            allowed = allowed_by_kind[ctx["kind"]]
            print(f"复制 {ctx['kind'].upper()} 配置：{ctx['path']}")
            for src in sorted(glob.glob(os.path.join(ctx["path"], "*.yaml"))):
                if os.path.islink(src):
                    continue
                basename = os.path.basename(src)
                hostname = os.path.splitext(basename)[0]
                dev = publish_devices.get(hostname.lower())
                if dev is None or dev["dev_type"] not in allowed:
                    print(f"[ERROR] {src} 在 release inventory 中不存在或类型与目录不符")
                    return False
                if ctx["kind"] == "air" and hostname.lower() not in air_profiles:
                    print(f"[ERROR] {src} 不在 air-config-manifest.json")
                    return False
                dest = os.path.join(staging_dir, basename)
                if os.path.lexists(dest):
                    print(f"[ERROR] 两个输入目录存在同名配置：{basename}")
                    return False
                shutil.copy2(src, dest)
                copied_hosts.add(hostname.lower())

        air_yaml_hosts = {
            host for host in copied_hosts
            if publish_devices[host].get("dev_type") == "air"
        }
        if air_yaml_hosts != set(air_profiles):
            print(
                "[ERROR] AIR manifest/YAML hostname 集合不一致："
                f"缺少={sorted(set(air_profiles) - air_yaml_hosts) or '无'}，"
                f"多余={sorted(air_yaml_hosts - set(air_profiles)) or '无'}"
            )
            return False

        try:
            pair_count = _validate_air_production_yaml_pairs(
                staging_dir, publish_devices, profiles
            )
            baseline_count = _validate_air_baselines(
                staging_dir, profiles, default_path
            )
        except ValueError as exc:
            print(f"[ERROR] {exc}")
            return False
        print(f"[OK] Production/AIR 配置一致性：{pair_count} 对，仅 hostname 不同")
        print(
            f"[OK] AIR baseline 一致性：{baseline_count} 份，仅在 "
            f"{os.path.basename(default_path)} 上增加 hostname"
        )

        print(f"\n在合并目录中校验配置并创建 MAC 链接：{staging_dir}\n")
        ok, counters, processed_hosts = _process_yaml_files(
            staging_dir, publish_devices, expected_types, profiles=profiles
        )
        _print_process_summary(counters)
        if not ok or processed_hosts != copied_hosts:
            print("[ERROR] Cumulus 合并目录校验失败，latest_yaml 保持不变")
            return False

        missing = _missing_expected_hosts(publish_devices, expected_types, processed_hosts)
        if missing:
            print(
                f"[ERROR] 以下 {len(missing)} 台 Cumulus/AIR 设备缺少 hostname YAML；"
                "即使 identity_pending 也必须先生成可审核配置，拒绝切换 latest："
            )
            for hostname in missing:
                print(f"  {hostname}.yaml")
            return False

        try:
            mode_count = _write_cumulus_mode_sidecars(
                staging_dir, publish_devices, profiles
            )
        except ValueError as exc:
            print(f"[ERROR] apply-mode sidecar 校验失败：{exc}")
            return False

        release_default = os.path.join(staging_dir, os.path.basename(default_path))
        if os.path.lexists(release_default):
            print(f"[ERROR] release 默认文件名与设备配置冲突：{release_default}")
            return False
        shutil.copy2(default_path, release_default)
        if _sha256_file(release_default) != current_default_hash:
            print("[ERROR] release 默认配置复制校验失败")
            return False

        production_count = sum(
            dev.get("dev_type") in {"eth", "eth_spx", "spx"}
            for dev in publish_devices.values()
        )
        air_count = sum(dev.get("dev_type") == "air" for dev in publish_devices.values())
        production_mac_count = sum(
            bool(dev.get("eth0_mac")) + bool(dev.get("eth1_mac"))
            for dev in publish_devices.values()
            if dev.get("dev_type") in {"eth", "eth_spx", "spx"}
        )
        air_mac_count = sum(
            bool(dev.get("eth0_mac")) + bool(dev.get("eth1_mac"))
            for dev in publish_devices.values() if dev.get("dev_type") == "air"
        )
        release_devices = []
        for hostname_key in sorted(processed_hosts):
            dev = publish_devices[hostname_key]
            profile = profiles[hostname_key]
            config_path = os.path.join(staging_dir, f"{dev['hostname']}.yaml")
            release_devices.append({
                "hostname": dev["hostname"],
                "environment": profile["environment"],
                "profile": profile["profile"],
                "apply_mode": profile["apply_mode"],
                "macs": [
                    mac for mac in (dev.get("eth0_mac"), dev.get("eth1_mac")) if mac
                ],
                "config": os.path.basename(config_path),
                "config_sha256": _sha256_file(config_path),
                "source_hostname": profile.get("source_hostname"),
                "source_default": profile.get("source_default"),
                "identity_state": (
                    "identity_pending" if dev.get("identity_pending") else "managed"
                ),
            })
        identity_pending_count = sum(
            item["identity_state"] == "identity_pending"
            for item in release_devices
        )
        release_manifest = {
            "schema_version": 1,
            "release_id": f"{timestamp}-cumulus-air",
            "target_cumulus_version": target_version,
            "effective_default": os.path.basename(release_default),
            "effective_default_sha256": current_default_hash,
            "mode_sidecars": mode_count,
            "identity_pending": identity_pending_count,
            "devices": release_devices,
        }
        with open(
            os.path.join(staging_dir, "release-manifest.json"),
            "w", encoding="utf-8",
        ) as stream:
            json.dump(release_manifest, stream, indent=2, sort_keys=True)
            stream.write("\n")
        with open(os.path.join(staging_dir, ".published-complete"), "w", encoding="utf-8") as f:
            f.write(
                f"{timestamp} cumulus+air\n"
                f"production_yaml={production_count}\n"
                f"air_yaml={air_count}\n"
                f"production_mac_links={production_mac_count}\n"
                f"air_mac_links={air_mac_count}\n"
                f"mode_sidecars={mode_count}\n"
                f"effective_default={os.path.basename(release_default)}\n"
                f"identity_pending={identity_pending_count}\n"
            )
        if not _confirm_replace(final_dir):
            print("[SKIP] 保留现有发布目录和 latest_yaml")
            return False

        backup_dir = None
        if os.path.exists(final_dir):
            backup_dir = f"{final_dir}.old.{os.getpid()}"
            if os.path.lexists(backup_dir):
                shutil.rmtree(backup_dir)
            os.replace(final_dir, backup_dir)
        try:
            os.replace(staging_dir, final_dir)
        except Exception:
            if backup_dir and os.path.exists(backup_dir) and not os.path.exists(final_dir):
                os.replace(backup_dir, final_dir)
            raise
        if backup_dir:
            shutil.rmtree(backup_dir)
        print(f"[OK] Cumulus/AIR 合并发布目录：{final_dir}（{len(processed_hosts)} 台设备）")
        if not _set_latest_yaml(contexts[0]["service_dir"], final_dir):
            return False
        try:
            _archive_combined_sources(contexts)
            _remove_superseded_cumulus_base(contexts)
        except (OSError, ValueError, tarfile.TarError) as exc:
            print(f"[ERROR] combine 已发布，但源目录归档清理失败：{exc}")
            return False
        return True
    finally:
        if os.path.lexists(staging_dir):
            shutil.rmtree(staging_dir)


def _print_process_summary(counters):
    print(
        f"\n完成：创建 {counters['linked']} 个链接，跳过 {counters['skipped']} 个，"
        f"identity pending {counters.get('pending', 0)} 台，"
        f"yaml 错误 {counters['yaml_error']} 个，其他警告 {counters['warned']} 个"
    )


def _cumulus_publish_context(yaml_dir):
    """返回普通/AIR Cumulus 输出目录的发布规则。"""
    name = os.path.basename(os.path.abspath(yaml_dir))
    if re.search(r"(?:_|-)air$", name, re.IGNORECASE):
        return {
            "types": {"air"}, "label": "AIR", "report_missing": True,
            "missing_is_error": False,
        }
    return {
        "types": {"eth", "eth_spx", "spx"}, "label": "Cumulus", "report_missing": True,
        "missing_is_error": False,
    }


# ── 默认目录解析 ──────────────────────────────────────────────────────────────

def _resolve_logical_link(path):
    """Resolve trailing symlinks without collapsing linked parent directories.

    Keeping ``template/99-output`` in the returned path is important because it
    identifies the owning Cumulus/NVOS service.  ``realpath`` is used only by
    callers when comparing destinations.
    """
    current = os.path.normpath(os.path.abspath(path))
    seen = set()
    for _ in range(16):
        if current in seen:
            raise RuntimeError(f"软链接形成循环：{path}")
        seen.add(current)
        if not os.path.islink(current):
            return current
        target = os.readlink(current)
        current = os.path.normpath(
            target if os.path.isabs(target)
            else os.path.join(os.path.dirname(current), target)
        )
    raise RuntimeError(f"软链接层级过深：{path}")

def _resolve_yaml_dir():
    """
    未指定目录时自动确定 yaml_dir：
    1. 找当前分支输出根目录下最新的待处理子目录（latest_on_disk）
    2. 读取 latest_yaml 软链接当前指向（latest_link）
    3. 若两者相同（或 latest_on_disk 不存在）→ 直接用 latest_yaml
    4. 若不同 → 提示用户选择
    """
    cwd         = os.getcwd()
    is_nvos     = os.path.basename(cwd) == "nvos"
    output_name = "99-output-ib_nvl" if is_nvos else "99-output"
    out_base    = os.path.join(cwd, "template", output_name)
    link_path   = os.path.join(cwd, "latest_yaml")

    # 找 template/99-output/ 下最新子目录（排除软链接本身）
    latest_on_disk = None
    if os.path.isdir(out_base):
        subs = [
            d for d in glob.glob(os.path.join(out_base, "*"))
            if os.path.isdir(d) and not os.path.islink(d)
        ]
        if is_nvos:
            # 合并目录是发布结果，不是下一次 hostname2mac 的输入。
            subs = [
                d for d in subs
                if re.fullmatch(r"\d{8}_\d{6}-(?:ib|nvl)", os.path.basename(d))
            ]
            subs.sort(
                key=lambda d: os.path.basename(d).rsplit("-", 1)[-1],
                reverse=True,
            )
        else:
            # combine 是发布结果，归档文件不是目录；只把尚未发布的三类
            # 生成目录作为 hostname2mac 的候选输入。
            completed_timestamps = {
                match.group(1)
                for directory in glob.glob(os.path.join(out_base, "*_combine"))
                for match in [re.fullmatch(
                    r"(\d{8}_\d{6})_combine", os.path.basename(directory)
                )]
                if match and os.path.isfile(
                    os.path.join(directory, ".published-complete")
                )
            }
            subs = [
                d for d in subs
                if (
                    (match := re.fullmatch(
                        r"(\d{8}_\d{6})(?:_(?:with_desc|air))?",
                        os.path.basename(d),
                        re.IGNORECASE,
                    ))
                    and match.group(1) not in completed_timestamps
                )
            ]
            subs.sort(reverse=True)
        if subs:
            latest_on_disk = subs[0]

    # latest_yaml 当前最终指向；保留 template/99-output* 逻辑父路径。
    if os.path.islink(link_path):
        latest_link = _resolve_logical_link(link_path)
    else:
        latest_link = None

    # 若 latest_on_disk 不存在，直接用 latest_yaml
    if latest_on_disk is None:
        if latest_link and os.path.isdir(latest_link):
            print(f"未指定目录，使用 latest_yaml：{latest_link}")
            return latest_link
        print("[ERROR] 未找到可用的输出目录，请手动指定")
        sys.exit(1)

    # 比较两者（规范化路径后比较）
    norm_disk = os.path.normpath(latest_on_disk)
    norm_link = os.path.normpath(latest_link) if latest_link else None

    if norm_link and os.path.realpath(norm_disk) == os.path.realpath(norm_link):
        print(f"未指定目录，latest_yaml 已是最新：{os.path.relpath(norm_disk, cwd)}")
        return latest_link

    # 不一致 → 提示用户选择
    print(f"\nlatest_yaml 指向的目录与 template/{output_name}/ 下最新目录不一致：")
    opts = []
    if latest_link and os.path.isdir(latest_link):
        opts.append(("latest_yaml", latest_link,    f"[1] latest_yaml 指向：{os.path.relpath(latest_link, cwd)}"))
    opts.append(("latest_disk", norm_disk,
                 f"[2] template/{output_name}/ 最新：{os.path.relpath(norm_disk, cwd)}"))
    for _, _, label in opts:
        print(f"  {label}")

    if _AUTO_YES or len(opts) == 1:
        chosen = opts[-1][1]
        print(f"自动选择：{os.path.relpath(chosen, cwd)}")
        return chosen

    print(f"请选择（{_CONFIRM_TIMEOUT} 秒内无输入自动选最新目录）：", end=" ", flush=True)
    ready, _, _ = select.select([sys.stdin], [], [], _CONFIRM_TIMEOUT)
    if ready:
        ans = sys.stdin.readline().strip()
    else:
        ans = ""
        print()

    if ans == "1" and len(opts) == 2:
        return opts[0][1]
    chosen = opts[-1][1]
    print(f"使用：{os.path.relpath(chosen, cwd)}")
    return chosen


# ── 主流程 ────────────────────────────────────────────────────────────────────

def main():
    global _AUTO_YES
    args = sys.argv[1:]
    if "-y" in args:
        _AUTO_YES = True
        args = [a for a in args if a != "-y"]

    # --csv=<path> 或 --csv <path>
    explicit_csv = None
    new_args = []
    i = 0
    while i < len(args):
        if args[i].startswith("--csv="):
            explicit_csv = args[i].split("=", 1)[1]
        elif args[i] == "--csv" and i + 1 < len(args):
            explicit_csv = args[i + 1]
            i += 1
        else:
            new_args.append(args[i])
        i += 1
    args = new_args

    if "-h" in args or "--help" in args:
        print("""usage: d-hostname2mac.py [-y] [--csv PATH] YAML_DIR [YAML_DIR]

一个 Cumulus 目录：自动补齐同时间戳 Production 与 _air 两个目录后发布。
          两套 YAML 除 set.system.hostname 外必须完全一致，各自 MAC 链接只指向
          本环境 hostname 对应的 YAML；缺少任一套时拒绝更新 latest_yaml。
两个目录：仅用于同时间戳 -ib 与 -nvl；复制配置到 combine 目录，创建 MAC 链接
          并原子更新项目 latest；latest_yaml 保持固定 HTTP 入口。
Cumulus 发布成功后归档并删除生成源目录。""")
        return

    if args:
        yaml_dirs = [arg.rstrip("/") for arg in args]
    else:
        yaml_dirs = [_resolve_yaml_dir()]
    if len(yaml_dirs) > 2:
        print("[ERROR] 最多接受两个 YAML 输入目录")
        sys.exit(2)
    for yaml_dir in yaml_dirs:
        if not os.path.isdir(yaml_dir):
            print(f"[ERROR] 目录不存在：{yaml_dir}")
            sys.exit(1)

    csv_file = find_csv(explicit_csv, yaml_dir=yaml_dirs[0])

    if not os.path.isfile(csv_file):
        print(f"[ERROR] CSV 文件不存在：{csv_file}")
        sys.exit(1)

    print(f"\n正在读取 CSV：{csv_file}")
    try:
        devices = load_csv(csv_file)
    except (OSError, ValueError) as exc:
        print(f"[ERROR] 设备 CSV 无法安全读取：{exc}")
        sys.exit(1)
    eth_n = sum(1 for d in devices.values() if d["dev_type"] in ("eth", "eth_spx", "spx"))
    air_n = sum(1 for d in devices.values() if d["dev_type"] == "air")
    ib_n  = sum(1 for d in devices.values() if d["dev_type"] == "ib")
    nvl_n = sum(1 for d in devices.values() if d["dev_type"] == "nvl")
    print(
        f"已加载 {len(devices)} 条设备记录（eth/eth_spx/spx: {eth_n}，air: {air_n}，"
        f"ib: {ib_n}，nvl: {nvl_n}）\n"
    )

    nvos_contexts = [_nvos_dir_context(path) for path in yaml_dirs]
    cumulus_contexts = [_cumulus_dir_context(path) for path in yaml_dirs]
    if any(ctx is not None for ctx in cumulus_contexts):
        cumulus_contexts = _preferred_cumulus_contexts(cumulus_contexts)
        yaml_dirs = [ctx["path"] for ctx in cumulus_contexts]
    if len(yaml_dirs) == 2:
        if all(ctx is not None for ctx in nvos_contexts):
            published = _publish_combined_nvos(nvos_contexts, devices)
        elif all(ctx is not None for ctx in cumulus_contexts):
            published = _publish_combined_cumulus(cumulus_contexts, devices)
        else:
            print("[ERROR] 双目录模式只接受同时间戳的 Cumulus+AIR 或 IB+NVL 目录")
            sys.exit(1)
        if not published:
            sys.exit(1)
        return

    yaml_dir = yaml_dirs[0]
    if nvos_contexts[0] is not None:
        if not _publish_single_nvos(nvos_contexts[0], devices):
            sys.exit(1)
        return

    try:
        _refresh_cumulus_defaults()
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"[ERROR] Cumulus 默认配置同步失败：{exc}")
        sys.exit(1)

    if cumulus_contexts[0] is not None:
        print("[ERROR] Cumulus 发布需要同时间戳的 Production 和 _air 两个目录")
        if len(cumulus_contexts) == 1:
            print("        请重新运行配置生成器创建 hostname-only AIR YAML")
            sys.exit(1)
        return

    print(f"处理目录：{yaml_dir}\n")
    publish = _cumulus_publish_context(yaml_dir)
    publish_types = publish["types"]
    ok, counters, hosts = _process_yaml_files(yaml_dir, devices, publish_types)
    missing = (
        _missing_expected_hosts(devices, publish_types, hosts)
        if publish["report_missing"] else []
    )
    if missing and publish["missing_is_error"]:
        ok = False
    _print_process_summary(counters)
    if not ok:
        print("[ERROR] Cumulus 发布目录校验失败，latest_yaml 保持不变")
        if missing:
            print(
                f"[ERROR] CSV 中存在、但 YAML 目录缺少以下 "
                f"{len(missing)} 台 {publish['label']} 设备配置："
            )
            for hostname in missing:
                print(f"  {hostname}.yaml")
        sys.exit(1)
    marker = os.path.join(yaml_dir, ".published-complete")
    with open(marker, "w", encoding="utf-8") as stream:
        stream.write(f"{os.path.basename(yaml_dir)} cumulus\n")
    published = _update_latest_yaml(yaml_dir)
    if published:
        try:
            _remove_superseded_cumulus_base([_cumulus_dir_context(yaml_dir)])
        except (OSError, ValueError) as exc:
            print(f"[ERROR] patch 已发布，但原配置目录清理失败：{exc}")
            published = False
    if missing:
        print(
            f"[WARN] CSV 中存在、但 YAML 目录缺少以下 "
            f"{len(missing)} 台 {publish['label']} 设备配置："
        )
        for hostname in missing:
            print(f"  {hostname}.yaml")
        print("[INFO] 这些设备没有专属 MAC 配置，ZTP 将使用默认配置")
    if not published:
        sys.exit(1)


if __name__ == "__main__":
    main()
