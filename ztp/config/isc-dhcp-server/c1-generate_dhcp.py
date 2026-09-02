#!/usr/bin/env python3
"""
读取当前目录下的 CSV 文件，生成 dhcpd.conf、dhcpd_eth.hosts、
dhcpd_ib.hosts 和 dhcpd_nvl.hosts。

用法：
  python3 c1-generate_dhcp.py [-y]

输入文件：
  01-global.yaml          — 提供 common.mgmt.ztp.ztp_url_prefix
  02-subnet_config.csv   — shared-network / subnet 配置
  02-devices_config.csv      — 统一设备清单；非 AIR 行人工维护，末尾 AIR 行由本脚本维护
  p2p-air.json           — 可选；提供 AIR Cumulus 节点名称和 eth0 MAC；管理字段继承同名 production 设备
"""

import csv
import glob
import hashlib
import ipaddress
import json
import os
import re
import select
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime

try:
    import yaml
except ModuleNotFoundError:
    yaml = None

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR    = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "..", "..", "tools"))
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)
from project_contract import validate_ztp_url_prefix
OUTPUT_ETH   = os.path.join(SCRIPT_DIR, "dhcpd_eth.hosts")
OUTPUT_IB    = os.path.join(SCRIPT_DIR, "dhcpd_ib.hosts")
OUTPUT_NVL   = os.path.join(SCRIPT_DIR, "dhcpd_nvl.hosts")
OUTPUT_CONF  = os.path.join(SCRIPT_DIR, "dhcpd.conf")
OUTPUT_MANIFEST = os.path.join(
    os.path.dirname(os.path.realpath(OUTPUT_CONF)), "dhcp-release-manifest.json"
)
SUBNET_CSV   = os.path.join(SCRIPT_DIR, "02-subnet_config.csv")
GLOBAL_YAML  = os.path.join(SCRIPT_DIR, "01-global.yaml")
P2P_AIR_JSON = os.path.join(SCRIPT_DIR, "p2p-air.json")
DEVICES_CSV  = os.path.join(SCRIPT_DIR, "02-devices_config.csv")

_AUTO_YES = False
_CONFIRM_TIMEOUT = 15

_LEGACY_SUBNET_COLUMNS = {"bootfile_name", "cumulus_provision_url"}
_CUMULUS_BOOTSTRAP_BY_PROFILE = {
    "oob": "ztp-bootstrap_oob.sh",
    "oobofoob": "ztp-bootstrap_oobofoob.sh",
}

# ── 交互 ──────────────────────────────────────────────────────────────────────

def _confirm(prompt, default="y"):
    """default='y' 超时自动确认，default='n' 超时自动拒绝。"""
    if _AUTO_YES:
        print(prompt + f" {default}（-y 模式自动确认）")
        return default == "y"
    print(prompt + f"（{_CONFIRM_TIMEOUT} 秒后自动 {default}）", end=" ", flush=True)
    ready, _, _ = select.select([sys.stdin], [], [], _CONFIRM_TIMEOUT)
    if ready:
        ans = sys.stdin.readline().strip().lower()
        if default == "y":
            return ans not in ("n", "no")
        else:
            return ans in ("y", "yes")
    print(default)
    return default == "y"

# ── 验证工具 ──────────────────────────────────────────────────────────────────

_IP_RE  = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_MAC_RE = re.compile(r"^[0-9a-f]{12}$")
_SAFE_DHCP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
_EXPECTED_DEVICE_HEADER_PREFIX = (
    "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw",
    "eth0_mac", "eth1_ip", "netmask", "eth1_gw", "eth1_mac",
)

def valid_ip(s):
    m = _IP_RE.match(s.strip())
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())

def normalize_mac(s):
    raw = re.sub(r"[:\-\s]", "", s).lower()
    if not _MAC_RE.match(raw):
        return None
    return ":".join(raw[i:i+2] for i in range(0, 12, 2))


def _validate_ztp_url_prefix(value):
    """Return one canonical, safe URL path prefix or raise ValueError."""
    return validate_ztp_url_prefix(value)


def load_ztp_url_prefix(path):
    """Read the single URL path policy used to derive every DHCP ZTP URL."""
    if yaml is None:
        raise ValueError("缺少 PyYAML，无法读取 01-global.yaml")
    if not os.path.isfile(path):
        raise ValueError(f"找不到 {os.path.basename(path)}")
    try:
        with open(path, encoding="utf-8") as stream:
            data = yaml.safe_load(stream)
        value = data["common"]["mgmt"]["ztp"]["ztp_url_prefix"]
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"01-global.yaml 无法读取：{exc}") from exc
    except (KeyError, TypeError) as exc:
        raise ValueError(
            "01-global.yaml 缺少 common.mgmt.ztp.ztp_url_prefix"
        ) from exc
    return _validate_ztp_url_prefix(value)


def _ztp_url(service_ip, prefix, filename):
    """Build a fixed HTTP URL; callers supply only validated declarative data."""
    return f"http://{service_ip}{prefix}/{filename}"

# ── 读取 CSV ──────────────────────────────────────────────────────────────────

def _fallback_fmt(hostname):
    """无 type 列时的兜底判断：主机名以 ib 开头 → ib，否则 → eth。"""
    return "ib" if hostname.strip().lower().startswith("ib") else "eth"

def load_csv(path):
    """
    统一读取 devices_config CSV，每行按 type 列判断 eth/eth_spx/spx/air/ib/nvl；server 供 infra 使用并跳过。
    无 type 列时用表头兜底（lo_ip 存在 → eth，否则 ib）。
    列结构：hostname=0, type=1, template=2, eth0_ip=3, eth0_mac=6, eth1_ip=7, eth1_mac=10
    """
    records = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, [])
        h_lower  = [c.strip().lower() for c in header]
        if tuple(h_lower[:len(_EXPECTED_DEVICE_HEADER_PREFIX)]) != _EXPECTED_DEVICE_HEADER_PREFIX:
            raise ValueError(
                "devices_config.csv 前 11 列顺序必须为："
                + ",".join(_EXPECTED_DEVICE_HEADER_PREFIX)
            )
        type_col = h_lower.index("type") if "type" in h_lower else None

        for lineno, raw in enumerate(reader, start=2):
            row = [c.strip() for c in raw]
            if not any(row):
                continue
            if len(row) < 11:
                raise ValueError(
                    f"{os.path.basename(path)} 第 {lineno} 行列数不足（{len(row)} < 11）"
                )

            if type_col is not None and len(row) > type_col:
                fmt = row[type_col].strip().lower()
                if fmt == "server":
                    continue
                if fmt not in ("eth", "eth_spx", "spx", "ib", "nvl", "air"):
                    raise ValueError(
                        f"{os.path.basename(path)} 第 {lineno} 行 type={fmt!r} 无效"
                    )
            else:
                fmt = _fallback_fmt(row[0])

            records.append({
                "src":      f"{os.path.basename(path)}:{lineno}",
                "hostname": row[0],
                "ip":       row[3],
                "mac":      row[6],
                "type":     fmt,
                "iface":    "eth0",
                "netmask":  row[4],
            })
            if row[10] and row[10].upper() != "NA":
                records.append({
                    "src":      f"{os.path.basename(path)}:{lineno}",
                    "hostname": row[0],
                    "ip":       row[7],
                    "mac":      row[10],
                    "type":     fmt,
                    "iface":    "eth1",
                    "netmask":  row[8],
                })
    return records


def load_p2p_air_json(path):
    """读取 AIR JSON 中需要 ZTP 配置的网络节点 eth0 IP/MAC。

    AIR 导出文件的节点通常位于 ``content.nodes``；同时兼容直接位于
    顶层 ``nodes`` 的结构。``os`` 以 ``cumulus`` 开头或等于
    ``oob-mgmt-switch`` 即视为网络设备；``oob-mgmt-server`` 等 server
    节点跳过。
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"无法读取 {os.path.basename(path)}：{exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"{os.path.basename(path)} 顶层必须是 JSON object")
    container = data.get("content", data)
    if not isinstance(container, dict) or not isinstance(container.get("nodes"), dict):
        raise ValueError(f"{os.path.basename(path)} 缺少 object 类型的 content.nodes")

    air_networks = []
    oob = container.get("oob") if isinstance(container.get("oob"), dict) else {}
    oob_subnets = oob.get("subnets") if isinstance(oob.get("subnets"), dict) else {}
    for subnet in oob_subnets:
        try:
            air_networks.append(ipaddress.ip_network(str(subnet), strict=False))
        except ValueError as exc:
            raise ValueError(f"AIR JSON OOB subnet 无效：{subnet!r}") from exc

    records = []
    for hostname, node in container["nodes"].items():
        if not isinstance(node, dict):
            continue
        os_name = str(node.get("os") or "").strip().casefold()
        if not (
            os_name.startswith("cumulus") or os_name == "oob-mgmt-switch"
        ):
            continue
        interfaces = node.get("management_interfaces")
        eth0 = interfaces.get("eth0", {}) if isinstance(interfaces, dict) else {}
        if not isinstance(eth0, dict):
            eth0 = {}
        ip_value = str(eth0.get("ip") or "").strip()
        matching_networks = []
        if ip_value:
            try:
                address = ipaddress.ip_address(ip_value)
            except ValueError:
                address = None
            if address is not None:
                matching_networks = [network for network in air_networks if address in network]
        records.append({
            "src":      f"{os.path.basename(path)}:content.nodes.{hostname}",
            "hostname": str(hostname).strip(),
            "ip":       ip_value,
            "mac":      str(eth0.get("mac_address") or eth0.get("mac") or "").strip(),
            "type":     "eth",
            "iface":    "eth0",
            # AIR's own OOB subnet is authoritative for its management
            # addresses and need not also appear in the production DHCP CSV.
            "netmask":  str(max(network.prefixlen for network in matching_networks))
                        if matching_networks else "",
        })
    return records


def merge_air_records(existing_records, air_records):
    """合并 AIR 记录；完全相同的 hostname/eth0 记录只保留一份。

    如果同名接口的 IP 或 MAC 不同，则保留 AIR 记录交由统一验证逻辑报告
    冲突，避免悄悄使用错误数据。
    """
    merged = list(existing_records)
    existing = {
        (r["hostname"].strip().casefold(), r["iface"].strip().casefold()): r
        for r in existing_records
    }
    skipped = []
    for rec in air_records:
        key = (rec["hostname"].strip().casefold(), rec["iface"].strip().casefold())
        previous = existing.get(key)
        if previous is not None:
            same_ip = previous["ip"].strip() == rec["ip"].strip()
            same_mac = normalize_mac(previous["mac"] or "") == normalize_mac(rec["mac"] or "")
            if same_ip and same_mac:
                skipped.append(rec)
                continue
        merged.append(rec)
        existing.setdefault(key, rec)
    return merged, skipped


def inherit_air_records_from_production(path, air_records, *, skip_missing=False):
    """Fill AIR management fields from the corresponding production CSV row.

    ``AIR-<hostname>`` first matches production ``<hostname>`` exactly.  A
    unique suffix match is accepted for site-prefixed AIR names.  AIR rows are
    never used as their own production source.
    """
    target = os.path.realpath(path)
    with open(target, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.reader(f))
    if not rows:
        raise ValueError(f"{os.path.basename(path)} 是空文件")

    header = [column.strip().lower() for column in rows[0]]
    required = ("hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw")
    missing = [column for column in required if column not in header]
    if missing:
        raise ValueError(f"{os.path.basename(path)} 缺少列：{missing}")
    indexes = {column: header.index(column) for column in required}

    production = []
    for row in rows[1:]:
        if len(row) < len(header):
            row = row + [""] * (len(header) - len(row))
        hostname = row[indexes["hostname"]].strip()
        row_type = row[indexes["type"]].strip().casefold()
        # Only Cumulus Production rows can be cloned into AIR Cumulus
        # reservations/configs.  A coincidentally named server/IB/NVL row must
        # never make a dynamic AIR node look statically provisionable.
        if hostname and row_type in {"eth", "eth_spx", "spx"}:
            production.append((hostname, row))

    resolved = []
    for rec in air_records:
        air_hostname = rec["hostname"].strip()
        base = re.sub(r"^air-", "", air_hostname, flags=re.IGNORECASE)
        # AIR-host is a legacy topology placeholder, never a production device.
        # Do not let a coincidental CSV row named "host" turn it into a static
        # reservation.
        placeholder = air_hostname.casefold() == "air-host"
        exact = [] if placeholder else [
            item for item in production if item[0].casefold() == base.casefold()
        ]
        candidates = exact
        if not candidates and not placeholder:
            candidates = [
                item for item in production
                if base.casefold().endswith(item[0].casefold())
                or item[0].casefold().endswith(base.casefold())
            ]
        if not candidates:
            if skip_missing:
                rec["production_missing"] = True
                print(
                    f"  [INFO] {air_hostname} 没有同名 Production 设备；"
                    "不写入静态 CSV、不生成 fixed-address，将作为动态 known host "
                    "从 range 获取地址；后续生成阶段会依据 AIR JSON 的 MAC "
                    "发布 hostname baseline 与专属 MAC 链接"
                )
                continue
            raise ValueError(f"AIR 设备 {air_hostname} 找不到同名 production 设备")
        if len(candidates) > 1:
            names = ", ".join(sorted(item[0] for item in candidates))
            raise ValueError(f"AIR 设备 {air_hostname} 匹配到多个 production 设备：{names}")

        production_hostname, row = candidates[0]
        values = {
            column: row[indexes[column]].strip()
            for column in ("template", "eth0_ip", "netmask", "eth0_gw")
        }
        rec["production_hostname"] = production_hostname
        rec["production_values"] = values
        rec["type"] = "air"
        rec["ip"] = values["eth0_ip"]
        rec["netmask"] = values["netmask"]
        resolved.append(rec)
    return resolved


def exclude_air_records(existing_records, hostnames):
    """Remove selected type=air rows from the in-memory DHCP record set."""
    unresolved = {
        str(hostname).strip().casefold() for hostname in hostnames
        if str(hostname).strip()
    }
    if not unresolved:
        return list(existing_records), 0
    filtered = []
    removed = 0
    for rec in existing_records:
        key = rec["hostname"].strip().casefold()
        if rec.get("type", "").strip().casefold() == "air" and key in unresolved:
            removed += 1
            continue
        filtered.append(rec)
    return filtered, removed


def _production_air_pair(left, right):
    """True when two records are AIR/prod variants of the same hostname."""
    left_air = left.get("type", "").strip().casefold() == "air"
    right_air = right.get("type", "").strip().casefold() == "air"
    if left_air == right_air:
        return False

    air_record, production_record = (left, right) if left_air else (right, left)
    # inherit_air_records_from_production() has already resolved exact and
    # site-prefixed AIR names to one unambiguous Production row. Reuse that
    # identity here; repeating a simple AIR- prefix strip rejects valid names
    # such as AIR-SITE01-Staging-Border01 -> Staging-Border01.
    production_name = str(air_record.get("production_hostname") or "").strip()
    if not production_name:
        production_name = re.sub(
            r"^air-", "", air_record["hostname"].strip(), flags=re.IGNORECASE
        )
    return production_name.casefold() == production_record["hostname"].strip().casefold()


def _prefix_length_for_ip(ip, subnets, fallback_prefix=""):
    """按 subnet 配置查找 IP，并返回 0–32 的 IPv4 前缀长度字符串。"""
    try:
        address = ipaddress.ip_address(ip.strip())
    except ValueError as exc:
        raise ValueError(f"AIR IP 格式无效：{ip!r}") from exc

    matches = []
    for subnet in subnets:
        try:
            network = ipaddress.ip_network(
                f"{subnet['subnet']}/{subnet['netmask']}", strict=False
            )
        except (KeyError, ValueError) as exc:
            raise ValueError(f"subnet 配置无效：{subnet}") from exc
        if address in network:
            matches.append(network)
    if not matches:
        if str(fallback_prefix).strip():
            try:
                prefix = int(str(fallback_prefix).strip())
            except ValueError as exc:
                raise ValueError(f"AIR netmask 无效：{fallback_prefix!r}") from exc
            if 0 <= prefix <= 32:
                return str(prefix)
            raise ValueError(f"AIR netmask 必须是 0-32：{fallback_prefix!r}")
        raise ValueError(f"AIR IP {ip} 未匹配到 02-subnet_config.csv 中的 subnet")
    # 存在嵌套 subnet 时使用最具体的网络；同等精度仍必须唯一。
    return str(max(network.prefixlen for network in matches))


def append_air_records_to_csv(path, air_records, subnets, production_path=None):
    """Atomically replace all type=air rows and append the new set at EOF."""
    target = os.path.realpath(path)
    production = os.path.realpath(production_path or target)
    if not os.path.isfile(production):
        raise ValueError(f"找不到 production CSV：{production}")
    with open(target, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.reader(f))
    if not rows:
        raise ValueError(f"{os.path.basename(path)} 是空文件")

    header = [column.strip().lower() for column in rows[0]]
    required = (
        "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw",
        "eth0_mac",
    )
    missing = [column for column in required if column not in header]
    if missing:
        raise ValueError(f"{os.path.basename(path)} 缺少列：{missing}")
    indexes = {column: header.index(column) for column in required}
    column_count = len(rows[0])

    inherit_air_records_from_production(production, air_records)

    previous_air = {}
    non_air_rows = []
    for original in rows[1:]:
        row = original + [""] * max(0, column_count - len(original))
        row = row[:column_count]
        hostname = row[indexes["hostname"]].strip()
        row_type = row[indexes["type"]].strip().casefold()
        if row_type == "air":
            if hostname:
                previous_air[hostname.casefold()] = row
            continue
        non_air_rows.append(original)

    generated_rows = []
    added = updated = already_exists = 0
    for rec in air_records:
        hostname = rec["hostname"].strip()
        key = hostname.casefold()
        production_values = rec["production_values"]
        row = [""] * column_count
        row[indexes["hostname"]] = hostname
        row[indexes["type"]] = "air"
        for column in ("template", "eth0_ip", "netmask", "eth0_gw"):
            row[indexes[column]] = production_values[column]
        row[indexes["eth0_mac"]] = rec.get("mac_norm") or normalize_mac(rec["mac"]) or rec["mac"].strip()
        generated_rows.append(row)
        previous = previous_air.get(key)
        if previous is None:
            added += 1
        elif previous == row:
            already_exists += 1
        else:
            updated += 1

    new_rows = [rows[0], *non_air_rows, *generated_rows]
    if new_rows == rows:
        return added, updated, already_exists

    target_dir = os.path.dirname(target)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{os.path.basename(target)}.", suffix=".tmp", dir=target_dir
    )
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows(new_rows)
        if os.path.isfile(target):
            shutil.copymode(target, temporary)
        else:
            os.chmod(temporary, 0o644)
        os.replace(temporary, target)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise
    return added, updated, already_exists

# ── 验证 ──────────────────────────────────────────────────────────────────────

def validate(all_records):
    errors        = []
    seen_hn_iface = {}
    seen_ips      = {}
    seen_macs     = {}
    valid         = []

    for rec in all_records:
        src, hostname, ip, mac_raw = rec["src"], rec["hostname"], rec["ip"], rec["mac"]
        iface = rec["iface"]

        if not hostname:
            errors.append(f"  {src}：hostname 为空")
            continue
        if not _SAFE_DHCP_NAME_RE.fullmatch(hostname):
            errors.append(
                f"  {src}：hostname 含不安全字符，不能写入 DHCP 配置：{hostname!r}"
            )
            continue
        hn_key = f"{hostname.lower()}|{iface}"
        if hn_key in seen_hn_iface:
            errors.append(f"  {src} [{hostname}/{iface}]：与 {seen_hn_iface[hn_key]} 重复")
            continue
        seen_hn_iface[hn_key] = src
        dynamic = bool(rec.get("dynamic"))
        ip_missing = not ip or ip.upper() == "NA"
        mac_missing = not mac_raw or mac_raw.upper() == "NA"
        if not ip_missing and not valid_ip(ip):
            errors.append(f"  {src} [{hostname}]：IP 格式无效 '{ip}'")
            continue
        if not dynamic and not ip_missing:
            ip_key = ip.strip()
            if ip_key in seen_ips:
                previous = seen_ips[ip_key]
                if not _production_air_pair(previous, rec):
                    errors.append(
                        f"  {src} [{hostname}]：IP {ip_key} 与 {previous['src']} 重复"
                    )
                    continue
            else:
                seen_ips[ip_key] = rec

        # MAC 未知是受支持的 staged-onboarding 状态，而不是输入错误。
        # 该记录保留在发布清单中，但绝不能写入 ISC DHCP host declaration，
        # 也不能由脚本按行序或 IP 猜测它对应哪个匿名客户端。
        if mac_missing:
            rec["mac_norm"] = ""
            rec["identity_pending"] = True
            rec["pending_reason"] = "mac_missing"
            valid.append(rec)
            continue

        mac = normalize_mac(mac_raw)
        if mac is None:
            errors.append(f"  {src} [{hostname}]：MAC 格式无效 '{mac_raw}'")
            continue

        if mac in seen_macs:
            errors.append(f"  {src} [{hostname}]：MAC {mac} 与 {seen_macs[mac]} 重复")
            continue
        seen_macs[mac] = src

        rec["mac_norm"] = mac
        valid.append(rec)

    return valid, errors


def validate_records_against_subnets(records, subnets):
    """Require in-scope static reservations to match a declared DHCP network.

    Merely checking that an address is contained by a broad subnet is unsafe:
    a /26 device can appear to belong to a mistakenly declared /25 pool while
    using a different broadcast address and gateway.  Compare the complete
    interface network instead.
    """
    declared = [item["_network"] for item in subnets]
    errors = []
    for rec in records:
        if rec.get("dynamic"):
            continue
        ip_text = str(rec.get("ip") or "").strip()
        mask_text = str(rec.get("netmask") or "").strip()
        context = f"{rec['src']} [{rec['hostname']}/{rec['iface']}]"
        if not ip_text or ip_text.upper() == "NA":
            continue
        try:
            address = ipaddress.ip_address(ip_text)
        except ValueError:
            # validate() reports this with the original CSV context.
            continue
        containing = [network for network in declared if address in network]
        # An address outside every subnet served by this dhcpd is a planned
        # *final* management address.  It deliberately receives a transit
        # dynamic lease here, so its final netmask is not a DHCP reservation
        # gate in this generator.
        if not containing:
            continue
        if not mask_text or mask_text.upper() == "NA":
            errors.append(f"  {context}：缺少 netmask，无法确认 DHCP subnet")
            continue
        try:
            planned = ipaddress.ip_interface(f"{ip_text}/{mask_text}").network
        except ValueError as exc:
            errors.append(f"  {context}：IP/netmask 无效 {ip_text}/{mask_text} ({exc})")
            continue
        if planned not in containing:
            errors.append(
                f"  {context}：设备网络 {planned} 与已声明的 "
                f"{', '.join(str(item) for item in containing)} 掩码不一致"
            )
    return errors


def plan_dhcp_assignments(records, subnets):
    """Select fixed, transit-dynamic, or pending behavior for each interface.

    The only reliable way to decide whether ``fixed-address`` is usable by this
    DHCP server is membership of the planned IP in one of the non-overlapping
    networks from ``02-subnet_config.csv``.  A known MAC whose final address is
    outside every served network remains a *known host* but deliberately has no
    ``fixed-address``; the active relay/interface chooses a transit range.  The
    device's YAML later moves it to its final management address.
    """
    errors = []
    for rec in records:
        rec.pop("served_subnet", None)
        ip_text = str(rec.get("ip") or "").strip()
        address = None
        if ip_text and ip_text.upper() != "NA" and valid_ip(ip_text):
            address = ipaddress.ip_address(ip_text)
        matches = [item for item in subnets
                   if address is not None and address in item["_network"]]
        if len(matches) > 1:
            # load_subnet_csv() normally rejects this first; keep this function
            # safe when called directly by tests or future tooling.
            errors.append(
                f"  {rec['src']} [{rec['hostname']}/{rec['iface']}]："
                f"计划 IP {ip_text} 同时匹配多个 DHCP subnet"
            )
            continue
        if matches:
            subnet = matches[0]
            rec["served_subnet"] = str(subnet["_network"])
            if not rec.get("dynamic"):
                start = ipaddress.ip_address(subnet["range_start"])
                end = ipaddress.ip_address(subnet["range_end"])
                if start <= address <= end:
                    errors.append(
                        f"  {rec['src']} [{rec['hostname']}/{rec['iface']}]："
                        f"计划静态 IP {ip_text} 落入 {subnet['_network']} 的动态 range "
                        f"{start}-{end}"
                    )
                    continue

        if rec.get("identity_pending"):
            rec["dhcp_assignment"] = "identity_pending"
        elif rec.get("dynamic"):
            rec["dhcp_assignment"] = "dynamic_known"
        elif not matches:
            rec["dhcp_assignment"] = "transit_dynamic"
            rec["transit_reason"] = (
                "planned_ip_missing" if address is None
                else "planned_ip_outside_served_subnets"
            )
        else:
            rec["dhcp_assignment"] = "fixed"
    return errors

# ── 生成输出文件 ──────────────────────────────────────────────────────────────

def write_hosts(path, records):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    declarations = [r for r in records if not r.get("identity_pending")]
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"##### Generated at {now}\n\n")
        for r in declarations:
            dhcp_label = (f"{r['hostname']}-{r['iface']}"
                          if r["type"] in ("ib", "nvl") else r["hostname"])
            f.write(f"host {dhcp_label} {{\n")
            f.write(f"        hardware ethernet {r['mac_norm']};\n")
            if r.get("dhcp_assignment") == "fixed":
                f.write(f"        fixed-address {r['ip'].strip()};\n")
            f.write(f"        option host-name \"{r['hostname']}\";\n")
            f.write("}\n\n")
        f.write(f"##### {len(declarations)} entries\n")
    pending = len(records) - len(declarations)
    suffix = f"，identity_pending {pending} 条未声明" if pending else ""
    print(f"[OK] {os.path.basename(path)}：{len(declarations)} 条记录{suffix}")


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_release_manifest(path, records, subnets, output_paths):
    """Atomically publish machine-readable planned identity/DHCP metadata."""
    devices = []
    for rec in sorted(
            records,
            key=lambda item: (
                item["hostname"].casefold(), item["iface"].casefold(),
                item.get("type", ""),
            )):
        device_type = rec.get("type", "").casefold()
        devices.append({
            "hostname": rec["hostname"],
            "type": device_type,
            "platform": "nvos" if device_type in {"ib", "nvl"} else "cumulus",
            "interface": rec["iface"],
            "mac": rec.get("mac_norm") or None,
            "planned_ip": (rec.get("ip") or "").strip() or None,
            "planned_netmask": (rec.get("netmask") or "").strip() or None,
            "identity_state": (
                "identity_pending" if rec.get("identity_pending") else "identified"
            ),
            "pending_reason": rec.get("pending_reason"),
            "dhcp_assignment": rec.get("dhcp_assignment"),
            "host_declared": not rec.get("identity_pending"),
            "fixed_address": (
                (rec.get("ip") or "").strip()
                if rec.get("dhcp_assignment") == "fixed" else None
            ),
            "served_subnet": rec.get("served_subnet"),
            "transit_reason": rec.get("transit_reason"),
            "source": rec.get("src"),
        })
    subnet_items = [{
        "shared_network": item["shared_network"],
        "network": str(item["_network"]),
        "range_start": item["range_start"],
        "range_end": item["range_end"],
        "routers": item["routers"],
        "ztp_service_ip": item.get("ztp_service_ip") or None,
        "cumulus_profile": item.get("cumulus_profile"),
        "nvos_ztp": item.get("nvos_ztp"),
        "cumulus_provision_url": item.get("cumulus_provision_url") or None,
        "nvos_bootfile_name": item.get("bootfile_name") or None,
        "cumulus_ztp_enabled": bool(item.get("cumulus_provision_url")),
        "nvos_ztp_enabled": bool(item.get("bootfile_name")),
    } for item in subnets]
    release_basis = {
        "schema_version": 1,
        "subnets": subnet_items,
        "devices": devices,
        "platform_routing": {
            "cumulus": "option60-prefix:cumulus/Cumulus -> option239",
            "nvos": "option61-prefix:NVOS##, option77-fallback:NVOS-ZTP -> option67",
            "unknown": "lease-only-no-ztp",
        },
    }
    canonical = json.dumps(
        release_basis, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    counts = {
        "inventory_interfaces": len(devices),
        "host_declarations": sum(item["host_declared"] for item in devices),
        "identity_pending": sum(
            item["identity_state"] == "identity_pending" for item in devices
        ),
        "fixed": sum(item["dhcp_assignment"] == "fixed" for item in devices),
        "transit_dynamic": sum(
            item["dhcp_assignment"] == "transit_dynamic" for item in devices
        ),
        "dynamic_known": sum(
            item["dhcp_assignment"] == "dynamic_known" for item in devices
        ),
    }
    manifest = {
        **release_basis,
        "release_id": hashlib.sha256(canonical).hexdigest()[:20],
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "counts": counts,
        "outputs": {
            os.path.basename(item): {"sha256": _sha256_file(item)}
            for item in output_paths
        },
    }
    directory = os.path.dirname(os.path.realpath(path))
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{os.path.basename(path)}.", suffix=".tmp", dir=directory
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(manifest, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
        os.chmod(temporary, 0o644)
        os.replace(temporary, os.path.realpath(path))
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise
    print(
        f"[OK] {os.path.basename(path)}：release_id={manifest['release_id']}，"
        f"identity_pending={counts['identity_pending']}"
    )
    return manifest

# ── Subnet 配置 ───────────────────────────────────────────────────────────────

def load_subnet_csv(path, ztp_prefix):
    """Read declarative subnet rows and derive the two platform ZTP URLs."""
    ztp_prefix = _validate_ztp_url_prefix(ztp_prefix)
    required = (
        "shared_network", "subnet", "netmask", "range_start", "range_end",
        "routers", "ztp_service_ip", "cumulus_profile", "nvos_ztp",
    )
    required_values = ("shared_network", "subnet", "netmask", "range_start",
                       "range_end", "routers")
    subnets = []
    errors  = []
    seen_networks = {}
    profile_services = {}
    nvos_service = None
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        reader.fieldnames = [c.strip().lower().replace(" ", "_") for c in (reader.fieldnames or [])]
        duplicate_cols = sorted({c for c in reader.fieldnames if reader.fieldnames.count(c) > 1})
        legacy_cols = sorted(_LEGACY_SUBNET_COLUMNS & set(reader.fieldnames))
        if duplicate_cols:
            print(f"[ERROR] {os.path.basename(path)} 列名重复：{duplicate_cols}")
            sys.exit(1)
        if legacy_cols:
            print(
                f"[ERROR] {os.path.basename(path)} 仍包含已废弃 URL 列：{legacy_cols}；"
                "请改用 ztp_service_ip,cumulus_profile,nvos_ztp"
            )
            sys.exit(1)
        missing_cols = [c for c in required if c not in reader.fieldnames]
        if missing_cols:
            print(f"[ERROR] {os.path.basename(path)} 缺少列：{missing_cols}")
            sys.exit(1)
        for lineno, row in enumerate(reader, start=2):
            row = {k: (v or "").strip() for k, v in row.items()}
            if not any(row.values()):
                continue
            for col in required_values:
                if not row.get(col):
                    errors.append(f"  第 {lineno} 行 {col} 为空")
            profile = row.get("cumulus_profile", "").casefold()
            nvos_ztp = row.get("nvos_ztp", "").casefold()
            service_ip = row.get("ztp_service_ip", "")
            if profile not in {"oob", "oobofoob", "none"}:
                errors.append(
                    f"  第 {lineno} 行 cumulus_profile={profile!r} 无效；"
                    "只允许 oob/oobofoob/none"
                )
            if nvos_ztp not in {"yes", "no"}:
                errors.append(
                    f"  第 {lineno} 行 nvos_ztp={nvos_ztp!r} 无效；只允许 yes/no"
                )
            service_address = None
            if service_ip:
                try:
                    service_address = ipaddress.IPv4Address(service_ip)
                    service_ip = str(service_address)
                except ipaddress.AddressValueError:
                    errors.append(
                        f"  第 {lineno} 行 ztp_service_ip={service_ip!r} 不是有效 IPv4"
                    )
            if (profile in _CUMULUS_BOOTSTRAP_BY_PROFILE or nvos_ztp == "yes") and not service_ip:
                errors.append(
                    f"  第 {lineno} 行启用了平台 ZTP，但 ztp_service_ip 为空"
                )
            if profile == "none" and nvos_ztp == "no" and service_ip:
                errors.append(
                    f"  第 {lineno} 行未启用任何平台 ZTP，ztp_service_ip 必须为空"
                )
            if service_address is not None and (
                service_address.is_unspecified or service_address.is_multicast
            ):
                errors.append(
                    f"  第 {lineno} 行 ztp_service_ip={service_address} 不是可用单播地址"
                )
            row["ztp_service_ip"] = service_ip
            row["cumulus_profile"] = profile
            row["nvos_ztp"] = nvos_ztp
            row["cumulus_provision_url"] = (
                _ztp_url(
                    service_ip, ztp_prefix,
                    _CUMULUS_BOOTSTRAP_BY_PROFILE[profile],
                )
                if service_ip and profile in _CUMULUS_BOOTSTRAP_BY_PROFILE else ""
            )
            row["bootfile_name"] = (
                _ztp_url(service_ip, ztp_prefix, "ztp.json")
                if service_ip and nvos_ztp == "yes" else ""
            )
            if service_ip and profile in _CUMULUS_BOOTSTRAP_BY_PROFILE:
                previous = profile_services.setdefault(profile, (service_ip, lineno))
                if previous[0] != service_ip:
                    errors.append(
                        f"  第 {lineno} 行 cumulus_profile={profile} 使用 {service_ip}，"
                        f"但第 {previous[1]} 行使用 {previous[0]}；同一 profile 只能有一个服务 IP"
                    )
            if service_ip and nvos_ztp == "yes":
                if nvos_service is None:
                    nvos_service = (service_ip, lineno)
                elif nvos_service[0] != service_ip:
                    errors.append(
                        f"  第 {lineno} 行 NVOS ZTP 使用 {service_ip}，但第 "
                        f"{nvos_service[1]} 行使用 {nvos_service[0]}；ztp.json 只能有一个服务 IP"
                    )
            network_name = row.get("shared_network", "")
            if network_name:
                if not _SAFE_DHCP_NAME_RE.fullmatch(network_name):
                    errors.append(
                        f"  第 {lineno} 行 shared_network 含不安全字符："
                        f"{network_name!r}"
                    )
                if network_name in seen_networks:
                    errors.append(
                        f"  第 {lineno} 行 shared_network={network_name} 重复"
                        f"（首次第 {seen_networks[network_name]} 行）；每个三层 subnet "
                        "必须使用独立名称"
                    )
                else:
                    seen_networks[network_name] = lineno
            try:
                network = ipaddress.ip_network(
                    f"{row.get('subnet', '')}/{row.get('netmask', '')}", strict=True
                )
                if network.version != 4:
                    raise ValueError("当前只支持 IPv4")
                row["_network"] = network
                usable = network.hosts()
                first_usable = next(usable, None)
                last_usable = (ipaddress.ip_address(int(network.broadcast_address) - 1)
                               if network.num_addresses > 2 else first_usable)
                start = ipaddress.ip_address(row.get("range_start", ""))
                end = ipaddress.ip_address(row.get("range_end", ""))
                router = ipaddress.ip_address(row.get("routers", ""))
                for label, address in (("range_start", start), ("range_end", end),
                                       ("routers", router)):
                    if address not in network or address in (
                            network.network_address, network.broadcast_address):
                        errors.append(
                            f"  第 {lineno} 行 {label}={address} 不是 {network} 的可用主机地址"
                        )
                if start > end:
                    errors.append(f"  第 {lineno} 行 range_start 大于 range_end")
                elif start <= router <= end:
                    errors.append(
                        f"  第 {lineno} 行 routers={router} 落入动态 range "
                        f"{start}-{end}；网关地址不能分配给客户端"
                    )
                if service_address is not None and service_address in network:
                    if service_address in (network.network_address, network.broadcast_address):
                        errors.append(
                            f"  第 {lineno} 行 ztp_service_ip={service_address} "
                            f"不是 {network} 的可用主机地址"
                        )
                    elif start <= service_address <= end:
                        errors.append(
                            f"  第 {lineno} 行 ztp_service_ip={service_address} 落入动态 "
                            f"range {start}-{end}"
                        )
                if first_usable is None or last_usable is None:
                    errors.append(f"  第 {lineno} 行 subnet={network} 没有可分配主机地址")
            except ValueError as exc:
                errors.append(f"  第 {lineno} 行 subnet/netmask 或地址无效：{exc}")
            subnets.append(row)
    parsed = [(index + 2, item.get("_network")) for index, item in enumerate(subnets)]
    for position, (line_a, network_a) in enumerate(parsed):
        if network_a is None:
            continue
        for line_b, network_b in parsed[position + 1:]:
            if network_b is not None and network_a.overlaps(network_b):
                errors.append(
                    f"  第 {line_a}、{line_b} 行 DHCP subnet 重叠：{network_a} / {network_b}"
                )
    if errors:
        print(f"[ERROR] {os.path.basename(path)} 存在问题：")
        for e in errors:
            print(e)
        sys.exit(1)
    return subnets


def _dhcp_packet_log_lines(indent="    "):
    """Return a safe, machine-readable request fingerprint log contract.

    DHCP options are arbitrary binary data.  They are therefore capped at 128
    bytes and rendered as hexadecimal instead of being interpolated into
    syslog as untrusted text.  The parser can decode printable values later.
    """
    def log_line(known, extra="  "):
        return (
            f'{indent}{extra}log(info, concat('
            '"ZTP_DHCP_EVENT_V1 event=packet msg=", '
            'binary-to-ascii(10, 8, "", option dhcp-message-type), '
            '" mac=", binary-to-ascii(16, 8, ":", substring(hardware, 1, 6)), '
            f'" ip=- known={known} vendor60_hex=", '
            'binary-to-ascii(16, 8, ":", substring('
            'pick-first-value(option vendor-class-identifier, ""), 0, 128)), '
            '" client61_hex=", binary-to-ascii(16, 8, ":", substring('
            'pick-first-value(option dhcp-client-identifier, ""), 0, 128)), '
            '" user77_hex=", binary-to-ascii(16, 8, ":", substring('
            'pick-first-value(option user-class, ""), 0, 128))));'
        )

    # Avoid `set` here: DHCP variable assignments can be persisted in the
    # lease database.  Two small conditional log expressions keep the lease
    # file clean while still recording whether a host declaration matched.
    return [
        f"{indent}if known {{",
        log_line("1"),
        f"{indent}}} else {{",
        log_line("0"),
        f"{indent}}}",
    ]


def _dhcp_lease_event_lines(indent="    "):
    """Return commit/release/expiry lines used to correlate MAC and lease IP."""
    result = []
    for hook, event, state, msg in (
        ("commit", "commit", "active", "5"),
        ("release", "release", "released", "7"),
        ("expiry", "expiry", "expired", "-"),
    ):
        result.extend([
            f"{indent}on {hook} {{",
            f'{indent}  log(info, concat('
            f'"ZTP_DHCP_EVENT_V1 event={event} msg={msg} mac=", '
            'binary-to-ascii(16, 8, ":", substring(hardware, 1, 6)), '
            '" ip=", binary-to-ascii(10, 8, ".", leased-address), '
            f'" known=- vendor60_hex=- client61_hex=- user77_hex=- lease_state={state}"));',
            f"{indent}}}",
        ])
    return result


def write_dhcpd_conf(path, subnets):
    """根据 subnet 列表生成 dhcpd.conf，并按客户端平台互斥下发 ZTP。"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        f"# dhcpd.conf — Generated at {now}",
        "",
        "default-lease-time 600;",
        "max-lease-time 7200;",
        "ddns-update-style none;",
        "authoritative;",
        "",
        "# ZTP of Cumulus switches",
        "option cumulus-provision-url code 239 = text;",
        "",
    ]

    # 每个三层 subnet 使用独立的 shared-network。禁止名称重复，避免 ISC DHCP
    # 把多个地址池视为同一二层广播域并跨 subnet 分配地址。
    seen_networks = set()
    for s in subnets:
        network_name = s["shared_network"]
        if network_name in seen_networks:
            raise ValueError(
                f"shared_network={network_name} 重复；每个三层 subnet 必须使用独立名称"
            )
        seen_networks.add(network_name)
        lines.append(f"shared-network {network_name} {{")
        lines.append(f"  subnet {s['subnet']} netmask {s['netmask']} {{")
        lines.append(f"    range {s['range_start']} {s['range_end']};")
        lines.append(f"    option routers {s['routers']};")
        lines.extend(_dhcp_packet_log_lines())
        lines.extend(_dhcp_lease_event_lines())
        cumulus_url = s.get("cumulus_provision_url", "")
        nvos_bootfile = s.get("bootfile_name", "")
        # Platform branches are mutually exclusive.  Unknown fingerprints get
        # a normal lease but no ZTP boot instruction.  Identity (known/unknown)
        # deliberately does not decide the platform.
        # Keep option 61 and option 77 in separate branches: ISC propagates a
        # missing option as null through `or`, which could hide a valid match.
        if cumulus_url:
            lines.append(
                '    if substring(option vendor-class-identifier, 0, 7) = "cumulus"'
            )
            lines.append(
                '      or substring(option vendor-class-identifier, 0, 7) = "Cumulus" {'
            )
            lines.append(f'      option cumulus-provision-url "{cumulus_url}";')
            if nvos_bootfile:
                lines.append(
                    '    } elsif substring(option dhcp-client-identifier, 0, 6) = "NVOS##" {'
                )
                lines.append(f'      option bootfile-name "{nvos_bootfile}";')
                lines.append(
                    '    } elsif substring(option user-class, 0, 8) = "NVOS-ZTP"'
                )
                lines.append(
                    '      or substring(option user-class, 1, 8) = "NVOS-ZTP" {'
                )
                lines.append(f'      option bootfile-name "{nvos_bootfile}";')
            lines.append("    }")
        elif nvos_bootfile:
            lines.append(
                '    if substring(option dhcp-client-identifier, 0, 6) = "NVOS##" {'
            )
            lines.append(f'      option bootfile-name "{nvos_bootfile}";')
            lines.append(
                '    } elsif substring(option user-class, 0, 8) = "NVOS-ZTP"'
            )
            lines.append(
                '      or substring(option user-class, 1, 8) = "NVOS-ZTP" {'
            )
            lines.append(f'      option bootfile-name "{nvos_bootfile}";')
            lines.append("    }")
        lines.append("  }")
        lines.append("}")
        lines.append("")

    lines += [
        'include "/etc/dhcp/dhcpd_eth.hosts";',
        'include "/etc/dhcp/dhcpd_ib.hosts";',
        'include "/etc/dhcp/dhcpd_nvl.hosts";',
        "",
    ]

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"[OK] {os.path.basename(path)}：{len(subnets)} 条 subnet")


# ── 入口 ──────────────────────────────────────────────────────────────────────

def main():
    global _AUTO_YES
    args = sys.argv[1:]
    if any(arg in ("-h", "--help") for arg in args):
        print(__doc__.strip())
        return
    if "-y" in args:
        _AUTO_YES = True
        args = [a for a in args if a != "-y"]
    if args:
        print(f"[ERROR] 不支持的参数：{' '.join(args)}", file=sys.stderr)
        print("使用 -h 或 --help 查看用法", file=sys.stderr)
        sys.exit(2)

    if not os.path.isfile(SUBNET_CSV):
        print(f"[ERROR] 找不到 {os.path.basename(SUBNET_CSV)}")
        sys.exit(1)
    try:
        ztp_prefix = load_ztp_url_prefix(GLOBAL_YAML)
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        sys.exit(1)
    print(f"读取：{os.path.basename(GLOBAL_YAML)}（ztp_url_prefix={ztp_prefix}）")
    print(f"读取：{os.path.basename(SUBNET_CSV)}")
    subnets = load_subnet_csv(SUBNET_CSV, ztp_prefix)
    print(f"  已加载 {len(subnets)} 条 subnet 配置\n")

    csv_files = [DEVICES_CSV]
    if not os.path.isfile(DEVICES_CSV):
        print("[ERROR] 当前目录下未找到 02-devices_config.csv 文件")
        sys.exit(1)

    all_records = []
    air_records = []
    for path in csv_files:
        print(f"读取：{os.path.basename(path)}")
        try:
            recs = load_csv(path)
        except (OSError, ValueError, csv.Error) as exc:
            print(f"[ERROR] 设备 CSV 无法安全读取：{exc}")
            sys.exit(1)
        eth_n = sum(1 for r in recs if r["type"] in ("eth", "eth_spx", "spx", "air") and r["iface"] == "eth0")
        ib_n  = sum(1 for r in recs if r["type"] == "ib"  and r["iface"] == "eth0")
        nvl_n = sum(1 for r in recs if r["type"] == "nvl" and r["iface"] == "eth0")
        print(f"  eth/eth_spx/spx/air {eth_n} 台，ib {ib_n} 台，nvl {nvl_n} 台，"
              f"共 {len(recs)} 条记录（含 eth1）")
        all_records.extend(recs)

    if os.path.isfile(P2P_AIR_JSON):
        print(f"读取：{os.path.basename(P2P_AIR_JSON)}")
        try:
            raw_air_records = load_p2p_air_json(P2P_AIR_JSON)
            air_records = inherit_air_records_from_production(
                DEVICES_CSV, raw_air_records, skip_missing=True
            )
            unresolved_air = {
                rec["hostname"] for rec in raw_air_records
                if rec.get("production_missing")
            }
            dynamic_air_records = []
            for rec in raw_air_records:
                if not rec.get("production_missing"):
                    continue
                rec["type"] = "air"
                rec["dynamic"] = True
                dynamic_air_records.append(rec)
            all_records, removed_static = exclude_air_records(
                all_records, unresolved_air
            )
            if unresolved_air:
                print(
                    f"  [INFO] {len(unresolved_air)} 台 AIR 设备改用动态 DHCP range；"
                    f"本次忽略 CSV 中 {removed_static} 条同名静态 AIR 记录"
                )
            resolved_air = {rec["hostname"] for rec in air_records}
            all_records, replaced_static = exclude_air_records(
                all_records, resolved_air
            )
            if replaced_static:
                print(
                    f"  [INFO] 使用 production 继承值替换内存中的 "
                    f"{replaced_static} 条已有 AIR 静态记录"
                )
        except ValueError as exc:
            print(f"[ERROR] {exc}")
            sys.exit(1)
        print(
            f"  AIR Cumulus 静态 {len(air_records)} 台、动态 "
            f"{len(dynamic_air_records)} 台，共 "
            f"{len(air_records) + len(dynamic_air_records)} 条 eth0 记录"
        )
        all_records, air_existing = merge_air_records(all_records, air_records)
        all_records, dynamic_existing = merge_air_records(
            all_records, dynamic_air_records
        )
        if air_existing:
            print(f"  其中 {len(air_existing)} 条已存在于 devices_config，DHCP 输出不重复添加")
        if dynamic_air_records:
            print(
                f"  另有 {len(dynamic_air_records)} 条动态 AIR known host："
                "仅写 MAC，不写 fixed-address"
            )
    else:
        print(f"[INFO] 当前目录未找到 {os.path.basename(P2P_AIR_JSON)}，跳过 AIR 节点")

    valid_records, errors = validate(all_records)
    errors.extend(validate_records_against_subnets(valid_records, subnets))
    errors.extend(plan_dhcp_assignments(valid_records, subnets))

    if errors:
        print("\n[ERROR] 发现以下问题，请修正后重新运行：")
        for e in errors:
            print(e)
        sys.exit(1)

    eth_records = [r for r in valid_records if r["type"] in ("eth", "eth_spx", "spx", "air")]
    ib_records  = [r for r in valid_records if r["type"] == "ib"]
    nvl_records = [r for r in valid_records if r["type"] == "nvl"]

    print(f"\n验证通过：eth/eth_spx/spx/air {len(eth_records)} 条，ib {len(ib_records)} 条，"
          f"nvl {len(nvl_records)} 条")
    pending_records = [r for r in valid_records if r.get("identity_pending")]
    transit_records = [
        r for r in valid_records if r.get("dhcp_assignment") == "transit_dynamic"
    ]
    if pending_records:
        print(
            f"  identity_pending {len(pending_records)} 条：保留在发布清单，"
            "不生成 host declaration"
        )
    if transit_records:
        print(
            f"  transit_dynamic {len(transit_records)} 条：计划 IP 不属于本机服务 subnet，"
            "生成已知 MAC host 但不写 fixed-address"
        )
    if not _confirm("[Y/n] 是否生成配置文件？"):
        print("已取消")
        sys.exit(0)

    print()
    write_dhcpd_conf(OUTPUT_CONF, subnets)
    write_hosts(OUTPUT_ETH, eth_records)
    write_hosts(OUTPUT_IB,  ib_records)
    write_hosts(OUTPUT_NVL, nvl_records)
    write_release_manifest(
        OUTPUT_MANIFEST, valid_records, subnets,
        (OUTPUT_CONF, OUTPUT_ETH, OUTPUT_IB, OUTPUT_NVL),
    )

    print()
    if _confirm("[y/N] 是否复制配置文件到 /etc/dhcp/？", default="n"):
        for src_path, destination in [(OUTPUT_CONF, "/etc/dhcp/dhcpd.conf"),
                                      (OUTPUT_ETH,  "/etc/dhcp/dhcpd_eth.hosts"),
                                      (OUTPUT_IB,   "/etc/dhcp/dhcpd_ib.hosts"),
                                      (OUTPUT_NVL,  "/etc/dhcp/dhcpd_nvl.hosts")]:
            result = subprocess.run(["sudo", "install", "-m", "0644", src_path, destination],
                                    capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[COPY] {src_path} -> {destination}")
            else:
                print(f"[WARN] 无法复制到 {destination}：{result.stderr.strip()}")
    else:
        print("跳过复制到 /etc/dhcp")

    generated_air = {
        (
            r["hostname"].strip().casefold(),
            r["ip"].strip(),
            r.get("mac_norm") or normalize_mac(r["mac"]) or "",
        )
        for r in air_records
    } & {
        (r["hostname"].strip().casefold(), r["ip"].strip(), r.get("mac_norm") or "")
        for r in eth_records if not r.get("identity_pending")
    }
    if os.path.isfile(P2P_AIR_JSON):
        print(f"\n检测到 {len(generated_air)} 台 AIR Cumulus 设备已写入 dhcpd_eth.hosts。")
        if _confirm(
            "[Y/n] 是否原子重建 02-devices_config.csv 末尾的 type=air 行？",
        ):
            try:
                added, updated, existed = append_air_records_to_csv(
                    DEVICES_CSV, air_records, subnets,
                )
            except (OSError, ValueError) as exc:
                print(f"[ERROR] 更新 02-devices_config.csv 的 AIR 行失败：{exc}")
                sys.exit(1)
            print(
                f"[OK] 02-devices_config.csv 末尾 AIR 行：新增 {added} 台，"
                f"更新 {updated} 台，内容不变 {existed} 台"
            )
        else:
            print("跳过更新 02-devices_config.csv 的 AIR 行")


if __name__ == "__main__":
    main()
