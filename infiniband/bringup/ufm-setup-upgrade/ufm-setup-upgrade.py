#!/usr/bin/env python3
"""UFM setup/upgrade entry: reads this directory's 01-global.yaml, ib.csv, p2p.xlsx, publickey/ and the master
inventory 02 (v3.1.6 B0: compared with ib.csv before anything else)."""

from __future__ import annotations

import argparse
import base64
import csv
import getpass
import hashlib
import ipaddress
import itertools
import json
import os
import pty
import pwd
import random
import re
import select
import shlex
import signal
import subprocess
import sys
import time
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Callable, Optional

TOOL_DIR = Path(__file__).resolve().parent
REPO_DIR = TOOL_DIR.parents[2]
INFRA_DIR = REPO_DIR / "infra"
if str(INFRA_DIR) not in sys.path:
    sys.path.insert(0, str(INFRA_DIR))
if str(REPO_DIR) not in sys.path:   # v3.1.6 B0: the shared tools/ modules, imported by package name
    sys.path.insert(0, str(REPO_DIR))
import ubuntu24_host as host  # noqa: E402  (shared Ubuntu 24.04 host configuration)
import tools.device_identity as device_identity  # noqa: E402  (MAC spellings, P3b)
import tools.hostname_ranges as hostname_ranges  # noqa: E402  (--refresh-host-key names)
import tools.inventory_subset as inventory_subset  # noqa: E402  (ib.csv against 02, R-016)
import tools.login_path as login_rules  # noqa: E402  (I-037 rules shared with initial-setup)
LOGS_NAME = "ufm-setup-upgrade-logs"
UFM_TYPE = "server_ufm"
MASTER_INVENTORY = "02-devices_config.csv"
NA_VALUES = {"", "na", "n/a", "none", "null", "tbd", "-"}
CSV_PREFIX = ("hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw", "eth0_mac")
POLICY_KEYS = ("version", "vip", "interfaces")
INTERFACE_KEYS = ("alias", "primary", "secondary")
ROLES = ("primary", "secondary")
SELECTOR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)+(?:[-_.+][0-9A-Za-z]+)*$")
PRIMARY_LABEL_RE = re.compile(r"(?:^|[-_])ufm-?01$", re.I)
USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9._-]{0,31}$")
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

_EXPIRED = re.compile(
    r"(?i)(?:password (?:has )?expired|required to change your password|"
    r"must change your password|password change required|"
    r"authentication token (?:is |has )?expired)")
_UPDATED = re.compile(r"(?i)(?:password.*(?:updated|changed).*success|all authentication tokens updated)")
# pam_pwquality ("BAD PASSWORD: ...") and Ubuntu's default pam_unix obscure checks ("You must choose a
# longer password.", "Bad: new password is too simple"); the first one aborts the change.
_BAD_NEW_PASSWORD = re.compile(
    r"(?im)^[^\n]*(?:BAD PASSWORD:[^\n]*|Bad: [^\n]*|You must choose a longer password[^\n]*|password unchanged|"
    r"have exhausted maximum number of retries[^\n]*|passwords? do not match[^\n]*)$")
_HOSTKEY_CONFLICT = re.compile(
    r"(?i)remote host identification has changed|host key verification failed|offending \S+ key")
_UNREACHABLE = re.compile(
    r"(?i)no route to host|network is unreachable|connection timed out|operation timed out|"
    r"timed out during banner exchange|host is down")
_REFUSED = re.compile(r"(?i)connection refused")
ABORT = object()


class UfmError(Exception):
    """Operator-facing failure; message is already redacted."""


class UfmUnreachable(UfmError):
    """The session never reached the UFM (connect timeout / no route); nothing ran remotely."""


class NotAuthorized(UfmError):
    """The operator declined the first device change; the run stops before any write."""


class SwitchUnreachable(UfmError):
    """A jump never answered on this address (no route, timeout, refused): only this moves to the next login
    candidate of the jump (I20, B0-O1 (a)); a refusal or an identity mismatch does not."""


class RouteStop(UfmError):
    """The route decided for this UFM cannot be used; status is its NodeResult status (B0-O5)."""

    def __init__(self, status: str, detail: str):
        super().__init__(detail)
        self.status = status


class IdentityMismatch(UfmError):
    """B0-O13 (a) (I-054): logged in, but not the UFM of the CSV; the node stops and no password is sent."""


class KeyLoginRejected(UfmError):
    """The deployment key was refused (classify AUTH_REJECTED); the classified route is next."""


class HostKeyConflict(UfmError):
    """This server's known_hosts holds another host key for the address (classify HOSTKEY_CONFLICT); change is
    login_path.parse_host_key_change of the warning, or None when it cannot be parsed."""

    def __init__(self, detail: str, change: object):
        super().__init__(detail)
        self.change = change


class HaWaitTimeout(UfmError):
    """A bounded HA wait (DRBD sync, status after start) ran out; the cluster is left as it is."""


class UpgradeInProgress(UfmError):
    """I-008 (v3.1.6 B2-O3): an upgrade is running, unfinished or outlasted the wait; run_steps reports it as
    UPGRADE_IN_PROGRESS, a retry (config-upgrade detects it and never starts a second one)."""


# ---------------------------------------------------------------- input model

@dataclass(frozen=True)
class UfmNode:
    hostname: str
    line: int
    address: str
    interface: str
    gateway: str
    mac: str


@dataclass(frozen=True)
class Transit:
    """A *jump row of ib.csv (I-037: only a type ending in jump is a jump). login_ip is the address in use:
    the first candidate until a session picks one (I20, B0-O1 (a)); eth0_mac is the CSV value as written."""
    hostname: str
    dev_type: str
    login_ip: str
    candidates: tuple = ()
    eth0_mac: str = ""


@dataclass(frozen=True)
class Attachment:
    leaf: Transit
    port: str
    p2p_device: str
    p2p_port: str


@dataclass
class Plan:
    input_dir: Path
    version: Optional[str] = None
    vip: Optional[str] = None
    alias: dict = field(default_factory=dict)
    logical: dict = field(default_factory=dict)
    inferred: set = field(default_factory=set)
    devices: list = field(default_factory=list)
    mgmt_device: str = ""
    nodes: list = field(default_factory=list)
    source_ufm_count: int = 0   # server_ufm rows in ib.csv, before any per-node filter (B6-O1, v3.1.6 指导 8.6)
    ufm_hostnames: list = field(default_factory=list)   # every server_ufm row, before any per-node filter (B0)
    # B0-O7 (a): UFMs skipped for a problem of their own data (INPUT_INCOMPLETE), hostname -> problems; they are
    # not in nodes, so every count and loop over nodes sees the complete UFMs only (核对 A, A-M4)
    incomplete: dict = field(default_factory=dict)
    inventory: dict = field(default_factory=dict)   # first label -> [(hostname, type)] of every ib.csv row
    links: dict = field(default_factory=dict)   # hostname -> login_rules.Attachment of its management port
    p2p_links: list = field(default_factory=list)
    roles: dict = field(default_factory=dict)
    addresses: dict = field(default_factory=dict)
    ipmi_gateways: dict = field(default_factory=dict)   # role -> IPMI gateway when global gives its own
    transits: dict = field(default_factory=dict)
    transit_errors: dict = field(default_factory=dict)
    attachments: dict = field(default_factory=dict)
    bmc_attachments: dict = field(default_factory=dict)   # hostname -> Attachment of the BMC/iDRAC port
    foreign_addresses: dict = field(default_factory=dict)  # IPv4 owned by other ib.csv rows -> "host column"
    foreign_macs: dict = field(default_factory=dict)
    ha_links: dict = field(default_factory=dict)
    public_keys: list = field(default_factory=list)
    key_lines: list = field(default_factory=list)
    dns: list = field(default_factory=list)
    ntp: list = field(default_factory=list)
    timezone: str = ""
    image_server: str = ""
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    def role_of(self, node: UfmNode) -> str:
        return next((role for role, host in self.roles.items() if host == node.hostname), "")


def clean(value: object) -> str:
    return str(value if value is not None else "").strip().strip("‘’“”")


def usable(value: object) -> bool:
    return clean(value).casefold() not in NA_VALUES


def first_label(hostname: str) -> str:
    return clean(hostname).casefold().rstrip(".").split(".", 1)[0]


def normalize_mac(value: str) -> str:
    compact = re.sub(r"[.:-]", "", clean(value))
    if not re.fullmatch(r"[0-9a-fA-F]{12}", compact):
        raise ValueError(f"无效 MAC: {clean(value)!r}")
    return ":".join(compact[i:i + 2] for i in range(0, 12, 2)).casefold()


def parse_ipv4_interface(address: str, mask: str = "") -> ipaddress.IPv4Interface:
    address, mask = clean(address), clean(mask).lstrip("/")
    if "/" in address:
        interface = ipaddress.IPv4Interface(address)
        if mask and ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen != interface.network.prefixlen:
            raise ValueError(f"{address} 的前缀与 netmask {mask} 不一致")
    elif mask:
        interface = ipaddress.IPv4Interface(f"{address}/{mask}")
    else:
        raise ValueError(f"{address} 缺少掩码")
    network = interface.network
    if network.prefixlen <= 30 and interface.ip in {network.network_address, network.broadcast_address}:
        raise ValueError(f"{interface} 是网络地址或广播地址")
    return interface


# ------------------------------------------------------------ 01-global.yaml

def load_global(path: Path) -> object:
    try:
        import yaml
    except ImportError as exc:
        raise UfmError("读取 01-global.yaml 需要 PyYAML（python3 -m pip install pyyaml）") from exc

    class UniqueKeyLoader(yaml.SafeLoader):
        pass

    def mapping(loader, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=True)
            if key in result:
                raise UfmError(f"01-global.yaml 第 {key_node.start_mark.line + 1} 行键重复: {key}")
            result[key] = loader.construct_object(value_node, deep=True)
        return result

    UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    try:
        with path.open(encoding="utf-8") as stream:
            return yaml.load(stream, Loader=UniqueKeyLoader)
    except OSError as exc:
        raise UfmError(f"无法读取 {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise UfmError(f"01-global.yaml 语法错误: {exc}") from exc


def find_ufm_policy(document: object, errors: list) -> Optional[dict]:
    if not isinstance(document, dict):
        errors.append("01-global.yaml 顶层必须是映射")
        return None
    servers = document.get("servers")
    if not isinstance(servers, list):
        errors.append("01-global.yaml 缺少 servers 列表（格式: servers: 下一行 '  - ufm:'）")
        return None
    found = []
    for index, record in enumerate(servers):
        if not isinstance(record, dict) or len(record) != 1:
            errors.append(f"servers[{index}] 必须是单键映射，例如 '- ufm:'")
            continue
        family, policy = next(iter(record.items()))
        if clean(family).casefold() == "ufm":
            found.append((index, policy))
    if len(found) != 1:
        errors.append("servers 中必须有且只有一个 ufm 段" if found else "servers 中没有 ufm 段")
        return None
    index, policy = found[0]
    if not isinstance(policy, dict):
        errors.append(f"servers[{index}].ufm 必须是映射")
        return None
    return policy


def parse_policy(policy: dict, plan: Plan) -> dict:
    errors, where = plan.errors, "servers.ufm"
    unknown = sorted(clean(key) for key in policy if clean(key) not in POLICY_KEYS)
    if unknown:
        errors.append(f"{where} 有未知字段 {', '.join(unknown)}；允许: {', '.join(POLICY_KEYS)}")
    version = policy.get("version")
    if version is not None:
        if not isinstance(version, str) or not VERSION_RE.fullmatch(version.strip()):
            errors.append(f"{where}.version 必须是带引号的版本号，例如 \"2.6.1-8\"，当前: {version!r}")
        else:
            plan.version = version.strip()
    interfaces = policy.get("interfaces")
    if not isinstance(interfaces, dict):
        errors.append(f"{where}.interfaces 必须是映射，包含 alias / primary / secondary")
        return {}
    unknown = sorted(clean(key) for key in interfaces if clean(key) not in INTERFACE_KEYS)
    if unknown:
        errors.append(f"{where}.interfaces 有未知字段 {', '.join(unknown)}；允许: {', '.join(INTERFACE_KEYS)}")
    alias = interfaces.get("alias")
    if not isinstance(alias, dict) or "eth0" not in alias:
        errors.append(f"{where}.interfaces.alias 必须把 eth0 映射到实际接口，例如 eth0: eno8303")
        alias = {}
    targets = set()
    for logical, device in alias.items():
        logical, device = clean(logical), clean(device)
        if not host.IFNAME_RE.fullmatch(logical) or not host.IFNAME_RE.fullmatch(device):
            errors.append(f"{where}.interfaces.alias.{logical}: 接口名无效 {device!r}")
            continue
        if device.casefold() in targets:
            errors.append(f"{where}.interfaces.alias: 实际接口 {device} 被映射了两次")
        targets.add(device.casefold())
        plan.alias[logical] = device
    plan.mgmt_device = plan.alias.get("eth0", "")
    blocks, gateways = {}, {}
    for role in ROLES:
        block = interfaces.get(role)
        if block is None:
            continue
        if not isinstance(block, dict) or not block:
            errors.append(f"{where}.interfaces.{role} 必须是非空映射（接口名: IPv4/前缀）")
            continue
        parsed = {}
        for name, value in block.items():
            name, path = clean(name), f"{where}.interfaces.{role}.{clean(name)}"
            if name != "ipmi" and not host.IFNAME_RE.fullmatch(name):
                errors.append(f"{path}: 接口名无效")
                continue
            device = "ipmi" if name == "ipmi" else plan.alias.get(name, name)
            if name == "eth0" or (plan.mgmt_device and device == plan.mgmt_device):
                errors.append(f"{path}: 管理口地址来自 ib.csv 的 eth0_ip，这里不能再配置")
                continue
            if device in parsed:
                errors.append(f"{path}: 与同一接口 {device} 的另一项重复")
                continue
            if device == "ipmi" and not isinstance(value, dict):
                errors.append(f"{path}: 改用 address/gateway 写法（gateway 可选，与 {plan.mgmt_device or 'eth0'} 同网段时"
                              f"取 ib.csv 的 eth0_gw），例如 ipmi: {{address: \"{value}\"}}")
                continue
            if device == "ipmi":
                # Owner 2026-10-21: `ipmi: {address: ..., gateway: ...}`; the BMC may sit in its own subnet.
                unknown = sorted(str(key) for key in value if key not in {"address", "gateway"})
                if unknown:
                    errors.append(f"{path}: 只支持 address 和 gateway，不认识: {', '.join(unknown)}")
                    continue
                if value.get("gateway") is not None:
                    try:
                        gateways[role] = ipaddress.IPv4Address(clean(str(value["gateway"])))
                    except ValueError:
                        errors.append(f"{path}.gateway: 不是 IPv4 地址: {value['gateway']!r}")
                        continue
                value, path = value.get("address"), f"{path}.address"
            if not isinstance(value, str) or "/" not in value:
                errors.append(f"{path}: 需要带引号的 IPv4/前缀，例如 \"192.0.2.1/30\"，当前: {value!r}")
                continue
            try:
                parsed[device] = parse_ipv4_interface(value)
            except ValueError as exc:
                errors.append(f"{path}: {exc}")
        blocks[role] = parsed
    resolve_logical_names(plan, blocks)
    return {"vip": policy.get("vip"), "blocks": blocks, "ipmi_gateways": gateways}


def resolve_logical_names(plan: Plan, blocks: dict) -> None:
    """eth1 is the HA interface: alias wins, else the single non-IPMI, non-IB host interface."""
    host_devices = {device for block in blocks.values() for device in block if device != "ipmi"}
    plan.devices = sorted(set(plan.alias.values()) | host_devices)
    plan.logical = dict(plan.alias)
    if "eth1" in plan.logical:
        return
    candidates = sorted(device for device in host_devices
                        if device != plan.mgmt_device and not device.casefold().startswith("ib"))
    if len(candidates) == 1:
        plan.logical["eth1"] = candidates[0]
        plan.inferred.add("eth1")
    elif blocks.get("secondary"):
        plan.warnings.append("无法确定 eth1（HA 接口）对应的实际接口，候选: "
                             f"{', '.join(candidates) or '无'}；P2P 若写 eth1，请在 alias 中声明 eth1")


def resolve_ufm_port(plan: Plan, port: str) -> Optional[str]:
    """Map a P2P UFM port spelling (eno8303 / eth0 / 8303) to the device interface."""
    text = clean(port).casefold()
    if not text:
        return None
    for device in plan.devices:
        if text == device.casefold():
            return device
    for name, device in plan.logical.items():
        if text == name.casefold():
            return device
    if text.isdigit():
        matches = [device for device in plan.devices if not device.casefold().startswith("ib")
                   and re.search(r"([0-9]+)$", device) and re.search(r"([0-9]+)$", device).group(1) == text]
        if len(matches) == 1:
            return matches[0]
    return None


# --------------------------------------------------------------------- ib.csv

def jump_vlan_groups(row: list, header: list) -> list:
    """(vlan_id, svi_ip, netmask) of each vlan_id column group of a *jump row, as the template repeats them
    (the column groups as transit_login_ip read them before v3.1.6; I20 takes every group, B0-O1 (a))."""
    def value(index: int) -> str:
        return clean(row[index]) if index < len(row) else ""

    names = dict(enumerate(header))
    boundaries = {"vlan_id", "vlan_ports", "bgp_asn", "bgp_ports", "bond_ports", "evpn_vrf", "evpn_l2vlan"}
    groups = []
    for start in (index for index, name in names.items() if name == "vlan_id"):
        end = next((i for i in range(start + 1, len(header)) if names.get(i) in boundaries), len(header))
        for position in (i for i in range(start + 1, end) if names[i] == "svi_ip"):
            mask = next((i for i in range(position + 1, end) if names[i] == "netmask"), None)
            groups.append((value(start), value(position), value(mask) if mask is not None else ""))
    return groups


def load_csv(path: Path, plan: Plan) -> None:
    errors = plan.errors
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        errors.append(f"无法读取 ib.csv: {exc}")
        return
    rows = list(csv.reader(text.splitlines()))
    if not rows:
        errors.append("ib.csv 是空文件")
        return
    header = [clean(item).casefold() for item in rows[0]]
    if tuple(header[:len(CSV_PREFIX)]) != CSV_PREFIX:
        errors.append("ib.csv 前 7 列必须是 " + ",".join(CSV_PREFIX))
        return
    for line, row in enumerate(rows[1:], 2):
        if not any(clean(item) for item in row):
            continue
        row = list(row) + [""] * max(0, len(CSV_PREFIX) - len(row))
        hostname, dev_type = clean(row[0]), clean(row[1]).casefold()
        where = f"ib.csv 第 {line} 行 ({hostname or '?'})"
        if dev_type == "ufm":
            errors.append(f"{where}: type 应为 {UFM_TYPE}")
        elif dev_type == UFM_TYPE:
            plan.source_ufm_count += 1
            plan.ufm_hostnames.append(hostname)
            node, problems = parse_node_row(row, header, line, where, errors)
            if node:
                plan.nodes.append(node)
            elif problems:
                plan.incomplete[hostname] = problems
        if dev_type != UFM_TYPE:
            record_foreign_identities(plan, row, header, hostname or f"第 {line} 行")
        if hostname:
            plan.inventory.setdefault(first_label(hostname), []).append((hostname, dev_type))
        if hostname and login_rules.is_jump_type(dev_type):
            # I20 (B0-O1 (a)): eth0_ip, then each VLAN SVI address; a jump without any is unusable on its own
            candidates, issues = login_rules.jump_login_candidates(
                hostname, eth0_ip=clean(row[3]), vlan_groups=jump_vlan_groups(row, header))
            if not candidates:
                plan.transit_errors[first_label(hostname)] = f"{where}: " + "; ".join(
                    f"{issue.field} {issue.problem} {issue.value!r}" for issue in issues)
            plan.transits.setdefault(first_label(hostname), []).append(Transit(
                hostname, dev_type, candidates[0].address if candidates else "", candidates, clean(row[6])))
    names = {}
    for line_no, name in enumerate(plan.ufm_hostnames):
        if name.casefold() in names:
            errors.append(f"ib.csv 中 {UFM_TYPE} 的 hostname 重复: {name}")
        names[name.casefold()] = line_no
    seen = {}
    for node in list(plan.nodes):
        for kind, key in (("eth0_ip", node.address), ("eth0_mac", node.mac)):
            other = seen.get((kind, key))
            if other:   # B0-O7 (a), D1b-O9 (b): both UFMs involved are skipped, nothing else
                skip_node(plan, node.hostname, f"{kind} {key} 与 {other.hostname}（ib.csv 第 {other.line} 行）重复")
                skip_node(plan, other.hostname, f"{kind} {key} 与 {node.hostname}（ib.csv 第 {node.line} 行）重复")
            seen[(kind, key)] = node
    if not plan.ufm_hostnames:
        errors.append(f"ib.csv 中没有 type={UFM_TYPE} 的行")
    elif len(plan.ufm_hostnames) > 2:
        errors.append(f"ib.csv 中有 {len(plan.ufm_hostnames)} 台 {UFM_TYPE}；只支持单机或两台 HA")


def skip_node(plan: Plan, hostname: str, problem: str) -> None:
    """B0-O7 (a): a problem of this UFM's own data skips this UFM only. It leaves plan.nodes and is reported as
    INPUT_INCOMPLETE; problems of the run as a whole stay in plan.errors."""
    plan.nodes = [node for node in plan.nodes if node.hostname != hostname]
    problems = plan.incomplete.setdefault(hostname, [])
    if problem not in problems:
        problems.append(problem)


def record_foreign_identities(plan: Plan, row: list, header: list, owner: str) -> None:
    """Addresses and MACs that other ib.csv rows already own; a UFM must not reuse any of them."""
    for index, column in enumerate(header):
        value = clean(row[index]) if index < len(row) else ""
        if column.endswith("_ip") and usable(value):
            try:
                plan.foreign_addresses.setdefault(str(ipaddress.ip_interface(value.split()[0]).ip),
                                                  f"{owner} {column}")
            except ValueError:
                continue
        elif column.endswith("_mac") and usable(value):
            try:   # every spelling tools/device_identity knows (P3b :163); one it does not know is skipped
                mac = device_identity.normalize_mac(value)
            except ValueError:
                continue
            plan.foreign_macs.setdefault(mac, f"{owner} {column}")


def parse_node_row(row: list, header: list, line: int, where: str, errors: list) -> tuple:
    """(UfmNode, []) or (None, problems of this UFM). I-037 rule 1: eth0_ip/netmask, eth0_gw and eth0_mac through
    login_rules.check_eth0_inputs, plus the two UFM rules kept beside it (v3.1.6 指导 :1194): the gateway is not
    eth0_ip, an address with a prefix agrees with the netmask column. An invalid hostname stays a run error."""
    hostname = clean(row[0])
    if not host.valid_hostname(hostname):
        errors.append(f"{where}: hostname 无效")
        return None, []
    address, mask = clean(row[3]), clean(row[4]).lstrip("/")   # "/23" means 23, as before
    eth0, issues = login_rules.check_eth0_inputs(hostname, mac=clean(row[6]), address=address, netmask=mask,
                                                 gateway=clean(row[5]))
    problems = [f"{where}: {issue.field} {issue.value!r} {issue.problem}" for issue in issues if issue.blocking]
    if eth0 is not None and "/" in address and usable(mask):
        try:
            if ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen != eth0.address.network.prefixlen:
                problems.append(f"{where}: eth0_ip {address} 的前缀与 netmask {mask} 不一致")
        except ValueError:
            problems.append(f"{where}: netmask {mask!r} 无效")
    if eth0 is not None and eth0.gateway == str(eth0.address.ip):
        problems.append(f"{where}: eth0_gw {eth0.gateway} 与 eth0_ip 相同")
    for index in range(len(CSV_PREFIX), len(row)):
        if usable(row[index]):
            name = header[index] if index < len(header) else f"第 {index + 1} 列"
            problems.append(f"{where}: 第 {index + 1} 列 ({name}) 有值 {clean(row[index])!r}；"
                            f"{UFM_TYPE} 只使用前 7 列，HA/IPMI/IB 地址写在 01-global.yaml")
    if problems:
        return None, problems
    return UfmNode(hostname, line, str(eth0.address.ip), str(eth0.address), eth0.gateway, eth0.mac), []


# ------------------------------------------------------------------ p2p.xlsx

def _xlsx_cell(cell: ET.Element, shared: list, ns: str) -> str:
    kind = cell.get("t", "")
    if kind == "inlineStr":
        return clean("".join(node.text or "" for node in cell.findall(f".//{ns}t")))
    value = cell.find(f"{ns}v")
    if value is None or value.text is None:
        return ""
    if kind == "s":
        try:
            return clean(shared[int(value.text)])
        except (ValueError, IndexError):
            return ""
    return clean(value.text)


def _xlsx_column(reference: str) -> int:
    letters = re.match(r"[A-Za-z]+", reference or "")
    result = 0
    for character in (letters.group(0).upper() if letters else ""):
        result = result * 26 + ord(character) - ord("A") + 1
    return result - 1


def parse_p2p_xlsx(path: Path) -> list:
    """Two name+port column groups per sheet, as in ib-initial-setup."""
    ns = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
    rel_ns = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
    pkg_ns = "{http://schemas.openxmlformats.org/package/2006/relationships}"
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise UfmError(f"无法打开 P2P 文件 {path}: {exc}") from exc
    links = []
    with archive:
        names = set(archive.namelist())
        shared = []
        if "xl/sharedStrings.xml" in names:
            root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
            shared = ["".join(node.text or "" for node in item.findall(f".//{ns}t"))
                      for item in root.findall(f"{ns}si")]
        try:
            workbook = ET.fromstring(archive.read("xl/workbook.xml"))
            relations = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
        except (KeyError, ET.ParseError) as exc:
            raise UfmError(f"P2P 文件结构无效: {exc}") from exc
        targets = {item.get("Id", ""): item.get("Target", "")
                   for item in relations.findall(f"{pkg_ns}Relationship")}
        for sheet in workbook.findall(f".//{ns}sheet"):
            target = targets.get(sheet.get(f"{rel_ns}id", ""), "").lstrip("/")
            sheet_path = target if target.startswith("xl/") else f"xl/{target}"
            if sheet_path not in names:
                continue
            rows = []
            for row_node in ET.fromstring(archive.read(sheet_path)).findall(f".//{ns}row"):
                values = []
                for cell in row_node.findall(f"{ns}c"):
                    index = _xlsx_column(cell.get("r", ""))
                    if index >= len(values):
                        values.extend([""] * (index - len(values) + 1))
                    values[index] = _xlsx_cell(cell, shared, ns)
                rows.append(values)
            for header_index, row in enumerate(rows[:20]):
                header = [re.sub(r"\s+", "", clean(value).casefold()) for value in row]
                name_columns = [i for i, value in enumerate(header) if value == "name"]
                if len(name_columns) < 2:
                    continue
                left, right = name_columns[:2]
                left_port = next((i for i in range(left + 1, right) if "port" in header[i]), None)
                right_port = next((i for i in range(right + 1, len(header)) if "port" in header[i]), None)
                if left_port is None or right_port is None:
                    continue
                columns = (left, left_port, right, right_port)
                for data in rows[header_index + 1:]:
                    if max(columns) < len(data):
                        values = tuple(clean(data[i]) for i in columns)
                        if all(usable(value) for value in values):
                            links.append(values)
                break
    if not links:
        raise UfmError(f"P2P 文件中没有找到两组 name+port 列: {path}")
    return links


def p2p_node_key(name: str) -> str:
    return re.sub(r"[-_]", "", first_label(name))


def ufm_port_links(plan: Plan, links: list, node: UfmNode, device: str) -> dict:
    """P2P links whose UFM-side port on this node resolves to the given device, keyed by peer endpoint."""
    key, found = p2p_node_key(node.hostname), {}
    for a, a_port, b, b_port in links:
        for name, port, peer, peer_port in ((a, a_port, b, b_port), (b, b_port, a, a_port)):
            if p2p_node_key(name) == key and resolve_ufm_port(plan, port) == device:
                found[(first_label(peer), clean(peer_port).casefold())] = (name, port, peer, peer_port)
    return found


def bind_ha_links(plan: Plan, links: list) -> None:
    ha = plan.logical.get("eth1")
    if len(plan.nodes) != 2 or not ha:
        return
    nodes = {p2p_node_key(node.hostname): node for node in plan.nodes}
    for node in list(plan.nodes):
        found = ufm_port_links(plan, links, node, ha)
        if not found:
            plan.warnings.append(f"{node.hostname}: P2P 中没有 {ha}（eth1/HA 直连）的连线")
            continue
        if len(found) > 1:   # B0-O7 (a): this UFM's own cabling
            skip_node(plan, node.hostname, f"P2P 中 {ha} 有多条连线: "
                      + "; ".join(f"{v[0]}:{v[1]} -> {v[2]}:{v[3]}" for v in found.values()))
            continue
        name, port, peer, peer_port = next(iter(found.values()))
        peer_node = nodes.get(p2p_node_key(peer))
        text = f"{name}:{port} - {peer}:{peer_port}"
        if peer_node is None or peer_node is node or resolve_ufm_port(plan, peer_port) != ha:
            plan.warnings.append(f"{node.hostname}: P2P 中 {ha} 接到 {peer}:{peer_port}，"
                                 f"不是另一台 UFM 的 {ha}")
            continue
        plan.ha_links[node.hostname] = (peer_node.hostname, ha, ha, text)


def bind_attachments(plan: Plan, links: list) -> None:
    """Where each management port is cabled. The peer is looked up by its first label among all ib.csv rows (the
    UFM side by p2p_node_key, 核对 A, A-M5); only a *jump peer is a jump (I-037 rule 3), and a peer that is not
    one, or not in ib.csv, is no error: that UFM is logged into directly (问题文档 :1563)."""
    for node in list(plan.nodes):
        found = ufm_port_links(plan, links, node, plan.mgmt_device)
        if not found:
            plan.warnings.append(f"{node.hostname}: P2P 中没有找到管理口 ({plan.mgmt_device}) 的连线；直接登录")
            continue
        if len(found) > 1:   # B0-O7 (a): this UFM's own cabling
            skip_node(plan, node.hostname, "P2P 中管理口有多条连线: "
                      + "; ".join(f"{v[0]}:{v[1]} -> {v[2]}:{v[3]}" for v in found.values()))
            continue
        name, port, peer, peer_port = next(iter(found.values()))
        leaf_port = f"swp{clean(peer_port)}" if clean(peer_port).isdigit() else clean(peer_port)
        if not SELECTOR_RE.fullmatch(leaf_port):
            skip_node(plan, node.hostname, f"P2P 对端端口无效 {peer_port!r}")
            continue
        leaves = plan.transits.get(first_label(peer), [])
        if len(leaves) > 1:
            skip_node(plan, node.hostname, f"P2P 对端 {peer} 在 ib.csv 中有多行")
            continue
        rows = plan.inventory.get(first_label(peer), [])
        peer_name, peer_type = ((leaves[0].hostname, leaves[0].dev_type) if leaves
                                else rows[0] if len(rows) == 1 else (clean(peer), ""))
        plan.links[node.hostname] = login_rules.Attachment(peer_name, peer_type, leaf_port)
        if leaves:
            plan.attachments[node.hostname] = Attachment(leaves[0], leaf_port, name, port)
    bind_bmc_attachments(plan, links)


BMC_PORT_NAMES = {"bmc", "idrac", "ipmi", "ilo", "imm"}


def bind_bmc_attachments(plan: Plan, links: list) -> None:
    """Where each UFM's BMC is cabled (P2P "ufm-01 BMC -> oob-leaf115 17"): the switch port whose FDB
    tells whether a device answering on the IPMI address is this UFM's own BMC."""
    for node in plan.nodes:
        key, found = p2p_node_key(node.hostname), []
        for a, a_port, b, b_port in links:
            for name, port, peer, peer_port in ((a, a_port, b, b_port), (b, b_port, a, a_port)):
                if p2p_node_key(name) == key and clean(port).casefold() in BMC_PORT_NAMES:
                    found.append((name, port, peer, peer_port))
        leaves = plan.transits.get(first_label(found[0][2]), []) if len(found) == 1 else []
        if len(leaves) == 1:
            name, port, peer, peer_port = found[0]
            leaf_port = f"swp{clean(peer_port)}" if clean(peer_port).isdigit() else clean(peer_port)
            if SELECTOR_RE.fullmatch(leaf_port):
                plan.bmc_attachments[node.hostname] = Attachment(leaves[0], leaf_port, name, port)


# ----------------------------------------------------------------- full plan

def build_plan(input_dir: Path) -> Plan:
    plan = Plan(input_dir)
    global_path, csv_path = input_dir / "01-global.yaml", input_dir / "ib.csv"
    policy_parts = {}
    for path in (global_path, csv_path):
        if not path.is_file():
            plan.errors.append(f"缺少输入文件 {path.name}（{path}）")
    if global_path.is_file():
        try:
            document = load_global(global_path)
            policy = find_ufm_policy(document, plan.errors)
            plan.dns, plan.ntp, plan.timezone, errors, warnings = host.infra_settings(document)
            plan.errors.extend(errors)
            plan.warnings.extend(warnings)
            parse_image_server(document, plan)
        except UfmError as exc:
            plan.errors.append(str(exc))
            policy = None
        if policy is not None:
            policy_parts = parse_policy(policy, plan)
    if csv_path.is_file():
        load_csv(csv_path, plan)
    assign_roles(plan)
    if policy_parts and plan.source_ufm_count in (1, 2):
        check_addresses(plan, policy_parts)
    p2p_path = input_dir / "p2p.xlsx"
    if not p2p_path.is_file():
        plan.warnings.append("缺少 p2p.xlsx；全部 UFM 直接登录（没有跳板）")
    elif plan.nodes and plan.mgmt_device:
        try:
            links = plan.p2p_links = parse_p2p_xlsx(p2p_path)
            bind_attachments(plan, links)
            bind_ha_links(plan, links)
        except UfmError as exc:
            plan.errors.append(str(exc))
    plan.public_keys, plan.key_lines, errors, warnings = host.read_public_keys(input_dir / "publickey")
    plan.errors.extend(errors)
    plan.warnings.extend(warnings)
    return plan


def parse_image_server(document: object, plan: Plan) -> None:
    """Images are served by the deployment server's HTTP (common.mgmt.http), as wget'ed by hand."""
    http = None
    if isinstance(document, dict):
        http = ((document.get("common") or {}).get("mgmt") or {}).get("http")
    if not isinstance(http, dict):
        plan.warnings.append("common.mgmt.http 未配置；upgrade 无法确定镜像下载地址")
        return
    address, port = clean(http.get("address")), clean(http.get("port") or "80")
    try:
        ipaddress.IPv4Address(address)
        if not 1 <= int(port) <= 65535:
            raise ValueError(port)
    except ValueError:
        plan.errors.append(f"common.mgmt.http 的 address/port 无效: {address!r}:{port!r}")
        return
    plan.image_server = f"http://{address}:{int(port)}"


def assign_roles(plan: Plan) -> None:
    """From every server_ufm row: a UFM skipped for its inputs keeps its role, so the other one never takes the
    wrong role block of global (B6 pair facts, v3.1.6 指导 8.6)."""
    names = plan.ufm_hostnames
    if len(names) == 1:
        plan.roles = {"primary": names[0]}
    elif len(names) == 2:
        primaries = [name for name in names if PRIMARY_LABEL_RE.search(first_label(name))]
        if len(primaries) != 1:
            plan.errors.append("无法确定安装期 primary：两台中必须恰好一台 hostname 第一段以 ufm01 结尾")
            return
        secondary = next(name for name in names if name != primaries[0])
        plan.roles = {"primary": primaries[0], "secondary": secondary}


def check_ipmi_gateway(plan: Plan, role: str, interface: ipaddress.IPv4Interface,
                       gateway: Optional[ipaddress.IPv4Address], mgmt_net: ipaddress.IPv4Network) -> None:
    """Without its own gateway the IPMI address shares the management subnet and uses eth0_gw; with
    `gateway` (owner 2026-10-21) it may sit in its own subnet, and the gateway must be usable there."""
    errors, network, where = plan.errors, interface.network, f"interfaces.{role}.ipmi"
    if gateway is None:
        if network != mgmt_net:
            errors.append(f"{where} ({interface}) 与 {plan.mgmt_device or 'eth0'} 管理网段 {mgmt_net} 不在同一网段，"
                          "ipmi 没有提供 gateway：请在 ipmi 下加 gateway")
        return
    if network != mgmt_net and network.overlaps(mgmt_net):
        errors.append(f"{where} ({interface}) 与管理网段 {mgmt_net} 部分重叠")
    elif gateway not in network or gateway in {network.network_address, network.broadcast_address}:
        errors.append(f"{where}.gateway {gateway} 不是 IPMI 网段 {network} 内的可用地址")
    elif gateway == interface.ip:
        errors.append(f"{where}.gateway {gateway} 与 IPMI 地址相同")
    else:
        plan.ipmi_gateways[role] = str(gateway)


def check_addresses(plan: Plan, parts: dict) -> None:
    """The pair or single shape of global follows the server_ufm rows; per-UFM clashes skip only the UFMs
    involved (B0-O7 (a)); global addresses (IPMI, VIP, HA links) stay run errors."""
    errors, blocks = plan.errors, parts.get("blocks", {})
    networks = {ipaddress.IPv4Interface(node.interface).network for node in plan.nodes}
    if len(networks) > 1:
        text = ", ".join(map(str, sorted(networks)))
        for node in list(plan.nodes):
            skip_node(plan, node.hostname, f"两台 UFM 的 eth0 必须在同一网段: {text}")
    mgmt_net = next(iter(networks)) if len(networks) == 1 else None
    if plan.source_ufm_count == 2:
        missing = [role for role in ROLES if role not in blocks]
        if missing:
            errors.append("双节点需要 interfaces." + " 和 interfaces.".join(missing))
        elif set(blocks["primary"]) != set(blocks["secondary"]):
            errors.append("interfaces.primary 与 secondary 的接口集合不同: "
                          f"{sorted(blocks['primary'])} / {sorted(blocks['secondary'])}")
        else:
            for device in blocks["primary"]:
                a, b = blocks["primary"][device], blocks["secondary"][device]
                if a.network != b.network:
                    errors.append(f"interfaces.primary.{device} ({a}) 与 secondary.{device} ({b}) 不在同一网段")
    elif "secondary" in blocks:
        errors.append("单节点不能配置 interfaces.secondary")
    owners = {}

    def claim(address: str, owner: str) -> None:
        if address in owners:
            errors.append(f"地址 {address} 同时用于 {owners[address]} 和 {owner}")
        if address in plan.foreign_addresses:
            errors.append(f"地址 {address}（{owner}）已在 ib.csv 中分配给 {plan.foreign_addresses[address]}")
        owners.setdefault(address, owner)

    for node in list(plan.nodes):
        if node.address in plan.foreign_addresses:
            skip_node(plan, node.hostname, f"地址 {node.address}（{node.hostname} eth0）已在 ib.csv 中分配给 "
                                           f"{plan.foreign_addresses[node.address]}")
        elif node.mac in plan.foreign_macs:
            skip_node(plan, node.hostname, f"{node.hostname} 的管理 MAC {node.mac} 已在 ib.csv 中属于 "
                                           f"{plan.foreign_macs[node.mac]}")
        else:
            claim(node.address, f"{node.hostname} eth0")
    for role, block in blocks.items():
        host = plan.roles.get(role, role)
        plan.addresses[role] = {device: str(interface) for device, interface in block.items()}
        for device, interface in block.items():
            claim(str(interface.ip), f"{host} {device}")
            if mgmt_net is not None and device != "ipmi" and interface.network.overlaps(mgmt_net):
                errors.append(f"interfaces.{role}.{device} ({interface}) 与管理网段 {mgmt_net} 重叠")
            if mgmt_net is not None and device == "ipmi":
                check_ipmi_gateway(plan, role, interface, parts.get("ipmi_gateways", {}).get(role), mgmt_net)
    vip = parts.get("vip")
    if plan.source_ufm_count == 1:
        if vip is not None:
            errors.append("单节点不能配置 vip")
        return
    if vip is None:
        errors.append("双节点需要 servers.ufm.vip")
        return
    try:
        address = ipaddress.IPv4Address(clean(vip))
    except ValueError:
        errors.append(f"servers.ufm.vip 不是 IPv4 地址: {vip!r}")
        return
    gateways = {node.gateway for node in plan.nodes}
    if mgmt_net is None:   # no complete UFM is left to tell the management subnet; nobody is logged into
        claim(str(address), "vip")
        plan.vip = str(address)
    elif address not in mgmt_net or address in {mgmt_net.network_address, mgmt_net.broadcast_address}:
        errors.append(f"vip {address} 必须是管理网段 {mgmt_net} 内的可用地址")
    elif str(address) in gateways:
        errors.append(f"vip {address} 与 eth0_gw 相同")
    else:
        claim(str(address), "vip")
        plan.vip = str(address)


# ----------------------------------------------------------------- reporting

class Reporter:
    def __init__(self, report: Optional[Path] = None):
        self.handle = report.open("a", encoding="utf-8") if report else None

    def __call__(self, message: str = "") -> None:
        print(message, flush=True)
        self.note(message)

    def note(self, message: str) -> None:
        """Report file only (for lines already shown on the terminal)."""
        if self.handle:
            self.handle.write(message + "\n")
            self.handle.flush()

    def close(self) -> None:
        if self.handle:
            self.handle.close()


def print_plan(plan: Plan, say: Callable[[str], None]) -> None:
    say(f"输入目录: {plan.input_dir}")
    say(f"版本: {plan.version or '未声明（跳过升级）'}    VIP: {plan.vip or '-'}")
    say("接口: " + (", ".join(f"{name} -> {device}" + ("（推断）" if name in plan.inferred else "")
                             for name, device in sorted(plan.logical.items())) or "?"))
    say(f"infra（common.switch.system）: DNS {' '.join(plan.dns) or '-'}    NTP {' '.join(plan.ntp) or '-'}    "
        f"时区 {plan.timezone or '-'}")
    for node in sorted(plan.nodes, key=lambda item: (plan.role_of(item) != "primary", item.hostname)):
        role = plan.role_of(node) or "?"
        extra = plan.addresses.get(role, {})
        say(f"[{role}] {node.hostname}")   # layout given by the owner, 2026-10-20
        say("    Interfaces:")
        say(f"      {plan.mgmt_device}: {node.interface}")
        for device in sorted(name for name in extra if name != "ipmi"):
            say(f"      {device}: {extra[device]}")
        if "ipmi" in extra:
            gateway = plan.ipmi_gateways.get(role)
            say(f"      ipmi: {extra['ipmi']}" + (f"  gw {gateway}" if gateway else ""))
        say("    Connections:")
        for device, attachment in ((plan.mgmt_device, plan.attachments.get(node.hostname)),
                                   ("ipmi", plan.bmc_attachments.get(node.hostname))):
            if attachment and device == plan.mgmt_device:
                say(f"      {device}: {attachment.leaf.hostname} ({attachment.leaf.login_ip}) {attachment.port}"
                    f"  [P2P {attachment.p2p_device}:{attachment.p2p_port}]")
                ha_link = plan.ha_links.get(node.hostname)
                if ha_link:
                    peer, ha_device, peer_device, text = ha_link
                    say(f"      {ha_device}: {peer} {peer_device}  [P2P {text}]")
            elif attachment:
                say(f"      {device}: {attachment.leaf.hostname} ({attachment.leaf.login_ip}) {attachment.port}"
                    f"  [P2P {attachment.p2p_device}:{attachment.p2p_port}]")
    spines = select_spine_inventory(plan)
    if spines:
        say("Spine 库存: " + ", ".join(f"{spine.hostname} ({spine.login_ip})" for spine in spines))
    say(f"publickey: {', '.join(plan.public_keys) or '无'}")
    for warning in plan.warnings:
        say(f"WARNING: {warning}")
    for error in plan.errors:
        say(f"ERROR: {error}")


def local_interfaces() -> tuple:
    """This management server's interfaces from `ip -j address show` (argv fixed). None at all when there is no
    `ip` (macOS) or it fails: every directly logged-in UFM then counts as on another subnet (v3.1.5 WP-1 item 3)."""
    try:
        result = subprocess.run(["ip", "-j", "address", "show"], capture_output=True, text=True, timeout=15,
                                check=False)
        return login_rules.parse_local_interfaces(result.stdout) if result.returncode == 0 else ()
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        return ()


def route_table(plan: Plan, direct: frozenset) -> dict:
    """I-037 rule 3, decided once before any login: hostname -> login_rules.Route of every complete UFM."""
    local = local_interfaces() if direct or any(node.hostname not in plan.attachments for node in plan.nodes) else ()
    same = {node.hostname: login_rules.same_subnet_interface(node.interface, local) if local else None
            for node in plan.nodes}
    return {route.hostname: route for route in
            login_rules.classify(plan.nodes, plan.links, direct=direct, same_subnet=same)}


def route_record(plan: Plan, routes: dict, hostname: str) -> dict:
    """The route columns kept in result.json: path, reason, jump, port, same_subnet and why it is skipped."""
    route = routes.get(hostname)
    if route is None:
        return {"path": "", "reason": "", "jump": None, "port": None, "same_subnet": None,
                "skip": "INPUT_INCOMPLETE" if hostname in plan.incomplete else ""}
    leaves = plan.transits.get(first_label(route.jump or ""), []) if route.path == "jump" else []
    skip = "JUMP_ADDRESS_INVALID" if leaves and not leaves[0].candidates else ""
    return {"path": route.path, "reason": route.reason, "jump": route.jump, "port": route.port,
            "same_subnet": route.same_subnet, "skip": skip}


def print_routes(plan: Plan, routes: dict, say: Callable[[str], None]) -> None:
    """The route table, before any login (I-037 设计 :67-73; 问题文档 :1561)."""
    say("登录路径（登录前归类）: 设备  路径  原因  跳板和端口  同网段  跳过")
    for hostname in plan.ufm_hostnames:
        record = route_record(plan, routes, hostname)
        if record["skip"] == "INPUT_INCOMPLETE":
            say(f"  {hostname}  -  -  -  -  INPUT_INCOMPLETE: {'; '.join(plan.incomplete[hostname])}")
        elif record["path"]:
            where = f"{record['jump']} {record['port']}" if record["jump"] else "-"
            say(f"  {hostname}  {'经跳板' if record['path'] == 'jump' else '直接登录'}  {record['reason']}  "
                f"{where}  同网段 {record['same_subnet'] or '否'}  {record['skip'] or '-'}")


# ----------------------------------------------------------------- SSH layer

@dataclass
class SessionResult:
    output: str
    exit_code: int


def strip_ansi(value: str) -> str:
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value).replace("\r", "")


def redact(text: str, secrets: tuple) -> str:
    for secret in sorted({value for value in secrets if value}, key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    return text


def interactive_run(command: list, responder: Callable[[str], object], timeout: int,
                    secrets: tuple = ()) -> SessionResult:
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execvp(command[0], command)
        except OSError:
            os._exit(127)
    output, status, deadline, aborted = "", None, time.monotonic() + timeout, False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise UfmError("SSH 会话超时，设备状态未知")
            if select.select([fd], [], [], min(0.2, remaining))[0]:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    chunk = b""
                if chunk:
                    output += chunk.decode("utf-8", errors="replace")
                    if len(output) > 4 * 1024 * 1024:
                        raise UfmError("SSH 输出超过安全上限")
                    if not aborted:
                        response = responder(strip_ansi(output))
                        if response is ABORT:
                            aborted = True
                            _signal(pid, signal.SIGTERM)
                        elif response is not None:
                            os.write(fd, str(response).encode("utf-8") + b"\n")
            ended, wait_status = os.waitpid(pid, os.WNOHANG)
            if ended:
                status = wait_status
                while select.select([fd], [], [], 0)[0]:
                    try:
                        chunk = os.read(fd, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    output += chunk.decode("utf-8", errors="replace")
                break
        return SessionResult(redact(strip_ansi(output), secrets), os.waitstatus_to_exitcode(status))
    finally:
        os.close(fd)
        if status is None:
            _signal(pid, signal.SIGKILL)
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass


def _signal(pid: int, number: int) -> None:
    for target in (lambda: os.killpg(pid, number), lambda: os.kill(pid, number)):
        try:
            target()
            return
        except PermissionError:
            continue
        except ProcessLookupError:
            return


def ssh_options(timeout: int) -> list:
    return ["-o", f"ConnectTimeout={timeout}", "-o", "ServerAliveInterval=10",
            "-o", "ServerAliveCountMax=2", "-o", "StrictHostKeyChecking=accept-new",
            "-o", "LogLevel=ERROR", "-o", "ControlMaster=no", "-o", "ControlPath=none"]


def ufm_ssh_options(timeout: int) -> list:
    return ssh_options(timeout) + [
        "-o", "NumberOfPasswordPrompts=1", "-o", "PubkeyAuthentication=no",
        "-o", "PreferredAuthentications=password,keyboard-interactive"]


def framed(command: list, marker: str) -> str:
    return ('printf "\\n__UFM_BEGIN_' + marker + '__\\n"; ' + shlex.join(command)
            + '; rc=$?; printf "\\n__UFM_END_' + marker + '__=%s\\n" "$rc"; exit "$rc"')


def extract_framed(output: str, marker: str) -> str:
    begin, end = "__UFM_BEGIN_" + marker + "__", "__UFM_END_" + marker + "__"
    matches = list(re.finditer(r"(?ms)^" + re.escape(begin) + r"\n(.*?)^" + re.escape(end)
                               + r"=([0-9]+)\s*$", output))
    if len(matches) != 1 or matches[0].group(2) != "0":
        raise UfmError("远端命令输出缺少完整的标记帧或退出码非 0；结果未知")
    return matches[0].group(1).strip("\n")


def leaf_argv(leaf: Transit, user: str, remote: list, timeout: int, *, tty: bool, batch: bool) -> list:
    script = "export PATH=" + shlex.quote(SAFE_PATH) + "; exec " + shlex.join(remote)
    auth = ["-o", "BatchMode=yes"] if batch else ["-o", "NumberOfPasswordPrompts=1"]
    return ["ssh", *(["-tt"] if tty else []), *ssh_options(timeout), *auth,
            f"{user}@{leaf.login_ip}", shlex.join(["sh", "-c", script])]


def direct_ufm_argv(address: str, user: str, remote: list, marker: str, timeout: int) -> list:
    return ["ssh", "-tt", *ufm_ssh_options(timeout), f"{user}@{address}",
            shlex.join(["sh", "-c", framed(remote, marker)])]


def nested_ufm_argv(leaf: Transit, eth_user: str, neighbor: "Neighbor", user: str,
                    remote: list, marker: str, timeout: int, *, batch: bool) -> list:
    inner = ["ip", "vrf", "exec", neighbor.vrf, "ssh", "-6", "-tt", *ufm_ssh_options(timeout),
             "-B", neighbor.interface, f"{user}@{neighbor.ipv6}",
             shlex.join(["sh", "-c", framed(remote, marker)])]
    return leaf_argv(leaf, eth_user, inner, timeout, tty=True, batch=batch)


class Responder:
    """Answers leaf and UFM password prompts and an enforced password change."""

    def __init__(self, *, ufm_destination: str, login_password: str, new_password: str,
                 allow_change: bool, outer_password: str = "", extra: tuple = ()):
        self.ufm_destination = ufm_destination
        self.login_password = login_password
        self.new_password = new_password
        self.allow_change = allow_change
        self.outer_password = outer_password
        self.extra = extra
        self.counts = {}
        self.change_required = False
        self.change_blocked = False
        self.change_attempted = False
        self.bad_password = ""
        # A second password prompt for the same target means the first answer was rejected: sshd
        # retries password auth through keyboard-interactive ("(root@host) Password:").
        self.rejected = False
        self.outer_rejected = False

    def _new(self, key: str, pattern: str, text: str) -> bool:
        count = len(re.findall(pattern, text, re.I | re.M))
        if count > self.counts.get(key, 0):
            self.counts[key] = count
            return True
        return False

    def __call__(self, text: str) -> object:
        bad = _BAD_NEW_PASSWORD.search(text)
        if bad and self.change_attempted:
            self.bad_password = bad.group(0).strip()
            return ABORT
        if _EXPIRED.search(text):
            self.change_required = True
            if not self.allow_change:
                self.change_blocked = True
                return ABORT
        for key, pattern, value in self.extra:
            if self._new(key, pattern, text):
                return value
        for key, pattern in (
            ("current", r"^\s*(?:\(current\)|current|old)[^\n]*password\s*:\s*$"),
            ("retype", r"^\s*[^\n]*(?:retype|repeat|confirm)[^\n]*password\s*:\s*$"),
            ("new", r"^(?![^\n]*(?:retype|repeat|confirm))[^\n]*new[^\n]*password\s*:\s*$"),
        ):
            if self._new(key, pattern, text):
                if not self.allow_change:
                    self.change_blocked = True
                    return ABORT
                if key == "current":
                    return self.login_password
                self.change_attempted = True
                return self.new_password
        if self._new("hostkey", r"are you sure you want to continue connecting", text):
            return "yes"
        prompts = re.findall(r"(?im)^([^\n]*@[^\n]*password):\s*$", text)
        ufm = [line for line in prompts if self.ufm_destination in line]
        outer = [line for line in prompts if line not in ufm]
        if len(ufm) > self.counts.get("ufm", 0):
            self.counts["ufm"] = len(ufm)
            if len(ufm) == 1:
                return self.login_password
            self.rejected = True
            return ABORT
        if len(outer) > self.counts.get("outer", 0):
            self.counts["outer"] = len(outer)
            if len(outer) == 1 and self.outer_password:
                return self.outer_password
            self.outer_rejected = len(outer) > 1
            return ABORT
        return None


def classify(result: SessionResult, responder: Responder, marker: str) -> str:
    output = result.output
    if responder.bad_password:
        return "NEW_PASSWORD_REJECTED"
    if responder.change_blocked:
        return "PASSWORD_CHANGE_REQUIRED"
    if responder.change_attempted:
        # sshd + PAM print no success line: the session simply continues and runs the command.
        try:
            extract_framed(output, marker)
            framed_ok = result.exit_code == 0
        except UfmError:
            framed_ok = False
        return "PASSWORD_CHANGED" if framed_ok or _UPDATED.search(output) else "PASSWORD_CHANGE_UNKNOWN"
    if responder.rejected:
        return "AUTH_REJECTED"
    if responder.outer_rejected:
        return "LEAF_AUTH_REJECTED"
    if result.exit_code == 0:
        try:
            extract_framed(output, marker)
            return "OK"
        except UfmError:
            return "UNKNOWN"
    if _HOSTKEY_CONFLICT.search(output):
        return "HOSTKEY_CONFLICT"
    for line in re.findall(r"(?im)^[^\n]*permission denied[^\n]*$", output):
        if responder.ufm_destination in line:
            return "AUTH_REJECTED"
        if re.search(r"@\S+: permission denied", line, re.I):
            return "LEAF_AUTH_REJECTED"
    if _UNREACHABLE.search(output):
        return "UNREACHABLE"
    if _REFUSED.search(output):
        return "REFUSED"
    return "UNKNOWN"


# ------------------------------------------------------- OOB leaf discovery

@dataclass(frozen=True)
class Neighbor:
    ipv6: str
    interface: str
    vrf: str
    source: str


def ip_link_blocks(table: str) -> dict:
    blocks, current = {}, None
    header = re.compile(r"^\s*\d+:\s+([^:@\s]+)(?:@[^:\s]+)?:\s+(.*)$")
    for line in table.splitlines():
        match = header.match(line)
        if match:
            current = match.group(1)
            blocks.setdefault(current, []).append(line)
        elif current is not None:
            blocks[current].append(line)
    return blocks


def fdb_port(table: str, port: str) -> str:
    blocks = ip_link_blocks(table)
    if port not in blocks:
        raise UfmError(f"{port} 不在 'ip -d link show' 输出中")
    master = re.search(r"(?:^|\s)master\s+(\S+)", blocks[port][0])
    if not master:
        return port
    name = master.group(1).split("@", 1)[0]
    if name not in blocks:
        raise UfmError(f"{port} 的 master {name} 不在 'ip -d link show' 输出中")
    return name if re.search(r"(?m)^\s*bond\s+mode\s+", "\n".join(blocks[name])) else port


def fdb_entries(fdb: str, port: str) -> list:
    entries = []
    for line in fdb.splitlines():
        fields = line.split()
        if "dev" not in fields or fields.index("dev") + 1 >= len(fields):
            continue
        flags = {value.casefold() for value in fields}
        if fields[fields.index("dev") + 1] != port or flags & {"permanent", "static", "local", "self"}:
            continue
        match = MAC_RE.search(line)
        if not match:
            continue
        vlan = fields[fields.index("vlan") + 1] if "vlan" in fields and fields.index("vlan") + 1 < len(fields) else ""
        bridge = fields[fields.index("master") + 1] if "master" in fields and fields.index("master") + 1 < len(fields) else ""
        entries.append((match.group(0).casefold(), vlan, bridge))
    return entries


def vlan_svi_interfaces(table: str, vlan: str, bridge: Optional[str] = None) -> list:
    """Real 802.1Q SVIs only; a VRR macvlan such as vlan1000-v0 is not one."""
    result = []
    for name, block in ip_link_blocks(table).items():
        parent = re.match(r"\s*\d+:\s+[^:@\s]+@([^:\s]+):", block[0])
        ids = re.findall(r"(?m)^\s*vlan\s+protocol\s+802\.1(?:Q|ad)\s+id\s+(\d+)\b", "\n".join(block))
        if parent and ids == [str(int(vlan))] and (bridge is None or parent.group(1) == bridge):
            result.append(name)
    return result


def parse_oob_addresses(text: str) -> list:
    try:
        payload = json.loads(text)
        if not isinstance(payload, list):
            raise ValueError("not a list")
        seen = set()
        for row in payload:
            if (not isinstance(row, dict) or not isinstance(row.get("ifname"), str)
                    or not isinstance(row.get("addr_info"), list) or row["ifname"] in seen
                    or not SELECTOR_RE.fullmatch(row["ifname"])
                    or any(not isinstance(item, dict) for item in row["addr_info"])):
                raise ValueError("invalid interface row")
            seen.add(row["ifname"])
        return payload
    except (ValueError, TypeError) as exc:
        raise UfmError("'ip -j address show' 输出无效；不能据此判断 SVI 是否有地址") from exc


def owns_address(rows: list, address: str) -> bool:
    """Identity by address (owner 2026-10-19: no host names in connectivity tests or verification):
    the switch we logged into must carry its CSV login address on one of its own interfaces."""
    wanted = ipaddress.ip_address(address)
    for row in rows:
        for item in row.get("addr_info", []):
            try:
                if ipaddress.ip_address(item.get("local", "")) == wanted:
                    return True
            except ValueError:
                continue
    return False


def svi_address_ready(rows: list, interface: str, *, require_ipv6: bool = False) -> bool:
    matches = [row for row in rows if row.get("ifname") == interface]
    if len(matches) != 1:
        return False
    row = matches[0]
    if require_ipv6 and ("UP" not in row.get("flags", [])
                         or str(row.get("operstate", "")).upper() in {"DOWN", "LOWERLAYERDOWN", "NOTPRESENT"}):
        return False
    ipv4 = ipv6 = False
    for item in row.get("addr_info", []):
        if (set(item.get("flags", [])) & {"tentative", "dadfailed"} or item.get("tentative")
                or item.get("dadfailed") or item.get("valid_life_time") == 0):
            continue
        try:
            value = ipaddress.ip_address(item.get("local", ""))
        except ValueError:
            continue
        if value.is_unspecified or value.is_multicast or value.is_loopback:
            continue
        ipv4 |= value.version == 4 and item.get("family") == "inet"
        ipv6 |= value.version == 6 and value.is_link_local and item.get("family") == "inet6"
    return ipv4 and (ipv6 or not require_ipv6)


def interface_oper_status(table: str, interface: str) -> str:
    pattern = re.compile(rf"^\s*[|│┃]?\s*{re.escape(interface)}(?:\s|[|│┃]|$)", re.I)
    rows = list(dict.fromkeys(line.strip() for line in table.splitlines() if pattern.search(line)))
    if len(rows) != 1:
        raise UfmError(f"'nv show interface' 中 {interface} 有 {len(rows)} 行，无法判断状态")
    fields = rows[0].translate(str.maketrans({"|": " ", "│": " ", "┃": " "})).split()
    if len(fields) < 3 or fields[0].casefold() != interface.casefold():
        raise UfmError(f"无法解析 {interface} 的 Oper Status: {rows[0]}")
    return fields[2].casefold()


def lldp_identity(peer: str, hostname: str) -> bool:
    a, b = clean(peer).casefold().rstrip("."), clean(hostname).casefold().rstrip(".")
    return a == b or (("." not in a or "." not in b) and a.split(".")[0] == b.split(".")[0])


def all_transits(plan: Plan) -> list:
    return [item for items in plan.transits.values() for item in items]


def select_spine_inventory(plan: Plan, explicit: Optional[str] = None) -> list:
    """Role hint only; live Leaf LLDP is still required before any Spine is used."""
    items = [item for item in all_transits(plan) if item.dev_type == "eth_jump"]
    if explicit is None:
        return sorted((item for item in items if first_label(item.hostname).startswith("oob-spine")),
                      key=lambda item: item.hostname.casefold())
    names = [name.strip() for name in explicit.split(",")]
    if not names or any(not host.valid_hostname(name) for name in names):
        raise UfmError("--oob-spines 需要逗号分隔的 CSV 主机名")
    result = {}
    for name in names:
        matches = [item for item in items if lldp_identity(name, item.hostname)]
        if len(matches) != 1:
            raise UfmError(f"--oob-spines {name}: 在 ib.csv 的 eth_jump 中缺失或不唯一")
        if matches[0].hostname in result:
            raise UfmError(f"--oob-spines 重复: {name}")
        result[matches[0].hostname] = matches[0]
    return list(result.values())


def lldp_spine_candidates(table: str, inventory: list) -> list:
    """Only UP rows of the Remote Host column; never descriptions or CSV alone."""
    columns, result = None, {}
    for line in table.splitlines():
        if all(label in line for label in ("Interface", "Oper Status", "Remote Host", "Remote Port")):
            columns = {match.group(0).strip(): match.start()
                       for match in re.finditer(r"\S(?:.*?\S)?(?=\s{2,}|$)", line)}
            if not {"Interface", "Oper Status", "Remote Host", "Remote Port"} <= set(columns):
                raise UfmError("'nv show interface' 的 LLDP 表头无法识别")
            continue
        if columns is None or not line.strip() or re.fullmatch(r"[\s-]+", line):
            continue

        def column(label: str) -> str:
            start = columns[label]
            end = min((value for value in columns.values() if value > start), default=len(line))
            return clean(line[start:end])
        if not column("Interface") or column("Oper Status").casefold() != "up":
            continue
        peer = column("Remote Host")
        if not usable(peer) or not column("Remote Port"):
            continue
        matches = [item for item in inventory if lldp_identity(peer, item.hostname)]
        if len(matches) > 1:
            raise UfmError(f"LLDP 邻居 {peer} 对应多个 CSV Spine")
        if matches:
            result[matches[0].hostname.casefold()] = matches[0]
    return [result[key] for key in sorted(result)]


def csv_neighbor(mac: str, interface: str, vrf: str) -> Neighbor:
    """I-037 rule 5: the UFM's link-local is always the EUI-64 of its CSV MAC, through a Leaf or a Spine alike
    (B0-O4 (a)); no neighbour table is read."""
    return Neighbor(login_rules.link_local_from_mac(mac), interface, vrf, "CSV_EUI64")


def leaf_cable_check(node: UfmNode, attachment: Attachment, tables: dict, *, others: tuple = (),
                     cascade_ports: frozenset = frozenset(), after_ping: bool = False,
                     ping_ok: Optional[bool] = None) -> "login_rules.CableCheck":
    """I-037 rules 4-6 in one call (login_path.check_cable): the expected jump's links/fdb/vlans first, other jumps'
    JumpTables when given; the verdict is MATCH, ELSEWHERE or NOT_LEARNED."""
    expected = login_rules.JumpTables(attachment.leaf.hostname, tables["links"], tables["fdb"], tables["vlans"])
    return login_rules.check_cable(node.hostname, node.mac, (attachment.leaf.hostname, attachment.port),
                                   [expected, *others], cascade_ports=cascade_ports, after_ping=after_ping,
                                   ping_ok=ping_ok)


def cascade_ports(plan: Plan) -> frozenset:
    """(jump, port) of every P2P link between two *jump rows: a MAC seen there is not where a UFM is cabled."""
    result = set()
    for a, a_port, b, b_port in plan.p2p_links:
        ends = [(plan.transits.get(first_label(name), []), clean(port)) for name, port in ((a, a_port), (b, b_port))]
        if all(len(leaves) == 1 for leaves, _port in ends):
            result.update((leaves[0].hostname, f"swp{port}" if port.isdigit() else port) for leaves, port in ends)
    return frozenset(result)


def cabling_fact(check: "login_rules.CableCheck", attachment: Attachment, port_state: str) -> dict:
    """facts["cabling"] (B0-O5): outcome, detail, expected (CSV MAC) and observed (dynamic MACs on the expected
    port) keep their meaning; expected_port, actual_ports, after_ping, ping_ok and ignored are added."""
    where = f"{attachment.leaf.hostname} {attachment.port}"
    actual = [f"{host} {port}" for host, port in check.actual]
    if check.verdict == "MATCH":
        detail = f"{where} 学到 {check.mac}" + (
            f"；端口上另有 {', '.join(check.extra_macs)}" if check.extra_macs else "")
    elif check.verdict == "ELSEWHERE":
        detail = f"预期 {where}；CSV MAC {check.mac} 出现在 {', '.join(actual)}"
    else:
        detail = f"预期 {where} 没有学到 CSV MAC {check.mac}"
    if check.verdict != "MATCH":
        if check.after_ping:
            detail += f"；ping 后仍没学到（ping {'通' if check.ping_ok else '不通'}）"
        detail += f"；{port_state}"
    return {"outcome": check.verdict, "detail": detail, "expected": check.mac,
            "observed": sorted(set(([check.mac] if check.verdict == "MATCH" else []) + list(check.extra_macs))),
            "expected_port": where, "actual_ports": actual, "after_ping": check.after_ping,
            "ping_ok": check.ping_ok, "ignored": False}


def local_neighbor_mac(address: str) -> Optional[str]:
    """The MAC of this server's neighbour entry for an IPv4 (`ip -4 neigh show <address>`), or None."""
    try:
        result = subprocess.run(["ip", "-4", "neigh", "show", address], capture_output=True, text=True, timeout=15,
                                check=False)
        return login_rules.neighbor_mac(result.stdout, address) if result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


# ------------------------------------------------------------------ login

@dataclass
class Credentials:
    ufm_user: str
    new_password: str
    factory_password: str
    eth_user: str
    eth_password: Optional[str] = None
    ipmi_password: str = ""


@dataclass
class NodeResult:
    hostname: str
    role: str
    status: str = "PENDING"
    path: str = ""
    detail: str = ""
    password: str = ""
    route: dict = field(default_factory=dict)
    neighbor: dict = field(default_factory=dict)
    facts: dict = field(default_factory=dict)
    attempts: list = field(default_factory=list)
    steps: list = field(default_factory=list)
    # v3.1.6 B0 (B0-O5; only added, none of the fields above changes its meaning)
    login_route: dict = field(default_factory=dict)   # the route decided before login (route_record)
    identity: dict = field(default_factory=dict)      # expected/observed when the identity check fails
    input_issues: list = field(default_factory=list)  # INPUT_INCOMPLETE: this UFM's own input problems
    host_key: dict = field(default_factory=dict)      # the management-server host-key record (WP-6)


def identity_command(device: str) -> list:
    if not host.IFNAME_RE.fullmatch(device):
        raise UfmError(f"管理接口名无效: {device!r}")
    path = shlex.quote(f"/sys/class/net/{device}/address")
    script = (
        'printf "hostname=%s\\n" "$(hostname)"; '
        f'printf "mac=%s\\n" "$(cat {path} 2>/dev/null)"; '
        f'printf "ipv4=%s\\n" "$(ip -4 -o addr show dev {shlex.quote(device)} 2>/dev/null '
        "| awk '{print $4}' | tr '\\n' ' ')\"; "
        'printf "os=%s\\n" "$(. /etc/os-release 2>/dev/null; printf %s "$PRETTY_NAME")"; '
        # v3.1.6 B0 (I-037 rule 8): the default route, one line per route joined by ";"
        'printf "route=%s\\n" "$(ip route show default 2>/dev/null | tr \'\\n\' \';\')"')
    return ["sh", "-c", script]


# Owner 2026-10-20: every script run on the UFM is kept here, named <execution order>-<step>.sh.
REMOTE_WORK = "/root/.setup"
SCRIPT_TAG = "__UFM_SCRIPT__="
REMOTE_BACKUP = "/root/ufm-setup-upgrade-backup"


def framed_status(output: str, marker: str) -> tuple:
    """(body, rc) of the single marker frame, or (None, None) when the frame is missing."""
    begin, end = "__UFM_BEGIN_" + marker + "__", "__UFM_END_" + marker + "__"
    matches = list(re.finditer(r"(?ms)^" + re.escape(begin) + r"\n(.*?)^" + re.escape(end)
                               + r"=([0-9]+)\s*$", output))
    if len(matches) != 1:
        return None, None
    return matches[0].group(1).strip("\n"), int(matches[0].group(2))


def bash_syntax_problem(text: str) -> str:
    """`bash -n` on the deployment server: the error text, or "" when the script parses."""
    try:
        checked = subprocess.run(["bash", "-n"], input=text, text=True, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"本地 bash -n 无法运行: {exc}"
    return "" if checked.returncode == 0 else (checked.stderr.strip() or f"bash -n 退出码 {checked.returncode}")


UPGRADE_LOG = "/var/log/ufm-setup-upgrade-os-upgrade.log"
STAMP_RE = re.compile(r"^[0-9]{8}-[0-9]{2}_[0-9]{2}_[0-9]{2}$")


# The block of one upgrade in the newest status log (I-008 expectation 3, v3.1.6 B2-O1 (a)): from the last
# `UFM_OS_UPGRADE ... [STARTED` line stamped at or after `since` ("" = the last one) to the end, whatever the
# later lines' own timestamps (NTP may set the clock back during the reboot). complete: UFM-OS-UPGRADE and
# UFM-OS-FIRSTBOOT PASSED without FAILED (expectation 2); a STARTED line alone is incomplete.
UPGRADE_BLOCK_AWK = r"""{ line[NR] = $0 }
substr($1, 1, 17) >= since && $2 == "UFM_OS_UPGRADE" && $0 ~ /\[ *STARTED/ { n = NR }
END {
  block = "incomplete"
  if (n) {
    started = substr(line[n], 1, 17)
    for (i = n; i <= NR; i++) {
      if (split(line[i], f, " ") < 2) continue
      result = line[i]; sub(/.*\[ */, "", result); sub(/ *\].*/, "", result)
      last_stamp = substr(f[1], 1, 17); last_step = f[2]
      if (f[2] == "UFM-OS-UPGRADE") os_upgrade = result
      if (f[2] == "UFM-OS-FIRSTBOOT") firstboot = result
      if (result == "FAILED") { failed = line[i]; gsub(/ +/, " ", failed) }
    }
    if (failed != "") block = "failed"
    else if (os_upgrade == "PASSED" && firstboot == "PASSED") block = "complete"
  }
  printf "started=%s\nlast_step=%s\nlast_stamp=%s\nos_upgrade=%s\nfirstboot=%s\nfailed=%s\nblock=%s\n", started, last_step, last_stamp, os_upgrade, firstboot, failed, block
}"""
# Active transient units of ufm-setup-upgrade's own upgrades (the start script names them ufm-os-upgrade-<n>).
UPGRADE_UNITS = ("$(systemctl list-units --state=active --no-legend --plain 'ufm-os-upgrade-*' 2>/dev/null "
                 "| awk '{ printf \"%s%s\", sep, $1; sep = \" \" }')")
UPGRADE_DIAG_MARK = "----ufm-setup-upgrade-stall-diagnostics----"


def upgrade_block_lines(since: str) -> str:
    """bash: status_log=, then the block facts of UPGRADE_BLOCK_AWK (block=none without a status log);
    leaves the verdict in $block. `since` is a checked stamp or ""."""
    return ("log=$(ls -t /var/log/ufm_os_upgrade_*_status.log 2>/dev/null | head -n 1)\n"
            "printf 'status_log=%s\\n' \"$log\"\n"
            f"if [ -n \"$log\" ]; then facts=$(awk -v since={shlex.quote(since)} {shlex.quote(UPGRADE_BLOCK_AWK)} "
            "\"$log\"); else facts='block=none'; fi\n"
            "printf '%s\\n' \"$facts\"\n"
            "block=$(printf '%s\\n' \"$facts\" | sed -n 's/^block=//p')\n")


def upgrade_status_script(since: str, unit: str = "", diagnose: bool = False) -> str:
    """Read-only, one per probe while waiting: version, this run's block of the status log (from the STARTED
    line stamped at or after `since`, the start script's started_at), the state of the unit the start script
    named and the boot id (I-008 expectations 3 and 4). `diagnose` adds `systemctl list-jobs` and the CGroup
    part of `systemctl status <unit>` after UPGRADE_DIAG_MARK lines."""
    if not STAMP_RE.fullmatch(since):
        raise UfmError(f"升级开始时间戳无效: {since!r}")
    if unit and not SELECTOR_RE.fullmatch(unit):
        raise UfmError(f"升级单元名无效: {unit!r}")
    text = ("set -u\n"
            "printf 'appliance=%s\\n' \"$(grep -E '^UFM_APPLIANCE=' /etc/ufm-release 2>/dev/null "
            "| head -n 1 | cut -d= -f2)\"\n"
            + upgrade_block_lines(since)
            + (f"printf 'unit_state=%s\\n' \"$(systemctl is-active {shlex.quote(unit)} 2>/dev/null || true)\"\n"
               if unit else "printf 'unit_state=\\n'\n")
            + "printf 'boot_id=%s\\n' \"$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)\"\n")
    if diagnose and unit:
        text += (f"echo {UPGRADE_DIAG_MARK}\n"
                 "systemctl list-jobs --no-pager 2>&1 || true\n"
                 f"echo {UPGRADE_DIAG_MARK}\n"
                 f"systemctl status {shlex.quote(unit)} --no-pager 2>&1 "
                 "| awk '/CGroup:/ { p = 1 } p && /^$/ { exit } p' || true\n")
    return text


def image_name(version: str) -> str:
    if not VERSION_RE.fullmatch(version):
        raise UfmError(f"版本号无效: {version!r}")
    return f"ufm-appliance-{version}-omu.x86_64.tar"


def upgrade_start_script(version: str, url: str) -> str:
    """As in ufm-manual.log: wget, tar, stop ufm-enterprise, then ufm-os-upgrade.sh (it reboots).

    The upgrade outlives this SSH session (reboot), so it runs as a transient systemd unit.
    """
    image = image_name(version)
    folder = image[:-len(".tar")]
    if not re.fullmatch(r"http://[0-9.]+:[0-9]+/image/[A-Za-z0-9._+-]+", url):
        raise UfmError(f"镜像地址无效: {url!r}")
    command = (f"cd /root/{folder} && bash ./ufm-os-upgrade.sh --appliance-sw-upgrade -r -y "
               f"> {UPGRADE_LOG} 2>&1")
    # I-008 (v3.1.6 B2): an upgrade under way (an active unit; or the target version with an unfinished block)
    # is never started again; at the target version only a complete block or no status log at all is done.
    in_progress = (f'units={UPGRADE_UNITS}\n'
                   'if [ -n "$units" ]; then printf "units=%s\\n" "$units"; echo "result=in_progress"; exit 0; fi\n')
    return ("set -eu\n"
            "before=$(grep -E '^UFM_APPLIANCE=' /etc/ufm-release 2>/dev/null | head -n 1 | cut -d= -f2 || true)\n"
            'printf "before=%s\\n" "$before"\n'
            + in_progress
            + f'if [ "$before" = {shlex.quote(version)} ]; then\n'
            + upgrade_block_lines("")
            + '  case "$block" in none|complete) echo "result=already";; failed) echo "result=failed";; '
              '*) echo "result=in_progress";; esac\n'
              "  exit 0\n"
              "fi\n"
            # No checksum (owner), but a file left by an interrupted or older download must not be
            # reused: keep it only when its size equals the server's Content-Length.
            f"remote_size=$(wget -q --spider -S {shlex.quote(url)} 2>&1 | awk 'tolower($1) == \"content-length:\" "
            "{print $2}' | tail -n 1 | tr -d '\\r' || true)\n"
            f"local_size=$(wc -c 2>/dev/null < /root/{image} | tr -d ' ' || true)\n"
            'printf "remote_size=%s\\nlocal_size=%s\\n" "$remote_size" "$local_size"\n'
            f'if [ -s /root/{image} ] && [ -n "$remote_size" ] && [ "$local_size" = "$remote_size" ]; then\n'
            '  echo "image=reused"\n'
            "else\n"
            f"  rm -f /root/{image}.part\n"
            f"  wget -q -O /root/{image}.part {shlex.quote(url)}\n"
            f"  mv /root/{image}.part /root/{image}\n"
            '  echo "image=downloaded"\n'
            "fi\n"
            # always (re-)extract so an interrupted earlier extraction cannot leave a partial tree
            f"tar -C /root/ -xf /root/{image}\n"
            f'[ -f /root/{folder}/ufm-os-upgrade.sh ] || {{ echo "result=missing_upgrade_script"; exit 6; }}\n'
            "systemctl stop ufm-enterprise || true\n"
            "state=$(systemctl is-active ufm-enterprise || true)\n"
            'printf "ufm_enterprise=%s\\n" "$state"\n'
            'case "$state" in active|activating|reloading) echo "result=ufm_enterprise_running"; exit 7;; esac\n'
            # again right before the start: nobody may have started one while this script downloaded
            + in_progress
            # I-008 expectation 1: apt's needrestart hook skips itself when NEEDRESTART_SUSPEND is set; the unit
            # name and the boot id let the wait report the unit and the reboot (expectation 4)
            + 'unit="ufm-os-upgrade-$(date +%s)"\n'
              'printf "unit=%s\\n" "$unit"\n'
              'printf "boot_id=%s\\n" "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)"\n'
              'printf "started_at=%s\\n" "$(date +%Y%m%d-%H_%M_%S)"\n'
              'systemd-run --quiet --unit "$unit" --setenv=NEEDRESTART_SUSPEND=1 /bin/bash -c '
            + f"{shlex.quote(command)}\n"
              'echo "result=started"\n')


def netplan_applied_script(backup: str) -> str:
    """Read-only: the exit code the deferred `netplan apply` recorded (empty while it has not run yet)."""
    quoted = shlex.quote(backup)
    return ("set -u\n"
            f"printf 'rc=%s\\n' \"$(cat {quoted}/netplan-apply.rc 2>/dev/null || true)\"\n"
            f"printf 'log=%s\\n' \"$(tail -c 300 {quoted}/netplan-apply.log 2>/dev/null | tr '\\n' ' ')\"\n")


STOP_UFM_ENTERPRISE_SCRIPT = (
    "set -u\n"
    "systemctl stop ufm-enterprise || true\n"
    "printf 'state=%s\\n' \"$(systemctl is-active ufm-enterprise 2>/dev/null || true)\"\n")


def ipmi_getaccess_script(channel: int, uid: int) -> str:
    """Read-only: the channel access of one IPMI user slot (inspect mode)."""
    if not 1 <= int(channel) <= 15 or not 1 <= int(uid) <= 63:
        raise UfmError(f"IPMI 通道或用户 ID 无效: {channel} {uid}")
    return f"set -eu\nipmitool channel getaccess {int(channel)} {int(uid)}\n"


def upgrade_probe_script(url: str) -> str:
    """Read-only: current appliance version, ufm-enterprise state and whether the image can be fetched; the
    last block of the newest status log and the active upgrade units (I-008 expectation 2, v3.1.6 B2)."""
    if not re.fullmatch(r"http://[0-9.]+:[0-9]+/image/[A-Za-z0-9._+-]+", url):
        raise UfmError(f"镜像地址无效: {url!r}")
    image = "/root/" + url.rsplit("/", 1)[1]
    # Same reuse rule as upgrade_start_script, so the confirmation names the action that will run:
    # a left-over file is reused only when its size equals the server's Content-Length.
    return ("set -u\n"
            "printf 'before=%s\\n' \"$(grep -E '^UFM_APPLIANCE=' /etc/ufm-release 2>/dev/null "
            "| head -n 1 | cut -d= -f2)\"\n"
            "printf 'ufm_enterprise=%s\\n' \"$(systemctl is-active ufm-enterprise 2>/dev/null || true)\"\n"
            f"headers=$(wget -q --spider -S {shlex.quote(url)} 2>&1); rc=$?\n"
            'if [ "$rc" = 0 ]; then echo image_remote=yes; else echo image_remote=no; fi\n'
            "remote_size=$(printf '%s\\n' \"$headers\" | awk 'tolower($1) == \"content-length:\" {print $2}' "
            "| tail -n 1 | tr -d '\\r')\n"
            f"local_size=$(wc -c 2>/dev/null < {image} | tr -d ' ' || true)\n"
            'printf "remote_size=%s\\nlocal_size=%s\\n" "$remote_size" "$local_size"\n'
            'if [ -n "$local_size" ] && [ "$local_size" != 0 ] && [ -n "$remote_size" ] '
            '&& [ "$local_size" = "$remote_size" ]; then echo image_local=reuse; else echo image_local=no; fi\n'
            + upgrade_block_lines("")
            + f'printf "units=%s\\n" "{UPGRADE_UNITS}"\n')


def address_probe_command(vrf: str, interface: str, address: str) -> list:
    """Run on an OOB Leaf/Spine (read-only): ping out of the SVI that owns the subnet so the switch
    ARPs for the address, then report the neighbour entry. The leading `:` line names the probe."""
    if not SELECTOR_RE.fullmatch(vrf) or not SELECTOR_RE.fullmatch(interface):
        raise UfmError(f"VRF 或接口名无效: {vrf!r} {interface!r}")
    ip = str(ipaddress.IPv4Address(address))
    # With an EVPN anycast gateway the reply goes to the host's own Leaf, and the entry for a remote host
    # arrives as `extern_learn` a moment later: without a reply or a confirmed entry, read once more.
    neigh = f"ip neigh show {ip} dev {interface} 2>/dev/null | head -n 1"
    script = (f": addr-probe {ip} {interface}\n"
              f"if ip vrf exec {vrf} ping -c 2 -W 1 -I {interface} {ip} >/dev/null 2>&1; then p=yes; else p=no; fi\n"
              f"n=$({neigh})\n"
              'case "$p $n" in "yes "*|*REACHABLE*|*NOARP*|*PERMANENT*) ;; '
              f"*) sleep 2; n=$({neigh});; esac\n"
              "printf 'ping=%s\\nneigh=%s\\n' \"$p\" \"$n\"\n")
    return ["sh", "-c", script]


def address_owner(facts: dict) -> str:
    """The MAC that currently answers for the address, or "" when nothing does. Only a confirmed entry
    counts: a STALE/FAILED neighbour left by an address that has just moved away is not an owner."""
    line = facts.get("neigh", "").casefold()
    match = re.search(r"lladdr ((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\b", line)
    # The state is not always the word after the MAC: an EVPN entry reads "lladdr M extern_learn NOARP proto zebra".
    if match and (set(line.split()) & {"reachable", "permanent", "noarp"} or facts.get("ping") == "yes"):
        return match.group(1)
    return ""


def ha_check_script(mgmt_device: str, peer_mgmt: str, ha_device: str, peer_ha: str, vip: str) -> str:
    """Read-only HA preconditions from the owner: service stopped, eth0/eth1 peers reachable,
    VIP unused, at least one IB port physically up (ibstat); UFM_APPLIANCE for the version (owner 11-03)."""
    for device in (mgmt_device, ha_device):
        if not host.IFNAME_RE.fullmatch(device):
            raise UfmError(f"接口名无效: {device!r}")
    for address in (peer_mgmt, peer_ha, vip):
        ipaddress.IPv4Address(address)
    return ("set -u\n"
            "printf 'ufm_enterprise=%s\\n' \"$(systemctl is-active ufm-enterprise 2>/dev/null || true)\"\n"
            f"if ping -c 3 -W 2 -I {mgmt_device} {peer_mgmt} >/dev/null 2>&1; then echo mgmt_peer=yes; "
            "else echo mgmt_peer=no; fi\n"
            f"if ping -c 3 -W 2 -I {ha_device} {peer_ha} >/dev/null 2>&1; then echo ha_peer=yes; "
            "else echo ha_peer=no; fi\n"
            f"printf 'vip_local=%s\\n' \"$(ip -4 -o addr show 2>/dev/null | awk '$4 ~ /^{re.escape(vip)}\\// "
            "{print $2}' | head -n 1)\"\n"
            # A cached neighbour entry outlives a VIP that was just removed, so it must not decide: always
            # drop it first; then duplicate address detection when arping exists (it decides on its own),
            # else ping so the kernel ARPs again (an lladdr answer counts even when ICMP is filtered).
            f"ip neigh flush to {vip} dev {mgmt_device} >/dev/null 2>&1 || true\n"
            "if command -v arping >/dev/null 2>&1; then\n"
            f"  if arping -D -q -c 2 -w 3 -I {mgmt_device} {vip}; then echo vip_arp=free; else echo vip_arp=used; fi\n"
            "fi\n"
            f"if ping -c 2 -W 1 -I {mgmt_device} {vip} >/dev/null 2>&1; then echo vip_ping=yes; "
            "else echo vip_ping=no; fi\n"
            f"printf 'vip_neigh=%s\\n' \"$(ip neigh show {vip} dev {mgmt_device} 2>/dev/null "
            "| grep -v FAILED | grep -o 'lladdr [0-9a-fA-F:]*' | head -n 1)\"\n"
            "if command -v ibstat >/dev/null 2>&1; then\n"
            "  printf 'ib_linkup=%s\\n' \"$(ibstat 2>/dev/null | grep -c 'Physical state: LinkUp' || true)\"\n"
            "else echo ib_linkup=missing; fi\n"
            "printf 'appliance=%s\\n' \"$(grep -E '^UFM_APPLIANCE=' /etc/ufm-release 2>/dev/null "
            "| head -n 1 | cut -d= -f2)\"\n")


RUNNING_STATES = {"active", "activating", "reloading"}


def ha_problems(facts: dict, peer: str, vip: str, version: str, *, ignore_service: bool = False) -> list:
    """HA preconditions that fail. ignore_service=True leaves out a running ufm-enterprise, which
    ha-setup may stop itself once the operator agrees. Owner 11-03: both UFM_APPLIANCE equal the target
    version of global; one that cannot be read fails too."""
    problems = []
    if not ignore_service and facts.get("ufm_enterprise") in RUNNING_STATES:
        problems.append(f"ufm-enterprise 正在运行（{facts.get('ufm_enterprise')}）")
    if facts.get("mgmt_peer") != "yes":
        problems.append(f"管理口 eth0 到 {peer} 不通")
    if facts.get("ha_peer") != "yes":
        problems.append(f"HA 直连 eth1 到 {peer} 不通")
    if facts.get("vip_local"):
        problems.append(f"VIP {vip} 已配置在本机 {facts['vip_local']} 上（HA 可能已配置过）")
    elif facts.get("vip_arp") in {"free", "used"}:
        # arping duplicate address detection is authoritative; a neighbour entry is only a fallback.
        if facts["vip_arp"] == "used" or facts.get("vip_ping") == "yes":
            evidence = "ARP 重复地址检测有应答" if facts["vip_arp"] == "used" else "ping 有应答"
            problems.append(f"VIP {vip} 已被网络中的设备使用（{evidence}）")
    elif facts.get("vip_ping") == "yes" or facts.get("vip_neigh"):
        problems.append(f"VIP {vip} 已被网络中的设备使用（{facts.get('vip_neigh') or 'ping 有应答'}）")
    linkup = facts.get("ib_linkup", "")
    if linkup == "missing":
        problems.append("设备上没有 ibstat，无法判断 IB 口状态")
    elif not linkup.isdigit() or int(linkup) < 1:
        problems.append("ibstat 中没有 Physical state: LinkUp 的 IB 口")
    if facts.get("appliance") != version:
        problems.append(f"UFM_APPLIANCE 为 {facts.get('appliance') or '未读到'}，应为 {version}"
                        "（先运行 config-upgrade --apply）")
    return problems


# ---------------------------------------------------- HA (owner 2026-10-22, ufm-manual.log)

HA_STATUS_MARK = "----- ufm_ha_cluster status -----"
HA_TAIL_MARK = "----- log tail -----"
HA_CONFIG_DONE = "[*] Configuring HA cluster done."
HA_DAEMONS = ("corosync", "pacemaker", "pcsd")
HA_LOG_RE = re.compile(r"^/root/\.setup/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+\.log$")


HA_NO_VERSION = "global 未声明 servers.ufm.version，不做 HA"   # owner 11-03 (R-012 设计 :240)
# I-009: without --force pcs refuses, since a single-node cluster loses its quorum; `pcs cluster start` undoes it.
PCS_CLUSTER_STOP_SCRIPT = "set -u\nLC_ALL=C pcs cluster stop --force </dev/null\n"


def ha_status_script() -> str:
    """Read-only. Owner 2026-10-22: `ufm_ha_cluster status` is the only basis for judging HA."""
    return ("set -u\n"
            "if ! command -v ufm_ha_cluster >/dev/null 2>&1; then echo ha_tool=missing; exit 0; fi\n"
            "out=$(LC_ALL=C ufm_ha_cluster status 2>&1 </dev/null); rc=$?\n"
            "printf 'ha_tool=yes\\nstatus_rc=%s\\n' \"$rc\"\n"
            f"echo {shlex.quote(HA_STATUS_MARK)}\n"
            "printf '%s\\n' \"$out\"\n")


DRBD_STATUS_SCRIPT = (
    "set -u\n"
    "if ! command -v drbdadm >/dev/null 2>&1; then echo drbd_tool=missing; exit 0; fi\n"
    "echo drbd_tool=yes\n"
    "LC_ALL=C drbdadm status 2>&1 </dev/null || true\n")

# Read-only; "几秒就结束" (owner 2026-10-21), so 60 s is ample.
HA_SANITY_SCRIPT = (
    "set -u\n"
    "if ! command -v ufm_enterprise_sanity.sh >/dev/null 2>&1; then echo sanity=missing; exit 0; fi\n"
    "out=$(LC_ALL=C timeout 60 ufm_enterprise_sanity.sh 2>&1 </dev/null); rc=$?\n"
    "if printf '%s\\n' \"$out\" | grep -q 'Sanity tests completed successfully'; then echo sanity=passed; "
    "else printf 'sanity=failed\\nsanity_rc=%s\\n' \"$rc\"; fi\n"
    f"echo {shlex.quote(HA_TAIL_MARK)}\n"
    "printf '%s\\n' \"$out\" | tail -n 8\n")


def parse_ha_status(text: str) -> dict:
    """Both layouts: Pacemaker 1 (owner's 2026-10-21 example) and Pacemaker 2 (ufm01, 2026-10-22: `* Online:`,
    Promoted/Unpromoted, indented DRBD lines with bracketed values). Same reading as
    monitor/generate-monitor-html.py::parse_ufm_ha_status; test_ufm_ha_status_parity keeps them equal."""
    def names(*labels: str) -> list:
        for label in labels:
            match = re.search(rf"^[\s*]*{label}:\s*\[([^\]]*)\]", text, re.MULTILINE)
            if match:
                return match.group(1).split()
        return []

    status = {"online": names("Online"), "offline": names("OFFLINE"),
              "masters": names("Masters", "Promoted"), "slaves": names("Slaves", "Unpromoted"),
              "nodes": 0, "dc": "", "quorum": None, "resources": [], "daemons": {}, "drbd": {},
              # I-009: ufm_ha_cluster's own "HA is not configured" line (not the "HA Cluster is not configured!"
              # printed once pacemaker is stopped) and the configured resource count (None when not printed)
              "ha_not_configured": bool(re.search(r"^Error: HA is not configured", text, re.MULTILINE)),
              "resource_count": None}
    count = re.search(r"^[\s*]*(\d+) (?:resource instances?|resources?) configured", text, re.MULTILINE)
    if count:
        status["resource_count"] = int(count.group(1))
    configured = re.search(r"^[\s*]*(\d+) nodes? configured", text, re.MULTILINE)
    status["nodes"] = max(int(configured.group(1)) if configured else 0,
                          len(status["online"]) + len(status["offline"]))
    dc = re.search(r"^[\s*]*Current DC:\s*(\S+).*partition (with|WITHOUT) quorum", text, re.MULTILINE)
    if dc:
        status["dc"], status["quorum"] = dc.group(1), dc.group(2) == "with"
    for match in re.finditer(r"^\s+(?:\*\s+)?(\S+)\s+\(([^)]*)\):\s+(\S+)(?:\s+(\S+))?\s*$", text, re.MULTILINE):
        status["resources"].append({"name": match.group(1), "state": match.group(3), "node": match.group(4) or ""})
    for match in re.finditer(r"^\s+(corosync|pacemaker|pcsd):\s+(\S+)", text, re.MULTILINE):
        status["daemons"][match.group(1)] = match.group(2)
    for match in re.finditer(
            r"^[ \t]*(DRBD_CONNECTIVITY|DISK_STATE|DRBD_ROLE|PEER_DISK_STATE|PEER_DRBD_ROLE|VIRTUAL_IP):"
            r"[ \t]*\[?[ \t]*([^\]\s]+)", text, re.MULTILINE):
        status["drbd"][match.group(1)] = match.group(2)
    return status


def ha_member(name: str, nodes: list) -> Optional[UfmNode]:
    """Pacemaker names a node by its host name; ufm01 printed `ufm01` while its hostname is the FQDN."""
    folded = name.casefold()
    return next((node for node in nodes
                 if folded in {node.hostname.casefold(), first_label(node.hostname).casefold()}), None)


def ha_cluster_kind(status: dict, nodes: list, vip: str) -> tuple:
    """('absent' | 'ours' | 'foreign', detail). Without a node list nor a node count there is no cluster."""
    members = status["online"] + status["offline"]
    if not members and not status["nodes"]:
        return "absent", ""
    problems = []
    strangers = [name for name in members if ha_member(name, nodes) is None]
    if strangers:
        problems.append("集群中有不在本次输入中的节点: " + ", ".join(strangers))
    missing = [node.hostname for node in nodes if not any(ha_member(name, [node]) for name in members)]
    if missing:
        problems.append("集群中没有: " + ", ".join(missing))
    current = status["drbd"].get("VIRTUAL_IP", "")
    if current and current != vip:
        problems.append(f"集群的 VIRTUAL_IP 为 {current}，global 为 {vip}")
    return ("foreign", "; ".join(problems)) if problems else ("ours", "")


def ha_default_cluster(status: dict, node: UfmNode) -> bool:
    """I-009: pacemaker's own single-node default cluster on a freshly upgraded UFM is not an HA configuration
    when all hold: ufm_ha_cluster says HA is not configured, the only node is the one it was read on, 0 resources,
    no DRBD and no VIRTUAL_IP. Anything else is judged by ha_cluster_kind as before (问题文档 I-009 期望 1)."""
    members = status["online"] + status["offline"]
    return (status["ha_not_configured"] and status["nodes"] == 1 and len(members) == 1
            and ha_member(members[0], [node]) is node
            and status["resource_count"] == 0 and not status["resources"] and not status["drbd"])


def ha_status_problems(status: dict, nodes: list, vip: str, master: Optional[UfmNode] = None) -> list:
    """Owner 2026-10-22: HA is judged only by `ufm_ha_cluster status`: one node Promoted (the master when
    given), both online, every resource Started on the promoted node, DRBD Connected and UpToDate on both
    sides; also quorum, the three daemons and the VIP. A field that cannot be read is a problem."""
    problems = []
    offline = [node.hostname for node in nodes if not any(ha_member(name, [node]) for name in status["online"])]
    if offline:
        problems.append("不在线: " + ", ".join(offline))
    if status["quorum"] is False:
        problems.append("集群没有 quorum")
    promoted = [ha_member(name, nodes) for name in status["masters"]]
    active = promoted[0] if len(promoted) == 1 else None
    if active is None:
        problems.append(f"Promoted 应为一台 UFM，实际 {' '.join(status['masters']) or '无'}")
    elif master is not None and active is not master:
        problems.append(f"Promoted 为 {active.hostname}，应为 {master.hostname}")
    if not any(item["name"] == "ufm-enterprise" for item in status["resources"]):
        problems.append("资源列表中没有 ufm-enterprise")
    for item in status["resources"]:
        if item["state"] != "Started":
            problems.append(f"{item['name']} {' '.join(filter(None, (item['state'], item['node'])))}")
        elif active is not None and ha_member(item["node"], [active]) is None:
            problems.append(f"{item['name']} 运行在 {item['node'] or '未知节点'}，不在 {active.hostname}")
    for daemon in HA_DAEMONS:
        state = status["daemons"].get(daemon, "")
        if not state.startswith("active"):
            problems.append(f"{daemon} {state or '未读到'}")
    drbd = status["drbd"]
    for key, want in (("DRBD_CONNECTIVITY", "Connected"), ("DISK_STATE", "UpToDate"),
                      ("PEER_DISK_STATE", "UpToDate"), ("VIRTUAL_IP", vip)):
        if drbd.get(key) != want:
            problems.append(f"{key} {drbd.get(key) or '未读到'}（应为 {want}）")
    return problems


def ha_summary(status: dict, nodes: list, vip: str) -> str:
    """One line about a cluster that already exists, for the final hint and for check."""
    kind, detail = ha_cluster_kind(status, nodes, vip)
    members = " ".join(status["online"] + status["offline"]) or f"{status['nodes']} 个节点"
    problems = ha_status_problems(status, nodes, vip)
    parts = [f"节点 {members}", f"VIRTUAL_IP {status['drbd'].get('VIRTUAL_IP') or '未读到'}",
             detail if kind == "foreign" else "",
             "status 正常" if not problems else "status 不正常: " + "; ".join(problems[:4])
             + ("…" if len(problems) > 4 else "")]
    return "，".join(part for part in parts if part)


def drbd_sync_state(text: str) -> dict:
    """`drbdadm status` on the master. Synced as the owner checked it on 2026-10-22: `disk:UpToDate` and
    `replication:Established peer-disk:UpToDate`. While syncing DRBD also prints `done:<percent>`."""
    def first(pattern: str) -> str:
        match = re.search(pattern, text)
        return match.group(1) if match else ""
    state = {"disk": first(r"(?<![\w-])disk:(\S+)"), "replication": first(r"\breplication:(\S+)"),
             "peer_disk": first(r"\bpeer-disk:(\S+)"), "connection": first(r"\bconnection:(\S+)"),
             "done": first(r"\bdone:([0-9.]+)")}
    state["synced"] = (state["disk"], state["replication"], state["peer_disk"]) == (
        "UpToDate", "Established", "UpToDate")
    return state


def drbd_progress(state: dict) -> str:
    return (f"disk:{state['disk'] or '-'} replication:{state['replication'] or state['connection'] or '-'} "
            f"peer-disk:{state['peer_disk'] or '-'}" + (f" done:{state['done']}%" if state["done"] else ""))


# ------------------------------------- after HA (owner 2026-10-22, ufm-manual.log lines 1143-2088)
# Everything below runs through the VIP, i.e. on the HA master, and reads or writes the shared
# /opt/ufm/files (DRBD), so a failover makes the new master read the same files.

GV_CFG = "/opt/ufm/files/conf/gv.cfg"
OPENSM_CONF = "/opt/ufm/files/conf/opensm/opensm.conf"
LICENSE_DIR = "/opt/ufm/files/licenses"
SMDB_DUMP = "/opt/ufm/files/log/opensm-smdb.dump"
ROOT_GUID_FILE = "/opt/ufm/files/conf/opensm/root_guid.conf"   # what opensm.conf names (ufm-manual.log 1724)
# Owner 2026-10-22: only these three keys of [Server] change, the same in every project.
GV_SERVER_SETTINGS = (("fabric_interface", "ib0"), ("multi_port_sm", "ha_enabled"),
                      ("additional_fabric_interfaces", "ib1"))
LICENSE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.lic$")
ROOT_GUID_PATH_RE = re.compile(r"^/opt/ufm/files/[A-Za-z0-9._/-]+$")
IBSWITCH_RE = re.compile(r'^Switch\s*:\s*(0x[0-9a-fA-F]{16})\s+ports\s+\d+\s+"([^"]*)"')
HOST_KEY_RE = re.compile(r"^(ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|ssh-rsa) ([A-Za-z0-9+/]+={0,2})(?:\s|$)")
POST_MARK = "----- {} -----"


def gv_server_update(text: str) -> tuple:
    """(new text, changes): only the three [Server] keys are set; every other byte stays (owner 2026-10-22)."""
    lines = text.splitlines(keepends=True)
    start = next((index for index, line in enumerate(lines) if line.strip() == "[Server]"), None)
    if start is None:
        raise UfmError(f"{GV_CFG} 里没有 [Server] 段，不改动")
    end = next((index for index in range(start + 1, len(lines)) if lines[index].lstrip().startswith("[")),
               len(lines))
    wanted, changes, seen = dict(GV_SERVER_SETTINGS), [], set()
    for index in range(start + 1, end):
        match = re.match(r"^\s*([A-Za-z_]+)\s*=\s*(.*?)\s*$", lines[index])
        if not match or match.group(1) not in wanted or match.group(1) in seen:
            continue
        key = match.group(1)
        seen.add(key)
        if match.group(2) != wanted[key]:
            newline = "\n" if lines[index].endswith("\n") else ""
            lines[index] = f"{key} = {wanted[key]}{newline}"
            changes.append(f"{key}: {match.group(2) or '空'} → {wanted[key]}")
    missing = [key for key, _value in GV_SERVER_SETTINGS if key not in seen]
    if missing:
        insert = end
        while insert > start + 1 and not lines[insert - 1].strip():
            insert -= 1
        if insert > 0 and not lines[insert - 1].endswith("\n"):
            lines[insert - 1] += "\n"
        lines[insert:insert] = [f"{key} = {wanted[key]}\n" for key in missing]
        changes += [f"{key}: 新增 {wanted[key]}" for key in missing]
    return "".join(lines), changes


def spine_like(hostname: str) -> bool:
    """The monitor page's Spine rule (generate-monitor-html.py::infer_device_role)."""
    name = hostname.strip().upper()
    return ("SPINE" in name or bool(re.search(r"EDIBS\d*$", name))
            or bool(re.search(r"(?:^|[-_.])SP(?:[-_.]?\d+)?$", name)))


def ib_root_switches(csv_path: Path) -> tuple:
    """('core' | 'spine', hostnames) from ib.csv type=ib. Owner 2026-10-22: a large fabric has core
    switches (their host names contain "core"), and then only the cores are roots."""
    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.reader(handle))
    names = [row[0].strip() for row in rows[1:]
             if len(row) > 1 and row[0].strip() and not row[0].lstrip().startswith("#")
             and row[1].strip().lower() == "ib"]
    cores = [name for name in names if "core" in name.casefold()]
    return ("core", cores) if cores else ("spine", [name for name in names if spine_like(name)])


def natural_key(text: str) -> list:
    return [int(part) if part.isdigit() else part.casefold() for part in re.split(r"(\d+)", text)]


def parse_ibswitches(text: str) -> list:
    """[(guid, description, host)]: `Switch : 0x... ports N "MF0;<host>:<model>/U<n>" ...`. Error lines
    such as `src/query_smp.c:199; umad ... Connection timed out` (ufm01, 2026-10-22) are skipped."""
    found = []
    for line in text.splitlines():
        match = IBSWITCH_RE.match(line.strip())
        if match:
            description = match.group(2)
            host = description.split(";", 1)[-1].split(":", 1)[0].strip()
            found.append((match.group(1).lower(), description, host))
    return found


def root_guid_plan(switches: list, roots: list) -> tuple:
    """(GUIDs in the owner's order, missing root switches): every ASIC GUID of each root switch,
    sorted naturally by description as `sort -t'"' -k2,2V` does."""
    def names(text: str) -> set:
        return {text.casefold(), first_label(text).casefold()}
    chosen = [(description, guid) for guid, description, host in switches
              if any(names(host) & names(root) for root in roots)]
    seen = {name for _guid, _description, host in switches for name in names(host)}
    missing = [root for root in roots if not names(root) & seen]
    return [guid for _description, guid in sorted(chosen, key=lambda item: natural_key(item[0]))], missing


def license_rows(text: str) -> list:
    """`docker exec ufm ufmlicense` prints a |-separated table; rows as {column: value}."""
    rows, header = [], None
    for line in text.splitlines():
        if not line.strip().startswith("|") or set(line.strip()) <= {"|", "-"}:
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if header is None:
            header = cells
        elif len(cells) == len(header):
            rows.append(dict(zip(header, cells)))
    return rows


def license_valid_for(rows: list, mac: str) -> bool:
    """Owner 2026-10-22: a new license shows one row per UFM, by its eno8303 MAC; the row of the node
    that is master now must be Valid. (A sample of that output is still to come.)"""
    def bare(value: str) -> str:
        return re.sub(r"[^0-9a-f]", "", value.casefold())
    return any(bare(row.get("MAC Address", "")) == bare(mac) and row.get("Status", "").casefold() == "valid"
               for row in rows if bare(row.get("MAC Address", "")))


def evaluation_expiry(rows: list) -> str:
    return next((row.get("Exp. Date", "") for row in rows if row.get("Type", "").casefold() == "evaluation"), "")


HOST_KEYS_SCRIPT = "set -u\ncat /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true\n"


def host_key_fingerprint(line: str) -> Optional[str]:
    """OpenSSH's SHA256 fingerprint of one public-key line (the key blob, sha256, base64 without "="); computed
    here and not in tools/login_path.py (v3.1.4 D3 pins that module without one)."""
    match = HOST_KEY_RE.match(line.strip())
    if not match:
        return None
    try:
        blob = base64.b64decode(match.group(2), validate=True)
    except ValueError:
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")


def local_home() -> Path:
    """The effective user's passwd home: OpenSSH finds ~/.ssh/known_hosts there, not by $HOME."""
    return Path(pwd.getpwuid(os.geteuid()).pw_dir)


def host_key_fact(record: "login_rules.HostKeyRefreshRecord") -> dict:
    """result.json's host_key: the library's record (no raw warning) and how it was verified."""
    return {**asdict(record), "note": "已核实（经已核验 MAC 的会话读取设备主机公钥）" if record.verification == "verified"
            else "未核实（操作员指定）"}
POST_CONFIG_PLAN = ("经 VIP 在主机上：安装 image 目录里的 *.lic、gv.cfg 的 [Server] 三项、按 ibswitches 写 root_guid.conf；"
                    "任何一项有改动就执行一次 ufm_ha_cluster failover（主机切到另一台），再核对 HA 状态、gv.cfg 和 license")


def post_read_script(mgmt_device: str, licenses: list) -> str:
    """Read-only, on the VIP holder: who it is, gv.cfg, root_guid.conf, the licenses in place,
    ibswitches and ufmlicense. Each part follows a POST_MARK line."""
    if not host.IFNAME_RE.fullmatch(mgmt_device) or not all(LICENSE_NAME_RE.fullmatch(name) for name in licenses):
        raise UfmError("内部错误：管理接口名或 license 文件名无效")
    mark = lambda name: f"echo {shlex.quote(POST_MARK.format(name))}"   # noqa: E731
    lines = ["set -u",
             f"printf 'mac=%s\\n' \"$(cat /sys/class/net/{mgmt_device}/address 2>/dev/null)\"",
             f"root_guid_file=$(awk '$1 == \"root_guid_file\" {{print $2; exit}}' {OPENSM_CONF} 2>/dev/null)",
             "printf 'root_guid_file=%s\\n' \"$root_guid_file\"",
             mark("gv.cfg"), f"if [ -f {GV_CFG} ]; then base64 < {GV_CFG} | tr -d '\\n'; fi; echo",
             mark("root_guid"), f"if [ -f {ROOT_GUID_FILE} ]; then base64 < {ROOT_GUID_FILE} | tr -d '\\n'; fi; echo",
             mark("licenses")]
    for name in licenses:
        path = f"{LICENSE_DIR}/{name}"
        lines.append(f"if [ -f {path} ]; then printf '%s %s\\n' {name} \"$(sha256sum < {path} | cut -d' ' -f1)\"; "
                     f"else printf '%s -\\n' {name}; fi")
    lines += [mark("ibswitches"), "docker exec ufm /opt/ufm/opensm/sbin/ibswitches 2>/dev/null || true",
              mark("ufmlicense"), "docker exec ufm ufmlicense 2>&1 || true",
              mark("smdb"), f"grep smi {SMDB_DUMP} 2>/dev/null || true"]
    return "\n".join(lines) + "\n"


def post_sections(body: str) -> dict:
    """{'': key=value head, 'gv.cfg': ..., ...} from post_read_script's output."""
    parts, name = {"": []}, ""
    for line in body.splitlines():
        found = re.fullmatch(r"----- (\S+) -----", line.strip())
        if found:
            name = found.group(1)
            parts[name] = []
        else:
            parts[name].append(line)
    return {key: "\n".join(value) for key, value in parts.items()}


def file_replace_script(path: str, content: bytes, backup_dir: str) -> str:
    """Back the file up, write the new bytes beside it with the old mode and owner (cp -p), check the
    sha256, then move it into place."""
    if not (path == GV_CFG or ROOT_GUID_PATH_RE.fullmatch(path)) or ".." in path:
        raise UfmError(f"内部错误：不改动这个文件: {path!r}")
    if not re.fullmatch(r"/root/ufm-setup-upgrade-backup/[A-Za-z0-9._/-]+", backup_dir):
        raise UfmError(f"内部错误：备份目录无效: {backup_dir!r}")
    payload = base64.b64encode(content).decode("ascii")
    digest = hashlib.sha256(content).hexdigest()
    return ("set -eu\n"
            f"f={shlex.quote(path)}; b={shlex.quote(backup_dir)}\n"
            'mkdir -p "$b"\n'
            'if [ -f "$f" ]; then cp -p "$f" "$b/${f##*/}"; cp -p "$f" "$f.part"; fi\n'
            f'printf %s {payload} | base64 -d > "$f.part"\n'
            f'if [ "$(sha256sum < "$f.part" | cut -d" " -f1)" != {digest} ]; then\n'
            '  rm -f "$f.part"; echo "written bytes differ" >&2; exit 1\n'
            "fi\n"
            'mv -f "$f.part" "$f"\n'
            "echo written=yes\n")


def license_install_script(licenses: list, image_server: str, backup_dir: str) -> str:
    """Owner 2026-10-22: the master downloads every *.lic from the image server into
    /opt/ufm/files/licenses/, a file of the same name is replaced (after a backup)."""
    if not re.fullmatch(r"http://[0-9.]+(?::[0-9]+)?", image_server) \
            or not re.fullmatch(r"/root/ufm-setup-upgrade-backup/[A-Za-z0-9._/-]+", backup_dir):
        raise UfmError("内部错误：镜像服务器地址或备份目录无效")
    lines = ["set -eu", f"mkdir -p {LICENSE_DIR} {shlex.quote(backup_dir)}"]
    for name, digest in licenses:
        if not LICENSE_NAME_RE.fullmatch(name) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise UfmError(f"内部错误：license 文件名或摘要无效: {name!r}")
        target = f"{LICENSE_DIR}/{name}"
        lines += [f"rm -f {target}.part",
                  f"wget -q -O {target}.part {shlex.quote(f'{image_server}/image/{name}')}",
                  f'if [ "$(sha256sum < {target}.part | cut -d" " -f1)" != {digest} ]; then',
                  f"  rm -f {target}.part; echo 'downloaded {name} differs from the image server copy' >&2; exit 1",
                  "fi",
                  f"if [ -f {target} ]; then cp -p {target} {shlex.quote(backup_dir)}/{name}; fi",
                  f"mv -f {target}.part {target}",
                  f"echo installed={name}"]
    return "\n".join(lines) + "\n"


def ha_config_argv(role: str, local_primary: str, peer_primary: str, local_secondary: str, peer_secondary: str,
                   vip: str = "") -> list:
    """`ufm_ha_cluster config` as the owner ran it: primary = the HA link (eno8403), secondary = the
    management port (eno8303); only the master gets the VIP."""
    for address in (local_primary, peer_primary, local_secondary, peer_secondary) + ((vip,) if vip else ()):
        ipaddress.IPv4Address(address)
    if role not in {"standby", "master"} or bool(vip) != (role == "master"):
        raise UfmError(f"HA 配置参数无效: role={role!r} vip={vip!r}")
    argv = ["ufm_ha_cluster", "config", "-r", role, "--local-primary-ip", local_primary,
            "--peer-primary-ip", peer_primary, "--local-secondary-ip", local_secondary,
            "--peer-secondary-ip", peer_secondary]
    return argv + (["--virtual-ip", vip] if vip else [])


def ha_logged_script(argv: list, log: str, key: str, done: str = "") -> str:
    """One ufm_ha_cluster change with its whole output in a log on the UFM; only a summary comes back.

    ufm_ha_cluster sets the hacluster password itself, and the `passwd` prompts it prints ("New password:")
    would reach this session, where the responder takes them for a forced password change and aborts the
    session in the middle of the configuration. nohup keeps the change running if the SSH session drops."""
    if not HA_LOG_RE.fullmatch(log) or not re.fullmatch(r"[a-z_]+", key):
        raise UfmError(f"HA 日志路径或键名无效: {log!r} {key!r}")
    lines = ["set -u", f"log={shlex.quote(log)}",
             f"nohup {shlex.join(argv)} </dev/null >\"$log\" 2>&1; rc=$?",
             f"printf '{key}_rc=%s\\nlog=%s\\n' \"$rc\" \"$log\""]
    if done:
        lines.append(f"if grep -qF -- {shlex.quote(done)} \"$log\"; then echo {key}_done=yes; "
                     f"else echo {key}_done=no; fi")
    lines += [f"echo {shlex.quote(HA_TAIL_MARK)}",
              # the tail explains a failure; the password lines stay in the log on the UFM
              "tail -n 15 \"$log\" | grep -viF password || true"]
    return "\n".join(lines) + "\n"


def node_others(plan: Plan, node: UfmNode) -> dict:
    return {device: cidr for device, cidr in plan.addresses.get(plan.role_of(node), {}).items()
            if device != "ipmi"}


def node_netplan(plan: Plan, node: UfmNode) -> dict:
    """I-055 (B6-O1 (a)): two server_ufm rows in ib.csv and eth1 among this node's links: eth1 is ignore-carrier."""
    others, ha_link = node_others(plan, node), plan.logical.get("eth1")
    if plan.source_ufm_count == 2 and ha_link in others:
        return host.netplan_document(plan.mgmt_device, node.interface, node.gateway, others,
                                     ignore_carrier={ha_link})
    return host.netplan_document(plan.mgmt_device, node.interface, node.gateway, others)


def node_network_problems(plan: Plan, node: UfmNode, facts: dict) -> tuple:
    return host.network_problems(facts, plan.mgmt_device, node.mac, node.interface, node.gateway,
                                 node_others(plan, node))


def parse_facts(text: str) -> dict:
    facts = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in {"hostname", "mac", "ipv4", "os", "route"}:
            facts[key] = value.strip()
    return facts


class Session:
    def __init__(self, plan: Plan, creds: Credentials, timeout: int, run_dir: Path,
                 say: Callable[[str], None], ask_eth_password: Callable[[], str], *,
                 spines: Optional[list] = None, choose: Optional[Callable[[list], tuple]] = None,
                 ipmi_user: str = "admin", ipmi_channel: int = 1, apply_wait: tuple = (15, 10, 9),
                 ask_ufm_password: Optional[Callable[[], str]] = None,
                 upgrade_wait: tuple = (600, 30, 2400), apply: bool = False,
                 confirm: Optional[Callable[[str, str], bool]] = None,
                 confirm_new_password: Optional[Callable[[], str]] = None,
                 ha_wait: tuple = (100, 7200, 15, 900), direct_access: frozenset = frozenset(),
                 routes: Optional[dict] = None, ignore_cable_check: bool = False,
                 refresh_host_key: frozenset = frozenset()):
        self.plan, self.creds, self.timeout = plan, creds, timeout
        # (DRBD probe interval, DRBD sync limit, status probe interval, limit after start), seconds. Owner
        # 2026-10-22: the sync took under 30 minutes on ufm01/02; a line every 100 s while waiting.
        self.ha_wait = ha_wait
        self.run_dir, self.say, self.ask_eth_password = run_dir, say, ask_eth_password
        self.spines = select_spine_inventory(plan) if spines is None else spines
        self.choose = choose or random.SystemRandom().choice
        self.ipmi_user, self.ipmi_channel, self.apply_wait = ipmi_user, ipmi_channel, apply_wait
        self.ask_ufm_password = ask_ufm_password
        self.upgrade_wait = upgrade_wait
        # As initial-setup: without --apply nothing is written (no password change, no configuration);
        # with --apply the operator confirms once, right before the first device change (--yes: confirm=None).
        self.apply, self.confirm = apply, confirm
        self.authorized = apply and confirm is None
        self.confirm_new_password, self.password_confirmed = confirm_new_password, False
        self.eth_password_asked = False
        self.stopped = ""
        self.pending_action = ""
        self.snapshots = {}
        self.sequence = itertools.count(1)   # every saved session log gets the next number: nothing is overwritten
        self.leaf_jump = {}
        self.access = {}
        self.oob = {}
        # I-037 (v3.1.6 B0): the route of each UFM is decided once, before any login
        self.routes = route_table(plan, direct_access) if routes is None else routes
        self.ignore_cable_check, self.refresh_host_key = ignore_cable_check, refresh_host_key
        self.cable_checks = {}      # hostname -> CableCheck, once per run
        self.jump_switches = {}     # jump hostname -> the Transit at the login address chosen for it (I20)
        self.mac_noted = set()

    def authorize(self, node: UfmNode, action: str) -> None:
        """Gate in front of every device write."""
        if not self.apply:
            raise UfmError(f"内部错误：未加 --apply 却尝试改动设备（{action}）")
        if self.stopped:
            raise NotAuthorized(self.stopped)
        if not self.authorized:
            if not self.confirm(node.hostname, action):
                self.stopped = "操作员未授权设备改动，本次运行停止，未做任何改动"
                raise NotAuthorized(self.stopped)
            self.authorized = True

    def would(self, step: str, action: str) -> str:
        """Check-only outcome of a step that needs a change; the action is printed with the outcome."""
        self.pending_action = action
        return "WOULD_CHANGE"

    def outcome_line(self, outcome: str) -> str:
        action, self.pending_action = self.pending_action, ""
        return f"{outcome}：{action}" if outcome.startswith("WOULD") and action else outcome

    def secrets(self) -> tuple:
        return (self.creds.new_password, self.creds.factory_password, self.creds.eth_password or "",
                self.creds.ipmi_password)

    def numbered(self, name: str) -> str:
        return f"{next(self.sequence):03d}-{name}"

    def save(self, name: str, text: str) -> None:
        path = self.run_dir / re.sub(r"[^A-Za-z0-9._-]+", "_", name)
        path.write_text(redact(text, self.secrets()), encoding="utf-8")
        os.chmod(path, 0o600)

    def jump_at(self, switch: Transit) -> Transit:
        """The jump at the login address this run chose for it (I20: chosen once by snapshot, then kept)."""
        return self.jump_switches.get(switch.hostname, switch)

    def run_switch(self, switch: Transit, remote: list, label: str = "") -> str:
        switch = self.jump_at(switch)
        if self.creds.eth_password is None:
            self.creds.eth_password = self.ask_eth_password()
        result = self.switch_session(switch, remote, label)
        if (not self.creds.eth_password and not self.eth_password_asked
                and re.search(r"(?i)permission denied", result.output)):
            # Owner 2026-10-21: the deployment server's key first; only when a switch rejects it, ask once.
            self.say(f"    {switch.hostname}: 部署服务器公钥登录被拒，改用密码")
            self.eth_password_asked = True
            self.creds.eth_password = self.ask_eth_password()
            if self.creds.eth_password:
                result = self.switch_session(switch, remote, label)
        leaf_pw = self.creds.eth_password
        if remote[0] == "ifquery" and result.exit_code == 1 and not result.output.strip():
            return ""
        if result.exit_code != 0:
            hint = ("；部署服务器公钥登录被拒，且没有提供交换机密码"
                    if not leaf_pw and re.search(r"(?i)permission denied", result.output) else "")
            network = (result.exit_code == 255 and not re.search(r"(?i)permission denied", result.output)
                       and (_UNREACHABLE.search(result.output) or _REFUSED.search(result.output)))
            raise (SwitchUnreachable if network else UfmError)(
                f"{switch.hostname} ({switch.login_ip}) 执行 {shlex.join(remote)} 失败，"
                f"exit={result.exit_code}: {result.output.strip()[-400:]}{hint}")
        return re.sub(r"(?im)^[^\n]*@[^\n]*password:\s*$", "", result.output)

    def switch_session(self, switch: Transit, remote: list, label: str) -> "SessionResult":
        leaf_pw = self.creds.eth_password or ""
        responder = Responder(ufm_destination="\0", login_password="", new_password="",
                              allow_change=False, outer_password=leaf_pw)
        result = interactive_run(leaf_argv(switch, self.creds.eth_user, remote, self.timeout,
                                           tty=False, batch=not leaf_pw),
                                 responder, self.timeout * 6, self.secrets())
        self.save(self.numbered(f"switch-{switch.hostname}-{label or '_'.join(remote)}.txt"), result.output)
        return result

    def snapshot(self, switch: Transit) -> dict:
        """Read-only tables, collected once per switch per run (`bridge vlan show` added and `ip neighbor` dropped by
        v3.1.6 B0, D1b-O18 (a), I-037 rule 5). The first command also picks the login address (I20, B0-O1 (a)):
        only a network failure moves to the next candidate; the address must be on the switch's own interfaces
        (owner 2026-10-19: identity by address), and on eth0 a valid CSV eth0_mac must match its eth0."""
        if switch.hostname not in self.snapshots:
            candidates = switch.candidates or (
                (login_rules.JumpCandidate(switch.login_ip, ""),) if switch.login_ip else ())
            if not candidates:
                raise RouteStop("JUMP_ADDRESS_INVALID", f"跳板 {switch.hostname} 在 ib.csv 中没有可用的登录地址: "
                                f"{self.plan.transit_errors.get(first_label(switch.hostname), '')}")
            failures = []
            for candidate in candidates:
                at = replace(switch, login_ip=candidate.address)
                try:
                    text = self.run_switch(at, ["ip", "-j", "address", "show"])
                    break
                except SwitchUnreachable as exc:
                    failures.append(f"{candidate.address}: {str(exc)[-160:]}")
            else:
                raise RouteStop("JUMP_UNREACHABLE", f"跳板 {switch.hostname} 连不上: " + "; ".join(failures))
            addresses = parse_oob_addresses(text.strip())
            if not owns_address(addresses, at.login_ip):
                raise UfmError(f"交换机身份不符: 经 {at.login_ip} 登录（CSV {switch.hostname}），"
                               "但该地址不在这台交换机的任何接口上")
            if candidate.entry == "JUMP_ETH0":
                self.check_jump_eth0_mac(switch, addresses)
            self.jump_switches[switch.hostname] = at
            tables = {key: self.run_switch(at, argv) for key, argv in (
                ("interfaces", ["nv", "show", "interface"]), ("links", ["ip", "-d", "link", "show"]),
                ("fdb", ["bridge", "fdb", "show"]), ("vlans", ["bridge", "vlan", "show"]))}
            tables["addresses"] = addresses
            tables["login"] = (at.login_ip, candidate.entry)
            self.snapshots[switch.hostname] = tables
        return self.snapshots[switch.hostname]

    def check_jump_eth0_mac(self, switch: Transit, addresses: list) -> None:
        """D1b-O2a (a), UFM wording: entered on eth0 with a valid CSV eth0_mac, eth0 must carry that MAC; an empty
        or unreadable eth0_mac is used as it is and reported once."""
        try:
            expected = device_identity.normalize_mac(switch.eth0_mac)
        except ValueError:
            expected = ""
        if not expected:
            if switch.hostname not in self.mac_noted:
                self.mac_noted.add(switch.hostname)
                self.say(f"    {switch.hostname}: 跳板 eth0_mac 未填，eth0 入口只核了地址")
            return
        observed = next((str(row.get("address", "")) for row in addresses if row.get("ifname") == "eth0"), "")
        try:
            observed = device_identity.normalize_mac(observed)
        except ValueError:
            observed = ""
        if observed != expected:
            raise UfmError(f"交换机身份不符: {switch.hostname} 的 eth0 MAC 为 {observed or '空'}，"
                           f"CSV eth0_mac 为 {expected}")

    def switch_vrf(self, switch: Transit, interface: str) -> str:
        values = re.findall(r"(?im)^\s*vrf\s+(\S+)\s*$", self.run_switch(switch, ["ifquery", interface]))
        unique = sorted(set(values))
        if len(unique) > 1:
            raise UfmError(f"{switch.hostname} {interface} 有多个 VRF: {unique}")
        return unique[0] if unique else "default"

    def port_vlan(self, attachment: Attachment) -> str:
        """The login VLAN of the expected port, from `bridge vlan show` (login_path's own reading of it, as
        initial-setup reads it: infiniband/bringup/xdr-initial-setup/initial-setup.py::_access_vlan_facts)."""
        tables = self.snapshot(attachment.leaf)
        try:
            return login_rules._login_interface_facts(tables["links"], tables["vlans"], attachment.port)[1]
        except ValueError as exc:
            raise UfmError(f"{attachment.leaf.hostname} {attachment.port}: {exc}") from None

    def port_state(self, attachment: Attachment) -> str:
        try:
            status = interface_oper_status(self.snapshot(attachment.leaf)["interfaces"], attachment.port)
        except UfmError:
            status = "未知"
        return f"{attachment.leaf.hostname} {attachment.port} Oper Status={status}"

    def other_jump_tables(self, expected: Transit) -> tuple:
        """B0-O10 (a): every other *jump row of ib.csv, read once each, only when the expected jump learned nothing."""
        tables = []
        for other in all_transits(self.plan):
            if other.hostname == expected.hostname:
                continue
            try:
                snapshot = self.snapshot(other)
            except UfmError as exc:
                self.say(f"    {other.hostname}: 读不到，不计入实际位置（{str(exc)[:160]}）")
                continue
            tables.append(login_rules.JumpTables(other.hostname, snapshot["links"], snapshot["fdb"], snapshot["vlans"]))
        return tuple(tables)

    def cable_check(self, node: UfmNode, attachment: Attachment) -> "login_rules.CableCheck":
        """I-037 rules 4-6 once per UFM per run: the expected jump; the CSV MAC learned nowhere there, the other
        jumps too; still nowhere, one ping of the CSV link-local from the expected jump (from the chosen Spine when
        the Leaf has no SVI of that VLAN), one more FDB read and the check again. A port that is down takes the
        same way (D1b-O4 (a)); the ping writes nothing on the switch (00 原则 :68)."""
        if node.hostname not in self.cable_checks:
            leaf, tables, cascade = attachment.leaf, self.snapshot(attachment.leaf), cascade_ports(self.plan)
            try:
                check = leaf_cable_check(node, attachment, tables, cascade_ports=cascade)
                others = ()
                if check.verdict == "NOT_LEARNED":
                    others = self.other_jump_tables(leaf)
                    check = leaf_cable_check(node, attachment, tables, others=others, cascade_ports=cascade)
                if check.verdict == "NOT_LEARNED":
                    if check.login_interface:
                        switch, interface = leaf, check.login_interface
                        vrf = self.switch_vrf(leaf, interface)
                    else:
                        switch, neighbor = self.spine_route(node, leaf, tables, self.port_vlan(attachment),
                                                            "LEAF_SVI_MISSING", {})
                        vrf, interface = neighbor.vrf, neighbor.interface
                    try:
                        self.run_switch(switch, login_rules.ping_argv(vrf, check.link_local, interface),
                                        label=f"ping-{node.hostname}")
                        ping_ok = True
                    except UfmError:
                        ping_ok = False
                    fdb = self.run_switch(leaf, ["bridge", "fdb", "show"], label=f"fdb-after-ping-{attachment.port}")
                    check = leaf_cable_check(node, attachment, dict(tables, fdb=fdb), others=others,
                                             cascade_ports=cascade, after_ping=True, ping_ok=ping_ok)
            except ValueError as exc:
                raise UfmError(f"{leaf.hostname} {attachment.port}: {exc}") from None
            self.cable_checks[node.hostname] = check
        return self.cable_checks[node.hostname]

    def oob_route(self, node: UfmNode, attachment: Attachment, result: NodeResult) -> tuple:
        """The jump path (I-037 rules 4-7): the cabling check decides; the target is the CSV MAC's link-local and the
        way out the SVI of the expected port's VLAN: a Leaf SVI with its own IPv4, else one LLDP Spine per Leaf."""
        leaf, route = attachment.leaf, result.route
        check = self.cable_check(node, attachment)
        tables = self.snapshot(leaf)
        result.facts["cabling"] = cabling_fact(check, attachment, self.port_state(attachment))
        if check.verdict != "MATCH":
            if not self.ignore_cable_check:
                raise RouteStop("CABLE_CHECK_FAILED", f"P2P 线路核对不通过（{check.verdict}），未登录: "
                                                      f"{result.facts['cabling']['detail']}")
            result.facts["cabling"]["ignored"] = True
            self.say(f"    {node.hostname}: 线路核对 {check.verdict}，按 --ignore-cable-check 继续")
        vlan = self.port_vlan(attachment)
        route.update(vlan=vlan)
        interface = check.login_interface
        if not (interface and svi_address_ready(tables["addresses"], interface)):
            reason = "LEAF_SVI_MISSING" if not interface else "LEAF_SVI_HAS_NO_IPV4"
            return self.spine_route(node, leaf, tables, vlan, reason, route)
        route.update(jump=leaf.hostname, reason="LEAF", jump_address=tables["login"][0], jump_entry=tables["login"][1])
        return self.jump_at(leaf), csv_neighbor(node.mac, interface, self.switch_vrf(leaf, interface))

    def spine_route(self, node: UfmNode, leaf: Transit, leaf_tables: dict, vlan: str,
                    reason: str, route: dict) -> tuple:
        candidates = lldp_spine_candidates(leaf_tables["interfaces"], self.spines)
        if not candidates:
            raise UfmError(f"{reason}: {leaf.hostname} 的 VLAN {vlan} 没有可用 SVI/IPv4，且没有 UP 的 "
                           "LLDP Spine 邻居与 CSV eth_jump 唯一对应")
        eligible, rejected = [], {}
        for spine in candidates:
            try:
                tables = self.snapshot(spine)
                svis = vlan_svi_interfaces(tables["links"], vlan)
                if len(svis) != 1:
                    raise UfmError(f"VLAN {vlan} 应有 1 个真实 SVI，实际 {len(svis)} 个")
                if not svi_address_ready(tables["addresses"], svis[0], require_ipv6=True):
                    raise UfmError(f"VLAN {vlan} 的 SVI {svis[0]} 需要 UP、自有 IPv4 和 link-local；"
                                   "VRR 网关地址不能替代")
                vrf = self.switch_vrf(spine, svis[0])
                eligible.append((self.jump_at(spine), csv_neighbor(node.mac, svis[0], vrf)))
            except UfmError as exc:
                rejected[spine.hostname] = str(exc)
        route.update(reason=reason, eligible=[spine.hostname for spine, _ in eligible], rejected=rejected)
        if not eligible:
            raise UfmError(f"{reason}: 没有合格的 Spine: "
                           + "; ".join(f"{name}: {why}" for name, why in rejected.items()))
        chosen = self.leaf_jump.get(leaf.hostname)
        if chosen is None:
            spine, neighbor = self.choose(eligible)
            self.leaf_jump[leaf.hostname] = spine.hostname
            self.say(f"    [JUMP] {leaf.hostname} -> {spine.hostname} ({spine.login_ip}); 原因 {reason}; "
                     f"合格 Spine {len(eligible)} 台; 每个 Leaf 只随机选择一次")
        else:
            match = [item for item in eligible if item[0].hostname == chosen]
            if not match:
                raise UfmError(f"{leaf.hostname} 本轮已选 Spine {chosen}，但它对 {node.hostname} 不合格: "
                               f"{rejected.get(chosen, '未知')}")
            spine, neighbor = match[0]
        route.update(jump=spine.hostname, jump_address=spine.login_ip,
                     jump_entry=self.snapshots[spine.hostname]["login"][1])
        return spine, neighbor

    def attempt(self, result: NodeResult, path: str, build: Callable[[str], list],
                destination: str, password_label: str, allow_change: bool) -> tuple:
        login_pw = self.creds.new_password if password_label == "new" else self.creds.factory_password
        marker = os.urandom(12).hex()
        responder = Responder(ufm_destination=destination, login_password=login_pw,
                              new_password=self.creds.new_password, allow_change=allow_change,
                              outer_password=self.creds.eth_password or "")
        try:
            session = interactive_run(build(marker), responder, max(self.timeout * 4, 60), self.secrets())
            outcome = classify(session, responder, marker)
        except UfmError as exc:
            # A timeout after any UFM prompt is an unknown session state, never "unreachable".
            engaged = responder.counts.get("ufm") or responder.change_required
            session, outcome = SessionResult(str(exc), -1), "SESSION_TIMEOUT" if engaged else "TIMEOUT"
        name = self.numbered(f"{result.hostname}-{path}-{password_label}.txt")
        self.save(name, session.output)
        result.attempts.append({"path": path, "password": password_label, "outcome": outcome, "log": name})
        self.say(f"    {path} 使用{'新' if password_label == 'new' else '出厂'}密码: {outcome}")
        if responder.bad_password:
            result.detail = responder.bad_password
        return outcome, session, marker

    def ufm_argv(self, node: UfmNode, access: dict, remote: list, marker: str) -> list:
        if access["path"] == "VIP-KEY":
            # Owner 2026-10-22: a failover moves the VIP to the other UFM and its host key changes with
            # it. Only the two UFMs' own host keys are accepted under the VIP, from a file of this run;
            # ~/.ssh/known_hosts is neither read nor changed. These options come first, so they win.
            return ["ssh", "-tt", "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={access['known_hosts']}",
                    "-o", "GlobalKnownHostsFile=/dev/null", *ssh_options(self.timeout), "-o", "BatchMode=yes",
                    "-o", "PreferredAuthentications=publickey", f"{self.creds.ufm_user}@{access['address']}",
                    shlex.join(["sh", "-c", framed(remote, marker)])]
        if access["path"] == "IPv4-KEY":
            return ["ssh", "-tt", *ssh_options(self.timeout), "-o", "BatchMode=yes",
                    "-o", "PreferredAuthentications=publickey", f"{self.creds.ufm_user}@{node.address}",
                    shlex.join(["sh", "-c", framed(remote, marker)])]
        if access["path"] == "IPv4":
            return direct_ufm_argv(node.address, self.creds.ufm_user, remote, marker, self.timeout)
        if access["path"] == "LINK-LOCAL":   # v3.1.6 B0: same subnet, this server's own link-local route
            return ["ssh", "-6", "-tt", *ufm_ssh_options(self.timeout), f"{self.creds.ufm_user}@{access['address']}",
                    shlex.join(["sh", "-c", framed(remote, marker)])]
        return nested_ufm_argv(access["jump"], self.creds.eth_user, access["neighbor"], self.creds.ufm_user,
                               remote, marker, self.timeout, batch=not self.creds.eth_password)

    def ufm_destination(self, node: UfmNode, access: dict) -> str:
        if access["path"] == "VIP-KEY":
            return f"{self.creds.ufm_user}@{access['address']}"
        host = (node.address if access["path"] in {"IPv4", "IPv4-KEY"} else access["address"]
                if access["path"] == "LINK-LOCAL" else access["neighbor"].ipv6)
        return f"{self.creds.ufm_user}@{host}"

    def login_path(self, node: UfmNode, result: NodeResult, access: dict, allow_change: bool) -> str:
        path, remote = access["path"], identity_command(self.plan.mgmt_device)
        destination = self.ufm_destination(node, access)

        def build(marker: str) -> list:
            return self.ufm_argv(node, access, remote, marker)
        outcome, session, marker = self.attempt(result, path, build, destination, "new", False)
        label = "new"
        if outcome == "AUTH_REJECTED" and self.creds.factory_password:
            outcome, session, marker = self.attempt(result, path, build, destination, "factory", False)
            label = "factory"
            if outcome == "PASSWORD_CHANGE_REQUIRED" and allow_change:
                # The forced change is a device write: confirm first, then log in again and submit it.
                self.authorize(node, "设备强制改密：把 root 出厂密码改为新密码")
                self.confirm_password_once()
                outcome, session, marker = self.attempt(result, path, build, destination, "factory", True)
        if outcome in {"PASSWORD_CHANGED", "PASSWORD_CHANGE_UNKNOWN"}:
            self.say(f"    {node.hostname} 已按强制要求提交新密码，用新密码重新登录确认")
            outcome, session, marker = self.attempt(result, path, build, destination, "new", False)
            label = "changed"
            if outcome != "OK":
                result.detail = f"改密后用新密码重新登录未成功（{outcome}），改密结果未知"
                outcome = "PASSWORD_CHANGE_UNKNOWN"
        if outcome == "OK":
            result.password = label
            # the identity facts join what the route already recorded (v3.1.6 B0: facts["cabling"])
            result.facts = {**result.facts, **parse_facts(extract_framed(session.output, marker))}
        return outcome

    def confirm_password_once(self) -> None:
        """The one password is typed again right before the first password change of the run: a typo
        there would leave the device with a password nobody knows."""
        if self.confirm_new_password is None or self.password_confirmed:
            return
        if self.confirm_new_password() != self.creds.new_password:
            raise NotAuthorized("再次输入的新密码与开始时输入的不一致，未修改任何设备的密码")
        self.password_confirmed = True

    def check_login_identity(self, node: UfmNode, result: NodeResult) -> None:
        """I-037 rule 8 (问题文档 :1565, :1569): the management MAC on every path; on IPv4 and IPv4-KEY also the
        address with its netmask and the default route's gateway (no default route passes), one shared function
        (login_path.check_identity). Not this UFM: IdentityMismatch, the node stops (B0-O13 (a))."""
        facts, ipv4 = result.facts, []
        for value in facts.get("ipv4", "").split():
            try:
                ipv4.append(ipaddress.IPv4Interface(value))
            except ValueError:
                continue
        try:
            gateways = login_rules.parse_default_routes(facts.get("route", "").replace(";", "\n"))
        except ValueError:
            gateways = ("?",)
        try:
            mac = device_identity.normalize_mac(facts.get("mac", ""))
        except ValueError:
            mac = ""
        check = login_rules.check_identity(node.mac, login_rules.IdentityFacts(mac, tuple(ipv4), gateways),
                                           via_ipv4=result.path in {"IPv4", "IPv4-KEY"},
                                           expected_ipv4=node.interface, expected_gateway=node.gateway)
        if check.ok:
            return
        result.identity = {"path": result.path, "mismatches": [list(item) for item in check.mismatches]}
        raise IdentityMismatch(f"IDENTITY_MISMATCH: 经 {result.path} 登录到的设备与 CSV 不符（" + "; ".join(
            f"{field} 应为 {expected or '空'}，实际 {observed or '空'}" for field, expected, observed in check.mismatches)
            + "）：连到的不是这台 UFM，停止，不改用口令")

    def login(self, node: UfmNode, allow_change: bool) -> NodeResult:
        return self.login_into(node, NodeResult(node.hostname, self.plan.role_of(node)), allow_change)

    def connect(self, node: UfmNode, result: NodeResult) -> None:
        """The deployment key over IPv4 first; only when it does not log in, the route decided for this UFM with the
        root password (jump, or direct) — the UFM and the server may have no direct route. Logged in by the key but
        not this UFM: IdentityMismatch, no password is sent (B0-O13 (a), I-054)."""
        try:
            self.key_access(node, result, "key-login")
            return
        except IdentityMismatch:
            raise
        except HostKeyConflict as exc:   # v3.1.6 B0 WP-6
            if self.host_key_changed(node, result, exc, False).status != "VERIFIED":
                detail, result.detail = result.detail, ""
                raise UfmError(f"{node.hostname} {result.status}: {detail}") from None
            return
        except UfmError as exc:
            self.say(f"    部署服务器公钥直连未成功，按登录前归类的路径改用 root 口令: {str(exc)[:160]}")
        if not self.creds.new_password:
            if self.ask_ufm_password is None:
                raise UfmError(f"{node.hostname}（{node.address}）公钥直连未成功，且没有提供 root 口令")
            self.creds.new_password = self.ask_ufm_password()
        self.login_into(node, result, allow_change=False)
        if result.status != "VERIFIED":
            detail, result.detail = result.detail, ""   # the caller's stop() reports it once
            raise UfmError(f"{node.hostname}（{node.address}）无法登录（{result.status}）: {detail}")

    def login_into(self, node: UfmNode, result: NodeResult, allow_change: bool) -> NodeResult:
        try:
            return self.login_paths(node, result, allow_change)
        except NotAuthorized as exc:
            return self.stop(result, "NOT_AUTHORIZED", str(exc))

    def host_key_changed(self, node: UfmNode, result: NodeResult, conflict: HostKeyConflict,
                         allow_change: bool) -> NodeResult:
        """v3.1.6 B0 WP-6 (B0-O2 (a), O8 (b); v3.1.4 指导 :740): the key login found another host key for this UFM in
        this server's own ~/.ssh/known_hosts. Logged in by the decided route (jump, or link-local on this subnet)
        with the MAC checked, that session reads the device's host key; check only records WOULD_REFRESH;
        --apply lets login_path.refresh_target_host_key remove this one address after the operator's go-ahead and
        retry the key once. Without such a session (IPv4 only) only a name in --refresh-host-key skips the
        verification; otherwise, and for every other file (the VIP's, a jump's), it is only reported."""
        change = conflict.change
        route = self.routes.get(node.hostname)
        manual = (f"ssh-keygen -f {shlex.quote(change.known_hosts_path)} -R {shlex.quote(change.address)}"
                  if change is not None else f"ssh-keygen -R {node.address}")
        summary = (f"本机 known_hosts 里 {change.address} 的主机密钥与设备送来的不同（{change.key_type} "
                   f"{change.new_fingerprint}）" if change is not None else "本机 known_hosts 主机密钥冲突")
        allowed = {node.address}
        if route is not None and route.path == "direct" and route.same_subnet:
            allowed.add(f"{login_rules.link_local_from_mac(node.mac)}%{route.same_subnet}")
        try:
            if change is None or change.location != "local" or change.address not in allowed:
                raise ValueError("告警不是这台 UFM 在本机 known_hosts 里的地址")
            editor = login_rules.LocalKnownHostsEditor(Path(change.known_hosts_path), home=local_home())
        except ValueError as exc:
            return self.stop(result, "HOSTKEY_CONFLICT", f"{summary}；只报告、不改文件（{exc}）；人工核实设备身份后执行: "
                                                         f"{manual}")
        forced = node.hostname in self.refresh_host_key
        read = None
        if route is not None and (route.path == "jump" or route.same_subnet):
            self.say(f"  {node.hostname}: {summary}；经登录前归类的路径登录并核 MAC，再读设备主机公钥核实")
            self.login_into(node, result, allow_change)
            if result.status != "VERIFIED":
                return result

            def read(key_type: str) -> Optional[str]:
                return self.device_fingerprint(node, result, key_type)
        elif not forced:
            return self.stop(result, "HOSTKEY_CONFLICT", f"{summary}；只能经 IPv4 登录，没有另一条已核验的会话可以核实，"
                                                         f"文件未改；确认做过 factory reset 后加 --refresh-host-key "
                                                         f"{first_label(node.hostname)} 重跑，或人工核实后执行: {manual}")
        try:
            if not self.apply:   # check: never calls the library (it has no read-only mode)
                fingerprint = read(change.key_type) if read is not None else None
                if read is not None and fingerprint != change.new_fingerprint:
                    raise ValueError(f"经已核验的会话读到的指纹 {fingerprint or '无'} 与告警不同")
                record = login_rules.HostKeyRefreshRecord(
                    change.location, change.jump, change.known_hosts_path, change.lines, change.address,
                    change.key_type, tuple(row[2] for row in editor.fingerprints(change.address)),
                    change.new_fingerprint, "verified" if read is not None else "operator-forced-unverified",
                    "refresh-pending", None)
            else:
                def retry() -> None:
                    try:
                        self.key_access(node, result, "key-login-retry")
                    except KeyLoginRejected:
                        return None   # the deployment key went with the factory reset; the configuration steps put it back
                record = login_rules.refresh_target_host_key(
                    change, editor, read_device_fingerprint=read, retry=retry, operator_forced=read is None,
                    before_remove=lambda: self.authorize(node, f"删除本机 known_hosts 里 {change.address} 的旧主机密钥"
                                                               "并重试公钥直连"))
        except NotAuthorized as exc:
            return self.stop(result, "NOT_AUTHORIZED", str(exc))
        except IdentityMismatch as exc:
            return self.stop(result, "IDENTITY_MISMATCH", str(exc))
        except (ValueError, OSError, subprocess.SubprocessError, UfmError) as exc:
            return self.stop(result, "HOSTKEY_CONFLICT", f"{summary}；未删除或刷新未完成（{exc}）；人工核实后执行: {manual}")
        result.host_key = host_key_fact(record)
        if record.result == "refresh-pending":
            result.steps.append({"step": "host_key", "outcome": "WOULD_REFRESH",
                                 "detail": f"--apply 时删除本机 known_hosts 里 {change.address} 的旧记录并重试（{result.host_key['note']}）"})
            self.say(f"    {node.hostname} [host_key] WOULD_REFRESH：{change.address}（{result.host_key['note']}）")
            if result.status != "VERIFIED":
                return self.stop(result, "NEEDS_CONFIGURATION", "只读检查：主机密钥待刷新，--apply 时处理")
            return result
        self.say(f"    {node.hostname} [host_key] REFRESHED：{change.address}（{result.host_key['note']}）")
        if result.status != "VERIFIED":   # named and IPv4 only: the retried key, else the password over IPv4
            if self.access.get(node.hostname, {}).get("path") == "IPv4-KEY":
                result.status = "VERIFIED"
                result.password = "key"
            else:
                self.login_into(node, result, allow_change)
        return result

    def device_fingerprint(self, node: UfmNode, result: NodeResult, key_type: str) -> Optional[str]:
        """The host key of the type in the warning, read over this run's session whose MAC was checked."""
        if not re.fullmatch(r"[A-Za-z0-9]{1,16}", key_type):
            return None
        text = self.run_script(node, result, "host-key-read",
                               f"set -u\ncat /etc/ssh/ssh_host_{key_type.casefold()}_key.pub\n")
        return next((value for value in map(host_key_fingerprint, text.splitlines()) if value), None)

    def login_paths(self, node: UfmNode, result: NodeResult, allow_change: bool) -> NodeResult:
        """One path, the one decided before login (I-037 rules 3 and 7): a chosen path that fails is reported, never
        replaced by another; the only exception is IPv4 after an unreachable same-subnet link-local (设计 :113)."""
        route = self.routes.get(node.hostname)
        if route is not None and route.path == "jump":
            return self.login_jump(node, result, allow_change)
        return self.login_direct(node, result, allow_change, route)

    def login_jump(self, node: UfmNode, result: NodeResult, allow_change: bool) -> NodeResult:
        attachment = self.plan.attachments[node.hostname]
        self.say(f"  {node.hostname}: 经跳板 {attachment.leaf.hostname} {attachment.port} 走 IPv6 link-local")
        result.path = "OOB-IPv6"
        result.route = {"leaf": attachment.leaf.hostname, "port": attachment.port}
        retry = f"；可用 --direct-access {first_label(node.hostname)} 重试"
        try:
            jump, neighbor = self.oob_route(node, attachment, result)
        except RouteStop as exc:
            return self.stop(result, exc.status, str(exc) + ("" if exc.status == "CABLE_CHECK_FAILED" else retry))
        except UfmError as exc:
            return self.stop(result, "OOB_DISCOVERY_FAILED", str(exc) + retry)
        result.neighbor = asdict(neighbor)
        self.say(f"    跳板 {jump.hostname}: 邻居 {neighbor.ipv6}%{neighbor.interface} VRF {neighbor.vrf}"
                 f"（来源 {neighbor.source}）")
        access = {"path": "OOB-IPv6", "jump": jump, "neighbor": neighbor}
        outcome = self.login_path(node, result, access, allow_change)
        if outcome == "HOSTKEY_CONFLICT":   # WP-6 item 7: the inner ssh's entry is on the jump; never written to
            retry = (f"；冲突在跳板 {jump.hostname} 上 {self.creds.eth_user} 的 known_hosts（地址 {neighbor.ipv6}），"
                     "只报告：不删除、不向跳板发任何写命令，请人工核实后处理")
        return self.finish_login(node, result, access, outcome, retry)

    def login_direct(self, node: UfmNode, result: NodeResult, allow_change: bool,
                     route: Optional["login_rules.Route"]) -> NodeResult:
        """I-037 设计 :111-114: on this server's subnet first the CSV MAC's link-local; IPv4 only when that cannot be
        reached, and only after this server's neighbour entry for the IPv4 shows the CSV MAC; else IPv4."""
        if route is not None and route.same_subnet:
            link_local = login_rules.link_local_from_mac(node.mac)
            access = {"path": "LINK-LOCAL", "address": f"{link_local}%{route.same_subnet}"}
            self.say(f"  {node.hostname}: 同网段，经本机 {route.same_subnet} 走 link-local {link_local}")
            result.path = "LINK-LOCAL"
            outcome = self.login_path(node, result, access, allow_change)
            if outcome not in {"UNREACHABLE", "TIMEOUT", "REFUSED"}:
                return self.finish_login(node, result, access, outcome)
            mac = local_neighbor_mac(node.address)
            if mac is None:   # no entry: one ping, then read it again (v3.1.5 WP-3 item 1)
                try:
                    subprocess.run(["ping", "-c", "1", "-W", "1", node.address], capture_output=True, timeout=15,
                                   check=False)
                except (OSError, subprocess.SubprocessError):
                    pass
                mac = local_neighbor_mac(node.address)
            if mac is None:
                return self.stop(result, "UNREACHABLE", f"link-local 不可达；本机邻居表没有 {node.address} 的记录"
                                                        "（ping 一次后仍没有），不改走 IPv4")
            if mac != node.mac:
                result.identity = {"path": "IPv4", "mismatches": [["mac", node.mac, mac]]}
                return self.stop(result, "IDENTITY_MISMATCH", f"本机邻居表里 {node.address} 的 MAC 为 {mac}，CSV 为 "
                                                              f"{node.mac}：不改走 IPv4，未发送口令")
        self.say(f"  {node.hostname}: 直接登录 IPv4 {node.address}")
        result.path, access = "IPv4", {"path": "IPv4"}
        return self.finish_login(node, result, access, self.login_path(node, result, access, allow_change))

    def finish_login(self, node: UfmNode, result: NodeResult, access: dict, outcome: str,
                     hint: str = "") -> NodeResult:
        if outcome != "OK":
            help_text = OUTCOME_HELP.get(outcome, "结果未知，停止，不重试")
            if outcome == "AUTH_REJECTED" and not self.creds.factory_password:
                help_text = "root 新密码被拒绝（该命令不使用出厂密码）；不切换访问路径，请核实凭据"
            if outcome in {"UNREACHABLE", "TIMEOUT"}:
                help_text = f"{access['path']} 不可达；{help_text}"
            return self.stop(result, outcome, help_text + hint)
        try:
            self.check_login_identity(node, result)
        except IdentityMismatch as exc:
            return self.stop(result, "IDENTITY_MISMATCH", str(exc))
        result.status = "VERIFIED"
        self.access[node.hostname] = access
        if access["path"] == "OOB-IPv6":
            self.oob[node.hostname] = access
        facts = result.facts
        self.say(f"    已核验: hostname={facts.get('hostname')} mac={facts.get('mac')} "
                 f"ipv4={facts.get('ipv4') or '-'} os={facts.get('os')}")
        if result.password == "factory":
            self.say("    注意: root 仍在使用出厂密码（未被强制改密）")
        return result

    def stop(self, result: NodeResult, status: str, detail: str) -> NodeResult:
        result.status = status
        result.detail = (result.detail + "; " if result.detail else "") + detail
        self.say(f"    STOP {status}: {result.detail}")
        return result

    # ---------------------------------------------------------- init steps

    def run_script(self, node: UfmNode, result: NodeResult, step: str, script: str, *,
                   extra: tuple = (), access: Optional[dict] = None, session_timeout: int = 0) -> str:
        """Upload one generated script (no secrets) by base64, verify its sha256 on the UFM, run it with bash."""
        access = access or self.access[node.hostname]
        text = script if script.endswith("\n") else script + "\n"
        # Owner 2026-10-22 (REQ-F01 2026-10-12 item 3): the generated script must parse before it is sent.
        problem = bash_syntax_problem(text)
        if problem:
            self.save_script(node, step, text, f"本地 bash -n 语法检查未通过，没有发送到设备: {problem}\n", None)
            raise UfmError(f"{step}: 生成的脚本未通过本地 bash -n 语法检查，没有发送到设备: {problem[-300:]}")
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        # Owner 2026-10-20: the scripts that really ran on the UFM are kept there for manual use as
        # /root/.setup/<run>/<NNN>-<step>.sh. The UFM numbers each script when it lands (highest number + 1),
        # so an attempt that never reached it takes no number and a session lost mid-script keeps its own.
        payload = base64.b64encode(text.encode("utf-8")).decode("ascii")
        loader = (f"umask 077 && d={shlex.quote(f'{REMOTE_WORK}/{self.run_dir.name}')} && mkdir -p \"$d\" && n=0"
                  " && for p in \"$d\"/[0-9][0-9][0-9]-*.sh; do [ -e \"$p\" ] || continue;"
                  " i=$(expr \"${p##*/}\" : '\\([0-9]*\\)'); i=$(expr \"$i\" + 0);"
                  " if [ \"$i\" -gt \"$n\" ]; then n=$i; fi; done"
                  f" && f=$(printf '%s/%03d-%s.sh' \"$d\" $((n + 1)) {shlex.quote(step)})"
                  f" && if printf %s {payload} | base64 -d > \"$f\""
                  f" && printf '%s  %s\\n' {digest} \"$f\" | sha256sum -c --status;"
                  f" then printf '{SCRIPT_TAG}%s\\n' \"${{f##*/}}\"; exec bash \"$f\";"
                  " else rm -f \"$f\"; echo 'script transfer failed the sha256 check' >&2; exit 1; fi")
        marker = os.urandom(12).hex()
        login_pw = self.creds.factory_password if result.password == "factory" else self.creds.new_password
        responder = Responder(ufm_destination=self.ufm_destination(node, access), login_password=login_pw,
                              new_password=self.creds.new_password, allow_change=False,
                              outer_password=self.creds.eth_password or "", extra=extra)
        try:
            session = interactive_run(self.ufm_argv(node, access, ["sh", "-c", loader], marker), responder,
                                      session_timeout or max(self.timeout * 12, 180), self.secrets())
        except UfmError as exc:
            self.save_script(node, step, text, str(exc), None)
            raise
        landed = re.search(r"^" + re.escape(SCRIPT_TAG) + r"([0-9]{3}-[A-Za-z0-9._-]+)\.sh\s*$",
                           session.output, re.M)
        self.save_script(node, step, text, session.output, landed.group(1) if landed else None)
        body, rc = framed_status(session.output, marker)
        if body is None:
            outcome = classify(session, responder, marker)
            error = UfmUnreachable if outcome in {"UNREACHABLE", "TIMEOUT"} else UfmError
            raise error(f"{step}: 远端执行结果未知（{outcome}，exit={session.exit_code}）: "
                        f"{session.output.strip()[-400:]}")
        body = re.sub(r"\A" + re.escape(SCRIPT_TAG) + r".*\n?", "", body)
        if rc != 0:
            raise UfmError(f"{step}: 远端脚本退出码 {rc}: {body.strip()[-600:]}")
        return body

    def save_script(self, node: UfmNode, step: str, text: str, output: str, landed: Optional[str]) -> None:
        """Locally the script and its output carry the UFM's number (<host>-<NNN>-<step>); an attempt that
        never ran on the UFM is kept as <run order>-<host>-<step>-not-run."""
        name = f"{node.hostname}-{landed}" if landed else self.numbered(f"{node.hostname}-{step}-not-run")
        self.save(f"{name}.sh", text)
        self.save(f"{name}.out.txt", output)

    def backup_dir(self) -> str:
        return f"{REMOTE_BACKUP}/{self.run_dir.name}"

    def step_hostname(self, node: UfmNode, result: NodeResult) -> str:
        probe = host.parse_kv(self.run_script(node, result, "hostname-check", host.hostname_script(
            node.hostname, None, check_only=True, hosts_file=True)))
        result.facts["hostname_before"] = probe.get("before", "")
        changes = ([f"hostnamectl set-hostname {node.hostname}"] if probe.get("would_hostname") == "yes" else []) + (
            [f"/etc/hosts 追加 127.0.1.1 {node.hostname}"] if probe.get("would_hosts") == "yes" else [])
        if not changes:
            return "UNCHANGED"
        if not self.apply:
            return self.would("hostname", "；".join(changes))
        self.authorize(node, "hostname: " + "；".join(changes))
        facts = host.parse_kv(self.run_script(node, result, "hostname", host.hostname_script(
            node.hostname, self.backup_dir(), hosts_file=True)))
        if facts.get("after", "").casefold() != node.hostname.casefold():
            raise UfmError(f"hostname 设置后读回为 {facts.get('after')!r}，应为 {node.hostname}")
        if facts.get("in_hosts") != "yes":
            raise UfmError(f"/etc/hosts 中仍没有 {node.hostname}（已尝试追加 127.0.1.1）")
        renamed = facts.get("before", "").casefold() != node.hostname.casefold()
        return "CHANGED" if renamed or facts.get("hosts_added") == "yes" else "UNCHANGED"

    def step_ipmi_lan(self, node: UfmNode, result: NodeResult) -> str:
        cidr = self.plan.addresses.get(self.plan.role_of(node), {}).get("ipmi")
        if not cidr:
            return "SKIPPED"
        interface = ipaddress.IPv4Interface(cidr)
        gateway = self.plan.ipmi_gateways.get(self.plan.role_of(node)) or node.gateway
        want = {"ip": str(interface.ip), "mask": str(interface.netmask), "gateway": gateway}
        before = host.parse_lan_print(self.run_script(node, result, "ipmi-lan-read",
                                                      host.ipmi_lan_read_script(self.ipmi_channel)))
        result.facts["ipmi_before"] = before
        # Owner 2026-10-21: the admin user manages power over the network, so IPMI over LAN (the channel's
        # Access Mode) must be on; ufm01 had it disabled and every lanplus session failed.
        access = host.parse_channel_access(self.run_script(node, result, "ipmi-access-read",
                                                           host.ipmi_channel_access_script(self.ipmi_channel)))
        result.facts["ipmi_access_before"] = access
        lan_ok, access_ok = host.lan_matches(before, want), host.lan_access_on(access)
        if lan_ok and access_ok:
            return "UNCHANGED"
        actions = [] if lan_ok else [f"IPMI LAN 通道 {self.ipmi_channel} 设为 static {want['ip']}/{want['mask']} "
                                     f"网关 {want['gateway']}"]
        if not access_ok:
            actions.append(f"开启 IPMI over LAN（通道 {self.ipmi_channel} Access Mode "
                           f"{access.get('volatile') or '未知'} → always available）")
        action = "；".join(actions)
        if not self.apply:
            return self.would("ipmi_lan", action)
        self.authorize(node, action)
        if not access_ok:
            after_access = host.parse_channel_access(self.run_script(
                node, result, "ipmi-access-set", host.ipmi_channel_access_script(self.ipmi_channel, enable=True)))
            if not host.lan_access_on(after_access):
                raise UfmError(f"`ipmitool lan set {self.ipmi_channel} access on` 后读回 Access Mode 仍为 {after_access}")
        if lan_ok:
            return "CHANGED"
        body = self.run_script(node, result, "ipmi-lan-set", host.ipmi_lan_set_script(
            self.ipmi_channel, want["ip"], want["mask"], want["gateway"]))
        after = host.parse_lan_print(body)
        if not host.lan_matches(after, want):
            results = [line[len("lanset="):] for line in body.splitlines() if line.startswith("lanset=")]
            refused = bool(results) and all(not item.startswith("0 ") for item in results) and after == before
            raise UfmError(f"IPMI LAN 设置后读回不符: {after}，应为 static {want}"
                           + ("（BMC 拒绝了全部写入：Dell iDRAC 常见于系统锁定模式或主机侧 IPMI 权限受限，"
                              "需要先在 iDRAC 中放开）" if refused else "")
                           + f"；各命令（退出码 命令 | 输出）: {'; '.join(results)}")
        return "CHANGED"

    def step_ipmi_user(self, node: UfmNode, result: NodeResult) -> str:
        # Same decision in both modes: no IPMI address for this role in global means no IPMI user step.
        if not self.plan.addresses.get(self.plan.role_of(node), {}).get("ipmi"):
            return "SKIPPED"
        if self.apply and not self.creds.ipmi_password:
            return "SKIPPED"
        users = host.parse_user_list(self.run_script(node, result, "ipmi-user-read",
                                                     host.ipmi_user_list_script(self.ipmi_channel)))
        uid, create = host.pick_ipmi_user_id(users, self.ipmi_user)
        # Owner 2026-10-19: the IPMI user's password is the root new password.
        ipmi_pw = self.creds.ipmi_password or self.creds.new_password
        prompt = (("ipmi-password", host.IPMI_PASSWORD_PROMPT, ipmi_pw),)
        problems = ["用户不存在"] if create else []
        if not create:
            access = host.parse_getaccess(self.run_script(node, result, "ipmi-user-access",
                                                          ipmi_getaccess_script(self.ipmi_channel, uid)))
            if access != {"User Name": self.ipmi_user, **host.IPMI_ADMIN_ACCESS}:
                problems.append("权限或启用状态不符")
            # The password cannot be read back, but `ipmitool user test` checks it (prompted, never argv).
            if not self.ipmi_password_ok(node, result, uid, prompt):
                problems.append("密码不是 root 新密码")
            if not problems:
                return "UNCHANGED"
        action = (f"{'创建' if create else '更新'} IPMI 用户 {self.ipmi_user}（ID {uid}；{'、'.join(problems)}）："
                  "密码设为 root 新密码、管理员权限、启用")
        if not self.apply:
            return self.would("ipmi_user", action)
        self.authorize(node, action)
        access = host.parse_getaccess(self.run_script(
            node, result, "ipmi-user-set",
            host.ipmi_user_set_script(self.ipmi_channel, uid, self.ipmi_user, create), extra=prompt))
        if access != {"User Name": self.ipmi_user, **host.IPMI_ADMIN_ACCESS}:
            raise UfmError(f"IPMI 用户 {self.ipmi_user}（ID {uid}）读回不符: {access}")
        if not self.ipmi_password_ok(node, result, uid, prompt):
            # ufm01 2026-10-21: right after the user was created the password did not take; set it once more.
            self.run_script(node, result, "ipmi-user-password", host.ipmi_user_set_script(
                self.ipmi_channel, uid, self.ipmi_user, False), extra=prompt)
            if not self.ipmi_password_ok(node, result, uid, prompt):
                raise UfmError(f"IPMI 用户 {self.ipmi_user}（ID {uid}）设置密码后 `ipmitool user test` 仍校验失败")
            result.facts["ipmi_password_retried"] = True
            self.say(f"    [ipmi_user] 密码设置后校验未通过，已重设一次并校验通过")
        result.facts["ipmi_user_id"] = uid
        return "CREATED" if create else "UPDATED"

    def step_ipmi_power(self, node: UfmNode, result: NodeResult) -> str:
        """Owner 2026-10-21: the IPMI user is for viewing/managing power over the network; tested on the UFM:
        `ipmitool -I lanplus -H <BMC> -U <user> -a chassis power status` must answer (read-only)."""
        cidr = self.plan.addresses.get(self.plan.role_of(node), {}).get("ipmi")
        if not cidr or (self.apply and not self.creds.ipmi_password):
            return "SKIPPED"
        done = {step["step"]: step["outcome"] for step in result.steps}
        if any(done.get(step, "").startswith("WOULD") or done.get(step) in {"FAILED", "SKIPPED"}
               for step in ("ipmi_lan", "ipmi_user")):
            return "NOT_TESTED"   # the IPMI configuration is not in place yet
        address = str(ipaddress.IPv4Interface(cidr).ip)
        ipmi_pw = self.creds.ipmi_password or self.creds.new_password
        body = self.run_script(node, result, "ipmi-power-status",
                               host.ipmi_lan_power_status_script(address, self.ipmi_user),
                               extra=(("ipmi-lan-password", host.IPMI_LAN_PASSWORD_PROMPT, ipmi_pw),))
        state = re.search(r"Chassis Power is (\w+)", body)
        if not state:
            raise UfmError(f"在 UFM 上用 {self.ipmi_user} 经 IPMI over LAN 查看电源状态失败"
                           f"（ipmitool -I lanplus -H {address} -U {self.ipmi_user} chassis power status）: "
                           f"{' '.join(body.split())[-300:]}")
        result.facts["ipmi_power"] = state.group(1)
        return "OK"

    def ipmi_password_ok(self, node: UfmNode, result: NodeResult, uid: int, prompt: tuple) -> bool:
        test = host.parse_kv(self.run_script(node, result, "ipmi-user-test", host.ipmi_user_test_script(uid),
                                             extra=prompt))
        return test.get("password_ok") == "yes"

    def network_facts(self, node: UfmNode, result: NodeResult, step: str,
                      access: Optional[dict] = None) -> dict:
        devices = [self.plan.mgmt_device] + sorted(node_others(self.plan, node))
        return host.parse_network_facts(self.run_script(node, result, step, host.network_facts_script(devices),
                                                        access=access))

    def step_netplan(self, node: UfmNode, result: NodeResult) -> str:
        desired = node_netplan(self.plan, node)
        files = host.parse_netplan_listing(self.run_script(node, result, "netplan-read",
                                                           host.NETPLAN_READ_SCRIPT))
        for path, text in files.items():
            self.save(self.numbered(f"{node.hostname}-before-{os.path.basename(path)}"), text)
        conflicts = host.netplan_conflicts(files, desired)
        config_ok = not conflicts and host.netplan_equivalent(host.effective_ethernets(files), desired)
        problems = []
        if config_ok:
            problems, pending = node_network_problems(self.plan, node,
                                                      self.network_facts(node, result, "network-read"))
            if not problems:
                result.facts["network_pending"] = pending
                return "UNCHANGED"
        # I-055 修法 3 (B6-O2): a node already in HA (not pacemaker's own default cluster, I-009) never gets a
        # whole `netplan apply`; only the HA link's ignore-carrier is written, then networkd reloads that file.
        status = self.ha_read_status(node, result, "netplan-ha-status")
        if (not ha_default_cluster(status, node)
                and ha_cluster_kind(status, self.plan.nodes, self.plan.vip)[0] != "absent"):
            if config_ok:   # B6-O3 (a)
                raise UfmError(f"HA 已配置：netplan 文件已符合，但运行状态不符（{'; '.join(problems)}）；"
                               "不整机 netplan apply，请人工处理")
            plain = host.netplan_document(self.plan.mgmt_device, node.interface, node.gateway,
                                          node_others(self.plan, node))
            if conflicts or not host.netplan_equivalent(host.effective_ethernets(files), plain):   # B6-O4 (a)
                raise UfmError("HA 已配置：netplan 与期望的差别不只 HA 口的 ignore-carrier"
                               + (f"（另有文件也配置了这些接口: {', '.join(conflicts)}）" if conflicts else "")
                               + "；不整机 netplan apply，设备上未做改动，请人工处理")
            device = self.plan.logical["eth1"]
            unit = f"10-netplan-{device}.network"
            yaml_text = host.render_netplan(desired)
            self.save(self.numbered(f"{node.hostname}-01-netcfg.yaml"), yaml_text)
            action = (f"HA 已配置：写入 {host.NETPLAN_TARGET}（只差 {device} 的 ignore-carrier，内容见运行目录 "
                      f"{node.hostname}-01-netcfg.yaml），netplan generate，核对 /run/systemd/network 只有 {unit} "
                      "变化后 networkctl reload，不整机 netplan apply")
            if not self.apply:
                return self.would("netplan", action)
            self.authorize(node, action)
            backup = self.backup_dir()
            try:
                body = self.run_script(node, result, "netplan-reload",
                                       host.netplan_reload_script(yaml_text, backup, device))
            except UfmError as exc:   # the operator needs the backup path; no automatic rollback (I-038)
                raise UfmError(f"{exc}；设备上的原配置备份在 {backup}") from exc
            reload = host.parse_kv(body)
            if reload.get("result") != "reloaded":   # B6-O5 (a)
                raise UfmError(f"HA 已配置：/run/systemd/network 的变化不是只有 {unit}"
                               f"（{reload.get('changed') or '没有变化'}），已还原 netplan 文件、未 reload"
                               f"（{reload.get('result') or '无结果'}）；备份在 {backup}")
            problems, pending = node_network_problems(self.plan, node,
                                                      self.network_facts(node, result, "network-verify-reload"))
            if problems:
                raise UfmError(f"networkctl reload 后核验未通过: {'; '.join(problems)}；设备上的原配置备份在 {backup}")
            result.facts["network_pending"] = pending
            result.facts["netplan_reload"] = {"changed": reload["changed"].split(), "backup": backup}
            self.say(f"    HA 已配置：只 reload 了 {unit}，未整机 netplan apply（备份 {backup}）")
            return "CHANGED"
        if config_ok:
            self.say(f"    netplan 内容已符合，但运行状态不符（{'; '.join(problems)}），只重新 apply")
        elif conflicts:
            self.say(f"    这些 netplan 文件也配置了相同接口，将移入备份目录: {', '.join(conflicts)}")
        yaml_text = host.render_netplan(desired)
        self.save(self.numbered(f"{node.hostname}-01-netcfg.yaml"), yaml_text)
        action = ("netplan apply（文件已符合）" if config_ok else
                  f"写入 {host.NETPLAN_TARGET}（内容见运行目录 {node.hostname}-01-netcfg.yaml）"
                  + (f"，移走 {', '.join(conflicts)}" if conflicts else "") + "，netplan generate 后 apply")
        if not self.apply:
            return self.would("netplan", action)
        self.authorize(node, action)
        backup = self.backup_dir()
        body = self.run_script(node, result, "netplan-apply",
                               host.netplan_apply_script(yaml_text, conflicts, backup, write=not config_ok))
        if "result=apply_scheduled" not in body:
            raise UfmError(f"netplan apply 未排程: {body.strip()[-400:]}")
        result.facts["netplan_backup"] = backup
        self.say(f"    netplan apply 已在设备上延后执行（备份 {backup}）；等待后用新的 IPv4 会话核验")
        return self.verify_after_apply(node, result, backup)

    def verify_after_apply(self, node: UfmNode, result: NodeResult, backup: str) -> str:
        """A fresh IPv4 session must re-verify MAC, addresses and route; the pre-change session proves nothing."""
        first, interval, attempts = self.apply_wait
        time.sleep(first)
        keyed = self.access.get(node.hostname, {}).get("path") == "IPv4-KEY"
        routes = [({"path": "IPv4-KEY" if keyed else "IPv4"}, "IPv4")]
        if node.hostname in self.oob:
            routes.append((self.oob[node.hostname], "OOB"))
        last = "未执行"
        for attempt in range(1, attempts + 1):
            for access, label in routes:
                try:
                    # The old runtime state can already pass the checks; only trust it once apply has run.
                    applied = host.parse_kv(self.run_script(node, result, f"netplan-applied-{attempt}-{label}",
                                                            netplan_applied_script(backup), access=access))
                    facts = (self.network_facts(node, result, f"network-verify-{attempt}-{label}", access=access)
                             if applied.get("rc") == "0" else {})
                except UfmUnreachable as exc:
                    last = f"{label}: {exc}"
                    continue
                except (UfmError, host.HostConfigError) as exc:
                    last = f"{label}: {exc}"
                    break
                if not applied.get("rc"):
                    last = f"{label}: netplan apply 尚未执行（延后的定时任务未到）"
                    break
                if applied["rc"] != "0":
                    raise UfmError(f"netplan apply 退出码 {applied['rc']}: {applied.get('log', '')}；"
                                   f"设备上的原配置备份在 {backup}")
                problems, pending = node_network_problems(self.plan, node, facts)
                if problems:
                    last = f"{label}: " + "; ".join(problems)
                    break
                self.access[node.hostname] = access
                result.facts["network_pending"] = pending
                result.facts["ipv4_verified_from_server"] = label == "IPv4"
                if label != "IPv4":
                    self.say(f"    注意: 部署服务器到 {node.address} 不通，已经 OOB 新会话核验管理口地址与默认路由")
                return "CHANGED"
            self.say(f"    核验 [{attempt}/{attempts}] 未通过: {last[:200]}")
            if attempt < attempts:
                time.sleep(interval)
        raise UfmError(f"netplan apply 后核验未通过: {last}；请经 OOB 登录检查，设备上的原配置备份在 {backup}")

    def step_authorized_keys(self, node: UfmNode, result: NodeResult) -> str:
        if not self.plan.key_lines:
            return "SKIPPED"
        probe = host.parse_kv(self.run_script(node, result, "authorized-keys-check",
                                              host.authorized_keys_script(self.plan.key_lines, check_only=True)))
        if probe.get("missing") == "0":
            return "UNCHANGED"
        action = f"向 root 的 authorized_keys 追加 {probe.get('missing')} 个公钥（{', '.join(self.plan.public_keys)}）"
        if not self.apply:
            return self.would("authorized_keys", action)
        self.authorize(node, action)
        facts = host.parse_kv(self.run_script(node, result, "authorized-keys",
                                              host.authorized_keys_script(self.plan.key_lines)))
        if facts.get("missing") != "0":
            raise UfmError(f"写入后仍缺少 {facts.get('missing')} 个部署服务器公钥")
        return "UNCHANGED" if facts.get("added") == "0" else f"ADDED_{facts.get('added')}"

    def key_access(self, node: UfmNode, result: NodeResult, step: str) -> dict:
        """Key-only IPv4 session; then the identity check of an IPv4 path: MAC, address, netmask and gateway
        (I-037 rule 8). A refused key, a host-key conflict and an identity mismatch raise their own errors."""
        access = {"path": "IPv4-KEY"}
        marker = os.urandom(12).hex()
        responder = Responder(ufm_destination=self.ufm_destination(node, access), login_password="",
                              new_password="", allow_change=False)
        session = interactive_run(self.ufm_argv(node, access, identity_command(self.plan.mgmt_device), marker),
                                  responder, max(self.timeout * 4, 60), self.secrets())
        self.save(self.numbered(f"{node.hostname}-{step}.txt"), session.output)
        outcome = classify(session, responder, marker)
        if outcome != "OK":
            detail = (f"部署服务器公钥登录 {self.creds.ufm_user}@{node.address} 失败（{outcome}）: "
                      f"{session.output.strip()[-300:]}")
            if outcome == "AUTH_REJECTED":
                raise KeyLoginRejected(detail)
            if outcome == "HOSTKEY_CONFLICT":
                raise HostKeyConflict(detail, login_rules.parse_host_key_change(session.output))
            raise UfmError(detail)
        facts = parse_facts(extract_framed(session.output, marker))
        result.path, result.facts = "IPv4-KEY", {**result.facts, **facts}
        self.check_login_identity(node, result)
        self.access[node.hostname] = access
        return facts

    def step_key_login(self, node: UfmNode, result: NodeResult) -> str:
        """Informational: the UFM may have no direct route from the deployment server; never blocks."""
        if any(step["step"] == "authorized_keys" and step["outcome"].startswith("WOULD") for step in result.steps):
            return "NOT_TESTED"   # inspect mode: the keys are not installed yet
        try:
            self.key_access(node, result, "key-login")
            return "OK"
        except UfmError as exc:
            result.facts["key_login"] = str(exc)
            self.say(f"    注意: 部署服务器暂时无法用公钥直连 {node.address}（{str(exc)[:160]}）；"
                     "公钥已写入，不影响后续步骤")
            # v3.1.6 B2-O7: the warnings go to one list too; the review before HA shows them before the plan
            result.facts.setdefault("attention", []).append(f"部署服务器暂时无法用公钥直连 {node.address}")
            return "WARN_NO_DIRECT_KEY_LOGIN"

    def config_line(self, node: UfmNode, result: NodeResult, step: str, path: str, key: str,
                    value: str, service: str) -> str:
        probe = host.parse_kv(self.run_script(node, result, f"{step}-check", host.config_line_script(
            path, key, value, service, None, check_only=True)))
        if probe.get("result") == "service_missing":
            self.say(f"    注意: {service} 未安装，跳过 {key}")
            result.facts.setdefault("attention", []).append(f"{service} 未安装，跳过 {key}")
            return "SKIPPED_SERVICE_MISSING"
        changes = ([f"{path} 中 {key}={value}（当前 {probe.get('before') or '未设置'}），重启 {service}"]
                   if probe.get("would_write") == "yes" else []) + (
            [f"{service} 被 mask，unmask 并 enable --now"] if probe.get("would_unmask") == "yes" else [])
        if not changes:
            if probe.get("active") != "active":
                raise UfmError(f"{path} 已是 {key}={value}，但 {service} 状态为 {probe.get('active')!r}")
            return "UNCHANGED"
        if not self.apply:
            return self.would(step, "；".join(changes))
        self.authorize(node, "；".join(changes))
        facts = host.parse_kv(self.run_script(node, result, step, host.config_line_script(
            path, key, value, service, self.backup_dir())))
        if facts.get("after") != value or facts.get("active") != "active":
            raise UfmError(f"{path} 读回 {key}={facts.get('after')!r}、{service} 状态 {facts.get('active')!r}，"
                           f"应为 {key}={value} 且 active")
        return "UNCHANGED" if facts.get("before") == value else "CHANGED"

    def step_dns(self, node: UfmNode, result: NodeResult) -> str:
        if not self.plan.dns:
            return "SKIPPED"
        return self.config_line(node, result, "dns", "/etc/systemd/resolved.conf", "DNS",
                                " ".join(self.plan.dns), "systemd-resolved")

    def step_ntp(self, node: UfmNode, result: NodeResult) -> str:
        if not self.plan.ntp:
            return "SKIPPED"
        return self.config_line(node, result, "ntp", "/etc/systemd/timesyncd.conf", "NTP",
                                " ".join(self.plan.ntp), "systemd-timesyncd")

    def step_timezone(self, node: UfmNode, result: NodeResult) -> str:
        probe = host.parse_kv(self.run_script(node, result, "timezone-check",
                                              host.timezone_script(self.plan.timezone, check_only=True)))
        result.facts["ntp_synchronized"] = probe.get("synced", "")
        if probe.get("synced") != "yes":
            self.say("    注意: NTP 尚未同步（timedatectl NTPSynchronized≠yes），请检查 NTP 服务器可达性")
            result.facts.setdefault("attention", []).append(
                "NTP 尚未同步（timedatectl NTPSynchronized≠yes），请检查 NTP 服务器可达性")
        if not self.plan.timezone:
            return "SKIPPED"
        if probe.get("would_timezone") != "yes":
            return "UNCHANGED"
        action = f"timedatectl set-timezone {self.plan.timezone}（当前 {probe.get('before')}）"
        if not self.apply:
            return self.would("timezone", action)
        self.authorize(node, action)
        facts = host.parse_kv(self.run_script(node, result, "timezone", host.timezone_script(self.plan.timezone)))
        if facts.get("after") != self.plan.timezone:
            raise UfmError(f"时区读回 {facts.get('after')!r}，应为 {self.plan.timezone}")
        return "UNCHANGED" if facts.get("before") == self.plan.timezone else "CHANGED"

    def hosts_entries(self) -> list:
        """Both UFMs by their HA link (eth1/eno8403) address, primary first (owner 2026-10-22,
        ufm-manual.log). Empty for a single UFM or when the HA link addresses are not given."""
        device = self.plan.logical.get("eth1")
        if not device or set(self.plan.roles) != set(ROLES):
            return []
        entries = []
        for role in ROLES:
            cidr = self.plan.addresses.get(role, {}).get(device)
            if not cidr:
                return []
            fqdn = self.plan.roles[role]
            entries.append((str(ipaddress.IPv4Interface(cidr).ip), fqdn, first_label(fqdn)))
        return entries

    def step_hosts(self, node: UfmNode, result: NodeResult) -> str:
        """Add the two UFM lines to /etc/hosts when missing; every other line is left alone
        (owner 2026-10-22: 只新增后面两条，前面的不用管)."""
        entries = self.hosts_entries()
        if not entries:
            return "SKIPPED"
        probe = host.parse_kv(self.run_script(node, result, "hosts-check",
                                              host.hosts_entries_script(entries, None, check_only=True)))
        missing = [entry for letter, entry in zip("abcdefghijklmnopqrstuvwxyz", entries)
                   if probe.get(f"entry_{letter}") != "present"]
        if not missing:
            return "UNCHANGED"
        action = "/etc/hosts 追加 " + "；".join(f"{ip} {fqdn} {short}" for ip, fqdn, short in missing)
        if not self.apply:
            return self.would("hosts", action)
        self.authorize(node, action)
        facts = host.parse_kv(self.run_script(node, result, "hosts",
                                              host.hosts_entries_script(entries, self.backup_dir())))
        if facts.get("hosts_ok") != "yes":
            raise UfmError("/etc/hosts 追加后读回仍缺少 UFM 条目")
        return "CHANGED"

    def step_dns_domains(self, node: UfmNode, result: NodeResult) -> str:
        suffix = node.hostname.rstrip(".").split(".", 1)[1] if "." in node.hostname.rstrip(".") else ""
        if not suffix:
            return "SKIPPED"
        return self.config_line(node, result, "dns-domains", "/etc/systemd/resolved.conf", "Domains",
                                suffix, "systemd-resolved")

    def trust(self, nodes: list) -> list:
        """Step 2: root mutual trust, only once both nodes are on key access with verified networking."""
        results = {node.hostname: NodeResult(node.hostname, self.plan.role_of(node), path="IPv4-KEY")
                   for node in nodes}
        if len(nodes) != 2:
            for result in results.values():
                self.stop(result, "SKIPPED", "单节点不需要互信")
            return list(results.values())
        for node in nodes:
            result = results[node.hostname]
            self.say(f"  {node.hostname}: 核验网络配置")
            try:
                if node.hostname not in self.access:   # reuse the session this run already verified
                    self.connect(node, result)
            except (UfmError, host.HostConfigError) as exc:
                self.stop(result, "NOT_READY", f"无法登录: {exc}")
                continue
            try:
                problems, pending = node_network_problems(self.plan, node,
                                                          self.network_facts(node, result, "network-read"))
            except (UfmError, host.HostConfigError) as exc:
                problems, pending = [str(exc)], []
            if problems:
                self.stop(result, "NOT_READY", "网络配置未按 global 完成: " + "; ".join(problems)
                          + "；两端都完成网络配置后再执行 trust")
                continue
            result.facts["network_pending"] = pending
            peer = next(other for other in nodes if other is not node)
            try:
                self.ha_link_check(node, peer, result)
            except (UfmError, host.HostConfigError) as exc:
                self.stop(result, "NOT_READY", str(exc))
        if any(result.status == "NOT_READY" for result in results.values()):
            for result in results.values():
                if result.status != "NOT_READY":
                    self.stop(result, "WAITING_PEER", "对端尚未就绪，本端不做改动")
            return list(results.values())
        pairs = [(nodes[0], nodes[1]), (nodes[1], nodes[0])]
        keys = {}
        try:
            for node, _peer in pairs:
                result = results[node.hostname]
                try:
                    outcome = self.trust_keypair(node, result, keys)
                except (UfmError, host.HostConfigError) as exc:
                    if isinstance(exc, NotAuthorized):
                        raise
                    return self.trust_failed(results, result, "root_keypair", exc)
                result.steps.append({"step": "root_keypair", "outcome": outcome})
                self.say(f"    {node.hostname} [root_keypair] {self.outcome_line(outcome)}")
            for step, action in (("peer_key", self.trust_install), ("peer_login", self.trust_verify)):
                for node, peer in pairs:
                    result = results[node.hostname]
                    try:
                        outcome = action(node, peer, result, keys)
                    except (UfmError, host.HostConfigError) as exc:
                        if isinstance(exc, NotAuthorized):
                            raise
                        return self.trust_failed(results, result, step, exc)
                    result.steps.append({"step": step, "outcome": outcome})
                    self.say(f"    {node.hostname} [{step}] {self.outcome_line(outcome)}")
        except NotAuthorized as exc:
            return [self.stop(result, "NOT_AUTHORIZED", str(exc)) for result in results.values()]
        for result in results.values():
            pending = any(step["outcome"].startswith(("WOULD", "UNVERIFIED")) for step in result.steps)
            result.status = "NEEDS_CONFIGURATION" if pending else "TRUSTED"
        return list(results.values())

    def trust_keypair(self, node: UfmNode, result: NodeResult, keys: dict) -> str:
        probe = host.parse_kv(self.run_script(node, result, "trust-keypair-check",
                                              host.root_keypair_script(check_only=True)))
        outcome = "UNCHANGED"
        if probe.get("would_create") == "yes":
            if not self.apply:
                return self.would("root_keypair", "为 root 生成 ed25519 密钥对（/root/.ssh/id_ed25519）")
            self.authorize(node, "为 root 生成 ed25519 密钥对，并与对端交换公钥")
            probe = host.parse_kv(self.run_script(node, result, "trust-keypair", host.root_keypair_script()))
            outcome = "CREATED"
        if not host.PUBLIC_KEY_RE.fullmatch(probe.get("pubkey", "")):
            raise UfmError(f"读回的 root 公钥格式无效: {probe.get('pubkey')!r}")
        keys[node.hostname] = probe["pubkey"]
        return outcome

    def ha_link_check(self, node: UfmNode, peer: UfmNode, result: NodeResult) -> None:
        """The HA back-to-back link (eth1) must reach the peer's address before trust."""
        device = self.plan.logical.get("eth1")
        cidr = self.plan.addresses.get(self.plan.role_of(peer), {}).get(device or "")
        if not device or not cidr:
            raise UfmError("无法确定 HA 直连接口（eth1）或对端地址，不能确认对端可达")
        address = str(ipaddress.IPv4Interface(cidr).ip)
        facts = host.parse_kv(self.run_script(node, result, "ha-link-ping", host.ping_script(address, device)))
        if facts.get("reachable") != "yes":
            raise UfmError(f"{device} 对端 {peer.hostname} 的 {address} 不通；HA 直连通了再执行 trust")
        result.facts["ha_link"] = f"{device} -> {address} reachable"

    def trust_install(self, node: UfmNode, peer: UfmNode, result: NodeResult, keys: dict) -> str:
        if peer.hostname not in keys:   # inspect mode: the peer has no key pair yet
            return self.would("peer_key", f"把 {peer.hostname} 的 root 公钥（待生成）写入本机 authorized_keys")
        probe = host.parse_kv(self.run_script(node, result, "trust-authorized-keys-check",
                                              host.authorized_keys_script([keys[peer.hostname]], check_only=True)))
        if probe.get("missing") == "0":
            return "UNCHANGED"
        if not self.apply:
            return self.would("peer_key", f"把 {peer.hostname} 的 root 公钥写入本机 authorized_keys")
        self.authorize(node, f"把 {peer.hostname} 的 root 公钥写入 {node.hostname} 的 authorized_keys")
        facts = host.parse_kv(self.run_script(node, result, "trust-authorized-keys",
                                              host.authorized_keys_script([keys[peer.hostname]])))
        if facts.get("missing") != "0":
            raise UfmError(f"{peer.hostname} 的 root 公钥写入后仍缺失")
        return "UNCHANGED" if facts.get("added") == "0" else "ADDED"

    def trust_verify(self, node: UfmNode, peer: UfmNode, result: NodeResult, _keys: dict) -> str:
        if any(step["outcome"].startswith("WOULD") for step in result.steps):
            return "NOT_TESTED"   # inspect mode with keys still to install: nothing to verify yet
        # First without touching known_hosts; only --apply may record the peer host key (accept-new).
        facts = host.parse_kv(self.run_script(node, result, "trust-verify-check",
                                              host.peer_ssh_check_script(peer.address, record_host_key=False)))
        if facts.get("rc") != "0":
            if not self.apply:
                self.say(f"    [peer_login] 不记录主机密钥的公钥登录 {peer.address} 未成功（rc={facts.get('rc')}）："
                         f"{facts.get('error', '').strip()[:160]}；--apply 会记录对端主机密钥后再验证")
                return "UNVERIFIED"
            self.authorize(node, f"记录 {peer.hostname} 的主机密钥（accept-new）并公钥登录验证")
            facts = host.parse_kv(self.run_script(node, result, "trust-verify",
                                                  host.peer_ssh_check_script(peer.address)))
        # Verified by address only: the peer reached at peer.address must own that address.
        if facts.get("rc") != "0" or facts.get("peer_has_address") != "yes":
            raise UfmError(f"从 {node.hostname} 公钥登录 {peer.address} 未通过地址核验（rc={facts.get('rc')}，"
                           f"对端接口上{'有' if facts.get('peer_has_address') == 'yes' else '没有'}该地址）: "
                           f"{facts.get('error', '').strip()}")
        return "OK"

    def trust_failed(self, results: dict, result: NodeResult, step: str, exc: Exception) -> list:
        result.steps.append({"step": step, "outcome": "FAILED", "detail": str(exc)})
        self.stop(result, f"STEP_FAILED_{step.upper()}", str(exc))
        for other in results.values():
            if other is not result and not other.status.startswith("STEP_FAILED"):
                self.stop(other, "INCOMPLETE", f"对端 {result.hostname} 的 {step} 失败，互信未完成")
        return list(results.values())

    def step_upgrade(self, node: UfmNode, result: NodeResult) -> str:
        """Step 3 (UFM only): appliance/OS upgrade to the global version; reboots, then waits for first boot.

        UNCHANGED when already at the version, SKIPPED without a version, WOULD_CHANGE in check mode."""
        if not self.plan.version:
            self.say("    global 未声明 servers.ufm.version，跳过升级")
            return "SKIPPED"
        if not self.plan.image_server:
            raise UfmError("global 缺少 common.mgmt.http，无法确定镜像下载地址")
        version, url = self.plan.version, f"{self.plan.image_server}/image/{image_name(self.plan.version)}"
        self.say(f"  {node.hostname}: 升级检查（目标 UFM_APPLIANCE={version}）")
        probe = host.parse_kv(self.run_script(node, result, "upgrade-check", upgrade_probe_script(url)))
        result.facts["upgrade_before"] = probe.get("before", "")
        # I-008 expectation 2 (v3.1.6 WP-2 table, first match wins): an active upgrade unit, then the target
        # version with the last block complete or no status log (B2-O2), FAILED, unfinished; below the target
        # an earlier run's PASSED or FAILED does not count and the upgrade starts as before.
        if probe.get("units"):
            raise UpgradeInProgress(f"升级单元 {probe['units']} 正在运行（UFM_APPLIANCE={probe.get('before') or '未知'}）；"
                                    "不发起第二次升级，等它完成后再运行")
        if probe.get("before") == version:
            if probe.get("block") in ("complete", "none"):
                self.say(f"    已是 UFM_APPLIANCE={version}，不升级")
                return "UNCHANGED"
            if probe.get("block") == "failed":
                raise UfmError(f"UFM_APPLIANCE 已是 {version}，但最近一次升级的状态日志有 FAILED: {probe.get('failed')}；"
                               "需人工处理，不重新发起升级")
            raise UpgradeInProgress(
                f"UFM_APPLIANCE 已是 {version}，但最近一次升级还没有完成：状态日志 {probe.get('status_log')} 从 "
                f"{probe.get('started') or '-'} 的 STARTED 起，最后一步 {probe.get('last_step') or '-'}"
                f"（设备时间 {probe.get('last_stamp') or '-'}），没有 UFM-OS-UPGRADE、UFM-OS-FIRSTBOOT 都 PASSED；"
                "不按已完成处理，也不重新发起升级")
        if probe.get("image_remote") != "yes":
            # The start script re-checks the server size before reusing anything, so it needs the server too.
            raise UfmError(f"IMAGE_UNAVAILABLE: 无法从 {url} 获取镜像（wget --spider 失败）；不升级")
        reuse = probe.get("image_local") == "reuse"
        action = (f"UFM_APPLIANCE {probe.get('before') or '未知'} → {version}："
                  + (f"复用设备上已下载的 /root/{image_name(version)}（大小与服务器一致，{probe.get('local_size')} 字节）"
                     if reuse else f"下载 {url}") + "，"
                  f"停止 ufm-enterprise（当前 {probe.get('ufm_enterprise') or '未知'}），"
                  "执行 ufm-os-upgrade.sh --appliance-sw-upgrade -r -y（完成后自动重启）")
        result.facts["upgrade_action"] = action
        if not self.apply:
            return self.would("upgrade", action)
        self.authorize(node, action)
        self.say(f"    升级到 {version}；镜像 {url}")
        facts = host.parse_kv(self.run_script(node, result, "upgrade-start",
                                              upgrade_start_script(version, url), session_timeout=1800))
        if facts.get("result") == "already":
            self.say(f"    已是 UFM_APPLIANCE={version}，不升级")
            return "UNCHANGED"
        if facts.get("result") == "in_progress":   # found by the start script's own check, right before starting
            raise UpgradeInProgress(f"启动前发现升级正在进行（{facts.get('units') or '最近一次升级还没有完成'}，"
                                    f"UFM_APPLIANCE={facts.get('before') or '未知'}）；不发起第二次升级")
        if facts.get("result") == "failed":
            raise UfmError(f"UFM_APPLIANCE 已是 {version}，但最近一次升级的状态日志有 FAILED: {facts.get('failed')}；"
                           "需人工处理，不重新发起升级")
        if facts.get("result") != "started" or not STAMP_RE.fullmatch(facts.get("started_at", "")):
            raise UfmError(f"升级未启动: {facts}")
        result.facts["upgrade_started_at"] = facts["started_at"]
        result.facts["upgrade_unit"] = facts.get("unit", "")
        self.wait_upgrade(node, result, version, facts["started_at"], facts.get("unit", ""), facts.get("boot_id", ""))
        return "UPGRADED"

    PROGRESS_EVERY = 100   # seconds between progress lines while nothing else is printed
    # I-008 expectation 4 (B2-O5 (a)): no new status line for this long while the unit is active and the
    # device has not rebooted prints the read-only diagnostics once, then again after every further period.
    UPGRADE_STALL_AFTER = 600

    def wait_upgrade(self, node: UfmNode, result: NodeResult, version: str, since: str, unit: str,
                     boot_id: str) -> None:
        """Rule from the requirements: wait first, then probe every interval, with a hard limit. Each probe
        prints the last step and its device time, the seconds since the status log last changed (this
        server's monotonic clock), the unit's state and whether the boot id changed (I-008 expectation 4).
        A stall is reported, never acted on: no early end, no process is stopped (B2-O5)."""
        initial, interval, limit = self.upgrade_wait
        script, diagnose = upgrade_status_script(since, unit), upgrade_status_script(since, unit, diagnose=True)
        self.say(f"    [{clock()}] 升级已在设备上启动（完成后自动重启）；先等 {initial}s，之后每 {interval}s 探测，"
                 f"最长 {limit}s")
        started = time.monotonic()
        # Owner 2026-10-20: the first wait printed nothing and looked stuck: a timestamped line every 100 s.
        while initial - (time.monotonic() - started) > 0:
            time.sleep(min(self.PROGRESS_EVERY, initial - (time.monotonic() - started)))
            if initial - (time.monotonic() - started) > 0:
                self.say(f"    [{clock()}] 等待升级：已等待 {int(time.monotonic() - started)}s / {initial}s，"
                         "之后开始探测")
        probe, last = 0, "未探测"
        seen, changed, reported = None, time.monotonic(), None
        while True:
            probe += 1
            failed = ""
            due = (time.monotonic() - changed >= self.UPGRADE_STALL_AFTER
                   and (reported is None or time.monotonic() - reported >= self.UPGRADE_STALL_AFTER))
            try:
                body = self.run_script(node, result, f"upgrade-status-{probe}", diagnose if due else script)
                head, *diagnostics = body.split(UPGRADE_DIAG_MARK)
                facts = host.parse_kv(head)
                failed = facts.get("failed", "")
                rebooted = bool(boot_id) and facts.get("boot_id", "") not in ("", boot_id)
                reboot = "已重启" if rebooted else "未重启" if boot_id else "是否重启未知"
                if not failed and facts.get("appliance") == version and facts.get("block") == "complete":
                    result.facts["upgrade_after"] = version
                    result.facts["upgrade_status_log"] = facts.get("status_log", "")
                    self.say(f"    [{clock()}] 升级完成: UFM_APPLIANCE={version}，UFM-OS-FIRSTBOOT PASSED"
                             f"（用时 {int(time.monotonic() - started)}s，设备{reboot}）")
                    return
                step = (facts.get("last_step", ""), facts.get("last_stamp", ""))
                if step != seen:
                    seen, changed = step, time.monotonic()
                state = facts.get("unit_state") or "-"
                last = (f"UFM_APPLIANCE={facts.get('appliance') or '-'} FIRSTBOOT={facts.get('firstboot') or '-'}；"
                        f"最后一步 {step[0] or '-'}（设备时间 {step[1] or '-'}），"
                        f"{int(time.monotonic() - changed)}s 无进展；升级单元 {state}；{reboot}")
                if (len(diagnostics) == 2 and state == "active" and not rebooted
                        and time.monotonic() - changed >= self.UPGRADE_STALL_AFTER):
                    reported = time.monotonic()
                    self.say(f"    [{clock()}] 状态日志 {int(reported - changed)}s 没有进展，升级单元 {unit} 仍在运行、"
                             f"设备未重启：卡在 {step[0] or '-'} 之后的阶段（只报告，不结束任何进程，照旧等到 {limit}s）")
                    for title, text in (("systemctl list-jobs --no-pager", diagnostics[0]),
                                        (f"systemctl status {unit} --no-pager（CGroup）", diagnostics[1])):
                        self.say(f"      {title}:")
                        for line in text.strip("\n").splitlines():
                            self.say(f"        {line}")
                    self.say("      只读排查：systemctl list-jobs --no-pager；pgrep -af '^systemctl restart'；"
                             "cat /proc/mdstat（mdcheck_start 正在 start 时 needrestart 的 systemctl restart 会一直等它）；"
                             "不要结束 apt-get，也不要停掉升级单元")
            except (UfmError, host.HostConfigError) as exc:
                last = f"暂不可达（可能正在重启）: {str(exc)[:120]}"
            if failed:
                raise UfmError(f"升级状态日志出现 FAILED: {failed}；详见设备 {UPGRADE_LOG} 与状态日志")
            if time.monotonic() - started >= limit:
                raise UpgradeInProgress(f"等待 {limit}s 仍未完成（{last}）；请登录设备查看 {UPGRADE_LOG}；"
                                        "可以重跑 config-upgrade：会先检测在途升级，不会重复启动")
            self.say(f"    [{clock()}] 探测 [{probe}] 已等待 {int(time.monotonic() - started)}s: {last}")
            time.sleep(interval)

    def ha_probe(self, node: UfmNode, peer: UfmNode, result: NodeResult, step: str) -> dict:
        """Read-only facts for the owner's five HA preconditions on one node."""
        device = self.plan.logical["eth1"]
        peer_ha = str(ipaddress.IPv4Interface(self.plan.addresses[self.plan.role_of(peer)][device]).ip)
        facts = host.parse_kv(self.run_script(node, result, step, ha_check_script(
            self.plan.mgmt_device, peer.address, device, peer_ha, self.plan.vip)))
        result.facts["ha_check"] = facts
        return facts

    def ha_pair(self, nodes: list) -> tuple:
        """(master, standby): the install-time primary (hostname ending in ufm01) is the HA master."""
        master = next((node for node in nodes if self.plan.role_of(node) == "primary"), nodes[0])
        return master, next(node for node in nodes if node is not master)

    def ha_node_argv(self, node: UfmNode, peer: UfmNode, role: str) -> list:
        device = self.plan.logical["eth1"]

        def link(item: UfmNode) -> str:
            return str(ipaddress.IPv4Interface(self.plan.addresses[self.plan.role_of(item)][device]).ip)
        return ha_config_argv(role, link(node), link(peer), node.address, peer.address,
                              self.plan.vip if role == "master" else "")

    def ha_log(self, name: str) -> str:
        return f"{REMOTE_WORK}/{self.run_dir.name}/{name}.log"

    def ha_read_status(self, node: UfmNode, result: NodeResult, step: str) -> dict:
        body = self.run_script(node, result, step, ha_status_script())
        head, _sep, text = body.partition(HA_STATUS_MARK)
        if host.parse_kv(head).get("ha_tool") != "yes":
            raise UfmError(f"{node.hostname} 上没有 ufm_ha_cluster 命令")
        status = parse_ha_status(text)
        result.facts["ha_status"] = {key: status[key] for key in ("online", "offline", "masters", "slaves", "drbd")}
        return status

    def ha_setup(self, nodes: list) -> list:
        """ha-setup --apply (step 4, owner 2026-10-20/22). First `ufm_ha_cluster status` on both nodes: when
        either shows an HA cluster (any state, any nodes or VIP), nothing is set up (HA_EXISTS) and the run ends
        with a hint to clear that configuration first (owner 2026-10-22). Without a cluster: the five
        preconditions (only a running ufm-enterprise may be stopped), one confirmation for the whole plan,
        mutual trust, the preconditions again, standby config, master config with the VIP, the DRBD wait,
        `ufm_ha_cluster start` and the status verdict. A failed ufm_enterprise_sanity.sh is only a note at the
        end. (check is the read-only view.) Owner 11-03: without servers.ufm.version in global there is no HA,
        decided before any input check or login. I-009: pacemaker's own default single-node cluster is not
        an existing HA; stopping it is part of the confirmed plan."""
        if not self.apply:
            raise UfmError("内部错误：ha-setup 只在 --apply 下运行")
        results = {node.hostname: NodeResult(node.hostname, self.plan.role_of(node)) for node in nodes}
        if not self.plan.version:
            return [self.stop(result, "HA_SKIPPED_NO_VERSION", HA_NO_VERSION) for result in results.values()]
        if len(nodes) != 2:
            return [self.stop(result, "INPUT_ERROR", "HA 需要两台 UFM") for result in results.values()]
        if not self.plan.vip or not self.plan.logical.get("eth1"):
            return [self.stop(result, "INPUT_ERROR", "global 缺少 vip 或无法确定 HA 接口 eth1")
                    for result in results.values()]
        master, standby = self.ha_pair(nodes)
        for node in nodes:
            try:
                self.connect(node, results[node.hostname])
            except (UfmError, host.HostConfigError) as exc:
                self.stop(results[node.hostname], "HA_NOT_READY", f"无法完成检查: {exc}")
        if self.ha_blocked(results, "HA_NOT_READY", "对端无法登录，本端不做改动"):
            return list(results.values())
        try:
            found, defaults = self.ha_clusters([master, standby], results)
        except (UfmError, host.HostConfigError) as exc:
            return [self.stop(result, "HA_NOT_READY", str(exc)) for result in results.values()]
        if found:
            return self.ha_exists(found, master, nodes, results)
        if not self.ha_review([master, standby], results, "ha-setup"):
            return list(results.values())
        if (not self.ha_prepare(master, standby, results, defaults)
                or not self.ha_configure(master, standby, results)):
            return list(results.values())
        return self.ha_finish(master, standby, results)

    def ha_clusters(self, nodes: list, results: dict) -> tuple:
        """([(node, status)] for every node whose `ufm_ha_cluster status` shows a cluster, [node] for every node
        that only has pacemaker's own default single-node cluster (I-009), kept out of the first list)."""
        found, defaults = [], []
        for node in nodes:
            self.say(f"  {node.hostname}: 读取 ufm_ha_cluster status（判断是否已有 HA 配置）")
            try:
                status = self.ha_read_status(node, results[node.hostname], "ha-status")
            except (UfmError, host.HostConfigError) as exc:
                raise UfmError(f"{node.hostname} 无法读取 ufm_ha_cluster status: {exc}") from exc
            if ha_default_cluster(status, node):
                defaults.append(node)
            elif ha_cluster_kind(status, nodes, self.plan.vip)[0] != "absent":
                found.append((node, status))
        return found, defaults

    def ha_exists(self, found: list, master: UfmNode, nodes: list, results: dict) -> list:
        """Owner 2026-10-22: an existing HA configuration is never set up again; the user clears it first."""
        where = ", ".join(node.hostname for node, _status in found)
        summary = ha_summary(found[0][1], nodes, self.plan.vip)
        self.say(f"  {where} 上已有 HA 配置（{summary}）：不做任何 HA 配置")
        for result in results.values():
            self.stop(result, "HA_EXISTS", "已有 HA 配置，本次未做任何改动（见最后的提示）")
        # Owner 2026-10-22: clear it and run ha-setup again, or, when this HA is fine, go on with ha-post-config.
        results[master.hostname].facts.setdefault("notes", []).append(
            f"当前 UFM 已有 HA 配置（{where} 上读到：{summary}）。本次没有做任何 HA 配置。"
            "要重新部署 HA，请先清除现有的 HA 配置，再运行 ha-setup --apply；"
            "如果确认当前 HA 正常，可直接运行 ha-post-config --apply 完成 HA 之后的配置")
        return list(results.values())

    def ha_review(self, nodes: list, results: dict, command: str) -> bool:
        """I-008 expectation 5 (owner 2026-11-01; v3.1.6 B2-O6, B2-O8): before any HA change, every configuration
        step of check and the upgrade verdict, read-only, on both nodes, each on a scratch NodeResult so that
        nothing lands in result.steps (written to facts["ha_review"]). A node that is not COMPLIANT (a WOULD_*
        step, a failed step, UPGRADE_IN_PROGRESS, a deferred IPMI failure) is HA_NOT_READY with every item and
        its detail, the peer WAITING_PEER. Warnings only go to facts["attention"] and do not block (B2-O7)."""
        self.apply = False
        try:
            for node in nodes:
                result = results[node.hostname]
                self.say(f"  {node.hostname}: 只读复核配置和升级（与 check 相同；HA 之前两台都要完成 config-upgrade）")
                scratch = NodeResult(node.hostname, result.role, password=result.password)
                self.settle_deferred(self.run_steps(node, scratch, self.config_steps() + (("upgrade", self.step_upgrade),),
                                                    "COMPLIANT"))
                result.facts["ha_review"] = {"status": scratch.status, "detail": scratch.detail, "steps": scratch.steps}
                result.facts.setdefault("attention", []).extend(scratch.facts.get("attention", []))
                if scratch.status == "COMPLIANT":
                    continue
                items = [f"{step['step']} {step['outcome']}" + (f"：{step['detail']}" if step.get("detail") else "")
                         for step in scratch.steps if step["outcome"].startswith("WOULD") or step["outcome"] == "FAILED"]
                if scratch.status == "UPGRADE_IN_PROGRESS" or not items:
                    items.append(f"{scratch.status}：{scratch.detail}")
                self.stop(result, "HA_NOT_READY", f"配置或升级未完成：{'；'.join(items)}。"
                                                  f"请先运行 config-upgrade --apply 完成配置和升级，再运行 {command} --apply")
        finally:
            self.apply = True
        return not self.ha_blocked(results, "HA_NOT_READY", "对端的配置或升级未完成，本端不做 HA 改动")

    def ha_blocked(self, results: dict, status: str, detail: str) -> bool:
        if not any(result.status == status for result in results.values()):
            return False
        for result in results.values():
            if result.status != status:
                self.stop(result, "WAITING_PEER", detail)
        return True

    def ha_plan_text(self, master: UfmNode, standby: UfmNode, running: list, defaults: list) -> str:
        lines = [f"停止 {node.hostname} 上 pacemaker 自带的默认单节点集群（pcs cluster stop --force；"
                 "可用 pcs cluster start 恢复）" for node in defaults]
        lines += [f"停止 {', '.join(node.hostname for node in running)} 上正在运行的 ufm-enterprise"] if running else []
        lines += ["两台 root 互信（已具备的不改动）",
                  f"{standby.hostname}: {shlex.join(self.ha_node_argv(standby, master, 'standby'))}",
                  f"{master.hostname}: {shlex.join(self.ha_node_argv(master, standby, 'master'))}",
                  "  这两条会把两台的 /opt/ha_data 备份到 /ha_backup/<时间>/ 后清空并交给 DRBD，"
                  "在 master 上格式化 /dev/drbd0，并销毁两台上原有的集群配置",
                  f"等 DRBD 同步完成（最长 {self.ha_wait[1]}s），然后在 {master.hostname} 上执行 ufm_ha_cluster start",
                  "之后自动做 ha-post-config：" + POST_CONFIG_PLAN]
        return "HA 部署：\n      " + "\n      ".join(lines)

    def ha_prepare(self, master: UfmNode, standby: UfmNode, results: dict, defaults: list) -> bool:
        """No cluster yet: the preconditions, one confirmation, stop pacemaker's default single-node clusters
        (I-009), stop the service, trust, the preconditions again."""
        pairs = ((master, standby), (standby, master))
        facts = {}
        for node, peer in pairs:
            result = results[node.hostname]
            self.say(f"  {node.hostname}: 检查 HA 前提")
            try:
                facts[node.hostname] = self.ha_probe(node, peer, result, "ha-check")
            except (UfmError, host.HostConfigError, KeyError) as exc:
                self.stop(result, "HA_NOT_READY", f"无法完成检查: {exc}")
                continue
            blockers = ha_problems(facts[node.hostname], peer.hostname, self.plan.vip, self.plan.version,
                                   ignore_service=True)
            if blockers:
                self.stop(result, "HA_NOT_READY", "; ".join(blockers))
        if self.ha_blocked(results, "HA_NOT_READY", "对端 HA 前提未满足，本端不做改动"):
            return False
        running = [node for node in (master, standby)
                   if facts[node.hostname].get("ufm_enterprise") in RUNNING_STATES]
        # v3.1.6 B2-O7: what the review only warned about is listed before the plan and does not block HA
        notes = [f"{node.hostname}: {item}" for node in (master, standby)
                 for item in dict.fromkeys(results[node.hostname].facts.get("attention", []))]
        heading = "注意（不阻止 HA）：\n      " + "\n      ".join(notes) + "\n    " if notes else ""
        try:
            self.authorize(master, heading + self.ha_plan_text(master, standby, running, defaults))
            for node in defaults:   # I-009: confirmed with the plan; nothing of HA has been changed yet
                result = results[node.hostname]
                self.say(f"  {node.hostname}: 停止 pacemaker 自带的默认单节点集群")
                self.run_script(node, result, "pcs-cluster-stop", PCS_CLUSTER_STOP_SCRIPT)
                status = self.ha_read_status(node, result, "ha-status-after-stop")
                if ha_cluster_kind(status, [master, standby], self.plan.vip)[0] != "absent":
                    raise UfmError(f"{node.hostname} 停止默认单节点集群后 ufm_ha_cluster status 仍显示集群")
                result.steps.append({"step": "ha_default_cluster", "outcome": "STOPPED"})
                self.say(f"    {node.hostname} [ha_default_cluster] STOPPED")
            if running:
                self.stop_ufm_enterprise(running, results)
            for item in self.trust([master, standby]):
                result = results[item.hostname]
                result.steps.extend(item.steps)
                if item.status not in {"TRUSTED", "NEEDS_CONFIGURATION"}:
                    self.stop(result, item.status, f"互信: {item.detail}")
        except NotAuthorized as exc:
            for result in results.values():
                self.stop(result, "NOT_AUTHORIZED", str(exc))
            return False
        except (UfmError, host.HostConfigError) as exc:
            for result in results.values():
                self.stop(result, "HA_NOT_READY", str(exc))
            return False
        if any(result.status not in {"PENDING", "VERIFIED"} for result in results.values()):
            return False
        for node, peer in pairs:   # every precondition again, now including the stopped service
            result = results[node.hostname]
            problems = ha_problems(self.ha_probe(node, peer, result, "ha-recheck"), peer.hostname, self.plan.vip,
                                   self.plan.version)
            if problems:
                self.stop(result, "HA_NOT_READY", "; ".join(problems))
            else:
                result.status = "HA_READY"
        if not all(result.status == "HA_READY" for result in results.values()):
            return False
        self.say("  HA 前提全部满足，互信已完成：开始配置 HA（先 standby，再 master）")
        return True

    def ha_configure(self, master: UfmNode, standby: UfmNode, results: dict) -> bool:
        """`ufm_ha_cluster config` on the standby, then on the master with the VIP (owner's order)."""
        for node, peer, role in ((standby, master, "standby"), (master, standby, "master")):
            result = results[node.hostname]
            argv, log = self.ha_node_argv(node, peer, role), self.ha_log(f"ha-config-{role}")
            self.say(f"  {node.hostname}: {shlex.join(argv)}（输出写入设备上的 {log}）")
            try:
                body = self.run_script(node, result, f"ha-config-{role}",
                                       ha_logged_script(argv, log, "config", HA_CONFIG_DONE), session_timeout=1800)
                head, _sep, tail = body.partition(HA_TAIL_MARK)
                facts = host.parse_kv(head)
                if facts.get("config_rc") != "0" or facts.get("config_done") != "yes":
                    raise UfmError(f"ufm_ha_cluster config -r {role} 未完成（rc={facts.get('config_rc')}，"
                                   f"{'有' if facts.get('config_done') == 'yes' else '没有'}「{HA_CONFIG_DONE}」）: "
                                   f"{tail.strip()[-600:]}")
            except (UfmError, host.HostConfigError) as exc:
                result.steps.append({"step": "ha_config", "outcome": "FAILED", "detail": str(exc)})
                self.stop(result, "HA_CONFIG_FAILED", f"{exc}；完整输出见设备上的 {log}")
                self.stop(results[peer.hostname], "INCOMPLETE",
                          f"standby {standby.hostname} 配置失败，master 未改动" if role == "standby" else
                          f"master {master.hostname} 配置失败；standby 已配置。排除问题后重跑 ha-setup --apply；"
                          "若提示已有 HA 配置，需先清除")
                return False
            result.steps.append({"step": "ha_config", "outcome": "CONFIGURED", "detail": log})
            self.say(f"    {node.hostname} [ha_config] CONFIGURED（-r {role}）")
        return True

    def ha_finish(self, master: UfmNode, standby: UfmNode, results: dict) -> list:
        """Wait for the DRBD sync, `ufm_ha_cluster start` on the master, then the status verdict."""
        nodes, mine = [master, standby], results[master.hostname]
        try:
            self.wait_drbd_sync(master, mine)
        except UfmError as exc:
            status = "HA_SYNC_TIMEOUT" if isinstance(exc, HaWaitTimeout) else "HA_SYNC_FAILED"
            return [self.stop(result, status, str(exc)) for result in results.values()]
        mine.steps.append({"step": "drbd_sync", "outcome": "SYNCED"})
        self.say(f"    {master.hostname} [drbd_sync] SYNCED")
        log = self.ha_log("ha-start")
        self.say(f"  {master.hostname}: ufm_ha_cluster start（输出写入设备上的 {log}）")
        try:
            body = self.run_script(master, mine, "ha-start", ha_logged_script(["ufm_ha_cluster", "start"], log, "start"),
                                   session_timeout=1800)
            head, _sep, tail = body.partition(HA_TAIL_MARK)
            if host.parse_kv(head).get("start_rc") != "0":
                raise UfmError(f"ufm_ha_cluster start 退出码 {host.parse_kv(head).get('start_rc')}: {tail.strip()[-600:]}")
        except (UfmError, host.HostConfigError) as exc:
            mine.steps.append({"step": "ha_start", "outcome": "FAILED", "detail": str(exc)})
            return [self.stop(result, "HA_START_FAILED", f"{exc}；完整输出见 {master.hostname} 上的 {log}")
                    for result in results.values()]
        mine.steps.append({"step": "ha_start", "outcome": "STARTED"})
        self.say(f"    {master.hostname} [ha_start] STARTED")
        try:
            status = self.wait_ha_status(master, nodes, mine)
        except HaWaitTimeout as exc:
            return [self.stop(result, "HA_UNHEALTHY", str(exc)) for result in results.values()]
        for result in results.values():
            result.steps.append({"step": "ha_status", "outcome": "OK"})
        # Owner 2026-10-22: once ha-setup has really set HA up, it goes on with ha-post-config.
        done, status = self.ha_post_config(master, standby, results, status)
        if not done:
            return list(results.values())
        for result in results.values():
            result.status = "HA_CONFIGURED"
        self.ha_sanity(status, nodes, results)
        return list(results.values())

    def wait_drbd_sync(self, master: UfmNode, result: NodeResult) -> None:
        interval, limit = self.ha_wait[0], self.ha_wait[1]
        self.say(f"    [{clock()}] 等待 DRBD 同步完成（{master.hostname} 上 drbdadm status，每 {interval}s 一次，"
                 f"最长 {limit}s）")
        started, probe = time.monotonic(), 0
        while True:
            probe += 1
            try:
                body = self.run_script(master, result, f"drbd-status-{probe}", DRBD_STATUS_SCRIPT)
            except (UfmError, host.HostConfigError) as exc:
                last = f"读取失败: {str(exc)[:120]}"
            else:
                if host.parse_kv(body).get("drbd_tool") != "yes":
                    raise UfmError(f"{master.hostname} 上没有 drbdadm，无法确认 DRBD 同步；HA 已配置，未启动")
                sync = drbd_sync_state(body)
                if sync["synced"]:
                    self.say(f"    [{clock()}] DRBD 同步完成（{drbd_progress(sync)}；"
                             f"用时 {int(time.monotonic() - started)}s）")
                    return
                last = drbd_progress(sync)
            elapsed = int(time.monotonic() - started)
            if elapsed >= limit:
                raise HaWaitTimeout(f"等待 {limit}s DRBD 仍未同步完成（{last}）；HA 已配置，未启动。"
                                    f"同步完成后在 {master.hostname} 上执行 ufm_ha_cluster start，再用 "
                                    "ufm_ha_cluster status 确认；重跑 ha-setup 会因已有 HA 配置而不做任何操作")
            self.say(f"    [{clock()}] 等待 DRBD 同步 [{probe}] 已等待 {elapsed}s: {last}")
            time.sleep(interval)

    def wait_ha_status(self, master: UfmNode, nodes: list, result: NodeResult) -> dict:
        """After `ufm_ha_cluster start` the resources need a while; the status alone decides (owner 2026-10-22)."""
        interval, limit = self.ha_wait[2], self.ha_wait[3]
        started, probe = time.monotonic(), 0
        while True:
            probe += 1
            try:
                status = self.ha_read_status(master, result, f"ha-status-{probe}")
                problems = ha_status_problems(status, nodes, self.plan.vip, master)
                if not problems:
                    self.say(f"    [{clock()}] ufm_ha_cluster status 正常：{master.hostname} Promoted，两台在线，"
                             f"资源都在 {master.hostname} 上 Started，DRBD Connected/UpToDate")
                    return status
                last = "; ".join(problems)
            except (UfmError, host.HostConfigError) as exc:
                last = f"读取失败: {str(exc)[:120]}"
            elapsed = int(time.monotonic() - started)
            if elapsed >= limit:
                raise HaWaitTimeout(f"ufm_ha_cluster start 之后 {limit}s 内 status 仍不正常: {last}；HA 已配置，"
                                    "需人工处理（重跑 ha-setup 会因已有 HA 配置而不做任何操作）")
            self.say(f"    [{clock()}] 等待 HA 启动 [{probe}] 已等待 {elapsed}s: {last}")
            time.sleep(interval)

    def ha_sanity(self, status: dict, nodes: list, results: dict) -> None:
        """Owner 2026-10-22: a failed ufm_enterprise_sanity.sh is only pointed out at the end of the run."""
        promoted = [ha_member(name, nodes) for name in status["masters"]]
        node = promoted[0] if len(promoted) == 1 and promoted[0] else nodes[0]
        result = results[node.hostname]
        try:
            head, _sep, tail = self.run_script(node, result, "ha-sanity", HA_SANITY_SCRIPT).partition(HA_TAIL_MARK)
            outcome = host.parse_kv(head).get("sanity", "") or "unknown"
        except (UfmError, host.HostConfigError) as exc:
            outcome, tail = "unknown", str(exc)
        result.facts["ha_sanity"] = outcome
        self.say(f"    {node.hostname} [ha_sanity] {'PASSED' if outcome == 'passed' else '未通过（只提示，不影响结果）'}")
        if outcome != "passed":
            reason = {"failed": "未通过", "missing": "设备上没有这个命令"}.get(outcome, "没有结果")
            result.facts.setdefault("notes", []).append(
                f"ufm_enterprise_sanity.sh {reason}（不影响 HA 判定）: {' '.join(tail.split())[-300:]}")

    # ------------------------------------------------------------ ha-post-config (owner 2026-10-22)

    def vip_access(self, nodes: list, results: dict) -> dict:
        """Pin both UFMs' own host keys under the VIP address in a file of this run: after a failover
        the VIP answers with the other UFM's key, and nothing else is accepted (owner 2026-10-22)."""
        lines = []
        for node in nodes:
            keys = [HOST_KEY_RE.match(line.strip()) for line in
                    self.run_script(node, results[node.hostname], "host-keys", HOST_KEYS_SCRIPT).splitlines()]
            keys = [match for match in keys if match]
            if not keys:
                raise UfmError(f"读不到 {node.hostname} 的 SSH 主机密钥，无法安全登录 VIP")
            lines += [f"{self.plan.vip} {match.group(1)} {match.group(2)}" for match in keys]
        path = self.run_dir / "vip-known-hosts"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.chmod(path, 0o600)
        return {"path": "VIP-KEY", "address": self.plan.vip, "known_hosts": str(path)}

    def local_licenses(self) -> tuple:
        """(found, [(name, sha256)]): every *.lic in the image directory beside this tool (a setup link to
        the management server's image/, served at {common.mgmt.http}/image/)."""
        directory = self.plan.input_dir / "image"
        if not directory.is_dir():
            return False, []
        return True, sorted((path.name, hashlib.sha256(path.read_bytes()).hexdigest())
                            for path in directory.glob("*.lic")
                            if path.is_file() and LICENSE_NAME_RE.fullmatch(path.name))

    def vip_read(self, vip_node: UfmNode, result: NodeResult, access: dict, nodes: list, step: str,
                 licenses: list) -> tuple:
        parts = post_sections(self.run_script(vip_node, result, step, post_read_script(
            self.plan.mgmt_device, [name for name, _digest in licenses]), access=access))
        try:
            mac = normalize_mac(host.parse_kv(parts[""]).get("mac", ""))
        except ValueError:
            mac = ""
        holder = next((node for node in nodes if mac and node.mac == mac), None)
        if holder is None:
            raise UfmError(f"VIP {self.plan.vip} 所在设备的管理口 MAC 为 {mac or '空'}，不是这两台 UFM 之一")
        return parts, holder

    def ha_post_config(self, primary: UfmNode, other: UfmNode, results: dict, status: dict) -> tuple:
        """(done, latest status). Owner 2026-10-22 (ufm-manual.log 1143-2088), all through the VIP:
        licenses, gv.cfg [Server], root_guid.conf; one `ufm_ha_cluster failover` if anything changed, then
        the HA status, gv.cfg (two smi lines in opensm-smdb.dump) and the license are checked on the new
        master. A missing .lic or root switch is only a note at the end."""
        nodes, mine = [primary, other], results[primary.hostname]
        notes = mine.facts.setdefault("notes", [])
        vip_node = UfmNode(f"VIP-{self.plan.vip}", 0, self.plan.vip, "", "", "")
        backup = f"{self.backup_dir()}/post-ha"
        self.say(f"  ha-post-config：{POST_CONFIG_PLAN}")
        try:
            access = self.vip_access(nodes, results)
            found, licenses = self.local_licenses()
            parts, holder = self.vip_read(vip_node, mine, access, nodes, "post-ha-read", licenses)
            self.say(f"    VIP {self.plan.vip} 在 {holder.hostname} 上")
            changed = []
            # licenses: every *.lic, a file of the same name replaced (owner 2026-10-22)
            installed = dict(line.split(" ", 1) for line in parts.get("licenses", "").splitlines() if " " in line)
            pending = [(name, digest) for name, digest in licenses if installed.get(name) != digest]
            if not licenses:
                expiry = evaluation_expiry(license_rows(parts.get("ufmlicense", "")))
                notes.append(("image 目录里没有 .lic 文件" if found else "工具目录下没有 image 链接")
                             + "：未安装 license，跳过这一步" + (f"；当前评估 license 到期日 {expiry}" if expiry else ""))
                self.ha_step(results, holder, "post_ha_license", "SKIPPED")
            elif pending:
                self.authorize(holder, "ha-post-config: " + POST_CONFIG_PLAN)
                self.run_script(vip_node, mine, "post-ha-license",
                                license_install_script(pending, self.plan.image_server, backup), access=access)
                changed.append("license")
                self.ha_step(results, holder, "post_ha_license", "INSTALLED",
                             ", ".join(name for name, _digest in pending))
            else:
                self.ha_step(results, holder, "post_ha_license", "UNCHANGED")
            # gv.cfg: the three [Server] keys only
            gv_text = base64.b64decode(parts.get("gv.cfg", "").strip() or b"").decode("utf-8")
            if not gv_text:
                raise UfmError(f"读不到 {GV_CFG}")
            new_text, gv_changes = gv_server_update(gv_text)
            if gv_changes:
                self.authorize(holder, "ha-post-config: " + POST_CONFIG_PLAN)
                self.run_script(vip_node, mine, "post-ha-gv-cfg",
                                file_replace_script(GV_CFG, new_text.encode("utf-8"), backup), access=access)
                changed.append("gv.cfg")
            self.ha_step(results, holder, "post_ha_gv_cfg", "CHANGED" if gv_changes else "UNCHANGED",
                         "; ".join(gv_changes))
            # root_guid.conf: the core switches, or the spines when there is no core (owner 2026-10-22)
            changed += self.post_root_guid(vip_node, mine, access, holder, results, parts, backup)
            if not changed:
                self.say("    HA 之后的配置都已符合，不做 failover")
                self.ha_step(results, holder, "post_ha_failover", "NOT_NEEDED")
                return True, status
            status = self.post_failover(vip_node, mine, access, holder, nodes, results, changed)
            new_master = next(node for node in nodes if node is not holder)
            self.post_verify(vip_node, mine, access, new_master, nodes, results, licenses)
            return True, status
        except NotAuthorized as exc:
            for result in results.values():
                self.stop(result, "NOT_AUTHORIZED", str(exc))
            return False, status
        except (UfmError, host.HostConfigError, ValueError) as exc:
            for result in results.values():
                self.stop(result, "HA_POST_CONFIG_FAILED", f"ha-post-config: {exc}")
            return False, status

    def ha_step(self, results: dict, node: UfmNode, step: str, outcome: str, detail: str = "") -> None:
        results[node.hostname].steps.append({"step": step, "outcome": outcome, **({"detail": detail} if detail else {})})
        self.say(f"    {node.hostname} [{step}] {outcome}{('：' + detail) if detail else ''}")

    def post_root_guid(self, vip_node: UfmNode, mine: NodeResult, access: dict, holder: UfmNode, results: dict,
                       parts: dict, backup: str) -> list:
        notes = mine.facts.setdefault("notes", [])
        path = host.parse_kv(parts[""]).get("root_guid_file", "")
        if path != ROOT_GUID_FILE:
            raise UfmError(f"{OPENSM_CONF} 的 root_guid_file 是 {path or '空'}，不是 {ROOT_GUID_FILE}：不自动改动，请人工确认")
        kind, roots = ib_root_switches(self.plan.input_dir / "ib.csv")
        if not roots:
            notes.append("ib.csv 里没有 spine/core 交换机：root_guid.conf 不改")
            self.ha_step(results, holder, "post_ha_root_guid", "SKIPPED")
            return []
        guids, missing = root_guid_plan(parse_ibswitches(parts.get("ibswitches", "")), roots)
        if missing:
            notes.append(f"ibswitches 里没有这些 {kind}（{len(missing)}/{len(roots)}）：{', '.join(missing)}；"
                         f"root_guid.conf 只写入已发现的 {len(guids)} 个 GUID，补齐后重跑 ha-post-config")
        if not guids:
            notes.append(f"ibswitches 里一台 {kind} 也没发现：root_guid.conf 不改")
            self.ha_step(results, holder, "post_ha_root_guid", "SKIPPED")
            return []
        current = base64.b64decode(parts.get("root_guid", "").strip() or b"").decode("utf-8", "replace")
        if [line.strip().casefold() for line in current.splitlines() if line.strip()] == guids:
            self.ha_step(results, holder, "post_ha_root_guid", "UNCHANGED", f"{len(guids)} 个 {kind} GUID")
            return []
        self.authorize(holder, "ha-post-config: " + POST_CONFIG_PLAN)
        self.run_script(vip_node, mine, "post-ha-root-guid",
                        file_replace_script(path, ("\n".join(guids) + "\n").encode("ascii"), backup), access=access)
        self.ha_step(results, holder, "post_ha_root_guid", "CHANGED", f"{len(guids)} 个 {kind} GUID → {path}")
        return ["root_guid.conf"]

    def post_failover(self, vip_node: UfmNode, mine: NodeResult, access: dict, holder: UfmNode, nodes: list,
                      results: dict, changed: list) -> dict:
        """One `ufm_ha_cluster failover` makes the changes take effect; the SSH session through the VIP
        drops when the VIP moves (ufm-manual.log 2009), so only the status decides afterwards."""
        log = self.ha_log("post-ha-failover")
        new_master = next(node for node in nodes if node is not holder)
        self.say(f"    {', '.join(changed)} 已改动：在 {holder.hostname} 上执行 ufm_ha_cluster failover"
                 f"（主机将切到 {new_master.hostname}，输出写入 {log}）")
        try:
            self.run_script(vip_node, mine, "post-ha-failover",
                            ha_logged_script(["ufm_ha_cluster", "failover"], log, "failover"), access=access)
        except UfmError as exc:   # the VIP moved under the session: expected
            self.say(f"    failover 后会话断开（VIP 已切换）：{str(exc)[:120]}")
        self.ha_step(results, holder, "post_ha_failover", "DONE", f"{holder.hostname} → {new_master.hostname}")
        return self.wait_ha_status(new_master, nodes, results[new_master.hostname])

    def post_verify(self, vip_node: UfmNode, mine: NodeResult, access: dict, new_master: UfmNode, nodes: list,
                    results: dict, licenses: list) -> None:
        """Owner 2026-10-22: on the new master, gv.cfg shows as two smi lines in opensm-smdb.dump, and the
        license row of this master's eno8303 MAC is Valid. root_guid.conf is not checked."""
        interval, limit = self.ha_wait[2], self.ha_wait[3]
        started, probe = time.monotonic(), 0
        while True:
            probe += 1
            problems = []
            try:
                parts, holder = self.vip_read(vip_node, mine, access, nodes, f"post-ha-verify-{probe}", licenses)
                if holder is not new_master:
                    problems.append(f"VIP 在 {holder.hostname} 上，应在 {new_master.hostname} 上")
                smi = [line for line in parts.get("smdb", "").splitlines() if "smi" in line]
                if len(smi) < 2:
                    problems.append(f"{SMDB_DUMP} 里只有 {len(smi)} 行 smi（gv.cfg 生效后应有 2 行）")
                if licenses and not license_valid_for(license_rows(parts.get("ufmlicense", "")), new_master.mac):
                    problems.append(f"ufmlicense 里 {new_master.hostname}（{new_master.mac}）的 license 不是 Valid")
            except (UfmError, host.HostConfigError) as exc:
                problems.append(f"读取失败: {str(exc)[:120]}")
            if not problems:
                self.ha_step(results, new_master, "post_ha_verify", "OK",
                             "HA 正常，gv.cfg 已生效" + ("，license 有效" if licenses else ""))
                return
            if time.monotonic() - started >= limit:
                raise UfmError("failover 后核对未通过: " + "; ".join(problems))
            self.say(f"    [{clock()}] 等待配置生效 [{probe}]: {'; '.join(problems)}")
            time.sleep(interval)

    def ha_post_config_command(self, nodes: list) -> list:
        """ha-post-config --apply: only on an existing HA of these two UFMs and this VIP whose
        `ufm_ha_cluster status` is healthy; the promoted node is the master now."""
        if not self.apply:
            raise UfmError("内部错误：ha-post-config 只在 --apply 下运行")
        results = {node.hostname: NodeResult(node.hostname, self.plan.role_of(node)) for node in nodes}
        if len(nodes) != 2 or not self.plan.vip:
            return [self.stop(result, "INPUT_ERROR", "需要两台 UFM 和 global 中的 vip") for result in results.values()]
        for node in nodes:
            try:
                self.connect(node, results[node.hostname])
            except (UfmError, host.HostConfigError) as exc:
                self.stop(results[node.hostname], "HA_NOT_READY", f"无法登录: {exc}")
        if self.ha_blocked(results, "HA_NOT_READY", "对端无法登录，本端不做改动"):
            return list(results.values())
        first = self.ha_pair(nodes)[0]
        try:
            status = self.ha_read_status(first, results[first.hostname], "ha-status")
        except (UfmError, host.HostConfigError) as exc:
            return [self.stop(result, "HA_NOT_READY", f"无法读取 ufm_ha_cluster status: {exc}")
                    for result in results.values()]
        kind, detail = ha_cluster_kind(status, nodes, self.plan.vip)
        problems = [detail] if kind == "foreign" else ["没有 HA 集群"] if kind == "absent" else \
            ha_status_problems(status, nodes, self.plan.vip)
        if problems:
            return [self.stop(result, "HA_NOT_READY", "HA 不正常，不做 ha-post-config: " + "; ".join(problems))
                    for result in results.values()]
        if not self.ha_review(nodes, results, "ha-post-config"):   # v3.1.6 B2-O8: before any change
            return list(results.values())
        promoted = ha_member(status["masters"][0], nodes)
        other = next(node for node in nodes if node is not promoted)
        done, _status = self.ha_post_config(promoted, other, results, status)
        if done:
            for result in results.values():
                changed = any(step["step"] == "post_ha_failover" and step["outcome"] == "DONE"
                              for item in results.values() for step in item.steps)
                result.status = "HA_POST_CONFIGURED" if changed else "HA_POST_UP_TO_DATE"
        return list(results.values())

    def stop_ufm_enterprise(self, running: list, results: dict) -> None:
        """The only blocker was a running ufm-enterprise; the operator has confirmed the HA plan that stops it."""
        names = ", ".join(node.hostname for node in running)
        self.say(f"  其它 HA 前提都已满足，停止 {names} 上正在运行的 ufm-enterprise")
        for node in running:
            result = results[node.hostname]
            facts = host.parse_kv(self.run_script(node, result, "stop-ufm-enterprise", STOP_UFM_ENTERPRISE_SCRIPT))
            if facts.get("state") in RUNNING_STATES:
                raise UfmError(f"{node.hostname} 的 ufm-enterprise 停止后仍为 {facts.get('state')}")
            result.steps.append({"step": "stop_ufm_enterprise", "outcome": "STOPPED"})
            self.say(f"    {node.hostname} [stop_ufm_enterprise] STOPPED")

    def run_steps(self, node: UfmNode, result: NodeResult, steps: tuple, done: str) -> NodeResult:
        for step, action in steps:
            try:
                outcome = action(node, result)
            except NotAuthorized as exc:
                return self.stop(result, "NOT_AUTHORIZED", str(exc))
            except UpgradeInProgress as exc:   # I-008 (B2-O3): a retry, not a failure that needs a person
                return self.stop(result, "UPGRADE_IN_PROGRESS", str(exc))
            except (UfmError, host.HostConfigError) as exc:
                result.steps.append({"step": step, "outcome": "FAILED", "detail": str(exc)})
                if step in DEFERRED_FAILURE_STEPS:
                    result.facts.setdefault("deferred_failures", []).append({"step": step, "detail": str(exc)})
                    self.say(f"    [{step}] FAILED（不影响后续步骤，最后整台仍标为失败）: {exc}")
                    continue
                return self.stop(result, f"STEP_FAILED_{step.upper()}", str(exc))
            # the action of a WOULD_* step stays with it, so the review before HA can list it (I-008 expectation 5)
            action = self.pending_action if outcome.startswith("WOULD") else ""
            result.steps.append({"step": step, "outcome": outcome, **({"detail": action} if action else {})})
            self.say(f"    [{step}] {self.outcome_line(outcome)}")
        for item in result.facts.get("network_pending", []):
            self.say(f"    待验证: {item}")
            result.facts.setdefault("attention", []).append(f"待验证: {item}")
        pending = [step["step"] for step in result.steps if step["outcome"].startswith("WOULD")]
        if pending:
            result.status = "NEEDS_CONFIGURATION"
            result.detail = "只读检查，未做改动；需要改动的步骤: " + ", ".join(pending)
        else:
            result.status = done
        return result

    def config_steps(self) -> tuple:
        """Phase 1 and step 1: the base configuration every Ubuntu 24.04 host gets from CSV/global."""
        return (("netplan", self.step_netplan), ("authorized_keys", self.step_authorized_keys),
                ("key_login", self.step_key_login), ("hostname", self.step_hostname),
                ("ipmi_lan", self.step_ipmi_lan), ("ipmi_user", self.step_ipmi_user),
                ("ipmi_power", self.step_ipmi_power),
                ("dns", self.step_dns), ("dns_domains", self.step_dns_domains), ("ntp", self.step_ntp),
                ("timezone", self.step_timezone), ("hosts", self.step_hosts))

    def open_node(self, node: UfmNode, allow_change: bool) -> NodeResult:
        """The deployment key over IPv4 when it already works (问题文档 :1557 第 4 条), else the route decided for this
        UFM with the new root password, else the factory password (first login); a forced password change only
        with allow_change (--apply). Logged in by the key but not this UFM stops the node (B0-O13 (a))."""
        result = NodeResult(node.hostname, self.plan.role_of(node))
        try:
            self.key_access(node, result, "key-login")
        except IdentityMismatch as exc:   # B0-O13 (a) (I-054): stop here, never a password to this address
            return self.stop(result, "IDENTITY_MISMATCH", str(exc))
        except HostKeyConflict as exc:   # v3.1.6 B0 WP-6
            return self.host_key_changed(node, result, exc, allow_change)
        except UfmError:
            return self.login(node, allow_change)
        result.status = "VERIFIED"
        result.password = "key"
        self.say(f"  {node.hostname}: 部署服务器公钥直连 {node.address} 已核验")
        return result

    def config_upgrade_all(self, nodes: list) -> list:
        """config-upgrade --apply (owner 2026-10-20): first the same read-only check as `check` on every
        node, then one confirmation for the whole plan, then per node: a new device changes its factory
        password first, every step re-checks and changes only what is wrong or missing, and the UFM
        upgrade comes last."""
        self.say("  一、先只读检查（与 check 相同）")
        self.apply = False
        try:
            findings = self.check_occupancy(nodes)
            cabling = self.check_cabling(nodes)
            checked = [self.checked(node, cabling) for node in nodes]
        finally:
            self.apply = True
        for item in checked:
            self.add_occupancy(item, findings[item.hostname])
        if any(item.status == "ADDRESS_CONFLICT" for item in checked):
            self.say("    输入地址已被其他设备占用：本次不改动任何设备")
            return [item if item.status == "ADDRESS_CONFLICT" else
                    self.stop(item, "NOT_ATTEMPTED", "另一台 UFM 的输入地址被占用，本次不改动任何设备")
                    for item in checked]
        plan, todo, results = [], [], {}
        for node, item in zip(nodes, checked):
            pending = [step["step"] for step in item.steps if step["outcome"].startswith("WOULD")]
            ipmi = [failure["step"] for failure in item.facts.get("deferred_failures", [])]
            note = f"；{', '.join(ipmi)} 检查失败（其余步骤照常执行，最后整台标为失败）" if ipmi else ""
            if item.status == "NEW_DEVICE":
                plan.append(f"{node.hostname}: 新设备——先把出厂密码改为新密码，再按 global 做全部基础配置并升级")
            elif item.status == "NEEDS_CONFIGURATION":
                plan.append(f"{node.hostname}: 需要改动 {', '.join(pending)}{note}")
            elif item.status == "COMPLIANT":
                item.status = "UP_TO_DATE"
                self.say(f"    {node.hostname}: 基本配置已符合，版本已是目标版本，不改动{note}")
                results[node.hostname] = self.settle_deferred(item)
                continue
            else:   # cannot be checked (unreachable, rejected, identity ...): never configured blindly
                results[node.hostname] = item
                continue
            todo.append(node)
        if todo:
            self.say("  二、改动计划")
            for line in plan:
                self.say(f"    {line}")
            try:
                self.authorize(todo[0], "按以下计划改动设备：\n      " + "\n      ".join(plan))
            except NotAuthorized as exc:
                for node in todo:
                    results[node.hostname] = self.stop(NodeResult(node.hostname, self.plan.role_of(node)),
                                                       "NOT_AUTHORIZED", str(exc))
                todo = []
        if todo:
            self.say("  三、执行（每一步执行前再检查一次，只改不符合的项）")
        for node in todo:
            results[node.hostname] = self.config_upgrade(node)
        return [results[node.hostname] for node in nodes]

    def config_upgrade(self, node: UfmNode, _allow_change: bool = False) -> NodeResult:
        """One node of config-upgrade: base configuration, then (UFM only) the upgrade to the global version."""
        result = self.open_node(node, allow_change=True)
        if result.status != "VERIFIED":
            return result
        self.run_steps(node, result, self.config_steps() + (("upgrade", self.step_upgrade),), "CONFIGURED")
        if result.status != "CONFIGURED":
            return result
        upgraded = dict((step["step"], step["outcome"]) for step in result.steps).get("upgrade") == "UPGRADED"
        if upgraded:
            self.after_upgrade(node, result)
        else:
            changed = [step["step"] for step in result.steps
                       if step["outcome"] not in QUIET_OUTCOMES and step["outcome"] != "FAILED"]
            result.status = "CONFIGURED" if changed else "UP_TO_DATE"
        return self.settle_deferred(result)

    def settle_deferred(self, result: NodeResult) -> NodeResult:
        """Failures of steps that do not block the rest (IPMI) still fail the node at the very end. A status
        that is already a failure (address conflict, a later step ...) stays; the summary lists both."""
        failures = result.facts.get("deferred_failures", [])
        if failures and result.status in SETTLED_BY_DEFERRED:
            self.stop(result, f"STEP_FAILED_{failures[0]['step'].upper()}",
                      f"{'、'.join(item['step'] for item in failures)} 失败（其余步骤已照常执行）")
        return result

    def after_upgrade(self, node: UfmNode, result: NodeResult) -> NodeResult:
        """Owner 2026-10-20: after the upgrade and reboot, log in again, confirm the version and check the
        configuration once more; whatever the upgrade changed is listed and configured again."""
        self.say(f"  {node.hostname}: 升级重启后重新登录，确认版本并重新检查配置")
        self.access.pop(node.hostname, None)
        post = self.open_node(node, allow_change=False)
        if post.status != "VERIFIED":
            return self.stop(result, "POST_UPGRADE_ACCESS_FAILED", f"升级后无法登录: {post.detail}")
        probe = host.parse_kv(self.run_script(node, post, "post-upgrade-version", upgrade_probe_script(
            f"{self.plan.image_server}/image/{image_name(self.plan.version)}")))
        if probe.get("before") != self.plan.version:
            return self.stop(result, "STEP_FAILED_UPGRADE", f"升级后 UFM_APPLIANCE 为 {probe.get('before')!r}，"
                                                            f"应为 {self.plan.version}")
        self.run_steps(node, post, self.config_steps(), "CONFIGURED")
        result.steps += [dict(step, step=f"post_upgrade_{step['step']}") for step in post.steps]
        result.facts["deferred_failures"] = post.facts.get("deferred_failures", [])   # the latest IPMI result counts
        if post.status != "CONFIGURED":
            return self.stop(result, f"POST_UPGRADE_{post.status}", post.detail)
        redone = [step["step"] for step in post.steps if step["outcome"] not in QUIET_OUTCOMES]
        result.facts["post_upgrade_reconfigured"] = redone
        if redone:
            self.say(f"    升级改动了以下配置，已重新配置: {', '.join(redone)}")
        else:
            self.say(f"    升级后版本为 {self.plan.version}，配置未被改动")
        result.status = "UPGRADED"
        return result

    def probe_switch_for(self, node: UfmNode, address: str, bmc_first: bool = False) -> tuple:
        """(switch, svi, vrf) of an OOB Leaf/Spine with its own IPv4 on the subnet of `address`: the Leaf
        the address is cabled to first (the BMC Leaf for the IPMI address: with an EVPN anycast gateway a
        reply only comes back to the host's own Leaf), then the other Leaf, then the Spines LLDP shows."""
        wanted = ipaddress.IPv4Address(address)
        cabled = (self.plan.attachments.get(node.hostname), self.plan.bmc_attachments.get(node.hostname))
        leaves = [item.leaf for item in (cabled[::-1] if bmc_first else cabled) if item]
        candidates = list(dict.fromkeys(leaves))
        for leaf in list(candidates):
            try:
                candidates += [spine for spine in lldp_spine_candidates(self.snapshot(leaf)["interfaces"], self.spines)
                               if spine not in candidates]
            except UfmError:
                continue
        for switch in candidates:
            try:
                rows = self.snapshot(switch)["addresses"]
            except UfmError:
                continue
            for row in rows:
                if str(row.get("ifname", "")).endswith("-v0"):   # VRR macvlan: shared gateway, not an SVI
                    continue
                for item in row.get("addr_info", []):
                    if item.get("family") != "inet":
                        continue
                    try:
                        network = ipaddress.IPv4Interface(f"{item.get('local')}/{item.get('prefixlen')}").network
                    except ValueError:
                        continue
                    if wanted in network:
                        return switch, row["ifname"], self.switch_vrf(switch, row["ifname"])
        return None, "", ""

    def bmc_macs(self, node: UfmNode) -> Optional[set]:
        """MACs learned on this UFM's BMC switch port (P2P), or None when the BMC cabling is unknown."""
        attachment = self.plan.bmc_attachments.get(node.hostname)
        if attachment is None:
            return None
        try:
            return set(self.learned_on(attachment)[1])
        except UfmError:
            return None

    def learned_on(self, attachment: Attachment) -> tuple:
        """(FDB port, dynamic MACs) of a P2P switch port from a fresh `bridge fdb show`: an entry may have aged
        out before the snapshot and come back with the probe that was just sent."""
        port = fdb_port(self.snapshot(attachment.leaf)["links"], attachment.port)
        fdb = self.run_switch(attachment.leaf, ["bridge", "fdb", "show"], label=f"fdb-{attachment.port}")
        return port, sorted({mac for mac, _vlan, _bridge in fdb_entries(fdb, port)}), fdb

    def check_cabling(self, nodes: list) -> dict:
        """B0-O9 (a): check and config-upgrade check the cabling of every jump-routed UFM before any login, the key
        or not (I-037 rules 4-6, one function); a directly logged-in UFM (--direct-access or no *jump) is not
        checked. B0-O3 (a): no question; a failure is CABLE_CHECK_FAILED unless --ignore-cable-check. hostname ->
        facts["cabling"]."""
        self.say("  P2P 线路核对（经跳板的 UFM：CSV eth0_mac 是否学在预期跳板端口上）")
        verdicts = {}
        for node in nodes:
            route, attachment = self.routes.get(node.hostname), self.plan.attachments.get(node.hostname)
            if route is None or route.path != "jump" or attachment is None:
                why = "--direct-access 指定直接登录" if route and route.reason == "DIRECT_ACCESS" else \
                    f"直接登录（{route.reason if route else '未归类'}）"
                verdict = {"outcome": "UNCHECKED", "detail": f"{why}，不做线路核对", "expected": node.mac,
                           "observed": []}
            else:
                try:
                    verdict = cabling_fact(self.cable_check(node, attachment), attachment, self.port_state(attachment))
                except UfmError as exc:
                    verdict = {"outcome": "UNCHECKED", "detail": f"无法读取 {attachment.leaf.hostname} "
                                                                f"{attachment.port}: {exc}",
                               "expected": node.mac, "observed": []}
            self.say(f"    {node.hostname} eth0 {verdict['outcome']}: {verdict['detail']}")
            verdicts[node.hostname] = verdict
        return verdicts

    def checked(self, node: UfmNode, cabling: dict) -> NodeResult:
        """check_node, unless the cabling check failed and --ignore-cable-check was not given."""
        verdict = cabling.get(node.hostname, {})
        if verdict.get("outcome") in {"ELSEWHERE", "NOT_LEARNED"}:
            if not self.ignore_cable_check:
                result = self.stop(NodeResult(node.hostname, self.plan.role_of(node)), "CABLE_CHECK_FAILED",
                                   f"P2P 线路核对不通过（{verdict['outcome']}），未登录: {verdict['detail']}")
                result.facts["cabling"] = verdict
                return result
            verdict = dict(verdict, ignored=True)
            self.say(f"    {node.hostname}: 线路核对 {verdict['outcome']}，按 --ignore-cable-check 继续")
        result = self.check_node(node)
        result.facts["cabling"] = verdict
        return result

    def check_occupancy(self, nodes: list) -> dict:
        """Owner 2026-10-20: no input address may be in use by another device. Probed read-only from
        the OOB Leaf/Spine that owns the subnet: management IPv4, IPMI and VIP. hostname -> findings."""
        self.say("  地址占用检查（在 OOB Leaf/Spine 上 ping 并读取邻居表）")
        mgmt_macs = {node.mac for node in nodes}
        targets = []
        for node in nodes:
            targets.append((node, "eth0", node.address, {node.mac}))
            ipmi = self.plan.addresses.get(self.plan.role_of(node), {}).get("ipmi")
            if ipmi:
                targets.append((node, "ipmi", str(ipaddress.IPv4Interface(ipmi).ip), self.bmc_macs(node)))
        if self.plan.vip and len(nodes) == len(self.plan.nodes) == 2:
            targets.append((nodes[0], "vip", self.plan.vip, mgmt_macs))
        findings = {node.hostname: [] for node in nodes}
        for node, kind, address, expected in targets:
            switch, svi, vrf = self.probe_switch_for(node, address, bmc_first=kind == "ipmi")
            if switch is None:
                verdict, detail = "UNCHECKED", "OOB Leaf/Spine 上没有该网段带 IPv4 的 SVI，无法检测"
            else:
                try:
                    facts = host.parse_kv(self.run_switch(switch, address_probe_command(vrf, svi, address),
                                                          label=f"addr-probe-{address}"))
                except UfmError as exc:
                    verdict, detail = "UNCHECKED", f"在 {switch.hostname} 上检测失败: {exc}"
                else:
                    owner = address_owner(facts)
                    where = f"{switch.hostname} {svi}"
                    if not owner:
                        verdict, detail = "FREE", f"无设备应答（{where}）"
                    elif expected is None:
                        verdict, detail = "UNVERIFIED", (f"{owner} 应答（{where}）；P2P 中没有该 UFM 的 BMC 连线，"
                                                         "无法确认是否就是它的 BMC")
                    elif owner in expected:
                        verdict, detail = ("IN_USE_BY_UFM" if kind == "vip" else "SELF"), f"{owner} 应答（{where}）"
                    else:
                        verdict, detail = "CONFLICT", f"已被其他设备 {owner} 占用（{where}）"
            line = f"{kind} {address}: {verdict} {detail}"
            findings[node.hostname].append({"kind": kind, "address": address, "outcome": verdict, "detail": line})
            self.say(f"    {node.hostname} {line}")
        return findings

    def check_node(self, node: UfmNode) -> NodeResult:
        """check: a new device (forced password change) ends here; otherwise every read-only check."""
        result = self.open_node(node, allow_change=False)
        if result.status == "PASSWORD_CHANGE_REQUIRED":
            result.status = "NEW_DEVICE"
            self.say(f"    {node.hostname} 是新设备（出厂密码要求立即修改），check 到此为止；下一步 config-upgrade --apply")
            return result
        if result.status != "VERIFIED":
            return result
        if result.password == "factory":
            return self.stop(result, "FACTORY_PASSWORD", "root 仍可用出厂密码登录且设备未要求改密；请先把 root 改为新密码")
        return self.run_steps(node, result, self.config_steps() + (("upgrade", self.step_upgrade),), "COMPLIANT")

    def check(self, nodes: list) -> list:
        """check: input addresses not taken by other devices, per node, then (two nodes, both fully
        checked) mutual trust and the HA state."""
        findings = self.check_occupancy(nodes)
        cabling = self.check_cabling(nodes)
        results = [self.checked(node, cabling) for node in nodes]
        for result in results:
            self.add_occupancy(result, findings[result.hostname])
        if len(nodes) == 2 and not self.plan.version:
            # Owner 11-03: no target version, no HA; neither trust nor the HA preconditions are checked.
            for item in results:
                if item.status in {"COMPLIANT", "NEEDS_CONFIGURATION"}:
                    item.steps.append({"step": "ha_config", "outcome": "SKIPPED", "detail": HA_NO_VERSION})
                    self.say(f"    {item.hostname} [ha_config] SKIPPED: {HA_NO_VERSION}")
        elif (len(nodes) == 2 and all(item.status in {"COMPLIANT", "NEEDS_CONFIGURATION"} for item in results)
                and all(node.hostname in self.access for node in nodes)   # B0 WP-6: a pending host key has no session
                and self.plan.vip and self.plan.logical.get("eth1")):
            self.check_ha(nodes, {item.hostname: item for item in results})
        return [self.settle_deferred(item) for item in results]

    def add_occupancy(self, result: NodeResult, findings: list) -> None:
        result.facts["address_check"] = findings
        conflicts = [item["detail"] for item in findings if item["outcome"] == "CONFLICT"]
        if conflicts:
            self.stop(result, "ADDRESS_CONFLICT", "; ".join(conflicts))

    def ha_config_view(self, nodes: list, results: dict) -> tuple:
        """Read-only (check): what ha-setup --apply would find, from `ufm_ha_cluster status` on both nodes."""
        try:
            found, defaults = self.ha_clusters(nodes, results)
        except (UfmError, host.HostConfigError) as exc:
            return "UNKNOWN", str(exc)
        if not found and defaults:
            return "WOULD_CHANGE", "只有 pacemaker 自带的默认单节点集群，ha-setup 会先停掉它再配置"
        if not found:
            return "WOULD_CHANGE", "未配置 HA：ha-setup --apply 会配置并启动"
        status = found[0][1]
        kind, _detail = ha_cluster_kind(status, nodes, self.plan.vip)
        problems = ha_status_problems(status, nodes, self.plan.vip)
        if kind == "ours" and not problems:
            return "OK", "HA 已配置，ufm_ha_cluster status 正常"
        # Owner 2026-10-22: ha-setup never touches an existing HA configuration.
        return ("MISMATCH" if kind == "foreign" else "UNHEALTHY",
                ha_summary(status, nodes, self.plan.vip) + "；ha-setup 不处理已有的 HA 配置，需人工处理或清除后再运行")

    def check_ha(self, nodes: list, results: dict) -> None:
        self.say("  互信与 HA 状态（只读）")
        for item in self.trust(nodes):
            result = results[item.hostname]
            result.steps.extend(item.steps)
            if item.status not in {"TRUSTED", "NEEDS_CONFIGURATION"}:
                result.steps.append({"step": "trust", "outcome": item.status, "detail": item.detail})
        master, standby = self.ha_pair(nodes)
        outcome, note = self.ha_config_view([master, standby], results)
        for node, peer in ((master, standby), (standby, master)):
            result = results[node.hostname]
            if outcome in {"OK", "UNHEALTHY", "MISMATCH"}:
                # A configured cluster runs ufm-enterprise and holds the VIP: the preconditions are pre-HA only.
                result.steps.append({"step": "ha_preconditions", "outcome": "SKIPPED", "detail": "已有 HA 集群"})
            else:
                try:
                    problems = ha_problems(self.ha_probe(node, peer, result, "ha-check"), peer.hostname,
                                           self.plan.vip, self.plan.version)
                except (UfmError, host.HostConfigError) as exc:
                    problems = [f"无法完成检查: {exc}"]
                result.facts["ha_problems"] = problems
                result.steps.append({"step": "ha_preconditions", "outcome": "OK" if not problems else "NOT_MET",
                                     "detail": "; ".join(problems)})
                self.say(f"    {node.hostname} [ha_preconditions] {'OK' if not problems else '; '.join(problems)}")
            result.steps.append({"step": "ha_config", "outcome": outcome, "detail": note})
            self.say(f"    {node.hostname} [ha_config] {outcome}: {note}")
        if outcome in {"OK", "UNHEALTHY", "MISMATCH"}:
            # Owner 2026-10-23: ha-setup never touches an existing HA, so it never builds trust for it (nor does
            # config-upgrade). A key pair or peer key it would add is shown, never counted as a change to make.
            downgraded = False
            for result in results.values():
                for step in result.steps:
                    if (step["step"] in {"root_keypair", "peer_key", "peer_login"}
                            and step["outcome"].startswith(("WOULD", "UNVERIFIED"))):
                        step["outcome"], step["detail"] = "NOT_NEEDED", "已有 HA 配置，ha-setup 不建互信"
                        downgraded = True
            if downgraded:
                self.say("    已有 HA 配置：互信只作提示（ha-setup 不改动已有 HA，也不建互信），上面互信的 WOULD_CHANGE 不计入需要改动")
        for result in results.values():
            pending = [step["step"] for step in result.steps
                       if step["outcome"].startswith(("WOULD", "UNVERIFIED", "UNHEALTHY", "MISMATCH"))]
            if pending:
                result.status = "NEEDS_CONFIGURATION"
                result.detail = "需要改动的步骤: " + ", ".join(pending)

OUTCOME_HELP = {
    "AUTH_REJECTED": "新密码和出厂密码都被拒绝；不切换访问路径，请核实凭据",
    "LEAF_AUTH_REJECTED": "OOB Leaf 认证失败；请核实 cumulus 密码或密钥",
    "PASSWORD_CHANGE_REQUIRED": "设备要求修改 root 密码；check 不改密码，确认后执行 config-upgrade --apply",
    "PASSWORD_CHANGE_UNKNOWN": "改密结果未知；请先手工用新密码登录确认，不要盲目重试",
    "NEW_PASSWORD_REJECTED": "新密码不符合 UFM 密码策略，未修改",
    "HOSTKEY_CONFLICT": "SSH 主机密钥与 known_hosts 冲突；核实设备身份后再处理，不自动接受；只能经 IPv4 登录、"
                        "确认做过 factory reset 时可加 --refresh-host-key <这台> 重跑",
    "REFUSED": "有主机应答但拒绝 SSH：可能地址被占用或 sshd 未运行，停止",
    "UNREACHABLE": "选定的登录路径不可达；不改走其他路径",
    "CABLE_CHECK_FAILED": "P2P 线路核对不通过：核对 CSV eth0_mac 和 P2P 连线；确认要继续时加 --ignore-cable-check 重跑",
    "JUMP_UNREACHABLE": "连不上跳板（全部候选登录地址）；核对跳板，或用 --direct-access <这台> 直接登录",
    "JUMP_ADDRESS_INVALID": "P2P 对端跳板在 ib.csv 中没有可用的登录地址；补全 eth0_ip 或 vlan_id/svi_ip，"
                            "或用 --direct-access <这台>",
    "INPUT_INCOMPLETE": "这台 UFM 的 ib.csv 输入不齐或有误，本次跳过，其他照常；改好后重跑",
    "TIMEOUT": "会话超时",
    "SESSION_TIMEOUT": "已出现登录提示后会话超时，状态未知，停止，不切换路径",
    "UNKNOWN": "输出无法识别，停止，不重试",
}


# ----------------------------------------------------------------- commands

def prepare_run_dir(input_dir: Path, command: str) -> Path:
    logs = input_dir / LOGS_NAME
    if logs.is_symlink() and not logs.exists():
        target = Path(os.readlink(logs))
        target = target if target.is_absolute() else logs.parent / target
        if not target.parent.is_dir():
            raise UfmError(f"{LOGS_NAME} 链接指向 {target}，但其上级目录不存在；请先核对项目目录")
        target.mkdir(exist_ok=True)
    else:
        logs.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for suffix in [""] + [f"-{index}" for index in range(1, 100)]:
        run_dir = logs / f"{stamp}-{command}{suffix}"
        try:
            run_dir.mkdir(mode=0o700)
            return run_dir
        except FileExistsError:
            continue
    raise UfmError(f"无法在 {logs} 下创建运行目录")


def clock() -> str:
    return time.strftime("%H:%M:%S")


def read_secret(prompt: str) -> str:
    try:
        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt):
        raise UfmError("已取消输入") from None


DEFAULT_FACTORY_PASSWORD = "UFMappliance"   # UFM appliance shipping default for root (owner, 2026-10-19)


def prompt_ufm_credentials(user: str, eth_user: str, *, first_login: bool, ask_factory: bool) -> Credentials:
    """Asked once at the start, before any device is contacted: the new (target) root password.

    The factory password is only for the first login (check/config-upgrade): the appliance default unless
    --ask-factory-password; later steps log in with the deployment key or the new password only."""
    if not sys.stdin.isatty():
        raise UfmError("需要在交互终端中输入 UFM 密码；密码不接受命令行参数或环境变量")
    # Owner 2026-10-21: one password per run; it is re-typed only right before a device's forced change.
    new = read_secret(f"UFM {user} 新密码（目标密码，BMC 的 IPMI 用户也用它；公钥登录不通时也用它登录）: ")
    if not new:
        raise UfmError("新密码为空")
    factory = ""
    if first_login:
        factory = read_secret(f"UFM {user} 出厂密码: ") if ask_factory else DEFAULT_FACTORY_PASSWORD
        if not factory or factory == new:
            raise UfmError("出厂密码不能为空，新密码不能与出厂密码相同")
    return Credentials(user, new, factory, eth_user)


def master_inventory(args: argparse.Namespace) -> Path:
    """B0-O6 (b): an explicit --input-dir holds its own 02 (never the repository's, which may be another project's);
    the default tool directory uses <repository>/infiniband/02-devices_config.csv."""
    return (args.input_dir if args.explicit_input_dir else REPO_DIR / "infiniband") / MASTER_INVENTORY


def check_inventory(args: argparse.Namespace) -> int:
    """需求文档 R-016 (:970-977): ib.csv must be 02 or a subset of it, also in read-only mode, before any prompt,
    run directory or login. 0 when consistent; 2 (B0-O12, :975) on a difference or when 02 cannot be read."""
    subset, master = args.input_dir / "ib.csv", master_inventory(args)
    if args.inventory_checked or not subset.exists():   # bringup has compared; no ib.csv is an input error later
        return 0
    try:
        mismatches = [] if subset.resolve() == master.resolve() else inventory_subset.compare(subset, master)
    except (OSError, UnicodeError, csv.Error, IndexError) as exc:
        print(f"ERROR: 无法比对 {subset} 与总清单 {master}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    for item in mismatches:   # the A2 / initial-setup line (v3.1.4 指导 :378)
        print(f"INVENTORY MISMATCH: {item.hostname}; {item.column}; ib.csv={item.subset_value}; "
              f"02={item.master_value}; {item.kind}")
    if mismatches:
        print(f"ERROR: {subset} 与总清单 {master} 不一致，未登录任何设备", file=sys.stderr)
        return 2
    return 0


def resolve_selectors(args: argparse.Namespace, plan: Plan) -> tuple:
    """(--direct-access, --refresh-host-key) as host-name sets, matched once against every server_ufm of ib.csv,
    never only the --node one (D1b-O17 (a); D34-O5); an item that matches nothing raises SelectorError."""
    names = plan.ufm_hostnames
    direct = login_rules.select_direct_access(args.direct_access, names) if args.direct_access else frozenset()
    refresh = frozenset(hostname_ranges.select(hostname_ranges.parse_selector(
        args.refresh_host_key, option="--refresh-host-key", allow_all=False), names)) if args.refresh_host_key \
        else frozenset()
    return direct, refresh


def cmd_inputs(args: argparse.Namespace) -> int:
    """check --inputs-only: the local input check alone, no device contact; the route table is printed too."""
    plan = build_plan(args.input_dir)
    print_plan(plan, print)
    if plan.errors:
        print(f"结果: {len(plan.errors)} 个错误{f'，{len(plan.warnings)} 个警告' if plan.warnings else ''}")
        return 1
    try:
        direct, _refresh = resolve_selectors(args, plan)
    except hostname_ranges.SelectorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print_routes(plan, route_table(plan, direct), print)
    skipped = f"{len(plan.incomplete)} 台 INPUT_INCOMPLETE" if plan.incomplete else "通过"
    print(f"结果: {skipped}{f'，{len(plan.warnings)} 个警告' if plan.warnings else ''}")
    return 1 if plan.incomplete else 0


def input_digests(input_dir: Path) -> dict:
    result = {}
    for name in ("01-global.yaml", "ib.csv", "p2p.xlsx"):
        path = input_dir / name
        if path.is_file():
            result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


# Owner 2026-10-20: three flows. check is read-only (and the default); config-upgrade and ha-setup
# only run with --apply.
FIRST_LOGIN_COMMANDS = {"check", "config-upgrade"}   # may use the factory password
PAIR_COMMANDS = {"ha-setup", "ha-post-config"}       # always both nodes
WRITE_COMMANDS = ("config-upgrade", "ha-setup", "ha-post-config")
# ha-setup (owner 2026-10-22): only HA_CONFIGURED (configured and started by this run) is done. An existing
# HA configuration is HA_EXISTS: nothing is set up and the user clears it first. HA_READY (only the
# preconditions met) is no longer an end state.
DONE_STATUSES = {"check": {"COMPLIANT"}, "config-upgrade": {"UPGRADED", "UP_TO_DATE", "CONFIGURED"},
                 # owner 11-03: without a target version there is no HA, which is not a failure (R-012 设计 :253)
                 "ha-setup": {"HA_CONFIGURED", "HA_SKIPPED_NO_VERSION"},
                 # ha-post-config (owner 2026-10-22): changed and failed over, or already as wanted
                 "ha-post-config": {"HA_POST_CONFIGURED", "HA_POST_UP_TO_DATE"}}
# Owner 2026-10-20: IPMI is out-of-band management; when its steps fail the run records the failure,
# carries on (DNS, NTP, upgrade ...) and still marks the node failed at the end, listing the IPMI errors.
DEFERRED_FAILURE_STEPS = {"ipmi_lan", "ipmi_user", "ipmi_power"}
SETTLED_BY_DEFERRED = {"COMPLIANT", "NEEDS_CONFIGURATION", "CONFIGURED", "UP_TO_DATE", "UPGRADED"}
# Step outcomes that mean "nothing was changed".
QUIET_OUTCOMES = {"UNCHANGED", "OK", "SKIPPED", "SKIPPED_SERVICE_MISSING", "NOT_TESTED", "WARN_NO_DIRECT_KEY_LOGIN"}
# Inspect mode found work that only --apply may do (a forced password change counts too).
EXIT_PENDING = 3   # 2 is argparse's usage error, an inventory mismatch (需求文档 :975) or a name list matching nothing
PENDING_STATUSES = {"NEEDS_CONFIGURATION", "NEW_DEVICE", "FACTORY_PASSWORD"}


def mode_line(args: argparse.Namespace) -> str:
    if args.command not in WRITE_COMMANDS:
        return "模式: 只读（check 从不改动设备：不改密码、不做任何配置；执行过的检查脚本保留在 /root/.setup/）"
    return ("模式: APPLY --yes（不再确认，直接改动设备）" if args.yes
            else "模式: APPLY（第一次改动设备前确认一次，授权对本次运行的后续设备同样有效）")


def confirmer(say: Callable[[str], None]) -> Callable[[str, str], bool]:
    def confirm(hostname: str, action: str) -> bool:
        say(f"\n首次设备改动: {hostname}")
        say(f"  将要执行: {action}")
        try:
            answer = input("授权本次及后续设备的改动？[y/N]: ").strip().casefold()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        granted = answer in {"y", "yes"}
        say(f"  操作员{'已授权' if granted else '未授权'}")
        return granted
    return confirm


def incomplete_result(plan: Plan, hostname: str) -> NodeResult:
    """B0-O7 (a): a UFM skipped for its own inputs; nothing on it is touched, the others go on."""
    problems = plan.incomplete[hostname]
    return NodeResult(hostname, next((role for role, name in plan.roles.items() if name == hostname), ""),
                      status="INPUT_INCOMPLETE", detail="输入不齐，本次跳过这台（其他照常）: " + "; ".join(problems),
                      input_issues=list(problems))


def cmd_nodes(args: argparse.Namespace) -> int:
    plan = build_plan(args.input_dir)
    if plan.errors:
        print_plan(plan, print)
        print("输入检查未通过，不登录任何设备")
        return 1
    try:
        direct, refresh = resolve_selectors(args, plan)
    except hostname_ranges.SelectorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    routes = route_table(plan, direct)
    print_plan(plan, print)   # the input check comes first, before any prompt
    print_routes(plan, routes, print)

    def wanted(hostname: str) -> bool:
        return not args.node or args.node.casefold() in {hostname.casefold(), first_label(hostname)}
    nodes = [node for node in plan.nodes if wanted(node.hostname)]
    skipped = [hostname for hostname in plan.ufm_hostnames if hostname in plan.incomplete and wanted(hostname)]
    if not nodes and not skipped:
        raise UfmError(f"--node {args.node} 不在 ib.csv 的 {UFM_TYPE} 中")
    if args.command in PAIR_COMMANDS and len(nodes) + len(skipped) != len(plan.ufm_hostnames):
        raise UfmError(f"{args.command} 总是处理两台 UFM，不能用 --node 只选一台")
    if not nodes:   # only skipped UFMs: no password, no session; the run directory still records them
        return finish_run(args, plan, routes, [incomplete_result(plan, name) for name in skipped])
    if args.apply and not args.yes and not sys.stdin.isatty():
        raise UfmError("--apply 需要在交互终端确认第一次设备改动；非交互运行请同时加 --yes")
    spines = select_spine_inventory(plan, args.oob_spines)
    print(mode_line(args))
    # Passwords first, before any device is contacted (owner 2026-10-19).
    creds = prompt_ufm_credentials(args.ufm_user, args.eth_user, first_login=args.command in FIRST_LOGIN_COMMANDS,
                                   ask_factory=getattr(args, "ask_factory_password", False))
    if args.command == "config-upgrade" and any(plan.addresses.get(plan.role_of(node), {}).get("ipmi")
                                                      for node in nodes):
        # The IPMI admin user gets the same new root password (owner 2026-10-19).
        if len(creds.new_password.encode("utf-8")) > 16:
            raise UfmError(f"新密码超过 16 字节：ipmitool 交互设置只支持 16 字节，IPMI 用户 {args.ipmi_user} "
                           "无法使用同一密码；未连接任何设备")
        creds.ipmi_password = creds.new_password
    creds.eth_password = ""   # owner 2026-10-21: switches by the deployment key; a password only if it is rejected
    run_dir = prepare_run_dir(args.input_dir, args.command)
    say = Reporter(run_dir / "report.log")
    try:
        say(f"运行目录: {run_dir}")
        say.note(mode_line(args))   # already printed before the password prompts
        print_plan(plan, say.note)
        say("Spine 库存（仅在 Leaf 的 SVI 缺失或无 IPv4 时经 LLDP 选用）: "
            + (", ".join(spine.hostname for spine in spines) or "无"))
        print_routes(plan, routes, say.note)
        session = Session(plan, creds, args.connect_timeout, run_dir, say,
                          lambda: read_secret(f"OOB Leaf/Spine ({args.eth_user}) 公钥登录被拒，请输入密码"
                                              "（直接回车则不登录交换机，相关检查记为 UNCHECKED）: "),
                          direct_access=direct, routes=routes, ignore_cable_check=args.ignore_cable_check,
                          refresh_host_key=refresh,
                          spines=spines, ipmi_user=getattr(args, "ipmi_user", "admin"),
                          ipmi_channel=getattr(args, "ipmi_channel", 1),
                          upgrade_wait=(args.wait_initial, args.wait_interval, args.wait_max)
                          if args.command == "config-upgrade" else (600, 30, 2400),
                          apply=args.apply, confirm=None if args.yes else confirmer(say),
                          confirm_new_password=lambda: read_secret(
                              "设备要求把出厂密码改为新密码：请再次输入 UFM root 新密码确认: "))
        if args.command == "check":
            results = session.check(nodes)
        elif args.command == "ha-setup":
            results = session.ha_setup(nodes)
        elif args.command == "ha-post-config":
            results = session.ha_post_config_command(nodes)
        else:
            results = session.config_upgrade_all(nodes)
        return write_result(args, plan, routes, results + [incomplete_result(plan, name) for name in skipped],
                            run_dir, say)
    finally:
        say.close()


def write_result(args: argparse.Namespace, plan: Plan, routes: dict, results: list, run_dir: Path,
                 say: Callable[[str], None]) -> int:
    order = {name: index for index, name in enumerate(plan.ufm_hostnames)}
    results = sorted(results, key=lambda item: order.get(item.hostname, len(order)))
    for item in results:
        item.login_route = route_record(plan, routes, item.hostname)
    (run_dir / "result.json").write_text(json.dumps(
        {"command": args.command, "apply": args.apply, "run_id": run_dir.name,
         "input_sha256": input_digests(args.input_dir), "nodes": [asdict(item) for item in results]},
        ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
    return summarize(args, results, run_dir, say)


def finish_run(args: argparse.Namespace, plan: Plan, routes: dict, results: list) -> int:
    """Every selected UFM was skipped for its inputs: the run directory, report and result.json only."""
    run_dir = prepare_run_dir(args.input_dir, args.command)
    say = Reporter(run_dir / "report.log")
    try:
        say(f"运行目录: {run_dir}")
        print_plan(plan, say.note)
        print_routes(plan, routes, say.note)
        return write_result(args, plan, routes, results, run_dir, say)
    finally:
        say.close()


def summarize(args: argparse.Namespace, results: list, run_dir: Path, say: Callable[[str], None]) -> int:
    """0: every node already in the wanted state; 3: inspect mode found changes for --apply; 1: failures.
    (2, before any of this: argparse's usage error, ib.csv differing from 02 (需求文档 :975, B0-O12) or a name
    list matching no server_ufm.)"""
    done = DONE_STATUSES[args.command]
    waiting = (lambda item: item.status in PENDING_STATUSES and not args.apply)
    pending = [item for item in results if waiting(item)]
    failed = [item for item in results if item.status not in done and not waiting(item)]
    say("")
    say(mode_line(args))
    for item in results:
        route = item.login_route   # I-037 设计 :155-160: each UFM's route as decided before login
        say(f"  {item.hostname:<36} {item.status}" + (
            f"  {'经跳板' if route['path'] == 'jump' else '直接登录'} {route['reason']}" if route.get("path") else ""))
        cabling = item.facts.get("cabling", {})
        if cabling.get("ignored"):   # B0-O3 (a): listed on its own line, with where the MAC really is
            say(f"      注意: 线路核对 {cabling['outcome']}，按 --ignore-cable-check 继续: {cabling['detail']}")
        if item.host_key:
            say(f"      主机密钥: {item.host_key['address']} {item.host_key['result']}（{item.host_key['note']}）")
        if item.status not in done and not waiting(item):
            for reason in ([item.detail] if item.detail else []) + [
                    f"{failure['step']}: {failure['detail']}" for failure in item.facts.get("deferred_failures", [])]:
                say(f"      {reason}")
    line = f"结果: {len(results) - len(pending) - len(failed)}/{len(results)} 台 {'/'.join(sorted(done))}"
    if pending:
        line += f"；{len(pending)} 台需要改动（只读检查未改动；核对上面的 WOULD_CHANGE 后执行 config-upgrade/ha-setup --apply）"
    if failed:
        line += f"；{len(failed)} 台未完成"
    say(f"{line}；日志 {run_dir}")
    unreachable = {}   # I-037 设计 :159: an unreachable jump is its own class, named
    for item in results:
        if item.status == "JUMP_UNREACHABLE":
            unreachable.setdefault(item.login_route.get("jump") or "?", []).append(first_label(item.hostname))
    for jump, names in unreachable.items():
        say(f"跳板不可达: {jump}（{', '.join(names)}）")
    # Owner 2026-10-22: notes (a failed ufm_enterprise_sanity.sh) come last and change no exit code.
    for item in results:
        for note in item.facts.get("notes", []):
            say(f"提示: {item.hostname}: {note}")
    return 1 if failed else EXIT_PENDING if pending else 0


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(
        description="UFM 部署：check（默认，只读）→ config-upgrade --apply → ha-setup --apply"
                    "（新做 HA 后自动 ha-post-config；已有 HA 时可单独 ha-post-config --apply）。"
                    "输入默认取脚本所在目录的 01-global.yaml、ib.csv、p2p.xlsx、publickey/。",
        epilog="不带子命令时执行 check。config-upgrade、ha-setup、ha-post-config 必须带 --apply 才执行。")
    parser.add_argument("--input-dir", type=Path, default=None,
                        help="输入目录（默认脚本所在目录）；显式给出时总清单用它下面的 02-devices_config.csv")
    sub = parser.add_subparsers(dest="command")
    check = sub.add_parser("check", help="默认：检查输入和设备状态（新设备只核验到需要改密；能登录的做全部只读检查："
                                         "基本配置、版本、互信与 HA）")
    config_upgrade = sub.add_parser("config-upgrade", help="部署基本配置（改密、netplan、公钥、hostname、IPMI、"
                                                           "DNS/NTP/时区），然后把 UFM 升级到 global 的 version")
    ha_setup = sub.add_parser("ha-setup", help="已有 HA 配置时不做任何事并提示；否则检查 HA 条件，做互信和 HA 部署，"
                                               "完成后自动执行 ha-post-config")
    ha_post = sub.add_parser("ha-post-config", help="在已有且正常的 HA 上经 VIP 配置 license、gv.cfg、root_guid.conf，"
                                                    "有改动就 failover 并核对")
    for command in (check, config_upgrade, ha_setup, ha_post):
        command.add_argument("--node", help="只处理这一台（hostname 或第一段）；默认 ib.csv 中全部 server_ufm")
        command.add_argument("--ufm-user", default="root", help="UFM 登录用户（默认 root）")
        command.add_argument("--eth-user", default="cumulus", help="OOB Leaf/Spine 登录用户")
        command.add_argument("--connect-timeout", type=int, default=5, help="SSH 连接超时秒数，1-60（默认 5）")
        command.add_argument("--oob-spines",
                             help="逗号分隔的 Spine 主机名（默认取 ib.csv 中 oob-spine 开头的 eth_jump）；仍需实时 LLDP")
        # v3.1.6 B0 (I-037): the names are matched against every server_ufm of ib.csv, --node or not
        command.add_argument("--direct-access", metavar="名单",
                             help="这些 UFM 不经跳板、直接登录（逗号分隔，可用 * 和 [01-04] 范围，all 表示全部）")
        command.add_argument("--ignore-cable-check", action="store_true",
                             help="线路核对失败时仍用 CSV MAC 的 link-local、经预期端口所属 VLAN 登录并继续")
        command.add_argument("--refresh-host-key", metavar="名单",
                             help="factory reset 后只能经 IPv4 登录的 UFM：跳过核实，只删本机 known_hosts 里它的那一条"
                                  "并重试（只在 --apply 时删）")
        command.add_argument("--inventory-checked", action="store_true", help=argparse.SUPPRESS)
    check.add_argument("--inputs-only", action="store_true", help="只检查本地输入，不登录设备")
    for command in (check, config_upgrade):
        command.add_argument("--ask-factory-password", action="store_true",
                             help=f"首次登录不用出厂默认密码 {DEFAULT_FACTORY_PASSWORD}，改为交互输入")
    for command in (config_upgrade, ha_setup, ha_post):
        command.add_argument("--apply", action="store_true", help="必需：执行改动（第一次改动设备前确认一次）")
        command.add_argument("--yes", action="store_true", help="与 --apply 一起使用：第一次改动前不再确认")
    check.set_defaults(apply=False, yes=False)
    config_upgrade.add_argument("--ipmi-user", default="admin", help="要创建或更新的 IPMI 用户名（密码同 root 新密码）")
    config_upgrade.add_argument("--ipmi-channel", type=int, default=1, help="IPMI LAN 通道")
    config_upgrade.add_argument("--wait-initial", type=int, default=600, help="启动升级后先等待的秒数")
    config_upgrade.add_argument("--wait-interval", type=int, default=30, help="之后每次探测的间隔秒数")
    config_upgrade.add_argument("--wait-max", type=int, default=2400, help="从启动升级算起的最长等待秒数")
    args = parser.parse_args(argv)
    if args.command is None:
        args = parser.parse_args(argv + ["check"])
    args.explicit_input_dir = args.input_dir is not None
    args.input_dir = (args.input_dir or TOOL_DIR).expanduser().absolute()
    if args.command in WRITE_COMMANDS and not args.apply:
        parser.error(f"{args.command} 必须带 --apply 才执行；只查看状态请运行 check（不带子命令即可）")
    if args.yes and not args.apply:
        parser.error("--yes 只能与 --apply 一起使用")
    if not USER_RE.fullmatch(args.ufm_user) or not USER_RE.fullmatch(args.eth_user):
        parser.error("用户名无效")
    if not 1 <= args.connect_timeout <= 60:
        parser.error("--connect-timeout 取值 1-60")
    if args.command == "config-upgrade":
        if not USER_RE.fullmatch(args.ipmi_user) or not 1 <= args.ipmi_channel <= 15:
            parser.error("--ipmi-user 或 --ipmi-channel 无效")
        if not (0 <= args.wait_initial <= args.wait_max and 1 <= args.wait_interval and 60 <= args.wait_max <= 14400):
            parser.error("--wait-* 无效：需 0 <= initial <= max，interval >= 1，max 取 60-14400")
    return args


def main(argv: Optional[list] = None) -> int:
    args = parse_args(argv)
    try:
        if check_inventory(args):
            return 2
        if args.command == "check" and args.inputs_only:
            return cmd_inputs(args)
        return cmd_nodes(args)
    except UfmError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
