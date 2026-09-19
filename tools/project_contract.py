#!/usr/bin/env python3
"""Shared deployment-project schema and transfer exclusion contract."""

from __future__ import annotations

import copy
import fnmatch
import ipaddress
import json
import os
import posixpath
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import re

import yaml

GLOBAL_SCHEMA_VERSION = 1
CURRENT_GLOBAL_SCHEMA_VERSION = 2
SUPPORTED_GLOBAL_SCHEMA_VERSIONS = frozenset({1, 2})
AIR_UNCONNECTED_ENDPOINT = "unconnected"
AIR_OUTBOUND_ENDPOINT = "outbound"
_MAC_ADDRESS = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")
_ISSUE_TRACKER_SPREADSHEET_ID = re.compile(r"^[A-Za-z0-9_-]{20,}$")
_ISSUE_TRACKER_PATH = "common.mgmt.issue-tracker"

# Image-only filename boundary. Keep generic public .pub keys and explicit
# *.service-account.json.example files; private-key basenames include copies.
# This is not a content classifier, nor the live project's transfer policy.
IMAGE_CREDENTIAL_NAME_PATTERNS = (
    "cre.json", "cre.json.*", "*.service-account.json",
    "*.key", "*.pem", "*.p12", "*.pfx", "*.jks", "*.keystore",
    "id_rsa*", "id_ed25519*", "id_ecdsa*", ".ssh", ".env", ".env.*",
    ".control-users.*", "*.htpasswd*",
)


def is_image_credential_name(name: str) -> bool:
    """Match one basename without opening or following its filesystem entry."""
    normalized = name.lower()
    return any(fnmatch.fnmatchcase(normalized, pattern)
               for pattern in IMAGE_CREDENTIAL_NAME_PATTERNS)


def image_credential_docker_patterns() -> tuple[str, ...]:
    """Spell the same ASCII case-insensitive vocabulary for Docker's matcher.

    Consumers pin these ordered final denials; actual Docker COPY, not this
    conversion or Python globbing, proves context membership.
    """
    names = tuple("".join(f"[{char}{char.upper()}]" if "a" <= char <= "z" else char
                          for char in pattern)
                  for pattern in IMAGE_CREDENTIAL_NAME_PATTERNS)
    return tuple("**/" + name for name in names) + ("**/.[sS][sS][hH]/**",)


# Declarative producer authority: setup consumes these mappings to create live
# links; activation consumes the published subset; image policy derives names
# from the entire authority. Paths here never inspect a live project/target.
SETUP_ZTP_MAPPINGS = (
    ("config/cumulus/template/01-global.yaml", "01-global.yaml", "file"),
    ("config/cumulus/template/02-devices_config.csv", "02-devices_config.csv", "file_csv"),
    ("config/cumulus/template/91-devices.yaml", "99-output-eth/91-devices.yaml", "output"),
    ("config/cumulus/template/99-output", "99-output-eth", "dir"),
    ("config/nvos/template/01-global.yaml", "01-global.yaml", "file"),
    ("config/nvos/template/02-devices_config.csv", "02-devices_config.csv", "file_csv"),
    ("config/nvos/template/99-output-ib_nvl", "99-output-ib_nvl", "dir"),
    ("config/isc-dhcp-server/01-global.yaml", "01-global.yaml", "file"),
    ("config/isc-dhcp-server/02-subnet_config.csv", "02-dhcp-subnet_config.csv", "file"),
    ("config/isc-dhcp-server/02-devices_config.csv", "02-devices_config.csv", "file_csv"),
    ("config/isc-dhcp-server/dhcpd_eth.hosts", "99-output-dhcp/dhcpd_eth.hosts", "output"),
    ("config/isc-dhcp-server/dhcpd_ib.hosts", "99-output-dhcp/dhcpd_ib.hosts", "output"),
    ("config/isc-dhcp-server/dhcpd_nvl.hosts", "99-output-dhcp/dhcpd_nvl.hosts", "output"),
    ("config/isc-dhcp-server/dhcpd.conf", "99-output-dhcp/dhcpd.conf", "output"),
    ("config/isc-dhcp-server/dhcp-release-manifest.json", "99-output-dhcp/dhcp-release-manifest.json", "output"),
    ("backup/02-devices_config.csv", "02-devices_config.csv", "file_csv"),
    ("backup/yaml-backup", "99-output-backup", "dir"),
)
SETUP_WORKSPACE_INPUT_MAPPINGS = (
    ("infra/01-global.yaml", "01-global.yaml", "file"),
    ("infra/02-devices_config.csv", "02-devices_config.csv", "file_csv"),
    ("monitor/01-global.yaml", "01-global.yaml", "file"),
)
P2P_INPUT_PATHS = (
    "ztp/config/cumulus/template/P2P/p2p.xlsx",
    "ztp/config/nvos/template/P2P/p2p.xlsx",
    "ethernet/p2p.xlsx", "infiniband/p2p.xlsx", "nvlink/p2p.xlsx",
)
P2P_OUTPUT_PATHS = (
    "ztp/config/cumulus/template/P2P/output-p2p",
    "ztp/config/nvos/template/P2P/output-p2p",
)
P2P_AIR_PATH = "ztp/config/isc-dhcp-server/p2p-air.json"
BRINGUP_OUTPUT_SPECS = tuple(
    ("infiniband/bringup/" + tool + "/" + name, "99-output-ib_nvl/bringup/" + name)
    for tool, name in (("ndr", "ndr-upgrade-logs"),
                       ("xdr-initial-setup", "xdr-initial-setup-logs"),
                       ("xdr-upgrade", "xdr-upgrade-logs"))
)
ANALYZER_INPUT_SPECS = (
    ("ztp/config/cumulus/template/P2P/eth-info", "99-output-monitor/ethernet/eth-info"),
    ("ztp/config/nvos/template/P2P/ib-info", "99-output-monitor/infiniband/ib-info"),
)
ANALYZER_OUTPUT_SPECS = (
    ("monitor/99-output-p2p", "99-output-p2p"),
    ("tools/lldp-analyze-tool/99-output-p2p", "99-output-p2p"),
    ("tools/lldp-analyze-tool/99-output-monitor", "99-output-monitor"),
    ("tools/ibdiagnet-analyze-tool/99-output-p2p", "99-output-p2p"),
)
NETWORK_MONITOR_SPECS = (
    ("ethernet", "eth.csv", "eth-info", "spx-link"),
    ("infiniband", "ib.csv", "ib-info", "ib-link"),
    ("nvlink", "nvsw.csv", "nvsw-info", "nvsw-link"),
)
NETWORK_CSV_MAPPINGS = tuple((network + "/" + csv, "02-devices_config.csv")
                             for network, csv, *_outputs in NETWORK_MONITOR_SPECS)
NETWORK_INVENTORY_LINKS = tuple((network + "/monitor/" + csv, network + "/" + csv)
                               for network, csv, *_outputs in NETWORK_MONITOR_SPECS)
# (repository name, project target, optional repository-internal alias target).
MONITOR_RUNTIME_MAPPINGS = (
    ("monitor/02-devices_config.csv", "02-devices_config.csv", None),
    ("ztp/status", "99-output-ztp", None),
    ("monitor/ztp-status", "99-output-ztp", "ztp/status"),
) + tuple(
    (network + "/monitor/" + name, "99-output-monitor/" + network + "/" + name, None)
    for network, _csv, *outputs in NETWORK_MONITOR_SPECS
    for name in (*outputs, "cronjob.log")
) + tuple(("monitor/" + network, "99-output-monitor/" + network, None)
          for network, *_rest in NETWORK_MONITOR_SPECS)
LATEST_YAML_SPECS = (("cumulus", "99-output"), ("nvos", "99-output-ib_nvl"))
PUBLISHED_RUNTIME_FILE_PATHS = (
    "ztp/ztp-bootstrap_oob.sh", "ztp/ztp-bootstrap_oobofoob.sh", "ztp/ztp.json",
)


def _runtime_relative_target(name, project_target, repository_target=None):
    target = repository_target or "DAY0-Prepare/{project}/" + project_target
    return posixpath.relpath(target, posixpath.dirname(name))


def published_runtime_link_specs():
    """Activation's live publication contract, derived from producer mappings."""
    mappings = tuple((name, target, None) for name, target, _kind in SETUP_WORKSPACE_INPUT_MAPPINGS
                     if name.startswith("monitor/"))
    mappings += MONITOR_RUNTIME_MAPPINGS
    mappings += tuple((name, target, None) for name, target in NETWORK_CSV_MAPPINGS)
    mappings += tuple((name, "02-devices_config.csv", target) for name, target in NETWORK_INVENTORY_LINKS)
    mappings += tuple((name, target, None) for name, target in ANALYZER_OUTPUT_SPECS
                      if not name.startswith("tools/ibdiagnet-analyze-tool/"))
    return tuple((name, _runtime_relative_target(name, target, alias), target)
                 for name, target, alias in mappings)


def runtime_link_specs():
    """All fixed live link names and target templates; no image selector input.

    Dynamic key/image names and project-internal pointers live under fully
    denied families; the fixed outer latest_yaml pointer is included here.
    P2P input/air targets use setup's canonical p2p.xlsx example (the chosen
    source stem is variable in a live project, never needed to classify names).
    """
    specs = {name: target for name, target, _project in published_runtime_link_specs()}
    project_mappings = [("ztp/" + name, target) for name, target, _kind in SETUP_ZTP_MAPPINGS]
    project_mappings += [(name, target) for name, target, _kind in SETUP_WORKSPACE_INPUT_MAPPINGS]
    project_mappings += list(BRINGUP_OUTPUT_SPECS + ANALYZER_INPUT_SPECS + ANALYZER_OUTPUT_SPECS)
    project_mappings += [(name, "p2p.xlsx") for name in P2P_INPUT_PATHS]
    project_mappings += [(name, "99-output-p2p") for name in P2P_OUTPUT_PATHS]
    project_mappings += [(P2P_AIR_PATH, "99-output-p2p/p2p-air.json")]
    specs.update((name, _runtime_relative_target(name, target)) for name, target in project_mappings)
    specs.update(("ztp/config/" + platform + "/latest_yaml", "template/" + output + "/latest")
                 for platform, output in LATEST_YAML_SPECS)
    return tuple(sorted(specs.items()))


class MacStringSafeLoader(yaml.SafeLoader):
    """SafeLoader variant that keeps exact colon-form MACs as strings."""


# YAML 1.1 resolves an all-numeric colon-form MAC as a sexagesimal integer.
# Copy before adding the exact MAC resolver so importing this module never
# changes ``yaml.safe_load`` or another consumer's loader behavior.
MacStringSafeLoader.yaml_implicit_resolvers = copy.deepcopy(
    yaml.SafeLoader.yaml_implicit_resolvers
)
for _first_mac_character in "0123456789abcdefABCDEF":
    MacStringSafeLoader.yaml_implicit_resolvers.setdefault(
        _first_mac_character, [],
    ).insert(
        0,
        (yaml.resolver.BaseResolver.DEFAULT_SCALAR_TAG, _MAC_ADDRESS),
    )


def safe_load_yaml_preserving_mac(stream):
    """Safely load one YAML document while preserving MAC-shaped scalars."""
    return yaml.load(stream, Loader=MacStringSafeLoader)


def safe_load_all_yaml_preserving_mac(stream):
    """Safely load YAML documents while preserving MAC-shaped scalars."""
    return yaml.load_all(stream, Loader=MacStringSafeLoader)


class GlobalSafeLoader(yaml.SafeLoader):
    """Plain SafeLoader semantics with recursive duplicate-key refusal."""


def _construct_unique_global_mapping(loader, node, deep=False):
    seen = set()
    for key_node, _value_node in node.value:
        # SafeLoader resolves YAML merge keys before constructing the final
        # mapping.  They are composition directives, not literal mapping keys;
        # keep their standard override semantics while checking every mapping
        # that supplies the merged values through this same constructor.
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in seen
        except TypeError as exc:
            raise ValueError("global YAML mapping key must be hashable") from exc
        if duplicate:
            raise ValueError(f"global YAML duplicate mapping key: {key!r}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


GlobalSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_global_mapping,
)


def safe_load_global_yaml(stream):
    """Match ``yaml.safe_load`` except recursively rejecting duplicate keys."""
    return yaml.load(stream, Loader=GlobalSafeLoader)

DEVICE_BASE_COLUMNS = (
    "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw",
    "eth0_mac", "eth1_ip", "netmask", "eth1_gw", "eth1_mac", "lo_ip",
)
DEVICE_FIXED_COLUMNS = (
    "bgp_asn", "bgp_ports", "bond_ports", "bond_type", "bond_mac",
    "peerlink_ports", "vrl",
)
DEVICE_V1_VLAN_COLUMNS = (
    "vrf_default", "vlan_id", "svi_ip", "netmask", "vrr_ip", "vrr_mac",
    "vlan_ports",
)
DEVICE_V1_EVPN_COLUMNS = (
    "evpn_vrf", "evpn_l3vni", "evpn_l3vlan", "dhcp_relay",
    "evpn_l2vni", "evpn_l2vlan", "svi_ip", "netmask", "vrr_ip",
    "vrr_mac", "vlan_ports",
)
DEVICE_V2_VLAN_COLUMNS = ("vlan_id", "svi_ip", "netmask", "vlan_ports")
DEVICE_V2_EVPN_COLUMNS = (
    "evpn_vrf", "evpn_l3vni", "evpn_l3vlan", "dhcp_relay",
    "evpn_l2vni", "evpn_l2vlan", "svi_ip", "netmask", "vlan_ports",
)
DEVICE_SOURCE_METADATA_COLUMNS = (
    "source_yaml_b64", "source_yaml_sha256", "source_fields_sha256",
)


@dataclass(frozen=True)
class DeviceCsvLayout:
    """Validated column offsets for one devices_config schema."""

    schema_version: int
    vlan_group_starts: tuple[int, ...]
    fixed_start: int
    evpn_group_starts: tuple[int, ...]
    metadata_start: int
    fixed_columns: tuple[str, ...] = DEVICE_FIXED_COLUMNS

    @property
    def fixed_indices(self) -> dict[str, int]:
        return {
            name: self.fixed_start + offset
            for offset, name in enumerate(self.fixed_columns)
        }

def detect_global_schema_version(data: object) -> int:
    """Return the explicit project schema, defaulting only a missing key to v1.

    ``None`` is deliberately not treated like a missing key.  A present key is
    an operator decision and therefore must be an exact supported integer;
    booleans are rejected even though ``bool`` is a Python ``int`` subclass.
    """
    if not isinstance(data, dict):
        raise ValueError("global YAML 顶层必须是 mapping")
    if "schema_version" not in data:
        return GLOBAL_SCHEMA_VERSION
    value = data["schema_version"]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("global.yaml 的 schema_version 必须是整数 1 或 2")
    if value not in SUPPORTED_GLOBAL_SCHEMA_VERSIONS:
        raise ValueError(
            f"不支持的 global schema_version={value}；当前支持 1 和 2"
        )
    return value


def normalize_issue_tracker_policy(
        global_document: object) -> dict[str, object]:
    """Validate and normalize ``common.mgmt.issue-tracker`` without mutation.

    This setup/load handoff does not discharge the nonvacuous L2b integration
    gate: the eventual real publisher must re-read and normalize on every
    publish attempt. No placeholder publisher belongs in this module.
    """
    path = _ISSUE_TRACKER_PATH
    if not isinstance(global_document, dict):
        raise ValueError(f"{path}: global document must be a mapping")
    try:
        schema_version = detect_global_schema_version(global_document)
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from exc

    if "common" not in global_document:
        block_present = False
        block = None
    else:
        common = global_document["common"]
        if not isinstance(common, dict):
            raise ValueError(f"{path}: common must be a mapping")
        if "mgmt" not in common:
            block_present = False
            block = None
        else:
            mgmt = common["mgmt"]
            if not isinstance(mgmt, dict):
                raise ValueError(f"{path}: common.mgmt must be a mapping")
            block_present = "issue-tracker" in mgmt
            block = mgmt.get("issue-tracker")

    if not block_present:
        return {
            "status": "disabled",
            "presence": "absent",
            "spreadsheet_id": None,
            "publish_every_cycles": 1,
        }
    if schema_version != CURRENT_GLOBAL_SCHEMA_VERSION:
        raise ValueError(f"{path}: schema v1 documents forbid this block")
    if not isinstance(block, dict):
        raise ValueError(f"{path}: block must be a mapping")

    allowed = {"status", "spreadsheet_id", "publish_every_cycles"}
    unexpected = set(block) - allowed
    if unexpected:
        names = sorted(repr(key) for key in unexpected)
        raise ValueError(f"{path}: unsupported keys: {names!r}")

    status = block.get("status")
    if not isinstance(status, str) or status not in {"disabled", "enabled"}:
        raise ValueError(f"{path}.status must be exactly disabled or enabled")
    cycles = block.get("publish_every_cycles", 1)
    if isinstance(cycles, bool) or not isinstance(cycles, int) or cycles < 1:
        raise ValueError(
            f"{path}.publish_every_cycles must be an integer >= 1, excluding bool"
        )

    if status == "disabled":
        if "spreadsheet_id" in block:
            raise ValueError(f"{path}.spreadsheet_id is forbidden when disabled")
        spreadsheet_id = None
    else:
        spreadsheet_id = block.get("spreadsheet_id")
        if (
            not isinstance(spreadsheet_id, str)
            or _ISSUE_TRACKER_SPREADSHEET_ID.fullmatch(spreadsheet_id) is None
        ):
            raise ValueError(
                f"{path}.spreadsheet_id must fullmatch [A-Za-z0-9_-]{{20,}}"
            )

    return {
        "status": status,
        "presence": "explicit",
        "spreadsheet_id": spreadsheet_id,
        "publish_every_cycles": cycles,
    }


def normalize_v2_vrr_policy(eth_config: object) -> dict[str, object]:
    """Validate and normalize the schema-v2 project-wide VRR policy."""
    if not isinstance(eth_config, dict):
        raise ValueError("schema 2 要求 switches.eth 为 mapping")
    raw = eth_config.get("vrr")
    if not isinstance(raw, dict):
        raise ValueError("schema 2 要求 switches.eth.vrr 为 mapping")
    base_mac = str(raw.get("base_mac") or "").strip().lower()
    if not _MAC_ADDRESS.fullmatch(base_mac):
        raise ValueError("switches.eth.vrr.base_mac 必须是合法 48-bit MAC")
    base_value = int(base_mac.replace(":", ""), 16)
    first_octet = int(base_mac[:2], 16)
    if base_value == 0 or first_octet & 0x01:
        raise ValueError(
            "switches.eth.vrr.base_mac 必须是非零 unicast MAC"
        )
    if not first_octet & 0x02:
        raise ValueError(
            "switches.eth.vrr.base_mac 必须使用 locally administered MAC"
        )
    if base_value & 0xFFFF:
        raise ValueError(
            "switches.eth.vrr.base_mac 的低 16 bit 必须为 0，"
            "用于编码四位十进制 VLAN ID"
        )
    if base_value + 0x4094 > 0xFFFFFFFFFFFF:
        raise ValueError("switches.eth.vrr.base_mac 加 VLAN 编码后会溢出")
    gateway = raw.get("gateway_ip")
    if gateway is None:
        gateway_mode = "subnet_maximum"
    elif isinstance(gateway, str):
        gateway_mode = gateway.strip().casefold()
    else:
        gateway_mode = ""
    if gateway_mode not in {"subnet_maximum", "subnet_minimum"}:
        raise ValueError(
            "switches.eth.vrr.gateway_ip 只允许 subnet_maximum、"
            "subnet_minimum、null 或省略"
        )
    return {
        "base_mac": base_mac,
        "base_value": base_value,
        "gateway_ip": gateway_mode,
    }


def normalize_redundancy_mac(value: object, *, label: str = "bond_mac") -> str:
    """Return one canonical non-zero unicast redundancy MAC."""
    mac = str(value or "").strip().lower()
    if not _MAC_ADDRESS.fullmatch(mac):
        raise ValueError(f"{label} 必须是合法 48-bit MAC")
    numeric = int(mac.replace(":", ""), 16)
    if numeric == 0 or int(mac[:2], 16) & 0x01:
        raise ValueError(f"{label} 必须是非零 unicast MAC")
    return mac


def normalize_v2_mlag_policy(eth_config: object) -> dict[str, object]:
    """Validate schema-v2 MLAG globals and index explicit IP overrides.

    Schema v2 derives MLAG membership from the device CSV ``bond_mac``.  The
    global document therefore no longer owns positional ``pairs``.  It can
    only provide an optional, MAC-keyed override for the VXLAN active-active
    shared address when automatic loopback derivation is unsuitable.
    """
    if not isinstance(eth_config, dict):
        raise ValueError("schema 2 要求 switches.eth 为 mapping")
    raw = eth_config.get("mlag")
    if raw is None:
        return {"shared_addresses": {}}
    if not isinstance(raw, dict):
        raise ValueError("schema 2 要求 switches.eth.mlag 为 mapping")
    if "pairs" in raw:
        raise ValueError(
            "schema 2 已删除 switches.eth.mlag.pairs；"
            "请将例外地址迁移到 mlag.shared-addresses[].bond-mac/anycast-ip"
        )

    entries = raw.get("shared-addresses", [])
    if not isinstance(entries, list):
        raise ValueError(
            "switches.eth.mlag.shared-addresses 必须是 list"
        )
    by_mac: dict[str, str] = {}
    by_ip: dict[str, str] = {}
    expected_keys = {"bond-mac", "anycast-ip"}
    for index, entry in enumerate(entries, 1):
        label = f"switches.eth.mlag.shared-addresses[{index}]"
        if not isinstance(entry, dict):
            raise ValueError(f"{label} 必须是 mapping")
        keys = set(entry)
        if keys != expected_keys:
            missing = sorted(expected_keys - keys)
            extra = sorted(keys - expected_keys)
            details = []
            if missing:
                details.append("缺少 " + ", ".join(missing))
            if extra:
                details.append("未知字段 " + ", ".join(extra))
            raise ValueError(f"{label} 字段无效：" + "；".join(details))

        bond_mac = normalize_redundancy_mac(
            entry.get("bond-mac"), label=f"{label}.bond-mac",
        )

        raw_ip = entry.get("anycast-ip")
        if not isinstance(raw_ip, str) or not raw_ip.strip() or "/" in raw_ip:
            raise ValueError(f"{label}.anycast-ip 必须是无 CIDR 的 IPv4 地址")
        try:
            parsed_ip = ipaddress.ip_address(raw_ip.strip())
        except ValueError as exc:
            raise ValueError(f"{label}.anycast-ip 必须是无 CIDR 的 IPv4 地址") from exc
        if not isinstance(parsed_ip, ipaddress.IPv4Address):
            raise ValueError(f"{label}.anycast-ip 必须是无 CIDR 的 IPv4 地址")
        anycast_ip = str(parsed_ip)

        if bond_mac in by_mac:
            raise ValueError(
                f"{label}.bond-mac 重复：{bond_mac}"
            )
        if anycast_ip in by_ip:
            raise ValueError(
                f"{label}.anycast-ip 重复：{anycast_ip}"
            )
        by_mac[bond_mac] = anycast_ip
        by_ip[anycast_ip] = bond_mac
    return {"shared_addresses": by_mac}


def v2_vrr_ipv4_plan(network: object, gateway_mode: str) -> dict[str, object]:
    """Return the strict two-sided three-address plan for one Border /29.

    A maximum-side Border owns N+4/N+5 with VRR N+6 and routes to the
    low-side peer gateway N+3.  A minimum-side Border owns N+2/N+3 with VRR
    N+1 and routes to the high-side peer gateway N+4.  This is deliberately
    a Border transit convention, not a generic rule for other switches.
    """
    try:
        parsed = ipaddress.ip_network(str(network), strict=False)
    except ValueError as exc:
        raise ValueError(f"Border VRR 网段无效：{network!r}") from exc
    if parsed.version != 4 or parsed.prefixlen != 29:
        raise ValueError(
            f"Border 三地址分区只适用于 /29 IPv4 网段：{parsed}"
        )
    if gateway_mode not in {"subnet_maximum", "subnet_minimum"}:
        raise ValueError(f"未知 VRR gateway_ip 模式：{gateway_mode!r}")

    start = parsed.network_address
    if gateway_mode == "subnet_maximum":
        gateway = start + 6
        device_ips = (start + 4, start + 5)
        peer_gateway = start + 3
    else:
        gateway = start + 1
        device_ips = (start + 2, start + 3)
        peer_gateway = start + 4
    return {
        "network": str(parsed),
        "gateway_ip": str(gateway),
        "device_ips": tuple(str(item) for item in device_ips),
        "peer_gateway_ip": str(peer_gateway),
    }


def _repeated_group_starts(
    columns: tuple[str, ...], start: int, end: int,
    group: tuple[str, ...], label: str,
    *, allow_empty: bool,
) -> tuple[int, ...]:
    selected = columns[start:end]
    if not selected:
        if allow_empty:
            return ()
        raise ValueError(f"devices_config.csv 缺少 {label} 字段组")
    width = len(group)
    if len(selected) % width:
        raise ValueError(
            f"devices_config.csv 的 {label} 列数不是 {width} 的整数倍"
        )
    starts = tuple(range(start, end, width))
    for offset in starts:
        if columns[offset:offset + width] != group:
            raise ValueError(
                f"devices_config.csv 的 {label} 必须重复字段组："
                + ",".join(group)
            )
    return starts


def parse_device_csv_layout(
    header: object, schema_version: int,
) -> DeviceCsvLayout:
    """Validate a complete v1/v2 devices CSV header and return its offsets.

    Schema v2 intentionally has no compatibility guessing: a project declaring
    v2 must use the v2 repeated VLAN/EVPN blocks and must not retain v1-only
    ``vrf_default``/``vrr_ip``/``vrr_mac`` input columns.
    """
    if schema_version not in SUPPORTED_GLOBAL_SCHEMA_VERSIONS:
        raise ValueError(f"不支持的 devices_config schema {schema_version}")
    if not isinstance(header, (list, tuple)):
        raise ValueError("devices_config.csv 表头必须是 sequence")
    columns = tuple(str(item or "").strip().casefold() for item in header)
    if columns[:len(DEVICE_BASE_COLUMNS)] != DEVICE_BASE_COLUMNS:
        raise ValueError(
            "devices_config.csv 前 12 列顺序必须为："
            + ",".join(DEVICE_BASE_COLUMNS)
        )

    metadata_start = len(columns)
    for index, name in enumerate(columns):
        if name in DEVICE_SOURCE_METADATA_COLUMNS:
            metadata_start = index
            break
    metadata = columns[metadata_start:]
    if metadata and metadata != DEVICE_SOURCE_METADATA_COLUMNS:
        raise ValueError(
            "devices_config.csv source metadata 必须完整且位于末尾："
            + ",".join(DEVICE_SOURCE_METADATA_COLUMNS)
        )
    body = columns[:metadata_start]

    if schema_version == 1:
        legacy_fixed = DEVICE_FIXED_COLUMNS[:-1]
        expected_prefix = DEVICE_BASE_COLUMNS + DEVICE_V1_VLAN_COLUMNS + legacy_fixed
        if body[:len(expected_prefix)] != expected_prefix:
            raise ValueError(
                "schema 1 devices_config.csv 固定列顺序无效"
            )
        fixed_start = len(DEVICE_BASE_COLUMNS) + len(DEVICE_V1_VLAN_COLUMNS)
        evpn_start = len(expected_prefix)
        fixed_columns = legacy_fixed
        if body[evpn_start:evpn_start + 1] == ("vrl",):
            fixed_columns = DEVICE_FIXED_COLUMNS
            evpn_start += 1
        evpn_starts = _repeated_group_starts(
            body, evpn_start, len(body), DEVICE_V1_EVPN_COLUMNS, "EVPN v1",
            allow_empty=False,
        )
        return DeviceCsvLayout(
            schema_version=1,
            vlan_group_starts=(len(DEVICE_BASE_COLUMNS) + 1,),
            fixed_start=fixed_start,
            evpn_group_starts=evpn_starts,
            metadata_start=metadata_start,
            fixed_columns=fixed_columns,
        )

    try:
        fixed_start = body.index(DEVICE_FIXED_COLUMNS[0], len(DEVICE_BASE_COLUMNS))
    except ValueError as exc:
        raise ValueError("schema 2 devices_config.csv 缺少 bgp_asn 固定列") from exc
    fixed_end = fixed_start + len(DEVICE_FIXED_COLUMNS)
    if body[fixed_start:fixed_end] != DEVICE_FIXED_COLUMNS:
        raise ValueError(
            "schema 2 devices_config.csv 固定列必须为："
            + ",".join(DEVICE_FIXED_COLUMNS)
        )
    if "terminal_l2_ports" in body:
        raise ValueError(
            "schema 2 devices_config.csv 不再支持 terminal_l2_ports；"
            "终端二层 STP 由生成器按接口角色自动处理"
        )
    evpn_start = fixed_end
    vlan_starts = _repeated_group_starts(
        body, len(DEVICE_BASE_COLUMNS), fixed_start, DEVICE_V2_VLAN_COLUMNS,
        "普通 VLAN v2", allow_empty=True,
    )
    evpn_starts = _repeated_group_starts(
        body, evpn_start, len(body), DEVICE_V2_EVPN_COLUMNS,
        "EVPN v2", allow_empty=True,
    )
    return DeviceCsvLayout(
        schema_version=2,
        vlan_group_starts=vlan_starts,
        fixed_start=fixed_start,
        evpn_group_starts=evpn_starts,
        metadata_start=metadata_start,
    )


def require_device_csv_row_width(
    row: object, header_width: int, schema_version: int, *, lineno: int | None = None,
) -> None:
    """Require exact positional row width for schema v2.

    V1 keeps its historical tolerance for omitted trailing empty cells.  V2
    uses repeated positional groups, so accepting a short or over-wide row
    could silently move a value into the wrong VLAN/EVPN group.
    """
    if schema_version != 2:
        return
    if not isinstance(row, (list, tuple)):
        raise ValueError("devices_config.csv 数据行必须是 sequence")
    actual = len(row)
    if actual != header_width:
        location = f"第 {lineno} 行" if lineno is not None else "数据行"
        raise ValueError(
            f"devices_config.csv {location}列数必须与 schema 2 表头完全一致："
            f"{actual} != {header_width}"
        )
ZTP_PREFIX_PUBLICATION_MARKER = ".ztp-prefix-publication.json"
_SAFE_ZTP_PREFIX = re.compile(
    r"/[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*"
)
# Apache's static publication boundary reserves these physical/URL path
# components for management-server-only state.  Every producer and consumer
# of ztp_url_prefix must reject them up front; otherwise Apache would accept a
# prefix that can never serve the public bootstrap/config tree.
ZTP_PREFIX_RESERVED_SEGMENTS = frozenset({
    "day0-prepare", "status", "backup", "optimize",
})
ZTP_PREFIX_RESERVED_SEQUENCES = (
    ("monitor", "ztp-status"),
    ("config", "isc-dhcp-server"),
    ("config", "cumulus", "template"),
    ("config", "nvos", "template"),
)

ANALYSIS_TOOL_NAMES = frozenset({
    "ib-tool-Jie",
    "ibdiagnet-analyze-tool",
})
DEPLOYABLE_TOOL_SUBTREES = frozenset({"lldp-analyze-tool"})

NON_DEPLOYMENT_DIR_NAMES = frozenset({
    "test", "tests", "test_cases", "test-results", "__pycache__", ".pytest_cache",
    "node_modules",
})
REFERENCE_ONLY_SUBTREES = frozenset({"monitor/cabletracker-main"})

# Image-only host state. Do not use this vocabulary to decide live transfers.
# Each pattern denies its entry AND descendants, including symlink objects;
# glob stars match one path component only. Dynamic producer families (keys,
# images, generated output and optimize samples) are denied as entire families.
IMAGE_MANIFEST_CARRIER = "infra/docker/deployment-source-manifest.json"
IMAGE_HOST_STATE_PATHS = frozenset(name for name, _target in runtime_link_specs()) | frozenset(
    PUBLISHED_RUNTIME_FILE_PATHS
) | frozenset({
    "infra/docker/infra-runtime.conf", "infra/docker/container.env",
    "infra/docker/desired-state.json", "infra/docker/runtime-state.json",
    "monitor/generate-monitor.log", "monitor/monitor.html", "ztp/.setup_manifest",
    "infiniband/bringup/xdr-upgrade/ib.csv",
    "infiniband/bringup/xdr-initial-setup/ib.csv",
    "infiniband/bringup/xdr-initial-setup/p2p.xlsx",
}) | frozenset(name + ".zip" for name in REFERENCE_ONLY_SUBTREES)
IMAGE_HOST_STATE_SUBTREES = frozenset({
    "Finished-projects", "infra/logs", "infiniband/bringup", "monitor/status",
    "ztp/backup", "ztp/config/cumulus/template/.claude", "ztp/config/publickey",
    "ztp/image", "tools/ib-tool-Jie", "tools/ibdiagnet-analyze-tool",
}) | REFERENCE_ONLY_SUBTREES
IMAGE_HOST_STATE_DYNAMIC_PATTERNS = (
    "ztp/config/isc-dhcp-server/dhcpd_*.hosts", "ztp/optimize/*-sample",
)


def image_host_state_docker_patterns():
    """Generate final denials, checked byte-for-byte in all three ignore files."""
    patterns = sorted(IMAGE_HOST_STATE_PATHS | IMAGE_HOST_STATE_SUBTREES
                      | frozenset(IMAGE_HOST_STATE_DYNAMIC_PATTERNS))
    return tuple(rule for pattern in patterns for rule in (pattern, pattern + "/**"))


def is_image_host_state_path(relative_name):
    """Name-only predicate; never follow a live link or read project bytes."""
    parts = relative_name.split("/")
    for pattern in IMAGE_HOST_STATE_PATHS | IMAGE_HOST_STATE_SUBTREES | frozenset(IMAGE_HOST_STATE_DYNAMIC_PATTERNS):
        expected = pattern.split("/")
        if len(parts) >= len(expected) and all(fnmatch.fnmatchcase(value, glob)
                                              for value, glob in zip(parts, expected)):
            return True
    return False

ROOT_LOCAL_PLANNING_DIR_NAMES = frozenset({"outputs"})
FINISHED_PROJECT_ROOT_NAME = "Finished-projects"
FINISHED_HISTORY_DIR_NAME = "finished-history"
ROOT_TRANSFERABLE_DOCUMENT_NAMES = frozenset({
    "AGENTS.md",
    "PUBLIC_REPOSITORY.md",
    "SECURITY.md",
})
ROOT_DOCUMENT_SUFFIXES = frozenset({".md", ".markdown", ".log"})
LOCAL_METADATA_DIR_NAMES = frozenset({
    ".git", ".codex", ".agents", ".claude", ".ssh",
})
DEPLOYMENT_CODE_TREE_NAMES = frozenset({
    "infra", "ztp", "monitor", "ethernet", "infiniband", "nvlink",
})

# tools/ is primarily an entrypoint directory.  Top-level runtime source files
# are transferred; README files are documentation-only and always excluded.
# DEPLOYABLE_TOOL_SUBTREES lists the small runtime exception.
# Other subdirectories remain workstation-only analyzers, imports, or samples.
TOOLS_CODE_SUFFIXES = frozenset({".py", ".sh", ".js", ".cjs", ".mjs"})

MANUAL_BACKUP_PATTERNS = (
    "*_副本.*",
    "*_copy.*",
    "*_bak.*",
)


def path_disposition(path: PurePosixPath | str) -> str:
    """Classify one canonical workspace-relative path for deployment.

    The vocabulary is deliberately centralized so archive, transfer, image,
    and governance discovery cannot drift on reference-only or test data.
    """
    if not isinstance(path, (str, PurePosixPath)):
        raise TypeError("workspace path must be a string or PurePosixPath")
    raw = path if isinstance(path, str) else path.as_posix()
    if (
        not raw
        or "\x00" in raw
        or "\\" in raw
        or raw.startswith("/")
        or any(part in {"", ".", ".."} for part in raw.split("/"))
    ):
        raise ValueError(f"workspace path must be canonical and relative: {raw!r}")
    value = PurePosixPath(raw)
    parts = value.parts
    for subtree in REFERENCE_ONLY_SUBTREES:
        subtree_parts = PurePosixPath(subtree).parts
        if parts[:len(subtree_parts)] == subtree_parts:
            return "reference-only"
    if any(part in NON_DEPLOYMENT_DIR_NAMES for part in parts):
        return "nondeployment"
    return "production"


def validate_ztp_url_prefix(value: object) -> str:
    """Return a canonical Apache-reachable ZTP URL prefix.

    In addition to traversal-safe URL syntax, this rejects path components
    reserved by the Apache publication boundary.  Matching is case-insensitive
    and applies at every depth so a nested custom prefix cannot bypass the
    same policy that protects the real ``/var/www/html/ztp`` tree.
    """
    prefix = str(value or "").strip().rstrip("/")
    if (
        not _SAFE_ZTP_PREFIX.fullmatch(prefix)
        or any(part in {".", ".."} for part in prefix.split("/"))
    ):
        raise ValueError(
            "common.mgmt.ztp.ztp_url_prefix 必须是安全绝对 URL path，"
            "只能包含字母、数字、/、-、_、.、~"
        )

    parts = tuple(part.casefold() for part in prefix.lstrip("/").split("/"))
    if any(part in ZTP_PREFIX_RESERVED_SEGMENTS for part in parts):
        raise ValueError(
            "common.mgmt.ztp.ztp_url_prefix 使用了 Apache 保留发布路径"
        )
    for reserved in ZTP_PREFIX_RESERVED_SEQUENCES:
        width = len(reserved)
        if any(parts[index:index + width] == reserved
               for index in range(len(parts) - width + 1)):
            raise ValueError(
                "common.mgmt.ztp.ztp_url_prefix 使用了 Apache 保留发布路径"
            )
    return prefix


def is_manual_backup_name(name: str) -> bool:
    """Identify common ad-hoc backup copies that are not deployment inputs."""
    folded = name.casefold()
    return any(fnmatch.fnmatch(folded, pattern.casefold())
               for pattern in MANUAL_BACKUP_PATTERNS)


def is_readme_name(name: str) -> bool:
    """Return whether *name* is a README document in any common extension."""
    return Path(name).name.casefold().startswith("readme")


def ztp_prefix_publication_relative(root: Path | str) -> PurePosixPath | None:
    """Return the load-owned custom ZTP publication link below *root*.

    The marker and link are management-server runtime, not deployable source.
    A present marker is an ownership boundary: malformed metadata, an unsafe
    path, a symlinked parent, or a conflicting leaf raises ``ValueError`` so
    callers fail closed instead of transferring an untrusted path.

    A valid marker may outlive a missing leaf after an interrupted operation;
    callers that intend to delete runtime state must additionally require the
    returned leaf to exist and revalidate it immediately before mutation.
    """
    workspace = Path(root).resolve(strict=True)
    marker = workspace / ZTP_PREFIX_PUBLICATION_MARKER
    if not os.path.lexists(marker):
        return None
    if marker.is_symlink() or not marker.is_file():
        raise ValueError(f"ZTP prefix marker is not a regular file: {marker}")
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid ZTP prefix marker {marker}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"ZTP prefix marker must contain an object: {marker}")
    schema_version = payload.get("schema_version")
    if isinstance(schema_version, bool) or schema_version != 1:
        raise ValueError("ZTP prefix marker schema_version must be 1")

    raw_prefix = payload.get("prefix")
    try:
        prefix = validate_ztp_url_prefix(raw_prefix)
    except ValueError as exc:
        raise ValueError(f"unsafe custom ZTP prefix: {raw_prefix!r}: {exc}") from exc
    if prefix == "/ztp":
        raise ValueError(f"unsafe custom ZTP prefix in marker: {prefix!r}")
    relative = PurePosixPath(prefix.lstrip("/"))
    if relative.parts[0] == "ztp":
        raise ValueError(f"custom ZTP prefix cannot be below /ztp: {prefix}")

    leaf = workspace.joinpath(*relative.parts)
    expected_target = workspace / "ztp"
    if expected_target.is_symlink() or not expected_target.is_dir():
        raise ValueError(f"ZTP runtime target is not a real directory: {expected_target}")
    if str(payload.get("path") or "") != str(leaf):
        raise ValueError("ZTP prefix marker prefix/path do not match this workspace")
    if str(payload.get("target") or "") != str(expected_target):
        raise ValueError("ZTP prefix marker target does not match this workspace")

    cursor = workspace
    for part in relative.parts[:-1]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError(f"ZTP prefix parent must not be a symlink: {cursor}")
        if os.path.lexists(cursor) and not cursor.is_dir():
            raise ValueError(f"ZTP prefix parent is not a directory: {cursor}")
    if os.path.lexists(leaf):
        if not leaf.is_symlink():
            raise ValueError(f"managed ZTP prefix leaf is not a symlink: {leaf}")
        try:
            resolved = leaf.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ValueError(f"managed ZTP prefix symlink is invalid: {leaf}: {exc}") from exc
        if resolved != expected_target.resolve(strict=True):
            raise ValueError(
                f"managed ZTP prefix symlink has unexpected target: {leaf}"
            )
    return relative


def is_tools_deployable_file(path: PurePosixPath | str) -> bool:
    """Return whether a tools/ source file belongs on a management server."""
    value = PurePosixPath(path)
    if not value.parts or value.parts[0] != "tools":
        return False
    if len(value.parts) > 2:
        if value.parts[1] not in DEPLOYABLE_TOOL_SUBTREES:
            return False
        if any(part in {"node_modules", "99-output-p2p", "99-output-monitor"}
               for part in value.parts[2:]):
            return False
        return not is_readme_name(value.name) and (
            value.suffix.casefold() in TOOLS_CODE_SUFFIXES
        )
    if len(value.parts) != 2:
        return False
    return not is_readme_name(value.name) and (
        value.suffix.casefold() in TOOLS_CODE_SUFFIXES
    )


def transfer_exclude_reason(path: PurePosixPath | str) -> str | None:
    """Return why a workspace-relative path is not deployable, if applicable."""
    value = PurePosixPath(path)
    parts = value.parts
    disposition = path_disposition(path)
    if parts and parts[0] == FINISHED_PROJECT_ROOT_NAME:
        return "finished project archive"
    if (
        len(parts) >= 3
        and parts[0] == "DAY0-Prepare"
        and parts[2] == FINISHED_HISTORY_DIR_NAME
    ):
        return "finished project history link"
    if disposition == "reference-only":
        return "reference-only input"
    if disposition == "nondeployment":
        return "test/development data"
    if parts and parts[0] in ROOT_LOCAL_PLANNING_DIR_NAMES:
        return "local workspace metadata/planning data"
    if any(
        part.casefold() in LOCAL_METADATA_DIR_NAMES
        or part.startswith(".codex_tmp")
        for part in parts
    ):
        return "local workspace metadata/planning data"
    if value == PurePosixPath("USER_MANUAL.md"):
        return "private operator documentation"
    if is_readme_name(value.name):
        return "README documentation"
    if (
        len(parts) == 1
        and value.suffix.casefold() in ROOT_DOCUMENT_SUFFIXES
        and value.name not in ROOT_TRANSFERABLE_DOCUMENT_NAMES
    ):
        return "local workspace metadata/planning data"
    if any(part in ANALYSIS_TOOL_NAMES for part in parts):
        return "offline analysis tool"
    if any(part == ".DS_Store" or part.startswith("._") for part in parts):
        return "macOS metadata"
    if value.name.startswith("~$"):
        return "Office temporary file"
    if value.name.casefold().startswith("deprecated-"):
        return "deprecated input"
    if value.name == "infra-runtime.conf":
        return "host-specific infra runtime"
    if parts and parts[0] in DEPLOYMENT_CODE_TREE_NAMES and (
        value.suffix.casefold() in {".docx", ".pdf", ".xlsx"}
        or (
            value.suffix.casefold() == ".log"
            and parts[:3] == ("infiniband", "bringup", "ndr")
        )
    ):
        return "non-code reference artifact"
    if (
        len(parts) >= 3
        and parts[0:2] == ("infra", "docker")
        and value.name in {
            "container.env", ".env", "desired-state.json", "runtime-state.json",
        }
    ):
        return "host-specific container runtime"
    if value.name == ZTP_PREFIX_PUBLICATION_MARKER:
        return "host-specific ZTP prefix runtime"
    if value.suffix == ".pyc":
        return "Python cache"
    return None


def rsync_excludes() -> tuple[str, ...]:
    """Unanchored patterns shared by every sync-code job.

    ``outputs`` is deliberately absent because only the workspace-root
    planning directory has that meaning; each sync job has its own transfer
    root. Repository metadata names are unsafe at any depth and can therefore
    use shared basename patterns. ``sync-code.py`` additionally applies
    :func:`transfer_exclude_reason` to dynamically matched files.
    """
    return (
        ".DS_Store", "._*", "~$*", "DEPRECATED-*", "deprecated-*", "*.pyc", "*.bak",
        ".git/", ".codex/", ".agents/", ".claude/", ".[Ss][Ss][Hh]/",
        ".codex_tmp*/",
        "Finished-projects/", "finished-history/",
        "*_副本.*", "*_copy.*", "*_bak.*",
        "__pycache__/", ".pytest_cache/", "test/", "tests/", "test_cases/", "test-results/",
        "ib-tool-Jie/", "ibdiagnet-analyze-tool/",
        "[Rr][Ee][Aa][Dd][Mm][Ee]*",
        "infra-runtime.conf", "container.env", ".env",
        "desired-state.json", "runtime-state.json",
        ZTP_PREFIX_PUBLICATION_MARKER,
    )
