#!/usr/bin/env python3
"""Shared deployment-project schema and transfer exclusion contract."""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import re

GLOBAL_SCHEMA_VERSION = 1
CURRENT_GLOBAL_SCHEMA_VERSION = 2
SUPPORTED_GLOBAL_SCHEMA_VERSIONS = frozenset({1, 2})
_MAC_ADDRESS = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")

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
    vlan_starts = _repeated_group_starts(
        body, len(DEVICE_BASE_COLUMNS), fixed_start, DEVICE_V2_VLAN_COLUMNS,
        "普通 VLAN v2", allow_empty=True,
    )
    evpn_starts = _repeated_group_starts(
        body, fixed_end, len(body), DEVICE_V2_EVPN_COLUMNS,
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
    """Return why a path is not deployable, or None when it may be transferred."""
    value = PurePosixPath(path)
    parts = value.parts
    if is_readme_name(value.name):
        return "README documentation"
    if any(part in ANALYSIS_TOOL_NAMES for part in parts):
        return "offline analysis tool"
    if any(part in NON_DEPLOYMENT_DIR_NAMES for part in parts):
        return "test/development data"
    if any(part == ".DS_Store" or part.startswith("._") for part in parts):
        return "macOS metadata"
    if value.name.startswith("~$"):
        return "Office temporary file"
    if value.name.casefold().startswith("deprecated-"):
        return "deprecated input"
    if value.name == "infra-runtime.conf":
        return "host-specific infra runtime"
    if value.name == ZTP_PREFIX_PUBLICATION_MARKER:
        return "host-specific ZTP prefix runtime"
    if value.suffix == ".pyc":
        return "Python cache"
    return None


def rsync_excludes() -> tuple[str, ...]:
    """Patterns shared by every sync-code job."""
    return (
        ".DS_Store", "._*", "~$*", "DEPRECATED-*", "deprecated-*", "*.pyc", "*.bak",
        "*_副本.*", "*_copy.*", "*_bak.*",
        "__pycache__/", ".pytest_cache/", "test/", "tests/", "test_cases/", "test-results/",
        "ib-tool-Jie/", "ibdiagnet-analyze-tool/",
        "[Rr][Ee][Aa][Dd][Mm][Ee]*",
        "infra-runtime.conf", ZTP_PREFIX_PUBLICATION_MARKER,
    )
