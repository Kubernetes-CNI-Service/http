#!/usr/bin/env python3
"""Safely trigger ZTP on explicitly selected project switches.

Positional selectors are exact hostnames or shell-style patterns.  Selection,
identity verification and confirmation happen before any remote ZTP action.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime
import difflib
import fnmatch
import fcntl
import getpass
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import uuid
from urllib.request import Request, urlopen

import yaml


HTTP_ROOT = Path(__file__).resolve().parent.parent
if str(HTTP_ROOT) not in sys.path:
    sys.path.insert(0, str(HTTP_ROOT))
TOOLS_DIR = HTTP_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from project_contract import (
    safe_load_all_yaml_preserving_mac,
    safe_load_yaml_preserving_mac,
    validate_ztp_url_prefix,
)
from deployment_lock import (
    DeploymentLockError,
    acquire_lock_descriptor,
    release_lock_descriptor,
)
from ztp.dynamic_air_inventory import (
    active_leases,
    dynamic_air_devices,
)
from ztp.nvue_normalizer import (
    deep_merge_nvue as _deep_merge_nvue,
    expand_nvue_selector as _expand_nvue_selector,
    normalize_nvue_selectors as _normalize_nvue_selectors,
)

DAY0_ROOT = HTTP_ROOT / "DAY0-Prepare"
STATUS_LINK = HTTP_ROOT / "ztp/status"
DEPLOYMENT_LOCK = HTTP_ROOT / ".deployment.lock"
DHCP_RELEASE_MANIFEST = (
    HTTP_ROOT / "ztp/config/isc-dhcp-server/dhcp-release-manifest.json"
)
AIR_TOPOLOGY_POLICY_NAME = "03-air-topology-policy.json"
SUPPORTED_TYPES = {"eth", "eth_spx", "spx", "air", "ib", "nvl"}
ETHERNET_TYPES = {"eth", "eth_spx", "spx", "air"}
SAFE_HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
SAFE_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,511}$")
CUMULUS_PROFILES = {"oob", "oobofoob", "none"}
NVOS_ZTP_VALUES = {"yes", "no"}
APPLIED_CONFIG_HELPER = (
    "sudo -n -- /usr/local/sbin/http-manual-ztp-applied-config"
)
APPLIED_CONFIG_MAGIC = "ZTP_APPLIED_CONFIG_V1"
TIME_SYNC_HELPER = "/usr/local/sbin/http-sync-management-time"
MAX_APPLIED_CONFIG_BYTES = 8 * 1024 * 1024
APPLIED_SOURCE_KINDS = {
    "dedicated", "default", "fallback", "fallback_default",
}
APPLIED_MODES = {"replace", "patch"}
SAFE_RECEIPT_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
SAFE_RECEIPT_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@%+,:._/-]{0,511}$")
SAFE_SOURCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
ZTP_LOG_LINE = re.compile(
    r"^\[\d{4}-\d{2}-\d{2}(?:T|\s)[^\]\r\n]+\]\s.*$"
)


class ManualZtpError(RuntimeError):
    pass


def ztp_command_log_evidence(text: str) -> tuple[str, bool]:
    """Fingerprint only bootstrap ``log()`` lines from one ztp invocation.

    ``ztp -r`` writes the provisioning script's stdout back to the caller.
    Device wall time can be minutes away from management-server time while NTP
    is converging, so the exact log bytes are a safer operation binding than a
    cross-host timestamp comparison.  Raw ``nv`` output is intentionally
    excluded because it is not emitted by bootstrap ``log()`` into the
    root-owned persistent ZTP result log.
    """
    lines = [
        line.rstrip("\r")
        for line in str(text or "").splitlines()
        if ZTP_LOG_LINE.fullmatch(line.rstrip("\r"))
    ]
    if not lines:
        return "", False
    rendered = "\n".join(lines) + "\n"
    complete = bool(
        any("provision complete" in line for line in lines)
        and any("ZTP FINISH" in line for line in lines)
    )
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest(), complete


def acquire_deployment_lock() -> int:
    """Join the shared deployment generation or fail instead of racing load."""
    try:
        return acquire_lock_descriptor(
            DEPLOYMENT_LOCK.parent, exclusive=False, create=True,
        )
    except DeploymentLockError as exc:
        raise ManualZtpError(
            "无法安全取得部署共享锁，或 load 正在切换部署 release；"
            "人工 ZTP/重置已拒绝，请稍后重试"
        ) from exc


def release_deployment_lock(descriptor: int | None) -> None:
    release_lock_descriptor(descriptor)


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_parent_release_input_hashes(
    project: Path, expected_inputs: dict,
) -> None:
    """Require current project inputs to match the committed parent release."""
    input_paths = {
        "global": (project / "01-global.yaml", "01-global.yaml"),
        "devices": (project / "02-devices_config.csv", "02-devices_config.csv"),
        "subnet": (
            project / "02-dhcp-subnet_config.csv",
            "02-dhcp-subnet_config.csv",
        ),
        "p2p": (project / "p2p.xlsx", "p2p.xlsx"),
    }
    policy_path = project / AIR_TOPOLOGY_POLICY_NAME
    if (
        "air_topology_policy" in expected_inputs
        or os.path.lexists(policy_path)
    ):
        input_paths["air_topology_policy"] = (
            policy_path, "AIR 拓扑策略",
        )

    for name, (path, label) in input_paths.items():
        expected = str(expected_inputs.get(name) or "")
        try:
            actual = sha256_path(path)
        except OSError as exc:
            raise ManualZtpError(
                f"统一 release 输入 {label} 无法读取: {exc}"
            ) from exc
        if not expected or actual != expected:
            raise ManualZtpError(
                f"统一 release 输入 {label} 已变化；请先完整执行 11-load.py"
            )


def require_bound_regular_file(path: Path, label: str) -> None:
    """Reject aliases for files that form a committed release binding."""
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ManualZtpError(f"{label} 无法验证: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ManualZtpError(
            f"{label} 必须是非符号链接、单硬链接的普通文件: {path}"
        )


def normalize_mac(value: str) -> str:
    return re.sub(r"[^0-9a-f]", "", str(value or "").casefold())


def resolve_project(value: str | None) -> Path:
    if value:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute() and not candidate.exists():
            candidate = DAY0_ROOT / candidate
        candidate = candidate.resolve()
    else:
        try:
            output = STATUS_LINK.resolve(strict=True)
        except OSError as exc:
            raise ManualZtpError(
                "无法识别当前项目；请先运行 setup 或使用 -p/--project"
            ) from exc
        candidate = output.parent if output.name == "99-output-ztp" else output
    if not (candidate / "02-devices_config.csv").is_file():
        raise ManualZtpError(f"项目缺少 02-devices_config.csv: {candidate}")
    if not (candidate / "02-dhcp-subnet_config.csv").is_file():
        raise ManualZtpError(f"项目缺少 02-dhcp-subnet_config.csv: {candidate}")
    return candidate


def read_devices(
    csv_path: Path,
    *,
    dhcp_leases: Path = Path("/var/lib/dhcp/dhcpd.leases"),
) -> list[dict]:
    with csv_path.open(newline="", encoding="utf-8-sig", errors="replace") as stream:
        reader = csv.reader(stream)
        headers = next(reader, [])
        normalized_headers = [str(value or "").strip().casefold() for value in headers]
        try:
            eth0_column = normalized_headers.index("eth0_ip")
        except ValueError as exc:
            raise ManualZtpError("02-devices_config.csv 缺少 eth0_ip 列") from exc
        if ("netmask" in normalized_headers
                and (eth0_column + 1 >= len(normalized_headers)
                     or normalized_headers[eth0_column + 1] != "netmask")):
            raise ManualZtpError(
                "02-devices_config.csv 中 eth0_ip 后必须紧跟 netmask 列"
            )
        rows = []
        seen_hostnames: dict[str, int] = {}
        for lineno, values in enumerate(reader, start=2):
            padded = values + [""] * max(0, len(headers) - len(values))
            row = dict(zip(headers, padded))
            hostname = str(row.get("hostname") or "").strip()
            device_type = str(row.get("type") or "").strip().casefold()
            if not any(str(value or "").strip() for value in values):
                continue
            if device_type == "server":
                continue
            if not hostname:
                raise ManualZtpError(f"02-devices_config.csv 第 {lineno} 行 hostname 为空")
            if device_type not in SUPPORTED_TYPES:
                raise ManualZtpError(
                    f"02-devices_config.csv 第 {lineno} 行 type={device_type!r} 无效"
                )
            if not SAFE_HOSTNAME.fullmatch(hostname):
                raise ManualZtpError(f"设备 hostname 含不安全字符: {hostname!r}")
            hostname_key = hostname.casefold()
            if hostname_key in seen_hostnames:
                raise ManualZtpError(
                    f"02-devices_config.csv 第 {lineno} 行 hostname 与第 "
                    f"{seen_hostnames[hostname_key]} 行重复: {hostname!r}"
                )
            seen_hostnames[hostname_key] = lineno
            ip = str(row.get("eth0_ip") or "").strip()
            try:
                ipaddress.ip_address(ip)
            except ValueError as exc:
                raise ManualZtpError(f"{hostname} 的 eth0_ip 无效: {ip!r}") from exc
            candidates = [(ip, "eth0")]
            eth0_mac_plain = normalize_mac(row.get("eth0_mac") or "")
            if str(row.get("eth0_mac") or "").strip() and len(eth0_mac_plain) != 12:
                raise ManualZtpError(f"{hostname} 的 eth0_mac 无效")
            identity_macs = {"eth0": eth0_mac_plain} if eth0_mac_plain else {}
            candidate_identity = {
                f"{ip}|eth0": ("eth0", eth0_mac_plain),
            }
            configured_ips = {ip}
            if device_type in {"ib", "nvl"}:
                eth1_ip = str(row.get("eth1_ip") or "").strip()
                eth1_mac_raw = str(row.get("eth1_mac") or "").strip()
                eth1_mac_plain = normalize_mac(eth1_mac_raw)
                if (eth1_mac_raw and eth1_mac_raw.casefold() not in {"na", "none"}
                        and len(eth1_mac_plain) != 12):
                    raise ManualZtpError(f"{hostname} 的 eth1_mac 无效")
                if eth1_mac_plain:
                    identity_macs["eth1"] = eth1_mac_plain
                try:
                    ipaddress.ip_address(eth1_ip)
                except ValueError:
                    eth1_ip = ""
                if eth1_ip and eth1_ip != ip:
                    candidates.append((eth1_ip, "eth1"))
                    configured_ips.add(eth1_ip)
                    candidate_identity[f"{eth1_ip}|eth1"] = (
                        "eth1", eth1_mac_plain or eth0_mac_plain,
                    )
            if device_type in ETHERNET_TYPES:
                try:
                    eth0_index = headers.index("eth0_ip")
                    prefix = padded[eth0_index + 1].strip()
                    network = ipaddress.ip_interface(f"{ip}/{prefix}").network
                except (ValueError, IndexError):
                    network = None
                if network is not None:
                    for index, column in enumerate(headers):
                        if column != "svi_ip" or index >= len(padded):
                            continue
                        svi = padded[index].strip()
                        if not svi or svi.casefold() in {"na", "none"}:
                            continue
                        try:
                            address = ipaddress.ip_address(svi.split("/", 1)[0])
                        except ValueError:
                            continue
                        if address not in network or str(address) == ip:
                            continue
                        vlan = ""
                        if index and headers[index - 1] in {
                            "vlan_id", "evpn_l2vlan", "evpn_l3vlan",
                        }:
                            vlan = padded[index - 1].strip()
                        candidates.append((str(address), f"vlan{vlan}" if vlan else "SVI"))
                        label = f"vlan{vlan}" if vlan else "SVI"
                        candidate_identity[f"{address}|{label}"] = (
                            "eth0", eth0_mac_plain,
                        )
            rows.append({
                "hostname": hostname,
                "type": device_type,
                "template": str(row.get("template") or "").strip(),
                "ip": ip,
                "mac": str(row.get("eth0_mac") or "").strip(),
                "mac_plain": eth0_mac_plain,
                "identity_macs": identity_macs,
                "candidate_identity": candidate_identity,
                "configured_ips": configured_ips,
                "candidates": list(dict.fromkeys(candidates)),
                "user": "admin" if device_type in {"ib", "nvl"} else "cumulus",
            })

    # AIR rows intentionally omit repeated SVI fields.  Inherit the Production
    # transport candidates sharing the same eth0 address.
    prod_candidates = {
        row["ip"]: row["candidates"] for row in rows
        if row["type"] != "air" and len(row["candidates"]) > 1
    }
    for row in rows:
        if row["type"] == "air" and len(row["candidates"]) == 1:
            row["candidates"] = list(prod_candidates.get(row["ip"], row["candidates"]))

    # A switch that was initially provisioned from a dynamic pool keeps that
    # lease until it actually consumes its newly published fixed identity.
    # Resolve this transport by MAC for every environment and switch family,
    # not just AIR.  The lease is never written back or extended here.
    lease_by_mac = active_leases(dhcp_leases)
    static_ip_owners = {
        address: row["hostname"]
        for row in rows for address in row.get("configured_ips", set()) if address
    }
    for row in rows:
        transition_ips = []
        for interface, mac_plain in row.get("identity_macs", {}).items():
            lease_ip = str(lease_by_mac.get(mac_plain) or "").strip()
            if (
                not mac_plain or not lease_ip
                or lease_ip in row.get("configured_ips", set())
            ):
                continue
            conflict = static_ip_owners.get(lease_ip, "")
            if conflict and conflict.casefold() != row["hostname"].casefold():
                row["lease_transition_issue"] = (
                    f"active lease {lease_ip} conflicts with static device {conflict}"
                )
                continue
            label = f"{interface}(DHCP过渡)"
            row["candidates"] = list(dict.fromkeys([
                *row["candidates"], (lease_ip, label),
            ]))
            row["candidate_identity"][f"{lease_ip}|{label}"] = (
                interface, mac_plain,
            )
            transition_ips.append(lease_ip)
        if transition_ips:
            row["dynamic_lease_ips"] = list(dict.fromkeys(transition_ips))

    for runtime in dynamic_air_devices(csv_path.resolve(), leases=dhcp_leases):
        ip = str(runtime.get("ip") or "").strip()
        rows.append({
            "hostname": runtime["hostname"],
            "type": "air",
            "template": str(runtime.get("template") or ""),
            "ip": ip,
            "mac": str(runtime.get("mac") or ""),
            "mac_plain": str(runtime.get("mac_plain") or ""),
            "identity_macs": {"eth0": str(runtime.get("mac_plain") or "")},
            "candidate_identity": {
                f"{ip}|eth0": ("eth0", str(runtime.get("mac_plain") or "")),
            } if ip else {},
            "configured_ips": set(),
            "candidates": [(ip, "eth0")] if ip else [],
            "user": "cumulus",
            "dynamic_dhcp": True,
            "address_source": str(runtime.get("address_source") or "unresolved"),
            "runtime_issue": str(runtime.get("issue") or ""),
        })
    return rows


def type_matches(device_type: str, requested: str) -> bool:
    if requested == "all":
        return True
    if requested == "prod":
        return device_type != "air"
    if requested == "ethernet":
        return device_type in {"eth", "eth_spx", "spx"}
    return device_type == requested


def select_devices(devices: list[dict], selectors: list[str], requested_type: str) -> list[dict]:
    selected = {}
    unmatched = []
    for selector in selectors:
        matches = [
            device for device in devices
            if type_matches(device["type"], requested_type)
            and fnmatch.fnmatchcase(device["hostname"].casefold(), selector.casefold())
        ]
        if not matches:
            unmatched.append(selector)
        for device in matches:
            selected[device["hostname"].casefold()] = device
    if unmatched:
        raise ManualZtpError(
            "以下设备名/通配符没有匹配当前类型的交换机: " + ", ".join(unmatched)
        )
    if not selected:
        raise ManualZtpError("没有选择任何交换机")
    return sorted(selected.values(), key=lambda item: item["hostname"].casefold())


def choose_one_device(devices: list[dict], *, non_interactive: bool) -> list[dict]:
    """Require an explicit choice whenever selectors resolve to several devices."""
    if len(devices) <= 1:
        return devices
    if non_interactive:
        names = ", ".join(device["hostname"] for device in devices)
        raise ManualZtpError(
            "非交互模式要求位置参数唯一匹配一台设备；当前匹配: " + names
        )
    print("\n位置参数匹配到多台交换机，请明确选择本次要操作的一台：")
    for index, device in enumerate(devices, 1):
        print(
            f"  {index}. {device['hostname']}  "
            f"type={device['type']}  ip={device['ip']}"
        )
    while True:
        answer = input(
            f"请选择设备编号 [1-{len(devices)}]，输入 q 取消："
        ).strip().casefold()
        if answer in {"q", "quit", "cancel"}:
            raise KeyboardInterrupt
        try:
            selected = int(answer)
        except ValueError:
            selected = 0
        if 1 <= selected <= len(devices):
            return [devices[selected - 1]]
        print(f"[WARN] 请输入 1-{len(devices)} 之间的编号，或输入 q 取消")


def validate_host_key_refresh_policy(
    args: argparse.Namespace, devices: list[dict],
) -> None:
    """Restrict explicit trust replacement to one exact Production target."""
    args.host_key_refresh_authorized = False
    if not args.refresh_host_key:
        return
    if args.non_interactive or args.origin != "cli":
        raise ManualZtpError(
            "--refresh-host-key 只允许交互 CLI 使用；GUI/--non-interactive 禁止刷新信任"
        )
    if len(devices) != 1:
        raise ManualZtpError(
            "--refresh-host-key 必须精确选择一台 Production 设备"
        )
    device = devices[0]
    if device.get("type") == "air":
        raise ManualZtpError(
            "--refresh-host-key 仅用于 Production；AIR 公钥模式会在 rebuild 后自动安全刷新"
        )
    if (
        len(args.selectors) != 1
        or args.selectors[0].casefold() != device["hostname"].casefold()
    ):
        raise ManualZtpError(
            "--refresh-host-key 必须使用设备完整 hostname 精确选择，不能使用通配符或多个 selector"
        )
    args.host_key_refresh_authorized = True


def published_yaml_paths(project: Path, device: dict) -> tuple[Path, Path, Path]:
    """Return current marker, hostname YAML and MAC link for one device."""
    output_name = (
        "99-output-ib_nvl" if device.get("type") in {"ib", "nvl"}
        else "99-output-eth"
    )
    latest = project / output_name / "latest"
    hostname_yaml = latest / f"{device['hostname']}.yaml"
    mac_plain = str(device.get("mac_plain") or "")
    mac_yaml = latest / f"{mac_plain}.yaml"
    return latest / ".published-complete", hostname_yaml, mac_yaml


def published_mac_paths(project: Path, device: dict) -> list[Path]:
    marker, _hostname, primary = published_yaml_paths(project, device)
    latest = marker.parent
    macs = list(dict.fromkeys(
        str(value or "") for value in (
            device.get("identity_macs") or {"eth0": device.get("mac_plain")}
        ).values() if str(value or "")
    ))
    return [latest / f"{mac}.yaml" for mac in macs] or [primary]


def _json_object(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManualZtpError(f"{label} 无法读取或不是有效 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ManualZtpError(f"{label} 必须是 JSON object")
    return value


def validate_parent_release_binding(project: Path, device: dict) -> dict[str, str]:
    """Prove current-release binds inputs, DHCP and the active child latest.

    A child generator publishes ``latest`` before load installs DHCP and
    commits the parent.  The deployment flock prevents a cooperating process
    from observing that window; this gate additionally rejects stale/manual
    artifacts or any out-of-band edit that does not match the committed parent.
    """
    parent_path = project / "99-output-ztp/current-release.json"
    parent = _json_object(parent_path, "统一 current-release")
    if (
        parent.get("schema_version") != 1
        or parent.get("validation") != "passed"
        or str(parent.get("project") or "") != project.name
    ):
        raise ManualZtpError("统一 current-release schema/project/validation 门禁未通过")
    release_basis = {
        "project": parent.get("project"),
        "inputs": parent.get("inputs"),
        "components": parent.get("components"),
        "inventory": parent.get("inventory"),
    }
    calculated_release_id = hashlib.sha256(
        json.dumps(
            release_basis, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()[:20]
    if str(parent.get("release_id") or "") != calculated_release_id:
        raise ManualZtpError("统一 current-release release_id 与内容不一致")

    expected_inputs = parent.get("inputs")
    if not isinstance(expected_inputs, dict):
        raise ManualZtpError("统一 current-release 缺少 inputs hash")
    validate_parent_release_input_hashes(project, expected_inputs)

    components = parent.get("components")
    if not isinstance(components, dict):
        raise ManualZtpError("统一 current-release 缺少 components")

    dhcp_component = components.get("dhcp")
    if not isinstance(dhcp_component, dict):
        raise ManualZtpError("统一 current-release 缺少 DHCP 子 release")
    dhcp = _json_object(DHCP_RELEASE_MANIFEST, "DHCP release manifest")
    dhcp_hash = sha256_path(DHCP_RELEASE_MANIFEST)
    if (
        str(dhcp.get("release_id") or "")
        != str(dhcp_component.get("release_id") or "")
        or dhcp_hash != str(dhcp_component.get("manifest_sha256") or "")
    ):
        raise ManualZtpError(
            "当前 DHCP manifest 未绑定到统一 current-release；请重新执行 11-load.py"
        )
    dhcp_outputs = dhcp.get("outputs")
    if not isinstance(dhcp_outputs, dict):
        raise ManualZtpError("DHCP release manifest 缺少 outputs hash")
    verified_dhcp_outputs: dict[str, tuple[Path, str]] = {}
    for name in (
        "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
    ):
        output = dhcp_outputs.get(name)
        expected_hash = str(output.get("sha256") or "") if isinstance(output, dict) else ""
        output_path = DHCP_RELEASE_MANIFEST.parent / name
        try:
            actual_hash = sha256_path(output_path)
        except OSError as exc:
            raise ManualZtpError(f"DHCP release 输出 {name} 无法读取: {exc}") from exc
        if not expected_hash or actual_hash != expected_hash:
            raise ManualZtpError(
                f"DHCP release 输出 {name} 与 manifest hash 不一致；请重新执行 11-load.py"
            )
        verified_dhcp_outputs[name] = (output_path, actual_hash)

    component_name = "nvos" if device.get("type") in {"ib", "nvl"} else "cumulus"
    component = components.get(component_name)
    if not isinstance(component, dict):
        raise ManualZtpError(
            f"统一 current-release 缺少 {component_name} 子 release"
        )
    marker, hostname_yaml, _mac_yaml = published_yaml_paths(project, device)
    try:
        current_release_dir = marker.parent.resolve(strict=True)
        project_root = project.resolve(strict=True)
        relative_release = Path(str(component.get("release_dir") or ""))
        if relative_release.is_absolute():
            raise OSError("release_dir must be relative")
        committed_release_dir = (project_root / relative_release).resolve(strict=True)
        committed_release_dir.relative_to(project_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ManualZtpError(f"{component_name} release_dir 无法验证: {exc}") from exc
    if current_release_dir != committed_release_dir:
        raise ManualZtpError(
            f"{component_name} latest 与统一 current-release 不属于同一代；"
            "请等待或重新执行 11-load.py"
        )

    manifest_path = current_release_dir / "release-manifest.json"
    marker_path = current_release_dir / ".published-complete"
    require_bound_regular_file(
        manifest_path, f"{component_name} release manifest",
    )
    manifest = _json_object(manifest_path, f"{component_name} release manifest")
    require_bound_regular_file(marker_path, f"{component_name} published marker")
    manifest_hash = sha256_path(manifest_path)
    marker_hash = sha256_path(marker_path)
    if (
        str(manifest.get("release_id") or "")
        != str(component.get("release_id") or "")
        or manifest_hash != str(component.get("manifest_sha256") or "")
        or marker_hash != str(component.get("published_marker_sha256") or "")
    ):
        raise ManualZtpError(
            f"{component_name} latest manifest/marker 未绑定到统一 current-release"
        )
    manifest_devices = manifest.get("devices")
    if not isinstance(manifest_devices, list):
        raise ManualZtpError(f"{component_name} release manifest 缺少 devices")
    child_matches = [
        item for item in manifest_devices
        if isinstance(item, dict)
        and str(item.get("hostname") or "").casefold()
        == str(device.get("hostname") or "").casefold()
    ]
    if len(child_matches) != 1:
        raise ManualZtpError(f"设备未唯一绑定到 {component_name} release manifest")
    child_device = child_matches[0]
    try:
        require_bound_regular_file(hostname_yaml, "专属 YAML")
        hostname_yaml_resolved = hostname_yaml.resolve(strict=True)
        config_hash = sha256_path(hostname_yaml_resolved)
    except OSError as exc:
        raise ManualZtpError(f"专属 YAML 无法读取 {hostname_yaml}: {exc}") from exc
    if (
        hostname_yaml_resolved.parent != current_release_dir
        or str(child_device.get("config") or "") != hostname_yaml.name
        or str(child_device.get("config_sha256") or "") != config_hash
    ):
        raise ManualZtpError(
            f"专属 YAML {hostname_yaml.name} 未绑定到 {component_name} release manifest"
        )

    inventory = parent.get("inventory")
    if not isinstance(inventory, list):
        raise ManualZtpError("统一 current-release 缺少 inventory")
    hostname_key = str(device.get("hostname") or "").casefold()
    matches = [
        item for item in inventory
        if isinstance(item, dict)
        and str(item.get("hostname") or "").casefold() == hostname_key
    ]
    if len(matches) != 1:
        raise ManualZtpError("设备未唯一绑定到统一 current-release inventory")
    inventory_device = matches[0]
    if str(inventory_device.get("type") or "").casefold() != str(
        device.get("type") or ""
    ).casefold():
        raise ManualZtpError("设备 type 与统一 current-release inventory 不一致")
    identity_macs = device.get("identity_macs") or {
        "eth0": device.get("mac_plain") or "",
    }
    for interface in ("eth0", "eth1"):
        actual_mac = normalize_mac(identity_macs.get(interface) or "")
        expected_mac = normalize_mac(inventory_device.get(f"{interface}_mac") or "")
        if actual_mac != expected_mac:
            raise ManualZtpError(
                f"设备 {interface} MAC 与统一 current-release inventory 不一致"
            )

    binding = {
        "parent_release_id": str(parent.get("release_id") or ""),
        "parent_manifest_path": str(parent_path),
        "parent_manifest_sha256": sha256_path(parent_path),
        "dhcp_release_id": str(dhcp.get("release_id") or ""),
        "dhcp_manifest_path": str(DHCP_RELEASE_MANIFEST),
        "dhcp_manifest_sha256": dhcp_hash,
        "child_component": component_name,
        "child_release_id": str(manifest.get("release_id") or ""),
        "child_manifest_path": str(manifest_path),
        "child_manifest_sha256": manifest_hash,
        "child_marker_path": str(marker_path),
        "child_marker_sha256": marker_hash,
        "child_release_dir": str(current_release_dir),
        "child_config_path": str(hostname_yaml_resolved),
        "child_config_sha256": config_hash,
    }
    for name, (output_path, output_hash) in verified_dhcp_outputs.items():
        key = name.replace(".", "_")
        binding[f"dhcp_output_{key}_path"] = str(output_path)
        binding[f"dhcp_output_{key}_sha256"] = output_hash
    binding["binding_sha256"] = hashlib.sha256(
        json.dumps(binding, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return binding


def verify_prepared_release_binding(prepared: dict) -> None:
    """Recheck every committed release artifact immediately before mutation."""
    checks = (
        ("parent_manifest_path", "parent_manifest_sha256"),
        ("dhcp_manifest_path", "dhcp_manifest_sha256"),
        ("child_manifest_path", "child_manifest_sha256"),
        ("child_marker_path", "child_marker_sha256"),
        ("child_config_path", "child_config_sha256"),
    )
    dynamic_checks = list(checks)
    for name in (
        "dhcpd_conf", "dhcpd_eth_hosts", "dhcpd_ib_hosts", "dhcpd_nvl_hosts",
    ):
        dynamic_checks.append(
            (f"dhcp_output_{name}_path", f"dhcp_output_{name}_sha256")
        )
    for path_key, hash_key in dynamic_checks:
        path = Path(str(prepared.get(path_key) or ""))
        expected = str(prepared.get(hash_key) or "")
        try:
            if path_key in {
                "parent_manifest_path", "child_manifest_path",
                "child_marker_path", "child_config_path",
            }:
                require_bound_regular_file(path, "确认后 release 绑定文件")
            actual = sha256_path(path)
        except OSError as exc:
            raise ManualZtpError(f"确认后 release 绑定文件无法读取 {path}: {exc}") from exc
        if not expected or actual != expected:
            raise ManualZtpError(
                f"确认后 release 绑定文件已变化 {path.name}；请重新预检"
            )


def dedicated_yaml_ready(
    project: Path, device: dict, *, require_completion: bool = False,
) -> tuple[bool, str]:
    """Validate current published per-host YAML and the exact per-MAC link.

    ``require_completion`` is enabled by every real manual operation.  The
    default remains useful to callers that only want to inspect link shape.
    """
    marker, hostname_yaml, mac_yaml = published_yaml_paths(project, device)
    if require_completion and not marker.is_file():
        return False, f"当前 latest 缺少发布完成标记 {marker.name}"
    if not hostname_yaml.is_file() or hostname_yaml.is_symlink():
        return False, f"当前 latest 缺少专属配置 {hostname_yaml.name}"
    if not str(device.get("mac_plain") or ""):
        return False, "设备缺少 eth0 MAC，无法校验专属配置和 SSH 身份"
    for mac_yaml in published_mac_paths(project, device):
        if not mac_yaml.is_symlink():
            return False, f"当前 latest 缺少 MAC 配置链接 {mac_yaml.name}"
        try:
            if mac_yaml.resolve(strict=True) != hostname_yaml.resolve(strict=True):
                return False, (
                    f"MAC 配置 {mac_yaml.name} 未指向 {hostname_yaml.name}"
                )
        except OSError as exc:
            return False, f"无法验证专属配置链接: {exc}"
    return True, ""


def effective_operation(requested: str, device: dict) -> str:
    """Map a user intent to the fixed safe action for this switch state."""
    if requested == "reset":
        return "reset" if device.get("type") in ETHERNET_TYPES else "ztp"
    if requested == "renew":
        if device.get("type") in ETHERNET_TYPES and device.get("dynamic_lease_ips"):
            return "reset"
        return "ztp"
    return "ztp"


def _canonical_yaml(value):
    """Canonicalize NVUE YAML without relying on textual ordering/quoting."""
    if isinstance(value, dict):
        return {
            str(key): _canonical_yaml(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, list):
        return [_canonical_yaml(item) for item in value]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    # PyYAML may materialize unquoted timestamps as date/datetime objects.
    # NVUE treats these scalar keys/values textually for our comparison.
    return str(value)


def _nvue_set_blocks(value):
    """Return only effective ``set`` blocks, intentionally ignoring headers."""
    if isinstance(value, list):
        blocks = []
        for item in value:
            blocks.extend(_nvue_set_blocks(item))
        return blocks
    if isinstance(value, dict) and "set" in value:
        block = value.get("set")
        return [block] if isinstance(block, dict) else []
    return []


def normalized_nvue_config(text: str, *, label: str) -> tuple[object, str, str]:
    """Canonicalize effective NVUE state across show/input YAML encodings.

    ``nv config show`` adds a header and combines selector keys.  Generated
    ZTP inputs do neither, so comparing the complete YAML documents would
    report a permanent false difference.  Only ``set`` is configuration state.
    """
    try:
        documents = list(safe_load_all_yaml_preserving_mac(text))
    except yaml.YAMLError as exc:
        raise ManualZtpError(f"{label} 不是可解析的 YAML: {exc}") from exc
    blocks = []
    for document in documents:
        blocks.extend(_nvue_set_blocks(document))
    if not blocks:
        raise ManualZtpError(f"{label} 没有有效的 set 配置段")
    merged = {}
    for block in blocks:
        merged = _deep_merge_nvue(merged, block)
    canonical = _canonical_yaml(_normalize_nvue_selectors(merged))
    rendered = json.dumps(canonical, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    return canonical, rendered, digest


_RUNTIME_VALUE_REMOVED = object()


def _remove_runtime_unobservable_nvue(value, path=()):
    """Remove fields that ``nv config show`` cannot reveal faithfully.

    A generated ZTP input contains the configured password hash, while NVUE
    either omits that field or returns a mask.  Removing only that leaf is not
    enough when it was the sole child: the resulting empty parent hierarchy
    would still create a false difference, so containers emptied solely by an
    ignored field are removed as well.  Native empty mappings remain intact.
    """
    if isinstance(value, dict):
        normalized = {}
        removed_child = False
        for key, child in value.items():
            key_text = str(key)
            if (
                key_text == "hashed-password"
                and len(path) == 4
                and path[:3] == ("system", "aaa", "user")
            ):
                removed_child = True
                continue
            comparable_child = _remove_runtime_unobservable_nvue(
                child, (*path, key_text),
            )
            if comparable_child is _RUNTIME_VALUE_REMOVED:
                removed_child = True
                continue
            normalized[key] = comparable_child
        if removed_child and not normalized:
            return _RUNTIME_VALUE_REMOVED
        return normalized
    if isinstance(value, list):
        normalized = []
        removed_child = False
        for index, child in enumerate(value):
            comparable_child = _remove_runtime_unobservable_nvue(
                child, (*path, f"[{index}]"),
            )
            if comparable_child is _RUNTIME_VALUE_REMOVED:
                removed_child = True
                continue
            normalized.append(comparable_child)
        if removed_child and not normalized:
            return _RUNTIME_VALUE_REMOVED
        return normalized
    return value


def runtime_comparable_nvue_config(
    text: str, *, label: str,
) -> tuple[object, str, str]:
    """Return the observable projection used only for live/latest comparison.

    Full normalized and raw hashes remain independent release/TOCTOU evidence;
    this projection must not be used to validate publication integrity.
    """
    canonical, _rendered, _digest = normalized_nvue_config(text, label=label)
    comparable = _remove_runtime_unobservable_nvue(canonical)
    if comparable is _RUNTIME_VALUE_REMOVED:
        comparable = {}
    rendered = json.dumps(
        comparable, ensure_ascii=False, indent=2, sort_keys=True,
    ) + "\n"
    digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    return comparable, rendered, digest


def _changed_config_paths(current, expected, path=""):
    """Return value-free paths for GUI review; never expose config values."""
    if isinstance(current, dict) and isinstance(expected, dict):
        changed = []
        for key in sorted(set(current) | set(expected), key=str):
            child = f"{path}.{key}" if path else str(key)
            if key not in current or key not in expected:
                changed.append(child)
            else:
                changed.extend(_changed_config_paths(current[key], expected[key], child))
        return changed
    if isinstance(current, list) and isinstance(expected, list):
        changed = []
        for index in range(max(len(current), len(expected))):
            child = f"{path}[{index}]"
            if index >= len(current) or index >= len(expected):
                changed.append(child)
            else:
                changed.extend(_changed_config_paths(current[index], expected[index], child))
        return changed
    return [] if current == expected else [path or "<root>"]


def normalized_yaml(text: str, *, label: str) -> tuple[object, str, str]:
    """Backward-compatible name for effective NVUE configuration parsing."""
    return normalized_nvue_config(text, label=label)


def _raw_text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _applied_result_fingerprint(returncode: int, stdout: str) -> str:
    digest = hashlib.sha256()
    digest.update(str(returncode).encode("ascii", errors="strict"))
    digest.update(b"\0")
    digest.update(stdout.encode("utf-8"))
    return digest.hexdigest()


def _validate_applied_at(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def collect_applied_config(
    client: "SshClient", device: dict, host: str,
) -> dict:
    """Read and validate the fixed, root-owned applied-config helper protocol.

    Absence or corruption is returned as untrusted audit evidence.  The live
    normalized ``nv config show`` comparison still proceeds; a receipt never
    replaces or weakens the current-running-config check.
    """
    result = client.run(
        device, host, APPLIED_CONFIG_HELPER,
        timeout=client.args.command_timeout,
    )
    stdout = result.stdout or ""
    fingerprint = _applied_result_fingerprint(result.returncode, stdout)

    def unavailable(reason: str) -> dict:
        return {
            "trusted": False,
            "fingerprint": fingerprint,
            "reason": reason,
            "receipt": {},
            "raw_yaml": "",
        }

    if result.returncode:
        return unavailable("设备尚无可读取的成功 ZTP 输入凭据")
    encoded = stdout.encode("utf-8")
    if len(encoded) > MAX_APPLIED_CONFIG_BYTES:
        return unavailable(
            f"设备 ZTP 输入凭据超过 {MAX_APPLIED_CONFIG_BYTES} bytes 安全上限"
        )
    separator = "\n---\n"
    header, marker, raw_yaml = stdout.partition(separator)
    lines = header.splitlines()
    if not marker or not lines or lines[0] != APPLIED_CONFIG_MAGIC:
        return unavailable("设备 ZTP 输入凭据协议头或分隔符无效")
    if not raw_yaml:
        return unavailable("设备 ZTP 输入凭据没有原始 YAML")
    receipt = {}
    for line in lines[1:]:
        if not line or "=" not in line:
            return unavailable("设备 ZTP receipt 含无效字段行")
        key, value = line.split("=", 1)
        value_is_safe = bool(SAFE_RECEIPT_VALUE.fullmatch(value)) or (
            key == "failed_raw_sha256" and value == ""
        )
        if (
            not SAFE_RECEIPT_KEY.fullmatch(key)
            or key in receipt
            or not value_is_safe
        ):
            return unavailable("设备 ZTP receipt 字段名、字段值或唯一性无效")
        receipt[key] = value
    required = {
        "schema", "status", "source_kind", "apply_mode", "raw_sha256",
        "source_name", "eth0_mac", "applied_at",
    }
    missing = sorted(required - set(receipt))
    if missing:
        return unavailable("设备 ZTP receipt 缺少字段: " + ", ".join(missing))
    if receipt["schema"] != "1" or receipt["status"] != "success":
        return unavailable("设备 ZTP receipt schema/status 不是成功的 V1 凭据")
    if receipt["source_kind"] not in APPLIED_SOURCE_KINDS:
        return unavailable("设备 ZTP receipt source_kind 无效")
    if receipt["apply_mode"] not in APPLIED_MODES:
        return unavailable("设备 ZTP receipt apply_mode 无效")
    if not SAFE_SOURCE_NAME.fullmatch(receipt["source_name"]):
        return unavailable("设备 ZTP receipt source_name 不是安全文件名")
    if not _validate_applied_at(receipt["applied_at"]):
        return unavailable("设备 ZTP receipt applied_at 不是带时区时间")
    raw_digest = _raw_text_sha256(raw_yaml)
    if (
        not re.fullmatch(r"[0-9a-f]{64}", receipt["raw_sha256"])
        or raw_digest != receipt["raw_sha256"]
    ):
        return unavailable("设备 ZTP receipt 的 YAML SHA-256 校验失败")
    failed_digest = receipt.get("failed_raw_sha256", "")
    if failed_digest and not re.fullmatch(r"[0-9a-f]{64}", failed_digest):
        return unavailable("设备 ZTP receipt failed_raw_sha256 无效")
    expected_mac = normalize_mac(device.get("mac_plain") or "")
    receipt_mac = normalize_mac(receipt["eth0_mac"])
    if not expected_mac or receipt_mac != expected_mac:
        return unavailable("设备 ZTP receipt 的 eth0 MAC 与清单身份不一致")

    stable_receipt = {key: receipt[key] for key in sorted(receipt)}
    trusted_fingerprint = hashlib.sha256(
        json.dumps(
            stable_receipt, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8") + b"\0" + raw_digest.encode("ascii")
    ).hexdigest()
    return {
        "trusted": True,
        "fingerprint": trusted_fingerprint,
        "reason": "",
        "receipt": receipt,
        "raw_yaml": raw_yaml,
    }


def _secure_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    os.chmod(path, 0o600)


def preflight_one(
    client: "SshClient", project: Path, device: dict, target_dir: Path,
) -> dict:
    """Verify identity and compare normalized current NVUE state with latest.

    The applied receipt is collected only as audit context and as part of the
    preview/confirm TOCTOU fingerprint.
    """
    release_binding = validate_parent_release_binding(project, device)
    host, interface = connect_and_verify(client, device)
    current = client.run(
        device, host, "nv config show", timeout=client.args.command_timeout,
    )
    if current.returncode or not current.stdout.strip():
        raise ManualZtpError(
            f"{device['hostname']} 配置采集失败: "
            f"{current.stderr.strip() or 'empty nv config show'}"
        )
    marker, expected_path, _mac_path = published_yaml_paths(project, device)
    try:
        release_dir = marker.parent.resolve(strict=True)
        expected_resolved = expected_path.resolve(strict=True)
        if expected_resolved.parent != release_dir or not marker.is_file():
            raise OSError("latest hostname YAML/marker is not in one published release")
        expected_text = expected_resolved.read_text(encoding="utf-8")
        if marker.parent.resolve(strict=True) != release_dir:
            raise OSError("latest changed while collecting preflight evidence")
    except OSError as exc:
        raise ManualZtpError(f"无法读取专属 YAML {expected_path}: {exc}") from exc
    _current_full_value, _current_full_json, current_semantic_digest = (
        normalized_nvue_config(
            current.stdout, label=f"{device['hostname']} 当前配置完整性",
        )
    )
    current_value, current_json, current_comparison_digest = (
        runtime_comparable_nvue_config(
            current.stdout, label=f"{device['hostname']} 当前配置",
        )
    )
    expected_value, expected_json, _expected_comparison_digest = (
        runtime_comparable_nvue_config(
            expected_text, label=f"{device['hostname']} 专属配置",
        )
    )
    # Keep the full semantic digest (including hashed-password) for release
    # and preview/confirm TOCTOU validation.  Only the equality/diff projection
    # above ignores that field.
    _expected_full_value, _expected_full_json, expected_digest = (
        normalized_nvue_config(
            expected_text, label=f"{device['hostname']} 专属配置完整性",
        )
    )
    current_digest = _raw_text_sha256(current.stdout)
    expected_raw_digest = _raw_text_sha256(expected_text)

    applied = collect_applied_config(client, device, host)
    comparison_warnings = []
    receipt = applied.get("receipt") if applied["trusted"] else {}
    source_kind = str(receipt.get("source_kind") or "")
    comparison_source = "nv_config_show_runtime"
    comparison_digest = current_comparison_digest
    payload_matches_latest = None
    fallback_semantic_matches = None
    comparison_reason = (
        "当前 nv config show 已忽略 header 并展开 NVUE 合并 selector，"
        "忽略 hashed-password 不可观测值后，仅与管理服务器发布的 latest 专属配置比较"
    )
    if not applied["trusted"]:
        comparison_warnings.append(
            f"{applied.get('reason') or '设备没有 applied-config receipt'}；"
            "不影响当前运行配置与 latest 的比较，但缺少上次 ZTP 输入审计凭据"
        )

    # The receipt proves what ZTP last applied; it is intentionally immutable
    # and therefore cannot reveal configuration changes made afterwards.  The
    # normalized live NVUE state is a separate comparison, so a trusted and
    # still-current receipt must never hide real device drift.
    runtime_matches_latest = current_value == expected_value
    if not runtime_matches_latest:
        comparison_warnings.append(
            "设备当前 nv config show 与 latest 存在运行态漂移；"
            "变化路径以下方“当前运行配置”比较为准"
        )

    expected_binding_digest = hashlib.sha256(
        (
            f"{expected_digest}:{release_binding['binding_sha256']}:"
            f"{applied['fingerprint']}:{comparison_source}"
        ).encode("utf-8")
    ).hexdigest()
    target_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(target_dir, 0o700)
    _secure_text(target_dir / "before.yaml", current.stdout)
    _secure_text(target_dir / "expected.yaml", expected_text)
    _secure_text(target_dir / "before.normalized.json", current_json)
    _secure_text(target_dir / "expected.normalized.json", expected_json)
    if applied["trusted"]:
        _secure_text(target_dir / "applied.yaml", applied["raw_yaml"])
    runtime_diff = "".join(difflib.unified_diff(
        current_json.splitlines(keepends=True),
        expected_json.splitlines(keepends=True),
        fromfile="runtime:current-nv-config-show",
        tofile=f"latest:{expected_path.name}",
    ))
    if not runtime_diff:
        runtime_diff = "# 当前 nv config show 与 latest 的规范化 NVUE 语义一致\n"
    _secure_text(target_dir / "config.diff", runtime_diff)

    diff_lines = runtime_diff.splitlines()
    excerpt_limit = 120
    changed_paths = _changed_config_paths(current_value, expected_value)
    # Retain the historical field for API compatibility, but make its name
    # truthful: "configuration" now means the current device state.
    configuration_matches = runtime_matches_latest
    payload = {
        "hostname": device["hostname"], "transport_ip": host,
        "interface": interface, "expected_yaml": str(expected_path),
        "published_marker": str(marker),
        "published_release_dir": str(release_dir),
        "published_mac_links": [
            str(path) for path in published_mac_paths(project, device)
        ],
        # Raw nv-config-show bytes are deliberately retained as the independent
        # preview -> confirm TOCTOU gate.  They are not compared across YAML
        # representations to decide whether the ZTP input is current.
        "current_sha256": current_digest,
        "current_semantic_sha256": current_semantic_digest,
        "comparison_sha256": comparison_digest,
        "applied_fingerprint": applied["fingerprint"],
        # This is intentionally the user-confirmed fingerprint: it binds the
        # latest YAML/release to the exact applied-receipt state observed by
        # the preview.  Existing CGI fields therefore also cover the receipt.
        "expected_sha256": expected_binding_digest,
        "expected_yaml_sha256": expected_digest,
        "expected_yaml_raw_sha256": expected_raw_digest,
        **release_binding,
        "comparison_source": comparison_source,
        "payload_matches_latest": payload_matches_latest,
        "fallback_semantic_matches": fallback_semantic_matches,
        "runtime_matches_latest": runtime_matches_latest,
        "configuration_matches": configuration_matches,
        "comparison_reason": comparison_reason,
        "comparison_warnings": comparison_warnings,
        "applied_source_kind": source_kind,
        "applied_apply_mode": str(receipt.get("apply_mode") or ""),
        "applied_source_name": str(receipt.get("source_name") or ""),
        "applied_at": str(receipt.get("applied_at") or ""),
        "failed_payload_matches_latest": False,
        "diff_summary": {
            "configuration_matches": configuration_matches,
            "comparison_source": comparison_source,
            "payload_matches_latest": payload_matches_latest,
            "fallback_semantic_matches": fallback_semantic_matches,
            "runtime_matches_latest": runtime_matches_latest,
            "comparison_reason": comparison_reason,
            "warnings": comparison_warnings,
            "applied_source_kind": source_kind,
            "applied_apply_mode": str(receipt.get("apply_mode") or ""),
            "failed_payload_matches_latest": False,
            "added_lines": sum(
                1 for line in diff_lines
                if line.startswith("+") and not line.startswith("+++")
            ),
            "removed_lines": sum(
                1 for line in diff_lines
                if line.startswith("-") and not line.startswith("---")
            ),
            "total_lines": len(diff_lines),
            # The CGI status endpoint is HTTP-readable by the dashboard.  It
            # receives only value-free paths/counts; the full unified diff is
            # retained in the local evidence directory for privileged review.
            "changed_paths": changed_paths[:excerpt_limit],
            "truncated": len(changed_paths) > excerpt_limit,
        },
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }
    atomic_json(target_dir / "preflight.json", payload)
    return payload


def display_preflight_diff(target_dir: Path, *, limit: int = 240) -> None:
    diff_path = target_dir / "config.diff"
    lines = diff_path.read_text(encoding="utf-8", errors="replace").splitlines()
    try:
        metadata = json.loads(
            (target_dir / "preflight.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        metadata = {}
    runtime_matches = "是" if metadata.get("runtime_matches_latest") else "否"
    print(f"\n--- {target_dir.name} 当前 nv config show vs latest ---")
    print(f"设备当前运行配置是否与 latest 一致：{runtime_matches}")
    if metadata.get("comparison_reason"):
        print(f"原因：{metadata['comparison_reason']}")
    for warning in metadata.get("comparison_warnings") or []:
        print(f"[WARN] {warning}")
    for line in lines[:limit]:
        print(line)
    if len(lines) > limit:
        print(f"... 已省略 {len(lines) - limit} 行，完整 diff: {diff_path}")
    else:
        print(f"完整 diff: {diff_path}")


def global_ztp_url_prefix(global_yaml: Path) -> str:
    """Return the validated project-owned URL prefix used by all ZTP URLs."""
    try:
        document = safe_load_yaml_preserving_mac(
            global_yaml.read_text(encoding="utf-8")
        )
        prefix = str(document["common"]["mgmt"]["ztp"]["ztp_url_prefix"]).strip()
    except (OSError, KeyError, TypeError, yaml.YAMLError) as exc:
        raise ManualZtpError(
            f"无法读取 01-global.yaml 的 common.mgmt.ztp.ztp_url_prefix: {exc}"
        ) from exc
    try:
        return validate_ztp_url_prefix(prefix)
    except ValueError as exc:
        raise ManualZtpError(str(exc)) from exc


def provision_urls(
    subnet_csv: Path, global_yaml: Path,
) -> list[tuple[ipaddress.IPv4Network, str]]:
    """Derive Cumulus bootstrap URLs from the declarative subnet contract."""
    prefix = global_ztp_url_prefix(global_yaml)
    result = []
    profile_services: dict[str, tuple[ipaddress.IPv4Address, int]] = {}
    nvos_service: tuple[ipaddress.IPv4Address, int] | None = None
    with subnet_csv.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        reader.fieldnames = [
            str(column or "").strip().casefold().replace(" ", "_")
            for column in (reader.fieldnames or [])
        ]
        duplicates = sorted({
            column for column in reader.fieldnames
            if reader.fieldnames.count(column) > 1
        })
        if duplicates:
            raise ManualZtpError(
                "02-dhcp-subnet_config.csv 列名重复: " + ", ".join(duplicates)
            )
        legacy = sorted(
            {"bootfile_name", "cumulus_provision_url"} & set(reader.fieldnames)
        )
        if legacy:
            raise ManualZtpError(
                "02-dhcp-subnet_config.csv 仍包含已废弃 URL 列: "
                + ", ".join(legacy)
                + "；请改用 ztp_service_ip,cumulus_profile,nvos_ztp"
            )
        required = {
            "shared_network", "subnet", "netmask", "range_start", "range_end",
            "routers", "ztp_service_ip", "cumulus_profile", "nvos_ztp",
        }
        missing = sorted(required - set(reader.fieldnames or []))
        if missing:
            raise ManualZtpError(
                "02-dhcp-subnet_config.csv 缺少列: " + ", ".join(missing)
            )
        for line_number, row in enumerate(reader, 2):
            if not any(str(value or "").strip() for value in row.values()):
                continue
            profile = str(row.get("cumulus_profile") or "").strip().casefold()
            nvos_ztp = str(row.get("nvos_ztp") or "").strip().casefold()
            if profile not in CUMULUS_PROFILES:
                raise ManualZtpError(
                    f"02-dhcp-subnet_config.csv:{line_number} cumulus_profile "
                    f"必须是 oob/oobofoob/none: {profile!r}"
                )
            if nvos_ztp not in NVOS_ZTP_VALUES:
                raise ManualZtpError(
                    f"02-dhcp-subnet_config.csv:{line_number} nvos_ztp "
                    f"必须是 yes/no: {nvos_ztp!r}"
                )
            service_ip_text = str(row.get("ztp_service_ip") or "").strip()
            service_ip = None
            if service_ip_text:
                try:
                    service_ip = ipaddress.IPv4Address(service_ip_text)
                except ValueError as exc:
                    raise ManualZtpError(
                        f"02-dhcp-subnet_config.csv:{line_number} "
                        f"ztp_service_ip 无效: {service_ip_text!r}"
                    ) from exc
                if service_ip.is_unspecified or service_ip.is_multicast:
                    raise ManualZtpError(
                        f"02-dhcp-subnet_config.csv:{line_number} "
                        f"ztp_service_ip={service_ip} 不是可用单播地址"
                    )
            if (profile != "none" or nvos_ztp == "yes") and service_ip is None:
                raise ManualZtpError(
                    f"02-dhcp-subnet_config.csv:{line_number} 启用 ZTP 时 "
                    "ztp_service_ip 不能为空"
                )
            if profile == "none" and nvos_ztp == "no" and service_ip is not None:
                raise ManualZtpError(
                    f"02-dhcp-subnet_config.csv:{line_number} Cumulus/NVOS ZTP "
                    "均停用时 ztp_service_ip 必须为空"
                )
            if service_ip is not None and profile != "none":
                previous = profile_services.setdefault(
                    profile, (service_ip, line_number),
                )
                if previous[0] != service_ip:
                    raise ManualZtpError(
                        f"02-dhcp-subnet_config.csv:{line_number} "
                        f"cumulus_profile={profile} 使用 {service_ip}，但第 "
                        f"{previous[1]} 行使用 {previous[0]}；同一 profile "
                        "只能有一个 ztp_service_ip"
                    )
            if service_ip is not None and nvos_ztp == "yes":
                if nvos_service is None:
                    nvos_service = (service_ip, line_number)
                elif nvos_service[0] != service_ip:
                    raise ManualZtpError(
                        f"02-dhcp-subnet_config.csv:{line_number} NVOS ZTP 使用 "
                        f"{service_ip}，但第 {nvos_service[1]} 行使用 "
                        f"{nvos_service[0]}；ztp.json 只能有一个 ztp_service_ip"
                    )
            subnet = str(row.get("subnet") or "").strip()
            netmask = str(row.get("netmask") or "").strip()
            try:
                network = ipaddress.IPv4Network(
                    f"{subnet}/{netmask}", strict=False,
                )
            except ValueError as exc:
                raise ManualZtpError(
                    f"02-dhcp-subnet_config.csv 的 subnet/netmask 无效: "
                    f"{subnet!r}/{netmask!r}"
                ) from exc
            if profile == "none":
                continue
            assert service_ip is not None
            filename = f"ztp-bootstrap_{profile}.sh"
            url = f"http://{service_ip}{prefix}/{filename}"
            result.append((network, url))
    if not result:
        raise ManualZtpError(
            "02-dhcp-subnet_config.csv 没有启用 Cumulus ZTP 的 subnet"
        )
    return result


def bootstrap_url(
    device: dict,
    urls: list[tuple[ipaddress.IPv4Network, str]],
) -> str:
    if device["type"] not in ETHERNET_TYPES:
        return ""
    address = ipaddress.ip_address(device["ip"])
    matches = [(network, url) for network, url in urls if address in network]
    selected_address = address
    if not matches:
        # transit_dynamic deliberately keeps the final management address out
        # of the DHCP/ZTP subnet.  In that state the active lease discovered by
        # authoritative MAC is the only valid subnet selector for bootstrap.
        transition_matches = []
        for value in device.get("dynamic_lease_ips") or []:
            try:
                candidate = ipaddress.ip_address(value)
            except ValueError:
                continue
            for network, url in urls:
                if candidate in network:
                    transition_matches.append((candidate, network, url))
        unique = {
            (str(candidate), str(network), url): (candidate, network, url)
            for candidate, network, url in transition_matches
        }
        if len(unique) == 1:
            selected_address, network, url = next(iter(unique.values()))
            matches = [(network, url)]
        elif len(unique) > 1:
            detail = ", ".join(
                f"{candidate}@{network}" for candidate, network, _url in unique.values()
            )
            raise ManualZtpError(
                f"{device['hostname']} 的 DHCP 过渡地址同时匹配多个 provision subnet: "
                f"{detail}"
            )
    if not matches:
        raise ManualZtpError(
            f"{device['hostname']} 的计划 eth0_ip={address} 不属于任何带 provision "
            "URL 的 subnet，且没有唯一的 active DHCP transit lease 可用于选择 bootstrap"
        )
    if len(matches) > 1:
        networks = ", ".join(str(network) for network, _url in matches)
        raise ManualZtpError(
            f"{device['hostname']} 的 eth0_ip={address} 同时匹配多个 DHCP subnet: {networks}"
        )
    device["bootstrap_source_ip"] = str(selected_address)
    device["bootstrap_source_network"] = str(matches[0][0])
    return matches[0][1]


def check_bootstrap_url(url: str, timeout: int) -> None:
    try:
        request = Request(url, headers={"Range": "bytes=0-65535"})
        with urlopen(request, timeout=timeout) as response:
            payload = response.read(65536)
    except Exception as exc:
        raise ManualZtpError(f"bootstrap URL 无法读取: {url}: {exc}") from exc
    if b"CUMULUS-AUTOPROVISIONING" not in payload:
        raise ManualZtpError(f"bootstrap URL 缺少 CUMULUS-AUTOPROVISIONING 标记: {url}")


def restricted_helper(url: str) -> str:
    bootstrap = Path(url.split("?", 1)[0]).name
    helpers = {
        "ztp-bootstrap_oob.sh": "/usr/local/sbin/http-manual-ztp-oob",
        "ztp-bootstrap_oobofoob.sh": "/usr/local/sbin/http-manual-ztp-oobofoob",
    }
    try:
        return helpers[bootstrap]
    except KeyError as exc:
        raise ManualZtpError(f"不支持的 Cumulus bootstrap URL: {url}") from exc


class SshClient:
    def __init__(self, args, known_hosts: Path):
        self.args = args
        self.known_hosts = known_hosts
        self.passwords: dict[str, str] = {}
        self.sudo_passwords: dict[str, str] = {}

    def _prefix(self, user: str, host: str) -> tuple[list[str], dict[str, str]]:
        command = []
        environment = os.environ.copy()
        if self.args.ssh_password:
            if self.args.non_interactive:
                raise ManualZtpError("--ssh-password 不能用于 --non-interactive")
            password = self.passwords.get(user)
            if password is None:
                password = getpass.getpass(f"SSH password for {user}@{host}: ")
                self.passwords[user] = password
            if not shutil_which("sshpass"):
                raise ManualZtpError("密码 SSH 需要先安装 sshpass")
            environment["SSHPASS"] = password
            command += ["sshpass", "-e"]
        host_key_file = self.host_key_file(host)
        command += [
            "ssh", "-o", f"ConnectTimeout={max(self.args.connect_timeout, 1)}",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={host_key_file}",
        ]
        if not self.args.ssh_password:
            command += ["-o", "BatchMode=yes"]
        if self.args.identity:
            command += ["-i", str(self.args.identity)]
        command += [f"{user}@{host}"]
        return command, environment

    def host_key_file(self, host: str) -> Path:
        """Return a per-target trust file, avoiding cross-device races."""
        directory = self.known_hosts.parent / "known_hosts.d"
        directory.mkdir(parents=True, exist_ok=True)
        safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", host)
        path = directory / f"{safe_host}.known_hosts"
        path.touch(exist_ok=True)
        return path

    def reset_host_key(self, host: str) -> None:
        """Forget one rebuilt target; hostname and eth0 MAC are rechecked."""
        self.host_key_file(host).unlink(missing_ok=True)

    def run(self, device: dict, host: str, remote: str, *, timeout: int, stdin: str = ""):
        prefix, environment = self._prefix(device["user"], host)
        return subprocess.run(
            [*prefix, remote], input=stdin, text=True, capture_output=True,
            timeout=timeout, check=False, env=environment,
        )

    def sudo_command(self, device: dict, command: list[str]) -> tuple[str, str]:
        quoted = " ".join(shlex.quote(item) for item in command)
        if self.args.sudo_password:
            if self.args.non_interactive:
                raise ManualZtpError("--sudo-password 不能用于 --non-interactive")
            password = self.sudo_passwords.get(device["hostname"])
            if password is None:
                password = getpass.getpass(f"sudo password for {device['user']}@{device['hostname']}: ")
                self.sudo_passwords[device["hostname"]] = password
            return f"sudo -S -p '' -- {quoted}", password + "\n"
        return f"sudo -n -- {quoted}", ""


def shutil_which(command: str) -> str | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / command
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def connect_and_verify(client: SshClient, device: dict) -> tuple[str, str]:
    failures = []
    for host, interface in device["candidates"]:
        identity_interface, expected_mac = (
            device.get("candidate_identity", {}).get(f"{host}|{interface}")
            or ("eth0", str(device.get("mac_plain") or ""))
        )
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", str(identity_interface)):
            failures.append(f"{interface}:{host}=unsafe identity interface")
            continue
        remote = (
            "printf '%s\\n%s\\n' \"$(hostname)\" "
            f"\"$(cat /sys/class/net/{identity_interface}/address 2>/dev/null)\""
        )
        try:
            result = client.run(device, host, remote, timeout=client.args.connect_timeout + 5)
        except subprocess.TimeoutExpired:
            failures.append(f"{interface}:{host}=timeout")
            continue
        if result.returncode and (
            "REMOTE HOST IDENTIFICATION HAS CHANGED" in result.stderr
            or "Host key verification failed" in result.stderr
        ):
            explicit_refresh = (
                getattr(client.args, "host_key_refresh_authorized", False) is True
            )
            password_auth = getattr(client.args, "ssh_password", False) is True
            air_auto_refresh = (
                device.get("type") == "air" and not password_auth
            )
            if not (explicit_refresh or air_auto_refresh):
                if password_auth:
                    reason = (
                        "host key changed; password SSH never refreshes trust "
                        "without an authorized Production --refresh-host-key"
                    )
                else:
                    reason = (
                        "host key changed; Production defaults to fail-closed "
                        "(use interactive CLI with the exact hostname and "
                        "--refresh-host-key after verifying the rebuild)"
                    )
                failures.append(f"{interface}:{host}={reason}")
                continue
            client.reset_host_key(host)
            try:
                result = client.run(
                    device, host, remote,
                    timeout=client.args.connect_timeout + 5,
                )
            except subprocess.TimeoutExpired:
                failures.append(f"{interface}:{host}=timeout after host-key refresh")
                continue
        if result.returncode:
            failures.append(f"{interface}:{host}={result.stderr.strip() or 'SSH failed'}")
            continue
        lines = result.stdout.splitlines()
        actual_hostname = lines[0].strip() if lines else ""
        actual_mac = normalize_mac(lines[1] if len(lines) > 1 else "")
        transitional = host in set(device.get("dynamic_lease_ips") or [])
        hostname_may_be_unconfigured = (
            bool(device.get("mac_plain"))
            and (bool(device.get("dynamic_dhcp")) or transitional)
        )
        if (actual_hostname.casefold() != device["hostname"].casefold()
                and not hostname_may_be_unconfigured):
            failures.append(f"{interface}:{host}=hostname {actual_hostname!r}")
            continue
        if expected_mac and actual_mac != expected_mac:
            failures.append(
                f"{interface}:{host}={identity_interface} MAC {actual_mac or 'unknown'}"
            )
            continue
        return host, interface
    raise ManualZtpError(f"{device['hostname']} 身份校验失败: " + " | ".join(failures))


def sync_management_time(
    client: SshClient, device: dict, host: str, interface: str,
) -> dict:
    """Run the fixed device helper, then independently re-measure its clock."""
    helper = client.run(
        device, host, f"sudo -n -- {TIME_SYNC_HELPER}",
        timeout=max(client.args.command_timeout, 30),
    )
    if helper.returncode:
        detail = helper.stderr.strip() or helper.stdout.strip() or "helper failed"
        raise ManualZtpError(
            f"{device['hostname']} 时间同步失败: {detail}。"
            "设备必须先通过新版 bootstrap 安装固定无参数 time-sync helper"
        )
    local_started = datetime.now().timestamp()
    measured = client.run(
        device, host,
        "date -u '+%s.%N' 2>/dev/null || date -u '+%s'",
        timeout=max(client.args.connect_timeout + 5, 10),
    )
    local_finished = datetime.now().timestamp()
    if measured.returncode:
        raise ManualZtpError(
            f"{device['hostname']} helper 返回成功，但重新读取交换机时间失败: "
            f"{measured.stderr.strip() or 'empty result'}"
        )
    try:
        remote_epoch = float(measured.stdout.strip().splitlines()[0])
    except (IndexError, ValueError) as exc:
        raise ManualZtpError(
            f"{device['hostname']} helper 返回成功，但交换机时间格式无效"
        ) from exc
    offset = remote_epoch - ((local_started + local_finished) / 2.0)
    uncertainty = max(0.501, (local_finished - local_started) / 2.0 + 0.5)
    worst_case_offset = abs(offset) + uncertainty
    if (
        not all(math.isfinite(value) for value in (
            remote_epoch, local_started, local_finished, offset, uncertainty,
        ))
        or local_finished < local_started
        or worst_case_offset > 5.0
    ):
        raise ManualZtpError(
            f"{device['hostname']} helper 执行后无法证明时间偏移不超过 5 秒："
            f"估计 {offset:+.3f}s、不确定度 ±{uncertainty:.3f}s、"
            f"最坏界限 {worst_case_offset:.3f}s"
        )
    return {
        "schema": 1,
        "state": "success",
        "hostname": device["hostname"],
        "transport_ip": host,
        "interface": interface,
        "offset_seconds": round(offset, 3),
        "uncertainty_seconds": round(uncertainty, 3),
        "helper_output": helper.stdout.strip()[-2000:],
        "measured_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def acquire_operation_lock(output_root: Path, hostname: str) -> int:
    """Hold one device lock across preflight, confirmation and submission."""
    lock_dir = output_root / ".manual-operation-locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        lock_dir / f"{hostname}.lock", os.O_RDWR | os.O_CREAT, 0o644,
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(descriptor)
        raise ManualZtpError(f"{hostname} 已有 CLI 或页面人工 ZTP/重置正在执行") from exc
    return descriptor


def trigger_one(
    client: SshClient, device: dict, url: str, run_dir: Path,
    trigger_source: str = "manual_cli", trigger_id: str = "", operation: str = "ztp",
    direct_privileged: bool = False, operation_id: str = "",
    prepared: dict | None = None, requested_operation: str = "",
) -> dict:
    started = datetime.now().astimezone().isoformat(timespec="seconds")
    command_started_at = ""
    target_dir = run_dir / device["hostname"]
    target_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(target_dir, 0o700)
    lock_descriptor = None
    try:
        if not prepared:
            lock_descriptor = acquire_operation_lock(
                run_dir.parent.parent, device["hostname"],
            )
        host, interface = connect_and_verify(client, device)
        backup = client.run(device, host, "nv config show", timeout=client.args.command_timeout)
        if backup.returncode or not backup.stdout.strip():
            raise ManualZtpError(
                f"配置备份失败: {backup.stderr.strip() or 'empty nv config show'}"
            )
        if prepared:
            marker = Path(str(prepared.get("published_marker") or ""))
            expected_path = Path(str(prepared.get("expected_yaml") or ""))
            verify_prepared_release_binding(prepared)
            try:
                current_release = marker.parent.resolve(strict=True)
            except OSError as exc:
                raise ManualZtpError(f"确认后 latest 发布入口失效: {exc}") from exc
            if (
                not marker.is_file()
                or str(current_release) != str(prepared.get("published_release_dir") or "")
            ):
                raise ManualZtpError(
                    "用户确认后 latest 发布代际已切换；已拒绝执行，请重新预检"
                )
            try:
                _value, _rendered, expected_digest = normalized_yaml(
                    expected_path.read_text(encoding="utf-8"),
                    label=f"{device['hostname']} 确认后 latest 配置",
                )
            except OSError as exc:
                raise ManualZtpError(f"确认后无法读取 latest 配置: {exc}") from exc
            if expected_digest != prepared.get("expected_yaml_sha256"):
                raise ManualZtpError(
                    "用户确认后 latest 专属 YAML 已变化；已拒绝执行，请重新预检"
                )
            for mac_link_value in prepared.get("published_mac_links") or []:
                mac_link = Path(str(mac_link_value))
                try:
                    linked = mac_link.is_symlink() and (
                        mac_link.resolve(strict=True) == expected_path.resolve(strict=True)
                    )
                except OSError:
                    linked = False
                if not linked:
                    raise ManualZtpError(
                        f"用户确认后 MAC 链接 {mac_link.name} 已变化；"
                        "已拒绝执行，请重新预检"
                    )
            try:
                release_stable = marker.parent.resolve(strict=True) == current_release
            except OSError:
                release_stable = False
            if not release_stable:
                raise ManualZtpError(
                    "用户确认后 latest 发布代际在复核期间切换；"
                    "已拒绝执行，请重新预检"
                )
            current_digest = _raw_text_sha256(backup.stdout)
            if current_digest != prepared.get("current_sha256"):
                _secure_text(target_dir / "before-confirm.yaml", backup.stdout)
                raise ManualZtpError(
                    "用户确认后设备配置发生变化；已拒绝执行，请重新预检"
                )
            applied_now = collect_applied_config(client, device, host)
            if applied_now.get("fingerprint") != prepared.get("applied_fingerprint"):
                raise ManualZtpError(
                    "用户确认后设备的已应用 ZTP 输入凭据发生变化；"
                    "已拒绝执行，请重新预检"
                )
        else:
            _secure_text(target_dir / "before.yaml", backup.stdout)
        if operation == "reset":
            if device["type"] not in ETHERNET_TYPES:
                raise ManualZtpError("手工重置仅支持 Cumulus Ethernet/AIR 交换机")
            # Keep the GUI/CLI boundary fixed: no caller-controlled reset
            # command or URL is sent to the switch.  The two-second delay lets
            # SSH return success before NVUE deletes configuration/logs and
            # reboots.  The fixed `force` action is non-interactive.
            remote = (
                "command -v nv >/dev/null 2>&1 || "
                "{ echo 'nv command not found' >&2; exit 127; }; "
                "nohup sh -c 'sleep 2; "
                "nv action reset system factory-default force' "
                "</dev/null >/home/cumulus/http-manual-reset.log 2>&1 & "
                "reset_pid=$!; sleep 1; "
                "kill -0 \"$reset_pid\" 2>/dev/null || "
                "{ echo 'failed to start NVUE factory-default reset' >&2; exit 1; }; "
                "echo \"scheduled NVUE factory-default reset pid=$reset_pid\""
            )
            stdin = ""
            action = "nv action reset system factory-default force (background)"
        elif device["type"] in ETHERNET_TYPES:
            if not direct_privileged:
                remote, stdin = client.sudo_command(
                    device, [restricted_helper(url)],
                )
                action = Path(restricted_helper(url)).name
            else:
                remote, stdin = client.sudo_command(device, ["ztp", "-r", url])
                action = f"ztp -r {url}"
        else:
            remote, stdin = "nv action run system ztp force", ""
            action = remote
        command_started_at = datetime.now().astimezone().isoformat(timespec="seconds")
        result = client.run(
            device, host, remote, timeout=client.args.command_timeout, stdin=stdin,
        )
        _secure_text(
            target_dir / "trigger.log",
            f"command: {action}\nreturncode: {result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}\n",
        )
        if result.returncode:
            raise ManualZtpError(
                f"触发命令失败 exit={result.returncode}: "
                f"{result.stderr.strip() or result.stdout.strip() or 'no detail'}"
            )
        command_log_sha256, command_log_complete = ztp_command_log_evidence(
            result.stdout
        )
        payload = {
            "hostname": device["hostname"], "type": device["type"],
            "state": "triggered", "transport_ip": host, "interface": interface,
            "action": action, "started_at": started,
            "command_started_at": command_started_at,
            "operation": operation,
            "effective_operation": operation,
            "requested_operation": requested_operation or operation,
            "operation_id": operation_id,
            "trigger_source": trigger_source, "trigger_id": trigger_id,
            "command_ztp_log_sha256": command_log_sha256,
            "command_ztp_complete": command_log_complete,
            "finished_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        }
    except (ManualZtpError, subprocess.TimeoutExpired) as exc:
        payload = {
            "hostname": device["hostname"], "type": device["type"],
            "state": "failed", "reason": str(exc), "started_at": started,
            "command_started_at": command_started_at,
            "operation": operation,
            "effective_operation": operation,
            "requested_operation": requested_operation or operation,
            "operation_id": operation_id,
            "trigger_source": trigger_source, "trigger_id": trigger_id,
            "finished_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        }
    finally:
        if lock_descriptor is not None:
            try:
                fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            finally:
                os.close(lock_descriptor)
    atomic_json(target_dir / "result.json", payload)
    return payload


def parser(operation: str = "ztp") -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="手工触发交换机 ZTP 或 NVUE factory-default 重置；位置参数支持具体 hostname 和通配符",
    )
    result.add_argument("selectors", nargs="+", metavar="DEVICE_OR_PATTERN")
    result.add_argument(
        "--operation", choices=("ztp", "reset", "renew", "time-sync"),
        default="ztp",
        help=(
            "操作类型：ztp 重新执行配置；reset 执行平台安全恢复；"
            "renew 重新进入 DHCP/ZTP；time-sync 仅调用固定时间同步 helper"
        ),
    )
    result.set_defaults(url=None)
    if operation != "reset":
        result.add_argument(
            "--url", help="显式覆盖 ZTP bootstrap URL；使用直接特权命令并询问 sudo 密码",
        )
    result.add_argument("-p", "--project", help="项目目录或 DAY0-Prepare 下的项目名；默认当前活动项目")
    result.add_argument(
        "--dhcp-leases", type=Path,
        default=Path("/var/lib/dhcp/dhcpd.leases"),
        help="ISC DHCP lease 文件（用于解析 AIR-only 动态地址）",
    )
    environment = result.add_mutually_exclusive_group()
    environment.add_argument(
        "--type", default="all",
        choices=("all", "prod", "air", "ethernet", "eth", "eth_spx", "spx", "ib", "nvl"),
        help="只从指定环境/设备类型中展开位置参数（默认 all）",
    )
    environment.add_argument("--air", action="store_const", const="air", dest="type")
    environment.add_argument("--prod", action="store_const", const="prod", dest="type")
    result.add_argument("-y", "--yes", action="store_true", help="跳过执行前确认")
    result.add_argument("--dry-run", action="store_true", help="只展开并打印目标，不连接设备")
    result.add_argument("--non-interactive", action="store_true", help=argparse.SUPPRESS)
    result.add_argument("--preflight-only", action="store_true", help=argparse.SUPPRESS)
    result.add_argument(
        "--origin", choices=("cli", "web"), default="cli", help=argparse.SUPPRESS,
    )
    result.add_argument("--operation-id", default="", help=argparse.SUPPRESS)
    result.add_argument("--trigger-id", default="", help=argparse.SUPPRESS)
    result.add_argument("--confirmed-current-sha256", default="", help=argparse.SUPPRESS)
    result.add_argument("--confirmed-expected-sha256", default="", help=argparse.SUPPRESS)
    result.add_argument("--confirmed-release-dir", default="", help=argparse.SUPPRESS)
    result.add_argument("--confirmed-effective-operation", default="", help=argparse.SUPPRESS)
    result.add_argument("--confirmed-transport-ip", default="", help=argparse.SUPPRESS)
    result.add_argument("--confirmed-interface", default="", help=argparse.SUPPRESS)
    result.add_argument("--confirmed-bootstrap-url", default="", help=argparse.SUPPRESS)
    result.add_argument("--confirmed-bootstrap-source-ip", default="", help=argparse.SUPPRESS)
    result.add_argument("--confirmed-bootstrap-source-network", default="", help=argparse.SUPPRESS)
    result.add_argument("--identity", type=Path, help="SSH 私钥")
    result.add_argument("--ssh-password", action="store_true", help="交互输入 SSH 密码（需要 sshpass）")
    result.add_argument(
        "--refresh-host-key", action="store_true",
        help=(
            "高风险显式授权：仅交互 CLI 使用完整 hostname 精确选择一台 "
            "Production 设备时，允许在确认设备确已 rebuild 后替换该地址的 SSH host key；"
            "随后仍强制校验 hostname 和身份 MAC"
        ),
    )
    if operation != "reset":
        sudo_auth = result.add_mutually_exclusive_group()
        sudo_auth.add_argument(
            "--sudo-password", dest="sudo_password", action="store_true",
            help="兼容参数；仅显式 URL 有效，且显式 URL 已默认启用",
        )
        sudo_auth.add_argument(
            "--no-sudo-password", dest="sudo_password", action="store_false",
            help="兼容参数；无 URL 本就不询问，显式 URL 禁止使用",
        )
        result.set_defaults(sudo_password=None)
    else:
        result.set_defaults(sudo_password=False)
    result.add_argument("--connect-timeout", type=int, default=10)
    result.add_argument("--command-timeout", type=int, default=900)
    if operation != "reset":
        result.add_argument("--http-timeout", type=int, default=10)
    else:
        result.set_defaults(http_timeout=10)
    return result


def apply_sudo_policy(args: argparse.Namespace) -> None:
    """Select the least-privileged sudo path from caller-controlled inputs."""
    explicit_url = bool(args.url)
    if not explicit_url:
        # The rendered, zero-argument helper has an exact NOPASSWD sudoers
        # entry.  Never ask for a broad sudo credential on this safe path,
        # even if an obsolete caller still passes --sudo-password.
        args.sudo_password = False
        return
    if args.sudo_password is None:
        args.sudo_password = not args.non_interactive
    if explicit_url and args.sudo_password is False:
        raise ManualZtpError("显式 URL 必须使用 sudo 密码，不能使用 --no-sudo-password")


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    operation_hint = "ztp"
    for index, value in enumerate(raw_argv[:-1]):
        if value == "--operation" and raw_argv[index + 1] in {"ztp", "reset", "renew", "time-sync"}:
            operation_hint = raw_argv[index + 1]
    args = parser(operation_hint).parse_args(raw_argv)
    # A no-URL CLI call and the GUI both use a root-owned, zero-argument
    # restricted helper.  Caller-controlled URLs deliberately require the
    # broader direct sudo path and therefore an interactive sudo password.
    operation_lock_descriptor = None
    deployment_lock_descriptor = None
    try:
        apply_sudo_policy(args)
        for label, value in (
            ("operation_id", args.operation_id), ("trigger_id", args.trigger_id),
        ):
            if value and not SAFE_OPERATION_ID.fullmatch(value):
                raise ManualZtpError(f"{label} 含不安全字符")
        if args.trigger_id and not args.operation_id:
            raise ManualZtpError("--trigger-id 必须与 --operation-id 同时使用")
        if args.preflight_only and args.dry_run:
            raise ManualZtpError("--preflight-only 与 --dry-run 不能同时使用")
        project = resolve_project(args.project)
        if not args.dry_run:
            deployment_lock_descriptor = acquire_deployment_lock()
        devices = select_devices(
            read_devices(
                project / "02-devices_config.csv", dhcp_leases=args.dhcp_leases,
            ),
            args.selectors,
            args.type,
        )
        if args.url and any(item["type"] not in ETHERNET_TYPES for item in devices):
            raise ManualZtpError("--url 仅适用于 Cumulus Ethernet/AIR 交换机")
        if len(devices) > 1 and not args.dry_run:
            devices = choose_one_device(devices, non_interactive=args.non_interactive)
        validate_host_key_refresh_policy(args, devices)
        if args.refresh_host_key:
            print(
                "[RISK] 已显式授权 Production host-key 刷新：仅在检测到 mismatch 时删除"
                "所选设备目标地址的旧记录；重连后仍必须通过 hostname 和身份 MAC 校验"
            )
        unresolved = [
            device for device in devices
            if device.get("dynamic_dhcp") and not device.get("ip")
        ]
        if unresolved:
            details = []
            for device in unresolved:
                reason = str(device.get("runtime_issue") or "").strip()
                details.append(
                    f"{device['hostname']} ({device.get('mac') or 'MAC unknown'}): "
                    + (reason or f"未从 {args.dhcp_leases} 解析到 active lease")
                )
            raise ManualZtpError(
                "以下 AIR-only 动态设备尚无可用 SSH 地址：" + "；".join(details)
            )
        unsafe_identity = [
            device["hostname"] for device in devices
            if not device.get("mac_plain")
        ]
        if unsafe_identity:
            raise ManualZtpError(
                "以下设备缺少 eth0 MAC，无法严格校验 SSH 身份："
                + ", ".join(unsafe_identity)
                + "。请先更新 02-devices_config.csv 并完整执行 11-load.py"
            )
        lease_conflicts = [
            f"{device['hostname']}: {device['lease_transition_issue']}"
            for device in devices if device.get("lease_transition_issue")
        ]
        if lease_conflicts:
            raise ManualZtpError(
                "旧动态 lease 与静态清单冲突，拒绝作为 SSH transport："
                + "；".join(lease_conflicts)
            )
        if args.operation == "time-sync":
            if args.url:
                raise ManualZtpError("时间同步不允许指定 URL 或时间值")
            print(f"项目：{project}")
            print(f"匹配设备：{len(devices)} 台")
            for device in devices:
                print(
                    f"  - {device['hostname']} type={device['type']} ip={device['ip']} "
                    f"action={Path(TIME_SYNC_HELPER).name} (固定无参数 helper)"
                )
            if args.dry_run:
                print("[DRY-RUN] 未连接设备、未改变交换机时间")
                return 0
            if args.non_interactive and not args.yes:
                raise ManualZtpError("--non-interactive 必须同时使用 --yes")
            if len(devices) != 1:
                devices = choose_one_device(
                    devices, non_interactive=args.non_interactive,
                )
            device = devices[0]
            operation_lock_descriptor = acquire_operation_lock(
                project / "99-output-ztp", device["hostname"],
            )
            evidence_root = project / "99-output-ztp" / "manual-time-sync"
            evidence_root.mkdir(parents=True, exist_ok=True)
            known_hosts = evidence_root / "known_hosts"
            known_hosts.touch(exist_ok=True)
            client = SshClient(args, known_hosts)
            host, interface = connect_and_verify(client, device)
            result = sync_management_time(client, device, host, interface)
            stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S_%f")
            result_dir = evidence_root / stamp / device["hostname"]
            result_dir.mkdir(parents=True, exist_ok=False)
            os.chmod(result_dir.parent, 0o700)
            os.chmod(result_dir, 0o700)
            result["operation_id"] = args.operation_id
            result["trigger_id"] = args.trigger_id
            result_path = result_dir / "result.json"
            atomic_json(result_path, result)
            os.chmod(result_path, 0o600)
            print("[TIME_SYNC_RESULT] " + json.dumps(result, ensure_ascii=False))
            return 0
        unready = []
        for device in devices:
            ready, reason = dedicated_yaml_ready(
                project, device, require_completion=True,
            )
            if not ready:
                unready.append(f"{device['hostname']}: {reason}")
        if unready:
            raise ManualZtpError(
                "专属 YAML 当前发布门禁未通过，拒绝触发："
                + "；".join(unready)
                + "。请先修复生成问题并完整执行 11-load.py"
            )
        if args.non_interactive and args.url:
            raise ManualZtpError("非交互/GUI 模式不允许调用者指定 URL")
        effective_by_name = {
            device["hostname"]: (
                "ztp" if args.url else effective_operation(args.operation, device)
            )
            for device in devices
        }
        needs_cumulus_url = any(
            effective_by_name[device["hostname"]] == "ztp"
            and device["type"] in ETHERNET_TYPES
            for device in devices
        )
        urls = (
            provision_urls(
                project / "02-dhcp-subnet_config.csv",
                project / "01-global.yaml",
            )
            if needs_cumulus_url and not args.url else []
        )
        plans = []
        for device in devices:
            actual = effective_by_name[device["hostname"]]
            url = (
                args.url or bootstrap_url(device, urls)
                if actual == "ztp" and device["type"] in ETHERNET_TYPES
                else ""
            )
            plans.append((device, url, actual))
        print(f"项目：{project}")
        print(f"匹配设备：{len(plans)} 台")
        for device, url, actual in plans:
            if actual == "reset":
                action = "nv action reset system factory-default force (后台)"
            else:
                action = (
                    f"ztp -r {url}" if args.url
                    else Path(restricted_helper(url)).name if url
                    else "nv action run system ztp force"
                )
            print(
                f"  - {device['hostname']}  type={device['type']}  ip={device['ip']}  "
                f"requested={args.operation}  effective={actual}  action={action}"
            )
        if args.dry_run:
            if len(plans) > 1:
                print("[DRY-RUN] 实际执行时将要求从以上匹配结果中明确选择一台设备")
            print("[DRY-RUN] 未连接设备、未执行 SSH 预检或远程操作")
            return 0
        if args.non_interactive and not args.yes:
            raise ManualZtpError("--non-interactive 必须同时使用 --yes")
        operation_lock_descriptor = acquire_operation_lock(
            project / "99-output-ztp", plans[0][0]["hostname"],
        )
        for device, url, _actual in plans:
            if url:
                check_bootstrap_url(url, max(args.http_timeout, 1))
        # GUI requests run concurrently; microseconds prevent two devices
        # accepted in the same second from sharing/overwriting one run dir.
        stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S_%f")
        actual_operations = {actual for _device, _url, actual in plans}
        if len(actual_operations) != 1:
            raise ManualZtpError("一次操作不能混合 factory reset 和 ZTP")
        actual_operation = next(iter(actual_operations))
        operation_dir = "manual-reset" if actual_operation == "reset" else "manual-trigger"
        run_dir = project / "99-output-ztp" / operation_dir / stamp
        known_hosts = project / "99-output-ztp" / operation_dir / "known_hosts"
        known_hosts.parent.mkdir(parents=True, exist_ok=True)
        known_hosts.touch(exist_ok=True)
        client = SshClient(args, known_hosts)
        requested_at = datetime.now().astimezone().isoformat(timespec="seconds")
        operation_id = args.operation_id or (
            f"{args.origin}:{project.name}:{stamp}:{uuid.uuid4().hex}"
        )
        trigger_source = (
            f"manual_reset_{args.origin}" if actual_operation == "reset"
            else f"manual_{args.origin}"
        )
        trigger_ids = {
            device["hostname"]: (
                args.trigger_id
                or f"{operation_id}:{device['hostname']}"
            )
            for device, _url, _actual in plans
        }
        summary = {
            "project": project.name, "selectors": args.selectors,
            "requested_type": args.type, "trigger_source": trigger_source,
            "requested_operation": args.operation,
            "operation": actual_operation,
            "effective_operation": actual_operation,
            "operation_id": operation_id,
            "state": "preflight", "requested_at": requested_at,
            "generated_at": requested_at,
            "targets": [
                {
                    "hostname": device["hostname"], "type": device["type"],
                    "trigger_id": trigger_ids[device["hostname"]],
                    "effective_operation": actual,
                }
                for device, _url, actual in plans
            ],
            "preflight": [],
            "results": [],
        }
        atomic_json(run_dir / "summary.json", summary)
        prepared = {}
        try:
            for device, _url, _actual in plans:
                evidence = preflight_one(
                    client, project, device, run_dir / device["hostname"],
                )
                evidence["bootstrap_url"] = _url
                evidence["bootstrap_source_ip"] = str(
                    device.get("bootstrap_source_ip") or ""
                )
                evidence["bootstrap_source_network"] = str(
                    device.get("bootstrap_source_network") or ""
                )
                evidence["operation_id"] = operation_id
                evidence["trigger_id"] = trigger_ids[device["hostname"]]
                atomic_json(run_dir / device["hostname"] / "preflight.json", evidence)
                prepared[device["hostname"]] = evidence
                summary["preflight"].append(evidence)
                summary["generated_at"] = datetime.now().astimezone().isoformat(
                    timespec="seconds"
                )
                atomic_json(run_dir / "summary.json", summary)
                display_preflight_diff(run_dir / device["hostname"])
        except (ManualZtpError, OSError, subprocess.TimeoutExpired) as exc:
            summary["state"] = "failed"
            summary["reason"] = str(exc)
            summary["generated_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
            atomic_json(run_dir / "summary.json", summary)
            raise
        if args.preflight_only:
            summary["state"] = "preview_ready"
            summary["generated_at"] = datetime.now().astimezone().isoformat(
                timespec="seconds"
            )
            atomic_json(run_dir / "summary.json", summary)
            print(
                f"[PREVIEW_READY] operation_id={operation_id} "
                f"trigger_id={trigger_ids[plans[0][0]['hostname']]} "
                f"证据={run_dir}"
            )
            return 0
        confirmed_values = (
            args.confirmed_current_sha256,
            args.confirmed_expected_sha256,
            args.confirmed_release_dir,
        )
        if any(confirmed_values):
            if (
                not all(confirmed_values) or len(plans) != 1
                or args.confirmed_effective_operation not in {"ztp", "reset"}
                or not args.confirmed_transport_ip
                or not args.confirmed_interface
            ):
                raise ManualZtpError("确认预览指纹不完整")
            evidence = prepared[plans[0][0]["hostname"]]
            material_matches = (
                str(evidence.get("current_sha256") or "")
                == args.confirmed_current_sha256
                and str(evidence.get("expected_sha256") or "")
                == args.confirmed_expected_sha256
                and str(evidence.get("published_release_dir") or "")
                == args.confirmed_release_dir
                and actual_operation == args.confirmed_effective_operation
                and str(evidence.get("transport_ip") or "")
                == args.confirmed_transport_ip
                and str(evidence.get("interface") or "")
                == args.confirmed_interface
                and str(evidence.get("bootstrap_url") or "")
                == args.confirmed_bootstrap_url
                and str(evidence.get("bootstrap_source_ip") or "")
                == args.confirmed_bootstrap_source_ip
                and str(evidence.get("bootstrap_source_network") or "")
                == args.confirmed_bootstrap_source_network
            )
            if not material_matches:
                summary["state"] = "failed"
                summary["reason"] = (
                    "实际执行预检与用户确认的 preview 指纹不一致"
                )
                summary["generated_at"] = datetime.now().astimezone().isoformat(
                    timespec="seconds"
                )
                atomic_json(run_dir / "summary.json", summary)
                raise ManualZtpError(
                    "当前配置、已应用 ZTP 输入凭据或 latest 发布已在预览后变化；"
                    "拒绝执行，请重新预检并确认"
                )
        if not args.yes:
            impact = (
                "系统配置和日志将被清除，交换机随后重启。"
                if actual_operation == "reset"
                else "将按 latest 专属 YAML 重新执行 ZTP；版本不符时可能升级或重启。"
            )
            answer = input(
                f"\n已保存当前运行配置与 latest 的差异，以及 applied receipt 审计指纹。即将"
                f"{'执行 factory-default 重置' if actual_operation == 'reset' else '触发 ZTP'}"
                f"以上 {len(plans)} 台交换机；{impact}继续？[y/N] "
            ).strip().casefold()
            if answer not in {"y", "yes"}:
                summary["state"] = "cancelled"
                summary["generated_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
                atomic_json(run_dir / "summary.json", summary)
                print(f"[CANCEL] 用户取消，未执行远程变更；预检证据：{run_dir}")
                return 130
        summary["state"] = "running"
        summary["confirmed_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
        atomic_json(run_dir / "summary.json", summary)
        results = []
        for device, url, actual in plans:
            trigger_id = trigger_ids[device["hostname"]]
            results.append(trigger_one(
                client, device, url, run_dir, trigger_source, trigger_id,
                actual, bool(args.url), operation_id,
                prepared[device["hostname"]], args.operation,
            ))
            summary["results"] = results
            summary["generated_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
            atomic_json(run_dir / "summary.json", summary)
        summary["state"] = (
            "triggered" if all(item["state"] == "triggered" for item in results)
            else "failed"
        )
        summary["generated_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
        atomic_json(run_dir / "summary.json", summary)
        for item in results:
            label = "OK" if item["state"] == "triggered" else "FAIL"
            detail = item.get("reason") or item.get("action") or ""
            print(f"[{label}] {item['hostname']}: {detail}")
        print(f"日志：{run_dir}")
        return 0 if all(item["state"] == "triggered" for item in results) else 1
    except (ManualZtpError, OSError, csv.Error) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[CANCEL] 用户取消或中断")
        return 130
    finally:
        if operation_lock_descriptor is not None:
            try:
                fcntl.flock(operation_lock_descriptor, fcntl.LOCK_UN)
            finally:
                os.close(operation_lock_descriptor)
        release_deployment_lock(deployment_lock_descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
