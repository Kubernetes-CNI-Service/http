#!/usr/bin/env python3
"""Correlate DHCP, Apache and switch-side logs into a per-device ZTP report."""

from __future__ import annotations

import argparse
import copy
import concurrent.futures
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Optional
from zoneinfo import ZoneInfo


HERE = Path(__file__).resolve().parent
HTTP_ROOT = HERE.parent
if str(HTTP_ROOT) not in sys.path:
    sys.path.insert(0, str(HTTP_ROOT))

from ztp.dynamic_air_inventory import (
    dynamic_air_devices,
    static_air_lease_fallbacks,
)
from ztp.dhcp_runtime_inventory import unknown_dhcp_devices
from monitor.switch_collection_gate import (
    CollectionGate,
    CollectionGateError,
    DEFAULT_STATUS_DIR as SWITCH_COLLECTION_STATUS_DIR,
)


ZTP_STATUS_DIR = HTTP_ROOT / "ztp" / "status"
ZTP_CONTROL_FILE = ZTP_STATUS_DIR / "ztp-monitor.control"
DEFAULT_HTML_SCRIPT = HERE.parent / "monitor" / "generate-monitor-html.py"
DEFAULT_APACHE_LOG = Path("/var/log/apache2/access.log")
ACTIVE_AIR_JSON = HTTP_ROOT / "ztp/config/isc-dhcp-server/p2p-air.json"
COLLECTOR_SCRIPTS = {
    "ethernet": HERE.parent / "ethernet" / "monitor" / "cron.sh",
    "infiniband": HERE.parent / "infiniband" / "monitor" / "cron.sh",
    "nvlink": HERE.parent / "nvlink" / "monitor" / "cron.sh",
}
STAGE_NAMES = (
    "dhcp",
    "bootstrap",
    "config_http",
    "ssh",
    "network",
    "version",
    "config_apply",
    "ssh_keys",
    "complete",
)
STATUS_TEXT = {
    "pending": "等待",
    "running": "进行中",
    "success": "成功",
    "warning": "警告",
    "failed": "失败",
    "unknown": "未知",
    "not_applicable": "不适用",
    "skipped": "跳过",
}

_KNOWN_HOSTS_LOCK = threading.Lock()
SNAPSHOT_RETENTION = 3
HANDOFF_STATE_SCHEMA = 2
HANDOFF_STATE_NAME = ".ztp-completion-handoff.json"
HANDOFF_RETRY_MIN_SECONDS = 120
COMPLETION_HANDOFF_GROUP_TYPES = {
    "air-ethernet": frozenset({"air", "pending_air"}),
    "prod-ethernet": frozenset({"eth", "eth_spx", "spx", "pending_eth"}),
    "prod-infiniband": frozenset({"ib", "pending_ib"}),
    "prod-nvlink": frozenset({"nvl", "pending_nvl"}),
}
COMPLETION_HANDOFF_KEYS = tuple(COMPLETION_HANDOFF_GROUP_TYPES)
_SNAPSHOT_NAME_RE = re.compile(r"^\d{8}_\d{6}(?:_\d+)?$")
_ZTP_LOG_LINE_RE = re.compile(
    r"^\[\d{4}-\d{2}-\d{2}(?:T|\s)[^\]\r\n]+\]\s.*$"
)


def now_local() -> dt.datetime:
    return dt.datetime.now().astimezone()


def ztp_log_evidence(text: str) -> tuple[str, bool]:
    """Return a clock-independent digest and completion flag for ZTP log lines."""
    lines = [
        line.rstrip("\r")
        for line in str(text or "").splitlines()
        if _ZTP_LOG_LINE_RE.fullmatch(line.rstrip("\r"))
    ]
    if not lines:
        return "", False
    rendered = "\n".join(lines) + "\n"
    complete = bool(
        any("provision complete" in line for line in lines)
        and any("ZTP FINISH" in line for line in lines)
    )
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest(), complete


def project_timezone(project: Path) -> dt.tzinfo:
    """Return the switch timezone declared by the active project's global YAML."""
    path = project / "01-global.yaml"
    try:
        match = re.search(
            r"(?m)^\s*timezone\s*:\s*['\"]?([^\s#'\"]+)",
            path.read_text(encoding="utf-8"),
        )
        if match:
            return ZoneInfo(match.group(1))
    except (OSError, UnicodeError, ValueError, KeyError):
        pass
    return dt.timezone.utc


def log(message: str = "", *, file=None) -> None:
    """Write timestamped monitor output suitable for foreground and file logs."""
    stream = file or sys.stdout
    stamp = now_local().isoformat(timespec="seconds")
    lines = str(message).splitlines() or [""]
    for line in lines:
        print(f"[{stamp}] {line}", file=stream, flush=True)


def normalize_mac(value: str) -> str:
    return re.sub(r"[^0-9a-f]", "", (value or "").lower())


def stage(
    status: str = "pending", detail: str = "", timestamp: str = "",
    success_index: int = 0,
) -> dict[str, Any]:
    return {
        "status": status, "detail": detail, "timestamp": timestamp,
        "success_index": max(0, int(success_index or 0)),
    }


def read_devices(
    csv_path: Path,
    scope: str = "all",
    *,
    air_json: Optional[Path] = None,
    dhcp_leases: Optional[Path] = Path("/var/lib/dhcp/dhcpd.leases"),
) -> list[dict[str, Any]]:
    # csv.DictReader cannot preserve repeated column names.  This inventory has
    # repeated SVI/EVPN field groups, so retain the positional row as well as the
    # conventional last-value mapping.
    merged_rows: dict[str, tuple[dict[str, str], list[str], list[str]]] = {}
    with csv_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        headers = next(reader, [])
        for values in reader:
            padded = values + [""] * max(0, len(headers) - len(values))
            row = dict(zip(headers, padded))
            key = (row.get("hostname") or "").strip().casefold()
            if key:
                merged_rows[key] = (row, headers, padded)

    devices: list[dict[str, Any]] = []
    for row, headers, values in merged_rows.values():
        hostname = (row.get("hostname") or "").strip()
        device_type = (row.get("type") or "").strip().lower()
        ip = (row.get("eth0_ip") or "").strip()
        eth1_ip = (row.get("eth1_ip") or "").strip()
        mac_display = (row.get("eth0_mac") or "").strip().lower()
        eth1_mac_display = (row.get("eth1_mac") or "").strip().lower()
        eth0_mac_plain = normalize_mac(mac_display)
        eth1_mac_plain = normalize_mac(eth1_mac_display)
        identity_macs = ({"eth0": eth0_mac_plain} if eth0_mac_plain else {})
        if device_type in {"ib", "nvl"} and eth1_mac_plain:
            identity_macs["eth1"] = eth1_mac_plain
        if not hostname or device_type == "server":
            continue
        alternate_ssh_ips: list[str] = []
        alternate_ssh_interfaces: dict[str, str] = {}
        template = (row.get("template") or "").strip()
        eth0_index = headers.index("eth0_ip") if "eth0_ip" in headers else -1
        eth0_prefix = (
            values[eth0_index + 1].strip()
            if eth0_index >= 0 and eth0_index + 1 < len(headers)
            and headers[eth0_index + 1] == "netmask" else ""
        )
        try:
            eth0_network = ipaddress.ip_interface(f"{ip}/{eth0_prefix}").network
        except ValueError:
            eth0_network = None
        if eth0_network is not None:
            for svi_index, name in enumerate(headers):
                if name != "svi_ip":
                    continue
                svi_ip = values[svi_index].strip() if svi_index < len(values) else ""
                svi_prefix = (
                    values[svi_index + 1].strip()
                    if svi_index + 1 < len(headers) and headers[svi_index + 1] == "netmask"
                    else ""
                )
                if not svi_ip or svi_ip.casefold() in {"na", "none"}:
                    continue
                try:
                    svi_address = ipaddress.ip_interface(f"{svi_ip}/{svi_prefix}").ip
                except ValueError:
                    continue
                if svi_address in eth0_network and str(svi_address) != ip:
                    address_text = str(svi_address)
                    alternate_ssh_ips.append(address_text)
                    vlan_value = ""
                    if svi_index > 0 and headers[svi_index - 1] in {
                        "vlan_id", "evpn_l2vlan", "evpn_l3vlan",
                    }:
                        vlan_value = values[svi_index - 1].strip()
                    alternate_ssh_interfaces[address_text] = (
                        f"vlan{vlan_value}" if vlan_value else "SVI"
                    )
        ssh_user = "admin" if device_type in {"ib", "nvl"} else "cumulus"
        ssh_ips = list(dict.fromkeys(filter(None, [ip, eth1_ip, *alternate_ssh_ips])))
        ssh_interfaces = {
            **({ip: "eth0"} if ip else {}),
            **({eth1_ip: "eth1"} if eth1_ip else {}),
            **alternate_ssh_interfaces,
        }
        candidate_identity = {}
        if ip and eth0_mac_plain:
            candidate_identity[ip] = ("eth0", eth0_mac_plain)
        if eth1_ip and eth1_mac_plain:
            candidate_identity[eth1_ip] = ("eth1", eth1_mac_plain)
        for address in alternate_ssh_ips:
            if eth0_mac_plain:
                candidate_identity[address] = ("eth0", eth0_mac_plain)
        devices.append({
            "hostname": hostname,
            "type": device_type,
            "template": template,
            "ip": ip,
            "ssh_ips": ssh_ips,
            "ssh_interfaces": ssh_interfaces,
            "mac": mac_display,
            "mac_plain": eth0_mac_plain,
            "eth1_mac": eth1_mac_display,
            "identity_macs": identity_macs,
            "candidate_identity": candidate_identity,
            "ssh_user": ssh_user,
            "time_sync": {"status": "unknown", "detail": "尚未完成 SSH 身份校验"},
            "stages": {name: stage() for name in STAGE_NAMES},
            "issues": [],
            "events": [],
        })

    # AIR rows intentionally contain identity data only; their generated config
    # is paired with Production.  Inherit same-subnet SVI candidates from the
    # Production row sharing the same eth0 address.
    prod_ssh_ips = {
        device["ip"]: device["ssh_ips"]
        for device in devices
        if device["type"] != "air" and len(device["ssh_ips"]) > 1
    }
    prod_ssh_interfaces = {
        device["ip"]: device["ssh_interfaces"]
        for device in devices
        if device["type"] != "air" and len(device["ssh_ips"]) > 1
    }
    for device in devices:
        if device["type"] == "air" and len(device["ssh_ips"]) == 1:
            device["ssh_ips"] = list(prod_ssh_ips.get(device["ip"], device["ssh_ips"]))
            device["ssh_interfaces"] = dict(
                prod_ssh_interfaces.get(device["ip"], device["ssh_interfaces"])
            )
            if device.get("mac_plain"):
                device["candidate_identity"] = {
                    address: ("eth0", device["mac_plain"])
                    for address in device["ssh_ips"] if address
                }

    # A topology node can be promoted from an AIR-only dynamic client to a
    # canonical static inventory row while the running switch still owns its
    # previous dynamic lease.  Keep that address as a temporary transport
    # alias only.  The canonical hostname/template/IP continue to come from
    # the static row, and identity verification still uses the AIR MAC.
    static_by_name = {
        str(device.get("hostname") or "").casefold(): device
        for device in devices if device.get("type") == "air"
    }
    static_by_mac = {
        str(device.get("mac_plain") or ""): device
        for device in devices
        if device.get("type") == "air" and device.get("mac_plain")
    }
    for transition in static_air_lease_fallbacks(
        csv_path, air_json=air_json, leases=dhcp_leases,
    ):
        device = (
            static_by_name.get(str(transition.get("hostname") or "").casefold())
            or static_by_mac.get(str(transition.get("mac_plain") or ""))
        )
        lease_ip = str(transition.get("ip") or "").strip()
        if device is None or not lease_ip:
            continue
        device["ssh_ips"] = list(dict.fromkeys([
            *device.get("ssh_ips", []), lease_ip,
        ]))
        device.setdefault("ssh_interfaces", {})[lease_ip] = "eth0(DHCP过渡)"
        device["dynamic_lease_ips"] = [lease_ip]
        device["transition_address_source"] = "dhcp-lease-transition"

    # AIR-only topology nodes have no Production address to inherit.  They are
    # legitimate monitored devices whose current transport address comes from
    # ISC DHCP.  Keep unresolved identities in the report so they appear as
    # waiting rather than silently disappearing; SSH is attempted only after
    # an active lease or this round's DHCPACK supplies an address.
    for runtime in dynamic_air_devices(
        csv_path, air_json=air_json, leases=dhcp_leases,
    ):
        ip = str(runtime.get("ip") or "").strip()
        issue = str(runtime.get("issue") or "").strip()
        devices.append({
            "hostname": runtime["hostname"],
            "type": "air",
            "template": runtime.get("template", ""),
            "ip": ip,
            "ssh_ips": [ip] if ip else [],
            "ssh_interfaces": {ip: "eth0"} if ip else {},
            "mac": str(runtime.get("mac") or "").lower(),
            "mac_plain": str(runtime.get("mac_plain") or ""),
            "ssh_user": "cumulus",
            "time_sync": {"status": "unknown", "detail": "尚未取得可验证的 SSH 地址"},
            "dynamic_dhcp": True,
            "address_source": runtime.get("address_source", "unresolved"),
            "runtime_issue": issue,
            "stages": {name: stage() for name in STAGE_NAMES},
            "issues": ([{
                "severity": "warning",
                "code": "dynamic_address_conflict",
                "message": issue,
            }] if issue else []),
            "events": [],
        })

    if scope == "air":
        return [device for device in devices if device["type"] == "air"]
    if scope == "prod":
        return [device for device in devices if device["type"] != "air"]
    return devices


def run_command(command: list[str], timeout: int = 20) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False,
        )
        return {"returncode": completed.returncode, "stdout": completed.stdout,
                "stderr": completed.stderr}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"returncode": 124, "stdout": "", "stderr": str(exc)}


def service_state(name: str) -> dict[str, str]:
    active = run_command(["systemctl", "is-active", name], timeout=8)
    enabled = run_command(["systemctl", "is-enabled", name], timeout=8)
    return {
        "active": active["stdout"].strip() or "unknown",
        "enabled": enabled["stdout"].strip() or "unknown",
        "error": (active["stderr"] + enabled["stderr"]).strip(),
    }


def parse_time(value: str) -> str:
    value = value.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = dt.datetime.strptime(value[:25 if "T" in value else 19], fmt)
            if parsed.tzinfo is None:
                parsed = parsed.astimezone()
            return parsed.isoformat(timespec="seconds")
        except ValueError:
            pass
    return value


DHCP_EVENT_RE = re.compile(r"\b(DHCPDISCOVER|DHCPOFFER|DHCPREQUEST|DHCPACK|DHCPNAK)\b", re.I)
MAC_RE = re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.I)
IP_RE = re.compile(r"\b(?:on|for|to|from)\s+(\d{1,3}(?:\.\d{1,3}){3})\b", re.I)
RUNTIME_DHCP_MARKER = "ZTP_DHCP_EVENT_V1 "


def normalize_runtime_dhcp_mac(value: str) -> str:
    """Normalize ISC ``binary-to-ascii`` MAC octets to 12 hex digits.

    ISC does not zero-pad base-16 output, so a hardware address can appear as
    ``2:b:b0:db:e9:20`` even though ordinary dhcpd messages print the same MAC
    as ``02:0b:b0:db:e9:20``.  Keep the looser form scoped to our structured
    runtime record instead of weakening the parser for unstructured messages.
    """
    octets = (value or "").strip().split(":")
    if len(octets) != 6 or any(
        re.fullmatch(r"[0-9a-fA-F]{1,2}", octet) is None for octet in octets
    ):
        return ""
    return "".join(octet.zfill(2).lower() for octet in octets)


def parse_dhcp(text: str) -> list[dict[str, str]]:
    events: list[dict[str, str]] = []
    for line in text.splitlines():
        if RUNTIME_DHCP_MARKER in line:
            fields = dict(re.findall(r"\b([a-zA-Z0-9_]+)=([^\s]+)", line))
            runtime_kind = {
                "commit": "LEASE_COMMIT",
                "release": "LEASE_RELEASE",
                "expiry": "LEASE_EXPIRY",
            }.get(str(fields.get("event") or "").casefold())
            if runtime_kind:
                timestamp = ""
                iso = re.match(
                    r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?"
                    r"(?:Z|[+-]\d\d:?\d\d)?)",
                    line,
                )
                if iso:
                    timestamp = parse_time(iso.group(1).replace("Z", "+00:00"))
                raw_mac = str(fields.get("mac") or "")
                raw_ip = str(fields.get("ip") or "")
                events.append({
                    "kind": runtime_kind,
                    "mac_plain": normalize_runtime_dhcp_mac(raw_mac),
                    "ip": raw_ip if raw_ip != "-" else "",
                    "timestamp": timestamp,
                    "lease_state": str(fields.get("lease_state") or ""),
                    "raw": line,
                })
                continue
        event_match = DHCP_EVENT_RE.search(line)
        if not event_match:
            continue
        mac_match = MAC_RE.search(line)
        ip_match = IP_RE.search(line)
        timestamp = ""
        iso = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:[+-]\d\d:?\d\d)?)", line)
        if iso:
            timestamp = parse_time(iso.group(1))
        events.append({
            "kind": event_match.group(1).upper(),
            "mac_plain": normalize_mac(mac_match.group(0)) if mac_match else "",
            "ip": ip_match.group(1) if ip_match else "",
            "timestamp": timestamp,
            "raw": line,
        })
    return events


def apply_dynamic_dhcp_addresses(
    devices: list[dict[str, Any]], events: list[dict[str, str]],
) -> None:
    """Resolve a live dynamic address without reviving a released lease.

    The lease parser is authoritative when it already supplies an active
    address.  Syslog DHCPACK is only a fallback for an unresolved identity and
    is invalidated by a later release/expiry event for the same MAC.
    """
    lifecycle: dict[str, tuple[dict[str, str], int]] = {}

    def event_time(event: dict[str, str]) -> Optional[dt.datetime]:
        value = str(event.get("timestamp") or "")
        if not value:
            return None
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.astimezone()
        except ValueError:
            return None

    def is_newer(
        candidate: dict[str, str], candidate_index: int,
        previous: dict[str, str], previous_index: int,
    ) -> bool:
        candidate_time = event_time(candidate)
        previous_time = event_time(previous)
        if candidate_time is not None and previous_time is not None:
            return candidate_time >= previous_time
        return candidate_index >= previous_index

    for index, event in enumerate(events):
        kind = str(event.get("kind") or "")
        mac_plain = str(event.get("mac_plain") or "")
        if kind not in {"DHCPACK", "LEASE_COMMIT", "LEASE_RELEASE", "LEASE_EXPIRY"}:
            continue
        if not mac_plain:
            continue
        previous = lifecycle.get(mac_plain)
        if previous is None or is_newer(event, index, previous[0], previous[1]):
            lifecycle[mac_plain] = (event, index)

    static_addresses = {
        str(device.get("ip") or "")
        for device in devices
        if not device.get("dynamic_dhcp") and device.get("ip")
    }
    candidates: dict[str, str] = {}
    candidate_sources: dict[str, str] = {}
    owners: dict[str, list[str]] = {}
    for device in devices:
        if not device.get("dynamic_dhcp"):
            continue
        mac_plain = str(device.get("mac_plain") or "")
        lease_state = str(device.get("lease_state") or "").casefold()
        current_address = str(device.get("ip") or "")
        if lease_state and lease_state not in {"active", "observed"}:
            if current_address:
                device["last_lease_ip"] = current_address
            current_address = ""
        latest_event = lifecycle.get(mac_plain, ({}, -1))[0]
        event_kind = str(latest_event.get("kind") or "")
        event_address = str(latest_event.get("ip") or "")
        event_is_live = event_kind in {"DHCPACK", "LEASE_COMMIT"}
        address = current_address
        if (
            not address and event_is_live
            and (not lease_state or lease_state in {"active", "observed"})
        ):
            address = event_address
        if address:
            candidates[device["hostname"]] = address
            candidate_sources[device["hostname"]] = (
                "dhcp-event" if not current_address else
                str(device.get("address_source") or "dhcp-lease")
            )
            owners.setdefault(address, []).append(device["hostname"])

    for device in devices:
        if not device.get("dynamic_dhcp"):
            continue
        address = candidates.get(device["hostname"], "")
        issue = ""
        if address in static_addresses:
            issue = f"dynamic address {address} conflicts with static inventory"
        elif address and len(owners.get(address, [])) > 1:
            issue = (
                f"dynamic address {address} belongs to multiple devices: "
                + ", ".join(owners[address])
            )
        if issue:
            address = ""
            device["runtime_issue"] = issue
            device["issues"] = [{
                "severity": "warning",
                "code": "dynamic_address_conflict",
                "message": issue,
            }]
        device["ip"] = address
        device["ssh_ips"] = [address] if address else []
        interface_label = "DHCP动态" if device.get("unbound_identity") else "eth0"
        device["ssh_interfaces"] = {address: interface_label} if address else {}
        if device.get("unbound_identity"):
            device["candidate_identity"] = {
                address: ("dhcp", str(device.get("mac_plain") or ""))
            } if address else {}
            if str(device.get("platform_family") or "") in {"cumulus", "nvos"}:
                device["ssh_collect_enabled"] = bool(address)
        device["address_source"] = (
            candidate_sources.get(device["hostname"], "dhcp-lease")
            if address else "unresolved"
        )


def runtime_unknown_devices(
    csv_path: Path,
    dhcp_text: str,
    *,
    scope: str,
    dhcp_leases: Optional[Path],
) -> list[dict[str, Any]]:
    """Convert unbound DHCP identities into safe monitor-only device rows.

    The DHCP runtime inventory deliberately has no planned hostname.  A stable
    synthetic name keeps history readable, while ``unbound_identity`` prevents
    manual actions from treating it as a configured switch.  Cumulus/NVOS
    fingerprints select only the SSH username; remote identity is still proven
    by the observed management-interface MAC before any logs are consumed.
    Cumulus accepts eth0 only; NVOS resolves the DHCP chaddr against eth0/eth1.
    """
    environment = (
        "air" if scope == "air"
        else "production" if scope == "prod"
        else "unknown"
    )
    rows: list[dict[str, Any]] = []
    try:
        discovered = unknown_dhcp_devices(
            journal_text=dhcp_text,
            lease_path=dhcp_leases,
            inventory_path=csv_path,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        log(f"[WARN] 未绑定 DHCP 设备解析失败：{exc}", file=sys.stderr)
        return rows

    for item in discovered:
        mac_plain = str(item.get("mac_plain") or "")
        if not mac_plain:
            continue
        platform = str(item.get("platform") or "unknown").casefold()
        managed_ztp = platform in {"cumulus", "nvos"}
        lease_state = str(item.get("lease_state") or "unknown").casefold()
        lease_is_live = lease_state in {"active", "observed"}
        raw_ip = str(item.get("ip") or "").strip()
        ip = raw_ip if lease_is_live else ""
        last_lease_ip = str(item.get("last_lease_ip") or raw_ip).strip()
        prefix = "AIR-" if environment == "air" else ""
        identity_label = "DISCOVERED" if managed_ztp else "UNKNOWN"
        # The full MAC is the physical identity key.  Using only the lower
        # 24 bits can merge two devices from different OUIs into one history
        # row, so keep all 12 hexadecimal digits in the synthetic name.
        hostname = (
            f"{prefix}{identity_label}-{platform.upper()}-{mac_plain.upper()}"
        )
        last_seen = str(item.get("last_seen") or "")
        product = str(item.get("product") or "")
        serial = str(item.get("serial") or "")
        if platform == "cumulus":
            device_type = "pending_eth"
        elif platform == "nvos" and product.upper().startswith("N"):
            device_type = "pending_nvl"
        elif platform == "nvos" and product.upper().startswith("Q"):
            device_type = "pending_ib"
        elif platform == "nvos":
            device_type = "pending_nvos"
        else:
            device_type = "unknown"
        fingerprints = item.get("fingerprints") if isinstance(
            item.get("fingerprints"), dict
        ) else {}
        identity_detail = ", ".join(filter(None, [
            f"platform={platform}", f"product={product}" if product else "",
            f"serial={serial}" if serial else "", f"MAC={item.get('mac', '')}",
            f"IP={ip}" if ip else "IP=未分配",
        ]))
        stages = {name: stage() for name in STAGE_NAMES}
        stages["dhcp"] = stage(
            "success" if ip else "running",
            (f"动态 DHCP 地址 {ip}" if ip else "已收到 DHCP 请求，等待地址分配"),
            last_seen,
        )
        issues = [{
            "code": (
                "ZTP_MANAGED_IDENTITY_PENDING" if managed_ztp
                else "UNMANAGED_DHCP_DEVICE"
            ),
            "severity": "warning",
            "message": (
                (
                    f"DHCP 已将该设备识别为 {platform} 并下发对应 ZTP 引导，"
                    "可继续使用默认配置完成首次接入；"
                    if managed_ztp else
                    "DHCP 无法识别该设备平台，因此只分配地址、不下发任何 ZTP 引导；"
                )
                + "尚未把 MAC 绑定到项目设备清单。请先核对物理连接/型号，"
                "更新 02-devices_config.csv 后重新 load。"
                f" 当前指纹：{identity_detail}"
            ),
            "timestamp": last_seen,
        }]
        if platform == "unknown":
            issues.append({
                "code": "DHCP_PLATFORM_UNKNOWN",
                "severity": "warning",
                "message": (
                    "DHCP option 60/61/77 无法识别平台；本次只分配租约，"
                    "不下发 Cumulus 或 NVOS ZTP 引导。"
                ),
                "timestamp": last_seen,
            })
        if not lease_is_live:
            issues.append({
                "code": "DHCP_LEASE_NOT_ACTIVE",
                "severity": "warning",
                "message": (
                    f"最近租约状态为 {lease_state}；"
                    + (f"地址 {last_lease_ip} 仅保留作审计，" if last_lease_ip else "")
                    + "等待设备重新取得 active lease 后才允许 SSH。"
                ),
                "timestamp": last_seen,
            })
        rows.append({
            "hostname": hostname,
            "type": device_type,
            "template": "default",
            "environment": environment,
            "ip": ip,
            # True unknown platforms are display/audit observations only.  Do
            # not retain an SSH transport candidate even though the outer
            # ssh_collect_enabled gate also rejects them; this keeps every
            # direct consumer fail-closed if that gate is ever bypassed.
            "ssh_ips": [ip] if managed_ztp and ip else [],
            "ssh_interfaces": {ip: "DHCP动态"} if managed_ztp and ip else {},
            "mac": str(item.get("mac") or "").lower(),
            "mac_plain": mac_plain,
            # Before the device is bound, DHCP chaddr is authoritative but an
            # NVOS request may originate on eth0 or eth1.  The remote probe
            # resolves the actual interface by matching both MACs.
            "identity_macs": {"dhcp": mac_plain},
            "candidate_identity": (
                {ip: ("dhcp", mac_plain)} if managed_ztp and ip else {}
            ),
            "ssh_user": "admin" if platform == "nvos" else "cumulus",
            "ssh_collect_enabled": platform in {"cumulus", "nvos"} and bool(ip),
            "managed_ztp": managed_ztp,
            "dynamic_dhcp": True,
            "unbound_identity": True,
            "identity_pending": True,
            "platform_family": platform,
            "product": product,
            "serial": serial,
            "dhcp_fingerprints": fingerprints,
            "lease_state": lease_state,
            "lease_ends": str(item.get("lease_ends") or ""),
            # This is the start/evidence boundary of the live holder epoch used
            # to prevent an old Apache GET from claiming a reassigned address.
            "runtime_last_seen": last_seen,
            "last_lease_ip": last_lease_ip,
            "address_source": "dhcp-runtime-inventory",
            "stages": stages,
            "issues": issues,
            "events": [],
        })
    return rows


def apply_static_runtime_lease_fallbacks(
    devices: list[dict[str, Any]],
    csv_path: Path,
    dhcp_text: str,
    *,
    dhcp_leases: Optional[Path],
) -> None:
    """Attach an old dynamic lease to a newly identified static device.

    This is transport discovery only: the canonical IP/template/hostname stay
    untouched.  The remote management-interface MAC must still match before
    SSH evidence is consumed, and a same-environment static-IP collision is
    rejected.
    """
    try:
        observations = unknown_dhcp_devices(
            journal_text=dhcp_text,
            lease_path=dhcp_leases,
            inventory_path=csv_path,
            include_known=True,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        log(f"[WARN] DHCP 过渡地址解析失败：{exc}", file=sys.stderr)
        return

    static_by_mac: dict[str, tuple[dict[str, Any], str]] = {}
    for device in devices:
        if device.get("unbound_identity"):
            continue
        identities = device.get("identity_macs") or {
            "eth0": str(device.get("mac_plain") or "")
        }
        for interface, mac_plain in identities.items():
            if mac_plain:
                static_by_mac[str(mac_plain)] = (device, str(interface))
    same_environment_owners: dict[tuple[str, str], list[str]] = {}
    for device in devices:
        address = str(device.get("ip") or "")
        if not address:
            continue
        environment = "air" if device.get("type") == "air" else "production"
        same_environment_owners.setdefault((environment, address), []).append(
            str(device.get("hostname") or "")
        )

    for observed in observations:
        matched = static_by_mac.get(str(observed.get("mac_plain") or ""))
        device, interface = matched if matched else (None, "")
        lease_ip = str(observed.get("ip") or "").strip()
        lease_state = str(observed.get("lease_state") or "").casefold()
        if device is None or not lease_ip or lease_state not in {"active", "observed"}:
            continue
        if lease_ip == str(device.get("ip") or ""):
            continue
        environment = "air" if device.get("type") == "air" else "production"
        other_owners = [
            hostname
            for hostname in same_environment_owners.get((environment, lease_ip), [])
            if hostname.casefold() != str(device.get("hostname") or "").casefold()
        ]
        if other_owners:
            message = (
                f"MAC {device.get('mac')} 的动态租约 {lease_ip} 与同环境静态设备 "
                f"{', '.join(other_owners)} 冲突，拒绝把它作为 SSH 候选。"
            )
            device.setdefault("issues", []).append({
                "code": "DHCP_TRANSITION_IP_CONFLICT",
                "severity": "failed", "message": message,
                "timestamp": str(observed.get("last_seen") or ""),
            })
            continue
        device["ssh_ips"] = list(dict.fromkeys([
            *device.get("ssh_ips", []), lease_ip,
        ]))
        label = f"{interface or 'management'}(DHCP过渡)"
        device.setdefault("ssh_interfaces", {})[lease_ip] = label
        device.setdefault("candidate_identity", {})[lease_ip] = (
            interface, str(observed.get("mac_plain") or ""),
        )
        device["dynamic_lease_ips"] = list(dict.fromkeys([
            *device.get("dynamic_lease_ips", []), lease_ip,
        ]))
        device["transition_address_source"] = "dhcp-runtime-transition"
        device["promotion_pending"] = True


def merge_previous_unbound_identities(
    previous_report: Optional[dict[str, Any]],
    devices: list[dict[str, Any]],
) -> Optional[dict[str, Any]]:
    """Move an anonymous previous cycle onto its newly bound canonical row.

    MAC is the physical identity key.  This preserves audit history without
    inheriting stale success as current dedicated-config evidence: the cloned
    previous row remains ``dynamic_dhcp`` and the current row is marked as a
    pending promotion, which existing round/index logic clears.
    """
    if not previous_report:
        return previous_report
    current_by_mac: dict[str, dict[str, Any]] = {}
    for device in devices:
        if device.get("unbound_identity"):
            continue
        for mac_plain in _device_identity_mac_values(device):
            current_by_mac[mac_plain] = device
    previous_items = previous_report.get("devices")
    if not isinstance(previous_items, list):
        return previous_report
    promoted_by_name: dict[str, dict[str, Any]] = {}
    for original in previous_items:
        if not isinstance(original, dict) or not original.get("unbound_identity"):
            continue
        mac_plain = normalize_mac(str(original.get("mac") or ""))
        current = current_by_mac.get(mac_plain)
        if current is None:
            continue
        canonical_name = str(current.get("hostname") or "")
        promoted = copy.deepcopy(original)
        promoted.update({
            "hostname": canonical_name,
            "type": current.get("type", ""),
            "template": current.get("template", ""),
            "dynamic_dhcp": True,
            "promotion_pending": True,
        })
        current["promotion_pending"] = True
        promoted_by_name[canonical_name.casefold()] = promoted
    if not promoted_by_name:
        return previous_report

    # A previous snapshot can contain both the planned canonical placeholder
    # and the anonymous DHCP identity.  Emit exactly one canonical row and use
    # the anonymous/default-ZTP evidence as history; promotion_pending prevents
    # that old evidence from counting as dedicated-config success.
    merged_items: list[Any] = []
    emitted_promotions: set[str] = set()
    for original in previous_items:
        if not isinstance(original, dict):
            merged_items.append(original)
            continue
        mac_plain = normalize_mac(str(original.get("mac") or ""))
        current = current_by_mac.get(mac_plain) if original.get("unbound_identity") else None
        key = (
            str(current.get("hostname") or "").casefold()
            if current is not None else str(original.get("hostname") or "").casefold()
        )
        if key in promoted_by_name:
            if key not in emitted_promotions:
                merged_items.append(promoted_by_name[key])
                emitted_promotions.add(key)
            continue
        merged_items.append(original)
    merged_report = copy.deepcopy(previous_report)
    merged_report["devices"] = merged_items
    return merged_report


APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^]]+)]\s+"(?P<method>\S+)\s+'
    r'(?P<path>\S+)(?:\s+HTTP/[^\"]+)?"\s+(?P<status>\d{3})\b'
)
APACHE_LATEST_YAML_MAC_RE = re.compile(
    r"^(?:/[A-Za-z0-9][A-Za-z0-9._~-]*)*/config/cumulus/latest_yaml/"
    r"(?P<mac>[0-9a-f]{12})\.yaml$",
    re.IGNORECASE,
)


def parse_apache(text: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = APACHE_RE.search(line)
        if not match:
            continue
        try:
            timestamp = dt.datetime.strptime(
                match.group("time"), "%d/%b/%Y:%H:%M:%S %z"
            ).isoformat(timespec="seconds")
        except ValueError:
            timestamp = match.group("time")
        events.append({
            "ip": match.group("ip"), "path": match.group("path"),
            "method": match.group("method"), "status": int(match.group("status")),
            "timestamp": timestamp, "raw": line,
        })
    return events


def _aware_event_time(value: Any) -> Optional[dt.datetime]:
    """Parse a comparable event time; naive/invalid values fail closed."""
    text = str(value or "").strip().replace("Z", "+00:00")
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def _canonical_eth0_mac(device: dict[str, Any]) -> str:
    identities = device.get("identity_macs")
    if isinstance(identities, dict) and identities.get("eth0"):
        return normalize_mac(str(identities["eth0"]))
    return normalize_mac(str(device.get("mac_plain") or ""))


def _http_claim_device(claim: Any) -> Optional[dict[str, Any]]:
    if not isinstance(claim, dict):
        return None
    device = claim.get("device")
    return device if isinstance(device, dict) else None


def _event_matches_http_claim(
    event: dict[str, Any], claim: dict[str, Any], *, source: str,
) -> bool:
    """Return whether one DHCP/HTTP event belongs to the claim's live epoch."""
    if str(event.get("ip") or "") != str(claim.get("ip") or ""):
        return False
    event_time = _aware_event_time(event.get("timestamp"))
    epoch_time = _aware_event_time(claim.get("epoch_started_at"))
    if event_time is None or epoch_time is None or event_time < epoch_time:
        return False
    if source == "dhcp":
        return normalize_mac(str(event.get("mac_plain") or "")) == normalize_mac(
            str(claim.get("holder_mac") or "")
        )
    return source == "apache"


def bind_apache_ztp_identities(
    devices: list[dict[str, Any]], apache_events: list[dict[str, Any]],
    dhcp_events: Optional[list[dict[str, str]]] = None,
    *, scope: str = "all",
) -> dict[str, dict[str, Any]]:
    """Bind one current unbound DHCP epoch to a scoped canonical device.

    A switch can obtain its bootstrap lease on a front-panel port whose MAC is
    intentionally absent from the management inventory.  The bootstrap then
    requests ``latest_yaml/<eth0-mac>.yaml``.  The GET is accepted only while
    that source address has exactly one current live unbound Cumulus holder and
    its comparable timestamp is at/after the holder's runtime epoch.  The
    caller must pass only devices in the report scope; this function never
    searches a global AIR/Production inventory.
    """
    canonical_by_mac: dict[str, list[dict[str, Any]]] = {}
    holders_by_ip: dict[str, list[dict[str, Any]]] = {}
    for device in devices:
        in_scope = (
            scope == "all"
            or (
                scope == "air"
                and (
                    device.get("type") == "air"
                    or device.get("environment") == "air"
                )
            )
            or (
                scope == "prod"
                and device.get("type") != "air"
                and device.get("environment") != "air"
            )
        )
        if not in_scope:
            continue
        if device.get("unbound_identity"):
            address = str(device.get("ip") or "").strip()
            if (
                address
                and str(device.get("platform_family") or "").casefold()
                == "cumulus"
                and str(device.get("lease_state") or "").casefold()
                in {"active", "observed"}
            ):
                holders_by_ip.setdefault(address, []).append(device)
            continue
        eth0_mac = _canonical_eth0_mac(device)
        if eth0_mac:
            canonical_by_mac.setdefault(eth0_mac, []).append(device)

    accepted_requests: dict[str, list[tuple[str, dt.datetime]]] = {}
    unreliable_request_time: set[str] = set()
    for event in apache_events:
        try:
            response_status = int(event.get("status") or 0)
        except (TypeError, ValueError):
            continue
        if (
            str(event.get("method") or "").upper() != "GET"
            or response_status != 200
        ):
            continue
        request_path = str(event.get("path") or "").split("?", 1)[0]
        match = APACHE_LATEST_YAML_MAC_RE.fullmatch(request_path)
        if not match:
            continue
        address = str(event.get("ip") or "").strip()
        if not address:
            continue
        request_time = _aware_event_time(event.get("timestamp"))
        if request_time is None:
            unreliable_request_time.add(address)
            continue
        accepted_requests.setdefault(address, []).append((
            match.group("mac").casefold(), request_time,
        ))

    claims: dict[str, dict[str, Any]] = {}
    for address, holders in holders_by_ip.items():
        if len(holders) != 1 or address in unreliable_request_time:
            continue
        holder = holders[0]
        holder_mac = normalize_mac(str(holder.get("mac_plain") or ""))
        if re.fullmatch(r"[0-9a-f]{12}", holder_mac) is None:
            continue
        epoch_time = _aware_event_time(holder.get("runtime_last_seen"))
        if epoch_time is None:
            continue
        epoch_requests = [
            (mac_plain, request_time)
            for mac_plain, request_time in accepted_requests.get(address, [])
            if request_time >= epoch_time
        ]
        requested_macs = {mac_plain for mac_plain, _ in epoch_requests}
        if len(requested_macs) != 1:
            continue
        requested_mac = next(iter(requested_macs))
        candidates = canonical_by_mac.get(requested_mac, [])
        if len(candidates) != 1:
            continue
        device = candidates[0]
        claim_time = max(request_time for _, request_time in epoch_requests)
        claim = {
            "ip": address,
            "device": device,
            "holder": holder,
            "holder_mac": holder_mac,
            "requested_mac": requested_mac,
            "epoch_started_at": epoch_time.isoformat(timespec="seconds"),
            "claimed_at": claim_time.isoformat(timespec="seconds"),
        }
        # A comparable holder-side DHCP event is not mandatory when the live
        # lease file supplied the epoch, but any supplied events must not show
        # a newer different holder for this address.
        lifecycle_conflict = False
        for event in (dhcp_events or []):
            if str(event.get("ip") or "") != address:
                continue
            event_time = _aware_event_time(event.get("timestamp"))
            if event_time is None:
                lifecycle_conflict = True
                break
            if event_time < epoch_time:
                continue
            event_mac = normalize_mac(str(event.get("mac_plain") or ""))
            event_kind = str(event.get("kind") or "").upper()
            if (
                (event_mac and event_mac != claim["holder_mac"])
                or event_kind in {"LEASE_RELEASE", "LEASE_EXPIRY"}
            ):
                lifecycle_conflict = True
                break
        if lifecycle_conflict:
            continue
        claims[address] = claim
        device["ztp_transport_ips"] = list(dict.fromkeys([
            *device.get("ztp_transport_ips", []), address,
        ]))
        device.setdefault("ztp_transport_holders", {})[address] = holder_mac
        device["ztp_transport_identity_source"] = "apache-mac-yaml"
        # A configured eth0 management address is always authoritative.  The
        # front-panel/transit lease is eligible as a temporary SSH endpoint
        # only when the inventory intentionally leaves eth0_ip empty.  Do not
        # write it into device["ip"] or silently use it when a configured eth0
        # address is merely unreachable.
        if not str(device.get("ip") or "").strip():
            device["ztp_transport_fallback"] = True
            device["ssh_ips"] = list(dict.fromkeys([
                *device.get("ssh_ips", []), address,
            ]))
            device.setdefault("ssh_interfaces", {})[address] = "ZTP transit"
            device.setdefault("candidate_identity", {})[address] = (
                "eth0", requested_mac,
            )
            issues = device.setdefault("issues", [])
            if not any(
                issue.get("code") == "MANAGEMENT_VIA_ZTP_TRANSIT"
                and str(issue.get("ip") or "") == address
                for issue in issues
            ):
                issues.append({
                    "code": "MANAGEMENT_VIA_ZTP_TRANSIT",
                    "severity": "warning",
                    "message": (
                        f"清单未配置 eth0 管理地址；当前仅通过 ZTP transit IP "
                        f"{address} 临时管理。该地址不会写回设备清单，也不代表正式管理地址。"
                    ),
                    "ip": address,
                    "timestamp": claim_time.isoformat(timespec="seconds"),
                })
        holder["superseded_by_hostname"] = device.get("hostname", "")
    return claims


def read_tail(path: Path, max_bytes: int = 20 * 1024 * 1024) -> tuple[str, str]:
    try:
        with path.open("rb") as handle:
            size = path.stat().st_size
            if size > max_bytes:
                handle.seek(-max_bytes, os.SEEK_END)
                handle.readline()
            return handle.read().decode("utf-8", errors="replace"), ""
    except OSError as exc:
        return "", str(exc)


def collect_dhcp(since_minutes: int, fixture: Optional[Path] = None) -> tuple[str, str]:
    if fixture:
        return read_tail(fixture)
    result = run_command([
        "journalctl", "-u", "isc-dhcp-server", "--since",
        f"{since_minutes} minutes ago", "--no-pager", "-o", "short-iso",
    ], timeout=30)
    if result["returncode"] == 0:
        return result["stdout"], result["stderr"]
    fallback = Path("/var/log/syslog")
    text, error = read_tail(fallback)
    return text, "; ".join(filter(None, [result["stderr"].strip(), error]))


def set_stage(device: dict[str, Any], name: str, status: str, detail: str,
              timestamp: str = "") -> None:
    # Inputs are processed oldest-to-newest; switch-side evidence is applied last.
    # Keep the new status/detail from the closest-to-device observation, but
    # do not move the event time backwards when a switch clock trails the
    # management server.  Apache's timestamp is authoritative for HTTP stages.
    existing_timestamp = str(device.get("stages", {}).get(name, {}).get("timestamp") or "")
    if existing_timestamp and timestamp and _timestamp_after(existing_timestamp, timestamp):
        timestamp = existing_timestamp
    device["stages"][name] = stage(status, detail, timestamp)


def _device_ips(device: dict[str, Any]) -> list[str]:
    """Return canonical and temporary transport addresses for one device."""
    return list(dict.fromkeys(
        str(value).strip()
        for value in [device.get("ip", ""), *device.get("ssh_ips", [])]
        if str(value).strip()
    ))


def _devices_by_ip(devices: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for device in devices:
        for address in _device_ips(device):
            grouped.setdefault(address, []).append(device)
    return grouped


def _device_identity_mac_values(device: dict[str, Any]) -> set[str]:
    """Return every management-interface MAC that can identify a device."""
    values = device.get("identity_macs")
    if isinstance(values, dict):
        identities = {str(value) for value in values.values() if value}
        if identities:
            return identities
    fallback = str(device.get("mac_plain") or "")
    return {fallback} if fallback else set()


def _same_device_identity(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return bool(_device_identity_mac_values(left) & _device_identity_mac_values(right))


def active_device_by_ip(
    devices: list[dict[str, Any]], dhcp_events: list[dict[str, str]]
) -> dict[str, dict[str, Any]]:
    """Resolve a shared management IP to exactly one inventory row by DHCP MAC.

    Production and AIR intentionally reuse management addresses.  IP therefore
    identifies only the transport endpoint; the observed client MAC identifies
    the environment.  Events are chronological, so the latest matching DHCP
    interaction owns the address for this collection round.
    """
    mac_candidates: dict[str, list[dict[str, Any]]] = {}
    for device in devices:
        for mac_plain in _device_identity_mac_values(device):
            mac_candidates.setdefault(mac_plain, []).append(device)
    owners: dict[str, dict[str, Any]] = {}
    for event in dhcp_events:
        candidates = mac_candidates.get(event.get("mac_plain", ""), [])
        if len(candidates) != 1:
            continue
        device = candidates[0]
        event_ip = event.get("ip", "")
        if event_ip and event_ip not in _device_ips(device):
            continue
        owner_ip = event_ip or str(device.get("ip") or "")
        if owner_ip:
            owners[owner_ip] = device
    return owners


def devices_for_switch_collection(
    devices: list[dict[str, Any]], owners: dict[str, dict[str, Any]],
    identity_devices: Optional[list[dict[str, Any]]] = None,
    http_identity_claims: Optional[dict[str, dict[str, Any]]] = None,
) -> list[dict[str, Any]]:
    """Collect unique IPs normally and shared IPs only for their MAC owner."""
    selected: list[dict[str, Any]] = []
    identity_by_ip = _devices_by_ip(identity_devices or devices)
    claimed_devices = {
        id(device)
        for device in (
            _http_claim_device(claim)
            for claim in (http_identity_claims or {}).values()
        )
        if device is not None
    }
    for device in devices:
        if device.get("ssh_collect_enabled") is False:
            continue
        # A claim normally authorizes only the canonical eth0 endpoint.  When
        # eth0_ip is intentionally empty, bind_apache_ztp_identities appends the
        # current live transit lease as a temporary endpoint.  analyze_switch
        # still requires both the canonical eth0 MAC and the DHCP holder MAC.
        selectable = id(device) in claimed_devices and bool(_device_ips(device))
        for ip in _device_ips(device):
            candidates = identity_by_ip.get(ip, [])
            if len(candidates) == 1:
                selectable = True
                break
            owner = owners.get(ip)
            if owner is not None and _same_device_identity(owner, device):
                selectable = True
                break
        if selectable:
            selected.append(device)
    return selected


def correlate_server_events(devices: list[dict[str, Any]], dhcp_events: list[dict[str, str]],
                            apache_events: list[dict[str, Any]],
                            identity_devices: Optional[list[dict[str, Any]]] = None,
                            http_identity_claims: Optional[
                                dict[str, dict[str, Any]]
                            ] = None,
                            ) -> dict[str, dict[str, Any]]:
    mac_candidates: dict[str, list[dict[str, Any]]] = {}
    for device in devices:
        for mac_plain in _device_identity_mac_values(device):
            mac_candidates.setdefault(mac_plain, []).append(device)
    by_ip = _devices_by_ip(devices)
    identity_by_ip = _devices_by_ip(identity_devices or devices)
    owners = active_device_by_ip(identity_devices or devices, dhcp_events)
    http_claims = http_identity_claims or {}
    for event in dhcp_events:
        claim = http_claims.get(event.get("ip", ""))
        if claim is not None:
            if not _event_matches_http_claim(event, claim, source="dhcp"):
                continue
            device = _http_claim_device(claim)
        else:
            candidates = mac_candidates.get(event["mac_plain"], [])
            device = candidates[0] if len(candidates) == 1 else None
            if device is None and not event["mac_plain"]:
                ip_candidates = by_ip.get(event["ip"], [])
                identity_candidates = identity_by_ip.get(event["ip"], [])
                device = (ip_candidates[0]
                          if len(ip_candidates) == 1 and len(identity_candidates) == 1
                          else None)
        if not device:
            continue
        device["events"].append({"source": "dhcp", **event})
        kind = event["kind"]
        if kind == "DHCPACK":
            set_stage(device, "dhcp", "success", f"DHCPACK {event['ip']}", event["timestamp"])
        elif kind == "DHCPNAK":
            set_stage(device, "dhcp", "failed", "收到 DHCPNAK", event["timestamp"])
        else:
            set_stage(device, "dhcp", "running", kind, event["timestamp"])
    for event in apache_events:
        claim = http_claims.get(event["ip"])
        if claim is not None:
            if not _event_matches_http_claim(event, claim, source="apache"):
                continue
            device = _http_claim_device(claim)
        else:
            ip_candidates = by_ip.get(event["ip"], [])
            identity_candidates = identity_by_ip.get(event["ip"], [])
            if len(identity_candidates) == 1 and len(ip_candidates) == 1:
                device = ip_candidates[0]
            else:
                owner = owners.get(event["ip"])
                device = next((candidate for candidate in ip_candidates
                               if owner is not None
                               and _same_device_identity(candidate, owner)), None)
        if not device:
            continue
        path, code = event["path"], event["status"]
        request_path = path.split("?", 1)[0]
        device["events"].append({"source": "apache", **event})
        ok = 200 <= code < 400
        if "ztp-bootstrap" in request_path:
            set_stage(device, "bootstrap", "success" if ok else "failed",
                      f"HTTP {code} {path}", event["timestamp"])
        if "/latest_yaml/" in request_path and request_path.endswith(".yaml"):
            set_stage(device, "config_http", "success" if ok else "failed",
                      f"HTTP {code} {path}", event["timestamp"])
    return owners


REMOTE_SCRIPT = r'''
set +e
printf '__REMOTE_TIME_START_BEGIN__\n'
date -u '+%s.%N' 2>/dev/null || date -u '+%s' 2>/dev/null || true
printf '__REMOTE_TIME_START_END__\n'
printf '__HOSTNAME_BEGIN__\n'
hostname 2>/dev/null || true
printf '__HOSTNAME_END__\n'
printf '__ETH0_MAC_BEGIN__\n'
cat /sys/class/net/eth0/address 2>/dev/null || true
printf '__ETH0_MAC_END__\n'
printf '__ETH1_MAC_BEGIN__\n'
cat /sys/class/net/eth1/address 2>/dev/null || true
printf '__ETH1_MAC_END__\n'
printf '__INTERFACE_MACS_BEGIN__\n'
for mac_file in /sys/class/net/*/address; do
    [ -f "$mac_file" ] || continue
    interface=${mac_file%/address}
    interface=${interface##*/}
    mac=$(cat "$mac_file" 2>/dev/null || true)
    [ -n "$interface" ] && [ -n "$mac" ] && printf '%s=%s\n' "$interface" "$mac"
done
printf '__INTERFACE_MACS_END__\n'
printf '__BOOT_ID_BEGIN__\n'
cat /proc/sys/kernel/random/boot_id 2>/dev/null || true
printf '__BOOT_ID_END__\n'
printf '__BOOT_TIME_BEGIN__\n'
awk '/^btime / {print $2; exit}' /proc/stat 2>/dev/null || true
printf '__BOOT_TIME_END__\n'
log_dir=/var/lib/nvidia-ztp/logs
log_pointer="$log_dir/latest-log"
log_pointer_state=absent
latest=""
if [ -e "$log_pointer" ] || [ -L "$log_pointer" ]; then
    log_pointer_state=invalid
    if [ -f "$log_pointer" ] && [ ! -L "$log_pointer" ] &&
       [ "$(stat -c '%U:%a' -- "$log_pointer" 2>/dev/null)" = root:644 ] &&
       [ "$(wc -l < "$log_pointer" 2>/dev/null | tr -d ' ')" = 1 ] &&
       [ "$(wc -c < "$log_pointer" 2>/dev/null | tr -d ' ')" -le 256 ] 2>/dev/null; then
        IFS= read -r pointed_log < "$log_pointer" || pointed_log=""
        case "$pointed_log" in
            ztp-result.log_*) ;;
            *) pointed_log="" ;;
        esac
        case "$pointed_log" in
            *[!A-Za-z0-9._-]*) pointed_log="" ;;
        esac
        candidate="$log_dir/$pointed_log"
        if [ -n "$pointed_log" ] && [ -f "$candidate" ] && [ ! -L "$candidate" ] &&
           [ "$(stat -c '%U:%a' -- "$candidate" 2>/dev/null)" = root:644 ]; then
            latest="$candidate"
            log_pointer_state=valid
        fi
    fi
fi
printf '__ZTP_LOG_POINTER_STATE_BEGIN__\n%s\n__ZTP_LOG_POINTER_STATE_END__\n' "$log_pointer_state"
if [ "$log_pointer_state" = absent ]; then
    for candidate in $(ls -1t "$log_dir"/ztp-result.log_* 2>/dev/null); do
        if [ -f "$candidate" ] && [ ! -L "$candidate" ]; then latest="$candidate"; break; fi
    done
fi
if [ "$log_pointer_state" = absent ] && [ -z "$latest" ]; then
    for candidate in $(ls -1t "$HOME"/ztp-result.log_* 2>/dev/null); do
        if [ -f "$candidate" ] && [ ! -L "$candidate" ]; then latest="$candidate"; break; fi
    done
fi
printf '__ZTP_LOG_BEGIN__\n'
if [ -n "$latest" ]; then printf '__FILE__=%s\n' "$latest"; cat -- "$latest"; fi
printf '__ZTP_LOG_END__\n'
printf '__ZTP_LOG_MTIME_BEGIN__\n'
if [ -n "$latest" ]; then stat -c '%Y' -- "$latest" 2>/dev/null || true; fi
printf '__ZTP_LOG_MTIME_END__\n'
printf '__IFRELOAD_BEGIN__\n'
sudo -n journalctl -u ifreload-nvue.service --no-pager -n 120 2>/dev/null || journalctl -u ifreload-nvue.service --no-pager -n 120 2>/dev/null || true
log=$(ls -1t /var/log/ifupdown2/network_config_ifupdown2_* 2>/dev/null | head -n 1)
if [ -n "$log" ]; then sudo -n tail -n 160 "$log" 2>/dev/null || tail -n 160 "$log" 2>/dev/null || true; fi
printf '__IFRELOAD_END__\n'
printf '__FAILED_YAML_BEGIN__\n'
failed=$(ls -1t "$HOME"/ztp-failed-configs/__MAC_PLAIN___*.yaml 2>/dev/null | head -n 1)
if [ -z "$failed" ]; then failed="/tmp/ztp/__MAC_PLAIN__.yaml"; fi
if [ ! -f "$failed" ]; then failed=$(ls -1t /tmp/ztp/*.yaml 2>/dev/null | head -n 1); fi
if [ -n "$failed" ]; then printf '__FILE__=%s\n' "$failed"; cat "$failed"; fi
printf '__FAILED_YAML_END__\n'
printf '__REMOTE_TIME_END_BEGIN__\n'
date -u '+%s.%N' 2>/dev/null || date -u '+%s' 2>/dev/null || true
printf '__REMOTE_TIME_END_END__\n'
'''


def marker(text: str, name: str) -> str:
    match = re.search(
        rf"__{re.escape(name)}_BEGIN__\n(.*?)__{re.escape(name)}_END__", text, re.S
    )
    return match.group(1).strip() if match else ""


def parse_remote_interface_macs(text: str) -> dict[str, str]:
    """Parse the fixed remote probe's interface=MAC records."""
    parsed: dict[str, str] = {}
    for line in text.splitlines():
        interface, separator, raw_mac = line.partition("=")
        interface = interface.strip()
        mac_plain = normalize_mac(raw_mac)
        if (
            separator
            and re.fullmatch(r"[A-Za-z0-9_.:-]+", interface)
            and re.fullmatch(r"[0-9a-f]{12}", mac_plain)
        ):
            parsed[interface] = mac_plain
    return parsed


def host_key_commands(device: dict[str, Any], stderr: str, known_hosts: Path) -> list[str]:
    targets = [device["hostname"], *device.get("ssh_ips", [device["ip"]])]
    commands = []
    for target in targets:
        if target:
            commands.append(f"ssh-keygen -f {shlex.quote(str(known_hosts))} -R {shlex.quote(target)}")
    match = re.search(r"Offending .* key in ([^:]+):(\d+)", stderr)
    if match:
        commands.insert(0, f"# 冲突位置: {match.group(1)}:{match.group(2)}")
    return commands


def refresh_air_host_keys(device: dict[str, Any], known_hosts: Path) -> list[str]:
    """Remove stale AIR entries after a simulation reset, serialized for parallel collectors."""
    removed: list[str] = []
    hostname = device.get("hostname", "")
    targets = list(dict.fromkeys(
        target for target in (
            hostname, hostname.casefold(), *device.get("ssh_ips", [device.get("ip", "")])
        ) if target
    ))
    with _KNOWN_HOSTS_LOCK:
        for target in targets:
            result = run_command(
                ["ssh-keygen", "-f", str(known_hosts), "-R", target], timeout=8
            )
            if result["returncode"] == 0:
                removed.append(target)
    return removed


def collect_switch(device: dict[str, Any], timeout: int, identity: Optional[Path],
                   known_hosts: Path) -> dict[str, Any]:
    # ``devices_for_switch_collection`` is the normal caller-side gate, but
    # keep the transport primitive fail-closed as well.  Runtime DHCP rows for
    # a genuinely unknown platform must never become SSH probes merely because
    # a future caller invokes this function directly.
    if device.get("ssh_collect_enabled") is False:
        return {
            "kind": "ssh_disabled", "returncode": 126,
            "stderr": "SSH collection is disabled for this device identity",
            "connected_ip": "", "attempt_errors": [], "attempts": [],
            "remote_hostname": "", "remote_eth0_mac": "",
            "remote_eth1_mac": "", "remote_interface_macs": {},
            "boot_id": "", "boot_time": "", "remote_time_start": "",
            "remote_time_end": "", "local_started_epoch": 0,
            "local_finished_epoch": 0, "ztp_log": "",
            "ztp_log_pointer_state": "", "ztp_log_mtime": "",
            "ifreload_log": "", "failed_yaml": "",
            "host_key_refreshed": False,
            "refreshed_host_key_targets": [], "host_key_commands": [],
        }

    def connect(host: str) -> dict[str, Any]:
        target = f"{device['ssh_user']}@{host}"
        command = [
            "ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={timeout}",
            "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "LogLevel=ERROR",
        ]
        if identity:
            command += ["-i", str(identity)]
        # OpenSSH concatenates arguments into one remote shell command. Send the
        # script as a single safely quoted argument so `sh -c` receives it intact.
        remote_script = REMOTE_SCRIPT.replace("__MAC_PLAIN__", device["mac_plain"])
        command += [target, "sh -c " + shlex.quote(remote_script)]
        local_started = time.time()
        result = run_command(command, timeout=timeout + 12)
        result["local_started_epoch"] = local_started
        result["local_finished_epoch"] = time.time()
        return result

    # Prefer the configured eth0 endpoint.  A current, identity-bound transit
    # lease is present in ssh_ips only when the inventory has no eth0 address.
    result: dict[str, Any] = {"returncode": 124, "stdout": "", "stderr": "no SSH target"}
    connected_ip = ""
    host_key_refreshed = False
    refreshed_targets: list[str] = []
    attempt_errors: list[str] = []
    attempts: list[dict[str, str]] = []
    for candidate in device.get("ssh_ips", [device["ip"]]):
        if not candidate:
            continue
        result = connect(candidate)
        stderr = result["stderr"].strip()
        lowered = stderr.lower()
        if (device.get("type") == "air" and result["returncode"] != 0
                and ("remote host identification has changed" in lowered
                     or "host key verification failed" in lowered)):
            refreshed_targets = refresh_air_host_keys(device, known_hosts)
            result = connect(candidate)
            stderr = result["stderr"].strip()
            lowered = stderr.lower()
            host_key_refreshed = result["returncode"] == 0
        if result["returncode"] == 0:
            connected_ip = candidate
            attempts.append({"ip": candidate, "status": "success", "error": ""})
            break
        attempt_errors.append(f"{candidate}: {stderr or 'SSH failed'}")
        attempts.append({
            "ip": candidate, "status": "failed", "error": stderr or "SSH failed",
        })
    stderr = result["stderr"].strip() if connected_ip else "\n".join(attempt_errors)
    lowered = stderr.lower()
    kind = "ok" if result["returncode"] == 0 else "ssh_failed"
    if "remote host identification has changed" in lowered or "host key verification failed" in lowered:
        kind = "host_key_changed"
    elif "permission denied" in lowered:
        kind = "authentication_failed"
    elif "timed out" in lowered or "no route to host" in lowered:
        kind = "unreachable"
    return {
        "kind": kind, "returncode": result["returncode"], "stderr": stderr,
        "connected_ip": connected_ip,
        "attempt_errors": attempt_errors,
        "attempts": attempts,
        "remote_hostname": marker(result["stdout"], "HOSTNAME").splitlines()[0].strip()
        if marker(result["stdout"], "HOSTNAME") else "",
        "remote_eth0_mac": marker(result["stdout"], "ETH0_MAC").splitlines()[0].strip()
        if marker(result["stdout"], "ETH0_MAC") else "",
        "remote_eth1_mac": marker(result["stdout"], "ETH1_MAC").splitlines()[0].strip()
        if marker(result["stdout"], "ETH1_MAC") else "",
        "remote_interface_macs": parse_remote_interface_macs(
            marker(result["stdout"], "INTERFACE_MACS")
        ),
        "boot_id": marker(result["stdout"], "BOOT_ID").splitlines()[0].strip()
        if marker(result["stdout"], "BOOT_ID") else "",
        "boot_time": marker(result["stdout"], "BOOT_TIME").splitlines()[0].strip()
        if marker(result["stdout"], "BOOT_TIME") else "",
        "remote_time_start": marker(result["stdout"], "REMOTE_TIME_START").splitlines()[0].strip()
        if marker(result["stdout"], "REMOTE_TIME_START") else "",
        "remote_time_end": marker(result["stdout"], "REMOTE_TIME_END").splitlines()[0].strip()
        if marker(result["stdout"], "REMOTE_TIME_END") else "",
        "local_started_epoch": result.get("local_started_epoch", 0),
        "local_finished_epoch": result.get("local_finished_epoch", 0),
        "ztp_log": marker(result["stdout"], "ZTP_LOG"),
        "ztp_log_pointer_state": marker(
            result["stdout"], "ZTP_LOG_POINTER_STATE"
        ).splitlines()[0].strip()
        if marker(result["stdout"], "ZTP_LOG_POINTER_STATE") else "",
        "ztp_log_mtime": marker(result["stdout"], "ZTP_LOG_MTIME").splitlines()[0].strip()
        if marker(result["stdout"], "ZTP_LOG_MTIME") else "",
        "ifreload_log": marker(result["stdout"], "IFRELOAD"),
        "failed_yaml": marker(result["stdout"], "FAILED_YAML"),
        "host_key_refreshed": host_key_refreshed,
        "refreshed_host_key_targets": refreshed_targets,
        "host_key_commands": host_key_commands(device, stderr, known_hosts)
        if kind == "host_key_changed" else [],
    }


def yaml_null_paths(text: str) -> list[str]:
    body = "\n".join(line for line in text.splitlines() if not line.startswith("__FILE__="))
    if not body.strip():
        return []
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(body)
    except Exception:
        return []
    found: list[str] = []
    def visit(value: Any, path: str) -> None:
        if value is None:
            found.append(path or "<root>")
        elif isinstance(value, dict):
            for key, child in value.items():
                visit(child, f"{path}.{key}" if path else str(key))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")
    visit(data, "")
    return found[:30]


_ZTP_LOG_TIMESTAMP_PATTERN = (
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:Z|[+-]\d{2}:\d{2})?"
)


def _parse_ztp_log_timestamp(value: str, legacy_timezone: dt.tzinfo) -> str:
    """Normalize RFC3339 UTC and legacy offset-less bootstrap timestamps."""
    normalized = str(value or "").strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=legacy_timezone)
    return parsed.isoformat(timespec="seconds")


def ztp_completion_timestamp(log_text: str, source_timezone: dt.tzinfo) -> str:
    """Extract the successful provision marker timestamp from either log format."""
    matches = re.findall(
        rf"(?m)^\[({_ZTP_LOG_TIMESTAMP_PATTERN})\]\s+"
        r"\[ZTP\]\s+(?:Cumulus|NVOS) provision complete\s*$",
        log_text or "",
    )
    if not matches:
        return ""
    return _parse_ztp_log_timestamp(matches[-1], source_timezone)


def ztp_event_timestamp(
    log_text: str, marker_pattern: str, source_timezone: dt.tzinfo,
) -> str:
    """Return the last timestamp whose ZTP log message matches marker_pattern."""
    matches = []
    expression = re.compile(marker_pattern, re.IGNORECASE)
    for line in (log_text or "").splitlines():
        match = re.match(
            rf"^\[({_ZTP_LOG_TIMESTAMP_PATTERN})\]\s+(.*)$", line,
        )
        if match and expression.search(match.group(2)):
            matches.append(match.group(1))
    if not matches:
        return ""
    return _parse_ztp_log_timestamp(matches[-1], source_timezone)


def analyze_switch(
    device: dict[str, Any], result: dict[str, Any],
    source_timezone: dt.tzinfo = dt.timezone.utc,
) -> None:
    kind = result["kind"]
    observed_at = str(result.get("observed_at") or now_local().isoformat(timespec="seconds"))
    device["observed_at"] = observed_at
    device["ip_probe"] = {
        "candidates": list(device.get("ssh_ips", [device.get("ip", "")])),
        "interfaces": dict(device.get("ssh_interfaces", {})),
        "connected_ip": str(result.get("connected_ip") or ""),
        "attempts": list(result.get("attempts") or []),
    }
    device["time_sync"] = {
        "status": "unknown",
        "detail": "尚未通过 SSH 身份校验，不能信任远端时间",
        "checked_at": observed_at,
    }
    if kind != "ok":
        status = "failed" if kind in {"host_key_changed", "authentication_failed"} else "unknown"
        set_stage(device, "ssh", status, kind, observed_at)
        if kind == "host_key_changed":
            fingerprint_match = re.search(r"fingerprint.*?\b(SHA256:[A-Za-z0-9+/=]+)",
                                          result["stderr"], re.I | re.S)
            fingerprint = fingerprint_match.group(1) if fingerprint_match else ""
            device["issues"].append({
                "code": "SSH_HOST_KEY_CHANGED", "severity": "failed",
                "message": "SSH 主机密钥已变化；设备重建或地址复用时常见，但应先核对新指纹。"
                           + (f" 远端报告指纹: {fingerprint}" if fingerprint else ""),
                "observed_fingerprint": fingerprint,
                "commands": result["host_key_commands"],
                "timestamp": observed_at,
            })
        elif device.get("unbound_identity") and kind == "authentication_failed":
            device["issues"].append({
                "code": "CONSOLE_INITIAL_PASSWORD_REQUIRED",
                "severity": "failed",
                "message": (
                    "动态 DHCP 地址可达，但项目公钥无法登录。首次 bootstrap 可能尚未完成，"
                    "或没有成功安装任何公钥；需从 console 完成初始账号处理或重新执行 "
                    "bootstrap，自动化不会尝试交互式改密。"
                ),
                "timestamp": observed_at,
            })
        else:
            device["issues"].append({
                "code": kind.upper(), "severity": "warning", "message": result["stderr"] or kind,
                "timestamp": observed_at,
            })
        return
    connected_ip = str(result.get("connected_ip") or device.get("ip") or "")
    expected_hostname = str(device.get("hostname") or "").strip()
    remote_hostname = str(result.get("remote_hostname") or "").strip()
    expected_short = expected_hostname.split(".", 1)[0].casefold()
    remote_short = remote_hostname.split(".", 1)[0].casefold()
    candidate_identity = device.get("candidate_identity") or {}
    expected_interface, expected_mac = candidate_identity.get(
        connected_ip,
        ("eth0", str(device.get("mac_plain") or "")),
    )
    expected_interface = str(expected_interface or "eth0")
    expected_mac = str(expected_mac or "")
    remote_macs = {
        "eth0": normalize_mac(str(result.get("remote_eth0_mac") or "")),
        "eth1": normalize_mac(str(result.get("remote_eth1_mac") or "")),
    }
    remote_interface_macs = {
        str(interface): normalize_mac(str(mac))
        for interface, mac in (result.get("remote_interface_macs") or {}).items()
        if re.fullmatch(r"[0-9a-f]{12}", normalize_mac(str(mac)))
    }
    if expected_interface == "dhcp":
        allowed_interfaces = (
            ("eth0", "eth1")
            if str(device.get("platform_family") or "").casefold() == "nvos"
            else ("eth0",)
        )
        matched_interfaces = [
            interface for interface in allowed_interfaces
            if expected_mac and remote_macs.get(interface) == expected_mac
        ]
        connected_interface = matched_interfaces[0] if len(matched_interfaces) == 1 else ""
    else:
        connected_interface = expected_interface
        matched_interfaces = (
            [expected_interface]
            if expected_mac and remote_macs.get(expected_interface) == expected_mac
            else []
        )
    transit_addresses = set(device.get("ztp_transport_ips") or [])
    transit_holder_mac = normalize_mac(str(
        (device.get("ztp_transport_holders") or {}).get(connected_ip, "")
    ))
    transit_interfaces: list[str] = []
    if connected_ip in transit_addresses:
        transit_interfaces = [
            interface for interface, mac in remote_interface_macs.items()
            if transit_holder_mac and mac == transit_holder_mac
        ]
        if len(transit_interfaces) == 1:
            connected_interface = f"ZTP transit ({transit_interfaces[0]})"
            device["ip_probe"]["interfaces"][connected_ip] = connected_interface
    device["ip_probe"]["connected_interface"] = connected_interface
    transitional = (
        connected_ip in set(device.get("dynamic_lease_ips") or [])
        or connected_ip in transit_addresses
    )
    hostname_may_be_unconfigured = (
        bool(expected_mac)
        and (
            bool(device.get("dynamic_dhcp"))
            or transitional
            or bool(device.get("unbound_identity"))
        )
    )
    identity_errors = []
    if not remote_short:
        identity_errors.append((
            "HOSTNAME_NOT_OBTAINED", "已通过 IP 登录，但未能从交换机取得 hostname。",
        ))
    elif (expected_short and remote_short != expected_short
          and not hostname_may_be_unconfigured):
        identity_errors.append((
            "HOSTNAME_MISMATCH",
            f"通过 {connected_ip} 登录后取得 hostname={remote_hostname!r}，"
            f"与 CSV hostname={device.get('hostname', '')!r} 不一致。",
        ))
    if expected_mac and len(matched_interfaces) != 1:
        observed = ", ".join(
            f"{name}={value or 'unknown'}" for name, value in remote_macs.items()
        )
        identity_errors.append((
            "MANAGEMENT_MAC_MISMATCH",
            f"通过 {connected_ip} 登录后取得 {observed}；"
            f"与 DHCP/清单期望 {expected_interface} MAC={expected_mac} 不唯一匹配。",
        ))
    if connected_ip in transit_addresses and len(transit_interfaces) != 1:
        observed = ", ".join(
            f"{name}={value}" for name, value in sorted(remote_interface_macs.items())
        ) or "未取得接口 MAC"
        identity_errors.append((
            "ZTP_TRANSIT_HOLDER_MAC_MISMATCH",
            f"通过临时 ZTP transit IP {connected_ip} 登录后，远端接口为 {observed}；"
            f"当前 DHCP holder MAC={transit_holder_mac or 'unknown'} 未唯一匹配。",
        ))
    if identity_errors:
        set_stage(device, "ssh", "failed", "设备身份校验失败", observed_at)
        for code, message in identity_errors:
            device["issues"].append({
                "code": code, "severity": "failed", "message": message,
                "timestamp": observed_at,
            })
        return

    try:
        local_started = float(result.get("local_started_epoch") or 0)
        local_finished = float(result.get("local_finished_epoch") or 0)
        remote_started = float(result.get("remote_time_start") or 0)
        remote_finished = float(result.get("remote_time_end") or 0)
    except (TypeError, ValueError):
        local_started = local_finished = remote_started = remote_finished = 0.0
    if (
        all(math.isfinite(value) for value in (
            local_started, local_finished, remote_started, remote_finished,
        ))
        and
        local_started > 0
        and local_finished >= local_started
        and remote_started > 0
        and remote_finished >= remote_started
    ):
        # NTP-style four-timestamp estimate.  The uncertainty removes time
        # spent executing the remote probe, so collecting logs does not look
        # like clock drift.
        offset_seconds = (
            (remote_started - local_started)
            + (remote_finished - local_finished)
        ) / 2.0
        uncertainty_seconds = max(
            0.001,
            ((local_finished - local_started) - (remote_finished - remote_started))
            / 2.0,
        )
        synchronized = abs(offset_seconds) + uncertainty_seconds <= 5.0
        device["time_sync"] = {
            "status": "success" if synchronized else "warning",
            "offset_seconds": round(offset_seconds, 3),
            "uncertainty_seconds": round(uncertainty_seconds, 3),
            "checked_at": observed_at,
            "detail": (
                f"交换机相对管理服务器偏移 {offset_seconds:+.3f}s，"
                f"测量不确定度 ±{uncertainty_seconds:.3f}s"
            ),
        }
    else:
        device["time_sync"] = {
            "status": "unknown",
            "detail": "SSH 身份已验证，但远端未返回有效时间戳",
            "checked_at": observed_at,
        }
    if expected_short and remote_short != expected_short:
        transition_message = (
            f"通过 {connected_ip} 登录后取得 hostname={remote_hostname!r}；"
            + (
                "设备尚未绑定项目 hostname，MAC 已匹配，按 DHCP 发现身份继续收集。"
                if device.get("unbound_identity") else
                f"尚未变更为计划 hostname={device.get('hostname', '')!r}；"
                "MAC 已匹配，按 DHCP 过渡地址继续收集。"
            )
        )
        device["issues"].append({
            "code": "HOSTNAME_TRANSITION", "severity": "warning",
            "message": transition_message,
            "timestamp": observed_at,
        })
    ssh_detail = f"已通过 {connected_ip} 收集交换机日志并通过身份校验"
    if result.get("host_key_refreshed"):
        ssh_detail += "；AIR reset 后的旧 host key 已自动刷新"
    set_stage(device, "ssh", "success", ssh_detail, observed_at)
    if device.get("unbound_identity"):
        # A successful BatchMode login with the management key is stronger
        # evidence than merely seeing a public-key HTTP GET in Apache logs.
        device["access_ready"] = True
        set_stage(
            device, "ssh_keys", "success",
            "管理服务器公钥已通过实际免密 SSH 登录验证", observed_at,
        )
    # Boot identity is valid SSH evidence even before the new ZTP log appears.
    # Persist it before the early return so round detection does not fall back to
    # ordinary DHCP renewals while a freshly rebooted switch is still starting.
    device["boot_id"] = str(result.get("boot_id") or "")
    device["boot_time"] = str(result.get("boot_time") or "")
    log = result["ztp_log"]
    device["ztp_log_stage_names"] = []
    device["ztp_log_mtime"] = ""
    device["ztp_log_current_boot"] = False
    device["ztp_log_sha256"] = ""
    log_pointer_state = str(result.get("ztp_log_pointer_state") or "")
    if log_pointer_state == "invalid":
        device["issues"].append({
            "code": "ZTP_LOG_POINTER_INVALID", "severity": "failed",
            "message": (
                "持久 ZTP 日志 latest-log 指针不安全或无效；已拒绝按 mtime "
                "猜测本轮日志。"
            ),
            "timestamp": observed_at,
        })
        return
    if not log:
        device["issues"].append({"code": "ZTP_LOG_NOT_FOUND", "severity": "warning",
                                 "message": "SSH 成功，但未找到持久 ZTP 日志（也没有旧版 home 日志）。",
                                 "timestamp": observed_at})
        return
    device["ztp_log_sha256"], _log_complete = ztp_log_evidence(log)
    completion_time = ztp_completion_timestamp(log, source_timezone)
    try:
        log_mtime_epoch = int(str(result.get("ztp_log_mtime") or "0"))
    except (TypeError, ValueError):
        log_mtime_epoch = 0
    # Completion is optional while a new ZTP is still running.  Parse the two
    # clocks independently so a missing completion marker cannot erase a valid
    # Linux boot epoch and let an incomplete log from the previous boot through
    # the stale-log gate below.
    try:
        completion_epoch = dt.datetime.fromisoformat(completion_time).timestamp()
    except (TypeError, ValueError):
        completion_epoch = 0
    try:
        boot_epoch = int(str(result.get("boot_time") or "0"))
    except (TypeError, ValueError):
        boot_epoch = 0
    if log_mtime_epoch > 0:
        device["ztp_log_mtime"] = dt.datetime.fromtimestamp(
            log_mtime_epoch, tz=dt.timezone.utc,
        ).isoformat(timespec="seconds")
        device["ztp_log_current_boot"] = bool(
            boot_epoch and log_mtime_epoch >= boot_epoch
        )
    stale_log = bool(
        boot_epoch
        and (
            (log_mtime_epoch and log_mtime_epoch < boot_epoch)
            or (not log_mtime_epoch and completion_epoch and completion_epoch < boot_epoch)
        )
    )
    if stale_log:
        device["issues"].append({
            "code": "STALE_ZTP_LOG_AFTER_REBOOT", "severity": "warning",
            "message": (
                "设备本次启动时间晚于最新 ZTP 完成日志；已忽略上一轮完成状态，"
                "等待本轮 ZTP 产生新日志。"
            ),
            "timestamp": observed_at,
        })
        return

    log_stage_names: set[str] = set()

    def set_log_stage(
        name: str, status: str, detail: str, timestamp: str = "",
    ) -> None:
        """Record both the stage value and its latest-device-log provenance."""
        set_stage(device, name, status, detail, timestamp)
        log_stage_names.add(name)

    # Apache access logs are windowed/rotated, while the device's latest ZTP log
    # is durable evidence that the bootstrap was downloaded and executed. Do not
    # let a completed device regress to pending when its HTTP event ages out.
    if device["stages"]["bootstrap"]["status"] == "pending":
        set_log_stage(
            "bootstrap", "success", "已由交换机 ZTP 日志确认 bootstrap 执行",
            ztp_event_timestamp(log, r"ZTP START", source_timezone),
        )
    elif "ZTP START" in log:
        # The server-side HTTP event may already be newer; retain its timestamp
        # while recording that this same device log independently proves it.
        log_stage_names.add("bootstrap")
    if "Network check passed" in log:
        set_log_stage("network", "success", "ZTP 网络检查通过",
                      ztp_event_timestamp(log, r"Network check passed", source_timezone))
    elif "Network check failed" in log or "Cannot reach" in log:
        set_log_stage("network", "failed", "ZTP 无法访问管理服务器",
                      ztp_event_timestamp(log, r"Network check failed|Cannot reach", source_timezone))
    if "Version matched" in log:
        set_log_stage("version", "success", "运行版本匹配",
                      ztp_event_timestamp(log, r"Version matched", source_timezone))
    elif "Version mismatch, but image upgrade is disabled" in log:
        set_log_stage("version", "warning", "版本不匹配，已按 no-upgrade 继续",
                      ztp_event_timestamp(log, r"Version mismatch, but image upgrade is disabled", source_timezone))
    elif "Version mismatch, install image" in log:
        set_log_stage("version", "running", "正在安装目标镜像",
                      ztp_event_timestamp(log, r"Version mismatch, install image", source_timezone))
    elif (
        str(device.get("type") or "").casefold() in {"ib", "nvl", "pending_ib", "pending_nvl", "pending_nvos"}
        and "NVOS provision complete" in log
    ):
        set_log_stage(
            "version", "skipped",
            "NVOS bootstrap 不执行 Cumulus 镜像版本检查，按设计跳过",
            ztp_event_timestamp(log, r"NVOS provision complete", source_timezone),
        )
    if "Load per-MAC config:" in log:
        set_log_stage("config_http", "success", "交换机已下载专用 YAML",
                      ztp_event_timestamp(log, r"Load per-MAC config:", source_timezone))
    if "MAC cfg not found" in log:
        if "Default config:" in log and "patch and save complete" in log:
            missing_time = ztp_event_timestamp(log, r"MAC cfg not found", source_timezone)
            default_time = ztp_event_timestamp(log, r"Default config:.*(?:apply|patch) and save complete", source_timezone)
            set_log_stage("config_http", "warning", "无专用 YAML，已按 bootstrap 设计使用默认配置", missing_time)
            set_log_stage(
                "config_apply", "warning",
                "无设备专属 YAML，默认配置 patch/save 成功", default_time,
            )
            device["issues"].append({"code": "DEFAULT_CONFIG_USED", "severity": "warning",
                                     "message": (
                                         "设备没有专属 MAC YAML；ZTP 已成功回退并应用默认配置，"
                                         "因此 YAML Apply 与总体状态按警告显示。"
                                     ),
                                     "timestamp": missing_time or default_time})
        else:
            missing_time = ztp_event_timestamp(log, r"MAC cfg not found", source_timezone)
            set_log_stage("config_http", "failed", "专用 YAML 不存在，且未确认默认配置成功", missing_time)
            set_log_stage("config_apply", "warning", "正在或尝试回退默认配置", missing_time)
            device["issues"].append({"code": "MAC_CONFIG_NOT_FOUND", "severity": "warning",
                                     "message": "未找到按 MAC 发布的 YAML，也未看到默认配置成功记录。",
                                     "timestamp": missing_time})
    if "Dedicated config:" in log and "apply and save complete" in log:
        set_log_stage("config_apply", "success", "专用 YAML apply/save 成功",
                      ztp_event_timestamp(log, r"Dedicated config:.*apply and save complete", source_timezone))
    if "Baseline identity config:" in log and "patch and save complete" in log:
        baseline_time = ztp_event_timestamp(
            log, r"Baseline identity config:.*patch and save complete", source_timezone,
        )
        set_log_stage(
            "config_apply", "warning",
            "主机名专属 baseline 已应用：内容来自默认配置，仅增加 AIR hostname",
            baseline_time,
        )
        device["issues"].append({
            "code": "AIR_BASELINE_CONFIG_USED", "severity": "warning",
            "message": (
                "该 AIR-only 设备没有 Production 全量配置；load 已按 AIR JSON MAC "
                "发布 default-derived hostname baseline。ZTP 已成功应用该 baseline，"
                "但业务接口配置仍需在设备转为正式项目设备后补齐。"
            ),
            "timestamp": baseline_time,
        })
    if "MAC config apply failed" in log:
        detail = "专用 YAML apply 失败，bootstrap 已回退默认配置"
        failure_time = ztp_event_timestamp(log, r"MAC config apply failed", source_timezone)
        set_log_stage("config_apply", "failed", detail, failure_time)
        diagnostics = []
        combined = result["ifreload_log"] + "\n" + result["failed_yaml"]
        if re.search(r"Invalid file|values must not be ['\"]?null", combined, re.I):
            diagnostics.append("YAML 含 NVUE 不接受的 null set 值")
        missing_ports = sorted(set(re.findall(r"(?:slave|interface)\s+(swp\S+?),?\s+(?:does not exist|not found)", combined, re.I)))
        if missing_ports:
            diagnostics.append("配置引用不存在端口: " + ", ".join(missing_ports))
        if "Unable to restart services" in combined or "ifreload-nvue.service failed" in combined:
            diagnostics.append("ifreload-nvue 服务重启失败")
        nulls = yaml_null_paths(result["failed_yaml"])
        if nulls:
            diagnostics.append("检测到 null 路径: " + ", ".join(nulls))
        device["issues"].append({
            "code": "YAML_APPLY_FAILED", "severity": "failed", "message": detail,
            "diagnostics": diagnostics or ["交换机未提供更详细的 NVUE/ifreload 错误日志"],
            "retained_yaml": re.search(r"__FILE__=(.+)", result["failed_yaml"] or "").group(1)
            if re.search(r"__FILE__=(.+)", result["failed_yaml"] or "") else "",
            "timestamp": failure_time,
        })
    key_count = len(re.findall(r"SSH public key installed:", log))
    if "ACCESS_READY:" in log or key_count:
        key_detail = (
            f"日志显示安装 {key_count} 个公钥文件" if key_count
            else "bootstrap 已确认至少安装一个有效 SSH 公钥"
        )
        set_log_stage("ssh_keys", "success", key_detail,
                      ztp_event_timestamp(
                          log, r"ACCESS_READY:|SSH public key installed:", source_timezone,
                      ))
    elif "ACCESS_NOT_READY:" in log or "No non-empty SSH public key" in log:
        if device.get("access_ready"):
            set_log_stage(
                "ssh_keys", "warning",
                "本轮 bootstrap 未下载到公钥，但管理服务器现有 key 已实际登录成功",
                observed_at,
            )
        else:
            set_log_stage("ssh_keys", "failed", "未安装有效公钥",
                          ztp_event_timestamp(
                              log, r"ACCESS_NOT_READY:|No non-empty SSH public key",
                              source_timezone,
                          ))
    if "provision complete" in log and "ZTP FINISH" in log:
        config_state = device["stages"]["config_apply"]["status"]
        set_log_stage("complete", "warning" if config_state in {"failed", "warning"} else "success",
                      "bootstrap 已结束" + ("，但专用配置未成功" if config_state in {"failed", "warning"} else ""),
                      completion_time)
    device["ztp_log_stage_names"] = sorted(log_stage_names)


def finalize_device(device: dict[str, Any]) -> None:
    statuses = [device["stages"][name]["status"] for name in STAGE_NAMES]
    try:
        current_round = max(1, int(device.get("ztp_round", 1)))
    except (TypeError, ValueError):
        current_round = 1
    done = sum(
        device["stages"][name]["status"] in {"success", "warning", "skipped"}
        and int(device["stages"][name].get("success_index") or 0) == current_round
        for name in STAGE_NAMES
    )
    device["progress"] = {"done": done, "total": len(STAGE_NAMES),
                          "percent": round(done * 100 / len(STAGE_NAMES))}
    if any(value == "failed" for value in statuses):
        device["overall"] = "failed"
    elif any(value == "warning" for value in statuses) or device["issues"]:
        device["overall"] = "warning"
    elif (done == len(STAGE_NAMES)
          and device["stages"]["complete"]["status"] == "success"
          and int(device["stages"]["complete"].get("success_index") or 0)
          == current_round):
        device["overall"] = "success"
    elif any(value in {"success", "running"} for value in statuses):
        device["overall"] = "running"
    else:
        device["overall"] = "pending"


def md_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(report: dict[str, Any]) -> str:
    services = report["services"]
    lines = [
        f"# ZTP 监控报告：{report['project']}", "",
        f"生成时间：{report['generated_at']}  ",
        f"观察窗口：最近 {report['since_minutes']} 分钟", "",
        "## 管理服务", "",
        "| 服务 | active | enabled |", "|---|---|---|",
    ]
    for name, value in services.items():
        lines.append(f"| {name} | {md_cell(value['active'])} | {md_cell(value['enabled'])} |")
    lines += ["", "## 设备进度", "",
              "| 设备 | 类型 | IP | DHCP | Bootstrap | YAML 下载 | SSH | YAML Apply | Key | 完成 | 进度 | 总体 |",
              "|---|---|---|---|---|---|---|---|---|---|---:|---|"]
    for device in report["devices"]:
        s = device["stages"]
        values = [device["hostname"], device["type"], device["ip"],
                  STATUS_TEXT[s["dhcp"]["status"]], STATUS_TEXT[s["bootstrap"]["status"]],
                  STATUS_TEXT[s["config_http"]["status"]], STATUS_TEXT[s["ssh"]["status"]],
                  STATUS_TEXT[s["config_apply"]["status"]], STATUS_TEXT[s["ssh_keys"]["status"]],
                  STATUS_TEXT[s["complete"]["status"]], f"{device['progress']['percent']}%",
                  STATUS_TEXT.get(device["overall"], device["overall"])]
        lines.append("| " + " | ".join(md_cell(v) for v in values) + " |")
    failed = [d for d in report["devices"] if d["issues"]]
    lines += ["", "## 诊断", ""]
    if not failed:
        lines.append("未发现已知问题。")
    for device in failed:
        lines += [f"### {device['hostname']} ({device['ip']})", ""]
        for issue in device["issues"]:
            issue_time = issue.get("timestamp") or "时间未记录"
            lines.append(f"- `{issue['code']}`（{issue_time}）：{issue['message']}")
            for detail in issue.get("diagnostics", []):
                lines.append(f"  - {detail}")
            if issue.get("commands"):
                lines += ["  - 核对设备控制台显示的新指纹后执行：", "", "```bash"]
                lines.extend(issue["commands"])
                lines += ["```", ""]
    if report.get("unmatched_interactions"):
        lines += ["", "## 未在设备清单中匹配的 ZTP 交互", "",
                  "| 标识 | 来源 | 事件 | 最后时间 |", "|---|---|---|---|"]
        for item in report["unmatched_interactions"]:
            lines.append("| " + " | ".join(md_cell(item.get(name, "")) for name in
                         ("identity", "source", "event", "timestamp")) + " |")
    if report["collection_errors"]:
        lines += ["", "## 采集警告", ""]
        lines.extend(f"- {item}" for item in report["collection_errors"])
    return "\n".join(lines).rstrip() + "\n"


def snapshot_device_state(report: dict[str, Any]) -> dict[str, Any]:
    """Return only stateful fields; timestamps and changing log text are ignored."""
    devices = []
    for device in report.get("devices", []):
        stages = device.get("stages") or {}
        progress = device.get("progress") or {}
        devices.append({
            "hostname": device.get("hostname", ""),
            "type": device.get("type", ""),
            "ip": device.get("ip", ""),
            "mac": device.get("mac", ""),
            "template": device.get("template", ""),
            "dynamic_dhcp": bool(device.get("dynamic_dhcp")),
            "unbound_identity": bool(device.get("unbound_identity")),
            "managed_ztp": bool(device.get("managed_ztp")),
            "platform_family": device.get("platform_family", ""),
            "access_ready": bool(device.get("access_ready")),
            "promotion_pending": bool(device.get("promotion_pending")),
            "overall": device.get("overall", ""),
            "ztp_round": device.get("ztp_round", 1),
            "progress": progress.get("percent"),
            "stages": {
                name: {
                    "status": (stages.get(name) or {}).get("status", ""),
                    "success_index": (stages.get(name) or {}).get("success_index", 0),
                }
                for name in STAGE_NAMES
            },
            "issues": sorted({
                str(issue.get("code", ""))
                for issue in device.get("issues", []) if isinstance(issue, dict)
            }),
        })
    devices.sort(key=lambda item: (item["hostname"].casefold(), item["ip"]))
    return {"devices": devices}


def _previous_report(output_root: Path) -> Optional[dict[str, Any]]:
    """Load the report currently referenced by latest, if it is valid."""
    directory = _latest_snapshot_dir(output_root)
    if directory is None:
        return None
    try:
        report = json.loads((directory / "report.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return report if isinstance(report, dict) else None


def _latest_dhcp_cycle_marker(device: dict[str, Any]) -> str:
    """Return a stable marker for the newest DHCP boot interaction."""
    candidates = []
    for event in device.get("events", []):
        if not isinstance(event, dict) or event.get("source") != "dhcp":
            continue
        # DHCPREQUEST is also emitted by an ordinary lease renewal and therefore
        # is not a ZTP-cycle boundary.  A real reboot is independently proven by
        # boot_id/boot_time; pre-SSH DHCP evidence uses DISCOVER only.
        if str(event.get("kind") or "").upper() != "DHCPDISCOVER":
            continue
        timestamp = str(event.get("timestamp") or "")
        if timestamp:
            candidates.append(timestamp)
    return max(candidates, default="")


def _timestamp_after(left: str, right: str) -> bool:
    try:
        return dt.datetime.fromisoformat(left) > dt.datetime.fromisoformat(right)
    except (TypeError, ValueError):
        return bool(left and right and left > right)


def _timestamp_at_or_after(left: str, right: str) -> bool:
    if not right:
        return bool(left)
    try:
        return dt.datetime.fromisoformat(left) >= dt.datetime.fromisoformat(right)
    except (TypeError, ValueError):
        return bool(left and left >= right)


def _timestamp_near_boundary(left: str, boundary: str, seconds: int = 30) -> bool:
    """Allow small switch-vs-server clock skew around a manual trigger."""
    try:
        event_time = dt.datetime.fromisoformat(left)
        boundary_time = dt.datetime.fromisoformat(boundary)
        return event_time >= boundary_time - dt.timedelta(seconds=max(seconds, 0))
    except (TypeError, ValueError):
        return False


def _timestamp_within_operation_window(
    event: str, started_at: str, finished_at: str, seconds: int = 30,
) -> bool:
    """Accept an event emitted while one successfully accepted command ran."""
    event_time = _aware_event_time(event)
    start_time = _aware_event_time(started_at)
    finish_time = _aware_event_time(finished_at)
    if event_time is None or start_time is None or finish_time is None:
        return False
    if finish_time < start_time:
        return False
    tolerance = dt.timedelta(seconds=max(0, seconds))
    return start_time - tolerance <= event_time <= finish_time + tolerance


def _boot_started_after(device: dict[str, Any], boundary: str) -> bool:
    """Return true when the observed Linux boot started after an operation."""
    try:
        boot_epoch = int(str(device.get("boot_time") or "0"))
        boundary_epoch = dt.datetime.fromisoformat(boundary).timestamp()
        return boot_epoch > boundary_epoch
    except (TypeError, ValueError, OSError):
        return False


def _boot_started_near_boundary(
    device: dict[str, Any], boundary: str, seconds: int = 30,
) -> Optional[bool]:
    """Compare the absolute boot epoch with an operation boundary.

    ``None`` means the switch did not provide a usable boot epoch.  A definite
    ``False`` is important: a changed boot ID whose boot predates the accepted
    reset belongs to an independently observed reboot, not to this reset.
    """
    try:
        boot_epoch = int(str(device.get("boot_time") or "0"))
        if boot_epoch <= 0:
            return None
        boot_time = dt.datetime.fromtimestamp(
            boot_epoch, tz=dt.timezone.utc,
        ).isoformat(timespec="seconds")
    except (TypeError, ValueError, OSError, OverflowError):
        return None
    return _timestamp_near_boundary(boot_time, boundary, seconds)


def latest_manual_trigger_markers(output_root: Path) -> dict[str, dict[str, Any]]:
    """Return the newest accepted manual-ZTP boundary for each device.

    manual-ztp.py writes a durable per-device result only after the remote ZTP
    command has been accepted.  This marker is the cycle boundary for a manual
    run, which may not reboot the switch or emit another DHCP transaction.
    """
    markers: dict[str, dict[str, Any]] = {}
    result_paths = [
        path
        for directory in ("manual-trigger", "manual-reset")
        for path in (output_root / directory).glob("*/*/result.json")
    ]
    for path in result_paths:
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(result, dict) or result.get("state") != "triggered":
            continue
        hostname = str(result.get("hostname") or "").strip().casefold()
        # The operation is accepted only when the remote command returns
        # successfully.  Keep that return time as the durable cycle boundary,
        # but retain the command start separately: a synchronous ``ztp -r``
        # can finish its device log minutes before the SSH command returns.
        marker = str(result.get("finished_at") or result.get("started_at") or "").strip()
        command_started_at = str(
            result.get("command_started_at") or result.get("started_at") or marker
        ).strip()
        command_log_sha256 = str(
            result.get("command_ztp_log_sha256") or ""
        ).strip().lower()
        command_log_complete = result.get("command_ztp_complete") is True
        if not re.fullmatch(r"[0-9a-f]{64}", command_log_sha256):
            command_log_sha256 = ""
            command_log_complete = False
        # Compatibility for operations accepted before result.json carried the
        # digest.  trigger.log is root-written alongside this exact result and
        # contains the stdout of only this SSH command.  Read it boundedly and
        # fingerprint only timestamped bootstrap log() lines.
        if (
            "command_ztp_log_sha256" not in result
            and "command_ztp_complete" not in result
        ):
            trigger_log = path.with_name("trigger.log")
            try:
                if trigger_log.is_file() and trigger_log.stat().st_size <= 8 * 1024 * 1024:
                    command_log_sha256, command_log_complete = ztp_log_evidence(
                        trigger_log.read_text(encoding="utf-8", errors="replace")
                    )
            except OSError:
                command_log_sha256, command_log_complete = "", False
        if not hostname or not marker:
            continue
        previous = markers.get(hostname, {})
        if not previous or _timestamp_after(marker, previous.get("timestamp", "")):
            markers[hostname] = {
                "timestamp": marker,
                "trigger_source": str(result.get("trigger_source") or "manual_cli"),
                "trigger_id": str(result.get("trigger_id") or path.parent.name),
                "operation": str(result.get("operation") or "ztp"),
                "command_started_at": command_started_at,
                "finished_at": marker,
                "command_ztp_log_sha256": command_log_sha256,
                "command_ztp_complete": command_log_complete,
            }
    return markers


def assign_ztp_rounds(
    devices: list[dict[str, Any]], previous_report: Optional[dict[str, Any]],
    manual_markers: Optional[dict[str, Any]] = None,
) -> None:
    """Persist and increment per-device ZTP cycles across monitor snapshots.

    A changed Linux boot ID is authoritative once SSH works. During the early
    rebuild window, a DHCP interaction newer than the previous completion is
    enough to expose the next round without waiting for SSH.
    """
    previous_devices = {
        str(item.get("hostname") or "").casefold(): item
        for item in (previous_report or {}).get("devices", [])
        if isinstance(item, dict) and item.get("hostname")
    }
    previous_report_time = str((previous_report or {}).get("generated_at") or "")
    manual_markers = manual_markers or {}
    for device in devices:
        hostname_key = str(device.get("hostname") or "").casefold()
        previous = previous_devices.get(hostname_key)
        marker = _latest_dhcp_cycle_marker(device)
        manual_value = manual_markers.get(hostname_key) or {}
        if isinstance(manual_value, dict):
            manual_marker = str(manual_value.get("timestamp") or "")
            manual_source = str(manual_value.get("trigger_source") or "manual_cli")
            manual_trigger_id = str(manual_value.get("trigger_id") or "")
            manual_operation = str(manual_value.get("operation") or "ztp")
            manual_command_started = str(
                manual_value.get("command_started_at")
                or manual_value.get("started_at")
                or manual_marker
            )
            manual_command_finished = str(
                manual_value.get("finished_at") or manual_marker
            )
            manual_command_log_sha256 = str(
                manual_value.get("command_ztp_log_sha256") or ""
            )
            manual_command_complete = (
                manual_value.get("command_ztp_complete") is True
            )
        else:
            manual_marker = str(manual_value)
            manual_source = "manual_cli"
            manual_trigger_id = ""
            manual_operation = "ztp"
            manual_command_started = manual_marker
            manual_command_finished = manual_marker
            manual_command_log_sha256 = ""
            manual_command_complete = False
        if previous is None:
            device["ztp_round"] = 1
            device["cycle_marker"] = marker
            device["manual_cycle_marker"] = manual_marker
            device["cycle_started_at"] = manual_marker or marker
            device["trigger_source"] = manual_source if manual_marker else "automatic"
            device["trigger_id"] = manual_trigger_id if manual_marker else ""
            device["manual_operation"] = manual_operation if manual_marker else ""
            device["manual_command_started_at"] = (
                manual_command_started if manual_marker else ""
            )
            device["manual_command_finished_at"] = (
                manual_command_finished if manual_marker else ""
            )
            device["manual_command_ztp_log_sha256"] = (
                manual_command_log_sha256 if manual_marker else ""
            )
            device["manual_command_ztp_complete"] = bool(
                manual_marker and manual_command_complete
            )
            reset_current = bool(manual_marker and manual_operation == "reset")
            device["reset_boot_id_before"] = (
                str(device.get("boot_id") or "") if reset_current else ""
            )
            device["reset_reboot_observed"] = bool(
                reset_current and (
                    _boot_started_after(device, manual_marker)
                    or (marker and _timestamp_after(marker, manual_marker))
                )
            )
            continue
        try:
            previous_round = max(1, int(previous.get("ztp_round", 1)))
        except (TypeError, ValueError):
            previous_round = 1
        previous_marker = str(previous.get("cycle_marker") or "")
        previous_manual_marker = str(previous.get("manual_cycle_marker") or "")
        previous_source = str(previous.get("trigger_source") or "automatic")
        previous_trigger_id = str(previous.get("trigger_id") or "")
        previous_operation = str(previous.get("manual_operation") or "")
        promotion_started = bool(
            previous.get("dynamic_dhcp") and not device.get("dynamic_dhcp")
        )
        promotion_pending = (
            bool(device.get("promotion_pending"))
            or bool(previous.get("promotion_pending"))
            or promotion_started
        )
        current_boot = str(device.get("boot_id") or "")
        previous_boot = str(previous.get("boot_id") or "")
        previous_reset_boot = str(previous.get("reset_boot_id_before") or "")
        complete = previous.get("stages", {}).get("complete", {})
        previous_complete = str(complete.get("timestamp") or "") if isinstance(complete, dict) else ""
        boot_cycle = bool(current_boot and previous_boot and current_boot != previous_boot)
        dhcp_cycle = False
        new_cycle = boot_cycle
        if not new_cycle and marker and marker != previous_marker:
            dhcp_cycle = bool(
                (previous_marker and _timestamp_after(marker, previous_marker))
                or (not previous_marker and previous_complete
                    and _timestamp_after(marker, previous_complete))
            )
            new_cycle = dhcp_cycle
        manual_cycle = False
        same_manual_trigger = bool(
            manual_trigger_id and previous_trigger_id
            and manual_trigger_id == previous_trigger_id
        )
        if manual_marker and manual_marker != previous_manual_marker and not same_manual_trigger:
            manual_cycle = bool(
                (previous_manual_marker
                 and _timestamp_after(manual_marker, previous_manual_marker))
                or (not previous_manual_marker and previous_report_time
                    and _timestamp_after(manual_marker, previous_report_time))
            )
            new_cycle = new_cycle or manual_cycle
        reset_cycle = manual_cycle and manual_operation == "reset"
        reset_in_progress = (
            previous_operation == "reset"
            and previous_source in {"manual_reset_web", "manual_reset_cli"}
            and not (
                isinstance(complete, dict)
                and complete.get("status") == "success"
                and int(complete.get("success_index") or 0) == previous_round
            )
        )
        if reset_in_progress and (boot_cycle or dhcp_cycle) and not manual_cycle:
            new_cycle = False
            boot_cycle = False
            dhcp_cycle = False
        device["ztp_round"] = 1 if reset_cycle else (
            previous_round + 1 if new_cycle else previous_round
        )
        device["cycle_marker"] = marker or previous_marker
        # Do not consume a marker that was not accepted as a new cycle.  This
        # matters when a monitor snapshot lands between operation start and
        # successful remote-command return.
        device["manual_cycle_marker"] = (
            manual_marker if manual_cycle else previous_manual_marker
        )
        if manual_cycle:
            device["cycle_started_at"] = manual_marker
            device["trigger_source"] = manual_source
            device["trigger_id"] = manual_trigger_id
            device["manual_operation"] = manual_operation
            device["manual_command_started_at"] = manual_command_started
            device["manual_command_finished_at"] = manual_command_finished
            device["manual_command_ztp_log_sha256"] = manual_command_log_sha256
            device["manual_command_ztp_complete"] = manual_command_complete
        elif dhcp_cycle:
            device["cycle_started_at"] = marker
            device["trigger_source"] = "automatic"
            device["trigger_id"] = ""
            device["manual_operation"] = ""
            device["manual_command_started_at"] = ""
            device["manual_command_finished_at"] = ""
            device["manual_command_ztp_log_sha256"] = ""
            device["manual_command_ztp_complete"] = False
        elif boot_cycle:
            try:
                device["cycle_started_at"] = dt.datetime.fromtimestamp(
                    int(device.get("boot_time") or 0), tz=dt.timezone.utc,
                ).isoformat(timespec="seconds")
            except (TypeError, ValueError, OSError):
                device["cycle_started_at"] = str(device.get("observed_at") or "")
            device["trigger_source"] = "automatic"
            device["trigger_id"] = ""
            device["manual_operation"] = ""
            device["manual_command_started_at"] = ""
            device["manual_command_finished_at"] = ""
            device["manual_command_ztp_log_sha256"] = ""
            device["manual_command_ztp_complete"] = False
        else:
            device["cycle_started_at"] = str(previous.get("cycle_started_at") or "")
            device["trigger_source"] = previous_source
            device["trigger_id"] = previous_trigger_id
            device["manual_operation"] = previous_operation
            accepted_marker_reloaded = bool(
                manual_marker
                and manual_marker == previous_manual_marker
                and (
                    not manual_trigger_id
                    or not previous_trigger_id
                    or manual_trigger_id == previous_trigger_id
                )
            )
            device["manual_command_started_at"] = (
                manual_command_started if accepted_marker_reloaded else
                str(previous.get("manual_command_started_at") or "")
            )
            device["manual_command_finished_at"] = (
                manual_command_finished if accepted_marker_reloaded else
                str(previous.get("manual_command_finished_at") or "")
            )
            device["manual_command_ztp_log_sha256"] = (
                manual_command_log_sha256 if accepted_marker_reloaded else
                str(previous.get("manual_command_ztp_log_sha256") or "")
            )
            device["manual_command_ztp_complete"] = (
                manual_command_complete if accepted_marker_reloaded else
                previous.get("manual_command_ztp_complete") is True
            )

        # Changing from a default-config dynamic identity to a dedicated
        # static profile is a configuration-generation boundary, not by itself
        # another ZTP round.  Clear old success evidence until a real automatic
        # or manual ZTP applies the new profile; the next actual cycle keeps the
        # normal round/index semantics.
        if promotion_started and not new_cycle:
            device["ztp_round"] = previous_round
            device["cycle_started_at"] = str(
                device.get("observed_at") or previous_report_time or now_local().isoformat(
                    timespec="seconds"
                )
            )
            device["trigger_source"] = "inventory_promotion"
            device["trigger_id"] = ""
            device["manual_operation"] = ""
            device["manual_command_started_at"] = ""
            device["manual_command_finished_at"] = ""
            device["manual_command_ztp_log_sha256"] = ""
            device["manual_command_ztp_complete"] = False
        device["promotion_pending"] = promotion_pending

        # A factory-default request is accepted before its detached NVUE job
        # reboots the device.  Preserve the pre-reset boot ID and require a
        # changed boot ID or a DHCP ZTP event after the accepted command before
        # any old round-1 success can count as reset completion.  The baseline
        # survives snapshots where the switch is temporarily unreachable and
        # therefore has no current boot ID.
        if reset_cycle:
            reset_boot_before = previous_reset_boot or previous_boot or current_boot
            reset_boundary = manual_marker
            boot_boundary = _boot_started_near_boundary(device, reset_boundary)
            if current_boot and reset_boot_before:
                # Once SSH provides both IDs it is authoritative.  A DHCP
                # discover on the still-running pre-reset boot must not make
                # reset stages advance, and an independently changed boot that
                # predates the accepted command is not this reset generation.
                reset_reboot_observed = bool(
                    current_boot != reset_boot_before
                    and boot_boundary is not False
                )
            else:
                reset_reboot_observed = bool(
                    boot_boundary is True
                    or (marker and reset_boundary
                        and _timestamp_after(marker, reset_boundary))
                )
        elif device.get("manual_operation") == "reset":
            reset_boot_before = previous_reset_boot or previous_boot
            reset_boundary = str(device.get("cycle_started_at") or "")
            boot_boundary = _boot_started_near_boundary(device, reset_boundary)
            if current_boot and reset_boot_before:
                reset_reboot_observed = bool(
                    current_boot != reset_boot_before
                    and boot_boundary is not False
                )
            else:
                reset_reboot_observed = bool(
                    previous.get("reset_reboot_observed")
                    or boot_boundary is True
                    or (marker and reset_boundary
                        and _timestamp_after(marker, reset_boundary))
                )
        else:
            reset_boot_before = ""
            reset_reboot_observed = False
        device["reset_boot_id_before"] = reset_boot_before
        device["reset_reboot_observed"] = reset_reboot_observed


def assign_stage_success_indices(
    devices: list[dict[str, Any]], previous_report: Optional[dict[str, Any]],
) -> None:
    """Carry stage success history and advance only stages proven this round."""
    previous_devices = {
        str(item.get("hostname") or "").casefold(): item
        for item in (previous_report or {}).get("devices", [])
        if isinstance(item, dict) and item.get("hostname")
    }
    for device in devices:
        previous = previous_devices.get(str(device.get("hostname") or "").casefold(), {})
        previous_stages = previous.get("stages", {}) if isinstance(previous, dict) else {}
        try:
            current_round = max(1, int(device.get("ztp_round", 1)))
            previous_round = max(0, int(previous.get("ztp_round", 0)))
        except (TypeError, ValueError):
            current_round, previous_round = 1, 0
        boundary = str(device.get("cycle_started_at") or "")
        manual_current_cycle = (
            str(device.get("trigger_source") or "") in {
                "manual_web", "manual_cli", "manual_reset_web", "manual_reset_cli",
            }
            and bool(device.get("manual_cycle_marker"))
            and str(device.get("manual_cycle_marker") or "") == boundary
        )
        reset_current_cycle = (
            manual_current_cycle
            and str(device.get("manual_operation") or "") == "reset"
        )
        reset_reboot_observed = bool(device.get("reset_reboot_observed"))
        log_stage_names = {
            str(name) for name in (device.get("ztp_log_stage_names") or [])
            if str(name) in STAGE_NAMES
        }
        log_mtime = str(device.get("ztp_log_mtime") or "")
        reset_boot_before = str(device.get("reset_boot_id_before") or "")
        current_boot = str(device.get("boot_id") or "")
        if reset_boot_before and current_boot:
            boot_boundary = _boot_started_near_boundary(device, boundary)
            reset_generation_proven = bool(
                current_boot != reset_boot_before
                and boot_boundary is not False
            )
        else:
            # When an older report has no boot-ID baseline, retain the existing
            # reset-reboot gate and additionally require the device log's epoch
            # mtime to be at/near the accepted server-side operation boundary.
            reset_generation_proven = bool(
                reset_reboot_observed
                and log_mtime
                and _timestamp_near_boundary(log_mtime, boundary)
            )
        completed_log_bundle_current = bool(
            reset_current_cycle
            and reset_reboot_observed
            and reset_generation_proven
            and device.get("ztp_log_current_boot")
            and bool(log_mtime)
            and (not boundary or _timestamp_near_boundary(log_mtime, boundary))
            and "complete" in log_stage_names
        )
        manual_log_bundle_current = bool(
            manual_current_cycle
            and not reset_current_cycle
            and device.get("ztp_log_current_boot")
            and bool(log_mtime)
            and "complete" in log_stage_names
            and _timestamp_within_operation_window(
                log_mtime,
                str(device.get("manual_command_started_at") or ""),
                str(device.get("manual_command_finished_at") or boundary),
            )
        )
        command_log_sha256 = str(
            device.get("manual_command_ztp_log_sha256") or ""
        )
        device_log_sha256 = str(device.get("ztp_log_sha256") or "")
        operation_started = str(device.get("manual_command_started_at") or "")
        operation_finished = str(
            device.get("manual_command_finished_at") or boundary
        )
        http_evidence_current = all(
            device["stages"][stage_name].get("status")
            in {"success", "warning"}
            and _timestamp_within_operation_window(
                str(device["stages"][stage_name].get("timestamp") or ""),
                operation_started,
                operation_finished,
            )
            for stage_name in ("bootstrap", "config_http")
        )
        # ``ztp -r`` is synchronous, but a switch that has not yet converged
        # NTP can stamp every log line and the copied file minutes away from
        # the management-server operation window.  Bind the exact stdout of
        # this accepted SSH command to the exact durable device log instead of
        # trusting cross-host wall clocks.  Current-window bootstrap and YAML
        # HTTP evidence prevents a cached/old log from satisfying the round.
        manual_command_log_bundle_current = bool(
            manual_current_cycle
            and not reset_current_cycle
            and device.get("manual_command_ztp_complete") is True
            and re.fullmatch(r"[0-9a-f]{64}", command_log_sha256)
            and command_log_sha256 == device_log_sha256
            and device.get("ztp_log_current_boot")
            and "complete" in log_stage_names
            and http_evidence_current
        )
        manual_evidence_bundle_current = bool(
            manual_log_bundle_current or manual_command_log_bundle_current
        )
        promotion_pending = bool(device.get("promotion_pending"))
        for name in STAGE_NAMES:
            current = device["stages"][name]
            old = previous_stages.get(name, {}) if isinstance(previous_stages, dict) else {}
            try:
                old_index = max(0, int(old.get("success_index", 0)))
            except (TypeError, ValueError, AttributeError):
                old_index = 0
            if not old_index and isinstance(old, dict) and old.get("status") in {"success", "warning", "skipped"}:
                old_index = previous_round
            if reset_current_cycle:
                old_index = 0
            if promotion_pending:
                old_index = 0
            current_timestamp = str(current.get("timestamp") or "")
            current_success = current.get("status") in {"success", "warning", "skipped"}
            old_timestamp = str(old.get("timestamp") or "") if isinstance(old, dict) else ""
            manual_skew_evidence = (
                manual_current_cycle
                and current_success
                and bool(current_timestamp)
                and current_timestamp != old_timestamp
                and _timestamp_near_boundary(current_timestamp, boundary)
            )
            if reset_current_cycle:
                proven_this_round = current_success and reset_reboot_observed and (
                    not boundary
                    or _timestamp_at_or_after(current_timestamp, boundary)
                    or manual_skew_evidence
                    or (
                        completed_log_bundle_current
                        and name in log_stage_names
                    )
                )
            elif promotion_pending:
                proven_this_round = current_success and bool(boundary) and (
                    _timestamp_at_or_after(current_timestamp, boundary)
                    or manual_skew_evidence
                    or (
                        manual_evidence_bundle_current
                        and name in log_stage_names
                    )
                )
            else:
                proven_this_round = current_success and (
                    current_round == 1
                    or not boundary
                    or _timestamp_at_or_after(current_timestamp, boundary)
                    or manual_skew_evidence
                    or (
                        manual_evidence_bundle_current
                        and name in log_stage_names
                    )
                )
            if proven_this_round:
                current["success_index"] = current_round
            else:
                current["success_index"] = old_index
                if (str(device.get("manual_operation") or "") != "reset"
                        and not promotion_pending
                        and current.get("status") == "pending" and isinstance(old, dict)) \
                        and old.get("status") in {"success", "warning", "skipped"}:
                    device["stages"][name] = {
                        "status": old.get("status", "success"),
                        "detail": old.get("detail", ""),
                        "timestamp": old.get("timestamp", ""),
                        "success_index": old_index,
                    }

        # A successfully accepted manual ZTP reaches the bootstrap directly
        # through ``ztp -r`` (or its restricted helper), so that round has no
        # DHCP exchange.  Mark the deliberate bypass as an indexed completed
        # stage; failed/unaccepted trigger attempts never create this cycle.
        if (
            str(device.get("trigger_source") or "") in {"manual_web", "manual_cli"}
            and str(device.get("type") or "").casefold()
            in {"", "eth", "eth_spx", "spx", "air"}
        ):
            manual_marker = str(device.get("manual_cycle_marker") or "")
            cycle_started = str(device.get("cycle_started_at") or "")
            if manual_marker and cycle_started == manual_marker:
                device["stages"]["dhcp"] = stage(
                    "skipped", "手工 ZTP 直接执行 bootstrap，跳过 DHCP",
                    manual_marker, current_round,
                )

        complete = device["stages"]["complete"]
        # Completion closes the cycle but must not manufacture evidence for
        # earlier stages.  In particular an NVOS manual ZTP still uses DHCP;
        # an old DHCP success from round 1 must never be relabelled success 2.
        # Each stage advances only through the timestamp/boundary proof above;
        # Cumulus direct-bootstrap DHCP is the explicit indexed skip exception.

        dedicated = device["stages"].get("config_apply", {})
        dedicated_current = (
            dedicated.get("status") == "success"
            and int(dedicated.get("success_index") or 0) == current_round
            and "专用 YAML" in str(dedicated.get("detail") or "")
        )
        complete_current = (
            complete.get("status") == "success"
            and int(complete.get("success_index") or 0) == current_round
        )
        if promotion_pending and dedicated_current and complete_current:
            device["promotion_pending"] = False
        elif promotion_pending:
            device["issues"].append({
                "code": "STATIC_PROMOTION_PENDING", "severity": "warning",
                "message": (
                    "设备已进入专属静态清单，但尚未取得本次专属 YAML apply/完成证据；"
                    "请执行手工 ZTP 或 factory-default 重置。"
                ),
                "timestamp": boundary,
            })


def _latest_snapshot_dir(output_root: Path) -> Optional[Path]:
    latest = output_root / "latest"
    try:
        candidate = latest.resolve(strict=True)
        root = output_root.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if (candidate.parent == root and candidate.is_dir()
            and _SNAPSHOT_NAME_RE.fullmatch(candidate.name)):
        return candidate
    return None


def _snapshot_state_from_dir(directory: Optional[Path]) -> Optional[dict[str, Any]]:
    if directory is None:
        return None
    try:
        report = json.loads((directory / "report.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return snapshot_device_state(report) if isinstance(report, dict) else None


def _prune_snapshot_history(output_root: Path, keep: int = SNAPSHOT_RETENTION) -> list[Path]:
    snapshots = sorted(
        path for path in output_root.iterdir()
        if path.is_dir() and not path.is_symlink()
        and _SNAPSHOT_NAME_RE.fullmatch(path.name)
    )
    removed = []
    for path in snapshots[:-max(keep, 1)]:
        shutil.rmtree(path)
        removed.append(path)
    return removed


def write_report(report: dict[str, Any], output_root: Path,
                 switch_results: dict[str, dict[str, Any]],
                 server_logs: Optional[dict[str, str]] = None) -> Path:
    output_root.mkdir(parents=True, exist_ok=True)
    previous_dir = _latest_snapshot_dir(output_root)
    previous_state = _snapshot_state_from_dir(previous_dir)
    current_state = snapshot_device_state(report)
    unchanged = previous_state is not None and previous_state == current_state

    stamp = now_local().strftime("%Y%m%d_%H%M%S")
    run_dir = output_root / stamp
    suffix = 1
    while run_dir.exists():
        run_dir = output_root / f"{stamp}_{suffix}"
        suffix += 1
    raw_dir = run_dir / "raw" / "switches"
    raw_dir.mkdir(parents=True)
    server_dir = run_dir / "raw" / "server"
    server_dir.mkdir()
    for name, content in (server_logs or {}).items():
        (server_dir / f"{name}.log").write_text(content, encoding="utf-8")
    (run_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (run_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")
    with (run_dir / "devices.csv").open("w", newline="", encoding="utf-8") as handle:
        fields = ["hostname", "type", "ip", "mac", "ztp_round", "overall", "progress"] + list(STAGE_NAMES) + ["issues"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for device in report["devices"]:
            writer.writerow({
                "hostname": device["hostname"], "type": device["type"], "ip": device["ip"],
                "mac": device["mac"], "overall": device["overall"],
                "ztp_round": device.get("ztp_round", 1),
                "progress": f"{device['progress']['percent']}%",
                **{name: device["stages"][name]["status"] for name in STAGE_NAMES},
                "issues": "; ".join(issue["code"] for issue in device["issues"]),
            })
    for hostname, result in switch_results.items():
        device_dir = raw_dir / re.sub(r"[^A-Za-z0-9_.-]", "_", hostname)
        device_dir.mkdir()
        for key in ("ztp_log", "ifreload_log", "failed_yaml", "stderr"):
            (device_dir / f"{key}.log").write_text(result.get(key, "") + "\n", encoding="utf-8")
    latest = output_root / "latest"
    temporary = output_root / ".latest.tmp"
    try:
        temporary.unlink(missing_ok=True)
        temporary.symlink_to(run_dir.name)
        temporary.replace(latest)
    except OSError as exc:
        shutil.rmtree(run_dir, ignore_errors=True)
        raise ValueError(f"无法原子更新 ZTP latest：{exc}") from exc

    if unchanged and previous_dir is not None and previous_dir != run_dir:
        shutil.rmtree(previous_dir)
        log(
            f"[INFO] 设备状态无变化：快照时间推进为 {run_dir.name}，"
            f"已替换 {previous_dir.name}"
        )
    else:
        log(f"[INFO] 设备状态发生变化：保留新快照 {run_dir.name}")
    removed = _prune_snapshot_history(output_root)
    if removed:
        log(
            f"[CLEAN] ZTP 快照只保留最近 {SNAPSHOT_RETENTION} 个："
            + ", ".join(path.name for path in removed)
        )
    return run_dir


def monitor_once(args: argparse.Namespace, project: Path) -> Path:
    scope = getattr(args, "scope", "all")
    output_root = args.output_dir or ZTP_STATUS_DIR
    previous_report = _previous_report(output_root)
    switch_timezone = project_timezone(project)
    identity_devices = read_devices(
        project / "02-devices_config.csv",
        "all",
        air_json=ACTIVE_AIR_JSON if ACTIVE_AIR_JSON.is_file() else None,
        dhcp_leases=getattr(
            args, "dhcp_leases", Path("/var/lib/dhcp/dhcpd.leases"),
        ),
    )
    dhcp_text, dhcp_error = collect_dhcp(args.since, args.dhcp_log)
    dhcp_events = parse_dhcp(dhcp_text)
    apply_static_runtime_lease_fallbacks(
        identity_devices,
        project / "02-devices_config.csv",
        dhcp_text,
        dhcp_leases=getattr(
            args, "dhcp_leases", Path("/var/lib/dhcp/dhcpd.leases"),
        ),
    )
    identity_devices.extend(runtime_unknown_devices(
        project / "02-devices_config.csv",
        dhcp_text,
        scope=scope,
        dhcp_leases=getattr(
            args, "dhcp_leases", Path("/var/lib/dhcp/dhcpd.leases"),
        ),
    ))
    apply_dynamic_dhcp_addresses(identity_devices, dhcp_events)
    if scope == "air":
        devices = [
            device for device in identity_devices
            if device.get("type") == "air" or device.get("environment") == "air"
        ]
    elif scope == "prod":
        devices = [
            device for device in identity_devices
            if device.get("type") != "air" and device.get("environment") != "air"
        ]
    else:
        devices = identity_devices
    if not devices:
        raise ValueError(f"监控范围 --scope {scope} 没有匹配任何设备")
    previous_report = merge_previous_unbound_identities(previous_report, devices)
    apache_text, apache_error = read_tail(args.apache_log)
    apache_events = parse_apache(apache_text)
    cutoff = now_local() - dt.timedelta(minutes=args.since)
    recent_apache = []
    for event in apache_events:
        try:
            observed = dt.datetime.fromisoformat(event["timestamp"])
        except (TypeError, ValueError):
            recent_apache.append(event)
            continue
        if observed >= cutoff:
            recent_apache.append(event)
    http_identity_claims = bind_apache_ztp_identities(
        devices, recent_apache, dhcp_events, scope=scope,
    )
    # A successful per-MAC YAML request upgrades the anonymous front-panel
    # DHCP row to the canonical eth0 identity.  Keep only the canonical row in
    # this report; its DHCP/bootstrap stages are correlated below through the
    # transit-IP claim.
    devices = [
        device for device in devices
        if not device.get("superseded_by_hostname")
    ]
    known_macs = {
        mac_plain for device in devices
        for mac_plain in _device_identity_mac_values(device)
    }
    known_ips = {
        address for device in devices for address in _device_ips(device)
    }
    unmatched: list[dict[str, str]] = []
    for event in dhcp_events:
        unmatched_identity = (
            event["mac_plain"] not in known_macs if event["mac_plain"]
            else event["ip"] not in known_ips
        )
        claim = http_identity_claims.get(event.get("ip", ""))
        if claim is not None and _event_matches_http_claim(
            event, claim, source="dhcp",
        ):
            unmatched_identity = False
        if unmatched_identity:
            unmatched.append({
                "identity": event["mac_plain"] or event["ip"] or "unknown",
                "source": "dhcp", "event": event["kind"],
                "timestamp": event["timestamp"],
            })
    for event in recent_apache:
        claim = http_identity_claims.get(event["ip"])
        claimed_event = claim is not None and _event_matches_http_claim(
            event, claim, source="apache",
        )
        if (
            event["ip"] not in known_ips
            and not claimed_event
            and "/ztp/" in event["path"]
        ):
            unmatched.append({
                "identity": event["ip"], "source": "apache",
                "event": f"HTTP {event['status']} {event['path']}",
                "timestamp": event["timestamp"],
            })
    active_owners = correlate_server_events(
        devices, dhcp_events, recent_apache, identity_devices=identity_devices,
        http_identity_claims=http_identity_claims,
    )
    switch_results: dict[str, dict[str, Any]] = {}
    if not args.no_ssh:
        collection_devices = devices_for_switch_collection(
            devices, active_owners, identity_devices=identity_devices,
            http_identity_claims=http_identity_claims,
        )
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futures = {
                pool.submit(collect_switch, device, args.ssh_timeout, args.identity,
                            args.known_hosts): device for device in collection_devices
            }
            for future in concurrent.futures.as_completed(futures):
                device = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # defensive: keep the whole report usable
                    result = {"kind": "collector_error", "stderr": str(exc), "ztp_log": "",
                              "ifreload_log": "", "failed_yaml": "", "host_key_commands": []}
                switch_results[device["hostname"]] = result
                analyze_switch(device, result, switch_timezone)
    for device in devices:
        device.setdefault("observed_at", now_local().isoformat(timespec="seconds"))
    assign_ztp_rounds(
        devices, previous_report, latest_manual_trigger_markers(output_root),
    )
    assign_stage_success_indices(devices, previous_report)
    for device in devices:
        finalize_device(device)
    report = {
        "schema_version": 1, "project": project.name, "scope": scope,
        "generated_at": now_local().isoformat(timespec="seconds"),
        "since_minutes": args.since,
        "services": {"apache2": service_state("apache2"),
                     "isc-dhcp-server": service_state("isc-dhcp-server")},
        "devices": devices,
        "unmatched_interactions": unmatched[-200:],
        "collection_errors": [item for item in (
            f"DHCP 日志: {dhcp_error}" if dhcp_error else "",
            f"Apache 日志: {apache_error}" if apache_error else "",
        ) if item],
    }
    return write_report(
        report, output_root, switch_results,
        {"dhcp": dhcp_text, "apache-access": apache_text},
    )


def generate_monitor_html(script: Path, scope: str = "all") -> bool:
    if not script.is_file():
        log(f"[WARN] HTML 生成脚本不存在，跳过页面刷新: {script}", file=sys.stderr)
        return False
    command = [sys.executable, str(script)]
    if scope in {"air", "prod"}:
        command += ["--type", scope]
    result = run_command(command, timeout=180)
    if result["returncode"] != 0:
        detail = result["stderr"].strip() or result["stdout"].strip()
        log(f"[WARN] monitor.html 刷新失败: {detail}", file=sys.stderr)
        return False
    log(f"[OK] 监控 HTML 已刷新: {script.parent / 'monitor.html'}")
    return True


def read_report(run_dir: Path) -> dict[str, Any]:
    data = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("devices"), list):
        raise ValueError(f"ZTP report.json 格式无效: {run_dir / 'report.json'}")
    return data


def all_devices_complete(report: dict[str, Any]) -> bool:
    """Return true only when the non-empty monitored device set is at 100%."""
    devices = report.get("devices")
    if not isinstance(devices, list) or not devices:
        return False
    return all(
        completion_handoff_device_complete(device)
        for device in devices
    )


def completion_handoff_device_complete(device: Any) -> bool:
    """Require a formal, fully identified device to complete its type group."""
    if not isinstance(device, dict):
        return False
    device_type = str(device.get("type") or "").strip().casefold()
    return bool(
        not device_type.startswith("pending_")
        and isinstance(device.get("progress"), dict)
        and device["progress"].get("percent") == 100
        and not device.get("unbound_identity")
        and not device.get("identity_pending")
        and not device.get("promotion_pending")
    )


def completion_handoff_group(device: Any) -> Optional[str]:
    """Map known and classifiable-pending devices to one fixed collection key."""
    if not isinstance(device, dict):
        return None
    device_type = str(device.get("type") or "").strip().casefold()
    environment = str(device.get("environment") or "").strip().casefold()
    # AIR inventory rows can temporarily use pending_eth before runtime
    # identity promotion.  Keep them in AIR's gate instead of blocking the
    # unrelated Production Ethernet collection domain.
    if device_type.startswith("pending_"):
        if environment == "air":
            return "air-ethernet" if device_type in {"pending_air", "pending_eth"} else None
        if environment not in {"prod", "production"}:
            return None
        # A contradictory pending_air row must not cross environments merely
        # because its type token appears in the AIR mapping below.  Runtime
        # observations are fail-closed until type and environment agree.
        if device_type == "pending_air":
            return None
    for key, device_types in COMPLETION_HANDOFF_GROUP_TYPES.items():
        if device_type in device_types:
            return key
    return None


def completion_handoff_reports(
    report: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Split a monitor report into known collection domains without overlap."""
    grouped: dict[str, list[dict[str, Any]]] = {
        key: [] for key in COMPLETION_HANDOFF_KEYS
    }
    for device in report.get("devices", []):
        key = completion_handoff_group(device)
        if key is not None:
            grouped[key].append(device)
    reports: dict[str, dict[str, Any]] = {}
    for key in COMPLETION_HANDOFF_KEYS:
        if not grouped[key]:
            continue
        scoped_report = dict(report)
        scoped_report["devices"] = grouped[key]
        scoped_report["handoff_group"] = key
        reports[key] = scoped_report
    return reports


def ready_completion_handoff_reports(
    report: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Return independently ready groups; unrelated types never gate each other."""
    return {
        key: group_report
        for key, group_report in completion_handoff_reports(report).items()
        if all_devices_complete(group_report)
    }


def completion_signature(report: dict[str, Any]) -> tuple[tuple[str, str, str], ...]:
    """Identify one completed ZTP cycle without using report refresh time."""
    signature = []
    for device in report.get("devices", []):
        if not isinstance(device, dict):
            continue
        complete = device.get("stages", {}).get("complete", {})
        signature.append((
            str(device.get("hostname") or ""),
            str(device.get("boot_id") or ""),
            str(complete.get("timestamp") or "legacy-complete"),
        ))
    return tuple(sorted(signature))


def _parse_completion_handoff_signature(
    value: Any,
) -> Optional[tuple[tuple[str, str, str], ...]]:
    if not isinstance(value, list):
        return None
    signature: list[tuple[str, str, str]] = []
    for row in value:
        if (
            not isinstance(row, list) or len(row) != 3
            or any(not isinstance(item, str) or len(item) > 1024 for item in row)
        ):
            return None
        signature.append((row[0], row[1], row[2]))
    return tuple(sorted(signature))


def _load_completion_handoff_records(
    path: Path, project: Path,
) -> dict[str, dict[str, Any]]:
    """Load validated per-group signatures together with their audit times."""
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > 1024 * 1024
        ):
            return {}
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = -1
            payload = json.load(stream)
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != HANDOFF_STATE_SCHEMA
        or payload.get("project") != str(project.resolve())
        or not isinstance(payload.get("groups"), dict)
    ):
        return {}
    groups = payload["groups"]
    if any(key not in COMPLETION_HANDOFF_KEYS for key in groups):
        return {}
    records: dict[str, dict[str, Any]] = {}
    for key, record in groups.items():
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("collected_at"), str)
            or len(record["collected_at"]) > 128
        ):
            return {}
        signature = _parse_completion_handoff_signature(record.get("signature"))
        if signature is None:
            return {}
        records[key] = {
            "signature": signature,
            "collected_at": record["collected_at"],
        }
    return records


def load_completion_handoff_signatures(
    path: Path, project: Path,
) -> dict[str, tuple[tuple[str, str, str], ...]]:
    """Load successful per-group handoffs; unsafe/legacy state means recollect."""
    return {
        key: record["signature"]
        for key, record in _load_completion_handoff_records(path, project).items()
    }


def persist_completion_handoff_signatures(
    path: Path, project: Path,
    signatures: dict[str, tuple[tuple[str, str, str], ...]],
) -> None:
    """Atomically persist all successful collection-group signatures."""
    if any(key not in COMPLETION_HANDOFF_KEYS for key in signatures):
        raise ValueError("invalid completion handoff collection key")
    path.parent.mkdir(parents=True, exist_ok=True)
    previous_records = _load_completion_handoff_records(path, project)
    current_collected_at = now_local().isoformat(timespec="seconds")
    payload = {
        "schema_version": HANDOFF_STATE_SCHEMA,
        "project": str(project.resolve()),
        "groups": {
            key: {
                "signature": [list(row) for row in signatures[key]],
                # collected_at describes this group's successful handoff, not
                # the last time an unrelated sibling rewrote the state file.
                "collected_at": (
                    previous_records[key]["collected_at"]
                    if key in previous_records
                    and previous_records[key]["signature"] == signatures[key]
                    else current_collected_at
                ),
            }
            for key in COMPLETION_HANDOFF_KEYS if key in signatures
        },
    }
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".ztp-completion-handoff.", dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def completion_handoff_retry_delay(watch_seconds: Optional[int]) -> int:
    """Bound failed collector retries so a busy lock is not polled every cycle."""
    return max(
        HANDOFF_RETRY_MIN_SECONDS,
        min(max(watch_seconds or 30, 5) * 4, 600),
    )


def monitor_control_state(path: Path = ZTP_CONTROL_FILE) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip().casefold()
    except OSError:
        return "running"
    if value == "paused":
        return "paused"
    return "running"


def controlled_sleep(seconds: int, path: Path = ZTP_CONTROL_FILE) -> None:
    """Sleep in short intervals so a ZTP pause request is handled promptly."""
    deadline = time.monotonic() + max(seconds, 0)
    while time.monotonic() < deadline:
        if monitor_control_state(path) == "paused":
            return
        time.sleep(min(2, max(deadline - time.monotonic(), 0)))


def paused_sleep(seconds: int, path: Path = ZTP_CONTROL_FILE) -> None:
    """Wait without busy-spinning, but resume promptly when the page state changes."""
    deadline = time.monotonic() + max(seconds, 0)
    while time.monotonic() < deadline and monitor_control_state(path) == "paused":
        time.sleep(min(2, max(deadline - time.monotonic(), 0)))


def print_environment_summary(report: dict[str, Any]) -> None:
    """Print a compact per-environment summary for foreground/background logs."""
    groups: dict[str, list[dict[str, Any]]] = {
        "AIR": [], "Production": [], "Unknown / 未归类": [],
    }
    for device in report.get("devices", []):
        if not isinstance(device, dict):
            continue
        explicit = str(device.get("environment") or "").strip().casefold()
        device_type = str(device.get("type") or "").strip().casefold()
        if explicit == "air" or (not explicit and device_type == "air"):
            name = "AIR"
        elif explicit in {"prod", "production"} or (
            not explicit and device_type in {"eth", "eth_spx", "spx", "ib", "nvl"}
        ):
            name = "Production"
        else:
            name = "Unknown / 未归类"
        groups[name].append(device)
    for name, devices in groups.items():
        if not devices:
            continue
        complete = sum(
            isinstance(device.get("progress"), dict)
            and device["progress"].get("percent") == 100
            for device in devices
        )
        counts = {state: 0 for state in ("success", "running", "warning", "failed", "pending")}
        for device in devices:
            state = str(device.get("overall") or "pending")
            counts[state] = counts.get(state, 0) + 1
        log(
            f"[STATUS] {name}: {complete}/{len(devices)} complete; "
            f"success={counts['success']} running={counts['running']} "
            f"warning={counts['warning']} failed={counts['failed']} "
            f"pending={counts['pending']}"
        )


def completion_collection_commands(
    report: dict[str, Any], scripts: Optional[dict[str, Path]] = None,
) -> list[list[str]]:
    """Build post-ZTP monitor collection commands without crossing scope."""
    scripts = scripts or COLLECTOR_SCRIPTS
    types = {
        str(device.get("type") or "").strip().casefold()
        for device in report.get("devices", []) if isinstance(device, dict)
    }
    commands: list[list[str]] = []
    if "air" in types:
        commands.append(["bash", str(scripts["ethernet"]), "--air"])
    if types & {"eth", "eth_spx", "spx"}:
        commands.append(["bash", str(scripts["ethernet"]), "--prod"])
    if "ib" in types:
        commands.append(["bash", str(scripts["infiniband"])])
    if "nvl" in types:
        commands.append(["bash", str(scripts["nvlink"])])
    return commands


def append_collector_log(script: Path, command: list[str], result: dict[str, Any]) -> None:
    """Persist captured cron output because this caller does not use shell redirection."""
    log_file = script.parent / "cronjob.log"
    stamp = now_local().isoformat(timespec="seconds")
    lines = [f"[{stamp}] [ZTP-HANDOFF][RUN] {shlex.join(command)}"]
    lines.extend(f"[{stamp}] {line}" for line in result["stdout"].splitlines())
    lines.extend(f"[{stamp}] [stderr] {line}" for line in result["stderr"].splitlines())
    lines.append(
        f"[{now_local().isoformat(timespec='seconds')}] "
        f"[ZTP-HANDOFF][EXIT] {result['returncode']}"
    )
    try:
        with log_file.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    except OSError as exc:
        log(f"[WARN] 无法写入 cron 日志 {log_file}: {exc}", file=sys.stderr)


def run_completion_handoff(
    report: dict[str, Any], html_script: Path, collector_timeout: int,
    manual: bool = False,
) -> bool:
    commands = completion_collection_commands(report)
    if not commands:
        log("[WARN] 当前 scope 没有可识别的监控类型，无法执行采集", file=sys.stderr)
        return False
    if manual:
        log("[INFO] 收到页面请求，开始手工采集 Switch Status")
    else:
        group = str(report.get("handoff_group") or "当前类型")
        log(f"[INFO] {group} 的 ZTP 设备已全部达到 100%，开始设备监控交接")
    for command in commands:
        script = Path(command[1])
        if not script.is_file():
            log(f"[WARN] 采集脚本不存在: {script}", file=sys.stderr)
            return False
        log("[RUN] " + shlex.join(command))
        result = run_command(command, timeout=collector_timeout)
        append_collector_log(script, command, result)
        for line in result["stdout"].splitlines():
            log(f"[COLLECT][stdout] {line}")
        for line in result["stderr"].splitlines():
            log(f"[COLLECT][stderr] {line}", file=sys.stderr)
        if result["returncode"] != 0:
            detail = result["stderr"].strip() or result["stdout"].strip()
            retry = "可在页面再次发起" if manual else "ZTP 监控保持运行并将在下一轮重试"
            log(f"[WARN] 设备采集失败（exit={result['returncode']}），{retry}: {detail[-2000:]}",
                file=sys.stderr)
            return False
    if not generate_monitor_html(html_script, str(report.get("scope") or "all")):
        log("[WARN] HTML 交接刷新失败，ZTP 监控保持运行并将在下一轮重试", file=sys.stderr)
        return False
    log("[OK] 设备采集和 monitor.html 刷新完成，ZTP 后台监控继续运行")
    return True


def run_completion_handoff_with_gate(
    report: dict[str, Any], html_script: Path, collector_timeout: int,
    project: Path, collection_key: str,
    status_dir: Path = SWITCH_COLLECTION_STATUS_DIR,
) -> bool:
    """Serialize an unseen completed-cycle handoff without a time cooldown."""
    scope = "air" if collection_key == "air-ethernet" else "prod"
    try:
        with CollectionGate(
            str(project.resolve()), scope, collection_keys=(collection_key,),
            status_dir=status_dir, enforce_cooldown=False,
        ) as gate:
            decision = gate.decision
            if not decision.allowed:
                log(
                    "[WARN] 另一项管理面 Switch 采集正在运行；本轮稍后重试",
                    file=sys.stderr,
                )
                return False
            success = run_completion_handoff(
                report, html_script, collector_timeout,
            )
            if success:
                gate.mark_success()
            return success
    except CollectionGateError as exc:
        log(f"[WARN] Switch 采集串行门禁失败：{exc}", file=sys.stderr)
        return False


def run_completion_handoff_with_cooldown(
    report: dict[str, Any], html_script: Path, collector_timeout: int,
    project: Path, collection_key: str,
    status_dir: Path = SWITCH_COLLECTION_STATUS_DIR,
) -> bool:
    """Deprecated compatibility alias for the automatic gate-only handoff."""
    return run_completion_handoff_with_gate(
        report, html_script, collector_timeout, project, collection_key,
        status_dir=status_dir,
    )


def process_ready_completion_handoffs(
    report: dict[str, Any], html_script: Path, collector_timeout: int,
    project: Path, handoff_state_path: Path,
    handed_off_signatures: dict[str, tuple[tuple[str, str, str], ...]],
    retry_signatures: dict[str, tuple[tuple[str, str, str], ...]],
    retry_after: dict[str, float], watch_seconds: Optional[int],
    *, monotonic=time.monotonic,
    status_dir: Path = SWITCH_COLLECTION_STATUS_DIR,
) -> tuple[
    dict[str, tuple[tuple[str, str, str], ...]],
    dict[str, tuple[tuple[str, str, str], ...]],
    dict[str, float],
]:
    """Attempt every ready type independently; one failure never stops siblings."""
    for collection_key, group_report in ready_completion_handoff_reports(report).items():
        signature = completion_signature(group_report)
        retry_deferred = bool(
            signature == retry_signatures.get(collection_key)
            and monotonic() < retry_after.get(collection_key, 0.0)
        )
        if signature == handed_off_signatures.get(collection_key) or retry_deferred:
            continue
        try:
            handoff_succeeded = run_completion_handoff_with_gate(
                group_report, html_script, collector_timeout, project,
                collection_key, status_dir=status_dir,
            )
        except OSError as exc:
            # A permission, disk, or state-file failure belongs to this
            # collection domain.  Preserve the monitor and let independently
            # ready sibling domains continue in the same report cycle.
            log(
                f"[WARN] {collection_key} Switch 交接 I/O 失败：{exc}",
                file=sys.stderr,
            )
            handoff_succeeded = False
        if handoff_succeeded:
            handed_off_signatures[collection_key] = signature
            retry_signatures.pop(collection_key, None)
            retry_after.pop(collection_key, None)
            try:
                persist_completion_handoff_signatures(
                    handoff_state_path, project, handed_off_signatures,
                )
            except OSError as exc:
                log(
                    f"[WARN] {collection_key} 交接已成功，但无法持久化去重签名：{exc}",
                    file=sys.stderr,
                )
            continue
        retry_delay = completion_handoff_retry_delay(watch_seconds)
        retry_signatures[collection_key] = signature
        retry_after[collection_key] = monotonic() + retry_delay
        log(
            f"[INFO] {collection_key} 完成轮次的 Switch 交接失败或采集锁忙；"
            f"{retry_delay} 秒后再重试，其他已就绪类型继续独立处理"
        )
    return handed_off_signatures, retry_signatures, retry_after


def remove_own_pid_file(pid_file: Path) -> None:
    try:
        if int(pid_file.read_text(encoding="utf-8").strip()) == os.getpid():
            pid_file.unlink(missing_ok=True)
    except (OSError, ValueError):
        pass


def resolve_project(value: str) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute() and not candidate.exists():
        candidate = HERE / candidate
    candidate = candidate.resolve()
    if not (candidate / "02-devices_config.csv").is_file():
        raise FileNotFoundError(f"项目缺少 02-devices_config.csv: {candidate}")
    return candidate


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="关联 DHCP、Apache 与交换机日志，生成逐设备 ZTP 进度报告")
    result.add_argument("project", help="项目名或项目目录")
    result.add_argument("--since", type=int, default=1440, help="服务端日志观察窗口（分钟，默认 1440）")
    result.add_argument("--watch", type=int, metavar="SECONDS", help="持续监控间隔；未指定则只运行一次")
    result.add_argument("--output-dir", type=Path, help="报告根目录（默认 /var/www/html/ztp/status）")
    result.add_argument("--apache-log", type=Path, default=DEFAULT_APACHE_LOG)
    result.add_argument("--dhcp-log", type=Path, help="从指定文件读取 DHCP 日志（测试/离线分析）")
    result.add_argument(
        "--dhcp-leases", type=Path,
        default=Path("/var/lib/dhcp/dhcpd.leases"),
        help="ISC DHCP lease 文件（用于解析 AIR-only 动态地址）",
    )
    result.add_argument("--no-ssh", action="store_true", help="只分析管理服务器日志，不连接交换机")
    result.add_argument("--ssh-timeout", type=int, default=8)
    result.add_argument("--jobs", type=int, default=12, help="并发 SSH 数（默认 12）")
    environment = result.add_mutually_exclusive_group()
    environment.add_argument(
        "--scope", choices=("all", "prod", "air"), dest="scope",
        help="监控全部设备，或仅监控 Production/AIR",
    )
    environment.add_argument(
        "--type", choices=("all", "prod", "air"), dest="scope",
        help="环境选择；等价于 --scope",
    )
    environment.add_argument(
        "--air", action="store_const", const="air", dest="scope",
        help="仅监控 AIR；等价于 --type air",
    )
    environment.add_argument(
        "--prod", action="store_const", const="prod", dest="scope",
        help="仅监控 Production；等价于 --type prod",
    )
    result.set_defaults(scope="all")
    result.add_argument("--identity", type=Path, help="SSH 私钥路径")
    result.add_argument("--known-hosts", type=Path, default=Path.home() / ".ssh" / "known_hosts")
    result.add_argument(
        "--generate-html", action="store_true",
        help="每轮 ZTP 报告完成后运行 generate-monitor-html.py 刷新 monitor.html",
    )
    result.add_argument(
        "--html-script", type=Path, default=DEFAULT_HTML_SCRIPT,
        help="HTML 生成脚本路径（默认 /var/www/html/monitor/generate-monitor-html.py）",
    )
    result.add_argument(
        "--exit-on-complete", action="store_true",
        help=("兼容参数：每个采集类型各自全部达到 100%% 后独立运行一次 cron.sh "
              "并继续监控；失败仅重试该类型"),
    )
    result.add_argument(
        "--collector-timeout", type=int, default=1200, metavar="SECONDS",
        help="完成交接时每个 cron 命令的最大运行时间（默认 1200 秒）",
    )
    return result


def main(argv: Optional[list[str]] = None) -> int:
    args = parser().parse_args(argv)
    pause_announced = False
    handoff_retry_signatures: dict[
        str, tuple[tuple[str, str, str], ...]
    ] = {}
    handoff_retry_after: dict[str, float] = {}
    try:
        project = resolve_project(args.project)
        output_root = args.output_dir or ZTP_STATUS_DIR
        handoff_state_path = output_root / HANDOFF_STATE_NAME
        handed_off_signatures = load_completion_handoff_signatures(
            handoff_state_path, project,
        )
        if handed_off_signatures:
            log(
                f"[INFO] 已恢复 {len(handed_off_signatures)} 个类型的 "
                "ZTP→Switch 交接签名；相同完成轮次不会因 monitor/load 重启而重复采集"
            )
        while True:
            control_state = monitor_control_state()
            if args.watch and control_state == "paused":
                if not pause_announced:
                    log("[INFO] 页面控制已暂停 ZTP 采集；进程保留并等待恢复")
                    pause_announced = True
                paused_sleep(max(args.watch or 5, 5))
                continue
            if pause_announced:
                log("[INFO] 页面控制已恢复 ZTP 采集")
                pause_announced = False
            run_dir = monitor_once(args, project)
            log(f"[OK] ZTP 监控报告: {run_dir / 'report.md'}")
            log(f"[OK] JSON: {run_dir / 'report.json'}")
            report = read_report(run_dir)
            print_environment_summary(report)
            if args.generate_html:
                generate_monitor_html(args.html_script, args.scope)
            if args.exit_on_complete:
                (
                    handed_off_signatures,
                    handoff_retry_signatures,
                    handoff_retry_after,
                ) = process_ready_completion_handoffs(
                    report, args.html_script, max(args.collector_timeout, 60),
                    project, handoff_state_path, handed_off_signatures,
                    handoff_retry_signatures, handoff_retry_after, args.watch,
                )
            if not args.watch:
                return 0
            controlled_sleep(max(args.watch, 5))
    except KeyboardInterrupt:
        log("[INFO] 监控已停止")
        return 130
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        log(f"[ERROR] {exc}", file=sys.stderr)
        return 2
    finally:
        remove_own_pid_file(ZTP_STATUS_DIR / "ztp-monitor.pid")


if __name__ == "__main__":
    raise SystemExit(main())
