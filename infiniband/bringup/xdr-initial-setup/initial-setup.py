#!/usr/bin/env python3
"""Initialize NVOS management through Ethernet OOB switches.

The program runs on a management host.  It logs in to each Ethernet switch
listed in ib.csv, correlates P2P ports with ``ip -d link show``,
``bridge fdb show`` and ``ip neighbor``, then reaches the attached NVOS switch
through its IPv6 link-local address from that Ethernet switch.

Python 3 standard library only.  No sshpass, pexpect, Paramiko, or Excel module
is required.
"""

from __future__ import annotations

import argparse
import ast
import base64
import copy
import csv
import fcntl
import getpass
import hashlib
import ipaddress
import json
import os
import pty
import re
import select
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Optional


NA_VALUES = {"", "na", "n/a", "none", "null", "tbd", "-"}
IB_PORT_ALIASES = {"eth0", "mgmt", "management", "bmc"}
DEFAULT_HOSTNAMES = {"", "nvos"}
TRANSIT_DEVICE_TYPES = frozenset({"eth", "eth_spx", "spx", "ethernet", "eth_jump"})
TARGET_CACHE_VERSION = 4
_SELF_SOURCE_PATH = Path(__file__).resolve()
MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
DOT_LINK_RE = re.compile(
    r'^\s*"([^"]+)"\s*:\s*"([^"]+)"\s*--\s*'
    r'"([^"]+)"\s*:\s*"([^"]+)"'
)
REPORT_HANDLE = None
_KEY_INSTALL_AWK = (
    "function iskey(v) { return v ~ /^(ssh-|ecdsa-|sk-)[A-Za-z0-9@._+-]+$/ } "
    "{ identity=\"\"; for (i=1; i<NF; i++) if (iskey($i)) "
    "{ identity=$i SUBSEP $(i+1); break } "
    "if (identity==\"\" || !seen[identity]++) print }"
)
_KEY_INSTALL_SCRIPT = (
    'set -eu; test -n "${HOME:-}" && test -d "$HOME" && test ! -L "$HOME" || exit 31; '
    'ssh_dir="$HOME/.ssh"; '
    'if test -L "$ssh_dir" || { test -e "$ssh_dir" && test ! -d "$ssh_dir"; }; then exit 32; fi; '
    'umask 077; mkdir -p "$ssh_dir"; chmod 700 "$ssh_dir"; '
    'auth="$ssh_dir/authorized_keys"; '
    'if test -L "$auth" || { test -e "$auth" && test ! -f "$auth"; }; then exit 33; fi; '
    'tmp="$(mktemp "$ssh_dir/.authorized_keys.XXXXXX")"; '
    'trap \'rm -f "$tmp"\' EXIT HUP INT TERM; '
    '{ if test -f "$auth"; then cat "$auth"; fi; '
    'printf %s "$1" | base64 -d; } | awk \'' + _KEY_INSTALL_AWK + '\' >"$tmp"; '
    'chmod 600 "$tmp"; '
    'if test -f "$auth" && cmp -s "$tmp" "$auth"; then rm -f "$tmp"; trap - EXIT; exit 0; fi; '
    'mv -f "$tmp" "$auth"; trap - EXIT'
)


class SetupError(RuntimeError):
    pass


@dataclass(frozen=True)
class Device:
    hostname: str
    dev_type: str
    login_ip: str
    eth0_prefix: str
    eth0_gateway: str
    eth0_mac: str
    eth1_prefix: str
    eth1_gateway: str


@dataclass(frozen=True)
class Link:
    left_device: str
    left_port: str
    right_device: str
    right_port: str


@dataclass(frozen=True)
class Target:
    ib: Device
    ethernet: Device
    ethernet_port: str
    ib_port_alias: str


@dataclass(frozen=True)
class Neighbor:
    ipv6: str
    interface: str
    mac: str
    vrf: str = "default"


@dataclass(frozen=True)
class DeviceState:
    eth0_addresses: tuple[str, ...]
    eth1_addresses: tuple[str, ...]
    eth0_gateways: tuple[str, ...]
    eth1_gateways: tuple[str, ...]
    hostname: str
    raw_commands: str


@dataclass
class SessionResult:
    output: str
    exit_code: int
    password_changed: bool = False
    password_change_required: bool = False


def log(message: str = "") -> None:
    print(message, flush=True)
    if REPORT_HANDLE is not None:
        print(message, file=REPORT_HANDLE, flush=True)


def clean(value: object) -> str:
    return str(value or "").strip().strip("‘’“”")


def usable(value: str) -> bool:
    return clean(value).casefold() not in NA_VALUES


def normalize_mac(value: str, *, field: str) -> str:
    """Return a lowercase colon-delimited MAC, or empty for an omitted value."""
    raw = clean(value)
    if not usable(raw):
        return ""
    compact = re.sub(r"[.:-]", "", raw)
    if not re.fullmatch(r"[0-9a-fA-F]{12}", compact):
        raise SetupError(f"invalid {field}: {raw!r}")
    return ":".join(compact[index:index + 2] for index in range(0, 12, 2)).casefold()


def normalize_name(value: str) -> str:
    return clean(value).casefold().rstrip(".")


def names_match(left: str, right: str) -> bool:
    a, b = normalize_name(left), normalize_name(right)
    return a == b or a.endswith("-" + b) or b.endswith("-" + a)


def cumulus_port_name(value: str) -> str:
    """Convert LLDPq numeric Ethernet ports to their Cumulus interface names."""
    port = clean(value)
    return f"swp{port}" if port.isdigit() else port


def header_indexes(header: list[str]) -> dict[str, list[int]]:
    indexes: dict[str, list[int]] = {}
    for index, name in enumerate(header):
        indexes.setdefault(clean(name).casefold(), []).append(index)
    return indexes


def row_value(row: list[str], indexes: dict[str, list[int]], name: str,
              occurrence: int = 0) -> str:
    positions = indexes.get(name.casefold(), [])
    if occurrence >= len(positions) or positions[occurrence] >= len(row):
        return ""
    return clean(row[positions[occurrence]])


def ipv4_prefix(address: str, netmask: str, *, field: str,
                required: bool) -> str:
    if not usable(address):
        if required:
            raise SetupError(f"{field} is required")
        return ""
    if "/" in address:
        value = address
    elif usable(netmask):
        value = f"{address}/{netmask}"
    else:
        raise SetupError(f"{field} has no netmask")
    try:
        interface = ipaddress.IPv4Interface(value)
        if interface.network.prefixlen <= 30 and interface.ip in {
            interface.network.network_address, interface.network.broadcast_address,
        }:
            raise SetupError(f"{field} uses a network/broadcast address: {value}")
        return str(interface)
    except ValueError as exc:
        raise SetupError(f"invalid {field}: {value}: {exc}") from exc


def valid_hostname(value: str) -> bool:
    hostname = clean(value).rstrip(".")
    if not hostname or len(hostname) > 253:
        return False
    label = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
    return all(label.fullmatch(part) for part in hostname.split("."))


def valid_ssh_user(value: str) -> bool:
    """Accept a login name, never an SSH option or shell fragment."""
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9._-]{0,63}", clean(value)))


def resolve_initial_ib_password(
    environment_name: str, *, factory_default_admin: bool = False,
    interactive: Optional[bool] = None,
) -> str:
    """Read the initial NVOS credential without source/argv/log disclosure."""
    selected_name = (
        "NVOS_FACTORY_DEFAULT_ADMIN_PASSWORD"
        if factory_default_admin else environment_name
    )
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", selected_name):
        raise SetupError(f"invalid initial-password environment name: {selected_name!r}")
    supplied = os.environ.get(selected_name, "")
    if supplied:
        return supplied
    can_prompt = sys.stdin.isatty() if interactive is None else interactive
    if not can_prompt:
        raise SetupError(
            f"initial NVOS password is required; export {selected_name} "
            "or run interactively"
        )
    label = (
        "NVOS factory-default admin password"
        if factory_default_admin else "Initial NVOS password"
    )
    supplied = getpass.getpass(f"{label}: ")
    if not supplied:
        raise SetupError("initial NVOS password cannot be empty")
    return supplied


def validate_ib_devices(devices: dict[str, Device]) -> None:
    addresses: dict[str, tuple[str, str]] = {}
    gateways_by_network: dict[str, tuple[str, str]] = {}
    gateway_uses: list[tuple[str, str, str]] = []
    for device in devices.values():
        if not valid_hostname(device.hostname):
            raise SetupError(f"invalid IB hostname: {device.hostname!r}")
        for interface_name, prefix, gateway in (
            ("eth0", device.eth0_prefix, device.eth0_gateway),
            ("eth1", device.eth1_prefix, device.eth1_gateway),
        ):
            if not prefix:
                continue
            interface = ipaddress.IPv4Interface(prefix)
            address = str(interface.ip)
            if address in addresses:
                other_hostname, other_interface = addresses[address]
                raise SetupError(
                    f"duplicate IB address {address}: "
                    f"{other_hostname}.{other_interface} and "
                    f"{device.hostname}.{interface_name}"
                )
            addresses[address] = (device.hostname, interface_name)
            gateway_address = ipaddress.IPv4Address(gateway)
            if interface.network.prefixlen <= 30 and gateway_address in {
                interface.network.network_address, interface.network.broadcast_address,
            }:
                raise SetupError(
                    f"{device.hostname}.{interface_name} gateway {gateway} is a "
                    "network/broadcast address"
                )
            network = str(interface.network)
            previous = gateways_by_network.get(network)
            if previous and previous[0] != gateway:
                raise SetupError(
                    f"conflicting IB gateways for {network}: {previous[0]} "
                    f"({previous[1]}) and {gateway} "
                    f"({device.hostname}.{interface_name})"
                )
            gateways_by_network[network] = (
                gateway, f"{device.hostname}.{interface_name}"
            )
            gateway_uses.append((gateway, device.hostname, interface_name))
    for gateway, hostname, interface_name in gateway_uses:
        if gateway in addresses:
            owner_hostname, owner_interface = addresses[gateway]
            raise SetupError(
                f"IB gateway {gateway} for {hostname}.{interface_name} duplicates "
                f"device address {owner_hostname}.{owner_interface}"
            )


def load_devices(path: Path) -> tuple[dict[str, Device], dict[str, Device]]:
    try:
        handle = path.open("r", encoding="utf-8-sig", newline="")
    except OSError as exc:
        raise SetupError(f"cannot open device CSV {path}: {exc}") from exc

    ib_devices: dict[str, Device] = {}
    eth_devices: dict[str, Device] = {}
    with handle:
        reader = csv.reader(handle)
        try:
            raw_header = next(reader)
        except StopIteration as exc:
            raise SetupError(f"device CSV is empty: {path}") from exc
        indexes = header_indexes(raw_header)
        required_headers = {"hostname", "type", "eth0_ip"}
        missing = sorted(required_headers - indexes.keys())
        if missing:
            raise SetupError(f"device CSV missing column(s): {', '.join(missing)}")

        for line_number, row in enumerate(reader, 2):
            hostname = row_value(row, indexes, "hostname")
            dev_type = row_value(row, indexes, "type").casefold()
            if not hostname or dev_type not in ({"ib"} | TRANSIT_DEVICE_TYPES):
                continue
            if not valid_hostname(hostname):
                raise SetupError(f"{path}:{line_number}: invalid hostname {hostname!r}")
            eth0_ip = row_value(row, indexes, "eth0_ip")
            netmask0 = row_value(row, indexes, "netmask", 0)
            eth0_gateway = row_value(row, indexes, "eth0_gw")
            eth0_mac = row_value(row, indexes, "eth0_mac")
            eth1_ip = row_value(row, indexes, "eth1_ip")
            netmask1 = row_value(row, indexes, "netmask", 1) or netmask0
            eth1_gateway = row_value(row, indexes, "eth1_gw")
            try:
                eth0_mac = normalize_mac(eth0_mac, field=f"{hostname}.eth0_mac")
                if dev_type == "ib":
                    eth0 = ipv4_prefix(
                        eth0_ip, netmask0, field=f"{hostname}.eth0_ip", required=True
                    )
                    eth1 = ipv4_prefix(
                        eth1_ip, netmask1, field=f"{hostname}.eth1_ip", required=False
                    )
                    if not usable(eth0_gateway):
                        raise SetupError(f"{hostname}.eth0_gw is required")
                    eth0_gateway = str(ipaddress.IPv4Address(eth0_gateway))
                    if ipaddress.IPv4Address(eth0_gateway) not in ipaddress.IPv4Interface(eth0).network:
                        raise SetupError(
                            f"{hostname}.eth0_gw {eth0_gateway} is outside "
                            f"{ipaddress.IPv4Interface(eth0).network}"
                        )
                    if eth1:
                        if not usable(eth1_gateway):
                            raise SetupError(
                                f"{hostname}.eth1_gw is required when eth1_ip is set"
                            )
                        eth1_gateway = str(ipaddress.IPv4Address(eth1_gateway))
                        if ipaddress.IPv4Address(eth1_gateway) not in ipaddress.IPv4Interface(eth1).network:
                            raise SetupError(
                                f"{hostname}.eth1_gw {eth1_gateway} is outside "
                                f"{ipaddress.IPv4Interface(eth1).network}"
                            )
                    elif usable(eth1_gateway):
                        raise SetupError(
                            f"{hostname}.eth1_gw is set but eth1_ip is empty"
                        )
                    else:
                        eth1_gateway = ""
                else:
                    if not usable(eth0_ip):
                        raise SetupError(f"{hostname}.eth0_ip login address is required")
                    eth0 = str(ipaddress.IPv4Address(eth0_ip.split("/", 1)[0]))
                    eth1 = ""
                    eth0_gateway = ""
                    eth1_gateway = ""
            except (SetupError, ValueError) as exc:
                raise SetupError(f"{path}:{line_number}: {exc}") from exc

            device = Device(
                hostname, dev_type, eth0.split("/", 1)[0], eth0,
                eth0_gateway, eth0_mac, eth1, eth1_gateway,
            )
            target_map = ib_devices if dev_type == "ib" else eth_devices
            key = normalize_name(hostname)
            if key in target_map:
                raise SetupError(f"duplicate device hostname in CSV: {hostname}")
            target_map[key] = device

    if not ib_devices:
        raise SetupError(f"device CSV contains no type=ib devices: {path}")
    if not eth_devices:
        raise SetupError(f"device CSV contains no Ethernet switch devices: {path}")
    validate_ib_devices(ib_devices)
    return ib_devices, eth_devices


def parse_p2p(path: Path) -> list[Link]:
    if path.suffix.casefold() == ".xlsx":
        return parse_p2p_xlsx(path)
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        raise SetupError(f"cannot read P2P file {path}: {exc}") from exc

    links: list[Link] = []
    if path.suffix.casefold() == ".dot" or " -- " in text:
        for line in text.splitlines():
            match = DOT_LINK_RE.search(line)
            if match:
                links.append(Link(*(clean(value) for value in match.groups())))
        if not links:
            raise SetupError(f"no links found in DOT file: {path}")
        return links

    nonblank = [line for line in text.splitlines() if line.strip()]
    if not nonblank:
        raise SetupError(f"P2P file is empty: {path}")
    rows = list(csv.reader(nonblank))
    header = [clean(value).casefold() for value in rows[0]]
    aliases = {
        "left_device": ("a-node", "srcdevice", "src_device", "source device"),
        "left_port": ("a-port", "srcport", "src_port", "source port"),
        "right_device": ("z-node", "dstdevice", "dst_device", "destination device"),
        "right_port": ("z-port", "dstport", "dst_port", "destination port"),
    }
    positions: dict[str, int] = {}
    for field, choices in aliases.items():
        for choice in choices:
            if choice in header:
                positions[field] = header.index(choice)
                break
    if len(positions) == 4:
        for row in rows[1:]:
            if len(row) <= max(positions.values()):
                continue
            values = [clean(row[positions[name]]) for name in aliases]
            if all(values):
                links.append(Link(*values))
    else:
        for line in nonblank:
            fields = [clean(value) for value in line.split()]
            if len(fields) < 4 or fields[0].casefold() in {"name", "source", "srcdevice"}:
                continue
            links.append(Link(fields[0], fields[1], fields[-2], fields[-1]))
    if not links:
        raise SetupError(f"no usable links found in P2P file: {path}")
    return links


def xlsx_cell_value(cell: ET.Element, shared_strings: list[str], ns: str) -> str:
    cell_type = cell.get("t", "")
    if cell_type == "inlineStr":
        return clean("".join(node.text or "" for node in cell.findall(f".//{ns}t")))
    value = cell.find(f"{ns}v")
    if value is None or value.text is None:
        return ""
    if cell_type == "s":
        try:
            return clean(shared_strings[int(value.text)])
        except (ValueError, IndexError):
            return ""
    return clean(value.text)


def xlsx_column(reference: str) -> int:
    letters = re.match(r"[A-Za-z]+", reference)
    if not letters:
        return 0
    result = 0
    for character in letters.group(0).upper():
        result = result * 26 + ord(character) - ord("A") + 1
    return result - 1


def parse_p2p_xlsx(path: Path) -> list[Link]:
    """Read source/destination name+port columns from an OOXML workbook."""
    main_ns = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
    rel_ns = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
    package_rel_ns = "{http://schemas.openxmlformats.org/package/2006/relationships}"
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise SetupError(f"cannot open P2P workbook {path}: {exc}") from exc
    with archive:
        names = set(archive.namelist())
        shared_strings: list[str] = []
        if "xl/sharedStrings.xml" in names:
            root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
            shared_strings = [
                "".join(node.text or "" for node in item.findall(f".//{main_ns}t"))
                for item in root.findall(f"{main_ns}si")
            ]
        try:
            workbook = ET.fromstring(archive.read("xl/workbook.xml"))
            relationships = ET.fromstring(
                archive.read("xl/_rels/workbook.xml.rels")
            )
        except (KeyError, ET.ParseError) as exc:
            raise SetupError(f"invalid P2P workbook structure in {path}: {exc}") from exc
        targets = {
            item.get("Id", ""): item.get("Target", "")
            for item in relationships.findall(f"{package_rel_ns}Relationship")
        }
        links: list[Link] = []
        for sheet in workbook.findall(f".//{main_ns}sheet"):
            rel_id = sheet.get(f"{rel_ns}id", "")
            target = targets.get(rel_id, "").lstrip("/")
            sheet_path = target if target.startswith("xl/") else f"xl/{target}"
            if sheet_path not in names:
                continue
            try:
                sheet_root = ET.fromstring(archive.read(sheet_path))
            except ET.ParseError as exc:
                raise SetupError(
                    f"invalid worksheet {sheet.get('name', rel_id)} in {path}: {exc}"
                ) from exc
            rows: list[list[str]] = []
            for row_node in sheet_root.findall(f".//{main_ns}row"):
                values: list[str] = []
                for cell in row_node.findall(f"{main_ns}c"):
                    index = xlsx_column(cell.get("r", ""))
                    if index >= len(values):
                        values.extend([""] * (index - len(values) + 1))
                    values[index] = xlsx_cell_value(cell, shared_strings, main_ns)
                rows.append(values)
            for header_index, row in enumerate(rows[:20]):
                header = [re.sub(r"\s+", "", clean(value).casefold()) for value in row]
                name_columns = [index for index, value in enumerate(header) if value == "name"]
                if len(name_columns) < 2:
                    continue
                left_name, right_name = name_columns[:2]

                def find_port(start: int, end: int) -> Optional[int]:
                    for index in range(start + 1, min(end, len(header))):
                        if "port" in header[index]:
                            return index
                    return None

                left_port = find_port(left_name, right_name)
                right_port = find_port(right_name, len(header))
                if left_port is None or right_port is None:
                    continue
                for data in rows[header_index + 1:]:
                    positions = (left_name, left_port, right_name, right_port)
                    if max(positions) >= len(data):
                        continue
                    values = [clean(data[index]) for index in positions]
                    if all(usable(value) for value in values):
                        links.append(Link(*values))
                break
    if not links:
        raise SetupError(
            f"no worksheets with two name+port column groups found in {path}"
        )
    return links


def validate_p2p_links(links: list[Link]) -> None:
    seen_links: dict[tuple[tuple[str, str], tuple[str, str]], int] = {}
    endpoints: dict[tuple[str, str], tuple[tuple[str, str], int]] = {}
    for line_number, link in enumerate(links, 1):
        left = (normalize_name(link.left_device), clean(link.left_port).casefold())
        right = (normalize_name(link.right_device), clean(link.right_port).casefold())
        if not all((*left, *right)):
            raise SetupError(f"P2P link {line_number} has an empty device or port")
        if left == right:
            raise SetupError(
                f"P2P link {line_number} connects an endpoint to itself: "
                f"{link.left_device}:{link.left_port}"
            )
        canonical = tuple(sorted((left, right)))
        if canonical in seen_links:
            raise SetupError(
                f"duplicate P2P link at parsed records "
                f"{seen_links[canonical]} and {line_number}: "
                f"{link.left_device}:{link.left_port} <-> "
                f"{link.right_device}:{link.right_port}"
            )
        seen_links[canonical] = line_number
        for endpoint, peer in ((left, right), (right, left)):
            previous = endpoints.get(endpoint)
            if previous and previous[0] != peer:
                previous_peer, previous_line = previous
                raise SetupError(
                    f"P2P endpoint {endpoint[0]}:{endpoint[1]} has multiple peers "
                    f"at parsed records {previous_line} and {line_number}: "
                    f"{previous_peer[0]}:{previous_peer[1]} and "
                    f"{peer[0]}:{peer[1]}"
                )
            endpoints[endpoint] = (peer, line_number)


def resolve_device(name: str, devices: dict[str, Device]) -> Optional[Device]:
    normalized = normalize_name(name)
    if normalized in devices:
        return devices[normalized]
    matches = [device for key, device in devices.items()
               if normalized.endswith("-" + key) or key.endswith("-" + normalized)]
    return matches[0] if len(matches) == 1 else None


def build_targets(links: list[Link], ib_devices: dict[str, Device],
                  eth_devices: dict[str, Device]) -> list[Target]:
    targets: list[Target] = []
    seen: set[str] = set()
    for link in links:
        orientations = (
            (link.left_device, link.left_port, link.right_device, link.right_port),
            (link.right_device, link.right_port, link.left_device, link.left_port),
        )
        for ib_name, ib_port, eth_name, eth_port in orientations:
            ib = resolve_device(ib_name, ib_devices)
            if not ib or clean(ib_port).casefold() not in IB_PORT_ALIASES:
                continue
            ethernet = resolve_device(eth_name, eth_devices)
            if not ethernet:
                raise SetupError(
                    f"P2P peer {eth_name!r} for IB device {ib.hostname} is not a "
                    "supported Ethernet transit device with a login IP in the CSV"
                )
            key = normalize_name(ib.hostname)
            if key in seen:
                raise SetupError(f"multiple management links found for IB device {ib.hostname}")
            seen.add(key)
            targets.append(
                Target(ib, ethernet, cumulus_port_name(eth_port), clean(ib_port))
            )
    missing = [device.hostname for key, device in ib_devices.items() if key not in seen]
    if missing:
        log("WARNING: no Ethernet management link found for: " + ", ".join(sorted(missing)))
    if not targets:
        raise SetupError(
            "no IB management links to supported Ethernet transit devices "
            "were found in P2P"
        )
    return sorted(targets, key=lambda target: normalize_name(target.ib.hostname))


def require_auto_full_target_coverage(ib_candidate_count: int,
                                      targets: list[Target]) -> None:
    names = [normalize_name(target.ib.hostname) for target in targets]
    if ib_candidate_count < 1 or len(names) != ib_candidate_count or len(set(names)) != len(names):
        raise SetupError(
            "--auto requires one P2P management link for every CSV IB switch; "
            "fix CSV/P2P before starting a watch"
        )


def device_to_dict(device: Device) -> dict[str, str]:
    return {
        "hostname": device.hostname,
        "dev_type": device.dev_type,
        "login_ip": device.login_ip,
        "eth0_prefix": device.eth0_prefix,
        "eth0_gateway": device.eth0_gateway,
        "eth0_mac": device.eth0_mac,
        "eth1_prefix": device.eth1_prefix,
        "eth1_gateway": device.eth1_gateway,
    }


def _global_yaml_subset(source: str) -> dict:
    """Read the bounded project-global block dialect without a leaf dependency.

    This is deliberately not general YAML: unsupported constructs fail closed.
    Real IB and NVL project globals are parity-checked against the generator.
    """
    if len(source.encode("utf-8")) > 1024 * 1024:
        raise SetupError("01-global.yaml exceeds the supported size")
    lines: list[tuple[int, str]] = []
    anchors: dict[str, object] = {}
    depth = 0
    for raw in source.splitlines():
        if re.match(r"^ *\t", raw):
            raise SetupError("01-global.yaml has tab indentation")
        quote = ""
        index = 0
        while index < len(raw):
            char = raw[index]
            if quote == "'":
                if char == "'" and index + 1 < len(raw) and raw[index + 1] == "'":
                    index += 2
                    continue
                if char == "'":
                    quote = ""
            elif quote == '"':
                if char == "\\":
                    index += 2
                    continue
                if char == '"':
                    quote = ""
            elif char in "'\"":
                quote = char
            elif char == "#" and (index == 0 or raw[index - 1].isspace()):
                raw = raw[:index]
                break
            index += 1
        text = raw.rstrip()
        if not text.strip():
            continue
        if text.strip() in {"---", "..."}:
            raise SetupError("01-global.yaml must contain one document")
        lines.append((len(text) - len(text.lstrip(" ")), text.lstrip(" ")))
    if not lines or len(lines) > 20000:
        raise SetupError("01-global.yaml is empty or too large")

    def scalar(value: str) -> object:
        if value.startswith("{"):
            raise SetupError("01-global.yaml flow mapping is unsupported")
        if value.startswith("["):
            if not value.endswith("]") or any(c in value[1:-1] for c in "[]{}"):
                raise SetupError("01-global.yaml nested flow syntax is unsupported")
            inner = value[1:-1]
            return [scalar(part.strip()) for part in inner.split(",")] if inner.strip() else []
        if value.startswith('"'):
            try:
                return ast.literal_eval(value)
            except (SyntaxError, ValueError) as exc:
                raise SetupError("01-global.yaml has an invalid quoted value") from exc
        if value.startswith("'"):
            if not value.endswith("'"):
                raise SetupError("01-global.yaml has an invalid quoted value")
            return value[1:-1].replace("''", "'")
        low = value.lower()
        if low in {"null", "~"}:
            return None
        if low in {"true", "yes", "on"}:
            return True
        if low in {"false", "no", "off"}:
            return False
        if re.fullmatch(r"[+-]?\d+", value):
            return int(value)
        if re.fullmatch(r"[+-]?(?:\d+\.\d*|\.\d+)(?:[Ee][+-]?\d+)?", value):
            return float(value)
        return value

    def key_value(text: str) -> tuple[str, str]:
        match = re.fullmatch(r"([^:]+):(?:\s+(.*))?", text)
        if not match or not re.fullmatch(r"[A-Za-z0-9_.-]+", match.group(1).strip()):
            raise SetupError("01-global.yaml has unsupported mapping syntax")
        return match.group(1).strip(), match.group(2) or ""

    def child(index: int, indent: int) -> tuple[object, int]:
        if index < len(lines) and (lines[index][0] > indent or
                                   lines[index][0] == indent and lines[index][1].startswith("- ")):
            return parse(index, lines[index][0])
        return None, index

    def value_at(value: str, index: int, indent: int) -> tuple[object, int]:
        if value.startswith("*"):
            if not re.fullmatch(r"\*[A-Za-z0-9_-]+", value) or value[1:] not in anchors:
                raise SetupError("01-global.yaml has an unknown alias")
            return copy.deepcopy(anchors[value[1:]]), index
        if value.startswith("&"):
            match = re.fullmatch(r"&([A-Za-z0-9_-]+)(?:\s+(.+))?", value)
            if not match:
                raise SetupError("01-global.yaml has invalid anchor syntax")
            parsed, index = (scalar(match.group(2)), index) if match.group(2) else child(index, indent)
            anchors[match.group(1)] = copy.deepcopy(parsed)
            return parsed, index
        return scalar(value), index

    def mapping(index: int, indent: int) -> tuple[dict, int]:
        result: dict = {}
        while index < len(lines) and lines[index][0] == indent and not lines[index][1].startswith("- "):
            key, value = key_value(lines[index][1])
            if key in result:
                raise SetupError("01-global.yaml has a duplicate key")
            index += 1
            result[key], index = value_at(value, index, indent) if value else child(index, indent)
        return result, index

    def sequence(index: int, indent: int) -> tuple[list, int]:
        result: list = []
        while index < len(lines) and lines[index][0] == indent and lines[index][1].startswith("- "):
            body = lines[index][1][2:].strip()
            index += 1
            if not body:
                value, index = child(index, indent)
            elif re.match(r"[^:]+:(?:\s|$)", body):
                key, remainder = key_value(body)
                member, index = value_at(remainder, index, indent) if remainder else child(index, indent)
                value = {key: member}
                if index < len(lines) and lines[index][0] > indent:
                    extra, index = mapping(index, lines[index][0])
                    if key in extra:
                        raise SetupError("01-global.yaml has a duplicate key")
                    value.update(extra)
            else:
                value, index = value_at(body, index, indent)
            result.append(value)
        return result, index

    def parse(index: int, indent: int) -> tuple[object, int]:
        nonlocal depth
        depth += 1
        try:
            if depth > 64:
                raise SetupError("01-global.yaml nesting exceeds the supported limit")
            if lines[index][1].startswith("- "):
                return sequence(index, indent)
            return mapping(index, indent)
        finally:
            depth -= 1

    document, end = parse(0, lines[0][0])
    if end != len(lines) or not isinstance(document, dict):
        raise SetupError("01-global.yaml has unsupported trailing syntax")
    return document


def _deep_merge_global(base: dict, override: dict) -> dict:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge_global(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _merged_global(document: dict, family: str) -> dict:
    switches = document.get("switches")
    if not isinstance(switches, list):
        raise SetupError("01-global.yaml switches must be a list")
    section = next((item[family] for item in switches
                    if isinstance(item, dict) and family in item), None)
    common = document.get("common", {})
    if not isinstance(common, dict) or not isinstance(common.get("switch", {}), dict) or not isinstance(section, dict):
        raise SetupError(f"01-global.yaml has invalid {family} or common.switch section")
    return _deep_merge_global(common.get("switch", {}), section)


def _neutral_services(tool: Path) -> dict[str, str]:
    neutral_path = tool.parents[2] / "infra/infra-neutral.conf"
    try:
        lines = neutral_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SetupError(f"neutral service authority unavailable: {neutral_path}") from exc
    values: dict[str, str] = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key in values or key not in {"DNS", "NTP", "TIMEZONE"}:
            raise SetupError("infra-neutral.conf has invalid or duplicate service entry")
        values[key] = value.strip()
    if set(values) != {"DNS", "NTP", "TIMEZONE"} or not all(values.values()):
        raise SetupError("infra-neutral.conf lacks a service fallback")
    return values


def _service_profile(tool: Path) -> Optional[dict[str, object]]:
    global_path = tool / "01-global.yaml"
    if not global_path.is_file():
        return None
    try:
        document = _global_yaml_subset(global_path.read_text(encoding="utf-8"))
        merged = _merged_global(document, "ib")
    except (OSError, UnicodeError) as exc:
        raise SetupError(f"cannot read 01-global.yaml: {exc}") from exc
    system = merged.get("system")
    if not isinstance(system, dict):
        raise SetupError("01-global.yaml IB system must be a mapping")
    neutral = _neutral_services(tool)
    output: dict[str, object] = {}
    for key, field, fallback in (
        ("dns", "server", "DNS"), ("ntp", "server", "NTP"),
        ("date-time", "timezone", "TIMEZONE"),
    ):
        group = system.get(key, {})
        if group is None:
            group = {}
        if not isinstance(group, dict):
            raise SetupError(f"01-global.yaml system.{key} must be a mapping")
        value = group.get(field)
        if value is None or value == "" or value == []:
            value = neutral[fallback] if field == "timezone" else [neutral[fallback]]
        if field == "server":
            if not isinstance(value, list) or not value or any(
                not isinstance(item, str) or not item.strip() for item in value
            ):
                raise SetupError(f"01-global.yaml system.{key}.{field} is invalid")
            for item in value:
                ib_command_argv(["nv", "set", "system", key, field, item])
            output[key] = list(value)
        else:
            if not isinstance(value, str) or not value.strip():
                raise SetupError("01-global.yaml timezone is invalid")
            ib_command_argv(["nv", "set", "system", key, field, value])
            output["timezone"] = value
    return output


def _public_key_fingerprint(line: str) -> str:
    if not isinstance(line, str) or re.search(r"[\x00-\x1f\x7f-\x9f]", line):
        raise SetupError("SSH public key contains a control character")
    parts = line.split()
    if len(parts) < 2 or not re.fullmatch(
        r"ssh-(?:ed25519|rsa)|ecdsa-sha2-nistp(?:256|384|521)|"
        r"sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com",
        parts[0],
    ):
        raise SetupError("invalid SSH public key type")
    try:
        blob = base64.b64decode(parts[1], validate=True)
        fields: list[bytes] = []
        offset = 0
        while offset < len(blob):
            if len(blob) - offset < 4:
                raise ValueError("truncated SSH key field")
            size = int.from_bytes(blob[offset:offset + 4], "big")
            offset += 4
            if size > 65536 or size > len(blob) - offset:
                raise ValueError("invalid SSH key field length")
            fields.append(blob[offset:offset + size])
            offset += size
        if not fields or fields[0].decode("ascii") != parts[0]:
            raise ValueError("SSH key type/blob mismatch")
        if parts[0] == "ssh-ed25519" and (len(fields) != 2 or len(fields[1]) != 32):
            raise ValueError("invalid ed25519 key payload")
        if len(fields) < 2:
            raise ValueError("SSH key has no public payload")
    except (ValueError, UnicodeError) as exc:
        raise SetupError("invalid SSH public key blob") from exc
    return "SHA256:" + base64.b64encode(
        hashlib.sha256(blob).digest()
    ).rstrip(b"=").decode("ascii")


def _public_key_profile(tool: Path, *, validate_with_ssh_keygen: bool = True
                        ) -> list[dict[str, str]]:
    directory = tool / "publickey"
    if not directory.is_dir():
        return []
    result: list[dict[str, str]] = []
    validator: Optional[str] = None
    for path in sorted(directory.glob("*.pub")):
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise SetupError(f"cannot read public key {path.name}: {exc}") from exc
        if not source.strip():
            continue  # project preparation placeholder; never deploy it
        for line in source.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                fingerprint = _public_key_fingerprint(line)
            except SetupError as exc:
                raise SetupError(f"invalid SSH public key in {path.name}") from exc
            if validate_with_ssh_keygen:
                if validator is None:
                    validator = shutil.which("ssh-keygen")
                    if validator is None:
                        raise SetupError("ssh-keygen is required to validate project public keys")
                try:
                    probe = subprocess.run(
                        [validator, "-l", "-E", "sha256", "-f", "/dev/stdin"],
                        input=line + "\n", capture_output=True, text=True,
                        timeout=10, check=False,
                    )
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise SetupError(
                        f"ssh-keygen could not validate public key in {path.name}"
                    ) from exc
                if (
                    probe.returncode != 0
                    or len(probe.stdout.splitlines()) != 1
                    or fingerprint not in probe.stdout.split()
                ):
                    raise SetupError(f"ssh-keygen rejected public key in {path.name}")
            result.append({"name": path.name, "line": line, "fingerprint": fingerprint})
    return result


def _validate_cache_profile(payload: dict) -> None:
    services = payload.get("services")
    if services is not None:
        if not isinstance(services, dict) or set(services) != {"dns", "ntp", "timezone"}:
            raise SetupError("target cache has invalid service categories")
        for category in ("dns", "ntp"):
            values = services[category]
            if not isinstance(values, list) or not values or any(
                not isinstance(value, str) for value in values
            ):
                raise SetupError(f"target cache has invalid {category} values")
            for value in values:
                ib_command_argv(["nv", "set", "system", category, "server", value])
        ib_command_argv([
            "nv", "set", "system", "date-time", "timezone", services["timezone"],
        ])
    keys = payload.get("public_keys")
    if not isinstance(keys, list):
        raise SetupError("target cache has invalid public-key list")
    if keys:
        key_install_command(keys)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _cache_authority(ib_csv: Path, p2p: Path,
                     global_file: Optional[Path]) -> dict[str, object]:
    """Record the P1 parser and source authority without requiring YAML on P2.

    This generator uses the bounded stdlib global dialect rather than PyYAML.
    PyYAML is explicitly not required by this stdlib-only generator.  P2
    never imports or reparses that dependency, even if it is installed.
    """
    return {
        "ib_csv_sha256": _file_sha256(ib_csv),
        "p2p_sha256": _file_sha256(p2p),
        "global_sha256": _file_sha256(global_file) if global_file else None,
        "generator": "initial-setup.py",
        "generator_sha256": _file_sha256(_SELF_SOURCE_PATH),
        "python": f"{sys.implementation.name}:{sys.version_info.major}.{sys.version_info.minor}",
        "pyyaml_required": False,
        "pyyaml_version": "not-required",
    }


def _valid_cache_authority(payload: dict, ib_csv: Path, p2p: Path,
                           global_file: Optional[Path]) -> bool:
    authority = payload.get("cache_authority")
    if not isinstance(authority, dict) or set(authority) != {
        "ib_csv_sha256", "p2p_sha256", "global_sha256", "generator",
        "generator_sha256", "python", "pyyaml_required", "pyyaml_version",
    }:
        return False
    hexdigest = r"[0-9a-f]{64}"
    if (
        authority["generator"] != "initial-setup.py"
        or authority["python"] !=
        f"{sys.implementation.name}:{sys.version_info.major}.{sys.version_info.minor}"
        or authority["pyyaml_required"] is not False
        or authority["pyyaml_version"] != "not-required"
        or any(not isinstance(authority[field], str)
               or not re.fullmatch(hexdigest, authority[field])
               for field in ("ib_csv_sha256", "p2p_sha256", "generator_sha256"))
        or (authority["global_sha256"] is not None and
            (not isinstance(authority["global_sha256"], str)
             or not re.fullmatch(hexdigest, authority["global_sha256"])))
    ):
        return False
    if (payload.get("global") is None) != (authority["global_sha256"] is None):
        return False
    if (
        authority["ib_csv_sha256"] != _file_sha256(ib_csv)
        or authority["p2p_sha256"] != _file_sha256(p2p)
        or authority["generator_sha256"] != _file_sha256(_SELF_SOURCE_PATH)
    ):
        return False
    if global_file is not None and global_file.is_file():
        if authority["global_sha256"] != _file_sha256(global_file):
            return False
    return True


def load_target_cache(cache_path: Path, ib_csv: Path,
                      p2p: Path, *, public_key_tool: Optional[Path] = None,
                      validate_public_keys_with_ssh_keygen: bool = False,
                      allow_baked_missing_global: bool = False
                      ) -> Optional[tuple[int, list[Target]]]:
    try:
        if cache_path.stat().st_mtime < max(ib_csv.stat().st_mtime, p2p.stat().st_mtime):
            return None
        checksum_path = cache_path.with_name(cache_path.name + ".sha256")
        if cache_path.stat().st_mtime_ns > checksum_path.stat().st_mtime_ns:
            return None
        raw_cache = cache_path.read_bytes()
        checksum_fields = checksum_path.read_text(encoding="ascii").split()
        if len(checksum_fields) != 2 or checksum_fields[1] != cache_path.name:
            return None
        if not re.fullmatch(r"[0-9a-f]{64}", checksum_fields[0]):
            return None
        if hashlib.sha256(raw_cache).hexdigest() != checksum_fields[0]:
            return None
        payload = json.loads(raw_cache.decode("utf-8"))
        if payload.get("version") != TARGET_CACHE_VERSION:
            return None
        if payload.get("ib_csv") != str(ib_csv) or payload.get("p2p") != str(p2p):
            return None
        current_global = public_key_tool / "01-global.yaml" if public_key_tool else None
        if not _valid_cache_authority(payload, ib_csv, p2p, current_global):
            return None
        if "global" not in payload or "services" not in payload or "public_keys" not in payload:
            return None
        _validate_cache_profile(payload)
        if public_key_tool is not None:
            global_file = public_key_tool / "01-global.yaml"
            if global_file.is_file():
                if payload["global"] != str(global_file.resolve()):
                    return None
                if global_file.stat().st_mtime_ns > cache_path.stat().st_mtime_ns:
                    return None
            elif payload["global"] is not None and not allow_baked_missing_global:
                return None
            source_dir = public_key_tool / "publickey"
            if source_dir.is_dir() and any(
                path.stat().st_mtime_ns > cache_path.stat().st_mtime_ns
                for path in source_dir.glob("*.pub")
            ):
                return None
            if source_dir.is_dir() or not allow_baked_missing_global:
                if _public_key_profile(
                    public_key_tool,
                    validate_with_ssh_keygen=validate_public_keys_with_ssh_keygen,
                ) != payload["public_keys"]:
                    return None
        targets = [
            Target(
                Device(**item["ib"]), Device(**item["ethernet"]),
                clean(item["ethernet_port"]), clean(item["ib_port_alias"]),
            )
            for item in payload["targets"]
        ]
        candidate_count = int(payload["ib_candidate_count"])
        if candidate_count < len(targets) or not targets:
            return None
        return candidate_count, targets
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


def save_target_cache(cache_path: Path, ib_csv: Path, p2p: Path,
                      ib_candidate_count: int, targets: list[Target], *,
                      global_file: Optional[Path] = None,
                      services: Optional[dict[str, object]] = None,
                      public_keys: Optional[list[dict[str, str]]] = None) -> None:
    payload = {
        "version": TARGET_CACHE_VERSION,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "ib_csv": str(ib_csv),
        "p2p": str(p2p),
        "global": str(global_file.resolve()) if global_file is not None else None,
        "cache_authority": _cache_authority(ib_csv, p2p, global_file),
        "ib_candidate_count": ib_candidate_count,
        "services": services,
        "public_keys": public_keys or [],
        "targets": [
            {
                "ib": device_to_dict(target.ib),
                "ethernet": device_to_dict(target.ethernet),
                "ethernet_port": target.ethernet_port,
                "ib_port_alias": target.ib_port_alias,
            }
            for target in targets
        ],
    }
    _validate_cache_profile(payload)
    checksum_path = cache_path.with_name(cache_path.name + ".sha256")
    temporary = cache_path.with_name(cache_path.name + ".tmp")
    checksum_temporary = checksum_path.with_name(checksum_path.name + ".tmp")
    try:
        raw_cache = (
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        ).encode("utf-8")
        temporary.write_bytes(raw_cache)
        checksum_temporary.write_text(
            f"{hashlib.sha256(raw_cache).hexdigest()}  {cache_path.name}\n",
            encoding="ascii",
        )
        temporary.replace(cache_path)
        checksum_temporary.replace(checksum_path)
    except OSError as exc:
        for unfinished in (temporary, checksum_temporary):
            try:
                unfinished.unlink(missing_ok=True)
            except OSError:
                pass
        raise SetupError(f"cannot write target cache {cache_path}: {exc}") from exc


def strip_ansi(value: str) -> str:
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value).replace("\r", "")


def interactive_run(command: list[str], responder: Callable[[str], Optional[str]],
                    timeout: int, *, display: bool = False) -> SessionResult:
    """Run a command on a PTY and answer prompts without third-party modules."""
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(command[0], command)
    output = ""
    password_changed = False
    deadline = time.monotonic() + timeout
    last_response_at = 0
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                os.kill(pid, signal.SIGTERM)
                raise SetupError(f"command timed out after {timeout}s: {shlex.join(command)}")
            ready, _, _ = select.select([fd], [], [], min(0.5, remaining))
            if ready:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    chunk = b""
                if chunk:
                    text = chunk.decode("utf-8", errors="replace")
                    output += text
                    if display:
                        sys.stdout.write(text)
                        sys.stdout.flush()
                    clean_output = strip_ansi(output[-12000:])
                    response = responder(clean_output)
                    if response is not None:
                        # PAM can emit Current/New/Retype prompts immediately after
                        # the preceding answer.  Do not discard an already-counted
                        # prompt during the short anti-echo interval, otherwise the
                        # responder will wait forever for text that will not repeat.
                        response_delay = 0.15 - (time.monotonic() - last_response_at)
                        if response_delay > 0:
                            time.sleep(response_delay)
                        os.write(fd, response.encode() + b"\n")
                        last_response_at = time.monotonic()
                        if "new password" in clean_output.casefold() or "retype" in clean_output.casefold():
                            password_changed = True
                        if getattr(responder, "password_change_blocked", False):
                            try:
                                os.killpg(pid, signal.SIGTERM)
                            except ProcessLookupError:
                                pass
                    deadline = time.monotonic() + timeout
            ended, status = os.waitpid(pid, os.WNOHANG)
            if ended:
                return SessionResult(
                    strip_ansi(output), os.waitstatus_to_exitcode(status),
                    password_changed,
                    bool(getattr(responder, "password_change_blocked", False)),
                )
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass


def ssh_options(timeout: int) -> list[str]:
    return [
        "-o", f"ConnectTimeout={timeout}",
        "-o", "ServerAliveInterval=10",
        "-o", "ServerAliveCountMax=2",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "LogLevel=ERROR",
    ]


def typed_argv(argv: object, *, label: str) -> list[str]:
    """Copy one command vector after rejecting scalar and control-byte carriers."""
    if type(argv) is not list or not argv:
        raise SetupError(f"{label} must be a non-empty argv array")
    if any(type(item) is not str or not item for item in argv):
        raise SetupError(f"{label} must contain only non-empty string tokens")
    if any(re.search(r"[\x00-\x1f\x7f-\x9f]", item) for item in argv):
        raise SetupError(f"{label} contains a forbidden control character")
    return list(argv)


def ethernet_command_argv(argv: object) -> list[str]:
    """Enforce the complete read-only command surface of a transit switch."""
    command = typed_argv(argv, label="Ethernet jump command")
    exact_commands = {
        ("hostname",),
        ("nv", "show", "interface"),
        ("nv", "config", "show"),
        ("ip", "-d", "link", "show"),
        ("bridge", "fdb", "show"),
        ("ip", "neighbor"),
    }
    tokens = tuple(command)
    if tokens in exact_commands:
        return command
    if (
        len(command) == 2
        and command[0] == "ifquery"
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", command[1])
    ):
        return command
    raise SetupError(
        "Ethernet jump command is not allowed by the read-only argv allowlist: "
        + shlex.join(command)
    )


def ib_command_argv(argv: object) -> list[str]:
    """Enforce the NVOS command vectors used by this Day-0 workflow."""
    command = typed_argv(argv, label="NVOS command")
    tokens = tuple(command)
    if (
        len(command) == 5 and command[:2] == ["sh", "-c"]
        and command[2] == _KEY_INSTALL_SCRIPT and command[3] == "--"
        and len(command[4]) <= 131072
        and re.fullmatch(r"[A-Za-z0-9+/=]+", command[4])
    ):
        return command
    if tokens in {
        ("true",),
        ("nv", "config", "show"),
        ("nv", "config", "show", "-o", "commands"),
        ("nv", "config", "apply"),
        ("nv", "config", "save"),
    }:
        return command
    if len(command) == 7 and command[:3] == ["nv", "set", "interface"]:
        interface, family, operation, value = command[3:]
        if interface not in {"eth0", "eth1", "eth0-1"} or family != "ipv4":
            raise SetupError(
                "NVOS command is not allowed by the Day-0 argv allowlist: "
                + shlex.join(command)
            )
        try:
            if operation == "address":
                ipaddress.IPv4Interface(value)
            elif operation == "gateway":
                ipaddress.IPv4Address(value)
            else:
                raise ValueError(operation)
        except ValueError as exc:
            raise SetupError(
                "NVOS command has an invalid interface value: "
                + shlex.join(command)
            ) from exc
        return command
    if (
        len(command) == 5
        and command[:4] == ["nv", "set", "system", "hostname"]
        and valid_hostname(command[4])
    ):
        return command
    if len(command) == 6 and command[:3] == ["nv", "set", "system"]:
        category, field, value = command[3:]
        if (category, field) == ("dns", "server"):
            try:
                ipaddress.ip_address(value)
            except ValueError as exc:
                raise SetupError("invalid DNS server address") from exc
            return command
        if (category, field) == ("ntp", "server") and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}", value
        ):
            return command
        if (category, field) == ("date-time", "timezone") and re.fullmatch(
            r"[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*", value
        ):
            return command
    raise SetupError(
        "NVOS command is not allowed by the Day-0 argv allowlist: "
        + shlex.join(command)
    )


def outer_ssh_command(ethernet: Device, user: str, remote_argv: list[str],
                      timeout: int, *, tty: bool = False,
                      local: bool = False) -> list[str]:
    command = typed_argv(remote_argv, label="outer SSH command")
    if local:
        return command
    return ["ssh", *( ["-tt"] if tty else [] ), *ssh_options(timeout),
            f"{user}@{ethernet.login_ip}", shlex.join(command)]


def ethernet_responder(ethernet_password: str) -> Callable[[str], Optional[str]]:
    answered_at = 0

    def respond(output: str) -> Optional[str]:
        nonlocal answered_at
        prompts = len(re.findall(r"(?im)(?:password|passphrase).*:\s*$", output))
        if prompts > answered_at:
            answered_at = prompts
            return ethernet_password
        if re.search(r"(?im)are you sure you want to continue connecting.*\?\s*$", output):
            return "yes"
        return None

    return respond


def run_on_ethernet(ethernet: Device, user: str, password: str,
                    remote_argv: list[str], timeout: int, *, local: bool = False) -> str:
    if ethernet.dev_type not in TRANSIT_DEVICE_TYPES:
        raise SetupError(
            f"{ethernet.hostname} is not a supported Ethernet transit device"
        )
    command = ethernet_command_argv(remote_argv)
    result = interactive_run(
        outer_ssh_command(ethernet, user, command, timeout, local=local),
        (lambda _output: None) if local else ethernet_responder(password), timeout,
    )
    if result.exit_code != 0:
        if (
            command[0] == "ifquery"
            and result.exit_code == 1
            and not result.output.strip()
        ):
            # ifupdown2 uses exit 1 with no output when the interface has no
            # stanza.  That semantic absence means the Linux default VRF; no
            # other exit/output combination is downgraded.
            return ""
        raise SetupError(
            f"Ethernet SSH failed for {ethernet.hostname} ({ethernet.login_ip}), "
            f"exit={result.exit_code}: {result.output.strip()[-600:]}"
        )
    return result.output


def collect_ethernet_interfaces(ethernet: Device, user: str, password: str,
                                timeout: int, *,
                                local: bool = False) -> tuple[str, str]:
    hostname_output = run_on_ethernet(
        ethernet, user, password, ["hostname"], timeout, local=local
    )
    interface_output = run_on_ethernet(
        ethernet, user, password, ["nv", "show", "interface"], timeout,
        local=local,
    )
    hostname_lines = [clean(line) for line in hostname_output.splitlines() if clean(line)]
    if len(hostname_lines) != 1 or not valid_hostname(hostname_lines[0]):
        raise SetupError(
            f"Ethernet switch {ethernet.login_ip} returned an invalid hostname: "
            f"{hostname_output.strip()!r}"
        )
    actual_hostname = hostname_lines[0]
    expected_short = normalize_name(ethernet.hostname).split(".", 1)[0]
    actual_short = normalize_name(actual_hostname).split(".", 1)[0]
    if actual_short != expected_short:
        raise SetupError(
            f"Ethernet identity mismatch at {ethernet.login_ip}: CSV expects "
            f"{ethernet.hostname}, device reports {actual_hostname}"
        )
    log(f"  Ethernet identity verified: {actual_hostname} ({ethernet.login_ip})")
    if not interface_output.strip():
        raise SetupError(f"empty 'nv show interface' output from {ethernet.hostname}")
    return actual_hostname, interface_output.strip()


def collect_ethernet_network_tables(ethernet: Device, user: str,
                                    password: str, timeout: int, *,
                                    local: bool = False) -> tuple[str, str, str]:
    links = run_on_ethernet(
        ethernet, user, password, ["ip", "-d", "link", "show"], timeout,
        local=local,
    )
    fdb = run_on_ethernet(
        ethernet, user, password, ["bridge", "fdb", "show"], timeout,
        local=local,
    )
    neighbors = run_on_ethernet(
        ethernet, user, password, ["ip", "neighbor"], timeout, local=local,
    )
    if not links.strip():
        raise SetupError(f"empty 'ip -d link show' output from {ethernet.hostname}")
    return links.strip(), fdb.strip(), neighbors.strip()


def snapshot_filename(hostname: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", clean(hostname))
    if not value or value in {".", ".."}:
        raise SetupError(f"cannot create snapshot filename for {hostname!r}")
    return value + ".snapshot.txt"


def discover_input_file(explicit: Optional[Path], preferred_name: str,
                        suffix: str, label: str) -> Path:
    if explicit is not None:
        path = explicit.expanduser().resolve()
        if not path.is_file():
            raise SetupError(f"{label} does not exist or is not a file: {path}")
        return path

    current = Path.cwd()
    preferred = current / preferred_name
    if preferred.is_file():
        return preferred.resolve()
    candidates = sorted(
        (
            path.resolve() for path in current.iterdir()
            if path.is_file()
            and path.suffix.casefold() == suffix.casefold()
            and not path.name.startswith((".", "~$"))
            and "tbd" not in path.name.casefold()
        ),
        key=lambda path: path.name.casefold(),
    )
    if not candidates:
        raise SetupError(
            f"no {label} found in current directory {current}; expected "
            f"{preferred_name!r} or one {suffix} file"
        )
    if len(candidates) > 1:
        raise SetupError(
            f"multiple {label} candidates found in current directory {current}; "
            "specify the input explicitly: "
            + ", ".join(path.name for path in candidates)
        )
    return candidates[0]


def save_ethernet_snapshot(directory: Path, ethernet: Device,
                           actual_hostname: str, location: str,
                           interfaces: str, links: str, fdb: str,
                           neighbors: str) -> Path:
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise SetupError(f"cannot create snapshot directory {directory}: {exc}") from exc
    path = directory / snapshot_filename(ethernet.hostname)
    temporary = path.with_name(path.name + ".tmp")
    content = (
        "Ethernet snapshot\n"
        f"Collected: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}\n"
        f"CSV hostname: {ethernet.hostname}\n"
        f"Device hostname: {actual_hostname}\n"
        f"Login IP: {ethernet.login_ip}\n"
        f"Execution: {location}\n"
        "\n===== nv show interface =====\n"
        f"{interfaces.rstrip()}\n"
        "\n===== ip -d link show =====\n"
        f"{links.rstrip()}\n"
        "\n===== bridge fdb show =====\n"
        f"{fdb.rstrip()}\n"
        "\n===== ip neighbor =====\n"
        f"{neighbors.rstrip()}\n"
    )
    try:
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(path)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise SetupError(f"cannot write Ethernet snapshot {path}: {exc}") from exc
    return path


def interface_status_line(interface_table: str, interface: str) -> str:
    escaped = re.escape(clean(interface))
    pattern = re.compile(
        rf"^\s*[|│┃]?\s*{escaped}(?:\s|[|│┃]|$)", re.IGNORECASE
    )
    matches = [
        line.strip() for line in interface_table.splitlines()
        if pattern.search(line)
    ]
    unique = list(dict.fromkeys(matches))
    if not unique:
        raise SetupError(f"{interface} is absent from 'nv show interface' output")
    if len(unique) > 1:
        raise SetupError(
            f"{interface} has multiple rows in 'nv show interface' output: "
            + " / ".join(unique)
        )
    return unique[0]


def interface_oper_status(status_line: str, interface: str) -> str:
    fields = status_line.translate(str.maketrans({
        "|": " ", "│": " ", "┃": " ",
    })).split()
    if len(fields) < 3 or fields[0].casefold() != clean(interface).casefold():
        raise SetupError(
            f"cannot parse Admin/Oper Status for {interface}: {status_line}"
        )
    return fields[2].casefold()


def _ip_link_blocks(link_table: str) -> dict[str, list[str]]:
    """Split ``ip -d link show`` output into blocks keyed by interface name."""
    blocks: dict[str, list[str]] = {}
    current: Optional[str] = None
    header = re.compile(r"^\s*\d+:\s+([^:@\s]+)(?:@[^:\s]+)?:\s+(.*)$")
    for raw_line in link_table.splitlines():
        match = header.match(raw_line)
        if match:
            current = clean(match.group(1))
            blocks.setdefault(current, []).append(raw_line)
        elif current is not None:
            blocks[current].append(raw_line)
    return blocks


def fdb_port_for_interface(link_table: str, interface: str) -> str:
    """Return the interface name used by FDB for a physical switch port.

    A bridge member keeps its original swp name in ``bridge fdb show``. A bond
    slave is represented by the bond master, so substitution occurs only when
    the detailed master block identifies link-kind ``bond``.
    """
    port = clean(interface)
    blocks = _ip_link_blocks(link_table)
    member_block = blocks.get(port)
    if not member_block:
        raise SetupError(f"{port} is absent from 'ip -d link show' output")
    master_match = re.search(r"(?:^|\s)master\s+(\S+)", member_block[0])
    if not master_match:
        return port
    master = master_match.group(1).split("@", 1)[0]
    master_block = blocks.get(master)
    if not master_block:
        raise SetupError(
            f"{port} reports master {master}, but that master is absent from "
            "'ip -d link show' output"
        )
    master_details = "\n".join(master_block)
    if re.search(r"(?m)^\s*bond\s+mode\s+", master_details):
        return master
    return port


def macs_on_port(fdb: str, port: str) -> list[str]:
    result: list[str] = []
    for line in fdb.splitlines():
        fields = line.split()
        if "dev" not in fields:
            continue
        try:
            line_port = fields[fields.index("dev") + 1]
        except IndexError:
            continue
        if line_port != port or "permanent" in {value.casefold() for value in fields}:
            continue
        match = MAC_RE.search(line)
        if match:
            mac = match.group(0).casefold()
            if mac not in result:
                result.append(mac)
    return result


def neighbor_for_port(fdb: str, neighbor_table: str, port: str) -> Neighbor:
    macs = macs_on_port(fdb, port)
    if not macs:
        raise SetupError(f"no dynamic MAC learned on Ethernet port {port}")
    matches: dict[tuple[str, str, str], Neighbor] = {}
    for line in neighbor_table.splitlines():
        fields = line.split()
        if len(fields) < 5 or "dev" not in fields or "lladdr" not in fields:
            continue
        try:
            address = ipaddress.ip_address(fields[0].split("%", 1)[0])
            interface = fields[fields.index("dev") + 1]
            mac = fields[fields.index("lladdr") + 1].casefold()
        except (ValueError, IndexError):
            continue
        if address.version == 6 and address.is_link_local and mac in macs:
            neighbor = Neighbor(str(address), interface, mac)
            matches[(neighbor.ipv6, neighbor.interface, neighbor.mac)] = neighbor
    if not matches:
        raise SetupError(
            f"port {port} learned MAC(s) {', '.join(macs)}, but ip neighbor has no "
            "matching IPv6 link-local entry"
        )
    if len(matches) != 1:
        details = ", ".join(
            f"{item.ipv6}%{item.interface}/{item.mac}" for item in matches.values()
        )
        raise SetupError(f"multiple IPv6 neighbors match port {port}: {details}")
    return next(iter(matches.values()))


def interface_vrf(ethernet: Device, user: str, password: str,
                  interface: str, timeout: int, *, local: bool = False) -> str:
    """Return the SVI's explicitly configured VRF, or default."""
    output = run_on_ethernet(
        ethernet, user, password, ["ifquery", interface], timeout,
        local=local,
    )
    matches = re.findall(r"(?im)^\s*vrf\s+(\S+)\s*$", output)
    unique = list(dict.fromkeys(clean(value) for value in matches if usable(value)))
    if len(unique) > 1:
        raise SetupError(
            f"interface {interface} has multiple VRF values in ifquery output: "
            + ", ".join(unique)
        )
    return unique[0] if unique else "default"


class NestedResponder:
    def __init__(self, ethernet_password: str, ib_default_password: str,
                 allow_password_change: bool):
        self.ethernet_password = ethernet_password
        self.ib_default_password = ib_default_password
        self.outer_answered = 0
        self.ib_login_attempt = 0
        self.hostkey_count = 0
        self.current_count = 0
        self.new_count = 0
        self.retype_count = 0
        self.allow_password_change = allow_password_change
        self.password_change_blocked = False

    def password_change_response(self, response: str) -> str:
        if self.allow_password_change:
            return response
        self.password_change_blocked = True
        return "\x03"

    def __call__(self, output: str) -> Optional[str]:
        lower = output.casefold()
        hostkeys = len(re.findall(r"are you sure you want to continue connecting", lower))
        if hostkeys > self.hostkey_count:
            self.hostkey_count = hostkeys
            return "yes"

        current = len(re.findall(r"(?im)^.*current.*password.*:\s*$", output))
        if current > self.current_count:
            self.current_count = current
            response = (
                self.ib_default_password
                if self.ib_login_attempt <= 1 else self.ethernet_password
            )
            return self.password_change_response(response)
        retype = len(re.findall(r"(?im)^.*(?:retype|repeat|confirm).*password.*:\s*$", output))
        if retype > self.retype_count:
            self.retype_count = retype
            return self.password_change_response(self.ethernet_password)
        # Check the more-specific retype prompt first: "Retype new password"
        # also contains "new password" and must not advance the wrong counter.
        new = len(re.findall(r"(?im)^.*new.*password.*:\s*$", output))
        if new > self.new_count:
            self.new_count = new
            return self.password_change_response(self.ethernet_password)

        password_lines = re.findall(r"(?im)^([^\n]*password[^\n]*):\s*$", output)
        # Outer password prompt normally contains the Ethernet login IP/user.
        outer_prompts = sum(
            1 for line in password_lines if "fe80:" not in line.casefold()
        )
        if outer_prompts > self.outer_answered:
            self.outer_answered = outer_prompts
            return self.ethernet_password
        ib_prompts = sum(1 for line in password_lines if "fe80:" in line.casefold())
        if ib_prompts > self.ib_login_attempt:
            self.ib_login_attempt = ib_prompts
            # Fresh NVOS normally uses the default password.  If it was already
            # changed during an earlier attempt, retry with the Ethernet password.
            return self.ib_default_password if ib_prompts == 1 else self.ethernet_password
        return None


def validate_jump_target(target: Target) -> None:
    """Bind a jump operation to one IB target and one supported transit."""
    if target.ib.dev_type != "ib":
        raise SetupError(
            f"{target.ib.hostname} is not a type=ib Day-0 target"
        )
    if target.ethernet.dev_type not in TRANSIT_DEVICE_TYPES:
        raise SetupError(
            f"{target.ethernet.hostname} is not a supported Ethernet transit device"
        )


def validate_network_selector(value: object, *, label: str) -> str:
    """Reject empty/control-bearing interface and VRF selectors."""
    if (
        type(value) is not str
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value)
    ):
        raise SetupError(f"invalid {label}: {value!r}")
    return value


def validate_neighbor_boundary(neighbor: Neighbor) -> None:
    """Validate semantic nested-SSH selectors before credentials are created."""
    if type(neighbor.ipv6) is not str or "%" in neighbor.ipv6:
        raise SetupError(f"invalid IPv6 link-local neighbor: {neighbor.ipv6!r}")
    try:
        address = ipaddress.IPv6Address(neighbor.ipv6)
    except ipaddress.AddressValueError as exc:
        raise SetupError(
            f"invalid IPv6 link-local neighbor: {neighbor.ipv6!r}"
        ) from exc
    if not address.is_link_local:
        raise SetupError(f"neighbor is not IPv6 link-local: {neighbor.ipv6!r}")
    validate_network_selector(neighbor.interface, label="neighbor interface")
    validate_network_selector(neighbor.vrf, label="neighbor VRF")


def nested_ssh_command(target: Target, neighbor: Neighbor, eth_user: str,
                       ib_user: str, timeout: int, ib_command: list[str], *,
                       local: bool = False) -> list[str]:
    validate_jump_target(target)
    validate_neighbor_boundary(neighbor)
    command = ib_command_argv(ib_command)
    destination = f"{ib_user}@{neighbor.ipv6}"
    nested = [
        "ip", "vrf", "exec", neighbor.vrf, "ssh", "-6",
        "-o", f"ConnectTimeout={timeout}",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "LogLevel=ERROR",
        destination, "-B", neighbor.interface, shlex.join(command),
    ]
    return outer_ssh_command(
        target.ethernet, eth_user, nested, timeout,
        tty=True, local=local,
    )


def run_on_ib(target: Target, neighbor: Neighbor, eth_user: str,
              ethernet_password: str, ib_user: str, ib_default_password: str,
              timeout: int, ib_command: list[str], *, local: bool = False,
              allow_password_change: bool = False) -> SessionResult:
    command = nested_ssh_command(
        target, neighbor, eth_user, ib_user, timeout, ib_command,
        local=local,
    )
    responder = NestedResponder(
        ethernet_password, ib_default_password, allow_password_change
    )
    result = interactive_run(
        command,
        responder,
        max(timeout * 4, 60),
    )
    password_change_completed = (
        result.password_changed
        and re.search(
            r"(?i)(?:password.*(?:updated|changed).*success|all authentication tokens updated)",
            result.output,
        )
    )
    if (
        result.exit_code != 0
        and not password_change_completed
        and not result.password_change_required
    ):
        tail = result.output.strip()[-1200:]
        raise SetupError(
            f"nested SSH to {target.ib.hostname} via {target.ethernet.hostname} "
            f"failed, exit={result.exit_code}: {tail}"
        )
    return result


def parse_nvue_state(output: str) -> DeviceState:
    eth0: list[str] = []
    eth1: list[str] = []
    eth0_gateways: list[str] = []
    eth1_gateways: list[str] = []
    hostname = ""
    commands: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line.startswith("nv set "):
            continue
        commands.append(line)
        match = re.match(r"nv set interface eth0 ipv4 address (\S+)", line)
        if match:
            eth0.append(match.group(1))
            continue
        match = re.match(r"nv set interface eth1 ipv4 address (\S+)", line)
        if match:
            eth1.append(match.group(1))
            continue
        match = re.match(r"nv set interface (eth0-1|eth0|eth1) ipv4 gateway (\S+)", line)
        if match:
            interface, gateway = match.groups()
            if interface in {"eth0", "eth0-1"}:
                eth0_gateways.append(gateway)
            if interface in {"eth1", "eth0-1"}:
                eth1_gateways.append(gateway)
            continue
        match = re.match(r"nv set system hostname\s+(\S+)", line)
        if match:
            hostname = match.group(1)
    return DeviceState(
        tuple(eth0), tuple(eth1), tuple(eth0_gateways),
        tuple(eth1_gateways), hostname, "\n".join(commands),
    )


def verify_fdb_eth0_mac(target: Target, learned_mac: str) -> None:
    """Compare an optional CSV MAC with the MAC learned on the P2P OOB port."""
    device = target.ib
    if not device.eth0_mac:
        return
    actual = normalize_mac(
        learned_mac, field=f"{target.ethernet.hostname}.{target.ethernet_port}.fdb_mac"
    )
    if actual != device.eth0_mac:
        raise SetupError(
            f"eth0 MAC mismatch: CSV expected {device.eth0_mac}, "
            f"OOB Leaf FDB reports {actual}; "
            "the CSV MAC may be wrong, or the IB device may be connected to the wrong "
            f"OOB Leaf interface (expected {target.ethernet.hostname}:"
            f"{target.ethernet_port} for {device.hostname})"
        )
    log(f"  eth0 MAC verified from OOB Leaf FDB: {actual}")


def state_is_unconfigured(state: DeviceState) -> bool:
    hostname = normalize_name(state.hostname)
    return (
        not state.eth0_addresses
        and not state.eth1_addresses
        and not state.eth0_gateways
        and not state.eth1_gateways
        and hostname in DEFAULT_HOSTNAMES
    )


def classify_auto_day0(device: Device, state: DeviceState) -> str:
    """Classify protected Day-0 fields without repairing partial configurations.

    A watch round may configure only the untouched factory state.  Existing
    fields must match the CSV exactly before services or keys are attempted;
    neither a missing field nor a contradictory field is silently complete.
    """
    if state_is_unconfigured(state):
        return "unconfigured"
    if normalize_name(state.hostname) != normalize_name(device.hostname):
        return "terminal"
    fields = (
        (state.eth0_addresses, device.eth0_prefix),
        (state.eth0_gateways, device.eth0_gateway),
        (state.eth1_addresses, device.eth1_prefix),
    )
    if any(actual != ((expected,) if expected else ()) for actual, expected in fields):
        return "terminal"
    allowed_eth1_gateways = (
        (device.eth1_gateway,) if device.eth1_prefix else (),
        (device.eth0_gateway,) if not device.eth1_prefix else (),
    )
    if state.eth1_gateways not in allowed_eth1_gateways:
        return "terminal"
    return "complete"


def desired_commands(device: Device) -> list[list[str]]:
    commands = [
        ["nv", "set", "interface", "eth0", "ipv4", "address", device.eth0_prefix],
    ]
    if device.eth1_prefix:
        commands.append(
            ["nv", "set", "interface", "eth1", "ipv4", "address", device.eth1_prefix]
        )
    if device.eth1_prefix and device.eth1_gateway != device.eth0_gateway:
        commands.extend([
            ["nv", "set", "interface", "eth0", "ipv4", "gateway", device.eth0_gateway],
            ["nv", "set", "interface", "eth1", "ipv4", "gateway", device.eth1_gateway],
        ])
    else:
        commands.append(
            [
                "nv", "set", "interface", "eth0-1", "ipv4", "gateway",
                device.eth0_gateway,
            ]
        )
    commands.extend([
        ["nv", "set", "system", "hostname", device.hostname],
        ["nv", "config", "apply"],
        ["nv", "config", "save"],
    ])
    return commands


def desired_service_commands(services: dict[str, object], current: str) -> list[list[str]]:
    """Add missing service values only; never synthesize an nv unset."""
    commands: list[list[str]] = []
    for category in ("dns", "ntp"):
        values = services.get(category)
        if not isinstance(values, list) or not values:
            raise SetupError(f"target cache has invalid {category} profile")
        for value in values:
            command = ib_command_argv(["nv", "set", "system", category, "server", value])
            if shlex.join(command) not in current.splitlines():
                commands.append(command)
    timezone = services.get("timezone")
    command = ib_command_argv(["nv", "set", "system", "date-time", "timezone", timezone])
    if shlex.join(command) not in current.splitlines():
        commands.append(command)
    return commands


def force_day0_needed(device: Device, state: DeviceState) -> bool:
    """Permit fill-only Day-0; a single contradictory value forbids all writes."""
    expected_eth1 = device.eth1_prefix
    expected_eth1_gateway = device.eth1_gateway if expected_eth1 else device.eth0_gateway
    fields = (
        ("eth0 address", state.eth0_addresses, device.eth0_prefix),
        ("eth1 address", state.eth1_addresses, expected_eth1),
        ("eth0 gateway", state.eth0_gateways, device.eth0_gateway),
        ("eth1 gateway", state.eth1_gateways, expected_eth1_gateway),
    )
    missing = False
    conflicts: list[str] = []
    for label, actual, expected in fields:
        if any(value != expected for value in actual):
            conflicts.append(f"{label}: expected {expected or 'unset'}, found {actual}")
        elif expected and not actual:
            missing = True
    hostname = normalize_name(state.hostname)
    if hostname in DEFAULT_HOSTNAMES:
        missing = True
    elif hostname != normalize_name(device.hostname):
        conflicts.append(f"hostname: expected {device.hostname}, found {state.hostname}")
    if conflicts:
        raise SetupError("Day-0 conflict; manual resolution required: " + "; ".join(conflicts))
    return missing


def key_install_command(keys: list[dict[str, str]]) -> list[str]:
    """Carry only validated public lines through a fixed, closed shell program."""
    if not isinstance(keys, list) or not keys:
        raise SetupError("public-key installation needs nonempty cache entries")
    lines: list[str] = []
    for entry in keys:
        if not isinstance(entry, dict) or set(entry) != {"name", "line", "fingerprint"}:
            raise SetupError("target cache has an invalid public-key entry")
        if not isinstance(entry["name"], str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]+\.pub", entry["name"]
        ):
            raise SetupError("target cache has invalid public-key name")
        line = entry["line"]
        fingerprint = _public_key_fingerprint(line)
        if entry.get("fingerprint") != fingerprint:
            raise SetupError("target cache has mismatched public-key fingerprint")
        lines.append(line)
    encoded = base64.b64encode(("\n".join(lines) + "\n").encode("utf-8")).decode("ascii")
    return ib_command_argv(["sh", "-c", _KEY_INSTALL_SCRIPT, "--", encoded])


def verify_state(device: Device, state: DeviceState) -> None:
    expected_eth1 = (device.eth1_prefix,) if device.eth1_prefix else ()
    errors: list[str] = []
    if device.eth0_prefix not in state.eth0_addresses:
        errors.append(f"eth0 expected {device.eth0_prefix}, got {state.eth0_addresses or 'none'}")
    if expected_eth1 and device.eth1_prefix not in state.eth1_addresses:
        errors.append(f"eth1 expected {device.eth1_prefix}, got {state.eth1_addresses or 'none'}")
    if device.eth0_gateway not in state.eth0_gateways:
        errors.append(
            f"eth0 gateway expected {device.eth0_gateway}, "
            f"got {state.eth0_gateways or 'none'}"
        )
    if device.eth1_prefix and device.eth1_gateway not in state.eth1_gateways:
        errors.append(
            f"eth1 gateway expected {device.eth1_gateway}, "
            f"got {state.eth1_gateways or 'none'}"
        )
    if normalize_name(state.hostname) != normalize_name(device.hostname):
        errors.append(f"hostname expected {device.hostname}, got {state.hostname or 'none'}")
    if errors:
        raise SetupError("post-configuration verification failed: " + "; ".join(errors))


def verify_ipv4_login(target: Target, vrf: str, eth_user: str,
                      ethernet_password: str, ib_user: str, timeout: int, *,
                      local: bool = False) -> None:
    validate_jump_target(target)
    validated_vrf = validate_network_selector(vrf, label="IPv4 verification VRF")
    command = ib_command_argv(["true"])
    nested = [
        "ip", "vrf", "exec", validated_vrf, "ssh",
        "-o", f"ConnectTimeout={timeout}",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "LogLevel=ERROR",
        f"{ib_user}@{target.ib.login_ip}", shlex.join(command),
    ]
    command = outer_ssh_command(
        target.ethernet, eth_user, nested, timeout,
        tty=True, local=local,
    )
    result = interactive_run(
        command,
        NestedResponder(ethernet_password, ethernet_password, False),
        max(timeout * 3, 45),
    )
    if result.exit_code != 0:
        raise SetupError(
            f"IPv4 SSH verification failed for {target.ib.hostname} "
            f"({target.ib.login_ip}) via {target.ethernet.hostname}: "
            f"{result.output.strip()[-800:]}"
        )


def local_ethernet_keys(targets: list[Target], mode: str,
                        override: str) -> set[str]:
    switches = {
        normalize_name(target.ethernet.hostname): target.ethernet
        for target in targets
    }
    if mode == "management":
        if override:
            raise SetupError(
                "--local-ethernet-hostname cannot be used with "
                "--execution-mode management"
            )
        return set()
    local_names = {
        normalize_name(socket.gethostname()), normalize_name(socket.getfqdn())
    }
    local_shorts = {value.split(".", 1)[0] for value in local_names if value}
    if override:
        requested = normalize_name(override)
        matches = [
            key for key in switches
            if key == requested or key.split(".", 1)[0] == requested.split(".", 1)[0]
        ]
        if len(matches) != 1:
            raise SetupError(
                f"local Ethernet override {override!r} does not uniquely match "
                "an Ethernet switch used by the P2P targets"
            )
        return {matches[0]}
    matches = {
        key for key in switches if key.split(".", 1)[0] in local_shorts
    }
    if len(matches) > 1:
        raise SetupError(
            "local hostname matches multiple Ethernet devices: "
            + ", ".join(sorted(matches))
        )
    if mode == "ethernet" and not matches:
        raise SetupError(
            f"local hostname {socket.gethostname()!r} does not match an Ethernet "
            "device used by the P2P targets; specify --local-ethernet-hostname"
        )
    return matches


def prompt_ethernet_passwords(targets: list[Target], supplied: Optional[str],
                              local_keys: set[str]) -> dict[str, str]:
    passwords: dict[str, str] = {}
    switches: dict[str, Device] = {
        normalize_name(target.ethernet.hostname): target.ethernet for target in targets
    }
    if supplied is not None:
        return {key: supplied for key in switches}
    for key, switch in sorted(switches.items()):
        purpose = (
            ", local; also used as the new NVOS password"
            if key in local_keys else ""
        )
        passwords[key] = getpass.getpass(
            f"Ethernet password for {switch.hostname} ({switch.login_ip}{purpose}): "
        )
    return passwords


_AUTO_ENV_MAX_BYTES = 65536
_AUTO_CRON_MARKER = "# http-v3-req10c-auto"


def _required_auto_fd_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    if not nofollow or not cloexec:
        raise SetupError("auto.env safety requires O_NOFOLLOW and O_CLOEXEC")
    return nofollow | cloexec


def _auto_state_dir(tool: Path) -> Path:
    return tool / "xdr-initial-setup-logs"


def _auto_input_identity(*paths: Path) -> str:
    """Bind terminal outcomes to input bytes, not only mutable mtimes."""
    digest = hashlib.sha256()
    for path in paths:
        digest.update(str(path).encode("utf-8"))
        digest.update(b"\0")
        try:
            with path.open("rb") as source:
                for chunk in iter(lambda: source.read(65536), b""):
                    digest.update(chunk)
        except OSError as exc:
            raise SetupError(f"cannot bind auto input {path}: {exc}") from exc
        digest.update(b"\0")
    return digest.hexdigest()


def _load_auto_terminal(path: Path, identity: str) -> set[str]:
    flags = os.O_RDONLY | _required_auto_fd_flags()
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return set()
    except OSError as exc:
        raise SetupError(f"cannot safely read auto terminal state: {exc}") from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.geteuid() or info.st_mode & 0o077
            or info.st_size > 65536
        ):
            raise SetupError("auto terminal state is not an owned 0600 regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(65537)
    finally:
        os.close(fd)
    if len(raw) > 65536:
        raise SetupError("auto terminal state exceeds bounded size")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SetupError("auto terminal state is malformed") from exc
    if (
        not isinstance(payload, dict) or set(payload) != {"version", "inputs", "terminal"}
        or payload["version"] != 1
        or not isinstance(payload["inputs"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", payload["inputs"])
        or not isinstance(payload["terminal"], list)
        or any(not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_.-]+", name)
               for name in payload["terminal"])
        or len(payload["terminal"]) != len(set(payload["terminal"]))
    ):
        raise SetupError("auto terminal state schema is invalid")
    return set(payload["terminal"]) if payload["inputs"] == identity else set()


def _save_auto_terminal(path: Path, identity: str, names: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {"version": 1, "inputs": identity, "terminal": sorted(names)},
        separators=(",", ":"), sort_keys=True,
    ).encode("utf-8") + b"\n"
    if len(payload) > 65536:
        raise SetupError("auto terminal state exceeds bounded size")
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _required_auto_fd_flags()
    try:
        fd = os.open(temporary, flags, 0o600)
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
    except OSError as exc:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise SetupError(f"cannot safely publish auto terminal state: {exc}") from exc


def _auto_password_key(hostname: str) -> str:
    suffix = re.sub(r"[^A-Z0-9]", "_", hostname.upper())
    if not suffix or not re.fullmatch(r"[A-Z0-9_]+", suffix):
        raise SetupError(f"invalid OOB Leaf hostname for auto credential: {hostname!r}")
    return "ZTP_ETH_PASSWORD_" + suffix


def read_auto_credentials(path: Path) -> dict[str, str]:
    """Read one bounded, owned data file through a NOFOLLOW fd, never a shell."""
    flags = os.O_RDONLY | _required_auto_fd_flags()
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise SetupError(f"auto.env credential cannot be opened safely: {exc}") from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_size > _AUTO_ENV_MAX_BYTES
        ):
            raise SetupError("auto.env credential has unsafe owner, mode, link or size")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(_AUTO_ENV_MAX_BYTES + 1)
        if len(raw) > _AUTO_ENV_MAX_BYTES:
            raise SetupError("auto.env credential exceeds bounded size")
    finally:
        os.close(fd)
    try:
        data = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SetupError("auto.env credential is not UTF-8") from exc
    values: dict[str, str] = {}
    for line in data.splitlines():
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=([^\x00-\x1f\x7f]*)", line)
        if not match:
            raise SetupError("auto.env credential contains a malformed KEY=VALUE line")
        key, value = match.groups()
        if (
            key in values
            or not value
            or key not in {"NVOS_INITIAL_PASSWORD", "ZTP_ETH_PASSWORD"}
            and not re.fullmatch(r"ZTP_ETH_PASSWORD_[A-Z0-9_]+", key)
        ):
            raise SetupError("auto.env credential contains an unknown, repeated or empty key")
        values[key] = value
    if not values.get("NVOS_INITIAL_PASSWORD"):
        raise SetupError("auto.env credential lacks NVOS_INITIAL_PASSWORD")
    if not any(key.startswith("ZTP_ETH_PASSWORD") for key in values):
        raise SetupError("auto.env credential lacks OOB Leaf password")
    return values


def _auto_passwords_for_targets(credentials: dict[str, str],
                                targets: list[Target]) -> dict[str, str]:
    passwords: dict[str, str] = {}
    normalized_keys: dict[str, str] = {}
    for target in targets:
        host = target.ethernet.hostname
        key = normalize_name(host)
        variable = _auto_password_key(host)
        previous = normalized_keys.setdefault(variable, key)
        if previous != key:
            raise SetupError("auto.env OOB Leaf hostname normalization collision")
        value = credentials.get(variable, credentials.get("ZTP_ETH_PASSWORD"))
        if not value:
            raise SetupError(f"auto.env credential lacks OOB Leaf password for {host}")
        passwords[key] = value
    return passwords


def install_oob_management_key(ethernet: Device, user: str, password: str,
                               entry: dict[str, str], timeout: int) -> None:
    """Install only the baked management key on a genuine OOB Leaf.

    The eth_jump transit type is intentionally not eligible: its owner-facing
    contract forbids any remote write.  This is a closed hard-coded installer,
    not a relaxation of the read-only Ethernet argv allowlist.
    """
    if ethernet.dev_type not in {"eth", "ethernet"}:
        raise SetupError(
            f"OOB key installation is not authorized for transit type {ethernet.dev_type}"
        )
    if entry.get("name") != "mgmt-server.pub":
        raise SetupError("OOB key installation accepts only mgmt-server.pub")
    command = key_install_command([entry])
    remote = outer_ssh_command(ethernet, user, command, timeout, tty=True)
    result = interactive_run(remote, ethernet_responder(password), max(timeout * 3, 45))
    if result.exit_code != 0:
        raise SetupError(
            f"OOB Leaf management-key installation failed for {ethernet.hostname} "
            f"(exit={result.exit_code})"
        )


def _write_auto_credentials(path: Path, initial: str,
                            passwords: dict[str, str], targets: list[Target]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["NVOS_INITIAL_PASSWORD=" + initial]
    hostname_for_key = {
        normalize_name(target.ethernet.hostname): target.ethernet.hostname
        for target in targets
    }
    for key, password in sorted(passwords.items()):
        if any(c in password for c in "\r\n\x00"):
            raise SetupError("auto.env credential contains an invalid password control")
        lines.append(_auto_password_key(hostname_for_key[key]) + "=" + password)
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    if len(payload) > _AUTO_ENV_MAX_BYTES:
        raise SetupError("auto.env credential exceeds bounded size")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _required_auto_fd_flags()
    try:
        fd = os.open(path, flags, 0o600)
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise SetupError(f"auto.env credential cannot be published safely: {exc}") from exc


def _auto_marker(path: Path) -> None:
    """Persist nonsecret watch ownership even if auto.env is later missing."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _required_auto_fd_flags()
        try:
            fd = os.open(path, flags, 0o600)
            try:
                os.write(fd, b"http-v3-req10c-auto-v1\n")
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as exc:
            raise SetupError(f"cannot create owned auto watch marker: {exc}") from exc
        return
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
        or info.st_size != len(b"http-v3-req10c-auto-v1\n")
        or path.read_bytes() != b"http-v3-req10c-auto-v1\n"
    ):
        raise SetupError("auto watch marker is not owned or valid")


@contextmanager
def _auto_crontab_lock(tool: Path):
    """Serialize this project's crontab RMW operations, not foreign clients.

    The lock inode is retained after cleanup: unlinking it while a process
    waits would allow two independent lock generations to enter together.
    The project's log directory may be a managed link, so pin and validate
    the opened destination directory before opening the lock relative to it.
    """
    state = _auto_state_dir(tool)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_CLOEXEC"):
        raise SetupError("secure project crontab lock requires directory/CLOEXEC flags")
    try:
        directory_fd = os.open(state, directory_flags)
    except OSError as exc:
        raise SetupError(f"cannot open project crontab lock directory: {exc}") from exc
    try:
        directory_info = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or directory_info.st_uid != os.geteuid()
            or directory_info.st_mode & 0o022
        ):
            raise SetupError("project crontab lock directory is not safely owned")
        try:
            fd = os.open(
                "auto-crontab.lock",
                os.O_RDWR | os.O_CREAT | _required_auto_fd_flags(),
                0o600, dir_fd=directory_fd,
            )
        except OSError as exc:
            raise SetupError(f"cannot open project crontab lock safely: {exc}") from exc
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o777 != 0o600
            ):
                raise SetupError("project crontab lock is not an owned 0600 single-link file")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                linked = os.stat(
                    "auto-crontab.lock", dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                if (linked.st_dev, linked.st_ino) != (info.st_dev, info.st_ino):
                    raise SetupError("project crontab lock pathname changed")
                current = os.stat(state)
                if (current.st_dev, current.st_ino) != (
                    directory_info.st_dev, directory_info.st_ino
                ):
                    raise SetupError("project crontab lock directory changed")
                yield
            except OSError as exc:
                raise SetupError(f"project crontab lock failed: {exc}") from exc
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)


def _read_auto_crontab() -> str:
    try:
        result = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True, timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SetupError(f"cannot read current-user crontab: {exc}") from exc
    if result.returncode == 0:
        return result.stdout
    if result.returncode == 1 and "no crontab" in result.stderr.casefold():
        return ""
    raise SetupError(f"cannot read current-user crontab (exit {result.returncode})")


def _write_auto_crontab(contents: str) -> None:
    try:
        result = subprocess.run(
            ["crontab", "-"], input=contents, capture_output=True,
            text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SetupError(f"cannot update current-user crontab: {exc}") from exc
    if result.returncode != 0:
        raise SetupError(f"cannot update current-user crontab (exit {result.returncode})")


def _own_auto_cron_line(line: str, tool: Path, credentials: Path) -> bool:
    if _AUTO_CRON_MARKER in line and str(tool / "initial-setup.py") in line:
        return True
    # Cleanup of the documented pre-marker shape remains exact to the known
    # script and credential path, never a generic 'initial-setup.py' match.
    return (
        line.startswith("*/10 * * * * ")
        and "initial-setup.py --auto --apply --yes --credentials-file " in line
        and str(credentials) in line
        and str(tool) in line
    )


def _install_auto_watch(tool: Path, credentials: Path, ib_csv: Path,
                        p2p: Path, cache: Path, report: Path,
                        snapshots: Path, *, force: bool) -> None:
    state = _auto_state_dir(tool)
    state.mkdir(parents=True, exist_ok=True)
    with _auto_crontab_lock(tool):
        _install_auto_watch_locked(
            tool, credentials, ib_csv, p2p, cache, report, snapshots, force=force,
        )


def _install_auto_watch_locked(tool: Path, credentials: Path, ib_csv: Path,
                               p2p: Path, cache: Path, report: Path,
                               snapshots: Path, *, force: bool) -> None:
    state = _auto_state_dir(tool)
    _auto_marker(state / "auto-watch.state")
    python = Path(sys.executable).resolve()
    if not python.is_absolute():
        raise SetupError("auto cron Python executable is not absolute")
    args = [
        str(python), str(tool / "initial-setup.py"), "--auto", "--apply", "--yes",
        "--credentials-file", str(credentials), "--execution-mode", "management",
        "--ib-csv", str(ib_csv), "--p2p", str(p2p), "--target-cache", str(cache),
        "--report", str(report), "--snapshot-dir", str(snapshots),
    ]
    if force:
        args.append("--force")
    shell = (
        "cd " + shlex.quote(str(tool)) + " && "
        + "flock -w 0 " + shlex.quote(str(state / "auto.lock")) + " "
        + shlex.join(args) + " >> " + shlex.quote(str(state / "auto-cron.log"))
        + " 2>&1 " + _AUTO_CRON_MARKER
    )
    job = "*/10 * * * * " + shell + "\n"
    existing = _read_auto_crontab()
    retained = "".join(
        line for line in existing.splitlines(keepends=True)
        if not _own_auto_cron_line(line, tool, credentials)
    )
    if retained and not retained.endswith("\n"):
        retained += "\n"
    _write_auto_crontab(retained + job)


def _remove_auto_watch(tool: Path, credentials: Path) -> None:
    with _auto_crontab_lock(tool):
        _remove_auto_watch_locked(tool, credentials)


def _remove_auto_watch_locked(tool: Path, credentials: Path) -> None:
    existing = _read_auto_crontab()
    retained = "".join(
        line for line in existing.splitlines(keepends=True)
        if not _own_auto_cron_line(line, tool, credentials)
    )
    if retained != existing:
        _write_auto_crontab(retained)
    if credentials.exists() or credentials.is_symlink():
        # A bad replacement is not deleted, because it could be a foreign
        # object.  Report a repairable failure instead of hiding it.
        read_auto_credentials(credentials)
        credentials.unlink()
    marker = _auto_state_dir(tool) / "auto-watch.state"
    if marker.exists() or marker.is_symlink():
        _auto_marker(marker)
        marker.unlink()


def confirm_first_device_change(target: Target, reason: str) -> bool:
    log(
        f"\nFIRST DEVICE CHANGE: {target.ib.hostname} via "
        f"{target.ethernet.hostname}:{target.ethernet_port}"
    )
    log(f"  Required action: {reason}")
    answer = input(
        "Authorize this change and subsequent eligible IB devices? [y/N]: "
    ).strip().casefold()
    return answer in {"y", "yes"}


def run_service_stage(target: Target, neighbor: Neighbor, eth_user: str,
                      eth_password: str, ib_user: str, timeout: int,
                      services: Optional[dict[str, object]], current: str,
                      *, local: bool, apply: bool, authorized: bool) -> tuple[bool, bool]:
    if services is None:
        log("  Services SKIP: 01-global.yaml was unavailable at cache generation.")
        return authorized, True
    commands = desired_service_commands(services, current)
    if not commands:
        log("  Services SKIP: all desired values are already present; no flash save.")
        return authorized, True
    for command in commands:
        log(f"  Services {'APPLY' if apply else 'WOULD APPLY'}: {shlex.join(command)}")
    if not apply:
        return authorized, False
    if not authorized:
        authorized = confirm_first_device_change(
            target, "apply the missing NVOS services and verify them independently"
        )
        if not authorized:
            log("  Services SKIP: device changes were not authorized.")
            return False, True
    for command in (*commands, ["nv", "config", "apply"], ["nv", "config", "save"]):
        run_on_ib(target, neighbor, eth_user, eth_password, ib_user,
                  eth_password, timeout, command, local=local)
    result = run_on_ib(
        target, neighbor, eth_user, eth_password, ib_user, eth_password, timeout,
        ["nv", "config", "show", "-o", "commands"], local=local,
    )
    remaining = desired_service_commands(services, result.output)
    if remaining:
        raise SetupError("service verification failed: " +
                         ", ".join(shlex.join(command) for command in remaining))
    log("  Services SUCCESS: desired values verified.")
    return authorized, False


def verify_management_key_possession(target: Target, ib_user: str,
                                     entry: dict[str, str], private_key: Path,
                                     timeout: int) -> None:
    """Prove the installed management key by a public-key-only IPv4 reconnect."""
    if private_key.is_symlink() or not private_key.is_file():
        raise SetupError("management private key is not a regular local file")
    if not valid_ssh_user(ib_user):
        raise SetupError("invalid IB user for public-key verification")
    try:
        login_ip = str(ipaddress.IPv4Address(target.ib.login_ip))
        derived = subprocess.run(
            ["ssh-keygen", "-y", "-f", str(private_key)],
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=max(timeout, 10), check=False,
        )
        if derived.returncode != 0:
            raise SetupError("local management private key could not be read")
        if _public_key_fingerprint(derived.stdout.strip()) != entry["fingerprint"]:
            raise SetupError("local management private key does not match installed public key")
        probe = [
            "ssh", "-i", str(private_key),
            "-o", "BatchMode=yes",
            "-o", "PreferredAuthentications=publickey",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "IdentitiesOnly=yes",
            "-o", f"ConnectTimeout={timeout}",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "LogLevel=ERROR",
            f"{ib_user}@{login_ip}", "true",
        ]
        result = subprocess.run(
            probe, stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=max(timeout * 2, 30), check=False,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        raise SetupError("management public-key verification could not complete") from exc
    if result.returncode != 0:
        raise SetupError("management public-key-only IPv4 SSH verification failed")


def run_key_stage(target: Target, neighbor: Neighbor, eth_user: str,
                  eth_password: str, ib_user: str, timeout: int,
                  keys: list[dict[str, str]], *, local: bool,
                  apply: bool, authorized: bool,
                  management_private_key: Optional[Path] = None) -> bool:
    if not keys:
        log("  Public keys SKIP: no usable project public keys were baked into cache.")
        return authorized
    command = key_install_command(keys)
    for entry in keys:
        log(f"  Public key {'INSTALL' if apply else 'WOULD INSTALL'}: "
            f"{entry['name']} {entry['fingerprint']}")
    if not apply:
        return authorized
    if not authorized:
        authorized = confirm_first_device_change(
            target, "install validated project public keys into authorized_keys"
        )
        if not authorized:
            log("  Public keys SKIP: device changes were not authorized.")
            return False
    run_on_ib(target, neighbor, eth_user, eth_password, ib_user,
              eth_password, timeout, command, local=local)
    for entry in keys:
        if entry["name"] == "mgmt-server.pub" and management_private_key is not None:
            verify_management_key_possession(
                target, ib_user, entry, management_private_key, timeout,
            )
            log(f"  Public key {entry['name']} {entry['fingerprint']}: 已验证")
        else:
            log(f"  Public key {entry['name']} {entry['fingerprint']}: 已写入，未验证")
    return authorized


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Initialize unconfigured NVOS switches through their Ethernet OOB peers."
    )
    parser.add_argument(
        "--ib-csv", type=Path,
        help="device CSV (default: discover CSV in current directory)",
    )
    parser.add_argument(
        "--p2p", type=Path,
        help="P2P XLSX/DOT/CSV/log (default: discover XLSX in current directory)",
    )
    parser.add_argument("--eth-user", default="cumulus",
                        help="Ethernet SSH user (default: cumulus)")
    parser.add_argument("--ib-user", default="admin",
                        help="NVOS SSH user (default: admin)")
    password_source = parser.add_mutually_exclusive_group()
    password_source.add_argument(
        "--ib-initial-password-env", default="NVOS_INITIAL_PASSWORD",
        metavar="NAME",
        help=("environment variable containing the initial NVOS password "
              "(default: NVOS_INITIAL_PASSWORD)"),
    )
    password_source.add_argument(
        "--factory-default-admin", action="store_true",
        help=("explicit factory-default admin credential flow; read "
              "NVOS_FACTORY_DEFAULT_ADMIN_PASSWORD or prompt without echo"),
    )
    parser.add_argument("--connect-timeout", type=int, default=10,
                        help="SSH connect timeout seconds (default: 10)")
    parser.add_argument("--plan", action="store_true",
                        help="show targets and all potential Day-0, service and key commands without connecting")
    parser.add_argument("--apply", action="store_true",
                        help="configure devices that pass the all-unconfigured check")
    parser.add_argument("--force", action="store_true",
                        help="only complete missing Day-0 fields; refuse conflicts")
    parser.add_argument(
        "--auto", action="store_true",
        help="watch all CSV IB switches; retry every 10 minutes until configured",
    )
    parser.add_argument(
        "--credentials-file", type=Path,
        help="owned 0600 auto.env data file for non-interactive --auto rounds",
    )
    parser.add_argument("--yes", action="store_true",
                        help="with --apply, do not ask for final confirmation")
    parser.add_argument(
        "--report", type=Path,
        default=Path("xdr-initial-setup-logs/initial-setup-report.log"),
        help=("run report path (default: "
              "./xdr-initial-setup-logs/initial-setup-report.log)"),
    )
    parser.add_argument(
        "--snapshot-dir", type=Path,
        default=Path("xdr-initial-setup-logs/initial-setup-ethernet-snapshots"),
        help=("Ethernet snapshot directory (default: "
              "./xdr-initial-setup-logs/initial-setup-ethernet-snapshots)"),
    )
    parser.add_argument(
        "--target-cache", type=Path,
        default=Path("xdr-initial-setup-logs/initial-setup-targets.json"),
        help=("parsed target cache (default: "
              "./xdr-initial-setup-logs/initial-setup-targets.json)"),
    )
    parser.add_argument(
        "--generate-json", "--generate-json-only",
        dest="generate_json", action="store_true",
        help="validate inputs, generate target JSON/checksum, then exit",
    )
    parser.add_argument(
        "--execution-mode", choices=("auto", "management", "ethernet"),
        default="auto",
        help="execution location (default: auto-detect local Ethernet)",
    )
    parser.add_argument(
        "--local-ethernet-hostname", default="",
        help="Ethernet CSV hostname representing this local switch",
    )
    parser.add_argument("--ethernet-password", help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> int:
    global REPORT_HANDLE
    args = parse_args()
    if args.plan and args.apply:
        raise SetupError("--plan cannot be combined with --apply")
    if args.generate_json and (args.plan or args.apply):
        raise SetupError(
            "--generate-json cannot be combined with --plan or --apply"
        )
    if args.auto:
        if args.plan or args.generate_json or args.execution_mode == "ethernet":
            raise SetupError("--auto requires management execution, not plan or P1 generation")
        if args.ethernet_password is not None:
            raise SetupError("--auto forbids --ethernet-password in argv")
        if args.credentials_file is None and not sys.stdin.isatty():
            raise SetupError("interactive first --auto round requires a tty")
        args.apply = True
        args.yes = True
    elif args.credentials_file is not None:
        raise SetupError("--credentials-file is only valid with --auto")
    auto_credentials = (
        read_auto_credentials(args.credentials_file)
        if args.credentials_file is not None else None
    )
    if not valid_ssh_user(args.eth_user):
        raise SetupError(f"invalid --eth-user: {args.eth_user!r}")
    if not valid_ssh_user(args.ib_user):
        raise SetupError(f"invalid --ib-user: {args.ib_user!r}")
    if not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]{0,127}", args.ib_initial_password_env,
    ):
        raise SetupError(
            f"invalid --ib-initial-password-env: {args.ib_initial_password_env!r}"
        )
    if not 1 <= args.connect_timeout <= 600:
        raise SetupError("--connect-timeout must be between 1 and 600 seconds")
    ib_csv_path = discover_input_file(
        args.ib_csv, "ib.csv", ".csv", "IB device CSV"
    )
    p2p_path = discover_input_file(
        args.p2p, "p2p.xlsx", ".xlsx", "P2P workbook"
    )
    cache_path = args.target_cache.resolve()
    report_path = args.report.resolve()
    snapshot_directory = args.snapshot_dir.resolve()
    for output_parent in dict.fromkeys((cache_path.parent, report_path.parent)):
        try:
            output_parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise SetupError(
                f"cannot create output directory {output_parent}: {exc}"
            ) from exc
    if args.generate_json:
        ib_devices, eth_devices = load_devices(ib_csv_path)
        links = parse_p2p(p2p_path)
        validate_p2p_links(links)
        targets = build_targets(links, ib_devices, eth_devices)
        tool = Path(__file__).resolve().parent
        services = _service_profile(tool)
        public_keys = _public_key_profile(tool)
        global_file = tool / "01-global.yaml"
        save_target_cache(
            cache_path, ib_csv_path, p2p_path, len(ib_devices), targets,
            global_file=global_file if global_file.is_file() else None,
            services=services, public_keys=public_keys,
        )
        print(f"Input CSV: {ib_csv_path}")
        print(f"Input P2P: {p2p_path}")
        print(f"Generated: {cache_path}")
        print(f"Generated: {cache_path.with_name(cache_path.name + '.sha256')}")
        print(
            f"IB candidates: {len(ib_devices)}; "
            f"P2P management links: {len(targets)}"
        )
        return 0
    try:
        REPORT_HANDLE = report_path.open("w", encoding="utf-8")
    except OSError as exc:
        raise SetupError(f"cannot create report {report_path}: {exc}") from exc
    log(f"Report: {report_path}")
    log(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    log(f"Input CSV: {ib_csv_path}")
    log(f"Input P2P: {p2p_path}")
    if args.auto:
        log(
            "AUTO WATCH: --auto authorizes --apply --yes including future IB password "
            "changes, installs an OOB Leaf key when supported, and may write a "
            "0600 auto.env with all OOB Leaf and IB passwords.  Disclosure of "
            "that file exposes all of those devices.  Edit CSV to correct "
            "bad MACs; the next round revalidates inputs."
        )
    tool = Path(__file__).resolve().parent
    source_inputs_available = (
        args.execution_mode in {"management", "ethernet"}
        or (args.execution_mode == "auto" and (
            (tool / "publickey").is_dir() or (tool / "01-global.yaml").is_file()
        ))
    )
    cached = load_target_cache(
        cache_path, ib_csv_path, p2p_path,
        public_key_tool=tool if source_inputs_available else None,
        validate_public_keys_with_ssh_keygen=args.execution_mode == "management",
        allow_baked_missing_global=args.execution_mode != "management",
    )
    if cached is not None and args.execution_mode == "auto":
        # A disconnected Ethernet leaf legitimately has neither project link.
        # Distinguish it from a management host using validated target identities;
        # a management cache reuse still needs the same P1 key validation as minting.
        local_for_cache = local_ethernet_keys(
            cached[1], args.execution_mode, args.local_ethernet_hostname,
        )
        if not local_for_cache:
            cached = load_target_cache(
                cache_path, ib_csv_path, p2p_path, public_key_tool=tool,
                validate_public_keys_with_ssh_keygen=True,
                allow_baked_missing_global=False,
            )
    if cached is not None:
        ib_candidate_count, targets = cached
        log(f"Target cache: reused {cache_path}")
    else:
        if args.execution_mode == "ethernet":
            if cache_path.is_file():
                raise SetupError(
                    "target cache version, checksum, or input identity is invalid; "
                    "regenerate version 4 on the management server"
                )
            raise SetupError("target cache is missing; generate version 4 on the management server")
        ib_devices, eth_devices = load_devices(ib_csv_path)
        links = parse_p2p(p2p_path)
        validate_p2p_links(links)
        targets = build_targets(links, ib_devices, eth_devices)
        ib_candidate_count = len(ib_devices)
        services = _service_profile(tool)
        public_keys = _public_key_profile(tool)
        global_file = tool / "01-global.yaml"
        save_target_cache(
            cache_path, ib_csv_path, p2p_path, ib_candidate_count, targets,
            global_file=global_file if global_file.is_file() else None,
            services=services, public_keys=public_keys,
        )
        log(f"Target cache: generated {cache_path}")
    if args.auto:
        require_auto_full_target_coverage(ib_candidate_count, targets)
    cache_payload = json.loads(cache_path.read_text(encoding="utf-8"))
    services = cache_payload["services"]
    public_keys = cache_payload["public_keys"]
    auto_management_keys = (
        [entry for entry in public_keys if entry["name"] == "mgmt-server.pub"]
        if args.auto else []
    )
    if args.auto and not auto_management_keys:
        raise SetupError("--auto requires a validated mgmt-server.pub for OOB Leaf key install")

    log(f"IB candidates in CSV: {ib_candidate_count}")
    log(f"P2P management links: {len(targets)}")
    for target in targets:
        log(
            f"  {target.ib.hostname:<32} {target.ib_port_alias:<6} <- "
            f"{target.ethernet.hostname}:{target.ethernet_port} "
            f"({target.ethernet.login_ip})"
        )
    if args.apply:
        log(
            "Device changes: REQUESTED by --apply; confirmation will occur "
            "immediately before the first device change."
        )
    else:
        log("Device changes: DISABLED (no --apply); read-only device mode.")
    if args.plan:
        log("Plan lists potential commands; already-present values may be omitted at runtime.")
        for target in targets:
            log(f"  [{target.ib.hostname}] Day-0 commands:")
            for command in desired_commands(target.ib):
                log("    " + shlex.join(command))
            if services is None:
                log("    Services SKIP: 01-global.yaml was unavailable at cache generation.")
            else:
                log("    Services commands:")
                for command in desired_service_commands(services, ""):
                    log("    " + shlex.join(command))
                log("    nv config apply")
                log("    nv config save")
            if public_keys:
                log("    Public-key install command:")
                log("    " + shlex.join(key_install_command(public_keys)))
                for entry in public_keys:
                    log(f"    {entry['name']} {entry['fingerprint']}")
            else:
                log("    Public keys SKIP: no usable project public keys were baked into cache.")
        return 0

    initial_ib_password = (
        auto_credentials["NVOS_INITIAL_PASSWORD"]
        if auto_credentials is not None else resolve_initial_ib_password(
            args.ib_initial_password_env,
            factory_default_admin=args.factory_default_admin,
        )
    )

    local_keys = local_ethernet_keys(
        targets, args.execution_mode, args.local_ethernet_hostname
    )
    if args.auto and local_keys:
        raise SetupError(
            "--auto watch must run on the management server, not a local OOB Leaf"
        )
    management_private_key = None
    if args.execution_mode != "ethernet" and not local_keys:
        candidate_private_key = Path.home() / ".ssh" / "id_ed25519"
        if candidate_private_key.is_file() and not candidate_private_key.is_symlink():
            management_private_key = candidate_private_key
    if local_keys:
        log("Local Ethernet execution: " + ", ".join(sorted(local_keys)))
    else:
        log("Execution location: management server (all Ethernet access uses SSH)")
    passwords = (
        _auto_passwords_for_targets(auto_credentials, targets)
        if auto_credentials is not None else prompt_ethernet_passwords(
            targets, args.ethernet_password, local_keys
        )
    )
    apply_authorized = bool(args.apply and args.yes)
    if apply_authorized:
        log("Device changes: pre-authorized by --apply --yes.")

    interface_tables: dict[str, str] = {}
    network_tables: dict[str, tuple[str, str, str]] = {}
    table_failures: dict[str, str] = {}
    failures = configured = skipped = day0_skipped = services_skipped = 0
    completed_targets: set[str] = set()
    terminal_path = _auto_state_dir(tool) / "auto-terminal.json"
    terminal_identity = _auto_input_identity(ib_csv_path, p2p_path) if args.auto else ""
    terminal_targets = (
        _load_auto_terminal(terminal_path, terminal_identity) if args.auto else set()
    )
    ethernet_switches = {
        normalize_name(target.ethernet.hostname): target.ethernet
        for target in targets
    }
    log("\nCollecting Ethernet snapshots ...")
    for eth_key, ethernet in sorted(ethernet_switches.items()):
        ethernet_is_local = eth_key in local_keys
        eth_password = passwords[eth_key]
        location = "local" if ethernet_is_local else "SSH"
        log(f"  [{ethernet.hostname}] via {location}")
        try:
            actual_hostname, interface_tables[eth_key] = collect_ethernet_interfaces(
                ethernet, args.eth_user, eth_password, args.connect_timeout,
                local=ethernet_is_local,
            )
            network_tables[eth_key] = collect_ethernet_network_tables(
                ethernet, args.eth_user, eth_password, args.connect_timeout,
                local=ethernet_is_local,
            )
            links, fdb, neighbors = network_tables[eth_key]
            snapshot_path = save_ethernet_snapshot(
                snapshot_directory, ethernet, actual_hostname, location,
                interface_tables[eth_key], links, fdb, neighbors,
            )
            log(f"    Snapshot saved: {snapshot_path}")
        except SetupError as exc:
            table_failures[eth_key] = str(exc)
            log(f"    ERROR: {exc}")

    log("\nEvaluating IB devices from local Ethernet snapshots ...")
    for target in targets:
        eth_key = normalize_name(target.ethernet.hostname)
        eth_password = passwords[eth_key]
        ethernet_is_local = eth_key in local_keys
        log(f"\n[{target.ib.hostname}] via {target.ethernet.hostname}:{target.ethernet_port}")
        ib_key = normalize_name(target.ib.hostname)
        if args.auto and ib_key in terminal_targets:
            failures += 1
            log(
                "  Day-0 TERMINAL: recorded partial/conflicting configuration; "
                "IB login and writes skipped until CSV/P2P change or operator "
                "clears owned auto-terminal.json after manual repair."
            )
            continue
        try:
            if eth_key in table_failures:
                raise SetupError(
                    "Ethernet snapshot collection failed: "
                    + table_failures[eth_key]
                )
            interface_table = interface_tables[eth_key]
            try:
                status_line = interface_status_line(
                    interface_table, target.ethernet_port
                )
                oper_status = interface_oper_status(
                    status_line, target.ethernet_port
                )
            except SetupError as exc:
                skipped += 1
                log(f"  SKIP: Ethernet interface state is not verifiable: {exc}")
                continue
            log(f"  Ethernet interface: {status_line}")
            if oper_status != "up":
                skipped += 1
                log(
                    f"  SKIP: {target.ethernet_port} Oper Status is "
                    f"{oper_status!r}, not 'up'; local FDB/neighbor lookup and "
                    "IB login not attempted."
                )
                continue
            links, fdb, neighbors = network_tables[eth_key]
            fdb_port = fdb_port_for_interface(links, target.ethernet_port)
            if fdb_port != target.ethernet_port:
                log(
                    f"  Ethernet interface {target.ethernet_port} is a member of "
                    f"bond {fdb_port}; using {fdb_port} for FDB lookup."
                )
            neighbor = neighbor_for_port(fdb, neighbors, fdb_port)
            verify_fdb_eth0_mac(target, neighbor.mac)
            vrf = interface_vrf(
                target.ethernet, args.eth_user, eth_password,
                neighbor.interface, args.connect_timeout,
                local=ethernet_is_local,
            )
            neighbor = Neighbor(neighbor.ipv6, neighbor.interface, neighbor.mac, vrf)
            log(
                f"  MAC {neighbor.mac} -> {neighbor.ipv6} "
                f"dev {neighbor.interface} vrf {neighbor.vrf}"
            )

            result = run_on_ib(
                target, neighbor, args.eth_user, eth_password,
                args.ib_user, initial_ib_password, args.connect_timeout,
                ["nv", "config", "show", "-o", "commands"],
                local=ethernet_is_local,
                allow_password_change=apply_authorized,
            )
            if result.password_change_required:
                if not args.apply:
                    skipped += 1
                    log(
                        "  SKIP: NVOS requires its initial password change; "
                        "check-only mode cancelled it. Re-run with --apply to "
                        "authorize device changes."
                    )
                    continue
                if not apply_authorized:
                    apply_authorized = confirm_first_device_change(
                        target,
                        "change the initial NVOS admin password to the "
                        "corresponding Ethernet password, then inspect and "
                        "possibly configure Day-0 settings",
                    )
                    if not apply_authorized:
                        log("No device changes authorized; stopping.")
                        return 0
                result = run_on_ib(
                    target, neighbor, args.eth_user, eth_password,
                    args.ib_user, initial_ib_password, args.connect_timeout,
                    ["nv", "config", "show", "-o", "commands"],
                    local=ethernet_is_local,
                    allow_password_change=True,
                )
            if result.password_changed:
                log("  Initial NVOS password changed to the Ethernet switch password.")
                log("  Reconnecting with the new NVOS password ...")
                result = run_on_ib(
                    target, neighbor, args.eth_user, eth_password,
                    args.ib_user, eth_password, args.connect_timeout,
                    ["nv", "config", "show", "-o", "commands"],
                    local=ethernet_is_local,
                )
            state = parse_nvue_state(result.output)
            log(
                "  Current: eth0={} eth0-gateway={} eth1={} "
                "eth1-gateway={} hostname={}".format(
                    ",".join(state.eth0_addresses) or "unset",
                    ",".join(state.eth0_gateways) or "unset",
                    ",".join(state.eth1_addresses) or "unset",
                    ",".join(state.eth1_gateways) or "unset",
                    state.hostname or "unset",
                )
            )
            if args.auto:
                auto_day0 = classify_auto_day0(target.ib, state)
                if auto_day0 == "terminal":
                    failures += 1
                    terminal_targets.add(ib_key)
                    log(
                        "  Day-0 TERMINAL: protected fields are partially configured "
                        "or conflict with CSV; manual resolution required; no write attempted."
                    )
                    continue
                day0_required = auto_day0 == "unconfigured"
            else:
                day0_required = state_is_unconfigured(state)
            if args.force and not day0_required:
                try:
                    day0_required = force_day0_needed(target.ib, state)
                except SetupError as exc:
                    log(f"  Day-0 SKIP: {exc}")
                    day0_required = False
            if not day0_required:
                skipped += 1
                day0_skipped += 1
                log("  Day-0 SKIP: protected fields already configured; services remain eligible.")
                apply_authorized, service_was_skipped = run_service_stage(
                    target, neighbor, args.eth_user, eth_password, args.ib_user,
                    args.connect_timeout, services, state.raw_commands,
                    local=ethernet_is_local, apply=args.apply,
                    authorized=apply_authorized,
                )
                services_skipped += int(service_was_skipped)
                apply_authorized = run_key_stage(
                    target, neighbor, args.eth_user, eth_password, args.ib_user,
                    args.connect_timeout, public_keys, local=ethernet_is_local,
                    apply=args.apply, authorized=apply_authorized,
                    management_private_key=management_private_key,
                )
                completed_targets.add(normalize_name(target.ib.hostname))
                continue

            commands = desired_commands(target.ib)
            for command in commands:
                log(
                    f"  {'APPLY' if args.apply else 'WOULD APPLY'}: "
                    f"{shlex.join(command)}"
                )
            if not args.apply:
                log("  Check-only mode; use --apply to configure.")
                continue

            if not apply_authorized:
                apply_authorized = confirm_first_device_change(
                    target,
                    "apply the displayed NVUE Day-0 commands and then verify "
                    "configuration and IPv4 SSH",
                )
                if not apply_authorized:
                    log("No device changes authorized; stopping.")
                    return 0

            try:
                for command in commands:
                    run_on_ib(
                        target, neighbor, args.eth_user, eth_password,
                        args.ib_user, eth_password, args.connect_timeout,
                        command, local=ethernet_is_local,
                    )
                verify_result = run_on_ib(
                    target, neighbor, args.eth_user, eth_password,
                    args.ib_user, eth_password, args.connect_timeout,
                    ["nv", "config", "show", "-o", "commands"],
                    local=ethernet_is_local,
                )
                verify_state(target.ib, parse_nvue_state(verify_result.output))
                verify_ipv4_login(
                    target, neighbor.vrf, args.eth_user, eth_password,
                    args.ib_user, args.connect_timeout, local=ethernet_is_local,
                )
            except SetupError as exc:
                failures += 1
                log(f"  ERROR after device change: {exc}")
                log(
                    "  STOP: post-configuration verification did not complete; "
                    "no subsequent IB device will be configured."
                )
                break
            configured += 1
            log(f"  SUCCESS: configuration verified; IPv4 SSH to {target.ib.login_ip} succeeded.")
            apply_authorized, service_was_skipped = run_service_stage(
                target, neighbor, args.eth_user, eth_password, args.ib_user,
                args.connect_timeout, services, verify_result.output,
                local=ethernet_is_local, apply=args.apply,
                authorized=apply_authorized,
            )
            services_skipped += int(service_was_skipped)
            apply_authorized = run_key_stage(
                target, neighbor, args.eth_user, eth_password, args.ib_user,
                args.connect_timeout, public_keys, local=ethernet_is_local,
                apply=args.apply, authorized=apply_authorized,
                management_private_key=management_private_key,
            )
            completed_targets.add(normalize_name(target.ib.hostname))
        except SetupError as exc:
            failures += 1
            log(f"  ERROR: {exc}")

    oob_key_pending = False
    if args.auto:
        for eth_key, ethernet in sorted(ethernet_switches.items()):
            if ethernet.dev_type not in {"eth", "ethernet"}:
                log(
                    f"  OOB key SKIP: {ethernet.hostname} is {ethernet.dev_type}; "
                    "transit write is not authorized."
                )
                continue
            if eth_key in table_failures:
                oob_key_pending = True
                log(f"  OOB key RETRY: {ethernet.hostname} snapshot was unavailable.")
                continue
            for entry in auto_management_keys:
                try:
                    install_oob_management_key(
                        ethernet, args.eth_user, passwords[eth_key], entry,
                        args.connect_timeout,
                    )
                except SetupError as exc:
                    oob_key_pending = True
                    log(f"  OOB key RETRY: {ethernet.hostname}: {exc}")
                else:
                    log(f"  OOB key installed: {ethernet.hostname} {entry['fingerprint']}")

    summary = (
        f"Summary: targets={len(targets)} configured={configured} "
        f"skipped={skipped} failed={failures} "
        f"day0-skipped={day0_skipped} services-skipped={services_skipped}"
    )
    if args.auto:
        ib_names = {
            normalize_name(target.ib.hostname): target.ib.hostname
            for target in targets
        }
        terminal_names = [
            ib_names.get(name, name) for name in sorted(terminal_targets)
        ]
        summary += (
            f" terminal={len(terminal_names)} "
            f"terminal-devices={','.join(terminal_names) or '-'}"
        )
    log("\n" + summary)
    if args.auto:
        if terminal_targets:
            _save_auto_terminal(terminal_path, terminal_identity, terminal_targets)
        credentials_path = (
            Path(os.path.abspath(args.credentials_file)) if args.credentials_file is not None
            else _auto_state_dir(tool) / "auto.env"
        )
        if len(completed_targets) == ib_candidate_count and failures == 0 and not oob_key_pending:
            if args.credentials_file is not None:
                _remove_auto_watch(tool, credentials_path)
                log("AUTO WATCH: all CSV IB switches configured; own cron and auto.env removed.")
            else:
                log("AUTO WATCH: all CSV IB switches configured; no cron installed.")
        else:
            created = False
            if args.credentials_file is None:
                _write_auto_credentials(
                    credentials_path, initial_ib_password, passwords, targets,
                )
                created = True
            try:
                _install_auto_watch(
                    tool, credentials_path, ib_csv_path, p2p_path, cache_path,
                    report_path, snapshot_directory, force=args.force,
                )
            except SetupError:
                if created:
                    credentials_path.unlink()
                raise
            log("AUTO WATCH: unresolved CSV IB switches; 10-minute own cron installed.")
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SetupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        if REPORT_HANDLE is not None:
            print(f"ERROR: {exc}", file=REPORT_HANDLE, flush=True)
        raise SystemExit(2)
