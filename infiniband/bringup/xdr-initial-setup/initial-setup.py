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
import csv
import getpass
import hashlib
import ipaddress
import json
import os
import pty
import re
import select
import shlex
import signal
import socket
import sys
import time
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional


NA_VALUES = {"", "na", "n/a", "none", "null", "tbd", "-"}
IB_PORT_ALIASES = {"eth0", "mgmt", "management", "bmc"}
DEFAULT_HOSTNAMES = {"", "nvos"}
TARGET_CACHE_VERSION = 3
MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
DOT_LINK_RE = re.compile(
    r'^\s*"([^"]+)"\s*:\s*"([^"]+)"\s*--\s*'
    r'"([^"]+)"\s*:\s*"([^"]+)"'
)
REPORT_HANDLE = None


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
            if not hostname or dev_type not in {"ib", "eth", "eth_spx", "spx", "ethernet"}:
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
                    "type=eth device with a login IP in the CSV"
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
        raise SetupError("no IB management links to type=eth devices were found in P2P")
    return sorted(targets, key=lambda target: normalize_name(target.ib.hostname))


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


def load_target_cache(cache_path: Path, ib_csv: Path,
                      p2p: Path) -> Optional[tuple[int, list[Target]]]:
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
                      ib_candidate_count: int, targets: list[Target]) -> None:
    payload = {
        "version": TARGET_CACHE_VERSION,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "ib_csv": str(ib_csv),
        "p2p": str(p2p),
        "ib_candidate_count": ib_candidate_count,
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


def outer_ssh_command(ethernet: Device, user: str, remote_command: str,
                      timeout: int, *, tty: bool = False,
                      local: bool = False) -> list[str]:
    if local:
        return ["sh", "-c", remote_command]
    return ["ssh", *( ["-tt"] if tty else [] ), *ssh_options(timeout),
            f"{user}@{ethernet.login_ip}", remote_command]


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
                    remote_command: str, timeout: int, *, local: bool = False) -> str:
    result = interactive_run(
        outer_ssh_command(ethernet, user, remote_command, timeout, local=local),
        (lambda _output: None) if local else ethernet_responder(password), timeout,
    )
    if result.exit_code != 0:
        raise SetupError(
            f"Ethernet SSH failed for {ethernet.hostname} ({ethernet.login_ip}), "
            f"exit={result.exit_code}: {result.output.strip()[-600:]}"
        )
    return result.output


def collect_ethernet_interfaces(ethernet: Device, user: str, password: str,
                                timeout: int, *,
                                local: bool = False) -> tuple[str, str]:
    marker_host = "__XDR_HOSTNAME__"
    marker_interfaces = "__XDR_NV_INTERFACES__"
    command = (
        f"printf '{marker_host}\\n'; hostname; "
        f"printf '{marker_interfaces}\\n'; nv show interface"
    )
    output = run_on_ethernet(
        ethernet, user, password, command, timeout, local=local
    )
    if marker_host not in output or marker_interfaces not in output:
        raise SetupError(
            f"incomplete hostname/interface output from {ethernet.hostname}"
        )
    body = output.split(marker_host, 1)[1]
    hostname_output, body = body.split(marker_interfaces, 1)
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
    return actual_hostname, body.strip()


def collect_ethernet_network_tables(ethernet: Device, user: str,
                                    password: str, timeout: int, *,
                                    local: bool = False) -> tuple[str, str, str]:
    marker_links = "__XDR_IP_LINKS__"
    marker_fdb = "__XDR_FDB__"
    marker_neigh = "__XDR_NEIGH__"
    command = (
        f"printf '{marker_links}\\n'; ip -d link show; "
        f"printf '{marker_fdb}\\n'; bridge fdb show; "
        f"printf '{marker_neigh}\\n'; ip neighbor"
    )
    output = run_on_ethernet(
        ethernet, user, password, command, timeout, local=local
    )
    if any(marker not in output for marker in (marker_links, marker_fdb, marker_neigh)):
        raise SetupError(
            f"incomplete link/FDB/neighbor output from {ethernet.hostname}"
        )
    body = output.split(marker_links, 1)[1]
    links, body = body.split(marker_fdb, 1)
    fdb, neighbors = body.split(marker_neigh, 1)
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
        ethernet, user, password,
        f"ifquery {shlex.quote(interface)} 2>/dev/null || true", timeout,
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


def nested_ssh_command(target: Target, neighbor: Neighbor, eth_user: str,
                       ib_user: str, timeout: int, ib_command: str, *,
                       local: bool = False) -> list[str]:
    destination = f"{ib_user}@{neighbor.ipv6}"
    nested = [
        "ip", "vrf", "exec", neighbor.vrf, "ssh", "-6",
        "-o", f"ConnectTimeout={timeout}",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "LogLevel=ERROR",
        destination, "-B", neighbor.interface, ib_command,
    ]
    return outer_ssh_command(
        target.ethernet, eth_user, shlex.join(nested), timeout,
        tty=True, local=local,
    )


def run_on_ib(target: Target, neighbor: Neighbor, eth_user: str,
              ethernet_password: str, ib_user: str, ib_default_password: str,
              timeout: int, ib_command: str, *, local: bool = False,
              allow_password_change: bool = False) -> SessionResult:
    responder = NestedResponder(
        ethernet_password, ib_default_password, allow_password_change
    )
    result = interactive_run(
        nested_ssh_command(
            target, neighbor, eth_user, ib_user, timeout, ib_command,
            local=local,
        ),
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


def desired_commands(device: Device) -> list[str]:
    commands = [
        f"nv set interface eth0 ipv4 address {shlex.quote(device.eth0_prefix)}",
    ]
    if device.eth1_prefix:
        commands.append(
            f"nv set interface eth1 ipv4 address {shlex.quote(device.eth1_prefix)}"
        )
    if device.eth1_prefix and device.eth1_gateway != device.eth0_gateway:
        commands.extend([
            f"nv set interface eth0 ipv4 gateway {shlex.quote(device.eth0_gateway)}",
            f"nv set interface eth1 ipv4 gateway {shlex.quote(device.eth1_gateway)}",
        ])
    else:
        commands.append(
            f"nv set interface eth0-1 ipv4 gateway {shlex.quote(device.eth0_gateway)}"
        )
    commands.extend([
        f"nv set system hostname {shlex.quote(device.hostname)}",
        "nv config apply",
        "nv config save",
    ])
    return commands


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
    nested = [
        "ip", "vrf", "exec", vrf, "ssh",
        "-o", f"ConnectTimeout={timeout}",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "LogLevel=ERROR",
        f"{ib_user}@{target.ib.login_ip}", "true",
    ]
    command = outer_ssh_command(
        target.ethernet, eth_user, shlex.join(nested), timeout,
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
                        help="only parse CSV/P2P and show targets")
    parser.add_argument("--apply", action="store_true",
                        help="configure devices that pass the all-unconfigured check")
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
        save_target_cache(
            cache_path, ib_csv_path, p2p_path, len(ib_devices), targets
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
    cached = load_target_cache(cache_path, ib_csv_path, p2p_path)
    if cached is not None:
        ib_candidate_count, targets = cached
        log(f"Target cache: reused {cache_path}")
    else:
        ib_devices, eth_devices = load_devices(ib_csv_path)
        links = parse_p2p(p2p_path)
        validate_p2p_links(links)
        targets = build_targets(links, ib_devices, eth_devices)
        ib_candidate_count = len(ib_devices)
        save_target_cache(
            cache_path, ib_csv_path, p2p_path, ib_candidate_count, targets
        )
        log(f"Target cache: generated {cache_path}")

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
        return 0

    initial_ib_password = resolve_initial_ib_password(
        args.ib_initial_password_env,
        factory_default_admin=args.factory_default_admin,
    )

    local_keys = local_ethernet_keys(
        targets, args.execution_mode, args.local_ethernet_hostname
    )
    if local_keys:
        log("Local Ethernet execution: " + ", ".join(sorted(local_keys)))
    else:
        log("Execution location: management server (all Ethernet access uses SSH)")
    passwords = prompt_ethernet_passwords(
        targets, args.ethernet_password, local_keys
    )
    apply_authorized = bool(args.apply and args.yes)
    if apply_authorized:
        log("Device changes: pre-authorized by --apply --yes.")

    interface_tables: dict[str, str] = {}
    network_tables: dict[str, tuple[str, str, str]] = {}
    table_failures: dict[str, str] = {}
    failures = configured = skipped = 0
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
                "nv config show -o commands", local=ethernet_is_local,
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
                    "nv config show -o commands", local=ethernet_is_local,
                    allow_password_change=True,
                )
            if result.password_changed:
                log("  Initial NVOS password changed to the Ethernet switch password.")
                log("  Reconnecting with the new NVOS password ...")
                result = run_on_ib(
                    target, neighbor, args.eth_user, eth_password,
                    args.ib_user, eth_password, args.connect_timeout,
                    "nv config show -o commands", local=ethernet_is_local,
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
            if not state_is_unconfigured(state):
                skipped += 1
                log("  SKIP: at least one protected field is already configured; nothing changed.")
                continue

            commands = desired_commands(target.ib)
            for command in commands:
                log(f"  {'APPLY' if args.apply else 'WOULD APPLY'}: {command}")
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
                run_on_ib(
                    target, neighbor, args.eth_user, eth_password,
                    args.ib_user, eth_password, args.connect_timeout,
                    " && ".join(commands), local=ethernet_is_local,
                )
                verify_result = run_on_ib(
                    target, neighbor, args.eth_user, eth_password,
                    args.ib_user, eth_password, args.connect_timeout,
                    "nv config show -o commands", local=ethernet_is_local,
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
        except SetupError as exc:
            failures += 1
            log(f"  ERROR: {exc}")

    log(
        f"\nSummary: targets={len(targets)} configured={configured} "
        f"skipped={skipped} failed={failures}"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SetupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        if REPORT_HANDLE is not None:
            print(f"ERROR: {exc}", file=REPORT_HANDLE, flush=True)
        raise SystemExit(2)
