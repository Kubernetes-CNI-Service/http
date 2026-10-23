#!/usr/bin/env python3
"""Generate a Cable Validation-compatible JSON report from P2P and ibdiagnet data.

The implementation intentionally uses only the Python standard library so it can
run beside CableTracker without adding another deployment dependency.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import posixpath
import re
import sys
import tarfile
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


XML_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
XML_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
XML_PACKAGE_REL = "http://schemas.openxmlformats.org/package/2006/relationships"

SWITCH_HEADER_RE = re.compile(
    r"^Switch:\s+\S+\s+MF0;([^:]+):.*?/U(\d+):\s*$", re.IGNORECASE
)
LINK_LINE_RE = re.compile(
    r"^\s*\d+\s+(\S+)\[[^\]]*\]\s+==\((.*?)\)==>", re.IGNORECASE
)
REMOTE_PORT_RE = re.compile(r"\)==>\s*(?:\d+\s+)?([^\s\[]*)\s*\[[^\]]*\]")
QUOTED_RE = re.compile(r'"([^"]*)"')
PM_HEADER_RE = re.compile(
    r"^APort=\d+\s+Host=(.*?)\s+Label=(\S+)\s+Lid=", re.IGNORECASE
)
CABLE_HEADER_RE = re.compile(r"^Port=\d+\s+.*?Port Name=(.+?)\s*$", re.IGNORECASE)
RUN_TIMESTAMP_RE = re.compile(
    r"Running timestamp\s*:\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?([+-]\d{4})\s*$"
)
CELL_REFERENCE_RE = re.compile(r"([A-Z]+)(\d+)$")

REQUIRED_SHEETS = ("Nodes", "DC Floor Layout", "Links", "Server Profile")
RELEVANT_TAR_MEMBERS = {
    "ibdiagnet2.iblinkinfo",
    "ibdiagnet2.net_dump_ext",
    "ibdiagnet2.cables",
    "ibdiagnet2.pm_agg",
}


def clean_text(value: Any) -> str:
    """Normalize spreadsheet and report text without changing semantic content."""
    if value is None:
        return ""
    return str(value).replace("\u00a0", " ").strip()


def compare_key(value: Any) -> str:
    return clean_text(value).casefold()


def json_text(value: Any) -> Optional[str]:
    text = clean_text(value)
    return text if text else None


def output_node_name(value: Any) -> Optional[str]:
    text = clean_text(value)
    return text.lower() if text else None


def output_port_name(value: Any) -> Optional[str]:
    text = clean_text(value)
    return text if text else None


def parse_optional_int(value: Any) -> Any:
    text = clean_text(value)
    if not text:
        return None
    try:
        return int(text, 10)
    except ValueError:
        return text


def rack_display_name(value: Any) -> Optional[str]:
    rack = clean_text(value)
    if not rack:
        return None
    if "-" in rack:
        suffix = rack.rsplit("-", 1)[1]
        return suffix or rack
    return rack


def parse_number(value: Any) -> Optional[float]:
    text = clean_text(value)
    if not text or text.upper() in {"NA", "N/A", "NONE", "NULL"}:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def parse_counter(value: Any) -> Optional[int]:
    text = clean_text(value)
    if not text or text.upper() in {"NA", "N/A", "NONE", "NULL"}:
        return None
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(float(text))
        except ValueError:
            return None


def column_index(reference: str) -> int:
    match = CELL_REFERENCE_RE.fullmatch(reference.upper())
    if not match:
        raise ValueError("Invalid XLSX cell reference: %s" % reference)
    value = 0
    for character in match.group(1):
        value = value * 26 + ord(character) - ord("A") + 1
    return value - 1


def shared_string_text(element: ET.Element) -> str:
    return "".join(node.text or "" for node in element.findall(".//{%s}t" % XML_MAIN))


def parse_xlsx_cell(cell: ET.Element, shared_strings: Sequence[str]) -> Any:
    cell_type = cell.get("t")
    if cell_type == "inlineStr":
        inline = cell.find("{%s}is" % XML_MAIN)
        return shared_string_text(inline) if inline is not None else ""
    value_node = cell.find("{%s}v" % XML_MAIN)
    if value_node is None or value_node.text is None:
        return None
    value = value_node.text
    if cell_type == "s":
        try:
            return shared_strings[int(value)]
        except (IndexError, ValueError) as error:
            raise ValueError("XLSX shared string index is invalid: %s" % value) from error
    if cell_type in {"str", "e"}:
        return value
    if cell_type == "b":
        return value == "1"
    try:
        number = float(value)
    except ValueError:
        return value
    return int(number) if number.is_integer() else number


def load_xlsx_sheets(path: Path) -> Dict[str, List[List[Any]]]:
    """Read worksheet values from an XLSX file using the OOXML standard."""
    if not path.is_file():
        raise FileNotFoundError("P2P workbook not found: %s" % path)
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as error:
        raise ValueError("P2P input is not a valid XLSX file: %s" % path) from error
    with archive:
        names = set(archive.namelist())
        if "xl/workbook.xml" not in names or "xl/_rels/workbook.xml.rels" not in names:
            raise ValueError("P2P workbook is missing required OOXML workbook files")

        shared_strings: List[str] = []
        if "xl/sharedStrings.xml" in names:
            shared_root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
            shared_strings = [
                shared_string_text(item)
                for item in shared_root.findall("{%s}si" % XML_MAIN)
            ]

        relationships_root = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
        relationships = {
            relation.get("Id"): relation.get("Target")
            for relation in relationships_root.findall("{%s}Relationship" % XML_PACKAGE_REL)
        }
        workbook_root = ET.fromstring(archive.read("xl/workbook.xml"))
        sheets: Dict[str, List[List[Any]]] = {}
        for sheet in workbook_root.findall(".//{%s}sheet" % XML_MAIN):
            sheet_name = clean_text(sheet.get("name"))
            relation_id = sheet.get("{%s}id" % XML_REL)
            target = relationships.get(relation_id)
            if not sheet_name or not target:
                continue
            if target.startswith("/"):
                member_name = target.lstrip("/")
            else:
                member_name = posixpath.normpath(posixpath.join("xl", target))
            if member_name not in names:
                raise ValueError(
                    "P2P workbook worksheet %r points to missing member %r"
                    % (sheet_name, member_name)
                )
            sheet_root = ET.fromstring(archive.read(member_name))
            rows: List[List[Any]] = []
            for row in sheet_root.findall(".//{%s}sheetData/{%s}row" % (XML_MAIN, XML_MAIN)):
                values: List[Any] = []
                for cell in row.findall("{%s}c" % XML_MAIN):
                    reference = cell.get("r")
                    index = column_index(reference) if reference else len(values)
                    if len(values) <= index:
                        values.extend([None] * (index + 1 - len(values)))
                    values[index] = parse_xlsx_cell(cell, shared_strings)
                rows.append(values)
            sheets[sheet_name] = rows
        return sheets


def worksheet_records(
    sheets: Mapping[str, List[List[Any]]], sheet_name: str
) -> List[Dict[str, Any]]:
    rows = sheets.get(sheet_name)
    if not rows:
        raise ValueError("P2P workbook sheet %r is missing or empty" % sheet_name)
    headers = [clean_text(value) for value in rows[0]]
    if not any(headers):
        raise ValueError("P2P workbook sheet %r has an empty header row" % sheet_name)
    duplicate_headers = [header for header, count in Counter(headers).items() if header and count > 1]
    if duplicate_headers:
        raise ValueError(
            "P2P workbook sheet %r has duplicate headers: %s"
            % (sheet_name, ", ".join(sorted(duplicate_headers)))
        )
    records: List[Dict[str, Any]] = []
    for row_number, row in enumerate(rows[1:], start=2):
        record = {
            header: row[index] if index < len(row) else None
            for index, header in enumerate(headers)
            if header
        }
        if any(clean_text(value) for value in record.values()):
            record["__row_number__"] = row_number
            records.append(record)
    return records


def require_columns(records: Sequence[Mapping[str, Any]], sheet: str, columns: Sequence[str]) -> None:
    if not records:
        raise ValueError("P2P workbook sheet %r contains no data rows" % sheet)
    available = set(records[0])
    missing = [column for column in columns if column not in available]
    if missing:
        raise ValueError(
            "P2P workbook sheet %r is missing columns: %s"
            % (sheet, ", ".join(missing))
        )


@dataclass
class NodeInfo:
    fabric_id: str
    rack: str
    unit: Any
    name: str
    node_type: str
    model: str
    server_profile: str
    managed: bool


@dataclass
class RackInfo:
    data_hall: str
    scalable_unit: str


@dataclass
class ProfilePort:
    physical_port: str
    rdma_name: str
    custom_nic_name: str
    nic_os_name: str
    pci_address: str

    def aliases(self) -> List[str]:
        return [
            self.physical_port,
            self.rdma_name,
            self.custom_nic_name,
            self.nic_os_name,
        ]


@dataclass
class PlannedLink:
    protocol: str
    a_node: str
    a_port: str
    a_module_pn: str
    a_connector: str
    a_mpo_connector: str
    z_node: str
    z_port: str
    z_mpo_connector: str
    source_ref: str
    source_line_number: int


@dataclass
class P2PData:
    nodes: Dict[str, NodeInfo]
    racks: Dict[str, RackInfo]
    profiles: Dict[str, List[ProfilePort]]
    links: List[PlannedLink]


@dataclass
class LinkObservation:
    plane: int
    active: bool
    remote_node: str
    remote_port: str


@dataclass
class PortRuntime:
    plane: int
    active: bool
    speed_gbps: Optional[float]
    raw_ber: Optional[float]
    effective_ber: Optional[float]
    symbol_ber: Optional[float]


@dataclass
class CableInfo:
    cable_pn: Optional[str] = None
    cable_sn: Optional[str] = None
    module_fw_version: Optional[str] = None
    module_temperature: Optional[float] = None
    temperature_low_th: Optional[float] = None
    temperature_high_th: Optional[float] = None
    rx_power_lane: List[float] = field(default_factory=list)
    tx_power_lane: List[float] = field(default_factory=list)
    rx_power_low_th: Optional[float] = None
    rx_power_high_th: Optional[float] = None
    tx_power_low_th: Optional[float] = None
    tx_power_high_th: Optional[float] = None
    member_name: str = ""
    member_timestamp: Optional[float] = None

    def score(self) -> int:
        values = [
            self.cable_pn,
            self.cable_sn,
            self.module_fw_version,
            self.module_temperature,
            self.rx_power_lane,
            self.tx_power_lane,
        ]
        return sum(value not in (None, [], "") for value in values)


@dataclass
class DiagData:
    topology: Dict[str, List[LinkObservation]] = field(
        default_factory=lambda: defaultdict(list)
    )
    runtime: Dict[str, List[PortRuntime]] = field(
        default_factory=lambda: defaultdict(list)
    )
    cables: Dict[str, CableInfo] = field(default_factory=dict)
    counters: Dict[str, Dict[str, int]] = field(default_factory=dict)
    run_timestamp: Optional[float] = None
    found_members: set = field(default_factory=set)
    warnings: List[str] = field(default_factory=list)


@dataclass
class Thresholds:
    raw_ber: float = 1e-6
    effective_ber: float = 1e-15
    symbol_ber: float = 1e-15


MEDIA_UNPLUGGED_REMEDIATION = "Insert, Reseat or Replace Cable/Transceiver"
MISWIRING_REMEDIATION = "Fix miswiring"
BER_REMEDIATION = "Pre-staging: Link Bit Error Rate is high. Reseat the connector."


def load_p2p(path: Path) -> P2PData:
    sheets = load_xlsx_sheets(path)
    missing_sheets = [sheet for sheet in REQUIRED_SHEETS if sheet not in sheets]
    if missing_sheets:
        raise ValueError("P2P workbook is missing sheets: %s" % ", ".join(missing_sheets))

    node_records = worksheet_records(sheets, "Nodes")
    rack_records = worksheet_records(sheets, "DC Floor Layout")
    link_records = worksheet_records(sheets, "Links")
    profile_records = worksheet_records(sheets, "Server Profile")

    require_columns(
        node_records,
        "Nodes",
        ("FabricId", "Rack", "Unit", "NodeName", "NodeType", "NodeModel", "Managed"),
    )
    require_columns(
        rack_records,
        "DC Floor Layout",
        ("DataHall", "ScalableUnit", "Rack"),
    )
    require_columns(
        link_records,
        "Links",
        ("Protocol", "A-Node", "A-Port", "Z-Node", "Z-Port"),
    )
    require_columns(
        profile_records,
        "Server Profile",
        ("ServerProfile", "PhysicalPort", "RDMAName", "CustomNICName", "NICOSName", "PCIAddress"),
    )

    nodes: Dict[str, NodeInfo] = {}
    for record in node_records:
        name = clean_text(record.get("NodeName"))
        if not name:
            continue
        node_key = compare_key(name)
        if node_key in nodes:
            raise ValueError("P2P Nodes contains duplicate NodeName: %s" % name)
        nodes[node_key] = NodeInfo(
            fabric_id=clean_text(record.get("FabricId")),
            rack=clean_text(record.get("Rack")),
            unit=parse_optional_int(record.get("Unit")),
            name=name,
            node_type=clean_text(record.get("NodeType")),
            model=clean_text(record.get("NodeModel")),
            server_profile=clean_text(record.get("ServerProfile")),
            managed=compare_key(record.get("Managed")) in {"yes", "true", "1", "managed"},
        )

    racks: Dict[str, RackInfo] = {}
    for record in rack_records:
        rack = clean_text(record.get("Rack"))
        if not rack:
            continue
        racks[compare_key(rack)] = RackInfo(
            data_hall=clean_text(record.get("DataHall")),
            scalable_unit=clean_text(record.get("ScalableUnit")),
        )

    profiles: Dict[str, List[ProfilePort]] = defaultdict(list)
    for record in profile_records:
        profile_name = clean_text(record.get("ServerProfile"))
        if not profile_name:
            continue
        profiles[compare_key(profile_name)].append(
            ProfilePort(
                physical_port=clean_text(record.get("PhysicalPort")),
                rdma_name=clean_text(record.get("RDMAName")),
                custom_nic_name=clean_text(record.get("CustomNICName")),
                nic_os_name=clean_text(record.get("NICOSName")),
                pci_address=clean_text(record.get("PCIAddress")),
            )
        )

    links: List[PlannedLink] = []
    seen_links = set()
    for record in link_records:
        protocol = clean_text(record.get("Protocol"))
        a_node = clean_text(record.get("A-Node"))
        a_port = clean_text(record.get("A-Port"))
        z_node = clean_text(record.get("Z-Node"))
        z_port = clean_text(record.get("Z-Port"))
        if not all((protocol, a_node, a_port, z_node, z_port)):
            raise ValueError(
                "P2P Links row %s has an empty required endpoint field"
                % record["__row_number__"]
            )
        if compare_key(a_node) not in nodes:
            raise ValueError(
                "P2P Links row %s references unknown A-Node %r"
                % (record["__row_number__"], a_node)
            )
        if compare_key(z_node) not in nodes:
            raise ValueError(
                "P2P Links row %s references unknown Z-Node %r"
                % (record["__row_number__"], z_node)
            )
        duplicate_key = tuple(map(compare_key, (protocol, a_node, a_port, z_node, z_port)))
        if duplicate_key in seen_links:
            raise ValueError(
                "P2P Links row %s duplicates an earlier link" % record["__row_number__"]
            )
        seen_links.add(duplicate_key)
        links.append(
            PlannedLink(
                protocol=protocol,
                a_node=a_node,
                a_port=a_port,
                a_module_pn=clean_text(record.get("A-Module-PN")),
                a_connector=clean_text(record.get("A-Connector")),
                a_mpo_connector=clean_text(record.get("A-MPO-Connector")),
                z_node=z_node,
                z_port=z_port,
                z_mpo_connector=clean_text(record.get("Z-MPO-Connector")),
                source_ref=clean_text(record.get("Source-Ref")),
                source_line_number=int(record["__row_number__"]),
            )
        )

    return P2PData(nodes=nodes, racks=racks, profiles=dict(profiles), links=links)


def endpoint_key(node: Any, port: Any) -> str:
    return "%s|%s" % (compare_key(node), compare_key(port))


def update_run_timestamp(diag: DiagData, line: str) -> None:
    match = RUN_TIMESTAMP_RE.search(line)
    if not match:
        return
    try:
        parsed = datetime.strptime(
            "%s %s" % (match.group(1), match.group(2)), "%Y-%m-%d %H:%M:%S %z"
        )
    except ValueError:
        return
    timestamp = parsed.timestamp()
    if diag.run_timestamp is None:
        diag.run_timestamp = timestamp


def parse_remote_endpoint(description: str, remote_port: str) -> Tuple[str, str]:
    description = clean_text(description)
    if not description:
        return "", ""
    switch_match = re.match(r"^MF0;([^:]+):", description, re.IGNORECASE)
    if switch_match:
        return clean_text(switch_match.group(1)), clean_text(remote_port)
    tokens = description.split()
    if len(tokens) < 2:
        return description, clean_text(remote_port)
    return " ".join(tokens[:-1]), tokens[-1]


def parse_iblinkinfo(stream: Iterable[str], diag: DiagData) -> None:
    current_node = ""
    current_plane = 0
    for line in stream:
        update_run_timestamp(diag, line)
        header = SWITCH_HEADER_RE.match(line.rstrip("\r\n"))
        if header:
            current_node = clean_text(header.group(1))
            current_plane = int(header.group(2))
            continue
        if not current_node:
            continue
        local = LINK_LINE_RE.match(line)
        if not local:
            continue
        local_port = clean_text(local.group(1))
        state = clean_text(local.group(2))
        remote_port_match = REMOTE_PORT_RE.search(line)
        description_match = QUOTED_RE.search(line)
        remote_node, remote_port = parse_remote_endpoint(
            description_match.group(1) if description_match else "",
            remote_port_match.group(1) if remote_port_match else "",
        )
        diag.topology[endpoint_key(current_node, local_port)].append(
            LinkObservation(
                plane=current_plane,
                active="active" in state.casefold() and "linkup" in state.casefold(),
                remote_node=remote_node,
                remote_port=remote_port,
            )
        )


def node_and_plane_from_description(description: str) -> Tuple[str, Optional[int]]:
    match = re.match(r"^MF0;([^:]+):.*?/U(\d+)$", clean_text(description), re.IGNORECASE)
    if not match:
        return "", None
    return clean_text(match.group(1)), int(match.group(2))


def parse_net_dump_ext(stream: Iterable[str], diag: DiagData) -> None:
    for line in stream:
        update_run_timestamp(diag, line)
        if not re.match(r"^\s*(SW|CA)\s*:", line, re.IGNORECASE):
            continue
        description_match = re.search(r':\s*"([^"]*)"\s*$', line)
        if not description_match:
            continue
        description = description_match.group(1)
        fields = [part.strip() for part in line[: description_match.start()].split(":")]
        if len(fields) < 17:
            continue
        device_type = fields[0].upper()
        status = fields[5].casefold()
        physical_status = fields[6].replace(" ", "").casefold()
        active = status == "act" and physical_status == "linkup"
        if device_type == "SW":
            node, plane = node_and_plane_from_description(description)
            port = fields[1]
        else:
            tokens = clean_text(description).split()
            if len(tokens) < 2:
                continue
            node = " ".join(tokens[:-1])
            port = tokens[-1]
            try:
                plane = int(fields[2])
            except ValueError:
                plane = None
        if not node or not port or plane is None:
            continue
        diag.runtime[endpoint_key(node, port)].append(
            PortRuntime(
                plane=plane,
                active=active,
                speed_gbps=parse_number(fields[8]),
                raw_ber=parse_number(fields[12]),
                effective_ber=parse_number(fields[13]),
                symbol_ber=parse_number(fields[14]),
            )
        )


def cable_endpoint_from_port_name(port_name: str) -> Tuple[str, str]:
    switch_match = re.match(r"^(.+?)/U\d+/(.+)$", clean_text(port_name), re.IGNORECASE)
    if switch_match:
        return clean_text(switch_match.group(1)), clean_text(switch_match.group(2))
    parts = clean_text(port_name).split("/")
    if len(parts) >= 2:
        return parts[0], parts[1]
    return "", ""


def threshold_to_dbm(value: Any) -> Optional[float]:
    numeric = parse_number(value)
    if numeric is None or numeric <= 0:
        return None
    return round(10.0 * math.log10(numeric / 1000.0), 2)


def parse_cables(
    stream: Iterable[str], diag: DiagData, member_name: str, member_timestamp: Optional[float]
) -> None:
    current_name = ""
    current = CableInfo(member_name=member_name, member_timestamp=member_timestamp)

    def save_current() -> None:
        if not current_name:
            return
        node, port = cable_endpoint_from_port_name(current_name)
        if not node or not port:
            return
        key = endpoint_key(node, port)
        existing = diag.cables.get(key)
        if existing is None or current.score() > existing.score():
            current.rx_power_lane = current.rx_power_lane[:4]
            current.tx_power_lane = current.tx_power_lane[:4]
            diag.cables[key] = current

    for line in stream:
        update_run_timestamp(diag, line)
        header = CABLE_HEADER_RE.match(line.rstrip("\r\n"))
        if header:
            save_current()
            current_name = clean_text(header.group(1))
            current = CableInfo(member_name=member_name, member_timestamp=member_timestamp)
            continue
        if not current_name:
            continue
        stripped = line.strip()
        if stripped.startswith("PN:"):
            current.cable_pn = json_text(stripped.split(":", 1)[1])
        elif stripped.startswith("SN:"):
            current.cable_sn = json_text(stripped.split(":", 1)[1])
        elif stripped.startswith("FW Version:"):
            current.module_fw_version = json_text(stripped.split(":", 1)[1])
        elif stripped.startswith("Temperature:"):
            current.module_temperature = parse_number(stripped.split(":", 1)[1].rstrip("C"))
        elif stripped.startswith("AlarmTemperatureHighThresh:"):
            current.temperature_high_th = parse_number(
                stripped.split(":", 1)[1].rstrip("C")
            )
        elif stripped.startswith("AlarmTemperatureLowThresh:"):
            current.temperature_low_th = parse_number(
                stripped.split(":", 1)[1].rstrip("C")
            )
        elif stripped.startswith("RXPowerHighThresh:"):
            current.rx_power_high_th = threshold_to_dbm(stripped.split(":", 1)[1])
        elif stripped.startswith("RXPowerLowThresh:"):
            current.rx_power_low_th = threshold_to_dbm(stripped.split(":", 1)[1])
        elif stripped.startswith("TXPowerHighThresh:"):
            current.tx_power_high_th = threshold_to_dbm(stripped.split(":", 1)[1])
        elif stripped.startswith("TXPowerLowThresh:"):
            current.tx_power_low_th = threshold_to_dbm(stripped.split(":", 1)[1])
        else:
            rx_match = re.match(
                r"RX(\d+)\s+Power:\s*[-+0-9.eE]+\s+mW,\s*([-+0-9.eE]+)\s+dBm",
                stripped,
            )
            tx_match = re.match(
                r"TX(\d+)\s+Power:\s*[-+0-9.eE]+\s+mW,\s*([-+0-9.eE]+)\s+dBm",
                stripped,
            )
            if rx_match:
                current.rx_power_lane.append(float(rx_match.group(2)))
            elif tx_match:
                current.tx_power_lane.append(float(tx_match.group(2)))
    save_current()


def parse_pm_agg(stream: Iterable[str], diag: DiagData) -> None:
    current_key = ""
    current: Dict[str, int] = {}

    def save_current() -> None:
        if current_key:
            diag.counters[current_key] = dict(current)

    for line in stream:
        update_run_timestamp(diag, line)
        header = PM_HEADER_RE.match(line.rstrip("\r\n"))
        if header:
            save_current()
            current_key = endpoint_key(header.group(1), header.group(2))
            current = {}
            continue
        if not current_key or "=" not in line or line.lstrip().startswith("#"):
            continue
        name, raw_value = line.strip().split("=", 1)
        value = parse_counter(raw_value)
        if value is not None:
            current[name] = value
    save_current()


def decoded_lines(binary: BinaryIO) -> Iterable[str]:
    for line in binary:
        yield line.decode("utf-8", errors="replace")


def load_ibdiagnet(path: Path) -> DiagData:
    if not path.is_file():
        raise FileNotFoundError("ibdiagnet tar file not found: %s" % path)
    diag = DiagData()
    try:
        archive = tarfile.open(path, mode="r|*")
    except tarfile.TarError as error:
        raise ValueError("Input is not a readable tar/tgz archive: %s" % path) from error
    try:
        for member in archive:
            if not member.isfile():
                continue
            base_name = posixpath.basename(member.name)
            if base_name not in RELEVANT_TAR_MEMBERS:
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                diag.warnings.append("Unable to read tar member: %s" % member.name)
                continue
            diag.found_members.add(base_name)
            with extracted:
                stream = decoded_lines(extracted)
                if base_name == "ibdiagnet2.iblinkinfo":
                    parse_iblinkinfo(stream, diag)
                elif base_name == "ibdiagnet2.net_dump_ext":
                    parse_net_dump_ext(stream, diag)
                elif base_name == "ibdiagnet2.cables":
                    parse_cables(stream, diag, member.name, float(member.mtime))
                elif base_name == "ibdiagnet2.pm_agg":
                    parse_pm_agg(stream, diag)
    except (tarfile.TarError, OSError) as error:
        raise ValueError("Failed while reading ibdiagnet archive %s: %s" % (path, error)) from error
    finally:
        archive.close()

    missing = sorted(RELEVANT_TAR_MEMBERS - diag.found_members)
    if "ibdiagnet2.iblinkinfo" in missing or "ibdiagnet2.net_dump_ext" in missing:
        raise ValueError(
            "ibdiagnet archive is missing status-critical files: %s"
            % ", ".join(
                name
                for name in missing
                if name in {"ibdiagnet2.iblinkinfo", "ibdiagnet2.net_dump_ext"}
            )
        )
    for name in missing:
        diag.warnings.append("Optional telemetry file is missing: %s" % name)
    return diag


def resolve_profile_port(
    p2p: P2PData, node_name: str, planned_port: str
) -> Tuple[Optional[ProfilePort], str]:
    node = p2p.nodes.get(compare_key(node_name))
    if node is None or compare_key(node.node_type) != "host":
        return None, clean_text(planned_port)
    candidates = p2p.profiles.get(compare_key(node.server_profile), [])
    planned_key = compare_key(planned_port)
    for candidate in candidates:
        if planned_key in {compare_key(alias) for alias in candidate.aliases() if clean_text(alias)}:
            return candidate, candidate.rdma_name or clean_text(planned_port)
    return None, clean_text(planned_port)


def unique_by_plane(records: Iterable[Any]) -> Dict[int, Any]:
    return {int(record.plane): record for record in records}


def records_are_up(records: Sequence[PortRuntime], expected_planes: int) -> bool:
    by_plane = unique_by_plane(records)
    return len(by_plane) == expected_planes and all(record.active for record in by_plane.values())


def topology_is_up(records: Sequence[LinkObservation], expected_planes: int) -> bool:
    by_plane = unique_by_plane(records)
    return len(by_plane) == expected_planes and all(record.active for record in by_plane.values())


def ber_good(
    records: Sequence[PortRuntime], expected_planes: int, thresholds: Thresholds
) -> Optional[bool]:
    by_plane = unique_by_plane(records)
    if len(by_plane) != expected_planes:
        return None
    has_ber_sample = False
    for record in by_plane.values():
        values = (record.raw_ber, record.effective_ber, record.symbol_ber)
        if any(value is not None for value in values):
            has_ber_sample = True
        if record.raw_ber is not None and record.raw_ber > thresholds.raw_ber:
            return False
        if (
            record.effective_ber is not None
            and record.effective_ber > thresholds.effective_ber
        ):
            return False
        if record.symbol_ber is not None and record.symbol_ber > thresholds.symbol_ber:
            return False
    return True if has_ber_sample else None


def maximum_metric(records: Sequence[PortRuntime], field_name: str) -> Optional[float]:
    values = [getattr(record, field_name) for record in records]
    available = [value for value in values if value is not None]
    return max(available) if available else None


def scientific_ber_string(value: Optional[float]) -> Optional[str]:
    if value is None:
        return None
    return format(Decimal(str(value)).normalize(), "E")


def speed_name(records: Sequence[PortRuntime]) -> Optional[str]:
    values = sorted({record.speed_gbps for record in records if record.speed_gbps is not None})
    if not values:
        return None
    if len(values) != 1:
        return "/".join("%gG" % value for value in values)
    speed = values[0]
    known = {
        200.0: "XDR",
        100.0: "NDR",
        50.0: "HDR",
        25.0: "EDR",
        14.0: "FDR",
        10.0: "QDR",
        5.0: "DDR",
        2.5: "SDR",
    }
    return known.get(speed, "%gG" % speed)


def series_sum(counters: Mapping[str, int], prefix: str) -> Optional[int]:
    values = [
        value
        for name, value in counters.items()
        if re.fullmatch(re.escape(prefix) + r"\d+", name)
    ]
    return sum(values) if values else None


def counter_stats(counters: Mapping[str, int]) -> Dict[str, Any]:
    linkdown = series_sum(counters, "link_downed_counter_extended")
    if linkdown is None:
        linkdown = series_sum(counters, "link_down_counter")
    in_data = series_sum(counters, "port_rcv_data_extended")
    out_data = series_sum(counters, "port_xmit_data_extended")
    return {
        "linkdown_counter": str(linkdown) if linkdown is not None else None,
        "traffic_stats": {
            "in_bytes": in_data * 4 if in_data is not None else None,
            "in_drops": None,
            "in_errors": series_sum(counters, "port_rcv_errors_extended"),
            "out_bytes": out_data * 4 if out_data is not None else None,
            "out_drops": series_sum(counters, "port_xmit_discards_extended"),
            "out_errors": None,
            "out_wait": series_sum(counters, "port_xmit_wait_extended"),
        },
    }


def distinct_remote_values(
    observations: Sequence[LinkObservation], field_name: str
) -> List[str]:
    return sorted(
        {
            clean_text(getattr(observation, field_name))
            for observation in observations
            if clean_text(getattr(observation, field_name))
        },
        key=str.casefold,
    )


def joined_or_none(values: Sequence[str]) -> Optional[str]:
    return ", ".join(values) if values else None


def topology_matches(
    observations: Sequence[LinkObservation],
    remote_node: str,
    remote_port: str,
    expected_planes: int,
) -> Tuple[bool, bool]:
    by_plane = unique_by_plane(observations)
    if len(by_plane) != expected_planes:
        return False, False
    node_match = all(
        observation.active and compare_key(observation.remote_node) == compare_key(remote_node)
        for observation in by_plane.values()
    )
    port_match = all(
        observation.active and compare_key(observation.remote_port) == compare_key(remote_port)
        for observation in by_plane.values()
    )
    return node_match, port_match


def reverse_topology_matches(
    diag: DiagData,
    p2p: P2PData,
    link: PlannedLink,
    z_runtime_port: str,
    expected_planes: int,
) -> bool:
    z_node = p2p.nodes.get(compare_key(link.z_node))
    if z_node is None or compare_key(z_node.node_type) != "switch":
        return True
    observations = diag.topology.get(endpoint_key(link.z_node, z_runtime_port), [])
    node_match, port_match = topology_matches(
        observations, link.a_node, link.a_port, expected_planes
    )
    return node_match and port_match


def endpoint_metadata(
    p2p: P2PData, node_name: str, planned_port: str
) -> Tuple[Optional[NodeInfo], Optional[RackInfo], Optional[ProfilePort], str]:
    node = p2p.nodes.get(compare_key(node_name))
    rack = p2p.racks.get(compare_key(node.rack)) if node else None
    profile_port, runtime_port = resolve_profile_port(p2p, node_name, planned_port)
    return node, rack, profile_port, runtime_port


def build_advanced_stats(
    diag: DiagData,
    actual_node: Optional[str],
    actual_port: Optional[str],
    runtime_records: Sequence[PortRuntime],
    port_up: bool,
    ber_result: Optional[bool],
    run_timestamp: Optional[float],
) -> Dict[str, Any]:
    key = endpoint_key(actual_node, actual_port) if actual_node and actual_port else ""
    cable = diag.cables.get(key)
    counters = diag.counters.get(key, {})
    counter_values = counter_stats(counters)
    powers_available = bool(cable and (cable.rx_power_lane or cable.tx_power_lane))
    return {
        "custom_amber_fields": {"Advanced_Status_Opcode": None},
        "metadata": {
            "read_time": run_timestamp,
            "file_name": cable.member_name if cable else None,
            "file_timestamp": cable.member_timestamp if cable else None,
        },
        "time_stamp": run_timestamp,
        "time_since_last_clear": None,
        "module_fw_version": cable.module_fw_version if cable else None,
        "cable_sn": cable.cable_sn if cable else None,
        "cable_pn": cable.cable_pn if cable else None,
        "protocol": "InfiniBand",
        "link_speed_active": speed_name(runtime_records),
        "transceiver_swap": None,
        "module_oper_status": (
            "plugged_enable" if cable and port_up else "plugged_disable" if cable else None
        ),
        "phy_manager_state": "Active" if port_up else "Down" if runtime_records else None,
        "transceiver_reinsert_cnt": None,
        "transceiver_swap_cnt": None,
        "last_valid_sn": cable.cable_sn if cable else None,
        "power_stats": {
            "rx_power_lane": cable.rx_power_lane if cable and cable.rx_power_lane else None,
            "rx_power_high_th": cable.rx_power_high_th if cable else None,
            "rx_power_low_th": cable.rx_power_low_th if cable else None,
            "tx_power_lane": cable.tx_power_lane if cable and cable.tx_power_lane else None,
            "tx_power_high_th": cable.tx_power_high_th if cable else None,
            "tx_power_low_th": cable.tx_power_low_th if cable else None,
            "power_data_stale": False if powers_available else None,
        },
        "temp_stats": {
            "module_temperature": cable.module_temperature if cable else None,
            "temperature_low_th": cable.temperature_low_th if cable else None,
            "temperature_high_th": cable.temperature_high_th if cable else None,
        },
        "ber_stats": {
            "effective_ber": scientific_ber_string(
                maximum_metric(runtime_records, "effective_ber")
            ),
            "raw_ber": scientific_ber_string(maximum_metric(runtime_records, "raw_ber")),
            "symbol_ber": scientific_ber_string(
                maximum_metric(runtime_records, "symbol_ber")
            ),
            "e2ber": None,
            "ber_status": "Good" if ber_result is True else "Bad" if ber_result is False else None,
            "ber_performance": None,
        },
        "linkdown_counter": counter_values["linkdown_counter"],
        "traffic_stats": counter_values["traffic_stats"],
    }


def endpoint_report(
    node: Optional[NodeInfo],
    observations: Sequence[LinkObservation],
    runtime_records: Sequence[PortRuntime],
    node_match: bool,
    port_match: bool,
    port_up: bool,
    ber_result: Optional[bool],
    expected_planes: int,
) -> Tuple[Optional[str], str]:
    """Return report/remediation values using the real report.json vocabulary."""
    if node is None or not node.managed:
        return None, ""

    topology_available = bool(observations)
    runtime_available = bool(runtime_records)
    if not topology_available and not runtime_available:
        return None, ""

    if (topology_available and not topology_is_up(observations, expected_planes)) or (
        runtime_available and not port_up
    ):
        return "Media Unplugged", MEDIA_UNPLUGGED_REMEDIATION

    # A live local port reports the neighbor problem before BER health.
    if topology_available and not node_match:
        return "Wrong-neighbor", MISWIRING_REMEDIATION
    if topology_available and not port_match:
        return "Wrong-port", MISWIRING_REMEDIATION

    if ber_result is False:
        return "Anomalous-port (Signal, Temperature)", BER_REMEDIATION
    if topology_available and port_up and ber_result is True:
        return "Ok", ""
    return None, ""


def build_endpoint(
    p2p: P2PData,
    diag: DiagData,
    expected_node: str,
    planned_port: str,
    actual_node: Optional[str],
    actual_port: Optional[str],
    module_pn: str,
    connector: str,
    mpo_connector: str,
    observations: Sequence[LinkObservation],
    node_match: bool,
    port_match: bool,
    expected_planes: int,
    thresholds: Thresholds,
) -> Tuple[Dict[str, Any], bool, Optional[bool]]:
    node, rack, profile_port, runtime_port = endpoint_metadata(
        p2p, expected_node, planned_port
    )
    local_key = endpoint_key(expected_node, runtime_port)
    runtime_records = diag.runtime.get(local_key, [])
    port_up = records_are_up(runtime_records, expected_planes)
    ber_result = ber_good(runtime_records, expected_planes, thresholds)
    cable = diag.cables.get(local_key)
    advanced_stats = build_advanced_stats(
        diag,
        expected_node,
        runtime_port,
        runtime_records,
        port_up,
        ber_result,
        diag.run_timestamp,
    )
    report, remediation_action = endpoint_report(
        node,
        observations,
        runtime_records,
        node_match,
        port_match,
        port_up,
        ber_result,
        expected_planes,
    )
    endpoint = {
        "node": output_node_name(expected_node),
        "node_type": clean_text(node.node_type).title() if node else None,
        "port": json_text(planned_port),
        "display_port": json_text(planned_port),
        "custom_nic_name": json_text(profile_port.custom_nic_name) if profile_port else None,
        "nic_os_name": json_text(profile_port.nic_os_name) if profile_port else None,
        "rdma_name": json_text(profile_port.rdma_name) if profile_port else None,
        "physical_port": json_text(profile_port.physical_port) if profile_port else None,
        "pci_address": json_text(profile_port.pci_address) if profile_port else None,
        "shuffle_cable_connector": json_text(connector),
        "shuffle_cable_mpo_connector": json_text(mpo_connector),
        "module_pn": json_text(module_pn),
        "is_internal": False,
        "rack": rack_display_name(node.rack) if node else None,
        "unit": node.unit if node else None,
        "su_number": json_text(rack.scalable_unit) if rack else None,
        "data_hall": json_text(rack.data_hall) if rack else json_text(node.fabric_id) if node else None,
        "is_managed": node.managed if node else False,
        "actual_node": output_node_name(actual_node),
        "actual_port": output_port_name(actual_port),
        "display_actual_port": output_port_name(actual_port),
        "port_status": "up" if port_up else "down",
        "plugged": bool(cable and (cable.cable_sn or cable.cable_pn)),
        "advanced_stats": advanced_stats,
        "remediation_action": remediation_action,
        "report": report,
        "last_update": diag.run_timestamp,
        "simulated": False,
        "report_status": "Latest Report" if report is not None else "No Report",
    }
    return endpoint, port_up, ber_result


def circuit_identifier(link: PlannedLink) -> str:
    material = "|".join(
        compare_key(value)
        for value in (link.protocol, link.a_node, link.a_port, link.z_node, link.z_port)
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def circuit_status_from_reports(
    a_report: Optional[str], z_report: Optional[str]
) -> Tuple[Optional[str], Optional[bool]]:
    """Mirror the real report.json status/healthy tri-state relationship."""
    available_reports = [
        report for report in (a_report, z_report) if clean_text(report)
    ]
    if not available_reports:
        return None, None
    if all(report == "Ok" for report in available_reports):
        return "Pass", True
    return "Fail", False


def evaluate_link(
    p2p: P2PData,
    diag: DiagData,
    link: PlannedLink,
    thresholds: Thresholds,
    expected_planes: int = 4,
) -> Tuple[Dict[str, Any], List[str]]:
    a_observations = diag.topology.get(endpoint_key(link.a_node, link.a_port), [])
    remote_nodes = distinct_remote_values(a_observations, "remote_node")
    remote_ports = distinct_remote_values(a_observations, "remote_port")
    actual_z_node = joined_or_none(remote_nodes)
    actual_z_port = joined_or_none(remote_ports)
    actual_a_node = link.a_node if a_observations else None
    actual_a_port = link.a_port if a_observations else None

    _, _, _, expected_z_runtime_port = endpoint_metadata(p2p, link.z_node, link.z_port)
    node_match, port_match = topology_matches(
        a_observations, link.z_node, expected_z_runtime_port, expected_planes
    )
    z_observations = diag.topology.get(
        endpoint_key(link.z_node, expected_z_runtime_port), []
    )
    z_node_match, z_port_match = topology_matches(
        z_observations, link.a_node, link.a_port, expected_planes
    )
    forward_up = topology_is_up(a_observations, expected_planes)
    reverse_match = reverse_topology_matches(
        diag, p2p, link, expected_z_runtime_port, expected_planes
    )

    a_endpoint, a_up, a_ber_good = build_endpoint(
        p2p,
        diag,
        link.a_node,
        link.a_port,
        actual_a_node,
        actual_a_port,
        link.a_module_pn,
        link.a_connector,
        link.a_mpo_connector,
        a_observations,
        node_match,
        port_match,
        expected_planes,
        thresholds,
    )
    z_endpoint, z_up, z_ber_good = build_endpoint(
        p2p,
        diag,
        link.z_node,
        link.z_port,
        actual_z_node,
        actual_z_port,
        "",
        "",
        link.z_mpo_connector,
        z_observations,
        z_node_match,
        z_port_match,
        expected_planes,
        thresholds,
    )

    reasons: List[str] = []
    if len(unique_by_plane(a_observations)) != expected_planes:
        reasons.append("missing_topology_planes")
    if not forward_up:
        reasons.append("link_not_up_on_all_planes")
    if not a_up:
        reasons.append("a_port_not_up")
    if not z_up:
        reasons.append("z_port_not_up")
    if not node_match:
        reasons.append("node_mismatch")
    if not port_match:
        reasons.append("port_mismatch")
    if not reverse_match:
        reasons.append("reverse_topology_mismatch")
    if a_ber_good is not True:
        reasons.append("a_ber_not_good")
    if z_ber_good is not True:
        reasons.append("z_ber_not_good")

    status, healthy = circuit_status_from_reports(
        a_endpoint["report"], z_endpoint["report"]
    )
    if status != "Fail":
        reasons = []
    circuit = {
        "circuit_id": circuit_identifier(link),
        "a_endpoint": a_endpoint,
        "z_endpoint": z_endpoint,
        "healthy": healthy,
        "status": status,
        "protocol": compare_key(link.protocol),
        "shuffle_cable_id": json_text(link.source_ref),
        "source_line_number": link.source_line_number,
    }
    return circuit, reasons


def generate_report(
    p2p_path: Path,
    ibdiagnet_path: Path,
    thresholds: Optional[Thresholds] = None,
    expected_planes: int = 4,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    if expected_planes <= 0:
        raise ValueError("expected_planes must be greater than zero")
    thresholds = thresholds or Thresholds()
    p2p = load_p2p(Path(p2p_path))
    diag = load_ibdiagnet(Path(ibdiagnet_path))
    report: List[Dict[str, Any]] = []
    failure_reasons: Counter = Counter()
    for link in p2p.links:
        circuit, reasons = evaluate_link(
            p2p, diag, link, thresholds=thresholds, expected_planes=expected_planes
        )
        report.append(circuit)
        failure_reasons.update(reasons)
    status_counts = Counter(circuit["status"] for circuit in report)
    coverage = {
        "a_actual_endpoint": sum(
            bool(circuit["a_endpoint"].get("actual_node") and circuit["a_endpoint"].get("actual_port"))
            for circuit in report
        ),
        "z_actual_endpoint": sum(
            bool(circuit["z_endpoint"].get("actual_node") and circuit["z_endpoint"].get("actual_port"))
            for circuit in report
        ),
        "a_port_up": sum(circuit["a_endpoint"].get("port_status") == "up" for circuit in report),
        "z_port_up": sum(circuit["z_endpoint"].get("port_status") == "up" for circuit in report),
        "a_ber_good": sum(
            circuit["a_endpoint"]["advanced_stats"]["ber_stats"].get("ber_status") == "Good"
            for circuit in report
        ),
        "z_ber_good": sum(
            circuit["z_endpoint"]["advanced_stats"]["ber_stats"].get("ber_status") == "Good"
            for circuit in report
        ),
        "a_cable_identity": sum(
            bool(circuit["a_endpoint"]["advanced_stats"].get("cable_sn")) for circuit in report
        ),
        "z_cable_identity": sum(
            bool(circuit["z_endpoint"]["advanced_stats"].get("cable_sn")) for circuit in report
        ),
    }
    summary = {
        "records": len(report),
        "pass": status_counts.get("Pass", 0),
        "fail": status_counts.get("Fail", 0),
        "no_report": status_counts.get(None, 0),
        "run_timestamp": diag.run_timestamp,
        "expected_planes": expected_planes,
        "ber_thresholds": {
            "raw_ber": thresholds.raw_ber,
            "effective_ber": thresholds.effective_ber,
            "symbol_ber": thresholds.symbol_ber,
        },
        "failure_reasons": dict(sorted(failure_reasons.items())),
        "coverage": coverage,
        "warnings": diag.warnings,
        "tar_members_used": sorted(diag.found_members),
    }
    return report, summary


def write_json(path: Path, value: Any, force: bool = False) -> None:
    path = Path(path)
    if path.exists() and not force:
        raise FileExistsError("Output already exists; use --force to replace it: %s" % path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(".%s.%s.tmp" % (path.name, os.getpid()))
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, allow_nan=False)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a tmp.json-compatible circuit report from a P2P XLSX workbook "
            "and an ibdiagnet tar/tgz archive."
        )
    )
    parser.add_argument("--p2p", required=True, type=Path, help="P2P XLSX workbook")
    parser.add_argument(
        "--ibdiagnet-tar", required=True, type=Path, help="ibdiagnet tar/tgz archive"
    )
    parser.add_argument("--output", required=True, type=Path, help="Output report JSON")
    parser.add_argument(
        "--summary-output", type=Path, help="Optional JSON file for counts and failure reasons"
    )
    parser.add_argument(
        "--expected-planes",
        type=positive_int,
        default=4,
        help="Required physical planes per logical P2P link (default: 4)",
    )
    parser.add_argument(
        "--raw-ber-threshold",
        type=positive_float,
        default=Thresholds.raw_ber,
        help="Maximum acceptable raw BER (default: 1e-6)",
    )
    parser.add_argument(
        "--effective-ber-threshold",
        type=positive_float,
        default=Thresholds.effective_ber,
        help="Maximum acceptable effective BER (default: 1e-15)",
    )
    parser.add_argument(
        "--symbol-ber-threshold",
        type=positive_float,
        default=Thresholds.symbol_ber,
        help="Maximum acceptable symbol BER (default: 1e-15)",
    )
    parser.add_argument(
        "--force", action="store_true", help="Replace existing output files atomically"
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    thresholds = Thresholds(
        raw_ber=args.raw_ber_threshold,
        effective_ber=args.effective_ber_threshold,
        symbol_ber=args.symbol_ber_threshold,
    )
    try:
        report, summary = generate_report(
            p2p_path=args.p2p,
            ibdiagnet_path=args.ibdiagnet_tar,
            thresholds=thresholds,
            expected_planes=args.expected_planes,
        )
        write_json(args.output, report, force=args.force)
        if args.summary_output:
            write_json(args.summary_output, summary, force=args.force)
    except (FileExistsError, FileNotFoundError, OSError, ValueError) as error:
        print("error: %s" % error, file=sys.stderr)
        return 2
    print(json.dumps(summary, ensure_ascii=False, indent=2), file=sys.stderr)
    print(str(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
