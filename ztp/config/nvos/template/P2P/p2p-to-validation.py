#!/usr/bin/env python3
"""Convert CL/CS link sheets in an XLSX workbook to a CVT workbook.

The implementation uses only the Python standard library.  It reads XLSX
files as ZIP/XML and therefore does not require openpyxl on the deployment
server.
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import os
import re
import sys
import tempfile
import zipfile
from collections import Counter, OrderedDict, defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Optional
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape, quoteattr


CSV_HEADER = [
    "Protocol", "A-Node", "A-Port", "A-Module-PN", "A-Connector",
    "A-MPO-Connector", "Z-Node", "Z-Port", "Z-MPO-Connector", "Source-Ref",
]
NODES_HEADER = [
    "FabricId", "Rack", "Unit", "TrayIndex", "NodeName", "NodeType",
    "NodeOs", "NodeModel", "ServerProfile", "Managed", "CredentialProfile", "IP",
]
DC_LAYOUT_HEADER = [
    "FabricId", "DataHall", "ScalableUnit", "Rack", "RackType", "RackGroup",
]
SERVER_PROFILE_HEADER = [
    "ServerProfile", "PhysicalPort", "RDMAName", "CustomNICName", "NICOSName", "PCIAddress",
]
SERVER_PROFILE_BY_DEVICE_TYPE = {
    "smc-b300": "B300_CX8",
}

MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
OFFICE_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PACKAGE_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
NS = {"m": MAIN_NS, "r": OFFICE_REL_NS, "pr": PACKAGE_REL_NS}
CL_CS_RE = re.compile(r"CL|CS", re.IGNORECASE)
HEADER_PORT_RE = re.compile(r"(?:^|[/ _-])port(?:$|[/ _-])", re.IGNORECASE)
BAD_QUOTES = str.maketrans("", "", "‘’“”")
MAX_XLSX_ENTRIES = 20_000
MAX_XLSX_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_XLSX_XML_BYTES = 128 * 1024 * 1024


def runtime_dir() -> Path:
    """Return the directory used for default inputs and outputs."""
    override = os.environ.get("XLSX_TO_CSV_BASE_DIR")
    return Path(override).expanduser().resolve() if override else Path(__file__).resolve().parent


class ConversionError(RuntimeError):
    """Raised for an invalid workbook or an unusable input layout."""


@dataclass(frozen=True)
class ExtractedLink:
    sheet: str
    row: int
    source_device: str
    source_port: str
    source_floor: str
    source_rack: str
    source_unit: str
    destination_device: str
    destination_port: str
    destination_floor: str
    destination_rack: str
    destination_unit: str


def clean(value: object) -> str:
    return str(value or "").translate(BAD_QUOTES).strip()


def normalize_header(value: object) -> str:
    return re.sub(r"\s+", " ", clean(value)).casefold()


def location_columns(
    header: dict[int, str], name_column: int
) -> tuple[Optional[int], Optional[int], Optional[int]]:
    """Find the floor/rack/unit columns immediately before an endpoint name column."""
    floor_column = name_column - 3
    rack_column = name_column - 2
    unit_column = name_column - 1
    floor_header = normalize_header(header.get(floor_column, ""))
    rack_header = normalize_header(header.get(rack_column, ""))
    unit_header = normalize_header(header.get(unit_column, ""))
    if floor_header != "floor":
        floor_column = None
    if rack_header != "rack":
        rack_column = None
    if unit_header not in ("u", "unit"):
        unit_column = None
    return floor_column, rack_column, unit_column


def natural_key(value: str) -> list[tuple[int, object]]:
    return [
        (0, int(part)) if part.isdigit() else (1, part.casefold())
        for part in re.split(r"(\d+)", value)
    ]


def first_unit(value: str) -> str:
    match = re.match(r"\s*(\d+)", clean(value))
    return match.group(1) if match else clean(value)


def data_hall(value: str) -> str:
    floor = clean(value)
    if not floor:
        return ""
    return floor if floor.casefold().endswith("f") else f"{floor}F"


def column_index(cell_ref: str) -> int:
    match = re.match(r"[A-Z]+", cell_ref.upper())
    if not match:
        raise ConversionError(f"invalid XLSX cell reference: {cell_ref!r}")
    result = 0
    for char in match.group():
        result = result * 26 + ord(char) - ord("A") + 1
    return result - 1


def validate_xlsx_archive(archive: zipfile.ZipFile) -> None:
    """Bound ZIP/XML resource use before parsing a user-supplied workbook."""
    members = archive.infolist()
    if len(members) > MAX_XLSX_ENTRIES:
        raise ConversionError(f"XLSX contains too many ZIP entries (>{MAX_XLSX_ENTRIES})")
    if sum(member.file_size for member in members) > MAX_XLSX_UNCOMPRESSED_BYTES:
        raise ConversionError(
            "XLSX uncompressed content exceeds "
            f"{MAX_XLSX_UNCOMPRESSED_BYTES} bytes"
        )
    names = [member.filename for member in members]
    if len(names) != len(set(names)):
        raise ConversionError("XLSX contains duplicate ZIP member names")
    for member in members:
        if member.filename.casefold().endswith(".xml") and member.file_size > MAX_XLSX_XML_BYTES:
            raise ConversionError(
                f"XLSX XML part is too large: {member.filename!r}"
            )


def load_shared_strings(archive: zipfile.ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in archive.namelist():
        return []
    root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
    return [
        "".join(node.text or "" for node in item.iterfind(".//m:t", NS))
        for item in root.findall("m:si", NS)
    ]


def workbook_sheets(archive: zipfile.ZipFile) -> list[tuple[str, str]]:
    rel_root = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
    relationships = {
        item.attrib["Id"]: item.attrib["Target"]
        for item in rel_root.findall("pr:Relationship", NS)
    }
    workbook = ET.fromstring(archive.read("xl/workbook.xml"))
    sheets: list[tuple[str, str]] = []
    for item in workbook.findall("m:sheets/m:sheet", NS):
        name = item.attrib["name"]
        rel_id = item.attrib[f"{{{OFFICE_REL_NS}}}id"]
        target = relationships[rel_id]
        if target.startswith("/"):
            part = target.lstrip("/")
        else:
            target_path = PurePosixPath(target)
            if "\\" in target or ".." in target_path.parts:
                raise ConversionError(f"unsafe XLSX worksheet relationship: {target!r}")
            part = str(PurePosixPath("xl") / target_path)
        part_path = PurePosixPath(part)
        if ("\\" in part or ".." in part_path.parts
                or not part.startswith("xl/") or part not in archive.namelist()):
            raise ConversionError(f"invalid XLSX worksheet part: {part!r}")
        sheets.append((name, part))
    return sheets


def cell_value(cell: ET.Element, shared_strings: list[str]) -> str:
    cell_type = cell.attrib.get("t", "")
    if cell_type == "inlineStr":
        inline = cell.find("m:is", NS)
        if inline is None:
            return ""
        return "".join(node.text or "" for node in inline.iterfind(".//m:t", NS))

    value = cell.find("m:v", NS)
    if value is None or value.text is None:
        return ""
    if cell_type == "s":
        try:
            return shared_strings[int(value.text)]
        except (IndexError, ValueError) as exc:
            raise ConversionError("invalid shared-string index in XLSX") from exc
    if cell_type == "b":
        return "TRUE" if value.text == "1" else "FALSE"
    return value.text


def read_sheet_rows(
    archive: zipfile.ZipFile, part: str, shared_strings: list[str]
) -> list[tuple[int, dict[int, str]]]:
    root = ET.fromstring(archive.read(part))
    rows: list[tuple[int, dict[int, str]]] = []
    for row in root.findall(".//m:sheetData/m:row", NS):
        row_number = int(row.attrib.get("r", len(rows) + 1))
        values: dict[int, str] = {}
        for cell in row.findall("m:c", NS):
            value = clean(cell_value(cell, shared_strings))
            if value:
                values[column_index(cell.attrib.get("r", "A1"))] = value
        rows.append((row_number, values))
    return rows


def find_endpoint_columns(rows: list[tuple[int, dict[int, str]]]) -> tuple[int, tuple[int, int, int, int]]:
    """Return the header-list index and source/destination name/port columns."""
    for row_index, (_number, values) in enumerate(rows):
        name_columns = [
            column for column, value in sorted(values.items())
            if normalize_header(value) == "name"
        ]
        pairs: list[tuple[int, int]] = []
        for name_column in name_columns:
            port_column = name_column + 1
            port_header = normalize_header(values.get(port_column, ""))
            if port_header and ("port" in port_header or HEADER_PORT_RE.search(port_header)):
                pairs.append((name_column, port_column))
        if len(pairs) >= 2:
            source, destination = pairs[0], pairs[1]
            return row_index, (source[0], source[1], destination[0], destination[1])
    raise ConversionError("could not find two name/port column pairs")


def parse_inventory(path: Path) -> tuple[list[str], list[tuple[str, str]]]:
    type_order: list[str] = []
    patterns: list[tuple[str, str]] = []
    current_type = ""
    in_meta = False
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line:
            in_meta = False
            continue
        if line.startswith("#"):
            continue
        if re.fullmatch(r"\[\[.*\]\]", line):
            in_meta = True
            current_type = ""
            continue
        if re.fullmatch(r"\[.*\]", line):
            if in_meta:
                continue
            current_type = line[1:-1]
            if current_type.casefold() not in {item.casefold() for item in type_order}:
                type_order.append(current_type)
            continue
        if current_type and not in_meta:
            patterns.append((current_type, line.casefold()))
    return type_order, patterns


def parse_port_map(path: Path) -> tuple[dict[tuple[str, str], str], OrderedDict[tuple[str, str], str]]:
    direct: dict[tuple[str, str], str] = {}
    switch: OrderedDict[tuple[str, str], str] = OrderedDict()
    section = ""
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if re.fullmatch(r"\[.*\]", line):
            section = line[1:-1]
            continue
        if not section or "," not in raw_line:
            continue
        pattern, output = (part.strip() for part in raw_line.split(",", 1))
        key = (section.casefold(), pattern.casefold())
        if "#" in pattern:
            switch[key] = output
        else:
            direct[key] = output
    return direct, switch


def parse_splitters(path: Path) -> tuple[dict[tuple[str, str], str], dict[str, str]]:
    exact: dict[tuple[str, str], str] = {}
    defaults: dict[str, str] = {}
    with path.open(encoding="utf-8-sig", newline="") as stream:
        for raw_line in stream:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = next(csv.reader([raw_line]))
            if len(parts) < 3:
                continue
            device, port, splitter = (part.strip() for part in parts[:3])
            if not device:
                continue
            if port == "*":
                defaults[device.casefold()] = splitter
            else:
                exact[(device.casefold(), port.casefold())] = splitter
    return exact, defaults


class RuleSet:
    def __init__(self, inventory: Path, port_map: Path, splitter: Path) -> None:
        self.type_order, self.inventory_patterns = parse_inventory(inventory)
        self.port_direct, self.port_switch = parse_port_map(port_map)
        self.splitter_exact, self.splitter_default = parse_splitters(splitter)

    def device_type(self, device: str) -> str:
        value = device.casefold()
        matches: list[tuple[int, int, str]] = []
        order = {name.casefold(): index for index, name in enumerate(self.type_order)}
        for device_type in self.type_order:
            for pattern_type, pattern in self.inventory_patterns:
                if (pattern_type.casefold() == device_type.casefold()
                        and fnmatch.fnmatchcase(value, pattern)):
                    # A hostname can match a broad rule such as ``*GPU*`` and a
                    # more precise platform rule such as ``*gpusrv*``. Prefer
                    # the rule with more literal characters; preserve inventory
                    # section order only as the tie breaker.
                    specificity = len(pattern.replace("*", "").replace("?", ""))
                    matches.append((specificity, -order[device_type.casefold()], device_type))
        if matches:
            return max(matches)[2]
        return "unknown"

    @staticmethod
    def protocol(device_type: str) -> str:
        value = device_type.casefold()
        if "ib" in value:
            return "ib"
        if "eth" in value or "spx" in value:
            return "eth"
        return "unknown"

    def resolve_port(self, device: str, port: str) -> str:
        device_type = self.device_type(device)
        direct_key = (device_type.casefold(), port.casefold())
        if direct_key in self.port_direct:
            return self.port_direct[direct_key]

        base_port, separator, suffix = port.partition("/")
        splitter = self.splitter_exact.get(
            (device.casefold(), base_port.casefold()),
            self.splitter_default.get(device.casefold(), "1to1"),
        )
        pattern = f"{splitter}#/{suffix}" if separator else f"{splitter}#"
        switch_key = (device_type.casefold(), pattern.casefold())
        if switch_key in self.port_switch:
            return self.port_switch[switch_key].replace("#", base_port)

        wanted_suffix = f"/{suffix}".casefold() if separator else ""
        for (rule_type, rule_pattern), output in reversed(self.port_switch.items()):
            if rule_type != device_type.casefold():
                continue
            rule_suffix = rule_pattern.split("#", 1)[1] if "#" in rule_pattern else ""
            if rule_suffix == wanted_suffix:
                return output.replace("#", base_port)
        return port


def device_name_type(device: str) -> str:
    """Group numbered peer devices by their hostname stem.

    Examples: HGX001 -> HGX, UFM02 -> UFM, leaf-01 -> leaf.
    Embedded digits remain part of the type; only the final numeric instance
    suffix (and its immediately preceding separator) is removed.
    """
    stem = re.sub(r"[-_ ]?\d+$", "", clean(device))
    return stem or clean(device)


def validate_links(links: list[ExtractedLink]) -> None:
    """Print link-count summaries and reject repeated device/port endpoints."""
    def compact_names(names: list[str], limit: int = 16) -> str:
        if len(names) <= limit:
            return ", ".join(names)
        return f"{', '.join(names[:limit])}, ... (+{len(names) - limit} more)"

    endpoint_uses: dict[tuple[str, str], list[tuple[str, int, str, str, str, str]]] = defaultdict(list)
    device_names: dict[str, str] = {}
    device_counts: Counter[str] = Counter()

    for link in links:
        endpoints = (
            (link.source_device, link.source_port,
             link.destination_device, link.destination_port),
            (link.destination_device, link.destination_port,
             link.source_device, link.source_port),
        )
        for device, port, peer_device, peer_port in endpoints:
            device_key = device.casefold()
            device_names.setdefault(device_key, device)
            device_counts[device_key] += 1
            endpoint_uses[(device_key, port.casefold())].append(
                (link.sheet, link.row, device, port, peer_device, peer_port)
            )

    devices_by_type: dict[str, list[tuple[str, int]]] = defaultdict(list)
    type_names: dict[str, str] = {}
    for device_key, count in device_counts.items():
        device = device_names[device_key]
        name_type = device_name_type(device)
        type_key = name_type.casefold()
        type_names.setdefault(type_key, name_type)
        devices_by_type[type_key].append((device, count))

    print("Link-count summary by device-name type:")
    for type_key in sorted(devices_by_type):
        device_type = type_names[type_key]
        devices = sorted(devices_by_type[type_key], key=lambda item: item[0].casefold())
        distribution = Counter(count for _device, count in devices)
        if len(distribution) == 1:
            link_count = next(iter(distribution))
            print(f"  [OK] {device_type}: {len(devices)} device(s), {link_count} link(s) per device")
            continue

        distribution_text = ", ".join(
            f"{count} links × {device_total} device(s)"
            for count, device_total in sorted(distribution.items())
        )
        print(f"  [WARNING] {device_type}: inconsistent link counts ({distribution_text})")
        for count in sorted(distribution):
            names = [device for device, value in devices if value == count]
            print(f"    {count} links: {compact_names(names)}")

    duplicates = [uses for uses in endpoint_uses.values() if len(uses) > 1]
    if not duplicates:
        print("Device/port uniqueness check: OK")
        return

    print(
        f"ERROR: {len(duplicates)} device/port endpoint(s) occur more than once:",
        file=sys.stderr,
    )
    for uses in sorted(duplicates, key=lambda items: (items[0][2].casefold(), items[0][3].casefold())):
        _sheet, _row, device, port, _peer_device, _peer_port = uses[0]
        print(f"  {device} / {port}: {len(uses)} occurrences", file=sys.stderr)
        for sheet, row, _device, _port, peer_device, peer_port in uses:
            print(
                f"    sheet={sheet!r}, row={row}, peer={peer_device} / {peer_port}",
                file=sys.stderr,
            )
    raise ConversionError("duplicate device/port validation failed; output files were not generated")


def is_switch_type(device_type: str) -> bool:
    value = device_type.casefold()
    return "-sw" in value or value in ("switch", "fw", "firewall")


def server_profile(device_type: str) -> str:
    return SERVER_PROFILE_BY_DEVICE_TYPE.get(device_type.casefold(), "")


def build_nodes_and_layout(
    links: list[ExtractedLink], rules: RuleSet, fabric_id: str
) -> tuple[list[list[str]], list[list[str]], list[list[str]]]:
    """Build the CVT Nodes and DC Floor Layout rows from link endpoints."""
    devices: dict[str, dict[str, str]] = {}
    profile_ports: set[tuple[str, str]] = set()
    for link in links:
        endpoints = (
            (link.source_device, link.source_port,
             link.source_floor, link.source_rack, link.source_unit),
            (link.destination_device, link.destination_port,
             link.destination_floor, link.destination_rack, link.destination_unit),
        )
        for device, port, floor, rack, unit in endpoints:
            key = device.casefold()
            info = devices.setdefault(key, {
                "name": device,
                "floor": floor,
                "rack": rack,
                "unit": first_unit(unit),
            })
            if not info["rack"] and rack:
                info["rack"] = rack
            if not info["floor"] and floor:
                info["floor"] = floor
            if not info["unit"] and unit:
                info["unit"] = first_unit(unit)
            profile = server_profile(rules.device_type(device))
            if profile:
                profile_ports.add((profile, clean(port)))

    node_rows: list[list[str]] = []
    racks: dict[str, dict[str, str]] = {}
    ordered_devices = sorted(
        devices.values(),
        key=lambda info: (
            0 if is_switch_type(rules.device_type(info["name"])) else 1,
            natural_key(info["name"]),
        ),
    )
    for info in ordered_devices:
        device = info["name"]
        device_type = rules.device_type(device)
        switch = is_switch_type(device_type)
        profile = server_profile(device_type)
        rack = info["rack"]
        if rack:
            rack_key = rack.casefold()
            rack_info = racks.setdefault(rack_key, {
                "name": rack,
                "floor": info["floor"],
                "type": "GPURack",
            })
            if not rack_info["floor"] and info["floor"]:
                rack_info["floor"] = info["floor"]
            if switch:
                rack_info["type"] = "NetworkRack"
        node_rows.append([
            fabric_id,
            rack,
            info["unit"],
            "",
            device,
            "switch" if switch else "host",
            "nvos" if switch else "linux",
            "",
            profile,
            "yes" if switch else "no",
            "default" if switch else "compute",
            "",
        ])

    layout_rows = [
        [fabric_id, data_hall(racks[key]["floor"]), "", racks[key]["name"], racks[key]["type"], ""]
        for key in sorted(racks, key=lambda item: natural_key(racks[item]["name"]))
    ]
    profile_rows = [
        [profile, port, "", "", "", ""]
        for profile, port in sorted(profile_ports, key=lambda item: (natural_key(item[0]), natural_key(item[1])))
    ]
    return node_rows, layout_rows, profile_rows


def excel_column(index: int) -> str:
    result = ""
    value = index + 1
    while value:
        value, remainder = divmod(value - 1, 26)
        result = chr(ord("A") + remainder) + result
    return result


def inline_cell(reference: str, value: str, style: int, force: bool = False) -> str:
    text = clean(value)
    if not text:
        return f'<c r={quoteattr(reference)} s="{style}"/>' if force else ""
    space = ' xml:space="preserve"' if text != text.strip() else ""
    return (
        f'<c r={quoteattr(reference)} s="{style}" t="inlineStr">'
        f'<is><t{space}>{escape(text)}</t></is></c>'
    )


def worksheet_xml(
    rows: list[list[str]], widths: list[float], yellow_cells: set[tuple[int, int]]
) -> str:
    column_count = len(rows[0])
    row_count = len(rows)
    last_cell = f"{excel_column(column_count - 1)}{row_count}"
    columns = "".join(
        f'<col min="{index + 1}" max="{index + 1}" width="{width}" customWidth="1"/>'
        for index, width in enumerate(widths)
    )
    xml_rows = []
    for row_number, row in enumerate(rows, 1):
        cells = "".join(
            inline_cell(
                f"{excel_column(column)}{row_number}",
                value,
                1 if row_number == 1 else 3 if (row_number, column) in yellow_cells else 2,
                force=(row_number, column) in yellow_cells,
            )
            for column, value in enumerate(row)
        )
        xml_rows.append(f'<row r="{row_number}">{cells}</row>')
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<worksheet xmlns="{MAIN_NS}">'
        f'<dimension ref="A1:{last_cell}"/>'
        '<sheetViews><sheetView workbookViewId="0">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
        '<selection pane="bottomLeft" activeCell="A2" sqref="A2"/>'
        '</sheetView></sheetViews>'
        '<sheetFormatPr defaultRowHeight="15"/>'
        f'<cols>{columns}</cols>'
        f'<sheetData>{"".join(xml_rows)}</sheetData>'
        f'<autoFilter ref="A1:{last_cell}"/>'
        '<pageMargins left="0.7" right="0.7" top="0.75" bottom="0.75" header="0.3" footer="0.3"/>'
        '</worksheet>'
    )


def write_cvt_workbook(
    path: Path,
    node_rows: list[list[str]],
    layout_rows: list[list[str]],
    link_rows: list[list[str]],
    profile_rows: list[list[str]],
) -> None:
    """Write a compact dependency-free CVT workbook with the reference sheet structure."""
    sheets = [
        ("Nodes", [NODES_HEADER] + node_rows,
         [18, 10, 10, 12, 32, 14, 14, 18, 20, 12, 20, 18]),
        ("DC Floor Layout", [DC_LAYOUT_HEADER] + layout_rows,
         [18, 16, 18, 12, 18, 18]),
        ("Links", [CSV_HEADER] + link_rows,
         [14, 34, 16, 18, 18, 22, 34, 16, 22, 18]),
        ("Server Profile", [SERVER_PROFILE_HEADER] + profile_rows,
         [18, 16, 16, 18, 18, 18]),
    ]
    yellow_by_sheet: dict[str, set[tuple[int, int]]] = defaultdict(set)

    for row_number, row in enumerate(node_rows, 2):
        for column in (0, 1, 2, 7):  # FabricId, Rack, Unit, NodeModel
            if not row[column]:
                yellow_by_sheet["Nodes"].add((row_number, column))
        if row[5] == "host" and not row[8]:
            yellow_by_sheet["Nodes"].add((row_number, 8))
        if row[5] == "switch" and not row[11]:
            yellow_by_sheet["Nodes"].add((row_number, 11))

    for row_number, row in enumerate(layout_rows, 2):
        for column in (0, 1, 2, 3, 4):
            if not row[column]:
                yellow_by_sheet["DC Floor Layout"].add((row_number, column))

    for row_number, row in enumerate(profile_rows, 2):
        for column in (2, 4, 5):  # RDMAName, NICOSName, PCIAddress
            if not row[column]:
                yellow_by_sheet["Server Profile"].add((row_number, column))
    sheet_overrides = "".join(
        f'<Override PartName="/xl/worksheets/sheet{index}.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        for index in range(1, len(sheets) + 1)
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        f'{sheet_overrides}</Types>'
    )
    workbook_sheets_xml = "".join(
        f'<sheet name={quoteattr(name)} sheetId="{index}" r:id="rId{index}"/>'
        for index, (name, _rows, _widths) in enumerate(sheets, 1)
    )
    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<workbook xmlns="{MAIN_NS}" xmlns:r="{OFFICE_REL_NS}">'
        f'<sheets>{workbook_sheets_xml}</sheets>'
        '<calcPr calcMode="auto"/></workbook>'
    )
    workbook_relationships = "".join(
        f'<Relationship Id="rId{index}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        f'Target="worksheets/sheet{index}.xml"/>'
        for index in range(1, len(sheets) + 1)
    ) + (
        f'<Relationship Id="rId{len(sheets) + 1}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" '
        'Target="styles.xml"/>'
    )
    workbook_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<Relationships xmlns="{PACKAGE_REL_NS}">{workbook_relationships}</Relationships>'
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<Relationships xmlns="{PACKAGE_REL_NS}">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/></Relationships>'
    )
    styles_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<styleSheet xmlns="{MAIN_NS}">'
        '<fonts count="2">'
        '<font><sz val="11"/><name val="Arial"/><family val="2"/></font>'
        '<font><b/><color rgb="FFFFFFFF"/><sz val="11"/><name val="Arial"/><family val="2"/></font>'
        '</fonts>'
        '<fills count="4">'
        '<fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FF1F4E78"/><bgColor indexed="64"/></patternFill></fill>'
        '<fill><patternFill patternType="solid"><fgColor rgb="FFFFF2CC"/><bgColor indexed="64"/></patternFill></fill>'
        '</fills>'
        '<borders count="2">'
        '<border><left/><right/><top/><bottom/><diagonal/></border>'
        '<border><left style="thin"><color rgb="FFD9E2F3"/></left>'
        '<right style="thin"><color rgb="FFD9E2F3"/></right>'
        '<top style="thin"><color rgb="FFD9E2F3"/></top>'
        '<bottom style="thin"><color rgb="FFD9E2F3"/></bottom><diagonal/></border>'
        '</borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="4">'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyAlignment="1">'
        '<alignment horizontal="center" vertical="center"/></xf>'
        '<xf numFmtId="49" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyAlignment="1">'
        '<alignment vertical="center"/></xf>'
        '<xf numFmtId="49" fontId="0" fillId="3" borderId="1" xfId="0" applyNumberFormat="1" applyAlignment="1">'
        '<alignment vertical="center"/></xf>'
        '</cellXfs>'
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        '</styleSheet>'
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", root_rels)
        archive.writestr("xl/workbook.xml", workbook_xml)
        archive.writestr("xl/_rels/workbook.xml.rels", workbook_rels_xml)
        archive.writestr("xl/styles.xml", styles_xml)
        for index, (name, rows, widths) in enumerate(sheets, 1):
            archive.writestr(
                f"xl/worksheets/sheet{index}.xml",
                worksheet_xml(rows, widths, yellow_by_sheet[name]),
            )


def publish_cvt_workbook(
    path: Path,
    node_rows: list[list[str]],
    layout_rows: list[list[str]],
    link_rows: list[list[str]],
    profile_rows: list[list[str]],
) -> Optional[Path]:
    """Generate safely, backing up an existing result before replacement."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    os.close(fd)
    temporary_path = Path(temporary_name)
    backup_path: Optional[Path] = None
    try:
        write_cvt_workbook(
            temporary_path, node_rows, layout_rows, link_rows, profile_rows
        )
        if path.exists():
            if not path.is_file():
                raise ConversionError(f"output path exists but is not a file: {path}")
            backup_path = Path(f"{path}.bak")
            print(f"WARNING: Output file already exists: {path}", file=sys.stderr)
            print(f"WARNING: Backing up existing file to: {backup_path}", file=sys.stderr)
            os.replace(path, backup_path)
        try:
            os.replace(temporary_path, path)
        except OSError:
            if backup_path is not None and backup_path.is_file() and not path.exists():
                os.replace(backup_path, path)
            raise
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
    return backup_path


def choose_input(script_dir: Path) -> Path:
    """Return the setup-managed canonical P2P input."""
    path = (script_dir / "p2p.xlsx").absolute()
    if not path.is_file():
        raise ConversionError(f"input XLSX not found: {path}")
    if path.suffix.casefold() != ".xlsx":
        raise ConversionError(f"input must be an .xlsx file: {path}")
    return path


def source_workbook_stem(path: Path) -> str:
    """Return the final source filename stem for a setup-managed XLSX link."""
    try:
        source = path.resolve(strict=True)
    except OSError as exc:
        raise ConversionError(f"cannot resolve input XLSX source: {path}: {exc}") from exc
    return source.stem


def convert(args: argparse.Namespace) -> tuple[Path, int, int, list[tuple[str, int]]]:
    script_dir = runtime_dir()
    input_path = choose_input(script_dir)
    workbook_path = (
        Path(args.output).expanduser().resolve()
        if args.output
        else script_dir / "output-p2p" / f"{source_workbook_stem(input_path)}-cvt.xlsx"
    )
    rules = RuleSet(Path(args.inventory), Path(args.port_map), Path(args.splitter))

    extracted_links: list[ExtractedLink] = []
    malformed = 0
    matched_sheets: list[tuple[str, int]] = []
    try:
        with zipfile.ZipFile(input_path) as archive:
            validate_xlsx_archive(archive)
            shared_strings = load_shared_strings(archive)
            for sheet_name, part in workbook_sheets(archive):
                if not CL_CS_RE.search(sheet_name):
                    continue
                rows = read_sheet_rows(archive, part, shared_strings)
                try:
                    header_index, columns = find_endpoint_columns(rows)
                except ConversionError as exc:
                    print(f"WARNING: sheet {sheet_name!r} skipped: {exc}", file=sys.stderr)
                    continue

                header_values = rows[header_index][1]
                source_floor_column, source_rack_column, source_unit_column = location_columns(
                    header_values, columns[0]
                )
                destination_floor_column, destination_rack_column, destination_unit_column = location_columns(
                    header_values, columns[2]
                )

                sheet_count = 0
                for row_number, values in rows[header_index + 1:]:
                    endpoints = [clean(values.get(column, "")) for column in columns]
                    if not any(endpoints):
                        continue
                    if not all(endpoints):
                        malformed += 1
                        continue
                    source_device, source_port, destination_device, destination_port = endpoints
                    extracted_links.append(ExtractedLink(
                        sheet=sheet_name,
                        row=row_number,
                        source_device=source_device,
                        source_port=source_port,
                        source_floor=clean(values.get(source_floor_column, "")) if source_floor_column is not None else "",
                        source_rack=clean(values.get(source_rack_column, "")) if source_rack_column is not None else "",
                        source_unit=clean(values.get(source_unit_column, "")) if source_unit_column is not None else "",
                        destination_device=destination_device,
                        destination_port=destination_port,
                        destination_floor=clean(values.get(destination_floor_column, "")) if destination_floor_column is not None else "",
                        destination_rack=clean(values.get(destination_rack_column, "")) if destination_rack_column is not None else "",
                        destination_unit=clean(values.get(destination_unit_column, "")) if destination_unit_column is not None else "",
                    ))
                    sheet_count += 1
                matched_sheets.append((sheet_name, sheet_count))
    except (KeyError, ET.ParseError, zipfile.BadZipFile) as exc:
        raise ConversionError(f"invalid or unsupported XLSX structure: {exc}") from exc

    if not matched_sheets:
        raise ConversionError("no CL/CS sheet with two name/port header pairs was found")

    validate_links(extracted_links)

    output_rows: list[list[str]] = []
    for link in extracted_links:
        protocol = rules.protocol(rules.device_type(link.source_device))
        if protocol == "unknown":
            protocol = rules.protocol(rules.device_type(link.destination_device))
        output_rows.append([
            protocol,
            link.source_device,
            rules.resolve_port(link.source_device, link.source_port),
            "", "", "",
            link.destination_device,
            rules.resolve_port(link.destination_device, link.destination_port),
            "", "",
        ])

    unknown = sum(row[0] == "unknown" for row in output_rows)
    node_rows, layout_rows, profile_rows = build_nodes_and_layout(
        extracted_links, rules, args.fabric_id
    )
    backup_path = publish_cvt_workbook(
        workbook_path, node_rows, layout_rows, output_rows, profile_rows
    )
    if backup_path is not None:
        print(f"Backup created: {backup_path}")
    return workbook_path, unknown, malformed, matched_sheets


def parse_args() -> argparse.Namespace:
    script_dir = runtime_dir()
    parser = argparse.ArgumentParser(
        description="Convert XLSX sheets whose names contain CL or CS to one CVT workbook.",
    )
    parser.add_argument(
        "-o", "--output", "--xlsx-output",
        dest="output",
        help="output CVT workbook path; default: output-p2p/<source-workbook>-cvt.xlsx",
    )
    parser.add_argument(
        "--fabric-id", default="",
        help="FabricId written to Nodes/DC Floor Layout; default: blank",
    )
    parser.add_argument("--inventory", default=str(script_dir / "01-inventory.log"))
    parser.add_argument("--port-map", default=str(script_dir / "02-port-mapping.log"))
    parser.add_argument("--splitter", default=str(script_dir / "03-splitter.log"))
    return parser.parse_args()


def main() -> int:
    try:
        workbook, unknown, malformed, sheets = convert(parse_args())
    except (ConversionError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print("Matched sheets:")
    for name, records in sheets:
        print(f"  {name}: {records} record(s)")
    total = sum(records for _name, records in sheets)
    print(f"Generated CVT XLSX: {workbook} ({total} link records)")
    if unknown:
        print(f"WARNING: {unknown} record(s) have Protocol=unknown; check inventory rules.", file=sys.stderr)
    if malformed:
        print(f"WARNING: {malformed} partial endpoint row(s) were skipped.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
