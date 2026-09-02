"""Parser for the human-readable output produced by ``iblinkinfo``."""

from __future__ import annotations

import re
from pathlib import Path

import pandas as pd

from lib.inventory import SHARP_AN, _parse_switch_name_asic, split_hca_desc


PORT_COLUMNS = [
    "SrcGUID", "SrcDescription", "SrcDevice", "SrcLID", "SrcIBPort", "SrcPort",
    "Width", "Speed", "LogicalState", "PhysicalState", "DstLID", "DstIBPort",
    "DstDescription", "DstDevice", "DstPort", "DstType", "InternalLink",
    "AggregationNode", "LineNumber",
]

_SWITCH_HEADER_RE = re.compile(
    r"^Switch:\s+(?P<guid>0x[0-9a-fA-F]+)\s+(?P<description>.+):\s*$"
)
_PORT_RE = re.compile(
    r'^\s*(?P<src_lid>\d+)\s+(?P<src_port>\d+)\[\s*\]\s*'
    r'==\(\s*(?P<link>.*?)\s*\)==>\s*'
    r'(?:(?P<dst_lid>\d+)\s+(?P<dst_port>\d+))?\[\s*\]\s*'
    r'"(?P<description>[^"]*)"'
)
_LINK_STATE_RE = re.compile(
    r"^(?:(?P<width>\d+X)\s+)?"
    r"(?:(?P<speed>[\d.]+\s+Gbps)\s+)?"
    r"(?P<logical>Active|Armed|Initialize|Down)\s*/\s*(?P<physical>\S+)$",
    re.IGNORECASE,
)


def ib_port_to_switch_port(value: int | str) -> str:
    """Translate iblinkinfo's 1-based switch port into NVOS ``swNpM``."""
    try:
        port = int(value)
    except (TypeError, ValueError):
        return ""
    if port <= 0:
        return ""
    return f"sw{(port + 1) // 2}p{1 if port % 2 else 2}"


def _parse_link_state(value: str) -> tuple[str, str, str, str]:
    normalized = " ".join(value.split())
    match = _LINK_STATE_RE.fullmatch(normalized)
    if not match:
        return "", "", normalized, ""
    return (
        (match.group("width") or "").upper(),
        match.group("speed") or "",
        (match.group("logical") or "").title(),
        match.group("physical") or "",
    )


def parse_iblinkinfo(path: Path) -> pd.DataFrame:
    """Return one row for every switch-port record in an iblinkinfo log."""
    path = Path(path)
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    rows: list[dict[str, object]] = []
    source_guid = source_description = source_device = ""

    for line_number, line in enumerate(text.splitlines(), 1):
        header = _SWITCH_HEADER_RE.match(line)
        if header:
            source_guid = header.group("guid").casefold()
            source_description = header.group("description").strip()
            source_device = _parse_switch_name_asic(source_description)[0]
            continue
        if line.startswith("CA:"):
            source_guid = source_description = source_device = ""
            continue
        if not source_device:
            continue
        match = _PORT_RE.match(line)
        if not match:
            continue

        src_ib_port = int(match.group("src_port"))
        dst_ib_port = int(match.group("dst_port")) if match.group("dst_port") else 0
        destination_description = match.group("description").strip()
        destination_is_switch = destination_description.startswith("MF0;")
        if destination_is_switch:
            destination_device = _parse_switch_name_asic(destination_description)[0]
            destination_port = ib_port_to_switch_port(dst_ib_port)
            destination_type = "switch"
        else:
            destination_device, hca_port = split_hca_desc(destination_description)
            destination_port = hca_port or ""
            destination_type = "host" if destination_device else ""
        width, speed, logical_state, physical_state = _parse_link_state(
            match.group("link")
        )
        aggregation = SHARP_AN in destination_description
        internal = bool(
            destination_is_switch
            and destination_device.casefold() == source_device.casefold()
        )
        rows.append({
            "SrcGUID": source_guid,
            "SrcDescription": source_description,
            "SrcDevice": source_device,
            "SrcLID": int(match.group("src_lid")),
            "SrcIBPort": src_ib_port,
            "SrcPort": ib_port_to_switch_port(src_ib_port),
            "Width": width,
            "Speed": speed,
            "LogicalState": logical_state,
            "PhysicalState": physical_state,
            "DstLID": int(match.group("dst_lid")) if match.group("dst_lid") else 0,
            "DstIBPort": dst_ib_port,
            "DstDescription": destination_description,
            "DstDevice": destination_device,
            "DstPort": destination_port,
            "DstType": destination_type,
            "InternalLink": internal,
            "AggregationNode": aggregation,
            "LineNumber": line_number,
        })

    if not rows:
        raise ValueError(f"no iblinkinfo switch-port records found in: {path}")
    return pd.DataFrame(rows, columns=PORT_COLUMNS)
