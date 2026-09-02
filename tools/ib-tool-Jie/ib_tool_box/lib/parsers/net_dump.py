"""
Parsers for ibdiagnet2.net_dump — unified for NDR and XDR.

Format
------
Switch block header (no guaranteed blank line between blocks):
    "<SW_NAME>", <VENDOR>, 0x<GUID>, LID <N>
Column header (one per block, skip):
    #  : IB# : Sta : PhysSta : MTU : LWA : LSA : FEC mode : Retran : Neighbor Guid : N# : NLID : Neighbor Description
Port rows (13 colon-separated fields):
    sw1p1 : 1 : ACT : LINK UP : 5 : 1x : 200 : MLNX_RS_544_514_PLR : NO-RTR : 0x... : ... : 2566 : "pg21a-1-1-hpc mlx5_0"

XDR: 4 ASIC blocks per physical switch (U1–U4), each with its own GUID.
Plane is extracted from /U<N> suffix in block header name.
NDR: single block per switch (/U1 only); plane returned as 0.
"""

from __future__ import annotations

import re
from pathlib import Path

import pandas as pd


# Block header: "<full_name>", <vendor>, 0x<GUID>, LID <N>
_HEADER_RE = re.compile(
    r'^"(.+)",\s*\w+,\s*(0x[0-9a-fA-F]+),\s*LID\s+(\d+)'
)

# Plane from /U<N> at end of switch name
_PLANE_RE = re.compile(r"/U(\d+)$")


def _parse_header(line: str):
    """Parse block header → (full_name, guid, lid) or None."""
    m = _HEADER_RE.match(line)
    if not m:
        return None
    return m.group(1), m.group(2).lower(), int(m.group(3))


def _extract_hostname(full_name: str) -> str:
    """Strip 'MF0;' prefix and ':<model>/U<N>' suffix → display hostname.

    'MF0;PG21A-R10-IB:Q3400_RA/U2' → 'PG21A-R10-IB'
    'MF0;ib-410-g01u19-p1-slg1-lf-08:MQM9700/U1' → 'ib-410-g01u19-p1-slg1-lf-08'
    """
    name = full_name
    if name.startswith("MF0;"):
        name = name[4:]
    colon_idx = name.rfind(":")
    if colon_idx > 0:
        name = name[:colon_idx]
    return name


def _extract_plane(full_name: str) -> int:
    """Extract plane number from /U<N> suffix. Returns 0 if not found."""
    m = _PLANE_RE.search(full_name)
    return int(m.group(1)) if m else 0


def _is_col_header(fields: list[str]) -> bool:
    """Detect column header row — first field is '#' after strip."""
    return len(fields) >= 2 and fields[0] == "#"


def _clean_desc(desc: str) -> str:
    """Strip surrounding quotes from neighbor description."""
    d = desc.strip()
    if d.startswith('"') and d.endswith('"'):
        d = d[1:-1]
    return d.strip()


def parse_links(net_dump_path: Path) -> pd.DataFrame:
    """Parse ibdiagnet2.net_dump into a link DataFrame (NDR and XDR).

    Returns one row per port per ASIC block. For XDR this means 4 rows
    per logical port (one per plane).

    Columns: sw_guid, sw_name, hostname, sw_lid, plane, phys_port, ib_port,
             sta, phys_sta, mtu, lwa, lsa, fec_mode, retran,
             neighbor_guid, neighbor_phys_port, neighbor_lid, neighbor_desc
    """
    text = Path(net_dump_path).read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    rows: list[dict] = []
    sw_guid = sw_name = hostname = ""
    sw_lid = 0
    plane = 0
    skip_next_header = False

    for line in lines:
        # Try block header
        hdr = _parse_header(line)
        if hdr is not None:
            sw_name, sw_guid, sw_lid = hdr
            hostname = _extract_hostname(sw_name)
            plane = _extract_plane(sw_name)
            skip_next_header = True
            continue

        # Skip column header line
        stripped = line.strip()
        if not stripped:
            continue

        fields = [f.strip() for f in line.split(":")]
        if skip_next_header and _is_col_header(fields):
            skip_next_header = False
            continue
        skip_next_header = False

        # Port data row — expect at least 13 colon-separated fields.
        # Neighbor Description (field 12+) may contain ':' for switch names
        # (e.g. "MF0;hostname:MQM9700/U1"), so rejoin fields[12:].
        if len(fields) < 13:
            continue

        # Parse neighbor_lid safely (may be empty for DOWN ports)
        nlid_str = fields[11]
        try:
            nlid = int(nlid_str) if nlid_str else 0
        except ValueError:
            nlid = 0

        # Rejoin fields[12:] to handle ':' inside neighbor description
        raw_desc = ":".join(fields[12:]) if len(fields) > 12 else ""

        rows.append({
            "sw_guid": sw_guid,
            "sw_name": sw_name,
            "hostname": hostname,
            "sw_lid": sw_lid,
            "plane": plane,
            "phys_port": fields[0],
            "ib_port": int(fields[1]) if fields[1].isdigit() else 0,
            "sta": fields[2],
            "phys_sta": fields[3],
            "mtu": fields[4],
            "lwa": fields[5],
            "lsa": fields[6],
            "fec_mode": fields[7],
            "retran": fields[8],
            "neighbor_guid": fields[9].lower() if fields[9] else "",
            "neighbor_phys_port": fields[10],
            "neighbor_lid": nlid,
            "neighbor_desc": _clean_desc(raw_desc),
        })

    if not rows:
        return pd.DataFrame()

    return pd.DataFrame(rows)


def parse_guid_lid_map(net_dump_path: Path) -> dict[str, int]:
    """Build {guid_hex_lowercase: lid} from net_dump.

    Includes both switch GUIDs (from block headers) and neighbor GUIDs
    (from port rows — covers HCAs and remote switches).
    """
    df = parse_links(net_dump_path)
    result: dict[str, int] = {}
    # Switch GUIDs from block headers
    for _, row in df.drop_duplicates("sw_guid").iterrows():
        result[row["sw_guid"]] = row["sw_lid"]
    # Neighbor GUIDs from port rows (covers HCAs)
    nbr = df[df["neighbor_guid"].ne("") & (df["neighbor_lid"] > 0)]
    for _, row in nbr.drop_duplicates("neighbor_guid").iterrows():
        result[row["neighbor_guid"]] = row["neighbor_lid"]
    return result
