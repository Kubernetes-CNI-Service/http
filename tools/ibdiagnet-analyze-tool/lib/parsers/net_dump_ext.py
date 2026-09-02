"""
Parser for ibdiagnet2.net_dump_ext — unified for NDR and XDR.

Format
------
Single flat CSV table with ':' separator. Comment lines start with '#'.
Header row: Ty : # : #IB : GUID : LID : Sta : PhysSta : LWA : LSA :
            Conn LID (#) : FEC mode : RTR : Raw BER : Effective BER :
            Symbol BER : Symbol Err : Effective Err : Node Desc

Note: Node Desc may contain ':' (e.g. "MF0;PG21A-R10-IB:Q3400_RA/U1"),
so fields[17:] must be joined back together.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd


def _parse_ber(val: str) -> float:
    """Parse BER value to float. N/A → NaN."""
    v = val.strip()
    if not v or v.upper() in ("N/A", "NA", "-"):
        return float("nan")
    try:
        return float(v)
    except ValueError:
        return float("nan")


def _parse_lid(val: str) -> int:
    """Extract decimal LID from 'N (0xHEX)' format."""
    v = val.strip()
    if not v:
        return 0
    # Take everything before the first space or '('
    parts = v.split()
    try:
        return int(parts[0])
    except (ValueError, IndexError):
        return 0


def _clean_desc(desc: str) -> str:
    """Strip surrounding quotes from node description."""
    d = desc.strip()
    if d.startswith('"') and d.endswith('"'):
        d = d[1:-1]
    return d.strip()


def parse_links_ext(net_dump_ext_path: Path) -> pd.DataFrame:
    """Parse ibdiagnet2.net_dump_ext into a BER/FEC DataFrame (NDR and XDR).

    Returns one row per port entry. For XDR this means one row per
    (ASIC, port) — 4 rows per logical switch port across U1–U4 blocks.

    Columns: ty, phys_port, ib_port, guid, lid, sta, phys_sta,
             lwa, lsa, conn_lid, fec_mode, rtr,
             raw_ber, eff_ber, sym_ber, sym_err, eff_err, node_desc
    """
    text = Path(net_dump_ext_path).read_text(encoding="utf-8", errors="replace")

    rows: list[dict] = []
    header_seen = False

    for line in text.splitlines():
        stripped = line.strip()

        # Skip comments and blank lines
        if not stripped or stripped.startswith("#"):
            continue

        fields = [f.strip() for f in line.split(":")]

        # Skip column header row (first non-comment line, starts with 'Ty')
        if not header_seen:
            if fields[0].upper() == "TY":
                header_seen = True
                continue
            continue

        if len(fields) < 18:
            continue

        # Node Desc may contain ':' — rejoin fields[17:]
        node_desc = _clean_desc(":".join(fields[17:]))

        rows.append({
            "ty": fields[0],
            "phys_port": fields[1],
            "ib_port": int(fields[2]) if fields[2].isdigit() else 0,
            "guid": fields[3].lower() if fields[3] else "",
            "lid": _parse_lid(fields[4]),
            "sta": fields[5],
            "phys_sta": fields[6],
            "lwa": fields[7],
            "lsa": fields[8],
            "conn_lid": _parse_lid(fields[9]),
            "fec_mode": fields[10],
            "rtr": fields[11],
            "raw_ber": _parse_ber(fields[12]),
            "eff_ber": _parse_ber(fields[13]),
            "sym_ber": _parse_ber(fields[14]),
            "sym_err": _parse_ber(fields[15]),
            "eff_err": _parse_ber(fields[16]),
            "node_desc": node_desc,
        })

    if not rows:
        return pd.DataFrame()

    return pd.DataFrame(rows)
