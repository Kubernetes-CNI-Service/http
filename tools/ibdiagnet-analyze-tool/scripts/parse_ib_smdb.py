#!/usr/bin/env python3
"""
parse_ib_smdb.py — Parse OpenSM smdb files for SM / switch / HCA / link inventory.

Single-snapshot mode:
    python scripts/parse_ib_smdb.py -l <opensm_logs_folder> -o <output.xlsx>

Two-snapshot comparison mode:
    python scripts/parse_ib_smdb.py \
        -l <opensm_logs_folder_X> --compare-logs <opensm_logs_folder_Y> \
        -o <output.xlsx> [--verbose]

The logs folder must contain `opensm-smdb.dump`.

See specification.MD §4 for the full spec.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd
import xlsxwriter

# Allow running from repo root without installation.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.inventory import (
    NODE_TYPE_HCA,
    NODE_TYPE_SWITCH,
    _normalize_guid,
    compare_dataframes,
    split_hca_desc,
)
from lib.parsers.smdb import extract_section
from lib.reporting import (
    count_line,
    section as _section,
    text_line,
    write_sheets,
)


# ─── Constants ───────────────────────────────────────────────────────────────

# SMS.State integer → human-readable label.
SM_STATE_MAP = {
    "0": "NotActive",
    "1": "Discovering",
    "2": "Standby",
    "3": "Master",
}


# ─── CLI ─────────────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Parse OpenSM smdb dump for SM / switch / HCA / link inventory."
    )
    p.add_argument(
        "-l", "--opensm-logs", required=True, metavar="FOLDER",
        help="OpenSM logs folder (snapshot X) — must contain opensm-smdb.dump.",
    )
    p.add_argument(
        "-o", "--output", required=True, metavar="FILE",
        help="Output Excel (.xlsx) file path.",
    )
    p.add_argument(
        "--compare-logs", metavar="FOLDER",
        help="OpenSM logs folder (snapshot Y) — must contain opensm-smdb.dump. "
             "Enables comparison mode.",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="Print detailed change lists in comparison mode.",
    )
    return p.parse_args()


def _resolve_smdb(folder: Path, flag: str) -> Path:
    """Validate that `folder` contains opensm-smdb.dump; return the file path."""
    if not folder.is_dir():
        sys.exit(f"Error: {flag} folder not found: {folder}")
    smdb = folder / "opensm-smdb.dump"
    if not smdb.is_file():
        sys.exit(
            f"Error: {flag} folder is missing opensm-smdb.dump: {folder}"
        )
    return smdb


# Local thin wrappers so existing call sites keep their names.
def _section_plain(title: str) -> None:
    _section(title)


def _section_with_total(title: str, total: int) -> None:
    _section(title, total)


def _text_line(label: str, value: str) -> None:
    text_line(label, value)


def _count_line(label: str, count: int) -> None:
    count_line(label, count)


# ─── DataFrame builders ──────────────────────────────────────────────────────


def _normalize_guid_col(s: pd.Series) -> pd.Series:
    """Vectorised GUID normalisation for a column (tolerates NaN)."""
    return s.astype(str).map(lambda g: _normalize_guid(g) if g and g != "nan" else "")


def _port_to_node_map(ports_df: pd.DataFrame) -> dict[str, str]:
    """PortGUID → NodeGUID lookup (both normalised)."""
    if ports_df.empty or "PortGUID" not in ports_df.columns or "NodeGUID" not in ports_df.columns:
        return {}
    pg = _normalize_guid_col(ports_df["PortGUID"])
    ng = _normalize_guid_col(ports_df["NodeGUID"])
    # Keep first occurrence if duplicates exist.
    # Both Series come from the same DataFrame rows. Plain zip retains the
    # intended truncation semantics and also supports workstation Python 3.9.
    return dict(zip(pg, ng))


def build_sm_df(smdb_path: Path) -> pd.DataFrame:
    """§4.1 SM DataFrame — merged SM + SMS on PortGUID, NodeGUID via PORTS."""
    sm = extract_section("SM", smdb_path)
    sms = extract_section("SMS", smdb_path)
    ports = extract_section("PORTS", smdb_path)

    if sms.empty:
        return pd.DataFrame(columns=[
            "HostName", "Node GUID", "LID", "SM version", "Routing Engine",
            "Start Time", "SM Priority", "SM State",
        ])

    sms = sms.copy()
    sms["PortGUID"] = _normalize_guid_col(sms["PortGUID"])

    port_to_node = _port_to_node_map(ports)
    sms["Node GUID"] = sms["PortGUID"].map(port_to_node).fillna(sms["PortGUID"])

    # Left-join SM details on PortGUID (only the local SM has full info).
    sm_info = sm[["PortGUID", "HostName", "Version", "RoutingEngine", "StartTime"]].copy() \
        if not sm.empty else pd.DataFrame(columns=["PortGUID", "HostName", "Version", "RoutingEngine", "StartTime"])
    sm_info["PortGUID"] = _normalize_guid_col(sm_info["PortGUID"])
    sm_info = sm_info.rename(columns={
        "Version": "SM version",
        "RoutingEngine": "Routing Engine",
        "StartTime": "Start Time",
    })

    merged = sms.merge(sm_info, on="PortGUID", how="left")

    # Decode State integer to human-readable label.
    merged["SM State"] = merged["State"].astype(str).str.strip().map(SM_STATE_MAP).fillna(merged["State"])
    merged["SM Priority"] = merged["Priority"]

    return merged[[
        "HostName", "Node GUID", "LID", "SM version", "Routing Engine",
        "Start Time", "SM Priority", "SM State",
    ]].reset_index(drop=True)


def build_sm_ports_df(smdb_path: Path) -> pd.DataFrame:
    """§4.2 SM Ports DataFrame — SM_PORTS joined with PORTS + NODES."""
    sm_ports = extract_section("SM_PORTS", smdb_path)
    if sm_ports.empty:
        return pd.DataFrame(columns=["Node GUID", "Hostname", "Port name", "Status"])

    ports = extract_section("PORTS", smdb_path)
    nodes = extract_section("NODES", smdb_path)

    sm_ports = sm_ports.copy()
    sm_ports["PortGUID"] = _normalize_guid_col(sm_ports["PortGUID"])

    # PortGUID → (NodeGUID, PortNum, PortLabel) via PORTS.
    if not ports.empty:
        p = ports.copy()
        p["PortGUID"] = _normalize_guid_col(p["PortGUID"])
        p["NodeGUID"] = _normalize_guid_col(p["NodeGUID"])
        p = p[["PortGUID", "NodeGUID", "PortNum", "PortLabel"]].drop_duplicates("PortGUID", keep="first")
    else:
        p = pd.DataFrame(columns=["PortGUID", "NodeGUID", "PortNum", "PortLabel"])

    merged = sm_ports.merge(p, on="PortGUID", how="left")

    # NodeGUID → (NodeDesc, NodeType) via NODES.
    if not nodes.empty:
        n = nodes[["NodeGUID", "NodeType", "NodeDesc"]].copy()
        n["NodeGUID"] = _normalize_guid_col(n["NodeGUID"])
        n["NodeType"] = n["NodeType"].astype(str).str.strip()
        n["NodeDesc"] = n["NodeDesc"].astype(str).str.strip().str.strip('"')
    else:
        n = pd.DataFrame(columns=["NodeGUID", "NodeType", "NodeDesc"])

    merged = merged.merge(n, on="NodeGUID", how="left")

    def _name_and_port(row) -> tuple[str, object]:
        desc = str(row.get("NodeDesc", "")).strip()
        nt = str(row.get("NodeType", "")).strip()
        if nt == NODE_TYPE_HCA:
            return split_hca_desc(desc)
        if nt == NODE_TYPE_SWITCH:
            label = str(row.get("PortLabel", "")).strip()
            return desc, (label if label else pd.NA)
        return (desc if desc else ""), pd.NA

    pairs = merged.apply(_name_and_port, axis=1, result_type="expand")
    pairs.columns = ["Hostname", "Port name"]
    merged["Hostname"] = pairs["Hostname"]
    merged["Port name"] = pairs["Port name"]

    # If NodeGUID was unresolved (PortGUID not in PORTS), fall back to PortGUID itself.
    merged["Node GUID"] = merged["NodeGUID"].where(
        merged["NodeGUID"].astype(str).str.len() > 0, merged["PortGUID"]
    )

    return merged[["Node GUID", "Hostname", "Port name", "Status"]].reset_index(drop=True)


def build_switches_df(smdb_path: Path) -> pd.DataFrame:
    """§4.3 IB Switches DataFrame."""
    nodes = extract_section("NODES", smdb_path)
    switches = extract_section("SWITCHES", smdb_path)
    ports = extract_section("PORTS", smdb_path)

    if nodes.empty:
        return pd.DataFrame(columns=["Node GUID", "Switch Name", "Status", "Rank", "LID"])

    nodes = nodes.copy()
    nodes["NodeGUID"] = _normalize_guid_col(nodes["NodeGUID"])
    nodes["NodeType"] = nodes["NodeType"].astype(str).str.strip()
    nodes["NodeDesc"] = nodes["NodeDesc"].astype(str).str.strip().str.strip('"')
    sw = nodes[nodes["NodeType"] == NODE_TYPE_SWITCH][["NodeGUID", "NodeDesc"]].copy()
    sw = sw.rename(columns={"NodeGUID": "Node GUID", "NodeDesc": "Switch Name"})

    if not switches.empty:
        s = switches.copy()
        s["NodeGUID"] = _normalize_guid_col(s["NodeGUID"])
        keep = [c for c in ("NodeGUID", "Status", "Rank") if c in s.columns]
        s = s[keep].drop_duplicates("NodeGUID", keep="first")
        s = s.rename(columns={"NodeGUID": "Node GUID"})
        sw = sw.merge(s, on="Node GUID", how="left")
    else:
        sw["Status"] = pd.NA
        sw["Rank"] = pd.NA

    # Switch LID = PORTS.LID where PortNum == 0 (management port).
    if not ports.empty:
        p = ports.copy()
        p["NodeGUID"] = _normalize_guid_col(p["NodeGUID"])
        p["PortNum"] = p["PortNum"].astype(str).str.strip()
        mgmt = p[p["PortNum"] == "0"][["NodeGUID", "LID"]].drop_duplicates("NodeGUID", keep="first")
        mgmt = mgmt.rename(columns={"NodeGUID": "Node GUID"})
        sw = sw.merge(mgmt, on="Node GUID", how="left")
    else:
        sw["LID"] = pd.NA

    return sw[["Node GUID", "Switch Name", "Status", "Rank", "LID"]].sort_values("Switch Name").reset_index(drop=True)


def build_hcas_df(smdb_path: Path) -> pd.DataFrame:
    """§4.4 IB HCAs DataFrame."""
    nodes = extract_section("NODES", smdb_path)
    ports = extract_section("PORTS", smdb_path)

    if nodes.empty:
        return pd.DataFrame(columns=["Node GUID", "Hostname", "Port name", "LID"])

    n = nodes.copy()
    n["NodeGUID"] = _normalize_guid_col(n["NodeGUID"])
    n["NodeType"] = n["NodeType"].astype(str).str.strip()
    n["NodeDesc"] = n["NodeDesc"].astype(str).str.strip().str.strip('"')
    hca = n[n["NodeType"] == NODE_TYPE_HCA][["NodeGUID", "NodeDesc"]].copy()
    if hca.empty:
        return pd.DataFrame(columns=["Node GUID", "Hostname", "Port name", "LID"])

    pairs = hca["NodeDesc"].map(split_hca_desc)
    hca["Hostname"] = pairs.map(lambda t: t[0])
    hca["Port name"] = pairs.map(lambda t: t[1] if t[1] is not None else pd.NA)
    hca = hca.rename(columns={"NodeGUID": "Node GUID"}).drop(columns=["NodeDesc"])

    # HCA LID = PORTS.LID where PortNum == 1 (first active HCA port).
    if not ports.empty:
        p = ports.copy()
        p["NodeGUID"] = _normalize_guid_col(p["NodeGUID"])
        p["PortNum"] = p["PortNum"].astype(str).str.strip()
        p1 = p[p["PortNum"] == "1"][["NodeGUID", "LID"]].drop_duplicates("NodeGUID", keep="first")
        p1 = p1.rename(columns={"NodeGUID": "Node GUID"})
        hca = hca.merge(p1, on="Node GUID", how="left")
    else:
        hca["LID"] = pd.NA

    return hca[["Node GUID", "Hostname", "Port name", "LID"]].sort_values(
        ["Hostname", "Port name"]
    ).reset_index(drop=True)


def build_links_df(smdb_path: Path) -> pd.DataFrame:
    """§4.5 IB Links DataFrame — undirected, canonical direction applied."""
    links = extract_section("LINKS", smdb_path)
    nodes = extract_section("NODES", smdb_path)
    ports = extract_section("PORTS", smdb_path)

    if links.empty or nodes.empty:
        return pd.DataFrame()

    links = links.copy()
    for col in ("NodeGUID1", "NodeGUID2"):
        links[col] = _normalize_guid_col(links[col])
    for col in ("PortNum1", "PortNum2"):
        links[col] = links[col].astype(str).str.strip()

    # NodeGUID → (NodeDesc, NodeType) for device-name resolution.
    n = nodes.copy()
    n["NodeGUID"] = _normalize_guid_col(n["NodeGUID"])
    n["NodeType"] = n["NodeType"].astype(str).str.strip()
    n["NodeDesc"] = n["NodeDesc"].astype(str).str.strip().str.strip('"')
    node_map = n.drop_duplicates("NodeGUID", keep="first").set_index("NodeGUID")[["NodeType", "NodeDesc"]]

    def _name_for(guid: str) -> str:
        if guid not in node_map.index:
            return guid
        desc = node_map.loc[guid, "NodeDesc"]
        nt = node_map.loc[guid, "NodeType"]
        if nt == NODE_TYPE_HCA:
            return split_hca_desc(desc)[0]
        return desc

    def _type_for(guid: str) -> str:
        return node_map.loc[guid, "NodeType"] if guid in node_map.index else ""

    links["NodeType1"] = links["NodeGUID1"].map(_type_for)
    links["NodeType2"] = links["NodeGUID2"].map(_type_for)
    links["Name1"] = links["NodeGUID1"].map(_name_for)
    links["Name2"] = links["NodeGUID2"].map(_name_for)

    # Join PORTS for per-endpoint attributes.
    if not ports.empty:
        p = ports.copy()
        p["NodeGUID"] = _normalize_guid_col(p["NodeGUID"])
        p["PortNum"] = p["PortNum"].astype(str).str.strip()
        keep = [c for c in ("NodeGUID", "PortNum", "LID", "PortState", "LinkWidth",
                            "LinkSpeed", "Status", "Timestamp") if c in p.columns]
        p = p[keep].drop_duplicates(["NodeGUID", "PortNum"], keep="first")

        for suffix, gcol, pcol in (("1", "NodeGUID1", "PortNum1"),
                                    ("2", "NodeGUID2", "PortNum2")):
            tmp = p.rename(columns={
                "NodeGUID": gcol, "PortNum": pcol,
                "LID": f"LID{suffix}",
                "PortState": f"PortState{suffix}",
                "LinkWidth": f"LinkWidth{suffix}",
                "LinkSpeed": f"LinkSpeed{suffix}",
                "Status": f"Status{suffix}",
                "Timestamp": f"Timestamp{suffix}",
            })
            links = links.merge(tmp, on=[gcol, pcol], how="left")

        # PORTS.LID is per-port for HCAs but per-chassis for switches —
        # switches only carry a real LID on PortNum=0; every other PortNum row
        # reports LID=0. Override switch-endpoint LIDs with the chassis LID
        # before canonical-direction swap so Src/Dst LID end up correct.
        sw_lid_map = (
            p[p["PortNum"] == "0"][["NodeGUID", "LID"]]
            .drop_duplicates("NodeGUID", keep="first")
            .set_index("NodeGUID")["LID"]
        )
        for suffix, gcol, tcol in (("1", "NodeGUID1", "NodeType1"),
                                    ("2", "NodeGUID2", "NodeType2")):
            lcol = f"LID{suffix}"
            if lcol in links.columns:
                is_sw = links[tcol] == NODE_TYPE_SWITCH
                links.loc[is_sw, lcol] = links.loc[is_sw, gcol].map(sw_lid_map)
    else:
        for suffix in ("1", "2"):
            for f in ("LID", "PortState", "LinkWidth", "LinkSpeed", "Status", "Timestamp"):
                links[f"{f}{suffix}"] = pd.NA

    # Undirected dedup via sorted-endpoint link_id (vectorised).
    # NodeGUID*/PortNum* are already stripped strings from the section parser.
    ep1 = links["NodeGUID1"].astype(str) + "|" + links["PortNum1"].astype(str)
    ep2 = links["NodeGUID2"].astype(str) + "|" + links["PortNum2"].astype(str)
    lo = ep1.where(ep1 < ep2, ep2)
    hi = ep2.where(ep1 < ep2, ep1)
    links["_link_id"] = lo + "|" + hi
    links = links.drop_duplicates("_link_id").drop(columns=["_link_id"])

    # Canonical direction (vectorised):
    #   SW-HCA → switch always Src (HCA always Dst).
    #   SW-SW  → alphabetically smaller Name on Src.
    #   Other  → preserve input order.
    t1 = links["NodeType1"].astype(str)
    t2 = links["NodeType2"].astype(str)
    sw_hca = (t1 == NODE_TYPE_HCA) & (t2 == NODE_TYPE_SWITCH)
    sw_sw = (t1 == NODE_TYPE_SWITCH) & (t2 == NODE_TYPE_SWITCH)
    sw_sw_swap = sw_sw & (links["Name1"].astype(str) > links["Name2"].astype(str))
    swap_mask = sw_hca | sw_sw_swap
    if swap_mask.any():
        swap_pairs = [
            ("NodeGUID1", "NodeGUID2"),
            ("PortNum1", "PortNum2"),
            ("Name1", "Name2"),
            ("NodeType1", "NodeType2"),
            ("LID1", "LID2"),
            ("PortState1", "PortState2"),
            ("LinkWidth1", "LinkWidth2"),
            ("LinkSpeed1", "LinkSpeed2"),
            ("Status1", "Status2"),
            ("Timestamp1", "Timestamp2"),
        ]
        old = links.loc[swap_mask].copy()
        for a, b in swap_pairs:
            if a in old.columns and b in old.columns:
                links.loc[swap_mask, a] = old[b].values
                links.loc[swap_mask, b] = old[a].values

    out = pd.DataFrame({
        "Src GUID": links["NodeGUID1"].values,
        "Src Device Name": links["Name1"].values,
        "Src IB port": links["PortNum1"].values,
        "Src LID": links.get("LID1", pd.NA).values if "LID1" in links.columns else pd.NA,
        "Port State": links.get("PortState1", pd.NA).values if "PortState1" in links.columns else pd.NA,
        "Port Status": links.get("Status1", pd.NA).values if "Status1" in links.columns else pd.NA,
        "Link Width": links.get("LinkWidth1", pd.NA).values if "LinkWidth1" in links.columns else pd.NA,
        "Link Speed": links.get("LinkSpeed1", pd.NA).values if "LinkSpeed1" in links.columns else pd.NA,
        "Dst GUID": links["NodeGUID2"].values,
        "Dst Device Name": links["Name2"].values,
        "Dst IB port": links["PortNum2"].values,
        "Dst LID": links.get("LID2", pd.NA).values if "LID2" in links.columns else pd.NA,
        "Last State Change": links.get("Timestamp1", pd.NA).values if "Timestamp1" in links.columns else pd.NA,
    })

    return out.sort_values(["Src Device Name", "Src IB port"]).reset_index(drop=True)


# ─── Single-snapshot CLI output ──────────────────────────────────────────────


def _sm_count_line(label: str, count: int) -> None:
    """SM-section count line: narrow label width + right-aligned count.

    Note: SM-section count rows use the narrow 30-char label (matches text_line),
    not the default 44-char wide label. The shared helper takes the same shape
    but here we keep the column-aligned-to-30 format used in the spec example.
    """
    print(f"    {label:<26}: {count:>7}")


def print_single_snapshot_summary(
    sm: pd.DataFrame,
    sm_ports: pd.DataFrame,
    switches: pd.DataFrame,
    hcas: pd.DataFrame,
    links: pd.DataFrame,
) -> None:
    # ── Subnet Manager section
    _section_plain("Subnet Manager")
    total_sm = len(sm)
    master = sm[sm["SM State"] == "Master"]
    standbys = sm[sm["SM State"] == "Standby"]
    _sm_count_line("SMs Total", total_sm)
    _sm_count_line("Master", len(master))
    _sm_count_line("Standbys", len(standbys))

    if not master.empty:
        m = master.iloc[0]
        routing = str(m.get("Routing Engine", "") or "")
        ver = str(m.get("SM version", "") or "")
        host = str(m.get("HostName", "") or "")
        start = str(m.get("Start Time", "") or "")
        if routing:
            _text_line("Routing Engine", routing)
        if ver:
            _text_line("SM Version", ver)
        if host:
            _text_line("Master HostName", host)
        if start:
            _text_line("Master Start Time", start)

    # ── SM Ports section
    _section_with_total("SM Ports", len(sm_ports))
    valid_count = int((sm_ports["Status"].astype(str).str.strip() == "VALID").sum()) if not sm_ports.empty else 0
    _count_line("VALID", valid_count)
    _count_line("Other", len(sm_ports) - valid_count)

    # ── IB Switches
    _section_with_total("IB Switches", len(switches))
    valid_sw = int((switches["Status"].astype(str).str.strip() == "VALID").sum()) if not switches.empty else 0
    held_sw = int((switches["Status"].astype(str).str.strip() == "HELD_BACK").sum()) if not switches.empty else 0
    _count_line("VALID", valid_sw)
    _count_line("HELD_BACK", held_sw)

    # ── IB HCAs (just the total — no body lines)
    _section_with_total("IB HCAs", len(hcas))

    # ── IB Links
    _section_with_total("IB Links", len(links))
    if not links.empty:
        ps = links["Port State"].astype(str).str.strip()
        act = int((ps == "ACT").sum())
        ini = int((ps == "INI").sum())
        down = int(ps.isin(["DOWN", "DWN"]).sum())
        status = links["Port Status"].astype(str).str.strip()
        ok = int((status == "VALID").sum())
        iso = int((status == "ISOLATED").sum())
    else:
        act = ini = down = ok = iso = 0
    _count_line("ACT", act)
    _count_line("INI", ini)
    _count_line("DOWN", down)
    _count_line("VALID", ok)
    _count_line("ISOLATED", iso)


# ─── Compare-mode CLI output ─────────────────────────────────────────────────


def _diff_counts(diff: pd.DataFrame) -> tuple[int, int, int]:
    """Return (new, disappeared, changed) from a compare_dataframes() output."""
    if diff.empty:
        return 0, 0, 0
    new = int((diff.get("New", pd.Series(dtype=str)).astype(str) == "Yes").sum())
    disp = int((diff.get("Disappeared", pd.Series(dtype=str)).astype(str) == "Yes").sum())
    chg = int((diff.get("Changed", pd.Series(dtype=str)).astype(str) == "Yes").sum())
    return new, disp, chg


def _print_verbose_changes(diff: pd.DataFrame, change_cols: list[str], title: str) -> None:
    """Print per-row New/Disappeared/Changed lists when --verbose."""
    if diff.empty:
        return

    def _mark(col: str) -> pd.Series:
        return diff.get(col, pd.Series(dtype=str)).astype(str) == "Yes"

    new_rows = diff[_mark("New")]
    dis_rows = diff[_mark("Disappeared")]
    chg_rows = diff[_mark("Changed")]

    if len(new_rows) or len(dis_rows) or len(chg_rows):
        print(f"\n  [verbose] {title}")
    if len(new_rows):
        print(f"    New ({len(new_rows)}):")
        for _, r in new_rows.iterrows():
            print(f"      + {_row_summary(r, change_cols)}")
    if len(dis_rows):
        print(f"    Disappeared ({len(dis_rows)}):")
        for _, r in dis_rows.iterrows():
            print(f"      - {_row_summary(r, change_cols)}")
    if len(chg_rows):
        print(f"    Changed ({len(chg_rows)}):")
        for _, r in chg_rows.iterrows():
            fields = []
            for c in change_cols:
                vx = r.get(f"{c}_x", r.get(c, ""))
                vy = r.get(f"{c}_y", r.get(c, ""))
                if str(vx).strip() != str(vy).strip():
                    fields.append(f"{c}: {vx!r} → {vy!r}")
            print(f"      ~ {_row_summary(r, change_cols)} | {', '.join(fields)}")


def _row_summary(row: pd.Series, change_cols: list[str]) -> str:
    """Short identity string for a diff row (first few non-change, non-flag columns)."""
    skip = set(change_cols) | {"New", "Disappeared", "Changed"}
    skip |= {f"{c}_x" for c in change_cols} | {f"{c}_y" for c in change_cols}
    parts = []
    for col in row.index:
        if col in skip:
            continue
        val = row[col]
        if pd.notna(val) and str(val).strip():
            parts.append(f"{col}={val}")
            if len(parts) >= 3:
                break
    return ", ".join(parts)


def print_compare_summary(
    diffs: dict[str, pd.DataFrame],
    totals_x: dict[str, int],
    totals_y: dict[str, int],
    verbose: bool,
    change_cols_map: dict[str, list[str]],
) -> None:
    # ── Subnet Manager
    _section_plain("Subnet Manager")
    new, disp, chg = _diff_counts(diffs["SM"])
    _count_line("Snapshot X", totals_x["SM"])
    _count_line("Snapshot Y", totals_y["SM"])
    _count_line("New SMs", new)
    _count_line("Disappeared SMs", disp)
    _count_line("Changed", chg)
    if verbose:
        _print_verbose_changes(diffs["SM"], change_cols_map["SM"], "Subnet Manager")

    # ── SM Ports
    _section_plain("SM Ports")
    new, disp, chg = _diff_counts(diffs["SM_Ports"])
    _count_line("Snapshot X", totals_x["SM_Ports"])
    _count_line("Snapshot Y", totals_y["SM_Ports"])
    _count_line("New", new)
    _count_line("Disappeared", disp)
    _count_line("Changed", chg)
    if verbose:
        _print_verbose_changes(diffs["SM_Ports"], change_cols_map["SM_Ports"], "SM Ports")

    # ── Switches
    _section_plain("IB Switches")
    new, disp, chg = _diff_counts(diffs["Switches"])
    _count_line("Snapshot X", totals_x["Switches"])
    _count_line("Snapshot Y", totals_y["Switches"])
    _count_line("New switches", new)
    _count_line("Disappeared switches", disp)
    _count_line("Changed", chg)
    if verbose:
        _print_verbose_changes(diffs["Switches"], change_cols_map["Switches"], "IB Switches")

    # ── HCAs
    _section_plain("IB HCAs")
    new, disp, chg = _diff_counts(diffs["HCAs"])
    _count_line("Snapshot X", totals_x["HCAs"])
    _count_line("Snapshot Y", totals_y["HCAs"])
    _count_line("New HCAs", new)
    _count_line("Disappeared HCAs", disp)
    _count_line("Changed", chg)
    if verbose:
        _print_verbose_changes(diffs["HCAs"], change_cols_map["HCAs"], "IB HCAs")

    # ── Links
    _section_plain("IB Links")
    new, disp, chg = _diff_counts(diffs["Links"])
    _count_line("Snapshot X", totals_x["Links"])
    _count_line("Snapshot Y", totals_y["Links"])
    _count_line("New links", new)
    _count_line("Disappeared links", disp)
    _count_line("Changed", chg)
    if verbose:
        _print_verbose_changes(diffs["Links"], change_cols_map["Links"], "IB Links")


# ─── Main ────────────────────────────────────────────────────────────────────


# Diff keys + change cols per DataFrame (see spec §4).
CHANGE_COLS = {
    "SM":        ["HostName", "SM State", "SM Priority", "Routing Engine", "SM version"],
    "SM_Ports":  ["Status"],
    "Switches":  ["Switch Name", "Status", "Rank", "LID"],
    "HCAs":      ["Hostname", "Port name", "LID"],
    "Links":     ["Port State", "Port Status", "Link Width", "Link Speed", "Src LID", "Dst LID"],
}
DIFF_KEYS = {
    "SM":        ["Node GUID"],
    "SM_Ports":  ["Node GUID"],
    "Switches":  ["Node GUID"],
    "HCAs":      ["Node GUID"],
    "Links":     ["Src GUID", "Src IB port", "Dst GUID", "Dst IB port"],
}


def _build_all(smdb_path: Path) -> dict[str, pd.DataFrame]:
    return {
        "SM":       build_sm_df(smdb_path),
        "SM_Ports": build_sm_ports_df(smdb_path),
        "Switches": build_switches_df(smdb_path),
        "HCAs":     build_hcas_df(smdb_path),
        "Links":    build_links_df(smdb_path),
    }


_SHEET_NAMES = ("SM", "SM_Ports", "Switches", "HCAs", "Links")


def _write_single_workbook(output: Path, frames: dict[str, pd.DataFrame]) -> None:
    wb = xlsxwriter.Workbook(str(output))
    try:
        write_sheets(wb, [
            (sheet, frames.get(sheet, pd.DataFrame()), True) for sheet in _SHEET_NAMES
        ])
    finally:
        wb.close()


def _write_compare_workbook(
    output: Path,
    frames_x: dict[str, pd.DataFrame],
    frames_y: dict[str, pd.DataFrame],
    diffs: dict[str, pd.DataFrame],
) -> None:
    wb = xlsxwriter.Workbook(str(output))
    try:
        specs = []
        for sheet in _SHEET_NAMES:
            specs.append((f"{sheet}_X",    frames_x.get(sheet, pd.DataFrame()), True))
            specs.append((f"{sheet}_Y",    frames_y.get(sheet, pd.DataFrame()), True))
            specs.append((f"{sheet}_Diff", diffs.get(sheet, pd.DataFrame()),    True))
        write_sheets(wb, specs)
    finally:
        wb.close()


def main() -> int:
    args = parse_args()
    smdb_x = _resolve_smdb(Path(args.opensm_logs), "-l/--opensm-logs")

    out = Path(args.output)

    frames_x = _build_all(smdb_x)

    if args.compare_logs:
        smdb_y = _resolve_smdb(Path(args.compare_logs), "--compare-logs")

        frames_y = _build_all(smdb_y)

        diffs = {
            sheet: compare_dataframes(
                frames_x[sheet], frames_y[sheet],
                merge_keys=DIFF_KEYS[sheet],
                change_cols=CHANGE_COLS[sheet],
            )
            for sheet in ("SM", "SM_Ports", "Switches", "HCAs", "Links")
        }

        totals_x = {k: len(v) for k, v in frames_x.items()}
        totals_y = {k: len(v) for k, v in frames_y.items()}

        print_compare_summary(diffs, totals_x, totals_y, args.verbose, CHANGE_COLS)
        _write_compare_workbook(out, frames_x, frames_y, diffs)
    else:
        print_single_snapshot_summary(
            frames_x["SM"], frames_x["SM_Ports"], frames_x["Switches"],
            frames_x["HCAs"], frames_x["Links"],
        )
        _write_single_workbook(out, frames_x)

    print(f"\nExcel report written: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
