#!/usr/bin/env python3
"""
validate_ib_topology.py — Compare actual IB fabric links against a designed P2P cabling plan.

Usage:
    python scripts/validate_ib_topology.py -i <ibdiagnet_folder> -p <P2P.xlsx> -o <output.xlsx>
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.parsers.net_dump import parse_links
from lib.parsers.db_csv import is_xdr
from lib.inventory import (
    build_node_type_map, _normalize_guid,
    _parse_switch_name_asic, _hca_port_name, NODE_TYPE_SWITCH,
)
from lib.reporting import (
    count_line as _summary_line,
    section as _section_full,
    write_sheets,
)


# ─── CLI ─────────────────────────────────────────────────────────────────────


def _section(title: str) -> None:
    """Plain-divider section header (no Total)."""
    _section_full(title)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Compare IB fabric links against P2P cabling plan"
    )
    p.add_argument("-i", "--ibdiagnet", required=True, metavar="FOLDER",
                   help="Path to ibdiagnet2 dump folder")
    p.add_argument("-p", "--p2p", required=True, metavar="FILE",
                   help="Path to P2P Excel (.xlsx) file")
    p.add_argument("-o", "--output", required=True, metavar="FILE",
                   help="Output Excel (.xlsx) file path")
    return p.parse_args()


# ─── Step 1: Parse ibdiagnet links ──────────────────────────────────────────


def build_ibdiagnet_links(ibdiagnet_dir: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Parse net_dump into bidirectional link table for topology validation.

    Keeps BOTH directions for SW-SW links (no undirected dedup).
    XDR: merges 4 planes into one logical link per (hostname, phys_port).
    Plane Faulty links (any plane DOWN) are separated and returned as second DataFrame.

    Returns: (valid_links, plane_faulty_links)
    """
    links = parse_links(ibdiagnet_dir / "ibdiagnet2.net_dump")
    if links.empty:
        return pd.DataFrame(), pd.DataFrame()

    ntmap = build_node_type_map(ibdiagnet_dir)
    xdr = is_xdr(ibdiagnet_dir)

    # Classify neighbors
    links["_nbr_is_sw"] = links["neighbor_guid"].map(
        lambda g: ntmap.get(_normalize_guid(g), "") == NODE_TYPE_SWITCH
    )

    # Filter FNMA* (intra-switch ASIC links) but keep FNM1 (external UFM connection).
    # Drop BOTH "Mellanox Technologies Aggregation Node" rows AND other rows whose
    # neighbor desc merely contains "Mellanox Technologies" (e.g. factory-default
    # "MT4131 ConnectX8   Mellanox Technologies" HCAs) — these have no Legend
    # mapping and would produce false Undefined/Miswired results.
    links = links[~links["phys_port"].str.upper().str.startswith("FNMA")].copy()
    links = links[~links["neighbor_desc"].str.contains("Mellanox Technologies", na=False)].copy()

    plane_faulty_df = pd.DataFrame()

    # XDR: propagate neighbor info from best non-DOWN plane, then merge planes
    if xdr:
        # Remove all-planes-DOWN logical links
        all_down = (
            links.groupby(["hostname", "phys_port"])["sta"]
            .transform(lambda s: (s == "DOWN").all())
        )
        links = links[~all_down].copy()

        # Detect Plane Faulty: any plane DOWN in a logical link
        has_down = (
            links.groupby(["hostname", "phys_port"])["sta"]
            .transform(lambda s: (s == "DOWN").any())
        )
        faulty_links = links[has_down].copy()
        valid_links = links[~has_down].copy()

        # Propagate and merge for valid links (all planes ACT/INI)
        if not valid_links.empty:
            _sta_ord = {"ACT": 0, "ARM": 1, "INI": 2, "DOWN": 3}
            valid_links["_sta_ord"] = valid_links["sta"].map(lambda s: _sta_ord.get(s, 99))
            best = (
                valid_links.sort_values(["hostname", "phys_port", "_sta_ord", "plane"])
                .drop_duplicates(subset=["hostname", "phys_port"], keep="first")
            )
            valid_links = best.drop(columns=["_sta_ord"])

        # Build Plane Faulty output (propagate for display, merge to logical link)
        if not faulty_links.empty:
            _sta_ord = {"ACT": 0, "ARM": 1, "INI": 2, "DOWN": 3}
            faulty_links["_sta_ord"] = faulty_links["sta"].map(lambda s: _sta_ord.get(s, 99))
            best_f = (
                faulty_links.sort_values(["hostname", "phys_port", "_sta_ord", "plane"])
                .drop_duplicates(subset=["hostname", "phys_port"], keep="first")
            )
            faulty_links = best_f.drop(columns=["_sta_ord"])

        links = valid_links
    else:
        # NDR: remove DOWN links
        links = links[links["sta"] != "DOWN"].copy()

    if links.empty and faulty_links.empty if xdr else links.empty:
        return pd.DataFrame(), pd.DataFrame()

    # Helper functions for building output
    def _dst_port(row):
        if row["_nbr_is_sw"]:
            return str(row.get("neighbor_phys_port", ""))
        desc = str(row.get("neighbor_desc", ""))
        return _hca_port_name(desc) if desc else ""

    def _dst_device(row):
        desc = str(row.get("neighbor_desc", "")).strip()
        if not desc:
            return ""
        if row["_nbr_is_sw"]:
            return _parse_switch_name_asic(desc)[0]
        parts = desc.rsplit(" ", 1)
        return parts[0] if len(parts) > 1 else desc

    def _build_output(df):
        if df.empty:
            return pd.DataFrame()
        result = pd.DataFrame({
            "SrcDevice": df["hostname"].values,
            "SrcPort": df["phys_port"].values,
            "DstDevice": df.apply(_dst_device, axis=1).values,
            "DstPort": df.apply(_dst_port, axis=1).values,
            "_dst_is_sw": df["_nbr_is_sw"].values,
        })
        result = result[result["DstDevice"].ne("") & result["DstPort"].ne("")].copy()
        return result.sort_values(["SrcDevice", "SrcPort"]).reset_index(drop=True)

    valid_result = _build_output(links)

    if xdr and not faulty_links.empty:
        plane_faulty_df = _build_output(faulty_links)

    return valid_result, plane_faulty_df


# ─── Step 2: Parse P2P cabling plan ─────────────────────────────────────────


def parse_p2p(p2p_path: Path) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Parse P2P Excel file.

    Returns: (p2p_links, incomplete_rows, duplicate_rows, mapping_failed_rows)
    """
    sheets = pd.read_excel(p2p_path, sheet_name=None, engine="openpyxl", dtype=str)

    # Load Legend
    if "Legend" not in sheets:
        sys.exit("ERROR: 'Legend' worksheet not found in P2P file")
    legend = sheets["Legend"]
    legend.columns = legend.columns.str.strip()
    legend = legend.apply(lambda x: x.str.strip() if x.dtype == "object" else x)

    # Load Port_Mapping
    if "Port_Mapping" not in sheets:
        sys.exit("ERROR: 'Port_Mapping' worksheet not found in P2P file")
    pm = sheets["Port_Mapping"]
    pm.columns = pm.columns.str.strip()
    pm = pm.apply(lambda x: x.str.strip() if x.dtype == "object" else x)
    # Build {(model, alias): physical_port}
    port_map: dict[tuple[str, str], str] = {}
    for _, r in pm.iterrows():
        model = str(r.get("Model", "")).strip()
        alias = str(r.get("Aias", "")).strip()
        port = str(r.get("Port", "")).strip()
        if model and alias and port:
            port_map[(model, alias)] = port

    # Build Legend regex → (model, type) mapping
    legend_rules: list[tuple[re.Pattern, str, str]] = []
    for _, r in legend.iterrows():
        name_pat = str(r.get("Name", "")).strip()
        model = str(r.get("Model", "")).strip()
        dev_type = str(r.get("Type", "")).strip().lower()
        if name_pat and model:
            legend_rules.append((re.compile(name_pat, re.IGNORECASE), model, dev_type))

    # Load P2P data sheets (skip Legend, Port_Mapping).
    skip = {"Legend", "Port_Mapping"}
    required_cols = ["SrcDevice", "SrcPort", "DstDevice", "DstPort"]
    frames = []
    for name, df in sheets.items():
        if name in skip:
            continue
        df.columns = df.columns.str.strip()
        if set(required_cols).issubset(set(df.columns)):
            frames.append(df[required_cols].copy())

    if not frames:
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), pd.DataFrame()

    p2p = pd.concat(frames, ignore_index=True)
    p2p = p2p.apply(lambda x: x.str.strip() if x.dtype == "object" else x)

    # Remove all-blank rows
    p2p.dropna(how="all", inplace=True)

    # Separate incomplete rows (any missing field)
    incomplete = p2p[p2p.isna().any(axis=1)].copy()
    p2p = p2p.dropna().copy()

    # Remove duplicates
    dup_mask = p2p.duplicated(subset=["SrcDevice", "SrcPort", "DstDevice", "DstPort"], keep="first")
    duplicates = p2p[dup_mask].copy()
    p2p = p2p[~dup_mask].copy()

    # Classify devices via Legend regex
    def _classify(device: str) -> tuple[str, str]:
        for pat, model, dev_type in legend_rules:
            if pat.search(device):
                return model, dev_type
        return "", ""

    p2p["SrcModel"], p2p["SrcType"] = zip(*p2p["SrcDevice"].map(_classify))
    p2p["DstModel"], p2p["DstType"] = zip(*p2p["DstDevice"].map(_classify))

    # Swap if HCA is on Src side (switch should be Src for SW-HCA)
    needs_swap = (p2p["SrcType"] != "switch") & (p2p["DstType"] == "switch")
    if needs_swap.any():
        old = p2p.loc[needs_swap].copy()
        p2p.loc[needs_swap, "SrcDevice"] = old["DstDevice"].values
        p2p.loc[needs_swap, "SrcPort"] = old["DstPort"].values
        p2p.loc[needs_swap, "SrcModel"] = old["DstModel"].values
        p2p.loc[needs_swap, "SrcType"] = old["DstType"].values
        p2p.loc[needs_swap, "DstDevice"] = old["SrcDevice"].values
        p2p.loc[needs_swap, "DstPort"] = old["SrcPort"].values
        p2p.loc[needs_swap, "DstModel"] = old["SrcModel"].values
        p2p.loc[needs_swap, "DstType"] = old["SrcType"].values

    # Keep alias columns before translation
    p2p["SrcPort_Alias"] = p2p["SrcPort"]
    p2p["DstPort_Alias"] = p2p["DstPort"]

    # Translate ports via Port_Mapping
    def _translate(model: str, alias: str) -> str:
        return port_map.get((model, alias), "")

    # Vectorised dict lookup — much faster than apply(axis=1) on large P2P tables.
    p2p["SrcPort_Phys"] = [
        port_map.get(k, "") for k in zip(p2p["SrcModel"], p2p["SrcPort"])
    ]
    p2p["DstPort_Phys"] = [
        port_map.get(k, "") for k in zip(p2p["DstModel"], p2p["DstPort"])
    ]

    # Separate rows where mapping failed
    mapping_failed = p2p[(p2p["SrcPort_Phys"] == "") | (p2p["DstPort_Phys"] == "")].copy()
    p2p = p2p[(p2p["SrcPort_Phys"] != "") & (p2p["DstPort_Phys"] != "")].copy()

    # Build final output with physical ports.
    # SrcType / DstType are kept on the result DataFrame for downstream
    # SW-HCA / SW-SW classification (CLI summary). They are dropped before
    # Excel export — same pattern as `_dst_is_sw` on the ibdiagnet table.
    result = pd.DataFrame({
        "SrcDevice": p2p["SrcDevice"].values,
        "SrcPort_Alias": p2p["SrcPort_Alias"].values,
        "SrcPort": p2p["SrcPort_Phys"].values,
        "DstDevice": p2p["DstDevice"].values,
        "DstPort_Alias": p2p["DstPort_Alias"].values,
        "DstPort": p2p["DstPort_Phys"].values,
        "SrcType": p2p["SrcType"].values,
        "DstType": p2p["DstType"].values,
    })

    result = result.sort_values(["SrcDevice", "SrcPort"]).reset_index(drop=True)

    return result, incomplete, duplicates, mapping_failed


# ─── Step 3: Compare ────────────────────────────────────────────────────────


def compare_links(
    ibdgnt: pd.DataFrame,
    p2p: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Compare ibdiagnet (bidirectional) vs P2P links.

    Returns: (matching, missing, undefined, miswired)
    """
    if ibdgnt.empty or p2p.empty:
        return pd.DataFrame(), p2p.copy(), ibdgnt.copy(), pd.DataFrame()

    # Drop internal columns before merge
    ibdgnt_clean = ibdgnt.drop(columns=["_dst_is_sw"], errors="ignore")

    merged = p2p.merge(
        ibdgnt_clean.rename(columns={
            "DstDevice": "Actual_DstDevice",
            "DstPort": "Actual_DstPort",
        }),
        on=["SrcDevice", "SrcPort"],
        how="outer",
        indicator=True,
    )

    # Matching: P2P dst == ibdiagnet dst
    match_mask = (
        (merged["_merge"] == "both")
        & (merged["DstDevice"] == merged["Actual_DstDevice"])
        & (merged["DstPort"] == merged["Actual_DstPort"])
    )
    matching = merged[match_mask].drop(columns=["Actual_DstDevice", "Actual_DstPort", "_merge"])

    # Miswired: both present but dst differs
    miswired_mask = (
        (merged["_merge"] == "both")
        & ~match_mask
    )
    miswired = merged[miswired_mask].drop(columns=["_merge"]).rename(columns={
        "DstDevice": "Expected_DstDevice",
        "DstPort_Alias": "Expected_DstPort_Alias",
        "DstPort": "Expected_DstPort",
    })

    # Missing: in P2P but not in ibdiagnet
    missing_mask = merged["_merge"] == "left_only"
    missing = merged[missing_mask].drop(columns=["Actual_DstDevice", "Actual_DstPort", "_merge"]).rename(columns={
        "DstDevice": "Expected_DstDevice",
        "DstPort_Alias": "Expected_DstPort_Alias",
        "DstPort": "Expected_DstPort",
    })

    # Undefined: in ibdiagnet but not in P2P
    undefined_mask = merged["_merge"] == "right_only"
    undefined = merged[undefined_mask][["SrcDevice", "SrcPort", "Actual_DstDevice", "Actual_DstPort"]].rename(
        columns={"Actual_DstDevice": "DstDevice", "Actual_DstPort": "DstPort"}
    )

    # Post-merge cleanup: remove reverse of Matching SW-SW links from Undefined
    if not matching.empty and not undefined.empty:
        # Build reverse keys of matching SW-SW links (where DstDevice looks like a switch)
        sw_matches = matching[matching["DstPort_Alias"].isna() | (matching.get("DstPort_Alias", "") == "")].copy()
        if sw_matches.empty:
            # Heuristic: if no alias info, check all matching links
            sw_matches = matching

        reverse_keys = set()
        for _, r in matching.iterrows():
            reverse_keys.add((r["DstDevice"], r["DstPort"], r["SrcDevice"], r["SrcPort"]))

        reverse_mask = undefined.apply(
            lambda r: (r["SrcDevice"], r["SrcPort"], r["DstDevice"], r["DstPort"]) in reverse_keys,
            axis=1,
        )
        undefined = undefined[~reverse_mask].copy()

    return (
        matching.reset_index(drop=True),
        missing.reset_index(drop=True),
        undefined.reset_index(drop=True),
        miswired.reset_index(drop=True),
    )


# ─── Main ────────────────────────────────────────────────────────────────────


def main() -> None:
    args = parse_args()

    ibdir = Path(args.ibdiagnet)
    if not ibdir.is_dir():
        sys.exit(f"ERROR: ibdiagnet folder not found: {ibdir}")

    p2p_path = Path(args.p2p)
    if not p2p_path.is_file():
        sys.exit(f"ERROR: P2P file not found: {p2p_path}")

    output = Path(args.output)

    # Step 1: ibdiagnet links
    print(f"Loading ibdiagnet data: {ibdir} ...")
    ibdgnt, plane_faulty = build_ibdiagnet_links(ibdir)
    ntmap = build_node_type_map(ibdir)

    if not ibdgnt.empty and "_dst_is_sw" in ibdgnt.columns:
        sw_hca = int((~ibdgnt["_dst_is_sw"]).sum())
        sw_sw_bi = int(ibdgnt["_dst_is_sw"].sum())
    else:
        sw_hca = len(ibdgnt)
        sw_sw_bi = 0
    sw_sw = sw_sw_bi // 2  # bidirectional, divide by 2

    _section("ibdiagnet Links")
    _summary_line("Total", sw_hca + sw_sw)
    _summary_line("SW-HCA", sw_hca)
    _summary_line("SW-SW", sw_sw)
    if not plane_faulty.empty:
        _summary_line("Plane Faulty (excluded)", len(plane_faulty))

    # Step 2: P2P links
    print(f"\nLoading P2P: {p2p_path} ...")
    p2p, incomplete, duplicates, mapping_failed = parse_p2p(p2p_path)

    # Classify P2P links via SrcType / DstType (added by parse_p2p after
    # canonical-direction swap, so switch is always Src for SW-HCA links).
    if not p2p.empty and "SrcType" in p2p.columns and "DstType" in p2p.columns:
        p2p_sw_hca = int(((p2p["SrcType"] == "switch") & (p2p["DstType"] == "hca")).sum())
        p2p_sw_sw = int(((p2p["SrcType"] == "switch") & (p2p["DstType"] == "switch")).sum())
    else:
        p2p_sw_hca = p2p_sw_sw = 0
    p2p_total = len(p2p)

    _section("P2P Defined Links")
    _summary_line("Total", p2p_total)
    _summary_line("SW-HCA", p2p_sw_hca)
    _summary_line("SW-SW", p2p_sw_sw)
    _summary_line("Incomplete (missing fields)", len(incomplete))
    _summary_line("Duplicates removed", len(duplicates))
    _summary_line("Port mapping failed", len(mapping_failed))

    # Step 3: Compare
    if not p2p.empty and not ibdgnt.empty:
        matching, missing, undefined, miswired = compare_links(ibdgnt, p2p)
    else:
        matching = missing = undefined = miswired = pd.DataFrame()

    _section("Validation Results")
    _summary_line("Matching", len(matching))
    _summary_line("Missing (in P2P, not in ibdiagnet)", len(missing))
    _summary_line("Undefined (in ibdiagnet, not in P2P)", len(undefined))
    _summary_line("Miswired (wrong destination)", len(miswired))

    # Step 4: Excel output
    wb = __import__("xlsxwriter").Workbook(str(output))

    # Drop internal columns before Excel export.
    # _dst_is_sw is on the ibdiagnet side; SrcType / DstType ride on p2p-derived
    # frames (matching / missing / miswired inherit them from the merge with p2p).
    def _strip(df: pd.DataFrame) -> pd.DataFrame:
        return df.drop(columns=["_dst_is_sw", "SrcType", "DstType"], errors="ignore")

    write_sheets(wb, [
        ("IBDGNT_Link_Table",  _strip(ibdgnt),         False),
        ("Plane_Faulty_Links", _strip(plane_faulty),   False),
        ("P2P_Link_Table",     _strip(p2p),            False),
        ("P2P_Incomplete",     _strip(incomplete),     False),
        ("P2P_Duplicates",     _strip(duplicates),     False),
        ("P2P_Mapping_Failed", _strip(mapping_failed), False),
        ("Matching_Links",     _strip(matching),       False),
        ("Missing_Links",      _strip(missing),        False),
        ("Undefined_Links",    undefined,              False),
        ("Miswired_Links",     _strip(miswired),       False),
    ])

    wb.close()
    print(f"\nExcel report written: {output}")


if __name__ == "__main__":
    main()
