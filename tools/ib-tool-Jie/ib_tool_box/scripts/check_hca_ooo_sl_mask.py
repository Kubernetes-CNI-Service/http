#!/usr/bin/env python3
"""
check_hca_ooo_sl_mask.py — Audit IB ports for OOOSLMask / AdaptiveTimeoutSLMask.

Single-snapshot only. Extracts every (NodeGuid, PortNum) row from
EXTENDED_PORT_INFO in ibdiagnet2.db_csv, joins with NODES / NODES_INFO for
hostname / port name / firmware context, and writes a CLI summary plus an
Excel report. Ports whose mask is not the expected `0xffff` are flagged for
human review (firmware drift, EDR/older HCAs that don't support the field,
or nodes still in preboot).

Usage:
    python scripts/check_hca_ooo_sl_mask.py -i <ibdiagnet_folder> -o <output.xlsx>

See specification.MD §7 for the full spec.
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
    SHARP_AN,
    _nodes_info_fw,
    _normalize_guid,
    split_hca_desc,
)
from lib.parsers.db_csv import extract_section
from lib.parsers.net_dump import parse_guid_lid_map
from lib.reporting import count_line, section as _section


MASK_COLS = ["OOOSLMask", "AdaptiveTimeoutSLMask"]


# ─── CLI ─────────────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Audit IB port OOOSLMask / AdaptiveTimeoutSLMask values."
    )
    p.add_argument(
        "-i", "--ibdiagnet", required=True, metavar="FOLDER",
        help="Path to ibdiagnet2 dump folder.",
    )
    p.add_argument(
        "-o", "--output", required=True, metavar="FILE",
        help="Output Excel (.xlsx) file path.",
    )
    return p.parse_args()


# ─── DataFrame builder ───────────────────────────────────────────────────────


def build_sl_mask_df(ibdir: Path) -> pd.DataFrame:
    """Build the per-HCA SL-Mask DataFrame from an ibdiagnet2 folder.

    One row per HCA `Node GUID` — for XDR fabrics each HCA appears as 4
    EXTENDED_PORT_INFO rows (one per plane-port) sharing the same NodeGUID and
    the same mask values; rows are deduplicated by `Node GUID` keeping the
    lowest `PortNum` reading. Switches and routers are excluded entirely.
    """
    db = ibdir / "ibdiagnet2.db_csv"
    ext = extract_section("EXTENDED_PORT_INFO", db)
    if ext.empty:
        return pd.DataFrame()

    keep = ["NodeGuid", "PortNum"] + MASK_COLS
    missing = [c for c in keep if c not in ext.columns]
    if missing:
        sys.exit(f"ERROR: EXTENDED_PORT_INFO is missing columns: {missing}")
    ext = ext[keep].copy()
    ext["Node GUID"] = ext["NodeGuid"].map(_normalize_guid)
    ext["PortNum"] = pd.to_numeric(ext["PortNum"], errors="coerce").astype("Int64")
    ext = ext.drop(columns=["NodeGuid"])

    nodes_fw = _nodes_info_fw(ibdir)
    if nodes_fw.empty:
        return pd.DataFrame()
    # HCAs only — drop Switches, Routers, and SHARP Aggregation Nodes
    # (NodeType=1 but always report 0x0000; same filter as build_hca_inventory).
    nodes_fw = nodes_fw[nodes_fw["NodeType"] == NODE_TYPE_HCA].copy()
    nodes_fw = nodes_fw[~nodes_fw["NodeDesc"].str.contains(SHARP_AN, na=False, regex=False)]
    nodes_fw["Node GUID"] = nodes_fw["NodeGUID"].map(_normalize_guid)

    split = nodes_fw["NodeDesc"].map(split_hca_desc)
    nodes_fw["Hostname"] = split.map(lambda t: t[0])
    nodes_fw["Port Name"] = split.map(lambda t: t[1] if t[1] is not None else "")

    lid_map = parse_guid_lid_map(ibdir / "ibdiagnet2.net_dump") or {}

    df = ext.merge(
        nodes_fw[["Node GUID", "Hostname", "Port Name", "Firmware Version"]],
        on="Node GUID", how="inner",
    )
    df["LID"] = df["Node GUID"].map(lambda g: lid_map.get(g, ""))
    df["Firmware Version"] = df["Firmware Version"].fillna("N/A")

    # XDR: 4 plane-ports per HCA NodeGUID share the same mask values; collapse
    # to one row per HCA. NDR is unaffected (already one PortNum per NodeGUID).
    df = (
        df.sort_values(["Node GUID", "PortNum"])
        .drop_duplicates(subset=["Node GUID"], keep="first")
        .drop(columns=["PortNum"])
    )

    df = df[[
        "Node GUID", "Hostname", "Port Name", "LID", "Firmware Version",
        "OOOSLMask", "AdaptiveTimeoutSLMask",
    ]]
    return df.sort_values(["Hostname", "Port Name", "Node GUID"]).reset_index(drop=True)


# ─── CLI summary ─────────────────────────────────────────────────────────────


def print_summary(df: pd.DataFrame) -> None:
    _section("IB HCA OOO / Adaptive-Timeout SL Mask")
    if df.empty:
        print("    (no EXTENDED_PORT_INFO rows for HCAs found)")
        return

    count_line("HCAs", len(df))
    for mask_col in MASK_COLS:
        print(f"\n  {mask_col} value counts:")
        counts = df[mask_col].fillna("N/A").value_counts().sort_values(ascending=False)
        for value, qty in counts.items():
            count_line(str(value), int(qty))


# ─── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    args = parse_args()

    ibdir = Path(args.ibdiagnet)
    if not ibdir.is_dir():
        sys.exit(f"ERROR: ibdiagnet folder not found: {ibdir}")

    print(f"Loading ibdiagnet snapshot: {ibdir} ...")
    df = build_sl_mask_df(ibdir)

    print_summary(df)

    output = Path(args.output)
    wb = xlsxwriter.Workbook(str(output))
    if df.empty:
        # Still emit an empty sheet so the run produces a valid file.
        wb.add_worksheet("HCA_SL_Mask")
    else:
        from lib.excel import write_dataframe
        write_dataframe(wb, "HCA_SL_Mask", df)
    wb.close()
    print(f"\nExcel report written: {output}")


if __name__ == "__main__":
    main()
