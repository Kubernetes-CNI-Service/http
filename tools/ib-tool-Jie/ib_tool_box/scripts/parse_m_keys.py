#!/usr/bin/env python3
"""
parse_m_keys.py — Per-port M_Key inventory from OpenSM config snapshots.

Reads `guid2mkey` + `guid2lid` from the OpenSM config folder and
`opensm-smdb.dump` from the OpenSM logs folder, builds a per-port M_Key
inventory, and (in comparison mode) surfaces nodes whose M_Key is new,
disappeared, or changed between two snapshots.

Single-snapshot mode:
    python scripts/parse_m_keys.py \
        -c <opensm_config_folder> -l <opensm_logs_folder> \
        -o <output.xlsx>

Two-snapshot comparison mode:
    python scripts/parse_m_keys.py \
        -c snap_X/ufm_conf/conf/opensm -l snap_X/ufm_logs \
        --compare-config snap_Y/ufm_conf/conf/opensm \
        --compare-logs   snap_Y/ufm_logs \
        -o <output.xlsx> [--verbose]

See specification.MD §8 for the full spec.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd
import xlsxwriter

# Allow running from repo root without installation.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.excel import write_dataframe
from lib.inventory import (
    NODE_TYPE_HCA,
    NODE_TYPE_ROUTER,
    NODE_TYPE_SWITCH,
    SHARP_AN,
    _normalize_guid,
    compare_dataframes,
    split_hca_desc,
)
from lib.parsers.smdb import extract_section
from lib.reporting import count_line, section as _section


NODE_TYPE_LABEL = {
    NODE_TYPE_HCA: "HCA",
    NODE_TYPE_SWITCH: "Switch",
    NODE_TYPE_ROUTER: "Router",
}


# ─── CLI ─────────────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Build per-port M_Key inventory from an OpenSM config snapshot.",
    )
    p.add_argument(
        "-c", "--opensm-config", required=True, metavar="FOLDER",
        help="OpenSM config folder (snapshot X) — must contain guid2mkey and guid2lid.",
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
        "--compare-config", metavar="FOLDER",
        help="OpenSM config folder (snapshot Y) — enables comparison mode.",
    )
    p.add_argument(
        "--compare-logs", metavar="FOLDER",
        help="OpenSM logs folder (snapshot Y) — required when --compare-config is set; "
             "no implicit fallback to -l.",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="Print detailed change lists in comparison mode.",
    )
    return p.parse_args()


# ─── Loaders ─────────────────────────────────────────────────────────────────


def _check_config_files(folder: Path, flag: str) -> tuple[Path, Path]:
    """Validate the OpenSM config folder contains guid2mkey and guid2lid."""
    if not folder.is_dir():
        sys.exit(f"ERROR: {flag} folder not found: {folder}")
    g2m = folder / "guid2mkey"
    g2l = folder / "guid2lid"
    missing = [p for p in (g2m, g2l) if not p.is_file()]
    if missing:
        names = ", ".join(p.name for p in missing)
        sys.exit(f"ERROR: {flag} folder is missing {names}: {folder}")
    return g2m, g2l


def _check_logs_smdb(folder: Path, flag: str) -> Path:
    """Validate the OpenSM logs folder contains opensm-smdb.dump."""
    if not folder.is_dir():
        sys.exit(f"ERROR: {flag} folder not found: {folder}")
    smdb = folder / "opensm-smdb.dump"
    if not smdb.is_file():
        sys.exit(f"ERROR: {flag} folder is missing opensm-smdb.dump: {folder}")
    return smdb


def _load_guid2mkey(path: Path) -> pd.DataFrame:
    """Read `guid2mkey` (`<NodeGUID> <M_Key>` per line)."""
    rows: list[dict[str, str]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) < 2:
                continue
            rows.append({
                "Node GUID": _normalize_guid(parts[0]),
                "M_Key": parts[1].strip().lower(),
            })
    return pd.DataFrame(rows)


def _load_guid2lid(path: Path) -> dict[str, int]:
    """Read `guid2lid` and return {Node GUID → LID (decimal int)}.

    Format: `<NodeGUID_hex> <LID_hex> <LID_hex>`. The second LID column is a
    duplicate (used when LMC > 0) — only the first is kept.
    """
    out: dict[str, int] = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) < 2:
                continue
            guid = _normalize_guid(parts[0])
            try:
                out[guid] = int(parts[1], 16)
            except ValueError:
                continue
    return out


def _load_smdb_nodes(smdb_path: Path) -> pd.DataFrame:
    """Read NODES from opensm-smdb.dump, return DataFrame with Hostname / Port name / Node Type.

    All `NodeType` values (HCA, Switch, Router) are kept. SHARP Aggregation
    Nodes are dropped (same filter as `build_hca_inventory`).
    """
    nodes = extract_section("NODES", smdb_path)
    if nodes.empty:
        return pd.DataFrame(columns=["Node GUID", "Hostname", "Port name", "Node Type"])

    nodes = nodes.copy()
    nodes["NodeType"] = nodes["NodeType"].astype(str).str.strip()
    nodes["NodeDesc"] = nodes["NodeDesc"].astype(str).str.strip().str.strip('"')
    nodes["Node GUID"] = nodes["NodeGUID"].astype(str).map(_normalize_guid)

    # Drop SHARP Aggregation Nodes — pseudo-nodes that aren't real ports.
    nodes = nodes[~nodes["NodeDesc"].str.contains(SHARP_AN, na=False, regex=False)]

    def _hostname_port(row: pd.Series) -> pd.Series:
        nt = row["NodeType"]
        desc = row["NodeDesc"]
        if nt == NODE_TYPE_HCA:
            host, port = split_hca_desc(desc)
            return pd.Series({"Hostname": host, "Port name": port if port is not None else ""})
        return pd.Series({"Hostname": desc, "Port name": ""})

    pairs = nodes.apply(_hostname_port, axis=1)
    nodes["Hostname"] = pairs["Hostname"]
    nodes["Port name"] = pairs["Port name"]
    nodes["Node Type"] = nodes["NodeType"].map(NODE_TYPE_LABEL).fillna("")

    nodes = nodes[nodes["Node Type"].isin(NODE_TYPE_LABEL.values())]
    return nodes[["Node GUID", "Hostname", "Port name", "Node Type"]].drop_duplicates(
        subset=["Node GUID"], keep="first",
    ).reset_index(drop=True)


# ─── DataFrame builder ───────────────────────────────────────────────────────


def build_m_keys_df(
    config_folder: Path, logs_folder: Path,
    config_flag: str = "-c/--opensm-config",
    logs_flag: str = "-l/--opensm-logs",
) -> pd.DataFrame:
    """Build the per-port M_Key DataFrame from a (config, logs) folder pair."""
    g2m_path, g2l_path = _check_config_files(config_folder, config_flag)
    smdb_path = _check_logs_smdb(logs_folder, logs_flag)

    mk = _load_guid2mkey(g2m_path)
    if mk.empty:
        return pd.DataFrame(
            columns=["Node GUID", "Hostname", "Port name", "Node Type", "LID", "M_Key"],
        )

    nodes = _load_smdb_nodes(smdb_path)
    lid_map = _load_guid2lid(g2l_path)

    df = mk.merge(nodes, on="Node GUID", how="inner")
    skipped = len(mk) - len(df)
    if skipped:
        print(
            f"  [warn] {skipped} guid2mkey row(s) had no matching NODES entry in smdb — skipped",
            file=sys.stderr,
        )

    df["LID"] = df["Node GUID"].map(lambda g: lid_map.get(g, ""))

    df = df[[
        "Node GUID", "Hostname", "Port name", "Node Type", "LID", "M_Key",
    ]]
    return df.sort_values(["Node Type", "Hostname", "Port name"]).reset_index(drop=True)


# ─── CLI summary ─────────────────────────────────────────────────────────────


def print_single_snapshot(df: pd.DataFrame) -> None:
    _section("IB M_Keys")
    if df.empty:
        print("    (no rows)")
        return
    count_line("Total M_Keys", len(df))
    count_line("IB Switch M_Keys", int((df["Node Type"] == "Switch").sum()))
    count_line("IB HCA M_Keys", int((df["Node Type"] == "HCA").sum()))
    rt = int((df["Node Type"] == "Router").sum())
    if rt > 0:
        count_line("IB Router M_Keys", rt)


def print_compare_summary(
    df_x: pd.DataFrame, df_y: pd.DataFrame, diff: pd.DataFrame, verbose: bool,
) -> None:
    _section("IB M_Keys")
    has_router = int((df_x["Node Type"] == "Router").sum() + (df_y["Node Type"] == "Router").sum()) > 0

    for label, df in (("X", df_x), ("Y", df_y)):
        count_line(f"Snapshot {label} — Total", len(df))
        count_line(f"Snapshot {label} — IB Switch", int((df["Node Type"] == "Switch").sum()))
        count_line(f"Snapshot {label} — IB HCA", int((df["Node Type"] == "HCA").sum()))
        if has_router:
            count_line(f"Snapshot {label} — IB Router", int((df["Node Type"] == "Router").sum()))

    new = int((diff.get("New", pd.Series(dtype=str)).astype(str) == "Yes").sum()) if not diff.empty else 0
    disp = int((diff.get("Disappeared", pd.Series(dtype=str)).astype(str) == "Yes").sum()) if not diff.empty else 0
    chg = int((diff.get("Changed", pd.Series(dtype=str)).astype(str) == "Yes").sum()) if not diff.empty else 0
    count_line("New", new)
    count_line("Disappeared", disp)
    count_line("Changed", chg)

    if verbose and not diff.empty:
        _print_verbose_changes(diff)


def _print_verbose_changes(diff: pd.DataFrame) -> None:
    def _mark(col: str) -> pd.Series:
        return diff.get(col, pd.Series(dtype=str)).astype(str) == "Yes"

    def _row_id(r: pd.Series) -> str:
        host = r.get("Hostname", "")
        port = r.get("Port name", "")
        nt = r.get("Node Type", "")
        guid = r.get("Node GUID", "")
        port_part = f" {port}" if port else ""
        return f"{nt} {host}{port_part} ({guid})"

    new_rows = diff[_mark("New")]
    dis_rows = diff[_mark("Disappeared")]
    chg_rows = diff[_mark("Changed")]

    if not (len(new_rows) or len(dis_rows) or len(chg_rows)):
        return
    print(f"\n  [verbose] M_Keys")
    if len(new_rows):
        print(f"    New ({len(new_rows)}):")
        for _, r in new_rows.iterrows():
            print(f"      + {_row_id(r)} | M_Key: {r.get('M_Key_y', r.get('M_Key', ''))}")
    if len(dis_rows):
        print(f"    Disappeared ({len(dis_rows)}):")
        for _, r in dis_rows.iterrows():
            print(f"      - {_row_id(r)} | M_Key: {r.get('M_Key_x', r.get('M_Key', ''))}")
    if len(chg_rows):
        print(f"    Changed ({len(chg_rows)}):")
        for _, r in chg_rows.iterrows():
            mx = r.get("M_Key_x", "")
            my = r.get("M_Key_y", "")
            print(f"      ~ {_row_id(r)} | M_Key: {mx} → {my}")


# ─── Diff post-processing ────────────────────────────────────────────────────


def _trim_diff_columns(diff: pd.DataFrame) -> pd.DataFrame:
    """Coalesce identity columns (prefer Y, fall back to X) and drop the suffixed copies.

    Keeps `M_Key_x` / `M_Key_y` side-by-side so the reader sees both values.
    """
    if diff.empty:
        return diff

    out = pd.DataFrame({"Node GUID": diff["Node GUID"]})
    for col in ("Hostname", "Port name", "Node Type", "LID"):
        cx, cy = f"{col}_x", f"{col}_y"
        if cy in diff.columns and cx in diff.columns:
            # `Series.fillna(other_series)` replaces null entries with the
            # paired entry from `other_series`. Functionally identical to
            # `combine_first` here (both indexes come from the same `diff`
            # DataFrame and are aligned), but avoids combine_first's internal
            # concat path that triggers the pandas FutureWarning about
            # "array concatenation with empty entries".
            out[col] = diff[cy].fillna(diff[cx])
        elif cx in diff.columns:
            out[col] = diff[cx]
        elif cy in diff.columns:
            out[col] = diff[cy]
        elif col in diff.columns:
            out[col] = diff[col]

    for col in ("M_Key_x", "M_Key_y"):
        if col in diff.columns:
            out[col] = diff[col]

    for col in ("New", "Disappeared", "Changed"):
        if col in diff.columns:
            out[col] = diff[col]
    return out.reset_index(drop=True)


# ─── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    args = parse_args()
    output = Path(args.output)

    cfg_x = Path(args.opensm_config)
    log_x = Path(args.opensm_logs)
    print(f"Loading OpenSM config: {cfg_x}")
    print(f"Loading OpenSM logs:   {log_x}")
    df_x = build_m_keys_df(cfg_x, log_x)

    if args.compare_config or args.compare_logs:
        if not args.compare_config:
            sys.exit("ERROR: --compare-logs given without --compare-config.")
        if not args.compare_logs:
            sys.exit("ERROR: --compare-config given without --compare-logs.")
        cfg_y = Path(args.compare_config)
        log_y = Path(args.compare_logs)
        print(f"Loading OpenSM config: {cfg_y}")
        print(f"Loading OpenSM logs:   {log_y}")
        df_y = build_m_keys_df(
            cfg_y, log_y,
            config_flag="--compare-config", logs_flag="--compare-logs",
        )

        diff = compare_dataframes(df_x, df_y, ["Node GUID"], ["M_Key"])
        diff = _trim_diff_columns(diff)
        print_compare_summary(df_x, df_y, diff, verbose=args.verbose)

        wb = xlsxwriter.Workbook(str(output))
        if not df_x.empty:
            write_dataframe(wb, "M_Keys_X", df_x)
        if not df_y.empty:
            write_dataframe(wb, "M_Keys_Y", df_y)
        if not diff.empty:
            write_dataframe(wb, "M_Keys_Diff", diff)
        wb.close()
    else:
        print_single_snapshot(df_x)
        wb = xlsxwriter.Workbook(str(output))
        if df_x.empty:
            wb.add_worksheet("M_Keys")
        else:
            write_dataframe(wb, "M_Keys", df_x)
        wb.close()

    print(f"\nExcel report written: {output}")


if __name__ == "__main__":
    main()
