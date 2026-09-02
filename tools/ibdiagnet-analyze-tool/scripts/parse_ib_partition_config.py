#!/usr/bin/env python3
"""
parse_ib_partition_config.py — Audit HCA partition membership from OpenSM
`partitions.conf` + `opensm-smdb.dump`.

Single-snapshot:
    python scripts/parse_ib_partition_config.py \
        -c /path/to/ufm_conf/conf/opensm \
        -l /path/to/ufm_logs \
        -o partitions.xlsx

Two-snapshot comparison:
    python scripts/parse_ib_partition_config.py \
        -c snap_X/ufm_conf/conf/opensm -l snap_X/ufm_logs \
        --compare-config snap_Y/ufm_conf/conf/opensm \
        --compare-logs   snap_Y/ufm_logs \
        -o partitions_compare.xlsx --verbose

See specification.MD §6 for the full spec.
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
    _normalize_guid,
    compare_dataframes,
    split_hca_desc,
)
from lib.parsers.partitions_conf import parse_partitions_conf
from lib.parsers.smdb import extract_section
from lib.reporting import (
    CNT_W as _CNT_W,
    LINE_W as _LINE_W,
    count_line,
    section as _section,
    write_sheets,
)

MGMT_PKEY = "0x7fff"


# ─── CLI ─────────────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Audit HCA partition membership from partitions.conf + opensm-smdb.dump."
    )
    p.add_argument("-c", "--opensm-config", required=True, metavar="FOLDER",
                   help="OpenSM config folder (snapshot X) — must contain partitions.conf.")
    p.add_argument("-l", "--opensm-logs", required=True, metavar="FOLDER",
                   help="OpenSM logs folder (snapshot X) — must contain opensm-smdb.dump.")
    p.add_argument("-o", "--output", required=True, metavar="FILE",
                   help="Output Excel (.xlsx) path.")
    p.add_argument("--compare-config", metavar="FOLDER",
                   help="OpenSM config folder (snapshot Y) — enables compare mode.")
    p.add_argument("--compare-logs", metavar="FOLDER",
                   help="OpenSM logs folder (snapshot Y) — required when --compare-config "
                        "is set; no implicit fallback to -l.")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Print detailed per-row change lists in comparison mode.")
    return p.parse_args()


def _resolve_required_file(folder: Path, filename: str, flag: str) -> Path:
    """Validate that `folder` contains `filename`; return the file path."""
    if not folder.is_dir():
        sys.exit(f"Error: {flag} folder not found: {folder}")
    f = folder / filename
    if not f.is_file():
        sys.exit(f"Error: {flag} folder is missing {filename}: {folder}")
    return f


# Local thin wrappers — keep existing call-site names while delegating to lib.reporting.
def _section_plain(title: str) -> None:
    _section(title)


def _section_with_total(title: str, total: int) -> None:
    _section(title, total)


def _count_line(label: str, count: int, indent: int = 4) -> None:
    count_line(label, count, indent=indent)


def _partition_line(pkey: str, name: str, count: int, breakdown: str) -> None:
    """'    0x8001  Name                                   :    7741   (full: 2, limited: 7739)'."""
    label = f"    {pkey}  {name}"
    count_str = f": {count:>{_CNT_W}}"
    pad = " " * max(1, _LINE_W - len(label) - len(count_str))
    print(f"{label}{pad}{count_str}{breakdown}")


# ─── DataFrame builders ──────────────────────────────────────────────────────


def _smdb_hca_ports(smdb_path: Path) -> pd.DataFrame:
    """HCA PortGUIDs from smdb — columns: PortGUID, NodeGUID, NodeDesc, LID."""
    ports = extract_section("PORTS", smdb_path)
    nodes = extract_section("NODES", smdb_path)

    if ports.empty or nodes.empty:
        return pd.DataFrame(columns=["PortGUID", "NodeGUID", "NodeDesc", "LID"])

    n = nodes[["NodeGUID", "NodeType", "NodeDesc"]].copy()
    n["NodeGUID"] = n["NodeGUID"].astype(str).map(_normalize_guid)
    n["NodeType"] = n["NodeType"].astype(str).str.strip()
    n["NodeDesc"] = n["NodeDesc"].astype(str).str.strip().str.strip('"')
    hca_nodes = n[n["NodeType"] == NODE_TYPE_HCA][["NodeGUID", "NodeDesc"]]

    p_cols = ["NodeGUID", "PortGUID"] + (["LID"] if "LID" in ports.columns else [])
    p = ports[p_cols].copy()
    p["NodeGUID"] = p["NodeGUID"].astype(str).map(_normalize_guid)
    p["PortGUID"] = p["PortGUID"].astype(str).map(_normalize_guid)
    if "LID" not in p.columns:
        p["LID"] = pd.NA

    out = p.merge(hca_nodes, on="NodeGUID", how="inner") \
           .drop_duplicates("PortGUID", keep="first")
    return out.reset_index(drop=True)


def _master_sm_port(smdb_path: Path) -> str | None:
    """Master SM's PortGUID (SMS.State == '3'), normalised. None if absent."""
    sms = extract_section("SMS", smdb_path)
    if sms.empty or "State" not in sms.columns or "PortGUID" not in sms.columns:
        return None
    state = sms["State"].astype(str).str.strip()
    master = sms[state == "3"]
    if master.empty:
        return None
    return _normalize_guid(str(master.iloc[0]["PortGUID"]))


def _resolve_membership(
    port_guid: str, partition: dict, master_port: str | None,
) -> object:
    """Most-specific wins: explicit GUID → SELF → ALL/ALL_CAS → blank."""
    explicit = self_mem = all_mem = None

    for m in partition["members"]:
        if m["kind"] == "guid":
            if m["guid"] == port_guid and explicit is None:
                explicit = m["membership"]
        else:  # keyword
            kw = m["keyword"]
            if kw == "SELF":
                if master_port and port_guid == master_port and self_mem is None:
                    self_mem = m["membership"]
            elif kw in ("ALL", "ALL_CAS"):
                if all_mem is None:
                    all_mem = m["membership"]

    if explicit is not None:
        return explicit
    if self_mem is not None:
        return self_mem
    if all_mem is not None:
        return all_mem
    return pd.NA


def build_partitions_df(partitions: list[dict], smdb_path: Path) -> pd.DataFrame:
    """Main Partitions DataFrame — see §6.3."""
    hcas = _smdb_hca_ports(smdb_path)

    host_map: dict[str, str] = {}
    port_map: dict[str, object] = {}
    lid_map: dict[str, object] = {}
    if not hcas.empty:
        split = hcas["NodeDesc"].map(split_hca_desc)
        for pg, pair, lid in zip(hcas["PortGUID"], split, hcas["LID"]):
            host_map[pg] = pair[0]
            port_map[pg] = pair[1] if pair[1] is not None else pd.NA
            lid_map[pg] = lid if pd.notna(lid) and str(lid).strip() else pd.NA

    master_port = _master_sm_port(smdb_path)

    # Union: smdb HCAs ∪ partitions.conf GUID entries.
    config_guids: set[str] = set()
    for part in partitions:
        for m in part["members"]:
            if m["kind"] == "guid":
                config_guids.add(m["guid"])
    smdb_guids = set(host_map.keys())
    all_guids = sorted(smdb_guids | config_guids)

    rows = [
        {
            "PortGUID": pg,
            "LID": lid_map.get(pg, pd.NA),
            "Hostname": host_map.get(pg, pd.NA),
            "Port name": port_map.get(pg, pd.NA),
        }
        for pg in all_guids
    ]
    df = pd.DataFrame(rows)

    # index0 key — per-port. The `indx0` flag means the partition is placed at
    # block 0, index 0 of the *member port's* PartitionTable; non-members keep
    # the management partition (0x7fff) at that slot. So we resolve membership
    # for each indx0-flagged partition individually; if the port belongs to one,
    # that's its index0 key, else 0x7fff.
    indx0_partitions = [p for p in partitions if p["flags"]["indx0"]]

    def _index0_for_port(port_guid: str) -> str:
        for part in indx0_partitions:
            if pd.notna(_resolve_membership(port_guid, part, master_port)):
                return part["pkey"]
        return MGMT_PKEY

    df["index0 key"] = df["PortGUID"].map(_index0_for_port)

    # Partition columns — sorted by numeric PKey ascending (0x7fff naturally last).
    for part in _ordered_pkeys(partitions):
        col = part["pkey"]
        df[col] = df["PortGUID"].map(
            lambda pg, p=part, mp=master_port: _resolve_membership(pg, p, mp)
        )

    return df


def build_partition_config_df(
    partitions: list[dict], partitions_df: pd.DataFrame,
) -> pd.DataFrame:
    """Per-partition config summary — see §6.7."""
    rows = []
    for part in partitions:
        pkey = part["pkey"]
        explicit_guids = sum(1 for m in part["members"] if m["kind"] == "guid")
        has_all = any(
            m["kind"] == "keyword" and m["keyword"] in ("ALL", "ALL_CAS")
            for m in part["members"]
        )
        hca_count = int(partitions_df[pkey].notna().sum()) if pkey in partitions_df.columns else 0
        rows.append({
            "PKey": pkey,
            "Name": part["name"],
            "indx0": "Yes" if part["flags"]["indx0"] else "",
            "ipoib": "Yes" if part["flags"]["ipoib"] else "",
            "defmember": part["defmember"],
            "Rate": part["flags"]["rate"] if part["flags"]["rate"] is not None else "",
            "MTU": part["flags"]["mtu"] if part["flags"]["mtu"] is not None else "",
            "SL": part["flags"]["sl"] if part["flags"]["sl"] is not None else "",
            "Scope": part["flags"]["scope"] if part["flags"]["scope"] is not None else "",
            "Member count (ALL)": "Yes" if has_all else "",
            "Member count (explicit GUIDs)": explicit_guids,
            "Member count (HCAs resolved)": hca_count,
        })
    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.sort_values("PKey", key=lambda s: s.map(lambda v: int(v, 16))) \
               .reset_index(drop=True)
    return df


def _ordered_pkeys(partitions: list[dict]) -> list[dict]:
    """Sorted by numeric PKey value ascending (so 0x7fff naturally lands last)."""
    return sorted(partitions, key=lambda p: int(p["pkey"], 16))


def _membership_breakdown(col: pd.Series) -> str:
    """Return '   (full: N, limited: N, both: N)' with only non-zero entries, or ''."""
    full = int((col == "full").sum())
    limited = int((col == "limited").sum())
    both = int((col == "both").sum())
    parts = []
    if full:
        parts.append(f"full: {full}")
    if limited:
        parts.append(f"limited: {limited}")
    if both:
        parts.append(f"both: {both}")
    return f"   ({', '.join(parts)})" if parts else ""


# ─── Single-snapshot CLI output ──────────────────────────────────────────────


def print_single_snapshot(
    partitions: list[dict], partitions_df: pd.DataFrame,
) -> None:
    non_mgmt_count = sum(1 for p in partitions if p["pkey"] != MGMT_PKEY)
    ipoib_count = sum(1 for p in partitions if p["flags"]["ipoib"])
    _section_with_total("Partition Config", non_mgmt_count)
    _count_line("Partitions (exclude 0x7fff)", non_mgmt_count)
    _count_line("IPoIB-enabled partitions", ipoib_count)

    _section_plain("Per-Partition Membership Counts")
    for part in _ordered_pkeys(partitions):
        pkey = part["pkey"]
        col = partitions_df[pkey] if pkey in partitions_df.columns else pd.Series(dtype=object)
        total = int(col.notna().sum())
        name = part["name"] or ("Default (Management)" if pkey == MGMT_PKEY else "")
        _partition_line(pkey, name, total, _membership_breakdown(col))


# ─── Compare-mode CLI output ─────────────────────────────────────────────────


def _diff_counts(diff: pd.DataFrame) -> tuple[int, int, int]:
    if diff.empty:
        return 0, 0, 0
    new = int((diff.get("New", pd.Series(dtype=str)).astype(str) == "Yes").sum())
    dis = int((diff.get("Disappeared", pd.Series(dtype=str)).astype(str) == "Yes").sum())
    chg = int((diff.get("Changed", pd.Series(dtype=str)).astype(str) == "Yes").sum())
    return new, dis, chg


def _per_partition_delta(
    df_x: pd.DataFrame, df_y: pd.DataFrame, pkey: str,
) -> tuple[int, int, int, int, int, pd.DataFrame]:
    """Return (count_x, count_y, added, removed, type_changed, detail_df).

    detail_df has columns PortGUID, Hostname, Port name, Change, X, Y.
    """
    x_has = pkey in df_x.columns
    y_has = pkey in df_y.columns

    x_series = df_x.set_index("PortGUID")[pkey] if x_has else pd.Series(dtype=object)
    y_series = df_y.set_index("PortGUID")[pkey] if y_has else pd.Series(dtype=object)

    all_guids = sorted(set(x_series.index) | set(y_series.index))

    added: list[str] = []
    removed: list[str] = []
    type_changed: list[tuple[str, object, object]] = []

    for g in all_guids:
        xv = x_series.get(g, pd.NA) if x_has else pd.NA
        yv = y_series.get(g, pd.NA) if y_has else pd.NA
        x_is = pd.notna(xv)
        y_is = pd.notna(yv)
        if not x_is and y_is:
            added.append(g)
        elif x_is and not y_is:
            removed.append(g)
        elif x_is and y_is and str(xv).strip() != str(yv).strip():
            type_changed.append((g, xv, yv))

    count_x = int(x_series.notna().sum()) if x_has else 0
    count_y = int(y_series.notna().sum()) if y_has else 0

    # Build verbose detail — combine added / removed / type_changed into one frame.
    host_x = df_x.set_index("PortGUID")[["Hostname", "Port name"]]
    host_y = df_y.set_index("PortGUID")[["Hostname", "Port name"]]
    detail_rows = []
    for g in added:
        host, port = _best_host_port(g, host_x, host_y)
        detail_rows.append({"PortGUID": g, "Hostname": host, "Port name": port,
                            "Change": "Added", "X": "", "Y": str(y_series.get(g, ""))})
    for g in removed:
        host, port = _best_host_port(g, host_x, host_y)
        detail_rows.append({"PortGUID": g, "Hostname": host, "Port name": port,
                            "Change": "Removed", "X": str(x_series.get(g, "")), "Y": ""})
    for g, xv, yv in type_changed:
        host, port = _best_host_port(g, host_x, host_y)
        detail_rows.append({"PortGUID": g, "Hostname": host, "Port name": port,
                            "Change": "Type changed", "X": str(xv), "Y": str(yv)})

    detail_df = pd.DataFrame(detail_rows, columns=[
        "PortGUID", "Hostname", "Port name", "Change", "X", "Y",
    ])
    return count_x, count_y, len(added), len(removed), len(type_changed), detail_df


def _best_host_port(guid, host_x, host_y) -> tuple[object, object]:
    """Prefer Y-side identity (current), fall back to X-side."""
    if guid in host_y.index:
        r = host_y.loc[guid]
        if pd.notna(r.get("Hostname")):
            return r["Hostname"], r.get("Port name", pd.NA)
    if guid in host_x.index:
        r = host_x.loc[guid]
        return r.get("Hostname", pd.NA), r.get("Port name", pd.NA)
    return pd.NA, pd.NA


def _union_ordered_pkeys(
    partitions_x: list[dict], partitions_y: list[dict],
) -> list[tuple[str, str]]:
    """Return [(pkey, display_name), …] in declaration order (X then Y additions), mgmt last."""
    seen: set[str] = set()
    out: list[tuple[str, str]] = []

    def _append(part: dict) -> None:
        if part["pkey"] in seen or part["pkey"] == MGMT_PKEY:
            return
        seen.add(part["pkey"])
        out.append((part["pkey"], part["name"]))

    for part in partitions_x:
        _append(part)
    for part in partitions_y:
        _append(part)

    # Append mgmt last (take name from whichever snapshot has it).
    mgmt_name = ""
    for part in (*partitions_x, *partitions_y):
        if part["pkey"] == MGMT_PKEY:
            mgmt_name = part["name"] or "Default (Management)"
            break
    out.append((MGMT_PKEY, mgmt_name or "Default (Management)"))
    return out


def print_compare(
    partitions_x: list[dict],
    partitions_y: list[dict],
    df_x: pd.DataFrame,
    df_y: pd.DataFrame,
    cfg_diff: pd.DataFrame,
    verbose: bool,
) -> None:
    _section_plain("Partition Config")
    new, dis, chg = _diff_counts(cfg_diff)
    _count_line("Snapshot X", len(partitions_x))
    _count_line("Snapshot Y", len(partitions_y))
    _count_line("New partitions", new)
    _count_line("Disappeared partitions", dis)
    _count_line("Changed", chg)

    _section_plain("Per-Partition Membership Comparison")
    for pkey, name in _union_ordered_pkeys(partitions_x, partitions_y):
        cx, cy, added, removed, typed, detail = _per_partition_delta(df_x, df_y, pkey)
        # Header line
        header = f"  {pkey}  {name}".rstrip()
        print(header)
        _count_line("Snapshot X", cx, indent=8)
        _count_line("Snapshot Y", cy, indent=8)
        _count_line("Added to partition", added, indent=8)
        _count_line("Removed from partition", removed, indent=8)
        _count_line("Membership type changed", typed, indent=8)

        if verbose and not detail.empty:
            print(f"        Details:")
            for _, row in detail.iterrows():
                host = row["Hostname"] if pd.notna(row["Hostname"]) else "N/A"
                port = row["Port name"] if pd.notna(row["Port name"]) else "N/A"
                chg_str = row["Change"]
                if chg_str == "Type changed":
                    print(f"          [{chg_str}] {row['PortGUID']}  "
                          f"{host} {port}  ({row['X']} → {row['Y']})")
                else:
                    val = row["Y"] if chg_str == "Added" else row["X"]
                    print(f"          [{chg_str}] {row['PortGUID']}  "
                          f"{host} {port}  ({val})")
        print()


# ─── Main ────────────────────────────────────────────────────────────────────


def _write_single_workbook(
    output: Path, partitions_df: pd.DataFrame, cfg_df: pd.DataFrame,
) -> None:
    wb = xlsxwriter.Workbook(str(output))
    try:
        write_sheets(wb, [
            ("Partitions",       partitions_df, True),
            ("Partition_Config", cfg_df,        True),
        ])
    finally:
        wb.close()


def _write_compare_workbook(
    output: Path,
    partitions_df_x: pd.DataFrame, partitions_df_y: pd.DataFrame, partitions_diff: pd.DataFrame,
    cfg_x: pd.DataFrame, cfg_y: pd.DataFrame, cfg_diff: pd.DataFrame,
) -> None:
    wb = xlsxwriter.Workbook(str(output))
    try:
        write_sheets(wb, [
            ("Partitions_X",         partitions_df_x, True),
            ("Partitions_Y",         partitions_df_y, True),
            ("Partitions_Diff",      partitions_diff, True),
            ("Partition_Config_X",   cfg_x,           True),
            ("Partition_Config_Y",   cfg_y,           True),
            ("Partition_Config_Diff", cfg_diff,       True),
        ])
    finally:
        wb.close()


def _partitions_long(df: pd.DataFrame) -> pd.DataFrame:
    """Unpivot the Partitions DataFrame to one row per (PortGUID, PKey) with non-blank membership."""
    if df.empty:
        return pd.DataFrame(columns=["PortGUID", "LID", "Hostname", "Port name", "PKey", "Membership"])
    pkey_cols = [c for c in df.columns if c.startswith("0x")]
    id_cols = [c for c in ("PortGUID", "LID", "Hostname", "Port name") if c in df.columns]
    long = df.melt(
        id_vars=id_cols,
        value_vars=pkey_cols,
        var_name="PKey", value_name="Membership",
    )
    return long[long["Membership"].notna()].reset_index(drop=True)


def main() -> int:
    args = parse_args()

    partitions_path = _resolve_required_file(
        Path(args.opensm_config), "partitions.conf", "-c/--opensm-config",
    )
    smdb_path = _resolve_required_file(
        Path(args.opensm_logs), "opensm-smdb.dump", "-l/--opensm-logs",
    )

    partitions_x = parse_partitions_conf(partitions_path)
    df_x = build_partitions_df(partitions_x, smdb_path)
    cfg_x = build_partition_config_df(partitions_x, df_x)

    if args.compare_config or args.compare_logs:
        if not args.compare_config:
            sys.exit("Error: --compare-logs given without --compare-config.")
        if not args.compare_logs:
            sys.exit("Error: --compare-config given without --compare-logs.")
        cmp_path = _resolve_required_file(
            Path(args.compare_config), "partitions.conf", "--compare-config",
        )
        cmp_smdb = _resolve_required_file(
            Path(args.compare_logs), "opensm-smdb.dump", "--compare-logs",
        )

        partitions_y = parse_partitions_conf(cmp_path)
        df_y = build_partitions_df(partitions_y, cmp_smdb)
        cfg_y = build_partition_config_df(partitions_y, df_y)

        cfg_diff = compare_dataframes(
            cfg_x, cfg_y,
            merge_keys=["PKey"],
            change_cols=["Name", "indx0", "ipoib", "defmember",
                         "Member count (explicit GUIDs)", "Member count (HCAs resolved)"],
        )
        # Partitions Diff: compare long-format (PortGUID, PKey) → Membership.
        long_x = _partitions_long(df_x)
        long_y = _partitions_long(df_y)
        partitions_diff = compare_dataframes(
            long_x, long_y,
            merge_keys=["PortGUID", "PKey"],
            change_cols=["Membership"],
        )

        print_compare(partitions_x, partitions_y, df_x, df_y, cfg_diff, args.verbose)
        _write_compare_workbook(
            Path(args.output),
            df_x, df_y, partitions_diff,
            cfg_x, cfg_y, cfg_diff,
        )
    else:
        print_single_snapshot(partitions_x, df_x)
        _write_single_workbook(Path(args.output), df_x, cfg_x)

    print(f"\nExcel report written: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
