#!/usr/bin/env python3
"""
show_ib_inventory.py — Extract IB hardware/firmware inventory from ibdiagnet2 dumps.

Single-snapshot mode:
    python scripts/show_ib_inventory.py -i <ibdiagnet_folder> -o <output.xlsx>

Two-snapshot comparison mode:
    python scripts/show_ib_inventory.py -i <ibdiagnet_folder_X> --compare <ibdiagnet_folder_Y> \
        -o <output.xlsx> [--verbose]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd
import xlsxwriter

# Allow running from repo root without installation.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.excel import write_dataframe, write_pivot, write_psu_pivot, write_temp_histogram
from lib.inventory import (
    TEMP_CHANGE_THRESHOLD,
    bin_temperatures,
    build_cable_inventory,
    build_hca_inventory,
    build_psu_inventory,
    build_router_inventory,
    build_switch_inventory,
    build_temp_inventory,
    combine_transceiver_temps,
    combine_transceivers,
    compare_dataframes,
    joint_temp_range,
)


# ─── CLI ─────────────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Extract IB hardware/firmware inventory from ibdiagnet2 dumps"
    )
    p.add_argument(
        "-i", "--ibdiagnet",
        required=True,
        metavar="FOLDER",
        help="Path to ibdiagnet2 dump folder (snapshot X)",
    )
    p.add_argument(
        "-o", "--output",
        required=True,
        metavar="FILE",
        help="Output Excel (.xlsx) file path",
    )
    p.add_argument(
        "-p", "--compare",
        metavar="FOLDER",
        help="Path to a second ibdiagnet2 folder (snapshot Y) — enables comparison mode",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print detailed change lists in comparison mode",
    )
    return p.parse_args()


# ─── CLI output helpers ───────────────────────────────────────────────────────

from lib.reporting import (
    CNT_W as _CNT_W,
    LBL_W as _LBL_W,
    LINE_W as _LINE_W,
    SEP,
    count_line as _summary_line,
    histogram_table as _histogram_table,
    section as _section_compare_full,
)

_VND_W = 12   # transceiver vendor column width (inventory-specific)
_PN_W = 18    # transceiver PN column width (inventory-specific)


def _section(title: str, total_label: str, count: int) -> None:
    """Section header with title-left, '<total_label>: N'-right.

    Custom layout (the `total_label` varies per section: 'Total' / 'Qty')
    so this can't directly use the shared `section()` helper.
    """
    right = f"{total_label}: {count:>{_CNT_W}}"
    left = f"  {title}"
    pad = " " * max(1, _LINE_W - len(left) - len(right))
    print(f"\n{SEP}")
    print(f"{left}{pad}{right}")
    print(SEP)


def _section_compare(title: str) -> None:
    """Plain-divider section header for comparison mode (no total)."""
    _section_compare_full(title)


def _print_fw_pivot(label: str, df: pd.DataFrame, psid_col: str, fw_col: str) -> None:
    """Print a PSID × FW pivot to stdout with aligned columns."""
    if df.empty:
        print(f"  (no {label} found)")
        return
    pivot = df.groupby([psid_col, fw_col]).size().reset_index(name="Qty")
    cur_psid = None
    for _, row in pivot.iterrows():
        if row[psid_col] != cur_psid:
            cur_psid = row[psid_col]
            total = int(df[df[psid_col] == cur_psid].shape[0])
            lbl = f"  PSID: {cur_psid}"
            print(f"{lbl:<{_LBL_W}}  Total: {total:>{_CNT_W}}")
        lbl = f"    FW: {row[fw_col]}"
        print(f"{lbl:<{_LBL_W}}    Qty: {row['Qty']:>{_CNT_W}}")


def _side_by_side_fw(label: str, dx: pd.DataFrame, dy: pd.DataFrame,
                     psid_col: str, fw_col: str) -> None:
    """Print two FW pivot tables side by side (snapshot X then Y)."""
    print(f"\n  Snapshot X:")
    _print_fw_pivot(label, dx, psid_col, fw_col)
    print(f"\n  Snapshot Y:")
    _print_fw_pivot(label, dy, psid_col, fw_col)


# ─── Temperature helpers ─────────────────────────────────────────────────────


def _switch_temp_total(temp: pd.DataFrame) -> int:
    """Switches with at least one of Current or Max temperature populated."""
    if temp is None or temp.empty:
        return 0
    cur = pd.to_numeric(temp.get("Current Temperature"), errors="coerce")
    mx = pd.to_numeric(temp.get("Max Temperature"), errors="coerce")
    return int((cur.notna() | mx.notna()).sum())


def _build_switch_hist(temp: pd.DataFrame, lo: int | None = None, hi: int | None = None) -> pd.DataFrame:
    """Joint Current+Max histogram for switches; one row per bin with both counts."""
    cur = pd.to_numeric(temp["Current Temperature"], errors="coerce")
    mx = pd.to_numeric(temp["Max Temperature"], errors="coerce")
    if lo is None or hi is None:
        lo, hi = joint_temp_range(cur, mx)
    if lo is None:
        return pd.DataFrame(columns=["Bin Label", "Current", "Max"])
    cur_h = bin_temperatures(cur, lo=lo, hi=hi).rename(columns={"Qty": "Current"})
    mx_h = bin_temperatures(mx, lo=lo, hi=hi).rename(columns={"Qty": "Max"})
    return cur_h.merge(mx_h[["Bin Label", "Max"]], on="Bin Label")


def _hca_temp_series(hca: pd.DataFrame) -> pd.Series:
    """Numeric Current Temperature Series from HCA inventory (NaNs dropped)."""
    if hca is None or hca.empty or "Current Temperature" not in hca.columns:
        return pd.Series(dtype=float)
    return pd.to_numeric(hca["Current Temperature"], errors="coerce").dropna().reset_index(drop=True)


def _hist_to_rows_single(hist: pd.DataFrame) -> list[tuple[str, list[int]]]:
    """[("Bin Label", [Qty])] rows for a single-column bin DataFrame."""
    return [(r["Bin Label"], [int(r["Qty"])]) for _, r in hist.iterrows()]


# ─── Single-snapshot output ───────────────────────────────────────────────────


def single_snapshot_cli(
    ibdir: Path,
    sw: pd.DataFrame,
    rt: pd.DataFrame | None,
    psu: pd.DataFrame,
    temp: pd.DataFrame,
    hca: pd.DataFrame,
    cable: pd.DataFrame,
) -> None:
    _section("IB Switch/ASIC Inventory", "Total", len(sw))
    _print_fw_pivot("switches", sw, "PSID", "Firmware Version")

    if rt is not None and not rt.empty:
        _section("IB Router Inventory", "Total", len(rt))
        _print_fw_pivot("routers", rt, "PSID", "Firmware Version")

    _section("IB Switch PSU", "Total", len(psu))
    if not psu.empty:
        present = psu[psu["PSU Present"] == "Yes"]
        good = present[(present["PSU DC State"] == "OK") & (present["PSU Fan State"] == "OK")]
        bad = present[~((present["PSU DC State"] == "OK") & (present["PSU Fan State"] == "OK"))]
        lbl = f"  Total PSU"
        print(f"{lbl:<{_LBL_W}}    Qty: {len(present):>{_CNT_W}}")
        lbl = f"  Good  PSU"
        print(f"{lbl:<{_LBL_W}}    Qty: {len(good):>{_CNT_W}}")
        lbl = f"  Bad   PSU"
        print(f"{lbl:<{_LBL_W}}    Qty: {len(bad):>{_CNT_W}}")
        print()
        print("  Note: For managed switches, check PSU/FAN status via the switch CLI.")

    sw_temp_total = _switch_temp_total(temp)
    _section("IB Switch Temperature Sensors", "Total", sw_temp_total)
    if sw_temp_total:
        sw_hist = _build_switch_hist(temp)
        _histogram_table(
            ["Current", "Max"],
            [(r["Bin Label"], [int(r["Current"]), int(r["Max"])])
             for _, r in sw_hist.iterrows()],
        )

    _section("IB HCA Inventory", "Total Ports", len(hca))
    _print_fw_pivot("HCAs", hca, "PSID", "Firmware Version")

    hca_temps = _hca_temp_series(hca)
    _section("IB HCA Temperature Sensors", "Total", len(hca_temps))
    if not hca_temps.empty:
        hca_hist = bin_temperatures(hca_temps)
        _histogram_table(
            [],
            [(r["Bin Label"], [int(r["Qty"])]) for _, r in hca_hist.iterrows()],
        )

    xcvr_temps = combine_transceiver_temps(cable)
    _section("IB Transceiver Temperature Sensors", "Total", len(xcvr_temps))
    if not xcvr_temps.empty:
        xcvr_hist = bin_temperatures(xcvr_temps)
        _histogram_table(
            [],
            [(r["Bin Label"], [int(r["Qty"])]) for _, r in xcvr_hist.iterrows()],
        )

    if not cable.empty and "Src Transceiver SN" in cable.columns and "Dst Transceiver SN" in cable.columns:
        # Combine src + dst transceiver entries, dedup by SN — one row per
        # unique physical module across both cable ends. Grouping by Src only
        # would miss dst-only transceivers (e.g. XDR plane-1 ports whose dst
        # has cable data but src does not).
        all_t = combine_transceivers(cable, columns=("Vendor", "PN", "SN"))
        _section("IB Cable/Transceiver Inventory", "Total", len(all_t))
        counts = (
            all_t.groupby(["Vendor", "PN"]).size().reset_index(name="Qty")
            .sort_values(["Vendor", "PN"])
        )
        for _, row in counts.iterrows():
            vendor = row["Vendor"]
            pn = row["PN"]
            qty = row["Qty"]
            print(f"  Vendor: {vendor:<{_VND_W}}  PN: {pn:<{_PN_W}}  Qty: {qty:>{_CNT_W}}")
    else:
        _section("IB Cable/Transceiver Inventory", "Total", len(cable))


def single_snapshot_excel(
    output_path: Path,
    sw: pd.DataFrame,
    rt: pd.DataFrame | None,
    psu: pd.DataFrame,
    temp: pd.DataFrame,
    hca: pd.DataFrame,
    cable: pd.DataFrame,
) -> None:
    wb = xlsxwriter.Workbook(str(output_path))

    if not sw.empty:
        write_pivot(wb, "SW_ASIC_Inventory_Summary", sw, "PSID", "Firmware Version")
        write_dataframe(wb, "SW_ASIC_Inventory", sw)

    if rt is not None and not rt.empty:
        write_pivot(wb, "Router_Inventory_Pivot", rt, "PSID", "Firmware Version",
                    title="IB Router Inventory")
        write_dataframe(wb, "Router_Inventory", rt)

    if not psu.empty:
        write_psu_pivot(wb, "SW_PSU_Summary", psu)
        write_dataframe(wb, "SW_PSU_Inventory", psu)

    if not temp.empty:
        sw_hist = _build_switch_hist(temp)
        if not sw_hist.empty:
            write_temp_histogram(
                wb, "SW_Temp_Summary", sw_hist,
                title="Switch Temperature Distribution",
                value_cols=["Current", "Max"],
            )
        write_dataframe(wb, "SW_Temp_Sensor", temp)

    if not hca.empty:
        write_pivot(wb, "HCA_Inventory_Summary", hca, "PSID", "Firmware Version")
        write_dataframe(wb, "HCA_Inventory", hca)
        hca_temps = _hca_temp_series(hca)
        if not hca_temps.empty:
            write_temp_histogram(
                wb, "HCA_Temp_Summary",
                bin_temperatures(hca_temps).rename(columns={"Qty": "Count"}),
                title="HCA Temperature Distribution",
                value_cols=["Count"],
            )

    if not cable.empty:
        if "Src Transceiver SN" in cable.columns and "Dst Transceiver SN" in cable.columns:
            # Same combine + dedup-by-SN as the CLI summary, but with extra
            # Rev/FW columns so the pivot matches the spec for Cable_Summary.
            all_t = combine_transceivers(
                cable, columns=("Vendor", "PN", "Rev", "FW", "SN"),
            )
            pivot_df = (
                all_t.groupby(["Vendor", "PN", "Rev", "FW"])
                .size().reset_index(name="Qty")
            )
            _write_simple_df(wb, "Cable_Summary", pivot_df)

            xcvr_temps = combine_transceiver_temps(cable)
            if not xcvr_temps.empty:
                write_temp_histogram(
                    wb, "Cable_Temp_Summary",
                    bin_temperatures(xcvr_temps).rename(columns={"Qty": "Count"}),
                    title="Transceiver Temperature Distribution",
                    value_cols=["Count"],
                )
        write_dataframe(wb, "Cable_Inventory", cable)

    wb.close()
    print(f"\nExcel report written: {output_path}")


def _write_simple_df(wb: xlsxwriter.Workbook, sheet_name: str, df: pd.DataFrame) -> None:
    """Thin wrapper for DataFrames that don't need auto-sized columns."""
    write_dataframe(wb, sheet_name, df)


# ─── Two-snapshot comparison output ──────────────────────────────────────────


def comparison_cli(
    sw_x, sw_y, rt_x, rt_y, psu_x, psu_y, temp_x, temp_y, hca_x, hca_y,
    cable_x, cable_y, verbose: bool,
) -> None:
    # Switches
    _section_compare("IB Switch/ASIC Inventory")
    guids_x = set(sw_x["Node GUID"]) if not sw_x.empty else set()
    guids_y = set(sw_y["Node GUID"]) if not sw_y.empty else set()
    new_sw = sw_y[sw_y["Node GUID"].isin(guids_y - guids_x)] if not sw_y.empty else pd.DataFrame()
    gone_sw = sw_x[sw_x["Node GUID"].isin(guids_x - guids_y)] if not sw_x.empty else pd.DataFrame()
    changed_sw = _find_changed(sw_x, sw_y, "Node GUID", ["Switch Name", "Firmware Version"])
    _summary_line("Snapshot X", len(sw_x))
    _summary_line("Snapshot Y", len(sw_y))
    _summary_line("New switches", len(new_sw))
    _summary_line("Disappeared", len(gone_sw))
    _summary_line("Changed", len(changed_sw))
    if verbose:
        _verbose_rows("New switches", new_sw, ["Node GUID", "Switch Name", "Firmware Version", "LID"])
        _verbose_rows("Disappeared switches", gone_sw, ["Node GUID", "Switch Name", "Firmware Version", "LID"])
        _verbose_rows("Changed switches", changed_sw, ["Node GUID"])

    # Routers
    rx = rt_x if rt_x is not None else pd.DataFrame()
    ry = rt_y if rt_y is not None else pd.DataFrame()
    if not rx.empty or not ry.empty:
        _section_compare("IB Router Inventory")
        guids_rx = set(rx["Node GUID"]) if not rx.empty else set()
        guids_ry = set(ry["Node GUID"]) if not ry.empty else set()
        _summary_line("Snapshot X", len(rx))
        _summary_line("Snapshot Y", len(ry))
        _summary_line("New routers", len(guids_ry - guids_rx))
        _summary_line("Disappeared", len(guids_rx - guids_ry))

    # PSU
    _section_compare("IB Switch PSU")
    psu_diff = _psu_compare(psu_x, psu_y)
    _summary_line("Snapshot X", len(psu_x))
    _summary_line("Snapshot Y", len(psu_y))
    _summary_line("New PSU found", int((psu_diff.get("New PSU", pd.Series()) == "Yes").sum()) if not psu_diff.empty else 0)
    _summary_line("Became Good", int((psu_diff.get("Became Good", pd.Series()) == "Yes").sum()) if not psu_diff.empty else 0)
    _summary_line("Became Bad", int((psu_diff.get("Became Bad", pd.Series()) == "Yes").sum()) if not psu_diff.empty else 0)
    print()
    print("  Note: For managed switches, check PSU/FAN status via the switch CLI.")
    if verbose and not psu_diff.empty:
        _verbose_rows("PSU changes", psu_diff, ["Node GUID", "Switch Name", "PSU Index"])

    # Switch Temperature — side-by-side histogram (joint bin axis across X and Y)
    _section_compare("IB Switch Temperature Sensors")
    _summary_line("Snapshot X", _switch_temp_total(temp_x))
    _summary_line("Snapshot Y", _switch_temp_total(temp_y))
    _print_switch_temp_compare(temp_x, temp_y)

    # HCA
    _section_compare("IB HCA Inventory")
    guids_hx = set(hca_x["Node GUID"]) if not hca_x.empty else set()
    guids_hy = set(hca_y["Node GUID"]) if not hca_y.empty else set()
    new_hca = hca_y[hca_y["Node GUID"].isin(guids_hy - guids_hx)] if not hca_y.empty else pd.DataFrame()
    gone_hca = hca_x[hca_x["Node GUID"].isin(guids_hx - guids_hy)] if not hca_x.empty else pd.DataFrame()
    changed_hca = _find_changed(hca_x, hca_y, "Node GUID", ["Hostname", "Port Name", "Firmware Version"])
    _summary_line("Snapshot X", len(hca_x))
    _summary_line("Snapshot Y", len(hca_y))
    _summary_line("New HCAs", len(new_hca))
    _summary_line("Disappeared", len(gone_hca))
    _summary_line("Changed", len(changed_hca))
    if verbose:
        _verbose_rows("New HCAs", new_hca, ["Node GUID", "Hostname", "Port Name"])
        _verbose_rows("Disappeared HCAs", gone_hca, ["Node GUID", "Hostname", "Port Name"])
        _verbose_rows("Changed HCAs", changed_hca, ["Node GUID"])

    # HCA Temperature
    hca_t_x = _hca_temp_series(hca_x)
    hca_t_y = _hca_temp_series(hca_y)
    _section_compare("IB HCA Temperature Sensors")
    _summary_line("Snapshot X", len(hca_t_x))
    _summary_line("Snapshot Y", len(hca_t_y))
    _print_xy_temp_compare(hca_t_x, hca_t_y)

    # Cable
    _section_compare("IB Cable/Transceiver Inventory")
    def _all_sns(df):
        # Combined unique-SN set across both cable ends.
        return set(combine_transceivers(df, columns=("SN",))["SN"])
    sns_x = _all_sns(cable_x)
    sns_y = _all_sns(cable_y)
    # Report unique transceiver count (matches single-snapshot section total
    # and the New/Disappeared rows below, which are also SN-based).
    _summary_line("Snapshot X", len(sns_x))
    _summary_line("Snapshot Y", len(sns_y))
    _summary_line("New transceivers", len(sns_y - sns_x))
    _summary_line("Disappeared transceivers", len(sns_x - sns_y))

    # Transceiver Temperature
    xcvr_t_x = combine_transceiver_temps(cable_x)
    xcvr_t_y = combine_transceiver_temps(cable_y)
    _section_compare("IB Transceiver Temperature Sensors")
    _summary_line("Snapshot X", len(xcvr_t_x))
    _summary_line("Snapshot Y", len(xcvr_t_y))
    _print_xy_temp_compare(xcvr_t_x, xcvr_t_y)


def comparison_excel(
    output_path: Path,
    sw_x, sw_y, rt_x, rt_y, psu_x, psu_y, temp_x, temp_y, hca_x, hca_y, cable_x, cable_y,
) -> None:
    wb = xlsxwriter.Workbook(str(output_path))

    # Switches
    if not sw_x.empty:
        write_dataframe(wb, "SW_ASIC_Inventory_X", sw_x)
    if not sw_y.empty:
        write_dataframe(wb, "SW_ASIC_Inventory_Y", sw_y)
    if not sw_x.empty and not sw_y.empty:
        diff = compare_dataframes(sw_x, sw_y, ["Node GUID"],
                                   ["Switch Name", "Firmware Version"],
                                   "New Switch", "Disappeared Switch")
        if not diff.empty:
            write_dataframe(wb, "SW_ASIC_Inventory_Diff", diff)

    # Routers
    rx = rt_x if rt_x is not None else pd.DataFrame()
    ry = rt_y if rt_y is not None else pd.DataFrame()
    if not rx.empty:
        write_dataframe(wb, "Router_Inventory_X", rx)
    if not ry.empty:
        write_dataframe(wb, "Router_Inventory_Y", ry)
    if not rx.empty and not ry.empty:
        diff = compare_dataframes(rx, ry, ["Node GUID"],
                                   ["Router Name", "Firmware Version"],
                                   "New Router", "Disappeared Router")
        if not diff.empty:
            write_dataframe(wb, "Router_Inventory_Diff", diff)

    # PSU
    if not psu_x.empty:
        write_dataframe(wb, "PSU_Inventory_X", psu_x)
    if not psu_y.empty:
        write_dataframe(wb, "PSU_Inventory_Y", psu_y)
    if not psu_x.empty and not psu_y.empty:
        diff = compare_dataframes(psu_x, psu_y, ["Node GUID", "PSU Index"],
                                   ["PSU DC State", "PSU Alert State", "PSU Fan State", "PSU Present"],
                                   "New PSU", "Disappeared PSU")
        if not diff.empty:
            write_dataframe(wb, "PSU_Inventory_Diff", diff)

    # Temperature
    if not temp_x.empty:
        write_dataframe(wb, "SW_Temp_Sensor_X", temp_x)
    if not temp_y.empty:
        write_dataframe(wb, "SW_Temp_Sensor_Y", temp_y)
    _write_switch_temp_summary_pair(wb, temp_x, temp_y)
    if not temp_x.empty and not temp_y.empty:
        diff = _build_switch_temp_diff(temp_x, temp_y)
        if not diff.empty:
            write_dataframe(wb, "SW_Temp_Sensor_Diff", diff)

    # HCA
    if not hca_x.empty:
        write_dataframe(wb, "HCA_Inventory_X", hca_x)
    if not hca_y.empty:
        write_dataframe(wb, "HCA_Inventory_Y", hca_y)
    if not hca_x.empty and not hca_y.empty:
        diff = compare_dataframes(hca_x, hca_y, ["Node GUID"],
                                   ["Hostname", "Port Name", "Firmware Version"],
                                   "New HCA", "Disappeared HCA")
        if not diff.empty:
            write_dataframe(wb, "HCA_Inventory_Diff", diff)
    _write_hca_temp_summary_pair(wb, hca_x, hca_y)
    hca_temp_diff = _build_hca_temp_diff(hca_x, hca_y)
    if not hca_temp_diff.empty:
        write_dataframe(wb, "HCA_Temp_Sensor_Diff", hca_temp_diff)

    # Cable — compare transceiver inventory (unique by SN, Src+Dst combined).
    if not cable_x.empty:
        write_dataframe(wb, "Cable_Inventory_X", cable_x)
    if not cable_y.empty:
        write_dataframe(wb, "Cable_Inventory_Y", cable_y)
    if not cable_x.empty and not cable_y.empty:
        diff = _compare_transceivers(cable_x, cable_y)
        if not diff.empty:
            write_dataframe(wb, "Cable_Inventory_Diff", diff)
    _write_cable_temp_summary_pair(wb, cable_x, cable_y)
    cable_temp_diff = _build_cable_temp_diff(cable_x, cable_y)
    if not cable_temp_diff.empty:
        write_dataframe(wb, "Cable_Temp_Sensor_Diff", cable_temp_diff)

    wb.close()
    print(f"\nExcel report written: {output_path}")


# ─── Internal comparison helpers ─────────────────────────────────────────────


_XCVR_COLS = [
    "Src Transceiver Vendor",
    "Src Transceiver PN",
    "Src Transceiver SN",
    "Src Transceiver Rev",
    "Src Transceiver FW",
]


def _transceiver_set(cable_df: pd.DataFrame) -> pd.DataFrame:
    """Unique transceivers (by SN) from both Src/Dst ends of a Cable_Inventory.

    Output columns match `_XCVR_COLS` (prefixed `Src Transceiver …` form), so
    the comparison-mode diff can outer-merge X and Y on `Src Transceiver SN`
    while preserving the source schema.
    """
    return combine_transceivers(
        cable_df,
        columns=("Vendor", "PN", "SN", "Rev", "FW"),
        prefix=True,
    )


def _compare_transceivers(cable_x: pd.DataFrame, cable_y: pd.DataFrame) -> pd.DataFrame:
    """Diff transceiver inventory between two snapshots, keyed by SN.

    Output columns: `_XCVR_COLS` + New Transceiver / Disappeared Transceiver /
    Changed. A row is kept only if it is new, disappeared, or has a changed
    Rev or FW value.
    """
    set_x = _transceiver_set(cable_x)
    set_y = _transceiver_set(cable_y)
    if set_x.empty and set_y.empty:
        return pd.DataFrame()

    merged = set_x.merge(
        set_y, on="Src Transceiver SN", how="outer",
        suffixes=("_x", "_y"), indicator=True,
    )

    def _diff(base: str) -> pd.Series:
        cx, cy = f"{base}_x", f"{base}_y"
        return (
            merged[cx].fillna("").astype(str).str.strip()
            != merged[cy].fillna("").astype(str).str.strip()
        )

    both = merged["_merge"] == "both"
    new = merged["_merge"] == "right_only"
    gone = merged["_merge"] == "left_only"
    changed = both & (_diff("Src Transceiver Rev") | _diff("Src Transceiver FW"))

    keep = new | gone | changed
    if not keep.any():
        return pd.DataFrame()

    kept = merged.loc[keep].reset_index(drop=True)

    # Coalesce identity/version columns: prefer Y (current), fall back to X.
    def _coalesce(base: str) -> pd.Series:
        return kept[f"{base}_y"].combine_first(kept[f"{base}_x"])

    out = pd.DataFrame({
        "Src Transceiver Vendor": _coalesce("Src Transceiver Vendor"),
        "Src Transceiver PN": _coalesce("Src Transceiver PN"),
        "Src Transceiver SN": kept["Src Transceiver SN"],
        "Src Transceiver Rev": _coalesce("Src Transceiver Rev"),
        "Src Transceiver FW": _coalesce("Src Transceiver FW"),
        "New Transceiver": (kept["_merge"] == "right_only").map({True: "Yes", False: ""}),
        "Disappeared Transceiver": (kept["_merge"] == "left_only").map({True: "Yes", False: ""}),
        "Changed": (changed.loc[keep].reset_index(drop=True)).map({True: "Yes", False: ""}),
    })
    return out


def _find_changed(
    dx: pd.DataFrame, dy: pd.DataFrame, key: str, cols: list[str]
) -> pd.DataFrame:
    if dx.empty or dy.empty:
        return pd.DataFrame()
    avail = [c for c in cols if c in dx.columns and c in dy.columns]
    merged = dx.merge(dy, on=key, suffixes=("_x", "_y"))
    mask = pd.Series(False, index=merged.index)
    for c in avail:
        mask |= merged[f"{c}_x"].fillna("").astype(str) != merged[f"{c}_y"].fillna("").astype(str)
    return merged[mask]


def _print_psu_summary(label: str, df: pd.DataFrame) -> None:
    print(f"\n  {label}:")
    if df.empty:
        print(f"    (no data)")
        return
    present = df[df["PSU Present"] == "Yes"]
    good = present[(present["PSU DC State"] == "OK") & (present["PSU Fan State"] == "OK")]
    bad = present[~((present["PSU DC State"] == "OK") & (present["PSU Fan State"] == "OK"))]
    _summary_line("Total PSUs", len(present))
    _summary_line("Good", len(good))
    _summary_line("Bad", len(bad))


def _psu_compare(psu_x: pd.DataFrame, psu_y: pd.DataFrame) -> pd.DataFrame:
    """Build a PSU diff DataFrame with New PSU / Became Good / Became Bad columns."""
    merged = psu_x.merge(psu_y, on=["Node GUID", "PSU Index"], how="outer",
                          suffixes=("_x", "_y"))

    def _good(dc, fan):
        return str(dc) == "OK" and str(fan) == "OK"

    rows = []
    for _, r in merged.iterrows():
        in_x = pd.notna(r.get("PSU DC State_x"))
        in_y = pd.notna(r.get("PSU DC State_y"))
        good_x = _good(r.get("PSU DC State_x", ""), r.get("PSU Fan State_x", ""))
        good_y = _good(r.get("PSU DC State_y", ""), r.get("PSU Fan State_y", ""))
        if not in_x and in_y:
            rows.append({**r.to_dict(), "New PSU": "Yes", "Became Good": "", "Became Bad": ""})
        elif in_x and not in_y:
            rows.append({**r.to_dict(), "New PSU": "", "Became Good": "", "Became Bad": ""})
        elif not good_x and good_y:
            rows.append({**r.to_dict(), "New PSU": "", "Became Good": "Yes", "Became Bad": ""})
        elif good_x and not good_y:
            rows.append({**r.to_dict(), "New PSU": "", "Became Good": "", "Became Bad": "Yes"})

    return pd.DataFrame(rows) if rows else pd.DataFrame()


def _write_switch_temp_summary_pair(
    wb: xlsxwriter.Workbook, temp_x: pd.DataFrame, temp_y: pd.DataFrame,
) -> None:
    """Write SW_Temp_Summary_X / _Y on a joint bin axis."""
    if temp_x.empty and temp_y.empty:
        return
    cur_x = pd.to_numeric(temp_x.get("Current Temperature"), errors="coerce") if not temp_x.empty else pd.Series(dtype=float)
    max_x = pd.to_numeric(temp_x.get("Max Temperature"), errors="coerce") if not temp_x.empty else pd.Series(dtype=float)
    cur_y = pd.to_numeric(temp_y.get("Current Temperature"), errors="coerce") if not temp_y.empty else pd.Series(dtype=float)
    max_y = pd.to_numeric(temp_y.get("Max Temperature"), errors="coerce") if not temp_y.empty else pd.Series(dtype=float)
    lo, hi = joint_temp_range(cur_x, max_x, cur_y, max_y)
    if lo is None:
        return
    if not temp_x.empty:
        write_temp_histogram(
            wb, "SW_Temp_Summary_X",
            _build_switch_hist(temp_x, lo=lo, hi=hi),
            title="Switch Temperature Distribution (X)",
            value_cols=["Current", "Max"],
        )
    if not temp_y.empty:
        write_temp_histogram(
            wb, "SW_Temp_Summary_Y",
            _build_switch_hist(temp_y, lo=lo, hi=hi),
            title="Switch Temperature Distribution (Y)",
            value_cols=["Current", "Max"],
        )


def _write_hca_temp_summary_pair(
    wb: xlsxwriter.Workbook, hca_x: pd.DataFrame, hca_y: pd.DataFrame,
) -> None:
    """Write HCA_Temp_Summary_X / _Y on a joint bin axis."""
    s_x = _hca_temp_series(hca_x)
    s_y = _hca_temp_series(hca_y)
    lo, hi = joint_temp_range(s_x, s_y)
    if lo is None:
        return
    if not s_x.empty:
        write_temp_histogram(
            wb, "HCA_Temp_Summary_X",
            bin_temperatures(s_x, lo=lo, hi=hi).rename(columns={"Qty": "Count"}),
            title="HCA Temperature Distribution (X)",
            value_cols=["Count"],
        )
    if not s_y.empty:
        write_temp_histogram(
            wb, "HCA_Temp_Summary_Y",
            bin_temperatures(s_y, lo=lo, hi=hi).rename(columns={"Qty": "Count"}),
            title="HCA Temperature Distribution (Y)",
            value_cols=["Count"],
        )


def _write_cable_temp_summary_pair(
    wb: xlsxwriter.Workbook, cable_x: pd.DataFrame, cable_y: pd.DataFrame,
) -> None:
    """Write Cable_Temp_Summary_X / _Y on a joint bin axis."""
    s_x = combine_transceiver_temps(cable_x)
    s_y = combine_transceiver_temps(cable_y)
    lo, hi = joint_temp_range(s_x, s_y)
    if lo is None:
        return
    if not s_x.empty:
        write_temp_histogram(
            wb, "Cable_Temp_Summary_X",
            bin_temperatures(s_x, lo=lo, hi=hi).rename(columns={"Qty": "Count"}),
            title="Transceiver Temperature Distribution (X)",
            value_cols=["Count"],
        )
    if not s_y.empty:
        write_temp_histogram(
            wb, "Cable_Temp_Summary_Y",
            bin_temperatures(s_y, lo=lo, hi=hi).rename(columns={"Qty": "Count"}),
            title="Transceiver Temperature Distribution (Y)",
            value_cols=["Count"],
        )


def _build_switch_temp_diff(temp_x: pd.DataFrame, temp_y: pd.DataFrame) -> pd.DataFrame:
    """SW_Temp_Sensor_Diff with cleaned columns: no Switch Name_y / ASIC_y / Alert_x / Alert_y.

    Filter: New, Disappeared, or Max Temperature mismatch (existing change-col logic).
    """
    if temp_x.empty or temp_y.empty:
        return pd.DataFrame()
    merged = temp_x.merge(
        temp_y, on="Node GUID", how="outer",
        suffixes=("_x", "_y"), indicator=True,
    )
    new = merged["_merge"] == "right_only"
    gone = merged["_merge"] == "left_only"
    both = merged["_merge"] == "both"
    mx_diff = pd.Series(False, index=merged.index)
    if "Max Temperature_x" in merged.columns and "Max Temperature_y" in merged.columns:
        mxa = pd.to_numeric(merged["Max Temperature_x"], errors="coerce").fillna(float("nan"))
        mxb = pd.to_numeric(merged["Max Temperature_y"], errors="coerce").fillna(float("nan"))
        mx_diff = (mxa.notna() | mxb.notna()) & (mxa.fillna(-1) != mxb.fillna(-1))
    keep = new | gone | (both & mx_diff)
    if not keep.any():
        return pd.DataFrame()
    kept = merged.loc[keep].reset_index(drop=True)
    out = pd.DataFrame({
        "Node GUID": kept["Node GUID"],
        "Switch Name": kept["Switch Name_y"].combine_first(kept["Switch Name_x"]),
        "ASIC": kept["ASIC_y"].combine_first(kept["ASIC_x"]),
        "Current Temperature_x": kept["Current Temperature_x"],
        "Max Temperature_x": kept["Max Temperature_x"],
        "Current Temperature_y": kept["Current Temperature_y"],
        "Max Temperature_y": kept["Max Temperature_y"],
        "New": (kept["_merge"] == "right_only").map({True: "Yes", False: ""}),
        "Disappeared": (kept["_merge"] == "left_only").map({True: "Yes", False: ""}),
        "Changed": (mx_diff.loc[keep].reset_index(drop=True) & (kept["_merge"] == "both")).map({True: "Yes", False: ""}),
    })
    return out


def _build_hca_temp_diff(hca_x: pd.DataFrame, hca_y: pd.DataFrame) -> pd.DataFrame:
    """HCA_Temp_Sensor_Diff: New / Disappeared / Changed (≥ TEMP_CHANGE_THRESHOLD °C delta).

    Cleaned cols — no _y duplicates of identity (Hostname, Port Name).
    """
    if hca_x.empty or hca_y.empty:
        return pd.DataFrame()
    keep_cols = ["Node GUID", "Hostname", "Port Name", "Current Temperature"]
    kx = hca_x[[c for c in keep_cols if c in hca_x.columns]].copy()
    ky = hca_y[[c for c in keep_cols if c in hca_y.columns]].copy()
    merged = kx.merge(
        ky, on="Node GUID", how="outer",
        suffixes=("_x", "_y"), indicator=True,
    )
    tx = pd.to_numeric(merged.get("Current Temperature_x"), errors="coerce")
    ty = pd.to_numeric(merged.get("Current Temperature_y"), errors="coerce")
    both = merged["_merge"] == "both"
    new = merged["_merge"] == "right_only"
    gone = merged["_merge"] == "left_only"
    delta = (tx - ty).abs()
    changed = both & delta.ge(TEMP_CHANGE_THRESHOLD).fillna(False)
    keep = new | gone | changed
    if not keep.any():
        return pd.DataFrame()
    kept = merged.loc[keep].reset_index(drop=True)
    out = pd.DataFrame({
        "Node GUID": kept["Node GUID"],
        "Hostname": kept.get("Hostname_y", pd.Series([pd.NA] * len(kept))).combine_first(kept.get("Hostname_x", pd.Series([pd.NA] * len(kept)))),
        "Port Name": kept.get("Port Name_y", pd.Series([pd.NA] * len(kept))).combine_first(kept.get("Port Name_x", pd.Series([pd.NA] * len(kept)))),
        "Current Temperature_x": kept.get("Current Temperature_x"),
        "Current Temperature_y": kept.get("Current Temperature_y"),
        "New": (kept["_merge"] == "right_only").map({True: "Yes", False: ""}),
        "Disappeared": (kept["_merge"] == "left_only").map({True: "Yes", False: ""}),
        "Changed": (changed.loc[keep].reset_index(drop=True)).map({True: "Yes", False: ""}),
    })
    return out


def _build_cable_temp_diff(cable_x: pd.DataFrame, cable_y: pd.DataFrame) -> pd.DataFrame:
    """Cable_Temp_Sensor_Diff keyed by SN.

    Filter: New, Disappeared, or |Temp_y - Temp_x| ≥ TEMP_CHANGE_THRESHOLD.
    Cleaned cols — no _y duplicates of identity (Vendor, PN).
    """
    if cable_x.empty or cable_y.empty:
        return pd.DataFrame()
    set_x = combine_transceivers(cable_x, columns=("Vendor", "PN", "SN", "Temp."))
    set_y = combine_transceivers(cable_y, columns=("Vendor", "PN", "SN", "Temp."))
    if set_x.empty and set_y.empty:
        return pd.DataFrame()
    merged = set_x.merge(
        set_y, on="SN", how="outer",
        suffixes=("_x", "_y"), indicator=True,
    )
    tx = pd.to_numeric(merged.get("Temp._x"), errors="coerce")
    ty = pd.to_numeric(merged.get("Temp._y"), errors="coerce")
    both = merged["_merge"] == "both"
    new = merged["_merge"] == "right_only"
    gone = merged["_merge"] == "left_only"
    delta = (tx - ty).abs()
    changed = both & delta.ge(TEMP_CHANGE_THRESHOLD).fillna(False)
    keep = new | gone | changed
    if not keep.any():
        return pd.DataFrame()
    kept = merged.loc[keep].reset_index(drop=True)
    out = pd.DataFrame({
        "Src Transceiver Vendor": kept["Vendor_y"].combine_first(kept["Vendor_x"]),
        "Src Transceiver PN": kept["PN_y"].combine_first(kept["PN_x"]),
        "Src Transceiver SN": kept["SN"],
        "Temp._x": kept["Temp._x"],
        "Temp._y": kept["Temp._y"],
        "New Transceiver": (kept["_merge"] == "right_only").map({True: "Yes", False: ""}),
        "Disappeared Transceiver": (kept["_merge"] == "left_only").map({True: "Yes", False: ""}),
        "Changed": (changed.loc[keep].reset_index(drop=True)).map({True: "Yes", False: ""}),
    })
    return out


def _print_switch_temp_compare(temp_x: pd.DataFrame, temp_y: pd.DataFrame) -> None:
    """Side-by-side histogram for Switch Current+Max temps (joint bin axis)."""
    cur_x = pd.to_numeric(temp_x.get("Current Temperature"), errors="coerce") if not temp_x.empty else pd.Series(dtype=float)
    max_x = pd.to_numeric(temp_x.get("Max Temperature"), errors="coerce") if not temp_x.empty else pd.Series(dtype=float)
    cur_y = pd.to_numeric(temp_y.get("Current Temperature"), errors="coerce") if not temp_y.empty else pd.Series(dtype=float)
    max_y = pd.to_numeric(temp_y.get("Max Temperature"), errors="coerce") if not temp_y.empty else pd.Series(dtype=float)
    lo, hi = joint_temp_range(cur_x, max_x, cur_y, max_y)
    if lo is None:
        return
    cx = bin_temperatures(cur_x, lo=lo, hi=hi)
    mx = bin_temperatures(max_x, lo=lo, hi=hi)
    cy = bin_temperatures(cur_y, lo=lo, hi=hi)
    my = bin_temperatures(max_y, lo=lo, hi=hi)
    rows = [
        (cx.iloc[i]["Bin Label"], [
            int(cx.iloc[i]["Qty"]), int(cy.iloc[i]["Qty"]),
            int(mx.iloc[i]["Qty"]), int(my.iloc[i]["Qty"]),
        ])
        for i in range(len(cx))
    ]
    _histogram_table(["Cur X", "Cur Y", "Max X", "Max Y"], rows)


def _print_xy_temp_compare(s_x: pd.Series, s_y: pd.Series) -> None:
    """Side-by-side histogram for two single-metric temp Series (HCA / Transceiver)."""
    lo, hi = joint_temp_range(s_x, s_y)
    if lo is None:
        return
    bx = bin_temperatures(s_x, lo=lo, hi=hi)
    by = bin_temperatures(s_y, lo=lo, hi=hi)
    rows = [
        (bx.iloc[i]["Bin Label"], [int(bx.iloc[i]["Qty"]), int(by.iloc[i]["Qty"])])
        for i in range(len(bx))
    ]
    _histogram_table(["X", "Y"], rows)


def _verbose_rows(title: str, df: pd.DataFrame, cols: list[str]) -> None:
    if df.empty:
        return
    avail = [c for c in cols if c in df.columns]
    print(f"\n  {title}:")
    for _, row in df[avail].iterrows():
        parts = "  |  ".join(f"{c}: {row[c]}" for c in avail)
        print(f"    {parts}")


# ─── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    args = parse_args()

    ibdir = Path(args.ibdiagnet)
    if not ibdir.is_dir():
        sys.exit(f"ERROR: ibdiagnet folder not found: {ibdir}")

    output = Path(args.output)

    print(f"Loading snapshot X: {ibdir} ...")
    sw_x = build_switch_inventory(ibdir)
    rt_x = build_router_inventory(ibdir)
    psu_x = build_psu_inventory(ibdir)
    temp_x = build_temp_inventory(ibdir)
    hca_x = build_hca_inventory(ibdir)
    cable_x = build_cable_inventory(ibdir)

    if args.compare:
        ibdir_y = Path(args.compare)
        if not ibdir_y.is_dir():
            sys.exit(f"ERROR: compare folder not found: {ibdir_y}")

        print(f"Loading snapshot Y: {ibdir_y} ...")
        sw_y = build_switch_inventory(ibdir_y)
        rt_y = build_router_inventory(ibdir_y)
        psu_y = build_psu_inventory(ibdir_y)
        temp_y = build_temp_inventory(ibdir_y)
        hca_y = build_hca_inventory(ibdir_y)
        cable_y = build_cable_inventory(ibdir_y)

        comparison_cli(sw_x, sw_y, rt_x, rt_y, psu_x, psu_y, temp_x, temp_y,
                       hca_x, hca_y, cable_x, cable_y, verbose=args.verbose)
        comparison_excel(output, sw_x, sw_y, rt_x, rt_y, psu_x, psu_y,
                          temp_x, temp_y, hca_x, hca_y, cable_x, cable_y)
    else:
        single_snapshot_cli(ibdir, sw_x, rt_x, psu_x, temp_x, hca_x, cable_x)
        single_snapshot_excel(output, sw_x, rt_x, psu_x, temp_x, hca_x, cable_x)


if __name__ == "__main__":
    main()
