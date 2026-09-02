#!/usr/bin/env python3
"""
check_ib_link_errors.py — Analyse IB link errors from ibdiagnet2 dumps.

Single-snapshot mode:
    python scripts/check_ib_link_errors.py -i <ibdiagnet_folder> -o <output.xlsx>

Two-snapshot comparison mode:
    python scripts/check_ib_link_errors.py -i <ibdiagnet_folder_X> \
        --compare <ibdiagnet_folder_Y> -o <output.xlsx> [--verbose]
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
from lib.link_errors import (
    SYM_BER_THRESHOLD,
    EFF_BER_THRESHOLD,
    TEMP_THRESHOLD,
    build_all_links,
    build_flapped_links,
    build_high_ber_links,
    build_high_temp_links,
    build_ini_links,
    build_plane_faulty_links,
    build_fnm_links,
    build_brief_links,
    compare_flapped,
    compare_high_ber,
)


# ─── CLI ─────────────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Analyse IB link errors from ibdiagnet2 dumps"
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
    # NOTE: Raw BER check disabled — not used for flagging for now.
    # To re-enable, import RAW_BER_THRESHOLD from lib.link_errors and uncomment:
    # p.add_argument(
    #     "--raw-ber",
    #     type=float,
    #     default=RAW_BER_THRESHOLD,
    #     metavar="THRESHOLD",
    #     help=f"Raw BER threshold (default: {RAW_BER_THRESHOLD})",
    # )
    p.add_argument(
        "--sym-ber",
        type=float,
        default=SYM_BER_THRESHOLD,
        metavar="THRESHOLD",
        help=f"Symbol BER threshold (default: {SYM_BER_THRESHOLD})",
    )
    p.add_argument(
        "--eff-ber",
        type=float,
        default=EFF_BER_THRESHOLD,
        metavar="THRESHOLD",
        help=f"Effective BER threshold (default: {EFF_BER_THRESHOLD})",
    )
    p.add_argument(
        "--temp",
        type=float,
        default=TEMP_THRESHOLD,
        metavar="CELSIUS",
        help=f"Transceiver temperature threshold in °C (default: {TEMP_THRESHOLD})",
    )
    return p.parse_args()


# ─── CLI output helpers ───────────────────────────────────────────────────────

from lib.reporting import (
    count_line as _summary_line,
    section as _section_full,
    write_sheets,
)


def _section(title: str) -> None:
    """Plain-divider section header (no Total)."""
    _section_full(title)


def _verbose_link_rows(title: str, df: pd.DataFrame) -> None:
    """Print link rows in 'Src Device / Src Port  →  Dst Device / Dst Port' format."""
    if df.empty:
        return
    print(f"\n  {title}:")
    src_dev = "Src Device" if "Src Device" in df.columns else None
    src_port = "Src Port" if "Src Port" in df.columns else None
    dst_dev = "Dst Device" if "Dst Device" in df.columns else None
    dst_port = "Dst Port" if "Dst Port" in df.columns else None

    for _, row in df.iterrows():
        sd = row[src_dev] if src_dev else "?"
        sp = row[src_port] if src_port else "?"
        dd = row[dst_dev] if dst_dev else "?"
        dp = row[dst_port] if dst_port else "?"
        print(f"    {sd} / {sp}  →  {dd} / {dp}")


# ─── Single-snapshot output ───────────────────────────────────────────────────


def single_snapshot_cli(
    flapped_brief: pd.DataFrame,
    high_ber_brief: pd.DataFrame,
    high_temp_brief: pd.DataFrame,
    ini_brief: pd.DataFrame,
    plane_faulty_brief: pd.DataFrame,
) -> None:
    _section("Flapped Links")
    _summary_line("Total", len(flapped_brief))
    if not flapped_brief.empty:
        ber_count = int((flapped_brief.get("High_BER", pd.Series()) == "Yes").sum())
        temp_count = int((flapped_brief.get("High_Temp", pd.Series()) == "Yes").sum())
        _summary_line("High BER marked", ber_count)
        _summary_line("High Temp. marked", temp_count)

    _section("High BER Links")
    _summary_line("Total", len(high_ber_brief))

    _section("High Temp. Links")
    _summary_line("Total", len(high_temp_brief))

    _section("INI Links")
    _summary_line("Total", len(ini_brief))

    if not plane_faulty_brief.empty:
        _section("XDR Plane Faulty Links")
        _summary_line("Total", len(plane_faulty_brief))


def single_snapshot_excel(
    output_path: Path,
    all_links: pd.DataFrame,
    flapped: pd.DataFrame,
    high_ber: pd.DataFrame,
    high_temp: pd.DataFrame,
    ini: pd.DataFrame,
    plane_faulty: pd.DataFrame,
    fnm: pd.DataFrame,
    flapped_brief: pd.DataFrame,
    high_ber_brief: pd.DataFrame,
    high_temp_brief: pd.DataFrame,
    ini_brief: pd.DataFrame,
    plane_faulty_brief: pd.DataFrame,
) -> None:
    wb = xlsxwriter.Workbook(str(output_path))
    write_sheets(wb, [
        ("Flapped_Links",            flapped,            False),
        ("High_BER_Links",           high_ber,           False),
        ("High_Temp_Links",          high_temp,          False),
        ("INI_Links",                ini,                False),
        ("All_Links",                all_links,          False),
        ("Plane_Faulty_Links",       plane_faulty,       False),
        ("FNM_Links",                fnm,                False),
        ("Flapped_Links_Brief",      flapped_brief,      False),
        ("High_BER_Links_Brief",     high_ber_brief,     False),
        ("High_Temp_Links_Brief",    high_temp_brief,    False),
        ("INI_Links_Brief",          ini_brief,          False),
        ("Plane_Faulty_Links_Brief", plane_faulty_brief, False),
    ])
    wb.close()
    print(f"\nExcel report written: {output_path}")


# ─── Comparison output ────────────────────────────────────────────────────────


def _link_keys(df: pd.DataFrame) -> set:
    """Extract unique logical link keys (Src Device, Src Port) from a DataFrame."""
    if df.empty or "Src Device" not in df.columns:
        return set()
    return set(zip(df["Src Device"], df["Src Port"]))


def comparison_cli(
    all_x: pd.DataFrame, all_y: pd.DataFrame,
    flapped_x: pd.DataFrame, flapped_y: pd.DataFrame,
    high_ber_x: pd.DataFrame, high_ber_y: pd.DataFrame,
    high_temp_x: pd.DataFrame, high_temp_y: pd.DataFrame,
    ini_x: pd.DataFrame, ini_y: pd.DataFrame,
    plane_x: pd.DataFrame, plane_y: pd.DataFrame,
    flapped_diff: pd.DataFrame, ber_diff: pd.DataFrame,
    verbose: bool,
) -> None:
    # Flapped
    _section("Flapped Links (Y > X)")
    keys_x = _link_keys(flapped_x)
    keys_y = _link_keys(flapped_y)
    _summary_line("Snapshot X", len(keys_x))
    _summary_line("Snapshot Y", len(keys_y))
    _summary_line("New flapped links", len(keys_y - keys_x))

    # Stop flapping: flapping in X AND present in Y, with BOTH Src LinkDowned
    # AND Dst LinkDowned unchanged between snapshots (no new flap events on
    # either end). Keep flapping: same link with at least one side's
    # LinkDowned strictly higher in Y. Both counted at the logical-link
    # level, not per plane.
    stop_flap = keep_flap = 0
    both_keys = keys_x & keys_y
    ld_cols = ("Src LinkDowned", "Dst LinkDowned")
    if both_keys and all(c in flapped_x.columns and c in flapped_y.columns for c in ld_cols):
        x_dedup = flapped_x.drop_duplicates(subset=["Src Device", "Src Port"]).set_index(["Src Device", "Src Port"])
        y_dedup = flapped_y.drop_duplicates(subset=["Src Device", "Src Port"]).set_index(["Src Device", "Src Port"])
        x_src = x_dedup["Src LinkDowned"].to_dict()
        x_dst = x_dedup["Dst LinkDowned"].to_dict()
        y_src = y_dedup["Src LinkDowned"].to_dict()
        y_dst = y_dedup["Dst LinkDowned"].to_dict()
        for k in both_keys:
            xs, ys = x_src.get(k), y_src.get(k)
            xd, yd = x_dst.get(k), y_dst.get(k)
            if not (pd.notna(xs) and pd.notna(ys)):
                continue
            src_incr = float(ys) > float(xs)
            dst_incr = pd.notna(xd) and pd.notna(yd) and float(yd) > float(xd)
            src_same = float(ys) == float(xs)
            dst_same = (not pd.notna(xd) and not pd.notna(yd)) or (
                pd.notna(xd) and pd.notna(yd) and float(yd) == float(xd)
            )
            if src_incr or dst_incr:
                keep_flap += 1
            elif src_same and dst_same:
                stop_flap += 1
    _summary_line("Stop flapping links", stop_flap)
    _summary_line("Keep flapping", keep_flap)

    if verbose and not flapped_diff.empty and "Change" in flapped_diff.columns:
        _verbose_link_rows("New flapped links",
                           flapped_diff[flapped_diff["Change"] == "New"])

    # High BER
    _section("High BER Links")
    ber_kx = _link_keys(high_ber_x)
    ber_ky = _link_keys(high_ber_y)
    _summary_line("Snapshot X", len(ber_kx))
    _summary_line("Snapshot Y", len(ber_ky))
    _summary_line("New BER links", len(ber_ky - ber_kx))
    _summary_line("Disappeared BER links", len(ber_kx - ber_ky))
    _summary_line("BER links (no change)", len(ber_kx & ber_ky))

    if verbose and not ber_diff.empty and "Change" in ber_diff.columns:
        _verbose_link_rows("New high BER links",
                           ber_diff[ber_diff["Change"] == "New"])

    # High Temp
    _section("High Temp. Links")
    temp_kx = _link_keys(high_temp_x)
    temp_ky = _link_keys(high_temp_y)
    _summary_line("Snapshot X", len(temp_kx))
    _summary_line("Snapshot Y", len(temp_ky))
    _summary_line("New high-temp links", len(temp_ky - temp_kx))
    _summary_line("Disappeared high-temp links", len(temp_kx - temp_ky))
    _summary_line("High-temp links (no change)", len(temp_kx & temp_ky))

    # INI
    _section("INI Links")
    ini_kx = _link_keys(ini_x)
    ini_ky = _link_keys(ini_y)
    _summary_line("Snapshot X", len(ini_kx))
    _summary_line("Snapshot Y", len(ini_ky))
    _summary_line("New INI links", len(ini_ky - ini_kx))
    _summary_line("Disappeared INI links", len(ini_kx - ini_ky))
    _summary_line("INI links (no change)", len(ini_kx & ini_ky))

    # Plane Faulty
    if not plane_x.empty or not plane_y.empty:
        _section("XDR Plane Faulty Links")
        pf_kx = _link_keys(plane_x)
        pf_ky = _link_keys(plane_y)
        _summary_line("Snapshot X", len(pf_kx))
        _summary_line("Snapshot Y", len(pf_ky))
        _summary_line("New Plane Faulty links", len(pf_ky - pf_kx))
        _summary_line("Disappeared Plane Faulty links", len(pf_kx - pf_ky))
        _summary_line("Plane Faulty links (no change)", len(pf_kx & pf_ky))

    print()
    print("  Note: Comparison results may be inaccurate if IB counters were "
          "cleared between the two snapshots.")


def comparison_excel(
    output_path: Path,
    all_x: pd.DataFrame, all_y: pd.DataFrame,
    flapped_x: pd.DataFrame, flapped_y: pd.DataFrame,
    flapped_diff: pd.DataFrame,
    high_ber_x: pd.DataFrame, high_ber_y: pd.DataFrame,
    ber_diff: pd.DataFrame,
    high_temp_x: pd.DataFrame, high_temp_y: pd.DataFrame,
    ini_x: pd.DataFrame, ini_y: pd.DataFrame,
    plane_x: pd.DataFrame, plane_y: pd.DataFrame,
    fnm_x: pd.DataFrame, fnm_y: pd.DataFrame,
    flapped_x_brief: pd.DataFrame, flapped_y_brief: pd.DataFrame,
    high_ber_x_brief: pd.DataFrame, high_ber_y_brief: pd.DataFrame,
    ini_x_brief: pd.DataFrame, ini_y_brief: pd.DataFrame,
    plane_x_brief: pd.DataFrame, plane_y_brief: pd.DataFrame,
) -> None:
    wb = xlsxwriter.Workbook(str(output_path))
    write_sheets(wb, [
        # Flapped
        ("Flapped_X",            flapped_x,        False),
        ("Flapped_Y",            flapped_y,        False),
        ("Flapped_Diff",         flapped_diff,     False),
        # High BER
        ("High_BER_X",           high_ber_x,       False),
        ("High_BER_Y",           high_ber_y,       False),
        ("High_BER_Diff",        ber_diff,         False),
        # High Temp
        ("High_Temp_X",          high_temp_x,      False),
        ("High_Temp_Y",          high_temp_y,      False),
        # INI
        ("INI_X",                ini_x,            False),
        ("INI_Y",                ini_y,            False),
        # All Links
        ("All_Links_X",          all_x,            False),
        ("All_Links_Y",          all_y,            False),
        # Plane Faulty (XDR only)
        ("Plane_Faulty_X",       plane_x,          False),
        ("Plane_Faulty_Y",       plane_y,          False),
        # FNM Links (XDR only)
        ("FNM_X",                fnm_x,            False),
        ("FNM_Y",                fnm_y,            False),
        # Brief summary tables
        ("Flapped_X_Brief",      flapped_x_brief,  False),
        ("Flapped_Y_Brief",      flapped_y_brief,  False),
        ("High_BER_X_Brief",     high_ber_x_brief, False),
        ("High_BER_Y_Brief",     high_ber_y_brief, False),
        ("INI_X_Brief",          ini_x_brief,      False),
        ("INI_Y_Brief",          ini_y_brief,      False),
        ("Plane_Faulty_X_Brief", plane_x_brief,    False),
        ("Plane_Faulty_Y_Brief", plane_y_brief,    False),
    ])
    wb.close()
    print(f"\nExcel report written: {output_path}")


# ─── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    args = parse_args()

    ibdir = Path(args.ibdiagnet)
    if not ibdir.is_dir():
        sys.exit(f"ERROR: ibdiagnet folder not found: {ibdir}")

    output = Path(args.output)

    # raw_ber = args.raw_ber  # NOTE: Raw BER check disabled for now
    sym_ber = args.sym_ber
    eff_ber = args.eff_ber
    temp = args.temp

    print(f"Loading snapshot X: {ibdir} ...")
    all_x = build_all_links(ibdir,
                             # raw_ber_threshold=raw_ber,
                             sym_ber_threshold=sym_ber,
                             eff_ber_threshold=eff_ber,
                             temp_threshold=temp)
    flapped_x = build_flapped_links(all_x)
    high_ber_x = build_high_ber_links(all_x, sym_ber_threshold=sym_ber, eff_ber_threshold=eff_ber)
    high_temp_x = build_high_temp_links(all_x, temp)
    ini_x = build_ini_links(all_x)
    plane_x = build_plane_faulty_links(ibdir, all_x)
    fnm_x = build_fnm_links(ibdir)
    flapped_x_brief = build_brief_links(flapped_x)
    high_ber_x_brief = build_brief_links(high_ber_x)
    high_temp_x_brief = build_brief_links(high_temp_x)
    ini_x_brief = build_brief_links(ini_x)
    plane_x_brief = build_brief_links(plane_x)

    if args.compare:
        ibdir_y = Path(args.compare)
        if not ibdir_y.is_dir():
            sys.exit(f"ERROR: compare folder not found: {ibdir_y}")

        print(f"Loading snapshot Y: {ibdir_y} ...")
        all_y = build_all_links(ibdir_y,
                                 # raw_ber_threshold=raw_ber,
                                 sym_ber_threshold=sym_ber,
                                 eff_ber_threshold=eff_ber,
                                 temp_threshold=temp)
        flapped_y = build_flapped_links(all_y)
        high_ber_y = build_high_ber_links(all_y, sym_ber_threshold=sym_ber, eff_ber_threshold=eff_ber)
        high_temp_y = build_high_temp_links(all_y, temp)
        ini_y = build_ini_links(all_y)
        plane_y = build_plane_faulty_links(ibdir_y, all_y)
        fnm_y = build_fnm_links(ibdir_y)
        flapped_y_brief = build_brief_links(flapped_y)
        high_ber_y_brief = build_brief_links(high_ber_y)
        high_temp_y_brief = build_brief_links(high_temp_y)
        ini_y_brief = build_brief_links(ini_y)
        plane_y_brief = build_brief_links(plane_y)

        flapped_diff = compare_flapped(flapped_x, flapped_y)
        ber_diff = compare_high_ber(high_ber_x, high_ber_y)

        comparison_cli(
            all_x, all_y,
            flapped_x, flapped_y,
            high_ber_x, high_ber_y,
            high_temp_x, high_temp_y,
            ini_x, ini_y,
            plane_x, plane_y,
            flapped_diff, ber_diff,
            verbose=args.verbose,
        )
        comparison_excel(
            output,
            all_x, all_y,
            flapped_x, flapped_y, flapped_diff,
            high_ber_x, high_ber_y, ber_diff,
            high_temp_x, high_temp_y,
            ini_x, ini_y,
            plane_x, plane_y,
            fnm_x, fnm_y,
            flapped_x_brief, flapped_y_brief,
            high_ber_x_brief, high_ber_y_brief,
            ini_x_brief, ini_y_brief,
            plane_x_brief, plane_y_brief,
        )
    else:
        single_snapshot_cli(flapped_x_brief, high_ber_x_brief, high_temp_x_brief, ini_x_brief, plane_x_brief)
        single_snapshot_excel(
            output, all_x, flapped_x, high_ber_x, high_temp_x, ini_x, plane_x,
            fnm_x, flapped_x_brief, high_ber_x_brief, high_temp_x_brief, ini_x_brief, plane_x_brief,
        )


if __name__ == "__main__":
    main()
