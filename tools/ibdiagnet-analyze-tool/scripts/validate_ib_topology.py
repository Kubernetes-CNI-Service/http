#!/usr/bin/env python3
"""Compare an ibdiagnet2 snapshot with a legacy P2P or CVT workbook."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import xlsxwriter

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.excel import write_dataframe
from lib.reporting import count_line, section, write_sheets
from lib.topology import (
    ActualResult,
    CompareResult,
    PlanResult,
    build_actual_links,
    build_actual_links_from_iblinkinfo,
    compare_links,
    device_key,
    is_host_type,
    is_switch_type,
    parse_plan,
    port_key,
)
from lib.snapshot import default_report_path, open_snapshot


DEFAULT_PROFILE_CATALOG = (
    Path(__file__).resolve().parent.parent / "config" / "port_profiles.csv"
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare IB fabric links with a legacy P2P or CVT workbook"
    )
    actual_group = parser.add_mutually_exclusive_group(required=True)
    actual_group.add_argument(
        "-i", "--ibdiagnet", metavar="PATH",
        help="ibdiagnet directory or .tgz/.tar.gz/.tar/.zip archive",
    )
    actual_group.add_argument(
        "--iblinkinfo", metavar="LOG",
        help="text output captured from the iblinkinfo command",
    )
    parser.add_argument("-p", "--p2p", required=True, metavar="FILE")
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="output workbook; archive input defaults beside the archive",
    )
    parser.add_argument(
        "--port-profiles", metavar="CSV", default=str(DEFAULT_PROFILE_CATALOG),
        help="fallback CVT LinkPort-to-physical-port catalog",
    )
    return parser.parse_args(argv)


def _strip_internal(df: pd.DataFrame) -> pd.DataFrame:
    return df.drop(
        columns=["_dst_is_sw", "SrcType", "DstType"], errors="ignore"
    )


def _logical_actual_counts(actual: ActualResult) -> tuple[int, int, int]:
    links = actual.links
    if links.empty:
        return 0, 0, 0
    sw_hca = int((~links["_dst_is_sw"]).sum())
    sw_sw = int(links["_dst_is_sw"].sum()) // 2
    return sw_hca + sw_sw, sw_hca, sw_sw


def _unique_physical_count(df: pd.DataFrame) -> int:
    if df.empty:
        return 0
    keys = set()
    for _, row in df.iterrows():
        a = (device_key(row.get("SrcDevice")), port_key(row.get("SrcPort")))
        z = (device_key(row.get("DstDevice")), port_key(row.get("DstPort")))
        keys.add(tuple(sorted((a, z))))
    return len(keys)


def _plan_counts(plan: PlanResult) -> tuple[int, int, int]:
    links = plan.links
    if links.empty:
        return 0, 0, 0
    sw_hca = int(sum(
        is_switch_type(src) and is_host_type(dst)
        for src, dst in zip(links["SrcType"], links["DstType"])
    ))
    sw_sw = int(sum(
        is_switch_type(src) and is_switch_type(dst)
        for src, dst in zip(links["SrcType"], links["DstType"])
    ))
    return len(links), sw_hca, sw_sw


def _summary_frame(
    actual_input: Path, actual_format: str, p2p_path: Path, output: Path,
    plan: PlanResult, actual: ActualResult, compared: CompareResult,
) -> pd.DataFrame:
    actual_total, actual_sw_hca, actual_sw_sw = _logical_actual_counts(actual)
    plan_total, plan_sw_hca, plan_sw_sw = _plan_counts(plan)
    rows = [
        ("Generated UTC", datetime.now(timezone.utc).isoformat(timespec="seconds"), ""),
        ("Actual Format", actual_format, "auto-detected by analyze.py"),
        ("P2P Format", plan.format_name, "auto-detected"),
        ("P2P Input", str(p2p_path.resolve()), ""),
        ("Actual Input", str(actual_input.resolve()), ""),
        ("Output", str(output.resolve()), ""),
        ("Actual Logical Links", actual_total, "SW-HCA + unique SW-SW"),
        ("Actual SW-HCA", actual_sw_hca, ""),
        ("Actual SW-SW", actual_sw_sw, "unique physical links"),
        ("Actual Plane Faulty", _unique_physical_count(actual.plane_faulty), "unique physical links"),
        ("Actual Unresolved", len(actual.unresolved), "not silently discarded"),
        ("P2P Raw Links", plan.raw_count, "before validation"),
        ("P2P Valid Links", plan_total, "used for comparison"),
        ("P2P SW-HCA", plan_sw_hca, ""),
        ("P2P SW-SW", plan_sw_sw, ""),
        ("P2P Incomplete", len(plan.incomplete), ""),
        ("P2P Duplicates", len(plan.duplicates), "undirected duplicate rows"),
        ("P2P Mapping Failed", len(plan.mapping_failed), ""),
        ("P2P Endpoint Conflicts", len(plan.endpoint_conflicts), "excluded"),
        ("Actual Endpoint Conflicts", len(compared.actual_conflicts), "excluded"),
        ("Matching", len(compared.matching), ""),
        ("Missing", len(compared.missing), "in P2P, not in actual topology"),
        ("Undefined", len(compared.undefined), "in actual topology, not in P2P"),
        ("Miswired", len(compared.miswired), "wrong destination"),
    ]
    return pd.DataFrame(rows, columns=["Metric", "Value", "Notes"])


def write_report(
    output: Path, actual_input: Path, actual_format: str, p2p_path: Path,
    plan: PlanResult, actual: ActualResult, compared: CompareResult,
    actual_details: pd.DataFrame | None = None,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    workbook = xlsxwriter.Workbook(str(output))
    summary = _summary_frame(
        actual_input, actual_format, p2p_path, output, plan, actual, compared
    )
    write_dataframe(workbook, "Summary", summary)
    summary_sheet = workbook.get_worksheet_by_name("Summary")
    summary_sheet.set_column(0, 0, 28)
    summary_sheet.set_column(1, 1, 150)
    summary_sheet.set_column(2, 2, 32)
    sheets = [
        ("IBDGNT_Link_Table", _strip_internal(actual.links), True),
        ("IBDGNT_Unresolved", _strip_internal(actual.unresolved), True),
        ("Plane_Faulty_Links", _strip_internal(actual.plane_faulty), True),
    ]
    if actual_details is not None:
        sheets.append(("IBLinkInfo_Ports", actual_details, True))
    sheets.extend([
        ("P2P_Link_Table", _strip_internal(plan.links), True),
        ("P2P_Incomplete", _strip_internal(plan.incomplete), True),
        ("P2P_Duplicates", _strip_internal(plan.duplicates), True),
        ("P2P_Mapping_Failed", _strip_internal(plan.mapping_failed), True),
        ("P2P_Endpoint_Conflicts", _strip_internal(plan.endpoint_conflicts), True),
        ("Actual_Endpoint_Conflicts", _strip_internal(compared.actual_conflicts), True),
        ("Matching_Links", _strip_internal(compared.matching), True),
        ("Missing_Links", _strip_internal(compared.missing), True),
        ("Undefined_Links", compared.undefined, True),
        ("Miswired_Links", _strip_internal(compared.miswired), True),
    ])
    write_sheets(workbook, sheets)
    workbook.close()


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    actual_input = Path(args.iblinkinfo or args.ibdiagnet).expanduser().resolve()
    actual_format = "iblinkinfo" if args.iblinkinfo else "ibdiagnet"
    p2p_path = Path(args.p2p)
    output = Path(args.output).expanduser().resolve() if args.output else default_report_path(actual_input)
    profile_catalog = Path(args.port_profiles) if args.port_profiles else None
    if not p2p_path.is_file():
        sys.exit(f"ERROR: P2P file not found: {p2p_path}")
    if profile_catalog is not None and not profile_catalog.is_file():
        sys.exit(f"ERROR: port profile catalog not found: {profile_catalog}")

    try:
        actual_details = None
        if args.iblinkinfo:
            print(f"Loading iblinkinfo input: {actual_input} ...")
            actual, actual_details = build_actual_links_from_iblinkinfo(actual_input)
        else:
            print(f"Loading ibdiagnet input: {actual_input} ...")
            with open_snapshot(actual_input) as ibdir:
                print(f"Using ibdiagnet snapshot: {ibdir}")
                actual = build_actual_links(ibdir)
        print(f"Loading P2P/CVT: {p2p_path} ...")
        plan = parse_plan(p2p_path, profile_catalog)
        compared = compare_links(actual.links, plan.links)
        write_report(
            output, actual_input, actual_format, p2p_path, plan, actual,
            compared, actual_details,
        )
    except (OSError, ValueError, KeyError) as exc:
        sys.exit(f"ERROR: {exc}")

    actual_total, actual_sw_hca, actual_sw_sw = _logical_actual_counts(actual)
    section(f"Actual Links ({actual_format})")
    count_line("Total", actual_total)
    count_line("SW-HCA", actual_sw_hca)
    count_line("SW-SW", actual_sw_sw)
    count_line("Plane Faulty physical links", _unique_physical_count(actual.plane_faulty))
    count_line("Unresolved endpoints", len(actual.unresolved))

    plan_total, plan_sw_hca, plan_sw_sw = _plan_counts(plan)
    section(f"P2P Defined Links ({plan.format_name})")
    count_line("Raw", plan.raw_count)
    count_line("Valid", plan_total)
    count_line("SW-HCA", plan_sw_hca)
    count_line("SW-SW", plan_sw_sw)
    count_line("Incomplete", len(plan.incomplete))
    count_line("Duplicates removed", len(plan.duplicates))
    count_line("Port mapping failed", len(plan.mapping_failed))
    count_line("Endpoint conflicts", len(plan.endpoint_conflicts))

    section("Validation Results")
    count_line("Matching", len(compared.matching))
    count_line("Missing", len(compared.missing))
    count_line("Undefined", len(compared.undefined))
    count_line("Miswired", len(compared.miswired))
    count_line("Actual endpoint conflicts", len(compared.actual_conflicts))

    print(f"\nExcel report written: {output}")


if __name__ == "__main__":
    main()
