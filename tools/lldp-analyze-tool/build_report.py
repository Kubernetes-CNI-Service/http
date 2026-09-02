#!/usr/bin/env python3
"""Render a normalized LLDP validation payload as an XLSX workbook."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import xlsxwriter


COLORS = {"green": "#76B900", "dark": "#3A5F00", "white": "#FFFFFF",
          "grid": "#606060", "ok": "#E8F3D6", "warn": "#FFF2CC",
          "error": "#F4CCCC", "orange": "#FCE5CD"}


def value(item):
    if item is None:
        return ""
    if isinstance(item, bool):
        return "Yes" if item else "No"
    return item


def make_formats(workbook):
    border = {"border": 1, "border_color": COLORS["grid"], "valign": "vcenter"}
    return {
        "cell": workbook.add_format(border),
        "wrap": workbook.add_format({**border, "text_wrap": True}),
        "header": workbook.add_format({**border, "bold": True,
            "font_color": COLORS["white"], "bg_color": COLORS["green"],
            "border_color": COLORS["dark"]}),
        **{name: workbook.add_format({"bg_color": color})
           for name, color in COLORS.items() if name in {"ok", "warn", "error", "orange"}},
        "pass": workbook.add_format({"bg_color": COLORS["ok"], "bold": True}),
        "fail": workbook.add_format({"bg_color": COLORS["error"], "bold": True}),
    }


def write_sheet(workbook, fmts, name, headers, rows, *, widths=None,
                wrap_columns=(), status_column=None):
    sheet = workbook.add_worksheet(name)
    sheet.freeze_panes(1, 0)
    sheet.set_row(0, 20)
    for column, header in enumerate(headers):
        sheet.write(0, column, header, fmts["header"])
    for row_index, row in enumerate(rows, start=1):
        for column, item in enumerate(row):
            sheet.write(row_index, column, value(item),
                        fmts["wrap"] if column in wrap_columns else fmts["cell"])
    sheet.autofilter(0, 0, max(1, len(rows)), len(headers) - 1)
    for column, header in enumerate(headers):
        natural = max([len(str(header)), *(len(str(value(row[column]))) for row in rows)]) + 2
        minimum, maximum = (widths or {}).get(column, (10, 42))
        sheet.set_column(column, column, min(max(natural, minimum), maximum))
    if status_column is not None and rows:
        rules = (("CONFIRMED_BOTH_SIDE", "ok"), ("CONFIRMED_SW_SIDE", "ok"),
                 ("DOWN", "error"), ("MISSING_DEVICE", "error"),
                 ("MISSING_INTERFACE", "error"), ("NO_LLDP", "warn"),
                 ("SW_LLDP_PRESENT", "orange"), ("WRONG_PEER", "orange"))
        for text, style in rules:
            sheet.conditional_format(1, status_column, len(rows), status_column, {
                "type": "text", "criteria": "containing", "value": text,
                "format": fmts[style]})


def result_rows(items):
    return [[item["link_type"], item["status"], item["device_a"], item["interface_a"],
             item["observation_a"]["oper"], item["observation_a"]["remote_host"],
             item["observation_a"]["remote_port"], item["device_b"], item["interface_b"],
             item["observation_b"]["oper"], item["observation_b"]["remote_host"],
             item["observation_b"]["remote_port"], item["detail"], f'DOT:{item["dot_line"]}']
            for item in items]


def build(payload, output_path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(f".{output_path.name}.tmp")
    workbook = xlsxwriter.Workbook(str(temporary))
    fmts = make_formats(workbook)
    try:
        p2p = [[link["left"]["device"], link["left"]["interface"],
                link["right"]["device"], link["right"]["interface"], f'DOT:{link["line"]}']
               for link in payload["p2p_links"]]
        interfaces = [[item[key] for key in ("device", "name", "admin", "oper", "speed",
                                              "kind", "remote_host", "remote_port", "in_p2p")]
                      for item in payload["interface_status"]]
        matching = result_rows(payload["matching_links"])
        miswired = result_rows(payload["miswired_links"])
        missing = result_rows(payload["missing_links"])
        undefined = [[item["device_a"], item["interface_a"], "up", item["device_b"],
                      item["interface_b"], item["detail"]] for item in payload["undefined_links"]]
        meta = payload["metadata"]
        counts = lambda rows, status: sum(row[1] == status for row in rows)
        summary_rows = [
            ["Metric", "Value", "Notes"],
            ["Generated Local", meta["generated_local"].replace("T", " "), "generator local timezone"],
            ["Expected DOT", meta["expected_dot"], "design topology"],
            ["Collection Archive", meta["collection_archive"], "selected collection archive"],
            ["Output", meta["output"], "single XLSX report"],
            ["P2P Links", len(p2p), "all links parsed from DOT"],
            ["Collected Ethernet Switches", meta["collected_ethernet_switches"], "valid .info snapshots"],
            ["Interface Records", len(interfaces), "eth*/swp* records"],
            ["Analyzed P2P Links", len(matching) + len(miswired) + len(missing), "Matching + Miswired + Missing"],
            ["Matching Links", len(matching), "confirmed planned links"],
            ["CONFIRMED_BOTH_SIDE", counts(matching, "CONFIRMED_BOTH_SIDE"), "both switch sides match"],
            ["CONFIRMED_SW_SIDE", counts(matching, "CONFIRMED_SW_SIDE"), "switch side matches"],
            ["Miswired Links", len(miswired), "peer cannot be confirmed"],
            ["WRONG_PEER", counts(miswired, "WRONG_PEER"), "different LLDP peer"],
            ["SW_LLDP_PRESENT", counts(miswired, "SW_LLDP_PRESENT"), "LLDP differs from P2P"],
            ["NO_LLDP", counts(miswired, "NO_LLDP"), "Up without matching LLDP"],
            ["Missing Links", len(missing), "Down or cannot be collected"],
            ["DOWN", counts(missing, "DOWN"), "not operationally Up"],
            ["Missing Device/Interface", counts(missing, "MISSING_DEVICE") + counts(missing, "MISSING_INTERFACE"), "snapshot or interface absent"],
            ["Undefined Links", len(undefined), "local Up interface absent from P2P"],
            ["Collection Warnings", len(payload["warnings"]), " | ".join(payload["warnings"])],
            ["Accounting Check", 0, "must equal 0"],
            ["Validation Result", "FAIL" if miswired or missing or undefined else "PASS", "issue counts must be 0"],
        ]
        summary = workbook.add_worksheet("Summary")
        summary.freeze_panes(1, 0)
        for row_index, row in enumerate(summary_rows):
            for column, item in enumerate(row):
                fmt = fmts["header"] if row_index == 0 else (fmts["wrap"] if column else fmts["cell"])
                summary.write(row_index, column, item, fmt)
        summary.set_column(0, 0, 30); summary.set_column(1, 1, 92); summary.set_column(2, 2, 62)
        for text, fmt in (("PASS", "pass"), ("FAIL", "fail")):
            summary.conditional_format(22, 1, 22, 1, {"type": "text", "criteria": "containing", "value": text, "format": fmts[fmt]})
        write_sheet(workbook, fmts, "Interface_Status", ["Device", "Interface", "Admin Status", "Oper Status", "Speed", "Type", "Remote Host", "Remote Port", "In P2P"], interfaces, widths={0: (18, 42), 6: (18, 42)})
        write_sheet(workbook, fmts, "P2P_Link_Table", ["Device A", "Interface A", "Device B", "Interface B", "Source Ref"], p2p, widths={0: (18, 44), 2: (18, 44)})
        headers = ["Link Type", "Status", "Device A", "Interface A", "A Oper", "A Remote Host", "A Remote Port", "Expected Device B", "Expected Interface B", "B Oper", "B Remote Host", "B Remote Port", "Detail", "Source Ref"]
        opts = {"status_column": 1, "wrap_columns": (12,), "widths": {1: (24, 32), 2: (20, 44), 7: (22, 46), 12: (24, 80)}}
        write_sheet(workbook, fmts, "Matching_Links", headers, matching, **opts)
        write_sheet(workbook, fmts, "Miswired_Links", headers, miswired, **opts)
        write_sheet(workbook, fmts, "Missing_Links", headers, missing, **opts)
        write_sheet(workbook, fmts, "Undefined_Links", ["Device", "Interface", "Oper Status", "LLDP Remote Host", "LLDP Remote Port", "Detail"], undefined, wrap_columns=(5,), widths={0: (20, 44), 3: (18, 44), 5: (24, 70)})
    finally:
        workbook.close()
    temporary.replace(output_path)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="normalized LLDP JSON payload")
    parser.add_argument("output", type=Path, help="output XLSX workbook")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    try:
        payload = json.loads(args.input.read_text(encoding="utf-8"))
        build(payload, args.output)
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
