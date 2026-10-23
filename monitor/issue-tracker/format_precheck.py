#!/usr/bin/env python3
"""Read-only gate: would this CableTracker run change the online Issue Tracker's format?

The online Issue Tracker is a shared standard format (owner 2026-10-23): a sync may only fill rows,
never rename, insert, delete or reorder a column, migrate the Whitelist or create a worksheet. The
vendored engine does all of those when the document differs from what it expects. This gate
computes, with the engine's own argument parser and header functions, the worksheets and header rows
the engine enforces for one exact engine command, reads the document's header rows read-only, and
passes only when they are identical.

    python3 format_precheck.py --credentials cre.json --engine-command-json command.json

The JSON file holds the exact engine argv (as built by issue-tracker-sync.py). Prints one JSON report.
Exit 0: no format change. Exit 3: the run would change the format (report lists every difference).
Exit 2: the check itself could not run. Never prints cell values below the header rows.
"""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import json
import sys
from pathlib import Path
from typing import Callable, Iterable

BASE = Path(__file__).resolve().parent
RUNNER = BASE / "cabletracker/cabletracker_runner.py"
READ_ONLY_SCOPE = "https://www.googleapis.com/auth/spreadsheets.readonly"


def load_engine(path: Path = RUNNER):
    spec = importlib.util.spec_from_file_location("cabletracker_runner", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def expected_layout(engine, engine_argv: list) -> dict:
    """Worksheets and header rows this exact engine command enforces."""
    saved = sys.argv
    sys.argv = [str(RUNNER), *engine_argv]
    try:
        args = engine.parse_args()
    finally:
        sys.argv = saved
    normalize = engine.normalize_and_validate_instance_args
    count = len(inspect.signature(normalize).parameters)
    normalize(args, *[None] * (count - 1))
    for flag in ("refresh_cvt_sum", "refresh_cabling_sum", "enable_cabling_events",
                 "refresh_agent_status", "enable_bcm", "ai_recommendations", "clear_data", "fresh_start"):
        if getattr(args, flag, False):
            raise ValueError(f"engine option {flag} writes worksheets outside the Cabling rows")
    cabling = []
    for option in ("ib_cabling_sheet", "eth_cabling_sheet"):
        sheet = getattr(args, option, None)
        if sheet:
            scoped = engine.cabling_args(args, sheet)
            cabling.append({"sheet": sheet, "headers": list(engine.selected_remediation_headers(scoped)[1])})
    return {
        "spreadsheet_id": args.spreadsheet_id,
        "import": {"sheet": args.cvt_sheet,
                   "headers": list(engine.parse_columns(args.cvt_columns, engine.cvt_headers(args), "--columns"))},
        "cabling": cabling,
        "whitelist": args.whitelist_sheet or None,
    }


def _clean(row: Iterable) -> list:
    values = [str(cell).strip() for cell in row]
    while values and not values[-1]:
        values.pop()
    return values


def whitelist_changes(rows: list) -> list:
    """What the engine's Whitelist migration would do to these first rows."""
    header = next((row for row in rows
                   if any(str(cell).strip().casefold() in {"filter", "device name"} for cell in row)), None)
    if header is None:
        return []
    names = [str(cell).strip().casefold() for cell in header]
    changes = []
    if "device name" in names and "filter" not in names:
        changes.append("rename Device Name to Filter")
    if "rack" in names:
        changes.append("delete the Rack column")
    if "comments" in names and "filter type" not in names:
        changes.append("rename Comments to Filter Type")
    if "cvt instance" in names:
        changes.append("rename CVT Instance to Instance")
    elif "instance" not in names:
        changes.append("insert an Instance column")
    return changes


def compare(layout: dict, tabs: Iterable[str], read_rows: Callable[[str, int], list]) -> list:
    """Every format change the engine would make; empty when the document already matches."""
    present = {tab.casefold(): tab for tab in tabs}
    problems = []
    for role, item in [("import", layout["import"])] + [("cabling", c) for c in layout["cabling"]]:
        sheet = item["sheet"]
        if sheet.casefold() not in present:
            problems.append(f"{role} worksheet {sheet!r} does not exist and would be created")
            continue
        rows = read_rows(present[sheet.casefold()], 2)
        header = _clean(rows[1]) if len(rows) > 1 else []
        if header != item["headers"]:
            only_sheet = [h for h in header if h not in item["headers"]]
            only_engine = [h for h in item["headers"] if h not in header]
            detail = (f"only in the document {only_sheet}; only in the engine {only_engine}"
                      if only_sheet or only_engine else "same columns in a different order")
            problems.append(f"{sheet!r} header row 2 would be rewritten: {detail}")
    whitelist = layout.get("whitelist")
    if whitelist and whitelist.casefold() in present:
        for change in whitelist_changes(read_rows(present[whitelist.casefold()], 3)):
            problems.append(f"{whitelist!r} would be migrated: {change}")
    return problems


def google_reader(credentials: Path, spreadsheet_id: str):
    from google.oauth2 import service_account
    from googleapiclient.discovery import build

    service = build("sheets", "v4", cache_discovery=False,
                    credentials=service_account.Credentials.from_service_account_file(
                        str(credentials), scopes=[READ_ONLY_SCOPE]))
    meta = service.spreadsheets().get(spreadsheetId=spreadsheet_id,
                                      fields="sheets.properties.title").execute()
    tabs = [sheet["properties"]["title"] for sheet in meta.get("sheets", [])]

    def read_rows(tab: str, last: int) -> list:
        quoted = "'" + tab.replace("'", "''") + "'"
        return service.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id, range=f"{quoted}!1:{last}").execute().get("values", [])

    return tabs, read_rows


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only check that a CableTracker run would not change the Issue Tracker format.")
    parser.add_argument("--credentials", type=Path, required=True, help="service account key file")
    parser.add_argument("--engine-command-json", type=Path, required=True,
                        help="JSON list: the exact engine argv after the script path")
    args = parser.parse_args(argv)
    try:
        engine_argv = json.loads(args.engine_command_json.read_text(encoding="utf-8"))
        if not isinstance(engine_argv, list) or not all(isinstance(item, str) for item in engine_argv):
            raise ValueError("engine command must be a JSON list of strings")
        layout = expected_layout(load_engine(), engine_argv)
        tabs, read_rows = google_reader(args.credentials, layout["spreadsheet_id"])
        problems = compare(layout, tabs, read_rows)
    except Exception as exc:  # report the failure class only; never a credential value
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:300]}"}))
        return 2
    print(json.dumps({"ok": not problems, "import": layout["import"]["sheet"],
                      "cabling": [item["sheet"] for item in layout["cabling"]],
                      "changes": problems}, ensure_ascii=False))
    return 0 if not problems else 3


if __name__ == "__main__":
    raise SystemExit(main())
