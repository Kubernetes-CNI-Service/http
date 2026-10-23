#!/usr/bin/env python3
"""Read-only gate: would this CableTracker run change the online Issue Tracker's format?

The online Issue Tracker is a shared standard format (owner 2026-10-23): a sync may only fill rows of
its import and Cabling worksheets, never create a worksheet, rename, insert, delete or reorder a
column, or touch any other worksheet. The vendored engine and the document may both change version
over time (owner 2026-10-23), so this gate depends on no engine internals: it runs the engine's own
main() with its exact command line in a shadow mode where every read goes to the real document and
every write is intercepted and never sent. Writes are judged only by where they land:

  allowed  - cell A1 of an import/Cabling worksheet whose A1 already holds its "... at:" timestamp
  data     - rows below the header row of the configured import/Cabling worksheets: the first such
             write means the preparation is over; the shadow run stops there and the gate passes
  refused  - anything else (new worksheet, header or title rows, column insert/delete, formatting of
             header rows, another worksheet, an unknown request kind)

A second mode records the document's worksheets and header rows before the real run and compares them
afterwards, so a format change made later in a run (by a future engine) is reported at once.

    python3 format_precheck.py --credentials cre.json --engine-command-json command.json [--snapshot S]
    python3 format_precheck.py --credentials cre.json --spreadsheet-id ID --compare-snapshot S

Exit 0: no format change. Exit 3: the run would change (or did change) the format; the report lists
every finding. Exit 2: the check itself could not run. Never prints cell values below the header rows.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Callable, Iterable

BASE = Path(__file__).resolve().parent
RUNNER = BASE / "cabletracker/cabletracker_runner.py"
READ_ONLY_SCOPE = "https://www.googleapis.com/auth/spreadsheets.readonly"
TIMESTAMP_TITLE = re.compile(r"^\s*[A-Za-z][A-Za-z ]* at\s*:", re.IGNORECASE)
READ_METHODS = frozenset({"get", "batchGet", "getByDataFilter", "batchGetByDataFilter"})
A1 = re.compile(r"^(?:'((?:[^']|'')+)'|([^!]+))(?:!(.*))?$")
CELL = re.compile(r"^([A-Za-z]*)(\d*)$")


class ShadowFinished(BaseException):
    """Raised at the first data write: the engine's preparation left the format unchanged."""


class FormatChange(BaseException):
    """Raised at the first write that would change the format; never caught by the engine."""


def column_number(letters: str) -> int:
    number = 0
    for char in letters.upper():
        number = number * 26 + ord(char) - 64
    return number


def parse_range(text: str) -> tuple:
    """'Sheet'!A3:BK -> ("Sheet", first_row, last_row, first_col, last_col); None means open."""
    match = A1.match(str(text).strip())
    if not match:
        raise ValueError(f"unreadable range {text!r}")
    sheet = (match.group(1) or "").replace("''", "'") if match.group(1) else (match.group(2) or "").strip()
    cells = (match.group(3) or "").strip()
    if not cells:
        return sheet, None, None, None, None
    start, _, end = cells.partition(":")
    first, last = CELL.match(start), CELL.match(end or start)
    if not first or not last:
        raise ValueError(f"unreadable range {text!r}")
    def row(value):
        return int(value) if value else None
    def col(value):
        return column_number(value) if value else None
    return sheet, row(first.group(2)), row(last.group(2)), col(first.group(1)), col(last.group(1))


class Document:
    """What the gate knows about the target document: worksheet titles/ids and their title rows."""

    def __init__(self, sheets: dict, first_cells: Callable[[str], str]):
        self.by_title = {title.casefold(): title for title in sheets}
        self.by_id = {sheet_id: title for title, sheet_id in sheets.items()}
        self._first_cells = first_cells
        self._header_rows: dict = {}

    def header_row(self, title: str) -> int:
        """2 when row 1 is a '... at:' title row (import and Cabling sheets), else 1."""
        if title not in self._header_rows:
            self._header_rows[title] = 2 if TIMESTAMP_TITLE.match(self._first_cells(title) or "") else 1
        return self._header_rows[title]


class Policy:
    def __init__(self, document: Document, data_sheets: Iterable[str]):
        self.document = document
        self.data_sheets = {name.casefold() for name in data_sheets}
        self.allowed: list = []

    def _sheet(self, name: str) -> str | None:
        return self.document.by_title.get(str(name).casefold())

    def judge_range(self, text: str, values=None) -> str:
        sheet, first_row, last_row, first_col, last_col = parse_range(text)
        title = self._sheet(sheet)
        if title is None:
            raise FormatChange(f"write to a worksheet that does not exist: {sheet!r}")
        if title.casefold() not in self.data_sheets:
            raise FormatChange(f"write to {title!r}, which is not an import or Cabling worksheet of this run")
        header = self.document.header_row(title)
        if first_row is not None and first_row > header:
            return "data"
        if (header == 2 and first_row == 1 and last_row == 1 and first_col in (None, 1)
                and last_col in (None, 1) and isinstance(values, list)
                and len(values) == 1 and len(values[0]) == 1 and TIMESTAMP_TITLE.match(str(values[0][0]))):
            self.allowed.append(f"{title!r} A1 timestamp")
            return "allowed"
        raise FormatChange(f"write to the title/header rows of {title!r} ({text})")

    def values_write(self, method: str, kwargs: dict) -> None:
        body = kwargs.get("body") or {}
        if method in ("update", "append", "clear"):
            items = [(kwargs.get("range"), body.get("values"))]
        elif method == "batchUpdate":
            items = [(item.get("range"), item.get("values")) for item in body.get("data", [])]
        elif method == "batchClear":
            items = [(text, None) for text in body.get("ranges", [])]
        else:
            raise FormatChange(f"unknown values write {method!r}")
        verdicts = [self.judge_range(text, values) for text, values in items]
        if "data" in verdicts:
            raise ShadowFinished()

    def batch_update(self, kwargs: dict) -> None:
        requests = (kwargs.get("body") or {}).get("requests", [])
        data = False
        for request in requests:
            for kind, spec in request.items():
                grid = (spec or {}).get("range") or (spec or {}).get("destination") or {}
                if kind in ("insertDimension", "deleteDimension", "appendDimension") and (
                        (spec or {}).get("range", spec or {}).get("dimension") == "ROWS"):
                    rows = (spec or {}).get("range", {})
                    title = self.document.by_id.get(rows.get("sheetId", (spec or {}).get("sheetId")))
                    if (title and title.casefold() in self.data_sheets
                            and int(rows.get("startIndex", self.document.header_row(title))) >= self.document.header_row(title)):
                        data = True
                        continue
                if kind in ("repeatCell", "updateCells", "setDataValidation") and "sheetId" in grid:
                    title = self.document.by_id.get(grid["sheetId"])
                    if (title and title.casefold() in self.data_sheets
                            and int(grid.get("startRowIndex", 0)) >= self.document.header_row(title)):
                        data = True
                        continue
                raise FormatChange(f"{kind} request would change the document structure or header formatting")
        if data:
            raise ShadowFinished()


class _Request:
    def __init__(self, run: Callable):
        self._run = run

    def execute(self, *args, **kwargs):
        return self._run(*args, **kwargs)


class _Values:
    def __init__(self, real, policy: Policy):
        self._real, self._policy = real, policy

    def __getattr__(self, method):
        def call(**kwargs):
            if method in READ_METHODS:
                return getattr(self._real, method)(**kwargs)
            return _Request(lambda *a, **k: self._policy.values_write(method, kwargs))
        return call


class _Spreadsheets:
    def __init__(self, real, policy: Policy):
        self._real, self._policy = real, policy

    def values(self):
        return _Values(self._real.values(), self._policy)

    def __getattr__(self, method):
        def call(**kwargs):
            if method in READ_METHODS:
                return getattr(self._real, method)(**kwargs)
            if method == "batchUpdate":
                return _Request(lambda *a, **k: self._policy.batch_update(kwargs))
            return _Request(lambda *a, **k: (_ for _ in ()).throw(FormatChange(f"unknown request {method!r}")))
        return call


class ShadowService:
    """Wraps a Sheets service: reads pass through, writes are judged and never sent."""

    def __init__(self, real, policy: Policy):
        self._real, self._policy = real, policy

    def spreadsheets(self):
        return _Spreadsheets(self._real.spreadsheets(), self._policy)


def engine_sheets(engine_argv: list) -> tuple:
    """Spreadsheet ID and the worksheets this command may fill, read from its own options."""
    def option(name, default=None):
        return engine_argv[engine_argv.index(name) + 1] if name in engine_argv else default
    sheets = [option("--cvt-sheet", "CVT_Import")]
    sheets += [value for value in (option("--ib-cabling-sheet"), option("--eth-cabling-sheet")) if value]
    return option("--spreadsheet-id"), sheets


def document_from_service(service, spreadsheet_id: str) -> Document:
    meta = service.spreadsheets().get(spreadsheetId=spreadsheet_id,
                                      fields="sheets.properties(sheetId,title)").execute()
    sheets = {s["properties"]["title"]: s["properties"].get("sheetId") for s in meta.get("sheets", [])}

    def first_cell(title):
        quoted = "'" + title.replace("'", "''") + "'"
        rows = service.spreadsheets().values().get(spreadsheetId=spreadsheet_id,
                                                   range=f"{quoted}!A1").execute().get("values", [])
        return str(rows[0][0]) if rows and rows[0] else ""
    return Document(sheets, first_cell)


def shadow_run(engine_argv: list, service_factory: Callable = None, runner: Path = RUNNER) -> dict:
    """Run the engine's main() once with writes intercepted. service_factory(real) may replace the
    real Sheets service (tests); by default reads go to Google."""
    import googleapiclient.discovery as discovery
    from google.oauth2 import service_account

    spreadsheet_id, data_sheets = engine_sheets(engine_argv)
    real_build = discovery.build
    state = {}
    # Defence in depth: whatever scope the engine asks for, its credentials are read-only here, so a
    # write that slipped past the interception would still be rejected by Google.
    credentials_class = service_account.Credentials
    real_from_file = credentials_class.__dict__["from_service_account_file"]
    real_from_info = credentials_class.__dict__["from_service_account_info"]

    def read_only_file(cls, filename, **kwargs):
        kwargs["scopes"] = [READ_ONLY_SCOPE]
        return real_from_file.__func__(cls, filename, **kwargs)

    def read_only_info(cls, info, **kwargs):
        kwargs["scopes"] = [READ_ONLY_SCOPE]
        return real_from_info.__func__(cls, info, **kwargs)

    credentials_class.from_service_account_file = classmethod(read_only_file)
    credentials_class.from_service_account_info = classmethod(read_only_info)

    def shadow_build(*args, **kwargs):
        service = real_build(*args, **kwargs)
        if service_factory is not None:
            service = service_factory(service)
        policy = Policy(document_from_service(service, spreadsheet_id), data_sheets)
        state["policy"] = policy
        return ShadowService(service, policy)

    discovery.build = shadow_build
    saved_argv = sys.argv
    sys.argv = [str(runner), *engine_argv]
    try:
        spec = importlib.util.spec_from_file_location("cabletracker_runner_shadow", runner)
        engine = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = engine
        spec.loader.exec_module(engine)
        try:
            code = engine.main()
        except SystemExit as exc:
            code = exc.code
        policy = state.get("policy")
        allowed = policy.allowed if policy else []
        if code == 0:
            return {"ok": True, "verdict": "engine finished without a data write", "allowed": allowed}
        return {"ok": False, "error": f"engine exited {code} before writing data "
                "(command rejected or document unreadable; was the engine updated?)"}
    except ShadowFinished:
        return {"ok": True, "verdict": "preparation leaves the format unchanged",
                "allowed": state["policy"].allowed}
    except FormatChange as change:
        return {"ok": False, "changes": [str(change)]}
    finally:
        sys.argv = saved_argv
        discovery.build = real_build
        credentials_class.from_service_account_file = real_from_file
        credentials_class.from_service_account_info = real_from_info


def snapshot(service, spreadsheet_id: str) -> dict:
    """Worksheet titles and header rows (title row values reduced to their '... at:' label)."""
    document = document_from_service(service, spreadsheet_id)
    result = {"worksheets": sorted(document.by_title.values()), "headers": {}}
    for title in result["worksheets"]:
        header = document.header_row(title)
        quoted = "'" + title.replace("'", "''") + "'"
        rows = service.spreadsheets().values().get(spreadsheetId=spreadsheet_id,
                                                   range=f"{quoted}!1:{header}").execute().get("values", [])
        rows = [[str(cell) for cell in row] for row in rows]
        if header == 2 and rows and rows[0]:
            rows[0] = [TIMESTAMP_TITLE.match(rows[0][0]).group(0)] + rows[0][1:]
        result["headers"][title] = rows
    return result


def snapshot_changes(before: dict, after: dict) -> list:
    changes = []
    added = sorted(set(after["worksheets"]) - set(before["worksheets"]))
    removed = sorted(set(before["worksheets"]) - set(after["worksheets"]))
    changes += [f"worksheet added: {title!r}" for title in added]
    changes += [f"worksheet removed: {title!r}" for title in removed]
    for title in before["worksheets"]:
        if title in after["headers"] and before["headers"].get(title) != after["headers"][title]:
            changes.append(f"header rows of {title!r} changed")
    return changes


def google_service(credentials: Path):
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    return build("sheets", "v4", cache_discovery=False,
                 credentials=service_account.Credentials.from_service_account_file(
                     str(credentials), scopes=[READ_ONLY_SCOPE]))


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only check that a CableTracker run does not change the Issue Tracker format.")
    parser.add_argument("--credentials", type=Path, required=True, help="service account key file")
    parser.add_argument("--engine-command-json", type=Path,
                        help="JSON list: the exact engine argv after the script path (shadow run)")
    parser.add_argument("--snapshot", type=Path, help="also save the worksheets and header rows here")
    parser.add_argument("--spreadsheet-id", help="document of --compare-snapshot")
    parser.add_argument("--compare-snapshot", type=Path,
                        help="compare the document now with a snapshot saved before the real run")
    args = parser.parse_args(argv)
    try:
        if args.compare_snapshot is not None:
            if not args.spreadsheet_id:
                raise ValueError("--compare-snapshot needs --spreadsheet-id")
            before = json.loads(args.compare_snapshot.read_text(encoding="utf-8"))
            changes = snapshot_changes(before, snapshot(google_service(args.credentials), args.spreadsheet_id))
            print(json.dumps({"ok": not changes, "changes": changes}, ensure_ascii=False))
            return 0 if not changes else 3
        if args.engine_command_json is None:
            raise ValueError("give --engine-command-json or --compare-snapshot")
        engine_argv = json.loads(args.engine_command_json.read_text(encoding="utf-8"))
        if not isinstance(engine_argv, list) or not all(isinstance(item, str) for item in engine_argv):
            raise ValueError("engine command must be a JSON list of strings")
        if args.snapshot is not None:
            spreadsheet_id, _sheets = engine_sheets(engine_argv)
            args.snapshot.write_text(json.dumps(snapshot(google_service(args.credentials), spreadsheet_id),
                                                ensure_ascii=False), encoding="utf-8")
        report = shadow_run(engine_argv)
    except Exception as exc:  # the failure class only; never a credential value
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:300]}"}))
        return 2
    print(json.dumps(report, ensure_ascii=False))
    if report.get("changes"):
        return 3
    return 0 if report.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
