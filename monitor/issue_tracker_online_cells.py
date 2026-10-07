"""Pure C-8 literal-cell candidates and C-26 typed observation comparison.

This is NOT a remote planner or send unit. Caller-provided indices, sheetIds
and values prove no key/row identity, occupancy, template, reservation, source
qualification or target authority. Those checks and C-19 History/fence/journal
must dominate any future send boundary. No HTTP, SDK, ledger or online ID
allocation occurs here; a NOOP candidate proves only the supplied read image,
never APPLIED or a historical generation's remote execution.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import re


class OnlineCellsHold(ValueError):
    def __init__(self): super().__init__("invalid_online_cell_candidate")


@dataclass(frozen=True)
class OnlineCellCandidate:
    requests_json: bytes
    outcome: str
    intended_sha256: str


_SWITCH_INSERT = frozenset(("B", "C", "F", "J", "K", "L", "N"))
_CABLING_INSERT = frozenset(("A", "B", "C", "D", "E", "F", "G", "K", "L", "M", "N", "Q", "R", "S", "T", "U"))
_CABLING_UPDATE = frozenset(("G", "M", "N", "S", "T"))
_MAX_TEXT = 32768
_MAX_BODY = 1024 * 1024


def _literal(value):
    if type(value) is not str or len(value) > _MAX_TEXT or "\x00" in value:
        raise OnlineCellsHold()
    try: value.encode("utf-8", "strict")
    except UnicodeError: raise OnlineCellsHold() from None
    return value


def _canonical(value):
    try:
        return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise OnlineCellsHold() from None


def _column(letter):
    value = 0
    for char in letter: value = value * 26 + ord(char) - ord("A") + 1
    return value - 1


def _observed(value):
    if type(value) is not dict or len(value) > 1: raise OnlineCellsHold()
    if not value: return value
    key, data = next(iter(value.items()))
    if key in ("stringValue", "formulaValue"): _literal(data)
    elif key == "boolValue":
        if type(data) is not bool: raise OnlineCellsHold()
    elif key == "numberValue":
        if type(data) not in (int, float): raise OnlineCellsHold()
        try:
            if not math.isfinite(data): raise OnlineCellsHold()
        except (ValueError, OverflowError): raise OnlineCellsHold() from None
    else: raise OnlineCellsHold()
    return value


def encode_tool_cells(sheet, sheet_id, action, values, *, row_index=None, observed_values=None):
    """Encode only permitted literal runs; preserve every unmentioned column.

    `observed_values` contains EVERY intended tool cell's userEnteredValue,
    not formatted/effective values. Empty/formula/numeric/bool differs from
    literal text. No missing/malformed observation can manufacture NOOP.
    Row numbers are API coordinates ONLY; this helper cannot resolve keys or
    prove the key still occupies a coordinate. Insert/update authorization
    and displacement detection are deliberately separate obligations.
    """
    if (type(sheet) is not str or sheet not in ("ETH&IB Switch", "ETH Cabling", "IB Cabling")
            or type(sheet_id) is not int or not 0 <= sheet_id <= 2147483647
            or type(action) is not str or action not in ("insert", "update")
            or type(values) is not dict):
        raise OnlineCellsHold()
    if sheet == "ETH&IB Switch":
        required = _SWITCH_INSERT if action == "insert" else frozenset(("L",))
        allowed = required
    else:
        required = _CABLING_INSERT if action == "insert" else _CABLING_UPDATE
        allowed = required | frozenset(("AC",))
    if not required <= set(values) <= allowed: raise OnlineCellsHold()
    literal = {letter: _literal(value) for letter, value in values.items()}
    append = sheet != "ETH&IB Switch" and action == "insert"
    if append:
        if row_index is not None: raise OnlineCellsHold()
    elif (type(row_index) is not int or not 2 <= row_index <= 2147483647
          or (sheet == "ETH&IB Switch" and row_index > 5001)):
        raise OnlineCellsHold()
    if sheet != "ETH&IB Switch" and action == "insert":
        if (re.fullmatch(r"NV[0-9]{5}", literal["A"]) is None
                or literal["E"] != ("ETH" if sheet == "ETH Cabling" else "IB")
                or literal["U"] != "New"):
            raise OnlineCellsHold()
    intended = {letter: {"stringValue": value} for letter, value in literal.items()}
    digest = hashlib.sha256(_canonical({"sheet": sheet, "sheet_id": sheet_id, "action": action,
                                        "row_index": row_index, "values": intended})).hexdigest()
    if observed_values is not None:
        if append or type(observed_values) is not dict or set(observed_values) != set(intended):
            raise OnlineCellsHold()
        if {letter: _observed(value) for letter, value in observed_values.items()} == intended:
            return OnlineCellCandidate(b"[]\n", "OBSERVED-SATISFIED-AT-READ", digest)
    indexed = sorted((_column(letter), value) for letter, value in literal.items())
    if append:
        cells = [{} for _ in range(indexed[-1][0] + 1)]
        for column, value in indexed: cells[column] = {"userEnteredValue": {"stringValue": value}}
        requests = [{"appendCells": {"sheetId": sheet_id, "rows": [{"values": cells}],
                                     "fields": "userEnteredValue"}}]
    else:
        runs = []
        for column, value in indexed:
            if not runs or column != runs[-1][0] + len(runs[-1][1]): runs.append((column, []))
            runs[-1][1].append({"userEnteredValue": {"stringValue": value}})
        requests = [{"updateCells": {"start": {"sheetId": sheet_id, "rowIndex": row_index,
                                               "columnIndex": start},
                                     "rows": [{"values": cells}], "fields": "userEnteredValue"}}
                    for start, cells in runs]
    body = _canonical(requests)
    if len(body) > _MAX_BODY or len(requests) > 1000: raise OnlineCellsHold()
    return OnlineCellCandidate(body, "WIRE-CANDIDATE", digest)


def source_tool_values(row, action, *, reserved_id=None):
    """Reuse real source contracts, not a local diff; never allocate an ID here."""
    from monitor.issue_tracker_local_workbook import (
        SwitchSourceWorkbookRow, CablingSourceRow, _validate_switch_source_row,
        _validate_cabling_source_row,
    )
    if action not in ("insert", "update"): raise OnlineCellsHold()
    try:
        if type(row) is SwitchSourceWorkbookRow:
            _validate_switch_source_row(row)
            if reserved_id is not None: raise OnlineCellsHold()
            key = row.activity_key
            description = f"[MONITOR][{key[2]}][{key[3]}] [fabric_source={row.fabric_source}] {row.evidence_description}"
            values = {"L": description}
            if action == "insert":
                values.update({"B": row.recorded_at_utc[:10], "C": "ZTP Monitor", "F": key[1],
                               "J": row.fabric, "K": row.priority, "N": "New"})
        elif type(row) is CablingSourceRow:
            digest = _validate_cabling_source_row(row)
            key = row.activity_key
            values = {"G": f"[MONITOR][{key[0]}][{digest}] {row.source_status}: {row.evidence_description}"}
            values.update(zip(("M", "N", "S", "T"), row.actual_endpoints or ("", "", "", "")))
            if action == "insert":
                if type(reserved_id) is not str or re.fullmatch(r"NV[0-9]{5}", reserved_id) is None:
                    raise OnlineCellsHold()
                values.update({"A": reserved_id, "B": "ZTP Monitor", "C": "ZTP Monitor",
                               "D": row.recorded_at_utc[:10], "E": "ETH" if row.sheet == "ETH Cabling" else "IB",
                               "F": key[3], "K": row.expected_endpoints[0], "L": row.expected_endpoints[1],
                               "Q": row.expected_endpoints[2], "R": row.expected_endpoints[3], "U": "New"})
            elif reserved_id is not None: raise OnlineCellsHold()
        else: raise OnlineCellsHold()
        return {letter: _literal(value) for letter, value in values.items()}
    except (ValueError, TypeError, KeyError, IndexError, RecursionError):
        raise OnlineCellsHold() from None
