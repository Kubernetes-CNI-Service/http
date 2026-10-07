"""Pure finite Switch occupancy checks and prewrite displacement detection.

The caller must supply actual explicit-column discovery plus exact A:U row
rectangles with userEnteredValue/FORMULA, not formatted/effective values.
This helper does not read Sheets, resolve active business keys, establish
template/target/source authority, persist reservations or grant a permit.
The frozen row digest is only a prewrite comparison, never CAS or rollback:
human edits can still race after observation; post-application checks remain
mandatory and mismatch is CONFLICT, not evidence that nothing was written.
"""

from dataclasses import dataclass
import hashlib
import json
import math
import re


class OnlineRowsHold(ValueError):
    def __init__(self): super().__init__("online_switch_row_unproved")


class OnlineRowConflict(ValueError):
    def __init__(self): super().__init__("online_switch_postimage_conflict")


@dataclass(frozen=True)
class ObservedSwitchFreeRow:
    row_index: int
    issue_id: str
    row_sha256: str


_COLUMNS = frozenset(tuple("ABCDEFGHIJKLMNOPQRSTU"))
_OCCUPANCY = frozenset(("B", "C", "F", *tuple("JKLMNOPQRSTU")))


def _cell(value):
    if type(value) is not dict or len(value) > 1: raise OnlineRowsHold()
    if not value: return value
    name, data = next(iter(value.items()))
    if name in ("stringValue", "formulaValue"):
        if type(data) is not str or len(data) > 32768 or "\x00" in data: raise OnlineRowsHold()
        try: data.encode("utf-8", "strict")
        except UnicodeError: raise OnlineRowsHold() from None
        if name == "formulaValue" and not data: raise OnlineRowsHold()
    elif name == "boolValue":
        if type(data) is not bool: raise OnlineRowsHold()
    elif name == "numberValue":
        if type(data) not in (int, float): raise OnlineRowsHold()
        try:
            if not math.isfinite(data): raise OnlineRowsHold()
        except (ValueError, OverflowError): raise OnlineRowsHold() from None
    else: raise OnlineRowsHold()
    return value


def _row(value):
    if (type(value) is not tuple or len(value) != 2 or type(value[0]) is not int
            or not 2 <= value[0] <= 5001 or type(value[1]) is not dict
            or set(value[1]) != _COLUMNS):
        raise OnlineRowsHold()
    index, cells = value
    for cell in cells.values(): _cell(cell)
    identifier = cells["A"].get("stringValue")
    if type(identifier) is not str or re.fullmatch(r"NV[0-9]{5}", identifier) is None:
        raise OnlineRowsHold()
    for column in ("D", "E", "G", "H"):
        if "formulaValue" not in cells[column]: raise OnlineRowsHold()
    if index == 2:
        if "formulaValue" not in cells["I"]: raise OnlineRowsHold()
    elif not _empty(cells["I"]): raise OnlineRowsHold()
    digest = hashlib.sha256((json.dumps({"row_index": index, "cells": cells},
                                       sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False, allow_nan=False) + "\n").encode()).hexdigest()
    return index, identifier, digest, cells


def _empty(cell):
    return not cell or cell == {"stringValue": ""}


def select_switch_free_row(rows, *, reserved_rows=()):
    """Never fabricate a row; any malformed rectangle makes the read unusable.

    Existing IDs and lookup formulas are mandatory even on empty slots.
    Operator cells count as occupied, including zero/False/blank-result
    formulas. Reservations are retained caller facts, not reclaimed here.
    """
    if (type(rows) is not tuple or not 1 <= len(rows) <= 5000
            or type(reserved_rows) is not tuple or len(reserved_rows) > 5000
            or any(type(item) is not int or not 2 <= item <= 5001 for item in reserved_rows)
            or len(set(reserved_rows)) != len(reserved_rows)):
        raise OnlineRowsHold()
    parsed = [_row(row) for row in rows]
    if (len({row[0] for row in parsed}) != len(parsed)
            or len({row[1] for row in parsed}) != len(parsed)):
        raise OnlineRowsHold()
    for index, identifier, digest, cells in sorted(parsed, key=lambda item: item[0]):
        if index not in reserved_rows and all(_empty(cells[column]) for column in _OCCUPANCY):
            return ObservedSwitchFreeRow(index, identifier, digest)
    raise OnlineRowsHold()


def require_switch_row_unchanged(expected, actual_row):
    """Check all 21 cells before mutation, without treating the digest as authority."""
    if type(expected) is not ObservedSwitchFreeRow: raise OnlineRowsHold()
    index, identifier, digest, cells = _row(actual_row)
    if ((index, identifier, digest) != (expected.row_index, expected.issue_id, expected.row_sha256)
            or not all(_empty(cells[column]) for column in _OCCUPANCY)):
        raise OnlineRowsHold()


def require_switch_insert_postimage(expected, before_row, after_row, intended_values):
    """Detect displacement/preservation conflict; never claim COMPLETE or rollback.

    The immutable observed preimage must still bind every cell. Exactly seven
    insertion columns may change to their intended literal userEnteredValue;
    all fourteen other cells, including reserved ID, formulas and operator
    columns, must remain identical. This is only one necessary postcondition:
    History, fence, enrollments and original journal are separately required.
    """
    require_switch_row_unchanged(expected, before_row)
    owned = frozenset(("B", "C", "F", "J", "K", "L", "N"))
    if type(intended_values) is not dict or set(intended_values) != owned:
        raise OnlineRowsHold()
    intended = {column: {"stringValue": value} for column, value in intended_values.items()}
    for cell in intended.values(): _cell(cell)
    try:
        index, identifier, _digest, cells = _row(after_row)
        if index != expected.row_index or identifier != expected.issue_id:
            raise OnlineRowConflict()
        for column in _COLUMNS:
            wanted = intended[column] if column in owned else before_row[1][column]
            if cells[column] != wanted: raise OnlineRowConflict()
    except OnlineRowsHold:
        raise OnlineRowConflict() from None
