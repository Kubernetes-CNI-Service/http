"""Bounded current-image business merge DATA; no IO, credential or permission.

The image is one read observation, not CAS. A caller must independently qualify
sources and bind the actual target. Concurrent human edits can race this plan.
"""

from dataclasses import dataclass
import json
import math
import re

from monitor.issue_tracker_source_model import TrackerChanges
from monitor.issue_tracker_online_cells import source_tool_values, encode_tool_cells
from monitor.issue_tracker_online_rows import select_switch_free_row
from monitor.issue_tracker_local_workbook import _EXPECTED_HEADERS


class CableMergeHold(ValueError):
    def __init__(self):
        super().__init__('current_online_merge_invalid')


@dataclass(frozen=True)
class SheetImage:
    name: str
    sheet_id: int
    headers: tuple
    rows: tuple


@dataclass(frozen=True)
class CablePlan:
    requests_json: bytes
    actions: tuple
    history_rows: tuple


_SWITCH = 'ETH&IB Switch'
_CABLING = ('ETH Cabling', 'IB Cabling')
_HEADERS = {name: _EXPECTED_HEADERS[name] for name in (_SWITCH, *_CABLING)}
_ID = re.compile(r'NV[0-9]{5}\Z')
_SWITCH_PREFIX = re.compile(r'\[MONITOR\]\[([A-Za-z0-9_.:-]+)\]\[([A-Za-z0-9_.:/-]+)\] ')
_MAX_BODY = 1024 * 1024
_MAX_IMAGE_BYTES = 16 * 1024 * 1024
_MAX_CHANGES = 1000


def _json(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8', 'strict')


def _cell(value):
    if type(value) is not dict or len(value) > 1:
        raise CableMergeHold()
    if not value:
        return
    kind, data = next(iter(value.items()))
    if kind in ('stringValue', 'formulaValue'):
        if (type(data) is not str or '\x00' in data or len(data) > 32768
                or len(data.encode('utf-8', 'strict')) > 32768
                or kind == 'formulaValue' and not data):
            raise CableMergeHold()
    elif kind == 'boolValue':
        if type(data) is not bool:
            raise CableMergeHold()
    elif kind == 'numberValue':
        if type(data) not in (int, float) or not math.isfinite(data):
            raise CableMergeHold()
    else:
        raise CableMergeHold()


def _column(letter):
    index = 0
    for char in letter:
        index = index * 26 + ord(char) - 64
    return index - 1


def _text(cells, letter):
    return cells[_column(letter)].get('stringValue', '')


def _snapshot(images):
    if (type(images) is not tuple or len(images) != 3
            or any(type(image) is not SheetImage for image in images)
            or tuple(image.name for image in images) != (_SWITCH, *_CABLING)):
        raise CableMergeHold()
    sheets = {}
    ids = set()
    image_bytes = 0
    for image in images:
        if (type(image.sheet_id) is not int or not 0 <= image.sheet_id <= 2147483647
                or image.sheet_id in ids or type(image.headers) is not tuple
                or image.headers != _HEADERS[image.name] or type(image.rows) is not tuple
                or len(image.rows) > (5000 if image.name == _SWITCH else 10000)):
            raise CableMergeHold()
        ids.add(image.sheet_id)
        width = len(image.headers)
        rows = {}
        for entry in image.rows:
            if (type(entry) is not tuple or len(entry) != 2 or type(entry[0]) is not int
                    or not 2 <= entry[0] <= (5001 if image.name == _SWITCH else 2147483647)
                    or entry[0] in rows or type(entry[1]) is not tuple or len(entry[1]) != width):
                raise CableMergeHold()
            for cell in entry[1]:
                _cell(cell)
            image_bytes += len(_json(entry))
            if image_bytes > _MAX_IMAGE_BYTES:
                raise CableMergeHold()
            # Detach observations from mutable caller dicts before planning.
            rows[entry[0]] = tuple(dict(cell) for cell in entry[1])
        sheets[image.name] = (image.sheet_id, rows)
    return sheets


def _cabling_inventory(sheets):
    identifiers = set()
    highest = 30000
    active = {}
    for name in _CABLING:
        for index, cells in sheets[name][1].items():
            identifier = _text(cells, 'A')
            if cells[0] not in ({}, {'stringValue': ''}):
                if not _ID.fullmatch(identifier) or identifier in identifiers:
                    raise CableMergeHold()
                identifiers.add(identifier)
                highest = max(highest, int(identifier[2:]))
            elif any(cell not in ({}, {'stringValue': ''}) for cell in cells):
                raise CableMergeHold()
            if _text(cells, 'U') == 'Closed':
                continue
            # Do not infer a key's absence from a formula/effective value.
            # An unresolved occupied key cannot authorize a new duplicate.
            for letter in ('K', 'L', 'F'):
                cell = cells[_column(letter)]
                if cell and 'stringValue' not in cell:
                    raise CableMergeHold()
            family = 'eth_cabling' if name == 'ETH Cabling' else 'ib_cabling'
            host, port, kind = (_text(cells, letter) for letter in ('K', 'L', 'F'))
            if host and port and kind:
                key = (family, host, port, kind)
                if key in active:
                    raise CableMergeHold()
                active[key] = (index, cells)
    return highest, active


def _switch_inventory(sheets):
    active = {}
    rows = tuple((index, dict(zip('ABCDEFGHIJKLMNOPQRSTU', cells)))
                 for index, cells in sorted(sheets[_SWITCH][1].items()))
    # Validate every reserved rectangle, including occupied/operator rows.
    from monitor.issue_tracker_online_rows import _row
    ids = set()
    for observed in rows:
        _, identifier, _, _ = _row(observed)
        if identifier in ids:
            raise CableMergeHold()
        ids.add(identifier)
        index, cells = observed
        if cells['N'].get('stringValue', '') == 'Closed':
            continue
        for letter in ('F', 'L'):
            if cells[letter] and 'stringValue' not in cells[letter]:
                raise CableMergeHold()
        description = cells['L'].get('stringValue', '')
        match = _SWITCH_PREFIX.match(description)
        if match and cells['N'].get('stringValue', '') != 'Closed':
            key = ('switch', cells['F'].get('stringValue', ''), *match.groups())
            if key in active:
                raise CableMergeHold()
            active[key] = (index, tuple(cells[column] for column in 'ABCDEFGHIJKLMNOPQRSTU'))
    return rows, active


def plan_current_online(changes, images):
    """Merge against this complete current image; never close absent sources.

    Preserve historical Closed rows and all non-tool columns. The result is
    immutable DATA, not a dispatch, permission, durable completion or retry key.
    """
    try:
        return _plan(changes, images)
    except Exception:
        raise CableMergeHold() from None


def _plan(changes, images):
    if (type(changes) is not TrackerChanges or type(changes.cabling) is not tuple
            or type(changes.switch) is not tuple
            or len(changes.cabling) + len(changes.switch) > _MAX_CHANGES):
        raise CableMergeHold()
    TrackerChanges(changes.cabling, changes.switch)
    sheets = _snapshot(images)
    highest, cabling_active = _cabling_inventory(sheets)
    switch_rows, switch_active = _switch_inventory(sheets)
    requests, actions, history = [], [], []
    seen_keys, reserved = set(), []
    for row in sorted((*changes.cabling, *changes.switch), key=lambda item: item.activity_key):
        key = row.activity_key
        # source_tool_values reuses the original strict source validators.
        is_switch = key[0] == 'switch'
        insert_values = source_tool_values(row, 'insert',
            **({} if is_switch else {'reserved_id': 'NV30001'}))
        if key in seen_keys:
            raise CableMergeHold()
        seen_keys.add(key)
        name = _SWITCH if is_switch else row.sheet
        match = (switch_active if is_switch else cabling_active).get(key)
        if match is not None:
            index, cells = match
            values = source_tool_values(row, 'update')
            if not is_switch:
                prefix = values['G'].split(' ', 1)[0] + ' '
                if not _text(cells, 'G').startswith(prefix):
                    raise CableMergeHold()
            observed = {letter: cells[_column(letter)] for letter in values}
            # Business-empty content may be observed with no entered value.
            # Compare it here, without fabricating observations for the old
            # literal-cell encoder or treating formula/zero/False as empty.
            if all(observed[letter] == {'stringValue': value}
                   or value == '' and observed[letter] == {}
                   for letter, value in values.items()):
                continue
            encoded = encode_tool_cells(name, sheets[name][0], 'update', values,
                row_index=index, observed_values=observed)
            action = 'Update'
        elif is_switch:
            slot = select_switch_free_row(switch_rows, reserved_rows=tuple(reserved))
            reserved.append(slot.row_index)
            encoded = encode_tool_cells(name, sheets[name][0], 'insert', insert_values,
                                        row_index=slot.row_index)
            action = 'Insert'
        else:
            highest += 1
            if highest > 99999:
                raise CableMergeHold()
            values = source_tool_values(row, 'insert', reserved_id=f'NV{highest:05d}')
            encoded = encode_tool_cells(name, sheets[name][0], 'insert', values)
            action = 'Insert'
        additions = json.loads(encoded.requests_json)
        if not additions:
            continue
        requests.extend(additions)
        actions.append((name, action, key))
        history.append((row.recorded_at_utc, name, action,
                        _json(key).decode('utf-8').rstrip('\n'), 'Monitor source merge'))
        if len(requests) > 1000:
            raise CableMergeHold()
        if len(_json(requests)) > _MAX_BODY:
            raise CableMergeHold()
    return CablePlan(_json(requests), tuple(actions), tuple(history))
