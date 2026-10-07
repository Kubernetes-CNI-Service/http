"""Uninstalled C17 durable shared Cabling sequence under the actual owner.

Both capacity-clipped original columns, enrollment and binding are retained;
one conservative pending unit blocks any other allocation, including across
projects. No expiry, reset, reclamation, network, credential persistence,
COMPLETE or send permission. Authentic source/admission, row reservations,
the audited launcher and authenticated settlement still require integration.
"""
from dataclasses import dataclass, field
import hashlib
import json
import os
import re
from types import SimpleNamespace
from urllib.parse import urlsplit

from monitor import issue_tracker_local_commit as local
from monitor import issue_tracker_attempt_journal as journal
from monitor import issue_tracker_global_attempt_journal as global_journal
from monitor import issue_tracker_spreadsheet_owner as ownership
from monitor import issue_tracker_enrollment_journal as enrollment
from monitor import issue_tracker_sheets_read_decode as decode
from monitor import issue_tracker_online_nv_ids as allocator
from monitor.issue_tracker_sheets_read_plan import PreparedSheetsRead

_NAMES = {'ETH-RAW', 'IB-RAW', 'HEADER', 'RESERVATIONS', 'INITIALIZED'}
_FAMILIES = {'ETH Cabling': 'eth_cabling', 'IB Cabling': 'ib_cabling'}
_LIMIT = 1024 * 1024


class NvReservationHold(ValueError):
    def __init__(self): super().__init__('req7_nv_reservation_unproved')


@dataclass(frozen=True)
class NvReservationObservation:
    reservations: tuple = field(repr=False)
    unit_id: str
    journal_sha256: str
    eth_source_sha256: str
    ib_source_sha256: str


def _inputs(token, binding, identity, generation_id, publish_id, sheet, requested_keys):
    from monitor.issue_tracker_send_unit import _generation_identity
    _generation_identity(generation_id)
    owner, parent, enrollment_name, original = enrollment._inputs(token, binding, identity)
    observed = enrollment.inspect_enrollment_journal(token, binding, identity)
    if (type(sheet) is not str or sheet not in _FAMILIES
            or any(type(digest) is not str or re.fullmatch(r'[0-9a-f]{64}', digest) is None
                   for digest in (publish_id,))
            or type(requested_keys) is not tuple or not 1 <= len(requested_keys) <= 1000):
        raise NvReservationHold()
    keys = tuple(sorted(allocator._key(key) for key in requested_keys))
    if len(set(keys)) != len(keys) or any(key[0] != _FAMILIES[sheet] for key in keys): raise NvReservationHold()
    ids = dict(original['sheet_ids'])
    unit = {'schema_version': 1, 'generation_id': generation_id, 'publish_id': publish_id,
            'spreadsheet_id': binding.spreadsheet_id, 'sheet': sheet, 'sheet_id': ids[sheet]}
    base = {'schema_version': 1, 'identity': unit, 'unit_id': hashlib.sha256(local._canonical(unit)).hexdigest(),
            'requested_keys': keys, 'sheet_ids': original['sheet_ids'], 'enrollment_sha256': observed.journal_sha256,
            'allowlist_sha256': binding.allowlist_sha256, 'policy_sha256': binding.policy_sha256}
    if len(local._canonical(base)) > _LIMIT: raise NvReservationHold()
    return parent, owner.lock_name[:-5] + '.nv', base, keys, ids


def _read_pair(binding, ids, eth_plan, eth_raw, ib_plan, ib_raw):
    result = []
    for title, family, plan, raw in (('ETH Cabling', 'eth_cabling', eth_plan, eth_raw),
                                     ('IB Cabling', 'ib_cabling', ib_plan, ib_raw)):
        if type(plan) is not PreparedSheetsRead or urlsplit(plan.path).path != '/v4/spreadsheets/' + binding.spreadsheet_id:
            raise NvReservationHold()
        # Fixed valid key is only used to invoke the full-body classifier. ALL
        # original A IDs, including Closed/unrelated rows, feed the allocator.
        result.append(decode.discover_activity_sheet(plan, raw, sheet_id=ids[title],
            activity_key=(family, '__nv_observation__', '__nv_observation__', 'Link Down')))
    return tuple(result)


def _header(base, eth_plan, ib_plan, observed, reservations):
    result = {**base, 'eth_read_path': eth_plan.path, 'ib_read_path': ib_plan.path,
        'eth_source_sha256': observed[0].source_sha256, 'ib_source_sha256': observed[1].source_sha256,
        'reservations_sha256': hashlib.sha256(reservations).hexdigest()}
    if len(local._canonical(result)) > _LIMIT: raise NvReservationHold()
    return result


def _marker(header):
    return local._canonical({'schema_version': 1, 'state': 'INITIALIZED',
                             'header_sha256': hashlib.sha256(local._canonical(header)).hexdigest()})


def _inspect(parent, name, folder, binding, base, keys, ids):
    if set(os.listdir(folder)) != _NAMES: raise NvReservationHold()
    header_raw = journal._read(folder, 'HEADER', _LIMIT)
    header = json.loads(header_raw.decode('utf-8'))
    if type(header) is not dict or any(type(header.get(key)) is not str for key in ('eth_read_path', 'ib_read_path')):
        raise NvReservationHold()
    plans = tuple(PreparedSheetsRead('sheets.googleapis.com', header[key], 'GET', (), b'')
                  for key in ('eth_read_path', 'ib_read_path'))
    raws = tuple(SimpleNamespace(status=200, complete=True, data=journal._read(folder, key, 2 * _LIMIT))
                 for key in ('ETH-RAW', 'IB-RAW'))
    observed = _read_pair(binding, ids, plans[0], raws[0], plans[1], raws[1])
    # Recompute from immutable original columns, never a later read, caller
    # counter or a reservation copied from the current implementation.
    allocation = allocator.plan_nv_reservations(observed[0].nv_ids, observed[1].nv_ids, (), keys)
    reservations = local._canonical(allocation.requested)
    if journal._read(folder, 'RESERVATIONS', _LIMIT) != reservations: raise NvReservationHold()
    expected = _header(base, plans[0], plans[1], observed, reservations)
    if header_raw != local._canonical(expected): raise NvReservationHold()
    fd = os.open('INITIALIZED', local._flags(), dir_fd=folder)
    try:
        info = local._check(fd, directory=False); journal._named(folder, 'INITIALIZED', fd, directory=False)
        raw = os.read(fd, 4097)
        if raw != _marker(expected) or len(raw) != info.st_size: raise NvReservationHold()
        os.fsync(fd); os.fsync(folder); os.fsync(parent)
        journal._named(folder, 'INITIALIZED', fd, directory=False)
    finally: os.close(fd)
    journal._named(parent, name, folder, directory=True)
    if set(os.listdir(folder)) != _NAMES: raise NvReservationHold()
    return NvReservationObservation(allocation.requested, base['unit_id'], hashlib.sha256(header_raw).hexdigest(),
                                    observed[0].source_sha256, observed[1].source_sha256)


def prepare_nv_reservation(token, binding, identity, eth_plan, eth_response, ib_plan, ib_response,
                           *, generation_id, publish_id, sheet, requested_keys):
    """New original unit only; no adoption or allocation after a global intent."""
    folder = None; failed = False
    try:
        parent, name, base, keys, ids = _inputs(token, binding, identity, generation_id, publish_id, sheet, requested_keys)
        # Even an unattempted or partial global journal is a conservative
        # barrier. UNKNOWN cannot be bypassed by switching project or family.
        if name in os.listdir(parent) or name[:-3] + '.journal' in os.listdir(parent): raise NvReservationHold()
        observed = _read_pair(binding, ids, eth_plan, eth_response, ib_plan, ib_response)
        allocation = allocator.plan_nv_reservations(observed[0].nv_ids, observed[1].nv_ids, (), keys)
        reservations = local._canonical(allocation.requested)
        if len(reservations) > _LIMIT: raise NvReservationHold()
        header = _header(base, eth_plan, ib_plan, observed, reservations)
        folder = global_journal._create_folder(parent, name)
        journal._write_read_image(folder, 'ETH-RAW', eth_response.data)
        journal._write_read_image(folder, 'IB-RAW', ib_response.data)
        local._write_new(folder, 'HEADER', local._canonical(header))
        local._write_new(folder, 'RESERVATIONS', reservations)
        journal._named(parent, name, folder, directory=True); ownership._validated_owner(token, binding)
        # Folder+parent and four file+folder pairs: ALL ten image barriers
        # precede genuine initialization. Partial stores stay retained HOLD.
        local._write_new(folder, 'INITIALIZED', _marker(header))
        result = _inspect(parent, name, folder, binding, base, keys, ids)
        ownership._validated_owner(token, binding)
    except Exception: failed = True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed = True
    if failed: raise NvReservationHold()
    return result


def inspect_nv_reservation(token, binding, identity, *, generation_id, publish_id, sheet, requested_keys):
    """Existing pending IDs only; never allocate, reclaim or clear UNKNOWN."""
    folder = None; failed = False
    try:
        parent, name, base, keys, ids = _inputs(token, binding, identity, generation_id, publish_id, sheet, requested_keys)
        folder = local._directory(parent, name); journal._named(parent, name, folder, directory=True)
        result = _inspect(parent, name, folder, binding, base, keys, ids)
        ownership._validated_owner(token, binding)
    except Exception: failed = True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed = True
    if failed: raise NvReservationHold()
    return result


def _literal_image(item, target):
    """Re-encode actual business requests; never trust a matching A alone."""
    from monitor.issue_tracker_online_cells import encode_tool_cells
    from monitor.issue_tracker_sheets_read_decode import _letter
    values = {}; row_index = None
    for request in item['requests']:
        if item['action'] == 'insert':
            if len(item['requests']) != 1 or set(request) != {'appendCells'}: raise NvReservationHold()
            body = request['appendCells']; start = 0
            if set(body) != {'sheetId', 'rows', 'fields'} or type(body['sheetId']) is not int or body['sheetId'] != target['sheet_id']:
                raise NvReservationHold()
        elif item['action'] == 'update':
            if set(request) != {'updateCells'}: raise NvReservationHold()
            body = request['updateCells']
            if set(body) != {'start', 'rows', 'fields'}: raise NvReservationHold()
            origin = body['start']
            if (type(origin) is not dict or set(origin) != {'sheetId', 'rowIndex', 'columnIndex'}
                    or any(type(origin[key]) is not int for key in origin)
                    or origin['sheetId'] != target['sheet_id'] or not 0 <= origin['columnIndex'] <= 28
                    or row_index is not None and row_index != origin['rowIndex']): raise NvReservationHold()
            row_index = origin['rowIndex']; start = origin['columnIndex']
        else: raise NvReservationHold()
        if (body['fields'] != 'userEnteredValue' or type(body['rows']) is not list or len(body['rows']) != 1
                or type(body['rows'][0]) is not dict or set(body['rows'][0]) != {'values'}): raise NvReservationHold()
        cells = body['rows'][0]['values']
        if type(cells) is not list or not 1 <= len(cells) <= 29 or start + len(cells) > 29: raise NvReservationHold()
        for offset, cell in enumerate(cells):
            if type(cell) is not dict: raise NvReservationHold()
            if not cell and item['action'] == 'insert': continue
            if set(cell) != {'userEnteredValue'}: raise NvReservationHold()
            entered = cell['userEnteredValue']
            if type(entered) is not dict or set(entered) != {'stringValue'} or type(entered['stringValue']) is not str:
                raise NvReservationHold()
            column = _letter(start + offset)
            if column in values: raise NvReservationHold()
            values[column] = entered['stringValue']
    candidate = encode_tool_cells(target['sheet'], target['sheet_id'], item['action'], values, row_index=row_index)
    if json.loads(candidate.requests_json) != item['requests'] or candidate.intended_sha256 != item['intended_sha256']:
        raise NvReservationHold()
    return values


def require_unit_nv_reservation(token, binding, identity, unit):
    """Bind all actual Cabling inserts to original IDs; no send capability.

Every business image is independently re-encoded, including updates (which
cannot touch A). All inserts must use exactly the journal's original key/ID
set and original nonces. A present global journal must bind this exact wire
and action, so UNKNOWN cannot rebuild a different payload with the same IDs.
Units with no inserts have no allocation to validate here and remain HOLD.
"""
    failed = False
    try:
        from monitor.issue_tracker_send_intent import _projection
        from monitor.issue_tracker_global_attempt_journal import inspect_global_unit
        _projection(unit); enrollment.require_unit_enrollment(token, binding, identity, unit)
        action = json.loads(unit.action_preimage); target = action['identity']
        if target['sheet'] not in _FAMILIES: raise NvReservationHold()
        inserted = []
        for item in action['business']:
            values = _literal_image(item, target)
            if item['action'] == 'insert':
                key = allocator._key(tuple(item['activity_key']))
                if (key[0] != _FAMILIES[target['sheet']] or (values['K'], values['L'], values['F']) != key[1:]):
                    raise NvReservationHold()
                inserted.append((key, values['A']))
        keys = tuple(key for key, _identifier in inserted)
        result = inspect_nv_reservation(token, binding, identity, generation_id=target['generation_id'],
            publish_id=target['publish_id'], sheet=target['sheet'], requested_keys=keys)
        if result.unit_id != unit.unit_id or tuple(sorted(inserted)) != result.reservations: raise NvReservationHold()
        owner = ownership._validated_owner(token, binding)
        if owner.lock_name[:-5] + '.journal' in os.listdir(owner.directories[-1][0]):
            inspect_global_unit(token, binding, unit)
        ownership._validated_owner(token, binding)
    except Exception: failed = True
    if failed: raise NvReservationHold()
    return result
