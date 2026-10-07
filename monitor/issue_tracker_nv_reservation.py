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
    owner, parent, enrollment_name, original = enrollment._inputs(token, binding, identity)
    observed = enrollment.inspect_enrollment_journal(token, binding, identity)
    if (type(sheet) is not str or sheet not in _FAMILIES
            or any(type(digest) is not str or re.fullmatch(r'[0-9a-f]{64}', digest) is None
                   for digest in (generation_id, publish_id))
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
        local._write_new(folder, 'ETH-RAW', eth_response.data)
        local._write_new(folder, 'IB-RAW', ib_response.data)
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
