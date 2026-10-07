"""Uninstalled G1 original visible quota reserved for an actual frozen unit.

Original nonces, global wire/action and fixed metadata response are mandatory.
The permanent fence is derived from that wire, never caller-supplied quota.
Hidden PROJECT metadata is still unproved: this is NOT admission, COMPLETE,
reclamation or transport permission. No network, expiry, reset or cleanup.
"""
from dataclasses import dataclass
import hashlib
import json
import os
import uuid
from types import SimpleNamespace

from monitor import issue_tracker_local_commit as local
from monitor import issue_tracker_attempt_journal as journal
from monitor import issue_tracker_global_attempt_journal as global_journal
from monitor import issue_tracker_spreadsheet_owner as ownership
from monitor import issue_tracker_enrollment_journal as enrollment

_NAMES = {'METADATA-RAW', 'HEADER', 'RESERVATION', 'INITIALIZED'}
_LIMIT = 1024 * 1024


class MetadataReservationHold(ValueError):
    def __init__(self): super().__init__('req7_metadata_reservation_unproved')


@dataclass(frozen=True)
class MetadataReservationObservation:
    outcome: str
    pools: tuple
    outstanding_reservations: int
    source_sha256: str
    identity_sha256: str
    fence_metadata_id: int
    action_digest: str
    wire_sha256: str
    inventory_complete: bool = False
    counting: str = 'utf8_bytes_conservative'


def _inputs(token, binding, identity, unit):
    owner, parent, name, base = global_journal._inputs(token, binding, unit)
    state = global_journal.inspect_global_unit(token, binding, unit)
    enrollment.require_unit_enrollment(token, binding, identity, unit)
    original = enrollment.inspect_enrollment_journal(token, binding, identity)
    action = json.loads(unit.action_preimage)
    # _inputs/_projection already require the canonical frozen composer and
    # its exact business, History and permanent z=1 fence wire structure.
    wire_fence = json.loads(unit.wire_bytes)['requests'][-1]['createDeveloperMetadata']['developerMetadata']
    # createDeveloperMetadata's request uses sheetId; the capacity decoder
    # consumes the read-response location shape (with computed locationType).
    # Add only that derived discriminator, without changing the frozen wire.
    fence = {**wire_fence, 'location': {'locationType': 'SHEET', **wire_fence['location']}}
    base = {**base, 'enrollment_sha256': original.journal_sha256,
            'identity_sha256': identity.source_sha256, 'sheet_ids': identity.sheet_ids}
    return parent, owner.lock_name[:-5] + '.metadata', base, state, action['identity']['sheet'], fence


def _observe(token, binding, identity, sheet, fence, plan, response):
    from monitor.issue_tracker_metadata_capacity import observe_metadata_capacity, _pairs, _nonfinite
    enrollment.observe_enrollment_pair(token, binding, identity, plan, response, sheet=sheet)
    budget = observe_metadata_capacity(plan, response, identity, reservations=(fence,))
    # Even an exactly matching visible fence is not an available new ID.
    # Do not adopt it, replace it or choose a different ID after intent.
    document = json.loads(response.data.decode('utf-8', 'strict'), object_pairs_hook=_pairs, parse_constant=_nonfinite)
    if (budget.outcome != 'VISIBLE_ONLY_UNPROVED' or any(
            item['developerMetadata']['metadataId'] == fence['metadataId']
            for item in document.get('matchedDeveloperMetadata', []))):
        raise MetadataReservationHold()
    return budget


def _header(base, plan, budget, reservation):
    return {**base, 'read_path': plan.path, 'source_sha256': budget.source_sha256,
            'reservation_sha256': hashlib.sha256(reservation).hexdigest()}


def _marker(header):
    return local._canonical({'schema_version': 1, 'state': 'INITIALIZED',
                             'header_sha256': hashlib.sha256(local._canonical(header)).hexdigest()})


def _write_raw(folder, raw):
    # The existing manifest writer is bounded to 1 MiB. A fixed metadata read
    # has a separate 2 MiB contract; retain every original byte, never truncate
    # it or increase other writers' limits. Same no-replace/file+folder barriers.
    if type(raw) is not bytes or not 1 <= len(raw) <= 2 * _LIMIT: raise MetadataReservationHold()
    name = '.pending-' + uuid.uuid4().hex
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=folder)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0: raise MetadataReservationHold()
            view = view[count:]
        os.fsync(fd)
    finally: os.close(fd)
    local._rename_new(folder, name, 'METADATA-RAW')
    os.fsync(folder)


def _inspect(token, binding, identity, parent, name, folder, base, sheet, fence):
    from monitor.issue_tracker_metadata_capacity import PreparedMetadataRead, _BODY
    if set(os.listdir(folder)) != _NAMES: raise MetadataReservationHold()
    header_raw = journal._read(folder, 'HEADER', 16384)
    header = json.loads(header_raw.decode('utf-8', 'strict'))
    if type(header) is not dict or type(header.get('read_path')) is not str: raise MetadataReservationHold()
    # Fixed non-secret syntax token for offline decoder validation ONLY.
    # No original bearer is stored and this plan is never sent to a transport.
    plan = PreparedMetadataRead('sheets.googleapis.com', header['read_path'], 'POST',
        (('Accept', 'application/json'), ('Authorization', 'Bearer journal-replay'),
         ('Content-Type', 'application/json')), _BODY)
    raw = journal._read(folder, 'METADATA-RAW', 2 * _LIMIT)
    budget = _observe(token, binding, identity, sheet, fence, plan,
                      SimpleNamespace(status=200, complete=True, data=raw))
    reservation = local._canonical(fence)
    if journal._read(folder, 'RESERVATION', 16384) != reservation: raise MetadataReservationHold()
    expected = _header(base, plan, budget, reservation)
    if header_raw != local._canonical(expected): raise MetadataReservationHold()
    fd = os.open('INITIALIZED', local._flags(), dir_fd=folder)
    try:
        info = local._check(fd, directory=False); journal._named(folder, 'INITIALIZED', fd, directory=False)
        marker = os.read(fd, 4097)
        if marker != _marker(expected) or len(marker) != info.st_size: raise MetadataReservationHold()
        os.fsync(fd); os.fsync(folder); os.fsync(parent)
        journal._named(folder, 'INITIALIZED', fd, directory=False)
    finally: os.close(fd)
    journal._named(parent, name, folder, directory=True)
    if set(os.listdir(folder)) != _NAMES: raise MetadataReservationHold()
    return MetadataReservationObservation(budget.outcome, budget.pools, budget.outstanding_reservations,
        budget.source_sha256, budget.identity_sha256, fence['metadataId'], base['action_digest'], base['wire_sha256'])


def prepare_metadata_reservation(token, binding, identity, unit, plan, response):
    """New actual-unit image before any intent; partial state cannot be adopted."""
    folder = None; failed = False
    try:
        parent, name, base, state, sheet, fence = _inputs(token, binding, identity, unit)
        if state.attempt_count != 0 or name in os.listdir(parent): raise MetadataReservationHold()
        budget = _observe(token, binding, identity, sheet, fence, plan, response)
        reservation = local._canonical(fence); header = _header(base, plan, budget, reservation)
        if len(local._canonical(header)) > 16384: raise MetadataReservationHold()
        folder = global_journal._create_folder(parent, name)
        _write_raw(folder, response.data)
        local._write_new(folder, 'HEADER', local._canonical(header))
        local._write_new(folder, 'RESERVATION', reservation)
        journal._named(parent, name, folder, directory=True); ownership._validated_owner(token, binding)
        # Folder+parent and three file+folder pairs: all eight image barriers
        # must precede INITIALIZED. Interrupted stores remain retained HOLD.
        local._write_new(folder, 'INITIALIZED', _marker(header))
        result = _inspect(token, binding, identity, parent, name, folder, base, sheet, fence)
        ownership._validated_owner(token, binding)
    except Exception: failed = True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed = True
    if failed: raise MetadataReservationHold()
    return result


def inspect_metadata_reservation(token, binding, identity, unit):
    """Existing immutable original reservation, including after UNKNOWN."""
    folder = None; failed = False
    try:
        parent, name, base, _state, sheet, fence = _inputs(token, binding, identity, unit)
        folder = local._directory(parent, name); journal._named(parent, name, folder, directory=True)
        result = _inspect(token, binding, identity, parent, name, folder, base, sheet, fence)
        ownership._validated_owner(token, binding)
    except Exception: failed = True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed = True
    if failed: raise MetadataReservationHold()
    return result
