"""Uninstalled G1 original visible quota reserved for an actual frozen unit.

Original nonces, global wire/action and fixed metadata response are mandatory.
The permanent fence is derived from that wire, never caller-supplied quota.
Hidden PROJECT metadata is still unproved: this is NOT admission, COMPLETE,
reclamation or transport permission. No network, expiry, reset or cleanup.
"""
from dataclasses import dataclass
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
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
    from monitor.issue_tracker_history_preread_journal import require_history_append_capacity
    owner, parent, name, base = global_journal._inputs(token, binding, unit)
    state = global_journal.inspect_global_unit(token, binding, unit)
    enrollment.require_unit_enrollment(token, binding, identity, unit)
    history = require_history_append_capacity(token, binding, unit)
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
            'identity_sha256': identity.source_sha256, 'sheet_ids': identity.sheet_ids,
            'history_source_sha256': history.source_sha256, 'history_first_row_index': history.first_row_index,
            'history_last_row_index': history.last_row_index, 'history_rows_reserved': history.rows_reserved}
    # Follow the actual global journal's original namespace. Catalog units
    # each own a permanent fence image; the legacy shared slot must not be
    # created beside a catalog and poison every subsequent original replay.
    return parent, name[:-len('.journal')] + '.metadata', base, state, action['identity']['sheet'], fence


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


@contextmanager
def _hold_quota_originals(parent,name,folder):
    """Pin the original quota namespace/images through final inspection.

    Identical-byte replacements are not the retained originals. This context
    never creates, adopts, repairs or deletes any image; all descriptors are
    closed on both successful and failed inspection.
    """
    held=[]
    try:
        journal._named(parent,name,folder,directory=True)
        directory_identity=journal._identity(os.fstat(folder))
        if set(os.listdir(folder))!=_NAMES: raise MetadataReservationHold()
        for entry in sorted(_NAMES):
            fd=os.open(entry,local._flags(),dir_fd=folder)
            held.append((entry,fd,None))
            journal._named(folder,entry,fd,directory=False)
            held[-1]=(entry,fd,journal._identity(os.fstat(fd)))
        def verify():
            journal._named(parent,name,folder,directory=True)
            if journal._identity(os.fstat(folder))!=directory_identity or set(os.listdir(folder))!=_NAMES:
                raise MetadataReservationHold()
            for entry,fd,identity in held:
                journal._named(folder,entry,fd,directory=False)
                if journal._identity(os.fstat(fd))!=identity: raise MetadataReservationHold()
            journal._named(parent,name,folder,directory=True)
            if journal._identity(os.fstat(folder))!=directory_identity: raise MetadataReservationHold()
        verify()
        yield verify
        verify()
    finally:
        failed=False
        for _entry,fd,_identity in reversed(held):
            try: os.close(fd)
            except OSError: failed=True
        if failed: raise MetadataReservationHold()


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
    return _prepare_metadata_reservation(token,binding,identity,unit,plan,response)


def _prepare_metadata_reservation(token,binding,identity,unit,plan,response,*,revalidate=None):
    """Keep original quota FDs through internal final source revalidation."""
    folder = None; failed = False
    try:
        parent, name, base, state, sheet, fence = _inputs(token, binding, identity, unit)
        if state.attempt_count != 0 or name in os.listdir(parent): raise MetadataReservationHold()
        budget = _observe(token, binding, identity, sheet, fence, plan, response)
        reservation = local._canonical(fence); header = _header(base, plan, budget, reservation)
        if len(local._canonical(header)) > 16384: raise MetadataReservationHold()
        folder = global_journal._create_folder(parent, name)
        journal._write_read_image(folder, 'METADATA-RAW', response.data)
        local._write_new(folder, 'HEADER', local._canonical(header))
        local._write_new(folder, 'RESERVATION', reservation)
        journal._named(parent, name, folder, directory=True); ownership._validated_owner(token, binding)
        # Folder+parent and three file+folder pairs: all eight image barriers
        # must precede INITIALIZED. Interrupted stores remain retained HOLD.
        local._write_new(folder, 'INITIALIZED', _marker(header))
        with _hold_quota_originals(parent,name,folder):
            result = _inspect(token, binding, identity, parent, name, folder, base, sheet, fence)
            if revalidate is not None: revalidate()
            ownership._validated_owner(token, binding)
    except Exception: failed = True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed = True
    if failed: raise MetadataReservationHold()
    return result


def prepare_owned_project_metadata_reservation(writer_token,owner_token,binding,authentication,unit,*,
                                               identity_response,metadata_response):
    """Actual project reads -> original unit's retained quota, NOT admission.

    No caller identity, plan, Cloud project, reservation list or freshness flag.
    The fixed owned auth/read registry and original typed template establish
    provenance; the existing actual global/enrollment/History journal derives
    the fence and keeps its permanent reservation. Late expiry/revocation
    retains any written quota and returns HOLD, never rollback/reset or GO.
    Dedicated-table/historical exclusivity is NOT inferred from these reads;
    even an empty exact response remains VISIBLE_ONLY_UNPROVED.
    """
    failed=False
    try:
        from monitor.issue_tracker_history_read_launcher import require_current_owned_project_read
        from monitor.issue_tracker_sheets_read_decode import decode_template_identity
        def current():
            identity_plan,project,digest=require_current_owned_project_read(
                writer_token,owner_token,binding,identity_response,authentication,read_kind='template_identity')
            metadata_plan,metadata_project,metadata_digest=require_current_owned_project_read(
                writer_token,owner_token,binding,metadata_response,authentication,read_kind='metadata')
            if (metadata_project,metadata_digest)!=(project,digest): raise MetadataReservationHold()
            return identity_plan,metadata_plan
        identity_plan,metadata_plan=current()
        identity=decode_template_identity(identity_plan,identity_response)
        current()
        # Revalidate inside the primitive's held-original scope, not after it
        # has closed and a same-byte quota replacement could be freshly read.
        result=_prepare_metadata_reservation(owner_token,binding,identity,unit,metadata_plan,
                                             metadata_response,revalidate=current)
    except Exception: failed=True
    if failed: raise MetadataReservationHold()
    return result


def inspect_metadata_reservation(token, binding, identity, unit):
    """Existing immutable original reservation, including after UNKNOWN."""
    folder = None; failed = False
    try:
        parent, name, base, _state, sheet, fence = _inputs(token, binding, identity, unit)
        folder = local._directory(parent, name); journal._named(parent, name, folder, directory=True)
        with _hold_quota_originals(parent,name,folder):
            result = _inspect(token, binding, identity, parent, name, folder, base, sheet, fence)
            ownership._validated_owner(token, binding)
    except Exception: failed = True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed = True
    if failed: raise MetadataReservationHold()
    return result


@contextmanager
def _hold_owned_project_catalog_metadata_capacity(writer_token,owner_token,binding,authentication,*,
                                                 identity_response,metadata_response):
    """Original live project reads -> ALL retained fences, still NOT G1 GO.

    No caller plan, identity, reservation list or completeness declaration.
    Both issued reads and their actual auth acquisition remain current across
    the consumer and final held-image check. Hidden PROJECT metadata remains
    unproved; this never grants FIRST/R2, increments count or releases quota.
    """
    failed=False
    try:
        from monitor.issue_tracker_history_read_launcher import require_current_owned_project_read
        from monitor.issue_tracker_sheets_read_decode import decode_template_identity
        def current():
            identity_plan,project,digest=require_current_owned_project_read(
                writer_token,owner_token,binding,identity_response,authentication,read_kind='template_identity')
            metadata_plan,metadata_project,metadata_digest=require_current_owned_project_read(
                writer_token,owner_token,binding,metadata_response,authentication,read_kind='metadata')
            if (metadata_project,metadata_digest)!=(project,digest): raise MetadataReservationHold()
            return identity_plan,metadata_plan
        identity_plan,metadata_plan=current()
        identity=decode_template_identity(identity_plan,identity_response)
        with _hold_catalog_metadata_capacity(owner_token,binding,identity,metadata_plan,
                                            metadata_response) as (budget,verify_inventory):
            def verify():
                current(); verify_inventory(); current()
            verify()
            yield budget,verify
            verify()
    except Exception:
        failed=True
    if failed:
        raise MetadataReservationHold() from None


@contextmanager
def _hold_owned_project_mixed_metadata_capacity(writer_token, owner_token, binding, authentication, *,
                                               identity_response, metadata_response):
    """Charge ALL permanent fences from actual mixed settlement originals.

    Only full held C6/COMPLETE/APPLIED/KEY originals permit a historical unit
    without a quota family. Its immutable wire fence remains charged anyway.
    Pending/UNKNOWN units require every original quota image. No caller rows,
    settlement flag, fence, identity, plan or completeness claim is accepted;
    no family is created, repaired, released or treated as G1/FIRST/R2 GO.
    """
    failed = False
    try:
        from monitor import issue_tracker_unit_catalog as catalog
        from monitor import issue_tracker_retained_inventory as inventory
        from monitor.issue_tracker_history_read_launcher import require_current_owned_project_read
        from monitor.issue_tracker_sheets_read_decode import decode_template_identity
        from monitor.issue_tracker_metadata_capacity import observe_metadata_capacity
        def current():
            identity_plan, project, digest = require_current_owned_project_read(
                writer_token, owner_token, binding, identity_response, authentication, read_kind='template_identity')
            metadata_plan, other_project, other_digest = require_current_owned_project_read(
                writer_token, owner_token, binding, metadata_response, authentication, read_kind='metadata')
            if (other_project, other_digest) != (project, digest):
                raise MetadataReservationHold()
            return identity_plan, metadata_plan
        identity_plan, metadata_plan = current()
        identity = decode_template_identity(identity_plan, identity_response)
        owner = ownership._validated_owner(owner_token, binding)
        parent = owner.directories[-1][0]; stem = owner.lock_name[:-5]
        held = catalog._Originals()
        def verify_quota():
            current()
            if ownership._validated_owner(owner_token, binding) is not owner:
                raise MetadataReservationHold()
            held.verify(); current()
        def close_quota():
            try:
                verify_quota()
            finally:
                held.close()
        with ExitStack() as scope:
            # Quota originals survive BOTH inventory and mixed proof finalizers.
            # The supplied actual project owner/auth remain live independently.
            scope.callback(close_quota)
            settlements, verify_settlements = scope.enter_context(
                inventory._hold_all_project_mixed_settlements(owner_token, binding))
            rows, verify_inventory = scope.enter_context(
                inventory._hold_catalog_retained_inventory(owner_token, binding))
            if tuple(row.unit for row in rows) != tuple(item.unit for item in settlements):
                raise MetadataReservationHold()
            held.namespace = (parent, stem + '.',
                              {name for name in os.listdir(parent) if name.startswith(stem + '.')})
            fences = []
            for row, settlement in zip(rows, settlements):
                if row.attempt_count != settlement.attempt_count:
                    raise MetadataReservationHold()
                if 'metadata' not in row.families:
                    if not settlement.settled:
                        raise MetadataReservationHold()
                    _owner, actual_parent, _name, _base = global_journal._inputs(owner_token, binding, row.unit)
                    enrollment.require_unit_enrollment(owner_token, binding, identity, row.unit)
                    action = json.loads(row.unit.action_preimage)
                    wire_fence = json.loads(row.unit.wire_bytes)['requests'][-1]['createDeveloperMetadata']['developerMetadata']
                    fence = {**wire_fence, 'location': {'locationType': 'SHEET', **wire_fence['location']}}
                    sheet = action['identity']['sheet']
                    if actual_parent != parent:
                        raise MetadataReservationHold()
                else:
                    actual_parent, name, base, _state, sheet, fence = _inputs(owner_token, binding, identity, row.unit)
                    if actual_parent != parent or name != stem + '.unit-' + row.unit.unit_id + '.metadata':
                        raise MetadataReservationHold()
                    folder = held.directory(parent, name)
                    images = {}
                    for entry in sorted(_NAMES):
                        images[entry], _original = held.file(folder, entry,
                            2 * _LIMIT if entry == 'METADATA-RAW' else 16384)
                    _inspect(owner_token, binding, identity, parent, name, folder, base, sheet, fence)
                    if images['RESERVATION'] != local._canonical(fence):
                        raise MetadataReservationHold()
                enrollment.observe_enrollment_pair(owner_token, binding, identity, metadata_plan, metadata_response, sheet=sheet)
                fences.append(fence)
            budget = observe_metadata_capacity(metadata_plan, metadata_response, identity, reservations=tuple(fences))
            def verify():
                verify_quota(); verify_settlements(); verify_inventory(); verify_quota()
            verify(); held.sync(); verify()
            yield budget, verify
            verify()
        # A last proof/quota finalizer may revoke or expire the original read.
        # Never re-open originals or use already-closed verifier callbacks.
        current()
    except Exception:
        failed = True
    if failed:
        raise MetadataReservationHold() from None


@contextmanager
def _hold_catalog_metadata_capacity(token, binding, identity, plan, response):
    """Charge ALL original permanent fences while their actual images stay held.

    No caller reservation list or selected-unit prefix. UNKNOWN and matching
    visible fences never release a reservation. The supplied fixed read is
    only visible accounting, NOT original remote source/freshness, historical
    Cloud exclusivity, complete inventory, NEW or a transport capability.
    """
    from monitor import issue_tracker_unit_catalog as catalog
    from monitor import issue_tracker_retained_inventory as inventory
    from monitor.issue_tracker_metadata_capacity import observe_metadata_capacity
    held = catalog._Originals(); failed = False
    try:
        owner = ownership._validated_owner(token, binding)
        parent = owner.directories[-1][0]; stem = owner.lock_name[:-5]
        with ExitStack() as scope:
            rows, verify_inventory = scope.enter_context(
                inventory._hold_catalog_retained_inventory(token, binding))
            held.namespace = (parent, stem + '.',
                              {name for name in os.listdir(parent) if name.startswith(stem + '.')})
            fences = []
            for row in rows:
                actual_parent, name, base, _state, sheet, fence = _inputs(token, binding, identity, row.unit)
                if actual_parent != parent or name != stem + '.unit-' + row.unit.unit_id + '.metadata':
                    raise MetadataReservationHold()
                folder = held.directory(parent, name)
                images = {}
                for entry in sorted(_NAMES):
                    images[entry], _original = held.file(folder, entry,
                        2 * _LIMIT if entry == 'METADATA-RAW' else 16384)
                _inspect(token, binding, identity, parent, name, folder, base, sheet, fence)
                if images['RESERVATION'] != local._canonical(fence):
                    raise MetadataReservationHold()
                enrollment.observe_enrollment_pair(token, binding, identity, plan, response, sheet=sheet)
                fences.append(fence)
            result = observe_metadata_capacity(plan, response, identity, reservations=tuple(fences))
            def verify():
                if ownership._validated_owner(token, binding) is not owner:
                    raise MetadataReservationHold()
                verify_inventory(); held.verify(); verify_inventory()
            verify(); held.sync(); verify()
            yield result, verify
            verify()
    except Exception:
        failed = True
    finally:
        try:
            held.close()
        except Exception:
            failed = True
    if failed:
        raise MetadataReservationHold() from None
