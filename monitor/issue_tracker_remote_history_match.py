"""Uninstalled journal-bound complete History matching, NOT remote APPLIED.

Only MATCHED_OBSERVATION when an actual counted global unit, original durable
preimage, both original enrollment nonces, exact permanent fence and ALL sent
business/audit rows agree. No send/clear/reset/high-water mutation. Remote read
objects remain necessary inputs, not authenticated source/admission authority;
The owned-read bridge below establishes actual fixed-read provenance, current
dual owners and typed template observations, not durable settlement authority.
"""
from dataclasses import dataclass
from contextlib import contextmanager
import hashlib
import json
import os
from urllib.parse import urlsplit

from monitor import issue_tracker_global_attempt_journal as global_journal
from monitor import issue_tracker_history_preread_journal as before
from monitor import issue_tracker_enrollment_journal as enrollment
from monitor import issue_tracker_sheets_read_decode as decode
from monitor import issue_tracker_metadata_capacity as metadata
from monitor import issue_tracker_spreadsheet_owner as ownership


class RemoteHistoryHold(ValueError):
    def __init__(self): super().__init__('req7_remote_history_unproved')


@dataclass(frozen=True)
class RemoteHistoryObservation:
    state: str
    attempt_count: int
    fence_present: bool
    target_nonce_valid: bool
    history_nonce_valid: bool
    history_rows_expected: int
    history_rows_matched: int
    history_last_row_before_send: int
    history_last_row_after_read: int
    action_digest: str
    wire_sha256: str
    metadata_sha256: str
    history_sha256: str


@dataclass(frozen=True)
class OwnedUnitReadGateObservation:
    """Necessary live read checks, not a mutation permit or globally free quota."""
    identity: object
    whitelist_sha256: str
    enrollment_sha256: str
    capacity_outcome: str


def _fence(unit, identity, response):
    """Presence of the exact ID/image, not any z=1 or substituted fence ID."""
    doc = json.loads(response.data.decode('utf-8', 'strict'), object_pairs_hook=metadata._pairs,
                     parse_constant=metadata._nonfinite)
    found = None
    for entry in doc.get('matchedDeveloperMetadata', []):
        mid, pool, size, image = metadata._entry(entry['developerMetadata'], set(dict(identity.sheet_ids).values()))
        if mid == unit.fence_metadata_id:
            if found is not None: raise RemoteHistoryHold()
            found = image
    target = json.loads(unit.action_preimage)['identity']
    expected = ('z', '1', 'DOCUMENT', 'SHEET', target['sheet_id'], None)
    return found is not None, found is not None and found != expected


def _rows(cells, first, last):
    # The typed decoder supplies ordered A:E cells. Group once, including all
    # empty cells/gaps; the 5000-row limit is not permission for O(rows*cells).
    grouped = {row: [] for row in range(first, last + 1)}
    for row, column, entered in cells:
        if row in grouped: grouped[row].append(entered)
    return tuple(tuple(grouped[row]) for row in range(first, last + 1))


@contextmanager
def _hold_match_originals(token,binding,unit):
    """Pin original count, History and nonces across the WHOLE observation.

    Same-byte replacement is not the retained original; an added attempt is
    not the count we matched. Only held private original directories/files,
    never refreshed/adopted images, may survive this context. No writes or
    COMPLETE authority are supplied by this necessary snapshot boundary.
    """
    from monitor import issue_tracker_local_commit as local
    from monitor import issue_tracker_attempt_journal as journal
    held=[]
    try:
        owner,parent,original_name,_header=global_journal._inputs(token,binding,unit)
        prefix=original_name[:-len('.journal')]
        for suffix in ('.journal','.history','.enrollment'):
            name=prefix+suffix
            folder=local._directory(parent,name)
            held.append((name,folder,None,None))
            journal._named(parent,name,folder,directory=True)
            directory_identity=journal._identity(os.fstat(folder))
            names=set(os.listdir(folder))
            if suffix=='.journal':
                count=len(names)-4
                expected={'ACTION-PREIMAGE','WIRE','HEADER','INITIALIZED',
                          *(f'ATTEMPT-{index}' for index in range(1,count+1))}
                if not 1<=count<=6: raise RemoteHistoryHold()
            elif suffix=='.history': expected={'HISTORY-RAW','HEADER','INITIALIZED'}
            else: expected={'NONCES','HEADER','INITIALIZED'}
            if names!=expected: raise RemoteHistoryHold()
            files={}
            for entry in sorted(names):
                identity_before=journal._identity(os.stat(entry,dir_fd=folder,follow_symlinks=False))
                raw=journal._read(folder,entry,2*1024*1024)
                if journal._identity(os.stat(entry,dir_fd=folder,follow_symlinks=False))!=identity_before:
                    raise RemoteHistoryHold()
                files[entry]=(raw,identity_before)
            held[-1]=(name,folder,directory_identity,files)
        def verify():
            if ownership._validated_owner(token,binding) is not owner: raise RemoteHistoryHold()
            for name,folder,directory_identity,files in held:
                journal._named(parent,name,folder,directory=True)
                if (journal._identity(os.fstat(folder))!=directory_identity
                        or set(os.listdir(folder))!=set(files)
                        or any((journal._read(folder,entry,2*1024*1024),
                            journal._identity(os.stat(entry,dir_fd=folder,follow_symlinks=False)))!=saved
                            for entry,saved in files.items())):
                    raise RemoteHistoryHold()
                journal._named(parent,name,folder,directory=True)
                if journal._identity(os.fstat(folder))!=directory_identity: raise RemoteHistoryHold()
            ownership._validated_owner(token,binding)
        verify()
        yield
        verify()
    finally:
        close_failed=False
        for _name,folder,_identity,_files in reversed(held):
            try: os.close(folder)
            except OSError: close_failed=True
        if close_failed: raise RemoteHistoryHold()


def observe_remote_history_unit(token, binding, unit, identity, metadata_plan, metadata_response, history_plan, history_response):
    failed=False
    try:
        with _hold_match_originals(token,binding,unit):
            result=_observe_remote_history_unit(token,binding,unit,identity,metadata_plan,
                                                metadata_response,history_plan,history_response)
    except Exception: failed=True
    if failed: raise RemoteHistoryHold()
    return result


def _observe_remote_history_unit(token, binding, unit, identity, metadata_plan, metadata_response, history_plan, history_response):
    """One conservative whole proof-set observation; no durable settlement.

    Fixed full-tail reads only, original prefix unchanged, exact ordered new
    rows including every piggybacked audit. No fabricated History for NOOPs.
    UNKNOWN/CONFLICT remain retained; later rejection never clears this unit.
    """
    failed = False
    try:
        state = global_journal.inspect_global_unit(token, binding, unit)
        if state.attempt_count < 1: raise RemoteHistoryHold()
        preread, original = before._read_preread(token, binding, unit)
        enrollment.require_unit_enrollment(token, binding, identity, unit)
        action = json.loads(unit.action_preimage)
        pair = enrollment.observe_enrollment_pair(token, binding, identity, metadata_plan, metadata_response,
                                                  sheet=action['identity']['sheet'])
        if urlsplit(history_plan.path).path != '/v4/spreadsheets/' + binding.spreadsheet_id: raise RemoteHistoryHold()
        post = decode.decode_history_tail(history_plan, history_response, sheet_id=action['history_sheet_id'])
        fence_present, foreign_fence = _fence(unit, identity, metadata_response)
        # Coherence was checked against actual global immutable ACTION/WIRE,
        # including full outcomes and ALL audit rows, before interpreting it.
        requests = json.loads(unit.wire_bytes)['requests']
        expected = tuple(tuple((('stringValue', cell['userEnteredValue']['stringValue']),) for cell in row['values'])
                         for row in requests[-2]['appendCells']['rows'])
        if len(expected) != unit.history_rows_expected: raise RemoteHistoryHold()
        old_tail = preread.history_last_row_before_send
        old = tuple(cell for cell in original.cells if cell[0] <= old_tail)
        still = tuple(cell for cell in post.cells if cell[0] <= old_tail)
        actual = _rows(post.cells, old_tail + 1, post.last_data_row_index)
        matched = sum(1 for first, second in zip(expected, actual) if first == second)
        conflict = (foreign_fence or post.row_count < original.row_count or old != still
                    or actual != expected or post.last_data_row_index != old_tail + len(expected))
        outcome = 'CONFLICT' if conflict else ('MATCHED_OBSERVATION' if fence_present else 'UNKNOWN')
        ownership._validated_owner(token, binding)
        result = RemoteHistoryObservation(outcome, state.attempt_count, fence_present,
            pair.target_nonce_valid, pair.history_nonce_valid, len(expected), matched,
            old_tail, post.last_data_row_index, unit.action_digest, unit.wire_sha256,
            hashlib.sha256(metadata_response.data).hexdigest(), post.source_sha256)
    except Exception: failed = True
    if failed: raise RemoteHistoryHold()
    return result


def observe_owned_remote_history_unit(writer_token, owner_token, binding, unit, *,
                                      identity_response, headers_response, metadata_response, history_response):
    """Keep original proof inputs pinned through the final issued-read gates."""
    failed=False
    try:
        with _hold_match_originals(owner_token,binding,unit):
            result=_observe_owned_remote_history_unit(writer_token,owner_token,binding,unit,
                identity_response=identity_response,headers_response=headers_response,
                metadata_response=metadata_response,history_response=history_response)
    except Exception: failed=True
    if failed: raise RemoteHistoryHold()
    return result


def _observe_owned_remote_history_unit(writer_token, owner_token, binding, unit, *,
                                       identity_response, headers_response, metadata_response, history_response):
    """Actual fixed-read observations → original journal matching, never APPLIED.

    No caller plan/identity/freshness flag is accepted. Each original completion
    must still be issued under these exact actual owner acquisitions, original
    deadline and current fixed target files, before AND after the whole match.
    Four reads are non-atomic observations, not a remote snapshot or CAS; the
    original matcher retains UNKNOWN/CONFLICT and never rewrites the journals.
    Metadata visibility accounting is not upgraded to globally complete here.
    """
    failed = False
    try:
        from monitor.issue_tracker_history_read_launcher import require_current_owned_read
        responses = (('template_identity', identity_response), ('template_headers', headers_response),
                     ('metadata', metadata_response), ('history_tail', history_response))
        plans = tuple(require_current_owned_read(writer_token, owner_token, binding, response, read_kind=kind)
                      for kind, response in responses)
        identity = decode.decode_template_identity(plans[0], identity_response)
        decode.decode_template_headers(plans[1], headers_response, identity)
        result = observe_remote_history_unit(owner_token, binding, unit, identity,
                                             plans[2], metadata_response, plans[3], history_response)
        # A matching response must not escape after local ownership/policy or
        # any original observation deadline becomes invalid during parsing.
        for kind, response in responses:
            require_current_owned_read(writer_token, owner_token, binding, response, read_kind=kind)
    except Exception: failed = True
    if failed: raise RemoteHistoryHold()
    return result


def observe_owned_unit_read_gates(writer_token, owner_token, binding, unit, *,
                                  whitelist_snapshot, identity_response, headers_response,
                                  whitelist_response, metadata_response):
    """Fresh original W1/template/nonces under actual dual owners, not GO.

    Read-only metadata inventory still cannot see other PROJECT scopes. Reject
    visible overflow, and any already-present unit fence must be reconciled,
    never turned into a new counted send here. Full row/History continuity,
    original C5/C6/cadence/reservations and the fixed mutation permit are separate.
    """
    failed=False
    try:
        from monitor.issue_tracker_history_read_launcher import require_current_owned_read
        from monitor.issue_tracker_online_whitelist_read import compare_online_whitelist_read
        responses=(('template_identity',identity_response),('template_headers',headers_response),
                   ('whitelist',whitelist_response),('metadata',metadata_response))
        plans=tuple(require_current_owned_read(writer_token,owner_token,binding,response,read_kind=kind)
                    for kind,response in responses)
        identity=decode.decode_template_identity(plans[0],identity_response)
        decode.decode_template_headers(plans[1],headers_response,identity)
        whitelist=compare_online_whitelist_read(plans[2],whitelist_response,whitelist_snapshot)
        if whitelist.sheet_id != dict(identity.sheet_ids)['Whitelist']: raise RemoteHistoryHold()
        global_journal.inspect_global_unit(owner_token,binding,unit)
        enrollment.require_unit_enrollment(owner_token,binding,identity,unit)
        action=json.loads(unit.action_preimage)
        pair=enrollment.observe_enrollment_pair(owner_token,binding,identity,plans[3],metadata_response,
                                                sheet=action['identity']['sheet'])
        capacity=metadata.observe_metadata_capacity(plans[3],metadata_response,identity,reservations=())
        if capacity.outcome=='STOP_CAPACITY' or _fence(unit,identity,metadata_response)[0]: raise RemoteHistoryHold()
        for kind,response in responses:
            require_current_owned_read(writer_token,owner_token,binding,response,read_kind=kind)
        result=OwnedUnitReadGateObservation(identity,whitelist.rules_sha256,pair.journal_sha256,capacity.outcome)
    except Exception: failed=True
    if failed: raise RemoteHistoryHold()
    return result
