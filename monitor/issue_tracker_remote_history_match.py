"""Uninstalled journal-bound complete History matching, NOT remote APPLIED.

Only MATCHED_OBSERVATION when an actual counted global unit, original durable
preimage, both original enrollment nonces, exact permanent fence and ALL sent
business/audit rows agree. No send/clear/reset/high-water mutation. Remote read
objects remain necessary inputs, not authenticated source/admission authority;
an eventual audited launcher/settlement bridge must establish those separately.
"""
from dataclasses import dataclass
import hashlib
import json
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


def observe_remote_history_unit(token, binding, unit, identity, metadata_plan, metadata_response, history_plan, history_response):
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
