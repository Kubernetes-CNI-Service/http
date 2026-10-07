"""Uninstalled durable action/wire binding under the existing private C-6 owner.

FrozenSendUnit is a coherent caller-supplied byte projection, NOT authenticated
qualification, enrollment, global reservation or a send permit. This records
its nonrecursive action preimage/digest durably before the legacy immutable
wire journal and any counted intent. Partial creation is HOLD, never repair.
No network, cleanup, reset, COMPLETE or expiry takeover. Project ownership is
NOT the eventual spreadsheet-wide cross-project lock; six intents are still
NOT six real sends until the fixed launcher consumes each exactly once.
"""
from dataclasses import dataclass
import hashlib
import json
import os
import re

from monitor import issue_tracker_attempt_journal as journal
from monitor import issue_tracker_local_commit as local
from monitor.issue_tracker_send_unit import FrozenSendUnit

_ROOT = 'remote-actions'


class SendIntentHold(ValueError):
    def __init__(self): super().__init__('req7_compiled_send_intent_unproved')


@dataclass(frozen=True)
class CompiledIntentObservation:
    attempt_count: int
    wire_sha256: str
    action_digest: str
    outcome: str


def _projection(unit):
    # Hash coherence only. Never promote a caller-built dataclass to authority.
    if (type(unit) is not FrozenSendUnit or unit.outcome != 'WIRE-CANDIDATE'
            or type(unit.action_preimage) is not bytes or not 1 <= len(unit.action_preimage) <= 1024 * 1024
            or hashlib.sha256(unit.action_preimage).hexdigest() != unit.action_digest
            or journal._inputs(unit.unit_id, unit.wire_bytes) != unit.wire_sha256):
        raise SendIntentHold()
    action = json.loads(unit.action_preimage.decode('utf-8'))
    if (type(action) is not dict or local._canonical(action) != unit.action_preimage
            or hashlib.sha256(local._canonical(action['identity'])).hexdigest() != unit.unit_id
            or 'action_digest' in action or 'wire_bytes' in action):
        raise SendIntentHold()
    _coherent_images(unit, action)
    return {'schema_version': 1, 'unit_id': unit.unit_id,
            'action_digest': unit.action_digest, 'wire_sha256': unit.wire_sha256}


def _coherent_images(unit, action):
    # Necessary structural coherence only, not protected provenance or a proof
    # that these caller-supplied business requests are permitted to be sent.
    if set(action) != {'identity', 'manifest_id', 'history_sheet_id', 'target_nonce', 'history_nonce',
                       'preread_sha256', 'business', 'audits', 'outcomes', 'decisions'}:
        raise SendIntentHold()
    identity = action['identity']
    if type(identity) is not dict or set(identity) != {'schema_version', 'generation_id', 'publish_id',
                                                     'spreadsheet_id', 'sheet', 'sheet_id'}:
        raise SendIntentHold()
    from monitor.issue_tracker_send_unit import _generation_identity
    _generation_identity(identity['generation_id'])
    for digest in (identity['publish_id'], action['manifest_id'],
                   action['target_nonce'], action['history_nonce'], action['preread_sha256']):
        if type(digest) is not str or re.fullmatch(r'[0-9a-f]{64}', digest) is None: raise SendIntentHold()
    outcomes = action['outcomes']; decisions = action['decisions']; business = action['business']; audits = action['audits']
    if any(type(values) is not list or len(values) > 1000 for values in (outcomes, decisions, business, audits)):
        raise SendIntentHold()
    if (type(unit.outcomes) is not tuple or tuple(tuple(pair) for pair in outcomes) != unit.outcomes
            or hashlib.sha256(local._canonical(outcomes)).hexdigest() != unit.outcome_mapping_sha256
            or type(unit.pending_audit_ids) is not tuple or unit.pending_audit_ids or len(decisions) != len(outcomes)):
        raise SendIntentHold()
    seen = set(); wanted = []
    for pair, decision in zip(outcomes, decisions):
        if (type(pair) is not list or len(pair) != 2 or type(pair[0]) is not str or not pair[0] or pair[0] in seen
                or pair[1] not in ('WIRE-CANDIDATE', 'OBSERVED-SATISFIED-AT-READ')
                or type(decision) is not dict or set(decision) != {'operation_id', 'outcome', 'intended_sha256'}
                or (decision['operation_id'], decision['outcome']) != tuple(pair)
                or type(decision['intended_sha256']) is not str
                or re.fullmatch(r'[0-9a-f]{64}', decision['intended_sha256']) is None):
            raise SendIntentHold()
        seen.add(pair[0])
        if pair[1] == 'WIRE-CANDIDATE': wanted.append(decision)
    if not wanted or len(wanted) != len(business): raise SendIntentHold()
    common = {'schema_version': 1, 'unit_id': unit.unit_id, 'manifest_id': action['manifest_id'],
              'generation_id': identity['generation_id'], 'publish_id': identity['publish_id'],
              'action_digest': unit.action_digest, 'outcome_mapping_sha256': unit.outcome_mapping_sha256,
              'target_nonce': action['target_nonce'], 'history_nonce': action['history_nonce'],
              'preread_sha256': action['preread_sha256']}
    requests = []; history = []
    for item, decision in zip(business, wanted):
        if (type(item) is not dict or set(item) != {'operation_id', 'activity_key', 'action', 'recorded_at_utc',
                                                 'intended_sha256', 'requests'}
                or item['operation_id'] != decision['operation_id'] or item['intended_sha256'] != decision['intended_sha256']
                or type(item['requests']) is not list or not item['requests']):
            raise SendIntentHold()
        requests.extend(item['requests'])
        details = local._canonical({**common, 'operation_id': item['operation_id'], 'intended_sha256': item['intended_sha256']}).decode().rstrip('\n')
        history.append((item['recorded_at_utc'], identity['sheet'], item['action'], item['operation_id'], details))
    for item in audits:
        if (type(item) is not dict or set(item) != {'event_id', 'recorded_at_utc', 'details'}
                or type(item['event_id']) is not str or not item['event_id'] or item['event_id'] in seen):
            raise SendIntentHold()
        seen.add(item['event_id'])
        details = local._canonical({**common, 'event_id': item['event_id'], 'event_details': item['details']}).decode().rstrip('\n')
        history.append((item['recorded_at_utc'], identity['sheet'], 'settings-audit', item['event_id'], details))
    fence_id = (int(unit.unit_id[:8], 16) & 0x7fffffff) or 1
    if (type(unit.fence_metadata_id) is not int or unit.fence_metadata_id != fence_id
            or type(unit.history_rows_expected) is not int or unit.history_rows_expected != len(history)):
        raise SendIntentHold()
    requests.append({'appendCells': {'sheetId': action['history_sheet_id'], 'fields': 'userEnteredValue', 'rows': [
        {'values': [{'userEnteredValue': {'stringValue': text}} for text in row]} for row in history]}})
    requests.append({'createDeveloperMetadata': {'developerMetadata': {'metadataId': fence_id, 'metadataKey': 'z',
                      'metadataValue': '1', 'visibility': 'DOCUMENT', 'location': {'sheetId': identity['sheet_id']}}}})
    if (len(requests) > 1000 or local._canonical({'requests': requests, 'includeSpreadsheetInResponse': False}) != unit.wire_bytes):
        raise SendIntentHold()


def _open(token, unit):
    owner = local._owner(token); root = folder = None
    try:
        root = local._directory(owner.root_fd, _ROOT)
        if set(os.listdir(root)) != {unit.unit_id}: raise SendIntentHold()
        folder = local._directory(root, unit.unit_id)
        journal._named(owner.root_fd, _ROOT, root, directory=True)
        journal._named(root, unit.unit_id, folder, directory=True)
        return owner, root, folder
    except BaseException:
        for fd in (folder, root):
            if fd is not None: os.close(fd)
        raise


def _inspect(folder, unit, header):
    if (set(os.listdir(folder)) != {'HEADER', 'ACTION-PREIMAGE'}
            or journal._read(folder, 'HEADER', 4096) != local._canonical(header)
            or journal._read(folder, 'ACTION-PREIMAGE', 1024 * 1024) != unit.action_preimage):
        raise SendIntentHold()


def prepare_send_intent(token, unit):
    """Durably bind action first, then immutable wire; no mutation attempt yet."""
    root = folder = None; failed = False
    try:
        header = _projection(unit); owner = local._owner(token)
        # Do not backfill action authority onto any old opaque wire journal.
        # It may already be UNKNOWN even when its bytes happen to agree.
        if {_ROOT, journal._ROOT} & set(os.listdir(owner.root_fd)): raise SendIntentHold()
        root = local._mkdir(owner.root_fd, _ROOT)
        folder = local._mkdir(root, unit.unit_id)
        local._write_new(folder, 'ACTION-PREIMAGE', unit.action_preimage)
        local._write_new(folder, 'HEADER', local._canonical(header))
        _inspect(folder, unit, header)
        local._owner(token)
        journal._named(owner.root_fd, _ROOT, root, directory=True)
        journal._named(root, unit.unit_id, folder, directory=True)
        # Never recover a partial action store after any wire-store failure.
        journal.prepare_unit(token, unit.unit_id, unit.wire_bytes)
        _inspect(folder, unit, header)
        local._owner(token)
        journal._named(owner.root_fd, _ROOT, root, directory=True)
        journal._named(root, unit.unit_id, folder, directory=True)
        observed = journal.inspect_unit(token, unit.unit_id, unit.wire_bytes)
        if observed.attempt_count != 0: raise SendIntentHold()
        result = CompiledIntentObservation(0, unit.wire_sha256, unit.action_digest, 'UNATTEMPTED_OBSERVATION')
    except Exception: failed = True
    finally:
        for fd in (folder, root):
            if fd is not None:
                try: os.close(fd)
                except OSError: failed = True
    if failed: raise SendIntentHold()
    return result


def _observe(token, unit, append):
    root = folder = None; failed = False
    try:
        header = _projection(unit); owner, root, folder = _open(token, unit)
        _inspect(folder, unit, header)
        before = journal.inspect_unit(token, unit.unit_id, unit.wire_bytes)
        if append: observed = journal.record_attempt_intent(token, unit.unit_id, unit.wire_bytes)
        else: observed = before
        _inspect(folder, unit, header)
        local._owner(token)
        journal._named(owner.root_fd, _ROOT, root, directory=True)
        journal._named(root, unit.unit_id, folder, directory=True)
        if observed.attempt_count != before.attempt_count + (1 if append else 0): raise SendIntentHold()
        result = CompiledIntentObservation(observed.attempt_count, observed.wire_sha256,
                                           unit.action_digest, observed.outcome)
    except Exception: failed = True
    finally:
        for fd in (folder, root):
            if fd is not None:
                try: os.close(fd)
                except OSError: failed = True
    if failed: raise SendIntentHold()
    return result


def inspect_send_intent(token, unit):
    """Read-only immutable action + wire + count observation, not COMPLETE."""
    return _observe(token, unit, False)


def record_compiled_attempt_intent(token, unit):
    """Count after both durable images bind; still no transport capability."""
    return _observe(token, unit, True)
