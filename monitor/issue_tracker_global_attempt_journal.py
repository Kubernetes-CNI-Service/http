"""Uninstalled conservative spreadsheet-wide immutable attempt evidence.

One retained unit blocks ALL new units in this spreadsheet, across projects.
The sole unit's action, binding and wire are immutable; at most six durable
UNKNOWN intents survive cold processes. No completion, reset, reclamation or
network here. A typed/coherent unit is not authenticated job/admission authority,
nor does an intent alone bound real sends: fixed launcher, single consumption,
fresh checks, reservations, FIFO and COMPLETE still need integration.
"""
from dataclasses import dataclass
import hashlib
import json
import os

from monitor import issue_tracker_local_commit as local
from monitor import issue_tracker_attempt_journal as journal
from monitor import issue_tracker_spreadsheet_owner as ownership
from monitor import issue_tracker_send_intent as compiled


class GlobalAttemptHold(ValueError):
    def __init__(self): super().__init__('req7_global_attempt_unproved')


@dataclass(frozen=True)
class GlobalIntentObservation:
    attempt_count: int
    wire_sha256: str
    action_digest: str
    outcome: str


def _inputs(token, binding, unit):
    owner = ownership._validated_owner(token, binding)
    header = compiled._projection(unit)
    identity = json.loads(unit.action_preimage.decode('utf-8'))['identity']
    if identity['spreadsheet_id'] != binding.spreadsheet_id: raise GlobalAttemptHold()
    header.update(spreadsheet_id=binding.spreadsheet_id, allowlist_sha256=binding.allowlist_sha256,
                  policy_sha256=binding.policy_sha256)
    return owner, owner.directories[-1][0], owner.lock_name[:-5] + '.journal', header


def _create_folder(parent, name):
    # Partial creation is retained HOLD, but no owned descriptor may leak when
    # a directory fsync or interruption happens before returning the handle.
    os.mkdir(name, 0o700, dir_fd=parent); os.fsync(parent)
    fd = local._directory(parent, name)
    try: os.fsync(fd)
    except BaseException:
        os.close(fd); raise
    return fd


def _inspect(folder, unit, header):
    if (journal._read(folder, 'ACTION-PREIMAGE', 1024 * 1024) != unit.action_preimage
            or journal._read(folder, 'WIRE', 1024 * 1024) != unit.wire_bytes
            or journal._read(folder, 'HEADER', 16384) != local._canonical(header)
            or journal._read(folder, 'INITIALIZED', 16384) != _initialization(header)):
        raise GlobalAttemptHold()
    names = set(os.listdir(folder)); count = len(names) - 4
    if not 0 <= count <= 6 or names != {'ACTION-PREIMAGE', 'WIRE', 'HEADER', 'INITIALIZED', *(f'ATTEMPT-{i}' for i in range(1, count + 1))}:
        raise GlobalAttemptHold()
    previous = hashlib.sha256(local._canonical(header)).hexdigest()
    for index in range(1, count + 1):
        raw = journal._read(folder, f'ATTEMPT-{index}', 16384)
        expected = {**header, 'attempt_count': index, 'previous_sha256': previous, 'outcome': 'UNKNOWN'}
        if raw != local._canonical(expected): raise GlobalAttemptHold()
        previous = hashlib.sha256(raw).hexdigest()
    return count, previous


def _initialization(header):
    return local._canonical({'schema_version': 1, 'state': 'INITIALIZED',
                            'header_sha256': hashlib.sha256(local._canonical(header)).hexdigest()})


def _sync_initialization(parent, folder, header):
    """Confirm genuine post-image-barrier marker under ownership, never create it.

    A present marker means this writer previously completed ALL eight image
    barriers before it was written. Synchronize its held file and directories
    before an intent; pathname existence alone, or a fully shaped HEADER whose
    final fsync failed, must not stand in for those preceding barriers.
    """
    fd = os.open('INITIALIZED', local._flags(), dir_fd=folder)
    try:
        info = local._check(fd, directory=False)
        journal._named(folder, 'INITIALIZED', fd, directory=False)
        raw = os.read(fd, 16385)
        if len(raw) != info.st_size or raw != _initialization(header): raise GlobalAttemptHold()
        os.fsync(fd); os.fsync(folder); os.fsync(parent)
        journal._named(folder, 'INITIALIZED', fd, directory=False)
    finally: os.close(fd)


def prepare_global_unit(token, binding, unit):
    """New coherent images only; never adopt a partial/existing global store."""
    folder = None; failed = False
    try:
        owner, parent, name, header = _inputs(token, binding, unit)
        # A retained store is a conservative barrier even before ATTEMPT-1.
        # New generations/sheets/projects cannot bypass it by another key.
        if name in os.listdir(parent): raise GlobalAttemptHold()
        folder = _create_folder(parent, name)
        local._write_new(folder, 'ACTION-PREIMAGE', unit.action_preimage)
        local._write_new(folder, 'WIRE', unit.wire_bytes)
        local._write_new(folder, 'HEADER', local._canonical(header))
        journal._named(parent, name, folder, directory=True)
        ownership._validated_owner(token, binding)
        # Never create this marker until ALL eight required image barriers
        # succeeded. A failed final HEADER directory fsync otherwise leaves
        # coherent-looking bytes which must not be adopted by a later owner.
        local._write_new(folder, 'INITIALIZED', _initialization(header))
        journal._named(parent, name, folder, directory=True)
        ownership._validated_owner(token, binding)
        count, _previous = _inspect(folder, unit, header)
        if count: raise GlobalAttemptHold()
    except Exception: failed = True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed = True
    if failed: raise GlobalAttemptHold()


def _observe(token, binding, unit, append):
    folder = None; failed = False
    try:
        owner, parent, name, header = _inputs(token, binding, unit)
        folder = local._directory(parent, name)
        journal._named(parent, name, folder, directory=True)
        count, previous = _inspect(folder, unit, header)
        if append:
            if count == 6: raise GlobalAttemptHold()
            _sync_initialization(parent, folder, header)
            ownership._validated_owner(token, binding)
            journal._named(parent, name, folder, directory=True)
            count += 1
            local._write_new(folder, f'ATTEMPT-{count}', local._canonical(
                {**header, 'attempt_count': count, 'previous_sha256': previous, 'outcome': 'UNKNOWN'}))
        journal._named(parent, name, folder, directory=True)
        ownership._validated_owner(token, binding)
        verified, _previous = _inspect(folder, unit, header)
        if verified != count: raise GlobalAttemptHold()
        result = GlobalIntentObservation(count, unit.wire_sha256, unit.action_digest,
                                         'UNKNOWN' if count else 'UNATTEMPTED_OBSERVATION')
    except Exception: failed = True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed = True
    if failed: raise GlobalAttemptHold()
    return result


def inspect_global_unit(token, binding, unit):
    """Read-only global barrier/count observation; never COMPLETE or a permit."""
    return _observe(token, binding, unit, False)


def record_global_attempt_intent(token, binding, unit):
    """Persist count BEFORE any eventual send, still not a transport capability."""
    return _observe(token, binding, unit, True)


def _reserved_images(token, binding, identity, unit):
    """Reopen actual original stores, not caller-supplied counts or snapshots."""
    from monitor.issue_tracker_enrollment_journal import require_unit_enrollment, inspect_enrollment_journal
    from monitor.issue_tracker_history_preread_journal import require_history_append_capacity
    from monitor.issue_tracker_metadata_reservation import inspect_metadata_reservation
    from monitor.issue_tracker_nv_reservation import require_unit_nv_reservation

    _inputs(token, binding, unit)
    require_unit_enrollment(token, binding, identity, unit)
    original = inspect_enrollment_journal(token, binding, identity)
    history = require_history_append_capacity(token, binding, unit)
    quota = inspect_metadata_reservation(token, binding, identity, unit)
    action = json.loads(unit.action_preimage)
    nv = None
    if action['identity']['sheet'] in ('ETH Cabling', 'IB Cabling') and any(
            item['action'] == 'insert' for item in action['business']):
        nv = require_unit_nv_reservation(token, binding, identity, unit)
    ownership._validated_owner(token, binding)
    return original, history, quota, nv


def record_reserved_attempt_intent(token, binding, identity, unit):
    """Count only after the exact original reservation chain, then recheck it.

    This necessary local gate is NOT a send permit or fresh admission. It does
    not launch a worker, bound actual wire attempts, discharge hidden PROJECT
    quota, prove row continuity/FIFO, settle UNKNOWN or grant COMPLETE. The
    primitive record_global_attempt_intent remains evidence-only and cannot
    authorize transport. A failed post-count barrier leaves counted UNKNOWN;
    never decrement, repair, replace a reservation or treat the count as send.
    """
    failed = False
    try:
        before = inspect_global_unit(token, binding, unit)
        if before.attempt_count == 6: raise GlobalAttemptHold()
        images = _reserved_images(token, binding, identity, unit)
        result = _observe(token, binding, unit, True)
        if (_reserved_images(token, binding, identity, unit) != images
                or result.attempt_count != before.attempt_count + 1
                or inspect_global_unit(token, binding, unit) != result):
            raise GlobalAttemptHold()
    except Exception: failed = True
    if failed: raise GlobalAttemptHold()
    return result


def record_original_business_reserved_attempt_intent(token, binding, identity, unit):
    """Bind ALL original business images to the necessary reservation count.

    This is still evidence, NOT fresh admission, a launcher capability, FIFO
    settlement or COMPLETE. Never recreate a missing original. A post-count
    failure retains UNKNOWN; quota's hidden PROJECT limitation is unchanged.
    """
    from monitor.issue_tracker_history_preread_journal import inspect_business_preread

    def originals():
        reservations = _reserved_images(token, binding, identity, unit)
        business = inspect_business_preread(token, binding, identity, unit)
        ownership._validated_owner(token, binding)
        return reservations, business

    failed = False
    try:
        before = inspect_global_unit(token, binding, unit)
        if before.attempt_count == 6: raise GlobalAttemptHold()
        images = originals()
        result = _observe(token, binding, unit, True)
        if (originals() != images or result.attempt_count != before.attempt_count + 1
                or inspect_global_unit(token, binding, unit) != result):
            raise GlobalAttemptHold()
    except Exception: failed = True
    if failed: raise GlobalAttemptHold()
    return result


def record_receipted_original_attempt_intent(
    token, binding, identity, unit, *, qualified_source, store, writer_token,
    settings, whitelist_snapshot, expected_template_sha256, http_root, whitelist_path,
):
    """Require original protected current-cycle C6 facts around durable count.

    Hold BOTH original project and spreadsheet owners. Reopen original C6
    STATE/MANIFEST/INTENT/RECEIPT through recovery and shared admissions; replay
    actual protected C5 sources rather than trust a caller's digest projection. Bind
    generation, published image and manifest to the immutable action, alongside
    ALL retained business and reservations, current locked project policy and
    fixed held-FD target allowlist. No caller receipt, compilation or
    missing-original repair. This conservative current-cycle observation does
    NOT authorize older-cycle R2, live W1/template/nonce continuity or cadence, transport, COMPLETE
    or FIFO. A failed post-count check leaves UNKNOWN and never rolls back.
    """
    from monitor.issue_tracker_send_unit import _original_receipt_identity
    from monitor.issue_tracker_history_preread_journal import inspect_business_preread, inspect_business_source_projection
    from monitor.issue_tracker_stage_l_consumer import qualify_prod_stage_l
    from monitor.issue_tracker_local_workbook_commit import _source_rows
    from monitor.issue_tracker_online_target import inspect_project_online_target
    from monitor.issue_tracker_settings_audit_allocation import inspect_settings_audit_allocation

    def originals():
        _inputs(token, binding, unit)
        inspect_project_online_target(writer_token, binding)
        action = json.loads(unit.action_preimage)
        audits = (inspect_settings_audit_allocation(writer_token, token, binding, unit)
                  if action['audits'] else b'')
        target = action['identity']
        receipt = _original_receipt_identity(
            qualified_source, store, target['generation_id'], writer_token,
            settings, whitelist_snapshot, expected_template_sha256)
        if receipt[:3] != (target['generation_id'], target['publish_id'], action['manifest_id']):
            raise GlobalAttemptHold()
        actual_source = qualify_prod_stage_l(
            store, http_root=http_root, settings=settings,
            whitelist_snapshot=whitelist_snapshot, whitelist_path=whitelist_path,
            writer_token=writer_token)
        if actual_source != qualified_source: raise GlobalAttemptHold()
        reservations = _reserved_images(token, binding, identity, unit)
        business = inspect_business_preread(token, binding, identity, unit)
        cabling_rows, switch_rows = _source_rows(actual_source)
        if inspect_business_source_projection(token, binding, identity, unit, (*cabling_rows, *switch_rows)) != business:
            raise GlobalAttemptHold()
        if qualify_prod_stage_l(
                store, http_root=http_root, settings=settings,
                whitelist_snapshot=whitelist_snapshot, whitelist_path=whitelist_path,
                writer_token=writer_token) != actual_source:
            raise GlobalAttemptHold()
        if _original_receipt_identity(
                qualified_source, store, target['generation_id'], writer_token,
                settings, whitelist_snapshot, expected_template_sha256) != receipt:
            raise GlobalAttemptHold()
        inspect_project_online_target(writer_token, binding)
        ownership._validated_owner(token, binding)
        return receipt, actual_source, reservations, business, audits

    failed = False
    try:
        before = inspect_global_unit(token, binding, unit)
        if before.attempt_count == 6: raise GlobalAttemptHold()
        images = originals()
        result = _observe(token, binding, unit, True)
        if (originals() != images or result.attempt_count != before.attempt_count + 1
                or inspect_global_unit(token, binding, unit) != result):
            raise GlobalAttemptHold()
    except Exception: failed = True
    if failed: raise GlobalAttemptHold()
    return result


def record_owned_receipted_attempt_intent(
    token, binding, unit, *, qualified_source, store, writer_token,
    settings, whitelist_snapshot, expected_template_sha256, http_root, whitelist_path,
    identity_response, headers_response, whitelist_response, metadata_response,
):
    """Issued live read gates around the original C5/C6 durable count, NOT GO.

    No caller template identity/plan/freshness flag is accepted. W1 equality,
    strict template headers, both original enrollment nonces and absence of an
    existing unit fence must survive the original protected count. Read expiry
    or post-count policy drift retains UNKNOWN, never rolls back a count. This
    observation still does not prove hidden PROJECT quota, fresh business/History
    rows, older-cycle R2, shared cadence or any actual mutation/COMPLETE permit.
    """
    from monitor.issue_tracker_remote_history_match import observe_owned_unit_read_gates

    def gates():
        return observe_owned_unit_read_gates(
            writer_token, token, binding, unit, whitelist_snapshot=whitelist_snapshot.whitelist,
            identity_response=identity_response, headers_response=headers_response,
            whitelist_response=whitelist_response, metadata_response=metadata_response)

    failed = False
    try:
        original_gates = gates()
        result = record_receipted_original_attempt_intent(
            token, binding, original_gates.identity, unit, qualified_source=qualified_source,
            store=store, writer_token=writer_token, settings=settings,
            whitelist_snapshot=whitelist_snapshot, expected_template_sha256=expected_template_sha256,
            http_root=http_root, whitelist_path=whitelist_path)
        if gates() != original_gates or inspect_global_unit(token,binding,unit) != result:
            raise GlobalAttemptHold()
    except Exception: failed = True
    if failed: raise GlobalAttemptHold()
    return result


def record_continuous_owned_attempt_intent(
    token,binding,unit,*,writer_token,identity_response,history_response,business_reads,
    qualified_source,store,settings,whitelist_snapshot,expected_template_sha256,
    http_root,whitelist_path,headers_response,whitelist_response,metadata_response,
):
    """Actual ALL business/History reads around original C6 count, not GO.

    Never recompile an UNKNOWN unit, ignore NOOP, reset a count, settle a fence
    or accept a caller freshness flag. Post-count expiry/drift keeps UNKNOWN.
    Shared cadence, actual one-use mutation and hidden PROJECT quota remain
    separate requirements, so this necessary counter yields no send capability.
    """
    from monitor.issue_tracker_history_preread_journal import observe_owned_business_continuity
    def continuity():
        return observe_owned_business_continuity(writer_token,token,binding,unit,
            identity_response=identity_response,history_response=history_response,business_reads=business_reads)
    failed = False
    try:
        original = continuity()
        result = record_owned_receipted_attempt_intent(token,binding,unit,
            qualified_source=qualified_source,store=store,writer_token=writer_token,
            settings=settings,whitelist_snapshot=whitelist_snapshot,
            expected_template_sha256=expected_template_sha256,http_root=http_root,whitelist_path=whitelist_path,
            identity_response=identity_response,headers_response=headers_response,
            whitelist_response=whitelist_response,metadata_response=metadata_response)
        if continuity() != original or inspect_global_unit(token,binding,unit) != result: raise GlobalAttemptHold()
    except Exception: failed = True
    if failed: raise GlobalAttemptHold()
    return result
