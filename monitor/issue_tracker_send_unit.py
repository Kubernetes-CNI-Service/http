"""Uninstalled C-19 immutable batch composer, NOT an online send/admission API.

The pure freeze_send_unit binds caller images. freeze_prod_source_unit replays
protected C5 sources, but caller coordinates, observations, local generation,
nonces and occupied IDs still are NOT authenticated as original receipt,
enrollment or global capacity. No network, credential, permit, COMPLETE,
reservation or receipt is created.
An eventual fixed launcher must be dominated by fresh admission and the
spreadsheet-wide owner; opaque local intent counting still does not bound sends.
The 31-bit explicit fence projection can collide: collision means HOLD, never
choose a different ID or infer that an existing fence proves this unit COMPLETE.
"""
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
import re

from monitor.issue_tracker_online_cells import encode_tool_cells
from monitor.issue_tracker_manifest import _runtime_operation, _validated_operations

_FAMILY = {"ETH&IB Switch": "switch", "ETH Cabling": "eth_cabling", "IB Cabling": "ib_cabling"}
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_MAX_BODY = 1024 * 1024
_MAX_REQUESTS = 1000


class SendUnitHold(ValueError):
    def __init__(self): super().__init__("req7_send_unit_unproved")


@dataclass(frozen=True)
class FrozenSendUnit:
    unit_id: str
    wire_bytes: bytes = field(repr=False)
    wire_sha256: str
    action_preimage: bytes = field(repr=False)
    action_digest: str
    outcomes: tuple
    outcome_mapping_sha256: str
    fence_metadata_id: object
    history_rows_expected: int
    pending_audit_ids: tuple
    outcome: str


def prepare_mutation_request(binding, token, unit):
    """Whole coherent C19 image, fixed batchUpdate path; no URL/body override.

    The existing compiler/journal projection enforces <=1 MiB and <=1000
    requests, including History/fence. Structural coherence does not prove
    original sources, durable one-use consumption, cadence or hidden quota.
    This uninstalled shape creates no socket/journal and grants no authority.
    """
    failed = False
    try:
        from monitor.issue_tracker_sheets_read_plan import prepare_template_identity_read, PreparedSheetsMutation
        from monitor.issue_tracker_send_intent import _projection
        base = prepare_template_identity_read(binding,token)
        _projection(unit)
        if json.loads(unit.action_preimage)['identity']['spreadsheet_id'] != binding.spreadsheet_id:
            raise SendUnitHold()
        result = PreparedSheetsMutation(base.host,'/v4/spreadsheets/'+binding.spreadsheet_id+':batchUpdate',
            'POST',unit.wire_bytes,base.headers+(('Content-Type','application/json'),),
            unit.wire_sha256,binding,token,unit)
    except Exception: failed = True
    if failed: raise SendUnitHold()
    return result


def _validate_mutation_request(prepared):
    # Revalidate before native connection creation, including token expiry.
    # Dataclass equality alone would accept bool/int as the fixed float budget.
    from monitor.issue_tracker_sheets_read_plan import PreparedSheetsMutation
    if (type(prepared) is not PreparedSheetsMutation or type(prepared.budget_seconds) is not float
            or prepared.budget_seconds != 60.0
            or prepared != prepare_mutation_request(prepared.binding,prepared.token,prepared.unit)):
        raise SendUnitHold()


def _canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8", "strict")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise SendUnitHold()
        result[key] = value
    return result


def _nonfinite(_value): raise SendUnitHold()


def _digest(value):
    if type(value) is not str or _SHA.fullmatch(value) is None: raise SendUnitHold()
    return value


def _generation_identity(value):
    """Preserve native C6 names; a well-shaped identity is NOT a receipt.

    Digest-only isolated candidate identities remain representable, never an
    authority to manufacture/adopt a local generation. Actual receipt/source
    binding and handoff/recovery still must dominate any transport boundary.
    """
    if type(value) is not str: raise SendUnitHold()
    match = re.fullmatch(r'gen-([0-9]{20})-([0-9a-f]{32})', value)
    if match is not None and int(match.group(1)) > 0: return value
    return _digest(value)


def _text(value):
    if type(value) is not str or not 1 <= len(value) <= 32768 or "\x00" in value: raise SendUnitHold()
    value.encode("utf-8", "strict")
    return value


def _timestamp(value):
    if type(value) is not str or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value) is None:
        raise SendUnitHold()
    datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    return value


def _identifier(value):
    if type(value) is not int or not 0 <= value <= 2147483647: raise SendUnitHold()
    return value


def freeze_send_unit(*, manifest, manifest_id, generation_id, publish_id,
                     spreadsheet_id, sheet, sheet_id, history_sheet_id,
                     target_nonce, history_nonce, preread_sha256,
                     business, audits, occupied_metadata_ids):
    """Freeze one finite batch, without silently selecting/chunking operations.

Every target-family manifest operation must have one ordered business input.
Real C-8 encoding determines NOOP, not a caller assertion. Audit rows piggyback
only when actual business requests exist. The action digest preimage excludes
History and its own digest, while binding ALL outcomes and ALL assigned audits.
Returned byte strings cannot track later mutation of supplied dictionaries.
"""
    failed = False
    try:
        result = _freeze(manifest, manifest_id, generation_id, publish_id, spreadsheet_id,
                         sheet, sheet_id, history_sheet_id, target_nonce, history_nonce,
                         preread_sha256, business, audits, occupied_metadata_ids)
    except Exception:
        failed = True
    if failed: raise SendUnitHold()
    return result


def freeze_prod_source_unit(qualified, store, *, http_root, settings,
                           whitelist_snapshot, whitelist_path, metadata,
                           expected_template_sha256, placements, writer_token=None,
                           **unit_binding):
    """Reverify protected C5 sources and derive ALL business text from them.

    No caller manifest, business values or timestamp override is accepted.
    Placements are necessary caller coordinates/observations, NOT row identity
    or allocation authority. Nonces, generation/publication and preread identities
    still need original C6/global/reservation binding before any send. This
    uninstalled compiler creates no journal, workbook, permit or transport.
    """
    failed = False
    try:
        from monitor.issue_tracker_local_commit import _owner
        from monitor.issue_tracker_local_workbook_commit import _source_rows
        from monitor.issue_tracker_manifest import freeze_prod_stage_l_manifest
        from monitor.issue_tracker_online_cells import source_tool_values

        names = {'generation_id', 'publish_id', 'spreadsheet_id', 'sheet', 'sheet_id',
                 'history_sheet_id', 'target_nonce', 'history_nonce', 'preread_sha256',
                 'audits', 'occupied_metadata_ids'}
        if (set(unit_binding) != names or type(unit_binding['sheet']) is not str
                or unit_binding['sheet'] not in _FAMILY or type(placements) is not tuple
                or len(placements) > 1000): raise SendUnitHold()
        owner = _owner(writer_token)
        if str(owner.project) != str(store.project_identity): raise SendUnitHold()
        context = dict(http_root=http_root, settings=settings, whitelist_snapshot=whitelist_snapshot,
                       whitelist_path=whitelist_path, metadata=metadata,
                       expected_template_sha256=expected_template_sha256, writer_token=writer_token)
        manifest, manifest_id = freeze_prod_stage_l_manifest(qualified, store, **context)
        family = _FAMILY[unit_binding['sheet']]
        operations = [item for item in json.loads(manifest)['operations'] if item['activity_key'][0] == family]
        cabling, switch = _source_rows(qualified)
        by_key = {row.activity_key: row for row in (*cabling, *switch)}
        if len(by_key) != len(cabling) + len(switch) or len(operations) != len(placements): raise SendUnitHold()
        placement_image = _canonical(placements)
        business = []
        for operation, placement in zip(operations, placements):
            if (type(placement) is not dict or set(placement) != {
                    'operation_id', 'action', 'row_index', 'observed_values', 'reserved_id'}
                    or placement['operation_id'] != operation['operation_id']
                    or type(placement['action']) is not str or placement['action'] not in ('insert', 'update')):
                raise SendUnitHold()
            row = by_key[tuple(operation['activity_key'])]
            values = source_tool_values(row, placement['action'], reserved_id=placement['reserved_id'])
            business.append({'operation_id': operation['operation_id'], 'action': placement['action'],
                'row_index': placement['row_index'], 'observed_values': placement['observed_values'],
                'values': values, 'recorded_at_utc': row.recorded_at_utc})
        result = freeze_send_unit(manifest=manifest, manifest_id=manifest_id, business=tuple(business), **unit_binding)
        if (freeze_prod_stage_l_manifest(qualified, store, **context) != (manifest, manifest_id)
                or _canonical(placements) != placement_image): raise SendUnitHold()
        _owner(writer_token)
    except Exception: failed = True
    if failed: raise SendUnitHold()
    return result


def _original_receipt_identity(qualified, store, generation_id, token, settings, snapshot, template_sha256):
    """Observe original current-cycle C6 facts under LK-P and recovery barriers.

    This does not issue eligibility, reconstruct/adopt a caller receipt or
    create a generation. Shared admissions and every prior original XLSX must
    already validate; a received name alone is never sufficient.
    """
    import os
    from monitor import issue_tracker_local_commit as local
    from monitor.issue_tracker_receipt_snapshot import read_current_cycle_local_receipts

    observed = read_current_cycle_local_receipts(token, store,
        expected_template_sha256=template_sha256, settings=settings,
        whitelist_sha256=snapshot.whitelist.sha256, qualified_source=qualified)
    if type(generation_id) is not str or generation_id not in observed.generation_ids: raise SendUnitHold()
    owner = local._owner(token)
    generations = local._directory(owner.root_fd, 'generations')
    try:
        directory = local._directory(generations, generation_id)
        try:
            def identity(info):
                return (info.st_dev, info.st_ino, info.st_size)
            def image(name, limit=local._MAX_DOC):
                raw, info = local._read(directory, name, limit)
                return raw, identity(info)
            ancestors = tuple((info.st_dev, info.st_ino) for info in (os.fstat(generations), os.fstat(directory)))
            if set(os.listdir(directory)) != {'STATE', 'MANIFEST', 'INTENT', 'RECEIPT'}: raise SendUnitHold()
            state_raw, state_identity = image('STATE')
            state = local._json(state_raw, {'schema_version', 'generation_id', 'sequence', 'manifest_id'})
            receipt_raw, receipt_identity = image('RECEIPT')
            manifest_raw, manifest_identity = image('MANIFEST', 1024 * 1024)
            intent_raw, intent_identity = image('INTENT')
            receipt = local._json(receipt_raw)
            if (type(state['sequence']) is not int or state['sequence'] < 1
                    or type(receipt.get('sequence')) is not int or receipt['sequence'] != state['sequence']
                    or receipt.get('kind') != 'xlsx'): raise SendUnitHold()
            generation = local.Generation(generation_id, state['sequence'], state['manifest_id'], token)
            status = local.inspect_local_generation(owner.project, owner.publication, generation, token=token)
            if status.status != 'RECEIPT-PRESENT-NOT-ELIGIBILITY': raise SendUnitHold()
            if tuple(image(name, limit) for name, limit in (
                    ('STATE', local._MAX_DOC), ('RECEIPT', local._MAX_DOC), ('MANIFEST', 1024 * 1024), ('INTENT', local._MAX_DOC))) != (
                    (state_raw, state_identity), (receipt_raw, receipt_identity),
                    (manifest_raw, manifest_identity), (intent_raw, intent_identity)):
                raise SendUnitHold()
            named = (os.stat('generations', dir_fd=owner.root_fd, follow_symlinks=False),
                     os.stat(generation_id, dir_fd=generations, follow_symlinks=False))
            if tuple((info.st_dev, info.st_ino) for info in named) != ancestors: raise SendUnitHold()
            return (generation_id, _digest(receipt['published_sha256']), _digest(receipt['manifest_id']),
                    ancestors, state_identity, receipt_identity, manifest_identity, intent_identity,
                    hashlib.sha256(state_raw).hexdigest(), hashlib.sha256(receipt_raw).hexdigest(),
                    hashlib.sha256(manifest_raw).hexdigest(), hashlib.sha256(intent_raw).hexdigest())
        finally:
            os.close(directory)
    finally:
        os.close(generations)


def freeze_receipted_prod_source_unit(qualified, store, *, http_root, settings,
                                     whitelist_snapshot, whitelist_path, metadata,
                                     expected_template_sha256, local_generation_id,
                                     placements, writer_token=None, **unit_binding):
    """Bind actual C5 sources to an original admitted C6 workbook receipt.

    Generation/publication cannot be supplied as substitutes. Coordinate,
    preread, enrollment, reservations, fresh send admission and fixed launcher
    remain separate obligations. No transport, intent, settlement or permit.
    """
    failed = False
    try:
        names = {'spreadsheet_id', 'sheet', 'sheet_id', 'history_sheet_id', 'target_nonce',
                 'history_nonce', 'preread_sha256', 'audits', 'occupied_metadata_ids'}
        if set(unit_binding) != names: raise SendUnitHold()
        before = _original_receipt_identity(qualified, store, local_generation_id, writer_token,
            settings, whitelist_snapshot, expected_template_sha256)
        result = freeze_prod_source_unit(qualified, store, http_root=http_root, settings=settings,
            whitelist_snapshot=whitelist_snapshot, whitelist_path=whitelist_path, metadata=metadata,
            expected_template_sha256=expected_template_sha256, placements=placements, writer_token=writer_token,
            generation_id=before[0], publish_id=before[1], **unit_binding)
        if json.loads(result.action_preimage)['manifest_id'] != before[2]: raise SendUnitHold()
        if _original_receipt_identity(qualified, store, local_generation_id, writer_token,
                settings, whitelist_snapshot, expected_template_sha256) != before: raise SendUnitHold()
    except Exception: failed = True
    if failed: raise SendUnitHold()
    return result


def freeze_observed_receipted_source_updates(qualified, store, *, http_root, settings,
                                           whitelist_snapshot, whitelist_path, metadata,
                                           expected_template_sha256, local_generation_id,
                                           business_reads, history_plan, history_response,
                                           writer_token=None, **unit_binding):
    """Compile ALL active updates from original full discovery/exact-row reads.

    Derive coordinates, typed tool-cell before-images and the combined business
    /History read digest; no caller placements, values or preread override. No
    fallback insert, key selection or silent batching. Original C5/C6 receipts
    remain revalidated under their real owner. Read images do not establish
    authentication, freshness, template/enrollment, reservations, CAS or send
    authority; a fixed launcher and original durable read-image journal remain
    necessary. This uninstalled compiler creates no intent or transport.
    """
    failed = False
    try:
        from urllib.parse import urlsplit
        from monitor.issue_tracker_local_commit import _owner
        from monitor.issue_tracker_local_workbook_commit import _source_rows
        from monitor.issue_tracker_manifest import freeze_prod_stage_l_manifest
        from monitor.issue_tracker_online_cells import source_tool_values
        from monitor.issue_tracker_sheets_read_decode import observe_active_row, decode_history_tail, _geometry

        names = {'spreadsheet_id', 'sheet', 'sheet_id', 'history_sheet_id', 'target_nonce',
                 'history_nonce', 'audits', 'occupied_metadata_ids'}
        if (set(unit_binding) != names or type(unit_binding['sheet']) is not str
                or unit_binding['sheet'] not in _FAMILY or type(business_reads) is not tuple
                or not 1 <= len(business_reads) <= 1000): raise SendUnitHold()
        owner = _owner(writer_token)
        if str(owner.project) != str(store.project_identity): raise SendUnitHold()
        context = dict(http_root=http_root, settings=settings, whitelist_snapshot=whitelist_snapshot,
                       whitelist_path=whitelist_path, metadata=metadata,
                       expected_template_sha256=expected_template_sha256, writer_token=writer_token)
        manifest, manifest_id = freeze_prod_stage_l_manifest(qualified, store, **context)
        operations = [item for item in json.loads(manifest)['operations']
                      if item['activity_key'][0] == _FAMILY[unit_binding['sheet']]]
        if len(operations) != len(business_reads): raise SendUnitHold()
        cabling, switch = _source_rows(qualified)
        sources = {row.activity_key: row for row in (*cabling, *switch)}
        if len(sources) != len(cabling) + len(switch): raise SendUnitHold()

        def read_images():
            history = decode_history_tail(history_plan, history_response, sheet_id=unit_binding['history_sheet_id'])
            if urlsplit(history_plan.path).path != '/v4/spreadsheets/' + unit_binding['spreadsheet_id']:
                raise SendUnitHold()
            placements, images = [], []
            for operation, reading in zip(operations, business_reads):
                if (type(reading) is not dict or set(reading) != {'operation_id', 'discovery_plan', 'discovery_response', 'row_plan', 'row_response'}
                        or reading['operation_id'] != operation['operation_id']): raise SendUnitHold()
                target, title, _ = _geometry(reading['row_plan'])
                if target != unit_binding['spreadsheet_id'] or title != unit_binding['sheet']: raise SendUnitHold()
                observed = observe_active_row(reading['discovery_plan'], reading['discovery_response'],
                    reading['row_plan'], reading['row_response'], sheet_id=unit_binding['sheet_id'],
                    activity_key=tuple(operation['activity_key']))
                values = source_tool_values(sources[tuple(operation['activity_key'])], 'update')
                cells = {column: dict(value) for _index, column, value in observed.cells}
                placements.append({'operation_id': operation['operation_id'], 'action': 'update',
                    'row_index': observed.row_index, 'reserved_id': None,
                    'observed_values': {column: cells[column] for column in values}})
                images.append({'operation_id': operation['operation_id'], 'discovery_path': reading['discovery_plan'].path,
                    'discovery_sha256': observed.discovery_sha256, 'row_path': reading['row_plan'].path,
                    'row_sha256': observed.row_sha256})
            image = _canonical({'schema_version': 1, 'spreadsheet_id': unit_binding['spreadsheet_id'],
                'sheet': unit_binding['sheet'], 'sheet_id': unit_binding['sheet_id'],
                'history_sheet_id': unit_binding['history_sheet_id'], 'history_path': history_plan.path,
                'history_sha256': history.source_sha256, 'business': images})
            return tuple(placements), hashlib.sha256(image).hexdigest(), history

        placements, digest, history = read_images()
        result = freeze_receipted_prod_source_unit(qualified, store, local_generation_id=local_generation_id,
            placements=placements, preread_sha256=digest, **context, **unit_binding)
        if (read_images() != (placements, digest, history)
                or freeze_prod_stage_l_manifest(qualified, store, **context) != (manifest, manifest_id)
                or history.last_data_row_index + result.history_rows_expected >= history.row_count):
            raise SendUnitHold()
        _owner(writer_token)
    except Exception: failed = True
    if failed: raise SendUnitHold()
    return result


def freeze_observed_receipted_switch_unit(qualified, store, *, http_root, settings,
                                        whitelist_snapshot, whitelist_path, metadata,
                                        expected_template_sha256, local_generation_id,
                                        business_reads, history_plan, history_response,
                                        spreadsheet_token, binding, identity, audits=(),
                                        occupied_metadata_ids=(), writer_token=None, **claims):
    """New Switch-only source unit under BOTH real owners and original nonces.

    Derive update vs insert from complete original key images, never caller
    action/coordinate/nonce. All operations share one original discovery and
    occupancy image; ordered inserts reserve distinct originally free slots
    inside this candidate. A retained same-spreadsheet pending namespace blocks
    compilation, even before ATTEMPT-1. No durable row/combined-preread journal,
    fresh remote enrollment/format/admission, transport or COMPLETE authority.
    This compiler is for a NEW unit only, never reconstruction of UNKNOWN.
    """
    failed = False
    try:
        import os
        from urllib.parse import urlsplit
        from monitor.issue_tracker_local_commit import _owner
        from monitor.issue_tracker_local_workbook_commit import _source_rows
        from monitor.issue_tracker_manifest import freeze_prod_stage_l_manifest
        from monitor.issue_tracker_online_cells import source_tool_values
        from monitor.issue_tracker_spreadsheet_owner import _validated_owner
        from monitor.issue_tracker_enrollment_journal import inspect_enrollment_journal
        from monitor.issue_tracker_sheets_read_decode import (
            _activity_sheet_image, _insertion_sheet_image, observe_active_row,
            observe_insertion_position, decode_history_tail)

        if claims or type(business_reads) is not tuple or not 1 <= len(business_reads) <= 1000: raise SendUnitHold()
        local_owner = _owner(writer_token)
        if str(local_owner.project) != str(store.project_identity): raise SendUnitHold()

        def original_nonce_state():
            owner = _validated_owner(spreadsheet_token, binding)
            stem = owner.lock_name[:-5]
            names = {name for name in os.listdir(owner.directories[-1][0]) if name.startswith(stem + '.')}
            if names != {stem + '.lock', stem + '.enrollment'}: raise SendUnitHold()
            return inspect_enrollment_journal(spreadsheet_token, binding, identity)

        original = original_nonce_state()
        nonces = {title: (sid, nonce) for title, sid, nonce in original.nonces}
        sid, target_nonce = nonces['ETH&IB Switch']; history_sid, history_nonce = nonces['Update_History']
        context = dict(http_root=http_root, settings=settings, whitelist_snapshot=whitelist_snapshot,
            whitelist_path=whitelist_path, metadata=metadata, expected_template_sha256=expected_template_sha256,
            writer_token=writer_token)
        manifest, manifest_id = freeze_prod_stage_l_manifest(qualified, store, **context)
        operations = [item for item in json.loads(manifest)['operations'] if item['activity_key'][0] == 'switch']
        if len(operations) != len(business_reads): raise SendUnitHold()
        cabling, switch = _source_rows(qualified)
        sources = {row.activity_key: row for row in (*cabling, *switch)}
        if len(sources) != len(cabling) + len(switch): raise SendUnitHold()

        def read_images():
            history = decode_history_tail(history_plan, history_response, sheet_id=history_sid)
            if urlsplit(history_plan.path).path != '/v4/spreadsheets/' + binding.spreadsheet_id: raise SendUnitHold()
            placements, images, reserved, shared = [], [], [], None
            for operation, reading in zip(operations, business_reads):
                if (type(reading) is not dict or set(reading) != {'operation_id', 'discovery_plan', 'discovery_response',
                        'occupancy_plan', 'occupancy_response', 'row_plan', 'row_response'}
                        or reading['operation_id'] != operation['operation_id']): raise SendUnitHold()
                key = tuple(operation['activity_key'])
                discovery, original_cells, target = _activity_sheet_image(reading['discovery_plan'], reading['discovery_response'],
                    sheet_id=sid, activity_key=key)
                if target != binding.spreadsheet_id: raise SendUnitHold()
                occupancy, capacity, occupancy_sha = _insertion_sheet_image(reading['occupancy_plan'], reading['occupancy_response'],
                    sheet_id=sid, title='ETH&IB Switch', target=target)
                occupancy_cells = {(index, letter): value for index, letter, value in occupancy}
                if capacity != discovery.row_count or any(occupancy_cells.get((index, letter)) != value for index, letter, value in original_cells):
                    raise SendUnitHold()
                current = (reading['discovery_plan'].path, discovery.source_sha256, reading['occupancy_plan'].path, occupancy_sha)
                if shared is not None and current != shared: raise SendUnitHold()
                shared = current
                if discovery.active_rows:
                    action = 'update'
                    observed = observe_active_row(reading['discovery_plan'], reading['discovery_response'],
                        reading['row_plan'], reading['row_response'], sheet_id=sid, activity_key=key)
                else:
                    action = 'insert'
                    observed = observe_insertion_position(reading['discovery_plan'], reading['discovery_response'],
                        reading['occupancy_plan'], reading['occupancy_response'], sheet_id=sid, activity_key=key,
                        reserved_row_indexes=tuple(reserved), append_rows=1, row_plan=reading['row_plan'], row_response=reading['row_response'])
                if observed.row_index in reserved: raise SendUnitHold()
                reserved.append(observed.row_index)
                values = source_tool_values(sources[key], action)
                cells = {letter: dict(value) for _index, letter, value in observed.cells}
                placements.append({'operation_id': operation['operation_id'], 'action': action,
                    'row_index': observed.row_index, 'reserved_id': None, 'observed_values': {letter: cells[letter] for letter in values}})
                images.append({'operation_id': operation['operation_id'], 'discovery_path': reading['discovery_plan'].path,
                    'discovery_sha256': discovery.source_sha256, 'occupancy_path': reading['occupancy_plan'].path,
                    'occupancy_sha256': occupancy_sha, 'row_path': reading['row_plan'].path, 'row_sha256': observed.row_sha256})
            image = _canonical({'schema_version': 1, 'spreadsheet_id': binding.spreadsheet_id, 'sheet': 'ETH&IB Switch',
                'sheet_id': sid, 'history_sheet_id': history_sid, 'history_path': history_plan.path,
                'history_sha256': history.source_sha256, 'business': images})
            return tuple(placements), hashlib.sha256(image).hexdigest(), history

        placements, digest, history = read_images()
        result = freeze_receipted_prod_source_unit(qualified, store, local_generation_id=local_generation_id,
            placements=placements, preread_sha256=digest, spreadsheet_id=binding.spreadsheet_id, sheet='ETH&IB Switch',
            sheet_id=sid, history_sheet_id=history_sid, target_nonce=target_nonce, history_nonce=history_nonce,
            audits=audits, occupied_metadata_ids=occupied_metadata_ids, **context)
        if (read_images() != (placements, digest, history) or original_nonce_state() != original
                or freeze_prod_stage_l_manifest(qualified, store, **context) != (manifest, manifest_id)
                or history.last_data_row_index + result.history_rows_expected >= history.row_count): raise SendUnitHold()
        _owner(writer_token); _validated_owner(spreadsheet_token, binding)
    except Exception: failed = True
    if failed: raise SendUnitHold()
    return result


def freeze_observed_receipted_cabling_unit(qualified, store, *, http_root, settings,
                                         whitelist_snapshot, whitelist_path, metadata,
                                         expected_template_sha256, local_generation_id, sheet,
                                         business_reads, history_plan, history_response,
                                         spreadsheet_token, binding, identity, audits=(),
                                         occupied_metadata_ids=(), writer_token=None, **claims):
    """NEW Cabling unit from original C5/C6, both owners and retained C17 IDs.

    All family operations share one complete original key/occupancy image.
    Active updates keep their IDs; missing/Closed keys append after ALL occupied
    columns, using exactly the original two-sheet NV reservation for the actual
    receipted generation/publication. No caller allocations/coordinates/nonces,
    retry reconstruction, new reservation, remote freshness, sender or COMPLETE.
    """
    failed = False
    try:
        import os
        from urllib.parse import urlsplit
        from monitor.issue_tracker_local_commit import _owner
        from monitor.issue_tracker_local_workbook_commit import _source_rows
        from monitor.issue_tracker_manifest import freeze_prod_stage_l_manifest
        from monitor.issue_tracker_online_cells import source_tool_values
        from monitor.issue_tracker_spreadsheet_owner import _validated_owner
        from monitor.issue_tracker_enrollment_journal import inspect_enrollment_journal
        from monitor.issue_tracker_nv_reservation import inspect_nv_reservation, require_unit_nv_reservation
        from monitor.issue_tracker_sheets_read_decode import (
            _activity_sheet_image, _insertion_sheet_image, observe_active_row,
            observe_insertion_position, decode_history_tail)

        if (claims or type(sheet) is not str or sheet not in ('ETH Cabling', 'IB Cabling')
                or type(business_reads) is not tuple or not 1 <= len(business_reads) <= 1000): raise SendUnitHold()
        local_owner = _owner(writer_token)
        if str(local_owner.project) != str(store.project_identity): raise SendUnitHold()
        context = dict(http_root=http_root, settings=settings, whitelist_snapshot=whitelist_snapshot,
            whitelist_path=whitelist_path, metadata=metadata, expected_template_sha256=expected_template_sha256,
            writer_token=writer_token)
        manifest, manifest_id = freeze_prod_stage_l_manifest(qualified, store, **context)
        receipt = _original_receipt_identity(qualified, store, local_generation_id, writer_token,
            settings, whitelist_snapshot, expected_template_sha256)
        if receipt[2] != manifest_id: raise SendUnitHold()
        operations = [item for item in json.loads(manifest)['operations'] if item['activity_key'][0] == _FAMILY[sheet]]
        if len(operations) != len(business_reads): raise SendUnitHold()
        cabling, switch = _source_rows(qualified)
        sources = {row.activity_key: row for row in (*cabling, *switch)}
        if len(sources) != len(cabling) + len(switch): raise SendUnitHold()

        def original_state(keys=None):
            owner = _validated_owner(spreadsheet_token, binding)
            stem = owner.lock_name[:-5]
            names = {name for name in os.listdir(owner.directories[-1][0]) if name.startswith(stem + '.')}
            expected = {stem+'.lock', stem+'.enrollment'}
            if keys is None:
                if names not in (expected, expected | {stem+'.nv'}): raise SendUnitHold()
            elif keys:
                if names != expected | {stem+'.nv'}: raise SendUnitHold()
            elif names != expected: raise SendUnitHold()
            enrolled = inspect_enrollment_journal(spreadsheet_token, binding, identity)
            reserved = None if not keys else inspect_nv_reservation(spreadsheet_token, binding, identity,
                generation_id=receipt[0], publish_id=receipt[1], sheet=sheet, requested_keys=keys)
            return enrolled, reserved

        enrolled, _ = original_state()
        nonces = {title: (sid, nonce) for title, sid, nonce in enrolled.nonces}
        sid, target_nonce = nonces[sheet]; history_sid, history_nonce = nonces['Update_History']

        def read_images():
            history = decode_history_tail(history_plan, history_response, sheet_id=history_sid)
            if urlsplit(history_plan.path).path != '/v4/spreadsheets/'+binding.spreadsheet_id: raise SendUnitHold()
            classified, shared, missing = [], None, []
            for operation, reading in zip(operations, business_reads):
                if (type(reading) is not dict or set(reading) != {'operation_id', 'discovery_plan', 'discovery_response',
                        'occupancy_plan', 'occupancy_response', 'row_plan', 'row_response'}
                        or reading['operation_id'] != operation['operation_id']): raise SendUnitHold()
                key = tuple(operation['activity_key'])
                discovery, original_cells, target = _activity_sheet_image(reading['discovery_plan'], reading['discovery_response'],
                    sheet_id=sid, activity_key=key)
                if target != binding.spreadsheet_id or discovery.sheet_title != sheet: raise SendUnitHold()
                occupancy, capacity, occupancy_sha = _insertion_sheet_image(reading['occupancy_plan'], reading['occupancy_response'],
                    sheet_id=sid, title=sheet, target=target)
                cells = {(index, letter): value for index, letter, value in occupancy}
                if capacity != discovery.row_count or any(cells.get((index, letter)) != value for index, letter, value in original_cells):
                    raise SendUnitHold()
                current = (reading['discovery_plan'].path, discovery.source_sha256, reading['occupancy_plan'].path, occupancy_sha)
                if shared is not None and current != shared: raise SendUnitHold()
                shared = current
                if not discovery.active_rows: missing.append(key)
                classified.append((operation, reading, discovery))
            keys = tuple(missing)
            original = original_state(keys)
            if original[0] != enrolled: raise SendUnitHold()
            reservation = original[1]
            if keys and (reservation.eth_source_sha256 if sheet == 'ETH Cabling' else reservation.ib_source_sha256) != shared[1]:
                raise SendUnitHold()
            allocations = {} if reservation is None else dict(reservation.reservations)
            placements, images, used = [], [], set()
            for operation, reading, discovery in classified:
                key = tuple(operation['activity_key'])
                if discovery.active_rows:
                    action = 'update'
                    observed = observe_active_row(reading['discovery_plan'], reading['discovery_response'],
                        reading['row_plan'], reading['row_response'], sheet_id=sid, activity_key=key)
                    if observed.row_index in used: raise SendUnitHold()
                    used.add(observed.row_index)
                    values = source_tool_values(sources[key], action)
                    cells = {letter: dict(value) for _index, letter, value in observed.cells}
                    placement = dict(row_index=observed.row_index, reserved_id=None,
                        observed_values={letter: cells[letter] for letter in values})
                else:
                    action = 'insert'
                    observed = observe_insertion_position(reading['discovery_plan'], reading['discovery_response'],
                        reading['occupancy_plan'], reading['occupancy_response'], sheet_id=sid, activity_key=key,
                        reserved_row_indexes=(), append_rows=len(keys), row_plan=reading['row_plan'], row_response=reading['row_response'])
                    placement = dict(row_index=None, reserved_id=allocations[key], observed_values=None)
                placements.append({'operation_id': operation['operation_id'], 'action': action, **placement})
                images.append({'operation_id': operation['operation_id'], 'discovery_path': reading['discovery_plan'].path,
                    'discovery_sha256': discovery.source_sha256, 'occupancy_path': reading['occupancy_plan'].path,
                    'occupancy_sha256': observed.occupancy_sha256 if action == 'insert' else shared[3],
                    'row_path': reading['row_plan'].path if action == 'update' else None,
                    'row_sha256': observed.row_sha256, 'append_start_row_index': observed.row_index if action == 'insert' else None})
            image = _canonical({'schema_version': 1, 'spreadsheet_id': binding.spreadsheet_id, 'sheet': sheet,
                'sheet_id': sid, 'history_sheet_id': history_sid, 'history_path': history_plan.path,
                'history_sha256': history.source_sha256, 'nv_journal_sha256': reservation.journal_sha256 if reservation else None,
                'business': images})
            return tuple(placements), hashlib.sha256(image).hexdigest(), history, original, keys

        placements, digest, history, original, keys = read_images()
        result = freeze_receipted_prod_source_unit(qualified, store, local_generation_id=local_generation_id,
            placements=placements, preread_sha256=digest, spreadsheet_id=binding.spreadsheet_id, sheet=sheet,
            sheet_id=sid, history_sheet_id=history_sid, target_nonce=target_nonce, history_nonce=history_nonce,
            audits=audits, occupied_metadata_ids=occupied_metadata_ids, **context)
        if keys and require_unit_nv_reservation(spreadsheet_token, binding, identity, result) != original[1]: raise SendUnitHold()
        if (read_images() != (placements, digest, history, original, keys)
                or freeze_prod_stage_l_manifest(qualified, store, **context) != (manifest, manifest_id)
                or _original_receipt_identity(qualified, store, local_generation_id, writer_token,
                    settings, whitelist_snapshot, expected_template_sha256) != receipt
                or history.last_data_row_index + result.history_rows_expected >= history.row_count): raise SendUnitHold()
        _owner(writer_token); _validated_owner(spreadsheet_token, binding)
    except Exception: failed = True
    if failed: raise SendUnitHold()
    return result


def _freeze(manifest, manifest_id, generation_id, publish_id, spreadsheet_id,
            sheet, sheet_id, history_sheet_id, target_nonce, history_nonce,
            preread_sha256, business, audits, occupied_metadata_ids):
    if (type(manifest) is not bytes or not 1 <= len(manifest) <= _MAX_BODY
            or hashlib.sha256(manifest).hexdigest() != _digest(manifest_id)
            or type(spreadsheet_id) is not str or re.fullmatch(r"[A-Za-z0-9_-]{20,4096}", spreadsheet_id) is None
            or type(sheet) is not str or sheet not in _FAMILY
            or _identifier(sheet_id) == _identifier(history_sheet_id)
            or type(business) is not tuple or len(business) > 1000
            or type(audits) is not tuple or len(audits) > 1000
            or type(occupied_metadata_ids) is not tuple or len(occupied_metadata_ids) > 30000):
        raise SendUnitHold()
    _generation_identity(generation_id)
    for digest in (publish_id, target_nonce, history_nonce, preread_sha256): _digest(digest)
    occupied = set()
    for identifier in occupied_metadata_ids:
        if _identifier(identifier) == 0 or identifier in occupied: raise SendUnitHold()
        occupied.add(identifier)
    document = json.loads(manifest.decode("utf-8", "strict"), object_pairs_hook=_pairs, parse_constant=_nonfinite)
    if type(document) is not dict or document.get("schema_version") != 1 or type(document.get("schema_version")) is not int:
        raise SendUnitHold()
    if _canonical(document) != manifest or type(document.get("operations")) is not list: raise SendUnitHold()
    if len(document["operations"]) > 1000: raise SendUnitHold()
    all_operations = _validated_operations(document["operations"], "send-unit manifest", validator=_runtime_operation)
    operations = [op for op in all_operations if op["activity_key"][0] == _FAMILY[sheet]]
    if len(operations) != len(business): raise SendUnitHold()
    identity = {"schema_version": 1, "generation_id": generation_id, "publish_id": publish_id,
                "spreadsheet_id": spreadsheet_id, "sheet": sheet, "sheet_id": sheet_id}
    unit_id = hashlib.sha256(_canonical(identity)).hexdigest()
    fence_id = (int(unit_id[:8], 16) & 0x7fffffff) or 1
    requests = []; sent = []; outcomes = []; decisions = []; coordinates = set()
    for operation, item in zip(operations, business):
        if (type(item) is not dict or set(item) != {"operation_id", "action", "row_index", "values", "observed_values", "recorded_at_utc"}
                or type(item["operation_id"]) is not str or item["operation_id"] != operation["operation_id"]
                or type(item["action"]) is not str or item["action"] not in ("insert", "update")):
            raise SendUnitHold()
        _timestamp(item["recorded_at_utc"])
        candidate = encode_tool_cells(sheet, sheet_id, item["action"], item["values"],
                                      row_index=item["row_index"], observed_values=item["observed_values"])
        if item["row_index"] is not None:
            if item["row_index"] in coordinates: raise SendUnitHold()
            coordinates.add(item["row_index"])
        outcomes.append((item["operation_id"], candidate.outcome))
        # NOOP intent hashes remain bound too; observation is not deletion of
        # a manifest operation and must not lose its intended literal image.
        decisions.append({"operation_id": item["operation_id"], "outcome": candidate.outcome,
                          "intended_sha256": candidate.intended_sha256})
        if candidate.outcome == "WIRE-CANDIDATE":
            objects = json.loads(candidate.requests_json)
            requests.extend(objects)
            sent.append({"operation_id": item["operation_id"], "activity_key": operation["activity_key"],
                         "action": item["action"], "recorded_at_utc": item["recorded_at_utc"],
                         "intended_sha256": candidate.intended_sha256, "requests": objects})
    audit_images = []; audit_ids = set()
    for item in audits:
        if type(item) is not dict or set(item) != {"event_id", "recorded_at_utc", "details"}: raise SendUnitHold()
        _text(item["event_id"]); _text(item["details"]); _timestamp(item["recorded_at_utc"])
        if item["event_id"] in audit_ids or item["event_id"] in {op["operation_id"] for op in all_operations}:
            raise SendUnitHold()
        audit_ids.add(item["event_id"])
        audit_images.append(dict(item))
    mapping_sha = hashlib.sha256(_canonical([list(row) for row in outcomes])).hexdigest()
    preimage = _canonical({"identity": identity, "manifest_id": manifest_id, "history_sheet_id": history_sheet_id,
                          "target_nonce": target_nonce, "history_nonce": history_nonce, "preread_sha256": preread_sha256,
                          "business": sent, "audits": audit_images, "outcomes": [list(row) for row in outcomes],
                          "decisions": decisions})
    if len(preimage) > _MAX_BODY: raise SendUnitHold()
    action_digest = hashlib.sha256(preimage).hexdigest()
    if not requests:
        return FrozenSendUnit(unit_id, b"", hashlib.sha256(b"").hexdigest(), preimage, action_digest,
                              tuple(outcomes), mapping_sha, None, 0, tuple(item["event_id"] for item in audit_images), "NO_SEND")
    if fence_id in occupied: raise SendUnitHold()
    common = {"schema_version": 1, "unit_id": unit_id, "manifest_id": manifest_id,
              "generation_id": generation_id, "publish_id": publish_id, "action_digest": action_digest,
              "outcome_mapping_sha256": mapping_sha, "target_nonce": target_nonce, "history_nonce": history_nonce,
              "preread_sha256": preread_sha256}
    history = []
    for item in sent:
        details = _canonical({**common, "operation_id": item["operation_id"], "intended_sha256": item["intended_sha256"]}).decode().rstrip("\n")
        history.append((item["recorded_at_utc"], sheet, item["action"], item["operation_id"], details))
    for item in audit_images:
        details = _canonical({**common, "event_id": item["event_id"], "event_details": item["details"]}).decode().rstrip("\n")
        history.append((item["recorded_at_utc"], sheet, "settings-audit", item["event_id"], details))
    requests.append({"appendCells": {"sheetId": history_sheet_id, "fields": "userEnteredValue", "rows": [
        {"values": [{"userEnteredValue": {"stringValue": text}} for text in row]} for row in history]}})
    requests.append({"createDeveloperMetadata": {"developerMetadata": {
        "metadataId": fence_id, "metadataKey": "z", "metadataValue": "1", "visibility": "DOCUMENT", "location": {"sheetId": sheet_id}}}})
    wire = _canonical({"requests": requests, "includeSpreadsheetInResponse": False})
    if len(requests) > _MAX_REQUESTS or len(wire) > _MAX_BODY: raise SendUnitHold()
    return FrozenSendUnit(unit_id, wire, hashlib.sha256(wire).hexdigest(), preimage, action_digest,
                          tuple(outcomes), mapping_sha, fence_id, len(history), (), "WIRE-CANDIDATE")
