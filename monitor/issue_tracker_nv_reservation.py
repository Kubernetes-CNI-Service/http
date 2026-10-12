"""Uninstalled C17 durable shared Cabling sequence under the actual owner.

Both capacity-clipped original columns, enrollment and binding are retained;
one conservative pending unit blocks any other allocation, including across
projects. No expiry, reset, reclamation, network, credential persistence,
COMPLETE or send permission. Authentic source/admission, row reservations,
the audited launcher and authenticated settlement still require integration.
"""
from dataclasses import dataclass, field
from contextlib import contextmanager, ExitStack
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
_CATALOG_NAMES = _NAMES | {'PRIOR'}
_ACTIVE_CATALOG_PREPARATIONS = {}


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
    # Decode and finish every barrier while all five original named images
    # remain pinned. Identical bytes at a replacement inode are not the
    # reservation already being replayed. Reuse the original-object cleanup
    # contract: never close a descriptor recycled onto a foreign object.
    from monitor.issue_tracker_unit_catalog import _Originals
    held = _Originals()
    try:
        original = held.directory(parent, name)
        if journal._identity(os.fstat(original)) != journal._identity(os.fstat(folder)):
            raise NvReservationHold()
        for entry in sorted(_NAMES):
            held.file(original, entry, 2 * _LIMIT if entry in ('ETH-RAW', 'IB-RAW') else _LIMIT)
        held.verify()
        result = _inspect_images(parent, name, original, binding, base, keys, ids)
        held.verify()
        return result
    finally:
        held.close()


def _inspect_images(parent, name, folder, binding, base, keys, ids):
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
    original_fd_identity = journal._identity(os.fstat(fd))
    try:
        info = local._check(fd, directory=False); journal._named(folder, 'INITIALIZED', fd, directory=False)
        raw = os.read(fd, 4097)
        if raw != _marker(expected) or len(raw) != info.st_size: raise NvReservationHold()
        os.fsync(fd); os.fsync(folder); os.fsync(parent)
        journal._named(folder, 'INITIALIZED', fd, directory=False)
    finally:
        from monitor.issue_tracker_unit_catalog import _close_original
        _close_original(fd, original_fd_identity)
    journal._named(parent, name, folder, directory=True)
    if set(os.listdir(folder)) != _NAMES: raise NvReservationHold()
    return NvReservationObservation(allocation.requested, base['unit_id'], hashlib.sha256(header_raw).hexdigest(),
                                    observed[0].source_sha256, observed[1].source_sha256)


def prepare_nv_reservation(token, binding, identity, eth_plan, eth_response, ib_plan, ib_response,
                           *, generation_id, publish_id, sheet, requested_keys):
    """New original unit only; no adoption or allocation after a global intent."""
    folder = None; original_folder_identity = None; failed = False
    try:
        parent, name, base, keys, ids = _inputs(token, binding, identity, generation_id, publish_id, sheet, requested_keys)
        # Even an unattempted or partial global journal is a conservative
        # barrier. UNKNOWN cannot be bypassed by switching project or family.
        owner = ownership._validated_owner(token, binding)
        if (name in os.listdir(parent) or name[:-3] + '.journal' in os.listdir(parent)
                or global_journal._catalog_present(owner)):
            raise NvReservationHold()
        observed = _read_pair(binding, ids, eth_plan, eth_response, ib_plan, ib_response)
        allocation = allocator.plan_nv_reservations(observed[0].nv_ids, observed[1].nv_ids, (), keys)
        reservations = local._canonical(allocation.requested)
        if len(reservations) > _LIMIT: raise NvReservationHold()
        header = _header(base, eth_plan, ib_plan, observed, reservations)
        folder = global_journal._create_folder(parent, name)
        original_folder_identity = journal._identity(os.fstat(folder))
        journal._write_read_image(folder, 'ETH-RAW', eth_response.data)
        journal._write_read_image(folder, 'IB-RAW', ib_response.data)
        local._write_new(folder, 'HEADER', local._canonical(header))
        local._write_new(folder, 'RESERVATIONS', reservations)
        journal._named(parent, name, folder, directory=True); ownership._validated_owner(token, binding)
        # Folder+parent and four file+folder pairs: ALL ten image barriers
        # precede genuine initialization. Partial stores stay retained HOLD.
        local._write_new(folder, 'INITIALIZED', _marker(header))
        result = _inspect(parent, name, folder, binding, base, keys, ids)
        if journal._identity(os.fstat(folder))[:2] != original_folder_identity[:2]:
            raise NvReservationHold()
        journal._named(parent, name, folder, directory=True)
        ownership._validated_owner(token, binding)
    except Exception: failed = True
    finally:
        if original_folder_identity is not None:
            from monitor.issue_tracker_unit_catalog import _close_original
            _close_original(folder, original_folder_identity)
    if failed: raise NvReservationHold()
    return result


def inspect_nv_reservation(token, binding, identity, *, generation_id, publish_id, sheet, requested_keys):
    """Existing pending IDs only; never allocate, reclaim or clear UNKNOWN."""
    folder = None; original_folder_identity = None; failed = False
    try:
        parent, name, base, keys, ids = _inputs(token, binding, identity, generation_id, publish_id, sheet, requested_keys)
        folder = local._directory(parent, name)
        original_folder_identity = journal._identity(os.fstat(folder))
        journal._named(parent, name, folder, directory=True)
        result = _inspect(parent, name, folder, binding, base, keys, ids)
        if journal._identity(os.fstat(folder))[:2] != original_folder_identity[:2]:
            raise NvReservationHold()
        journal._named(parent, name, folder, directory=True)
        ownership._validated_owner(token, binding)
    except Exception: failed = True
    finally:
        if original_folder_identity is not None:
            from monitor.issue_tracker_unit_catalog import _close_original
            _close_original(folder, original_folder_identity)
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


@dataclass(frozen=True, eq=False)
class _CatalogNvPreparation:
    """Live original preparation only, never source admission or send authority."""
    observation: NvReservationObservation


@dataclass(frozen=True, eq=False)
class _CatalogNonallocatingPreparation:
    """Live catalog originals; no NV reservation, admission or send permit."""
    unit_id: str


@dataclass(eq=False)
class _NonallocatingProjectReadTail:
    """Context-owned original observations, never a caller callback/permit."""
    packet: object = field(default=None, repr=False)
    bound: bool = False
    _issued_packet: object = field(default=None, init=False, repr=False)


def _verify_nonallocating_no_send_image(unit):
    """Necessary NO_SEND byte coherence only, never source/send authority."""
    from monitor import issue_tracker_send_unit as compiler
    try:
        if (type(unit) is not compiler.FrozenSendUnit or unit.outcome!='NO_SEND'
                or type(unit.wire_bytes) is not bytes or unit.wire_bytes!=b''
                or unit.wire_sha256!=hashlib.sha256(b'').hexdigest()
                or unit.fence_metadata_id is not None
                or type(unit.history_rows_expected) is not int or unit.history_rows_expected!=0
                or type(unit.action_preimage) is not bytes
                or not 1<=len(unit.action_preimage)<=compiler._MAX_BODY
                or hashlib.sha256(unit.action_preimage).hexdigest()!=unit.action_digest):raise NvReservationHold()
        for digest in (unit.unit_id,unit.wire_sha256,unit.action_digest,unit.outcome_mapping_sha256):
            compiler._digest(digest)
        action=local._json(unit.action_preimage,{'identity','manifest_id','history_sheet_id',
            'target_nonce','history_nonce','preread_sha256','business','audits','outcomes','decisions'})
        identity=action['identity']
        if (type(identity) is not dict or set(identity)!={'schema_version','generation_id','publish_id',
                'spreadsheet_id','sheet','sheet_id'} or type(identity['schema_version']) is not int
                or identity['schema_version']!=1 or identity['sheet'] not in compiler._FAMILY
                or type(identity['spreadsheet_id']) is not str
                or re.fullmatch(r'[A-Za-z0-9_-]{20,4096}',identity['spreadsheet_id']) is None
                or hashlib.sha256(local._canonical(identity)).hexdigest()!=unit.unit_id):raise NvReservationHold()
        compiler._generation_identity(identity['generation_id'])
        if compiler._identifier(identity['sheet_id'])==compiler._identifier(action['history_sheet_id']):
            raise NvReservationHold()
        for digest in (identity['publish_id'],action['manifest_id'],action['target_nonce'],
                action['history_nonce'],action['preread_sha256']):compiler._digest(digest)
        outcomes=action['outcomes'];decisions=action['decisions'];audits=action['audits']
        if (type(action['business']) is not list or action['business']
                or any(type(items) is not list or len(items)>1000 for items in (outcomes,decisions,audits))
                or not outcomes or len(decisions)!=len(outcomes) or type(unit.outcomes) is not tuple
                or tuple(tuple(pair) for pair in outcomes)!=unit.outcomes
                or any(type(pair) is not tuple for pair in unit.outcomes)
                or hashlib.sha256(local._canonical(outcomes)).hexdigest()!=unit.outcome_mapping_sha256
                or type(unit.pending_audit_ids) is not tuple):raise NvReservationHold()
        seen=set()
        for pair,decision in zip(outcomes,decisions):
            if (type(pair) is not list or len(pair)!=2 or type(pair[0]) is not str or not pair[0]
                    or pair[0] in seen or pair[1]!='OBSERVED-SATISFIED-AT-READ'
                    or type(decision) is not dict or set(decision)!={'operation_id','outcome','intended_sha256'}
                    or (decision['operation_id'],decision['outcome'])!=tuple(pair)):raise NvReservationHold()
            compiler._digest(decision['intended_sha256']);seen.add(pair[0])
        for item in audits:
            if (type(item) is not dict or set(item)!={'event_id','recorded_at_utc','details'}
                    or item['event_id'] in seen):raise NvReservationHold()
            compiler._text(item['event_id']);compiler._text(item['details'])
            compiler._timestamp(item['recorded_at_utc']);seen.add(item['event_id'])
        if tuple(item['event_id'] for item in audits)!=unit.pending_audit_ids:raise NvReservationHold()
    except Exception:raise NvReservationHold() from None


def _verify_nonallocating_no_send_state(record,tail,packet):
    # Recheck before AND after delegated original-read guards. No mutable
    # cancel flag or registered=True fiction substitutes for zero writes.
    if (record.get('project_read_tail') is not tail or tail.bound is not True or tail.packet is not packet
            or record['registered'] is not False or record['failed'] is not False
            or record['budget'].failed or record['budget'].pending
            or record['unit'] is not None or record['origin'] is not None or record['indexed'] is not None
            or record['settings'] is not None or type(record['additions']) is not set or record['additions']
            or record['appended'] is not None):raise NvReservationHold()


def _verify_nonallocating_no_send_preparation(record,tail):
    # Called only by the actual preparation's normal unregistered exit. Its
    # original context state must already bind the fixed receiver's result.
    try:
        if (type(tail) is not _NonallocatingProjectReadTail or tail.bound is not True
                or type(tail.packet) is not tuple or len(tail.packet)!=8
                or tail.packet[-1].outcome!='NO_SEND'):raise NvReservationHold()
        _verify_nonallocating_project_read_tail(record,tail)
    except Exception:raise NvReservationHold() from None


def _verify_nonallocating_project_read_tail(record, tail):
    # Runs after preparation revocation and every original cleanup. Only the
    # outer writer/sheet owners remain live; do not borrow closed K/raw scopes.
    try:
        if (type(tail) is not _NonallocatingProjectReadTail
                or record.get('project_read_tail') is not tail): raise NvReservationHold()
        if tail.bound is False and tail.packet is None and tail._issued_packet is None:return
        if tail.bound is not True or type(tail.packet) is not tuple or len(tail.packet)!=8:
            raise NvReservationHold()
        original_packet=tail.packet
        if original_packet is not tail._issued_packet:raise NvReservationHold()
        writer,token,binding,project,owner,authentication,images,unit=original_packet
        if (writer is not record['nonallocating_writer'] or token is not record['token']
                or binding!=record['binding'] or project is not record['nonallocating_owner']
                or owner is not record['owner'] or local._owner(writer) is not project
                or ownership._validated_owner(token,binding) is not owner): raise NvReservationHold()
        from monitor.issue_tracker_send_intent import _projection
        from monitor.issue_tracker_history_read_launcher import require_current_owned_project_read
        from monitor.issue_tracker_token_launcher import require_current_owned_project_token
        no_send=unit.outcome=='NO_SEND'
        if no_send:
            _verify_nonallocating_no_send_image(unit)
            _verify_nonallocating_no_send_state(record,tail,original_packet)
        else:_projection(unit)
        action=local._json(unit.action_preimage)
        if action['identity']['sheet']!='ETH&IB Switch':raise NvReservationHold()
        # One original row read per actual manifest outcome, including NOOP;
        # never hard-code a fixture's seven reads or adopt caller row plans.
        count=len(unit.outcomes)
        if (type(images) is not tuple or not count or len(images)!=5+count
                or any(type(item) is not tuple or len(item)!=4 for item in images)):
            raise NvReservationHold()
        shape=tuple(item[:3] for item in images)
        if (shape[:4]!=(('template_identity',None,None),('metadata',None,None),
                ('activity','ETH&IB Switch',None),('insertion','ETH&IB Switch',None))
                or shape[-1]!=('history_tail',None,None)
                or any(kind!='row' or sheet!='ETH&IB Switch' or type(row) is not int or row<3
                    for kind,sheet,row in shape[4:-1])
                or len({row for _kind,_sheet,row in shape[4:-1]})!=count
                or len({id(item[3]) for item in images})!=len(images)):raise NvReservationHold()
        require_current_owned_project_token(token,binding,authentication)
        for kind,sheet,row,response in images:
            require_current_owned_project_read(writer,token,binding,response,authentication,
                read_kind=kind,sheet=sheet,row=row)
        require_current_owned_project_token(token,binding,authentication)
        if (local._owner(writer) is not project
                or ownership._validated_owner(token,binding) is not owner):raise NvReservationHold()
        if (record.get('project_read_tail') is not tail or tail.bound is not True
                or tail.packet is not original_packet or tail._issued_packet is not original_packet):raise NvReservationHold()
        if no_send:_verify_nonallocating_no_send_state(record,tail,original_packet)
    except Exception:raise NvReservationHold() from None


def _bind_nonallocating_project_read_tail(prepared,writer,token,binding,authentication,images,unit):
    # Only the fixed receiver calls this after actual compilation. Every image
    # must still have its original issuer/shape/deadline and project auth.
    try:
        record=_ACTIVE_CATALOG_PREPARATIONS.get(prepared)
        if (type(prepared) is not _CatalogNonallocatingPreparation or record is None
                or record['nonallocating_writer'] is not writer or record['token'] is not token
                or record['binding']!=binding or prepared.unit_id!=unit.unit_id):raise NvReservationHold()
        tail=record['project_read_tail']
        if (type(tail) is not _NonallocatingProjectReadTail or tail.bound is not False
                or tail.packet is not None or tail._issued_packet is not None):
            raise NvReservationHold()
        tail.packet=(writer,token,binding,record['nonallocating_owner'],record['owner'],authentication,images,unit)
        # Keep the original binding separately from the live record slot:
        # replacement BETWEEN verifier calls is not a new original issuance.
        tail._issued_packet=tail.packet
        tail.bound=True
        _verify_nonallocating_project_read_tail(record,tail)
    except Exception:raise NvReservationHold() from None


def _nonallocating_identity(token, binding, identity, generation_id, publish_id, sheet):
    from monitor.issue_tracker_send_unit import _generation_identity
    _generation_identity(generation_id)
    enrollment._inputs(token, binding, identity)
    enrolled = enrollment.inspect_enrollment_journal(token, binding, identity)
    if (type(sheet) is not str or sheet not in {'ETH&IB Switch', *_FAMILIES}
            or type(publish_id) is not str or re.fullmatch(r'[0-9a-f]{64}', publish_id) is None):
        raise NvReservationHold()
    body = {'schema_version': 1, 'generation_id': generation_id, 'publish_id': publish_id,
            'spreadsheet_id': binding.spreadsheet_id, 'sheet': sheet, 'sheet_id': dict(identity.sheet_ids)[sheet]}
    return hashlib.sha256(local._canonical(body)).hexdigest(), enrolled


@contextmanager
def hold_catalog_nonallocating_preparation(writer_token, token, binding, identity, *,
                                           generation_id, publish_id, sheet):
    """Retain ALL prior catalog/C6/settlement originals without allocating IDs.

    Switch and all-update Cabling still need the genuine source compiler and
    unique C6 registration. No invented insertion keys or caller settlement,
    verifier, namespace allowance or path vector are accepted. An interruption
    retains any created original and revokes this live handoff before cleanup.
    """
    from monitor import issue_tracker_unit_catalog as catalog
    budget = catalog._OriginalImageBudget()
    old = catalog._Originals(_image_budget=budget); current = catalog._Originals(_image_budget=budget)
    prepared = None; active_budget = None; failed = False; primary = None; cleanup_problem = None
    record=None; read_tail=_NonallocatingProjectReadTail()
    proofs = {'scope': ExitStack(), 'verify': lambda: None, 'delivery_scope': ExitStack(),
              'delivery_events': [], 'owner_tail': ExitStack()}
    try:
        project_owner = local._owner(writer_token)
        unit_id, _enrolled = _nonallocating_identity(token, binding, identity, generation_id, publish_id, sheet)
        if token in catalog._IMAGE_BUDGETS: raise NvReservationHold()
        active_budget = (ownership._validated_owner(token, binding), binding, budget)
        catalog._IMAGE_BUDGETS[token] = active_budget
        owner, parent, stem, catalog_fd, units, _prior, _observations = _pin_catalog_prefix(
            token, binding, identity, old, new_allocation=True, _project_proofs=proofs)
        if any(unit.unit_id == unit_id for unit in units): raise NvReservationHold()
        old.sync(); proofs['verify']()
        if local._owner(writer_token) is not project_owner: raise NvReservationHold()
        record = {'owner': owner, 'token': token, 'binding': binding, 'identity': identity, 'old': old,
                  'current': current, 'catalog': catalog_fd, 'units': units, 'stem': stem, 'parent': parent,
                  'additions': set(), 'appended': None, 'registered': False, 'unit': None, 'indexed': None,
                  'budget': budget, 'origin': None, 'settings': None, 'settings_scope': ExitStack(),
                  'failed': False, 'verify_prior_c6': proofs['verify'],
                  'prior_delivery_events': proofs['delivery_events'],
                  'project_read_tail': read_tail,
                  'nonallocating_writer': writer_token, 'nonallocating_owner': project_owner}
        prepared = _CatalogNonallocatingPreparation(unit_id); _ACTIVE_CATALOG_PREPARATIONS[prepared] = record
        for delivery in record['prior_delivery_events']:
            if delivery['raw'] is not None: delivery['raw'].bind(record)
        _verify_catalog_preparation(prepared)
        yield prepared
        _verify_catalog_preparation(prepared)
        if not record['registered']:_verify_nonallocating_no_send_preparation(record,read_tail)
    except BaseException as exc:
        if isinstance(exc, Exception): failed = True
        else: primary = exc
    finally:
        closes = []
        if prepared is not None:
            retained = _ACTIVE_CATALOG_PREPARATIONS.pop(prepared, None)
            if retained is not None:
                for delivery in retained['prior_delivery_events']:
                    if delivery['raw'] is not None:
                        try: delivery['raw'].freeze(retained)
                        except BaseException as exc:
                            failed = True
                            if cleanup_problem is None: cleanup_problem = exc
                            if not isinstance(exc, Exception) and primary is None: primary = exc
                closes.append(retained['settings_scope'].close)
                if retained['indexed'] is not None: closes.append(retained['indexed'].close)
                if retained['origin'] is not None:
                    origin = retained['origin']; closes.append(origin['held'].close)
                    if origin['folder'] is not None:
                        closes.append(lambda: catalog._close_original(origin['folder'], origin['identity']))
        if active_budget is not None and catalog._IMAGE_BUDGETS.get(token) is active_budget:
            catalog._IMAGE_BUDGETS.pop(token)
        closes.extend((proofs['scope'].close, current.close, old.close,
                       proofs['delivery_scope'].close, proofs['owner_tail'].close))
        for close in closes:
            try: close()
            except BaseException as exc:
                failed = True
                if cleanup_problem is None: cleanup_problem = exc
                if not isinstance(exc, Exception) and primary is None: primary = exc
        try:
            if record is not None:_verify_nonallocating_project_read_tail(record,read_tail)
        except BaseException as exc:
            failed=True
            if cleanup_problem is None:cleanup_problem=exc
            if not isinstance(exc,Exception) and primary is None:primary=exc
        finally:
            # Context-local original state prevents a deleted/replaced record
            # slot from silently downgrading a bound tail to legacy. Revoke all
            # strong references only AFTER that final check, even on failure.
            read_tail.packet=None
            read_tail._issued_packet=None
    if primary is not None:
        if cleanup_problem is not None and cleanup_problem is not primary: raise primary from cleanup_problem
        raise primary
    if failed: raise NvReservationHold() from None


def _catalog_nonallocating_source_observation(prepared, token, binding, identity, *,
                                             writer_token, generation_id, publish_id, sheet):
    record = _verify_catalog_preparation(prepared)
    if (type(prepared) is not _CatalogNonallocatingPreparation or record['token'] is not token
            or record['binding'] != binding or record['identity'] != identity or record['registered']
            or record['nonallocating_writer'] is not writer_token):
        raise NvReservationHold()
    unit_id, original = _nonallocating_identity(token, binding, identity, generation_id, publish_id, sheet)
    if prepared.unit_id != unit_id: raise NvReservationHold()
    _verify_catalog_preparation(prepared)
    return original


def _unit_insertions(unit):
    from monitor.issue_tracker_send_intent import _projection
    _projection(unit)
    action = local._json(unit.action_preimage); target = action['identity']
    pairs = []
    for item in action['business']:
        if target['sheet'] not in _FAMILIES:
            return ()
        values = _literal_image(item, target)
        if item['action'] == 'insert':
            key = allocator._key(tuple(item['activity_key']))
            if key[0] != _FAMILIES[target['sheet']] or (values['K'], values['L'], values['F']) != key[1:]:
                raise NvReservationHold()
            allocator._id(values['A']); pairs.append((key, values['A']))
    if len({key for key, _value in pairs}) != len(pairs):
        raise NvReservationHold()
    return tuple(sorted(pairs))


def _catalog_allocation(observed, prior, keys):
    # Prior keys are unit-scoped. A NEW generation with the same activity key
    # must not obtain the previous unit's ID from the pure helper's key reuse.
    # ALL prior IDs remain an immutable high-water input, including Closed rows.
    old = tuple(identifier for row in prior for _key, identifier in row['reservations'])
    if len(old) != len(set(old)):
        raise NvReservationHold()
    for identifier in old:
        allocator._id(identifier)
    # First classify both originals independently (including duplicate IDs).
    allocator.plan_nv_reservations(observed[0].nv_ids, observed[1].nv_ids, (), ())
    seen = set(observed[0].nv_ids + observed[1].nv_ids)
    extra = tuple(identifier for identifier in old if identifier not in seen)
    return allocator.plan_nv_reservations(observed[0].nv_ids + extra, observed[1].nv_ids, (), keys)


def _catalog_marker(header, originals, identity):
    return local._canonical({'schema_version': 1, 'state': 'NATIVE-NV-ORIGINALS-NOT-AUTHORITY',
        'header_sha256': hashlib.sha256(local._canonical(header)).hexdigest(),
        'directory_identity': header['directory_identity'], 'initialized_identity': list(identity[:2]),
        'originals': {entry: {'identity': list(originals[entry][1]),
            'sha256': hashlib.sha256(originals[entry][0]).hexdigest()}
            for entry in sorted(_CATALOG_NAMES - {'INITIALIZED'})}})


def _write_catalog_image(parent, name, raw, held, verify, *, initialization=None):
    """Own the fixed-name creator FD through the full native handoff.

    Direct exclusive names retain even partial STOP evidence. No post-write
    reopen can become the first identity of this file. Legacy writers unchanged.
    """
    from monitor import issue_tracker_unit_catalog as catalog
    if name not in _CATALOG_NAMES and re.fullmatch(r'[0-9a-f]{64}\.unit-[0-9a-f]{64}\.nv-started', name) is None:
        raise NvReservationHold()
    fd = None; opened = None; retained = False
    budget = held._image_budget
    try:
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        # Capture actual creator provenance immediately. An initial failure is
        # recovered only from this exclusive name if the FD still matches it.
        opened = journal._identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
        actual = journal._identity(os.fstat(fd))
        if actual != opened: raise NvReservationHold()
        if initialization is not None:
            if name != 'INITIALIZED' or raw is not None: raise NvReservationHold()
            raw = _catalog_marker(initialization[0], initialization[1], opened)
        limit = 2 * _LIMIT if name in ('ETH-RAW', 'IB-RAW') else (16384 if name.endswith('.nv-started') else _LIMIT)
        if type(raw) is not bytes or not 1 <= len(raw) <= limit: raise NvReservationHold()
        budget.begin_written(opened, len(raw))
        def check_created():
            verify(); journal._named(parent, name, fd, directory=False)
            if journal._identity(os.fstat(fd))[:5] != opened[:5]: raise NvReservationHold()
        view = memoryview(raw)
        while view:
            check_created(); count = os.write(fd, view)
            if count <= 0: raise NvReservationHold()
            view = view[count:]; check_created()
        written = journal._identity(os.fstat(fd))
        check_created(); os.fsync(fd); check_created(); os.fsync(parent); check_created()
        if journal._identity(os.fstat(fd)) != written or os.pread(fd, limit + 1, 0) != raw:
            raise NvReservationHold()
        budget.seal_written(written, raw)
        held.files.append((parent, name, fd, written, raw)); retained = True
        return raw, written
    except BaseException:
        budget.failed = True
        raise
    finally:
        if fd is not None and not retained:
            if opened is None:
                try: opened = journal._identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                except OSError: pass
            if opened is not None: catalog._close_original(fd, opened)


def _native_original(parent, name, binding, base, keys, ids, prior, held):
    folder = held.directory(parent, name)
    if set(os.listdir(folder)) != _CATALOG_NAMES:
        raise NvReservationHold()
    images = {entry: held.file(folder, entry, 2 * _LIMIT if entry in ('ETH-RAW', 'IB-RAW') else _LIMIT)
              for entry in sorted(_CATALOG_NAMES)}
    started, started_identity = held.file(parent, name + '-started', 16384)
    held.verify()
    header = local._json(images['HEADER'][0])
    plans = tuple(PreparedSheetsRead('sheets.googleapis.com', header[key], 'GET', (), b'')
                  for key in ('eth_read_path', 'ib_read_path'))
    raws = tuple(SimpleNamespace(status=200, complete=True, data=images[key][0]) for key in ('ETH-RAW', 'IB-RAW'))
    observed = _read_pair(binding, ids, plans[0], raws[0], plans[1], raws[1])
    allocation = _catalog_allocation(observed, prior, keys)
    reservations = local._canonical(allocation.requested); prior_raw = local._canonical(prior)
    common = _header(base, plans[0], plans[1], observed, reservations)
    witness = local._canonical({**common, 'state': 'NV-PREPARATION-STARTED-NOT-AUTHORITY',
                               'prior_sha256': hashlib.sha256(prior_raw).hexdigest()})
    expected = {**common, 'prior_sha256': hashlib.sha256(prior_raw).hexdigest(),
                'started_identity': list(started_identity), 'started_sha256': hashlib.sha256(witness).hexdigest(),
                'directory_identity': list(journal._identity(os.fstat(folder))[:2])}
    if (started != witness or images['PRIOR'][0] != prior_raw or images['RESERVATIONS'][0] != reservations
            or images['HEADER'][0] != local._canonical(expected)
            or images['INITIALIZED'][0] != _catalog_marker(expected, images, images['INITIALIZED'][1])):
        raise NvReservationHold()
    held.verify()
    return NvReservationObservation(allocation.requested, base['unit_id'], hashlib.sha256(images['HEADER'][0]).hexdigest(),
                                    observed[0].source_sha256, observed[1].source_sha256)


def _pin_catalog_prefix(token, binding, identity, held, *, new_allocation, _project_proofs=None):
    """ALL indexed original families before any NEW write, not absent-journal GO."""
    from monitor import issue_tracker_unit_catalog as catalog
    owner = ownership._validated_owner(token, binding); parent = owner.directories[-1][0]
    stem = owner.lock_name[:-5]; names = {name for name in os.listdir(parent) if name.startswith(stem + '.')}
    catalog_fd = None; units = ()
    if names - {stem + '.lock', stem + '.enrollment'}:
        catalog_fd, units, _previous = catalog._inspect(token, binding, held)
        allowed = {stem + '.lock', stem + '.enrollment', stem + '.units', stem + '.units-started',
                   *(stem + '.units-position-%020d' % index for index in range(1, len(units) + 1))}
        families = ('journal', 'journal-started', 'history', 'business', 'metadata', 'nv', 'nv-started',
                    'dispatch', 'completion', 'completion-started', 'project-origin', 'settings-audit', 'settings-audit-started')
        allowed.update(stem + '.unit-' + unit.unit_id + '.' + family for unit in units for family in families)
        if names - allowed:
            raise NvReservationHold()
    else:
        held.namespace = (parent, stem + '.', names)
    # Capture all retained auxiliary images BEFORE semantic count/lineage reads.
    # Catalog position/start originals were already captured by its own reader.
    captured = {name for p, name, *_rest in held.files if p == parent}
    captured.update(name for p, name, *_rest in held.directories if p == parent)
    for name in sorted(names - captured - {stem + '.lock'}):
        if name.endswith('-started'):
            held.file(parent, name, 16384)
        else:
            folder = held.directory(parent, name)
            for entry in sorted(os.listdir(folder)):
                held.file(folder, entry, 2 * _LIMIT if entry in ('ETH-RAW', 'IB-RAW') else _LIMIT)
    held.verify()
    counts = ()
    if new_allocation and units:
        for unit in units:
            prefix = stem + '.unit-' + unit.unit_id
            # Both absent is diagnostic only: lost whole journals cannot be
            # reinterpreted as permission to allocate a fresh generation.
            if not {prefix + '.journal', prefix + '.journal-started'} <= names:
                raise NvReservationHold()
        with global_journal._hold_catalog_attempts(token, binding) as (counts, verify):
            if any(state.outcome == 'PENDING_NO_JOURNAL' for _unit, state in counts):
                raise NvReservationHold()
            verify(); held.verify()
    prior = []; observations = []
    for unit in units:
        target = local._json(unit.action_preimage)['identity']; insertions = _unit_insertions(unit)
        name = stem + '.unit-' + unit.unit_id + '.nv'
        present = {name, name + '-started'} & names
        if not insertions:
            if present:
                raise NvReservationHold()
            continue
        if present != {name, name + '-started'}:
            raise NvReservationHold()
        _parent, _legacy, base, keys, ids = _inputs(token, binding, identity, target['generation_id'],
            target['publish_id'], target['sheet'], tuple(key for key, _value in insertions))
        seen = _native_original(parent, name, binding, base, keys, ids, prior, held)
        enrollment.require_unit_enrollment(token, binding, identity, unit)
        if seen.unit_id != unit.unit_id or seen.reservations != insertions:
            raise NvReservationHold()
        observations.append((unit, seen))
        prior.append({'unit_id': unit.unit_id, 'journal_sha256': seen.journal_sha256, 'reservations': seen.reservations})
    held.verify()
    if new_allocation and units:
        # Only actual catalog HEADER originals select origin-backed C6.
        # Legacy uninstalled catalogs retain their old diagnostic contract;
        # an origin-backed catalog cannot silently omit any older project.
        unit_ids = {unit.unit_id for unit in units}
        unit_folders = {folder for _parent, child, folder, _stat, _names in held.directories if child in unit_ids}
        # Both real registration paths exist: the native NV handoff anchors
        # its origin in HEADER; the earlier C6 registrar commits a separate
        # original project-origin pair. Names only select the mandatory proof
        # reader below; neither their presence nor a HEADER label is evidence.
        native_origins = any(name.endswith('.project-origin') for name in names) or any(local._json(raw).get('project_origin') is not None
            for p, name, _fd, _identity, raw in held.files
            if name == 'HEADER' and p in unit_folders)
        counted = tuple(unit for unit, state in counts if state.attempt_count)
        if counted and not native_origins:
            # A legacy count or a settlement dataclass cannot release the
            # original UNKNOWN barrier. Only actual installed C6 origins do.
            raise NvReservationHold()
        if native_origins:
            if _project_proofs is None:
                raise NvReservationHold()
            with catalog.hold_pending_project_origins(token, binding) as (origins, verify_origins):
                if tuple(origin.unit for origin in origins) != units:
                    raise NvReservationHold()
                rows, verify_projects = _project_proofs['scope'].enter_context(
                    catalog._hold_project_c6_from_origins(token, binding, origins,
                        _owner_tail=_project_proofs['owner_tail']))
                if tuple(row.unit for row in rows) != units:
                    raise NvReservationHold()
                verify_origins(); held.verify(); verify_projects()
                if tuple(unit for unit, _state in counts) != units:
                    raise NvReservationHold()
                from monitor import issue_tracker_remote_history_match as remote
                validators = [];actual_writers={}
                for row in rows:
                    if row.unit not in counted:
                        continue
                    matches = [(writer, local._owner(writer)) for writer, active in tuple(local._ACTIVE.items())
                        if active.pid == os.getpid()
                        and journal._identity(os.fstat(active.project_fd))[:2] == row.project_identity]
                    if len(matches) != 1:raise NvReservationHold()
                    writer,project=matches[0];actual_writers[writer]=project
                    facts = local._json(row.c6_facts)
                    generation = local.Generation(facts['generation_id'], facts['sequence'], facts['manifest_id'], writer)
                    actual, verify_inputs, body, _keys = _project_proofs['scope'].enter_context(
                        remote._hold_settled_catalog_key_watermarks(writer, token, binding, row.unit, generation))
                    if (actual is not project or tuple(body['project_identity']) != row.project_identity
                            or body['binding']['unit_id'] != row.unit.unit_id):
                        raise NvReservationHold()
                    validators.append(verify_inputs)
                def verify_settlement():
                    if ownership._validated_owner(token, binding) is not owner:
                        raise NvReservationHold()
                    verify_projects()
                    for validate in validators:
                        validate()
                    verify_projects()
                verify_settlement()
                _project_proofs['verify'] = verify_settlement
                from monitor import issue_tracker_settings_audit_allocation as allocation
                for writer,project in actual_writers.items():
                    events,check,raw=_project_proofs['scope'].enter_context(
                        allocation._hold_native_allocation_prior_deliveries(writer,token,binding,held,
                            _project_proofs['delivery_scope']))
                    _project_proofs['delivery_events'].append(
                        {'writer':writer,'owner':project,'events':events,'verify':check,'raw':raw})
                verify_settlement();held.verify()
            # The same actual origin files were already captured in held
            # BEFORE this semantic read. They stay pinned while project C6
            # and locks survive the entire native creator/compiler/append.
            held.verify(); _project_proofs['verify']()
    return owner, parent, stem, catalog_fd, units, prior, tuple(observations)


@contextmanager
def hold_catalog_nv_preparation(token, binding, identity, eth_plan, eth_response, ib_plan, ib_response,
                                *, generation_id, publish_id, sheet, requested_keys):
    """Native reservation->compiler->catalog handoff under one actual owner.

    No caller high-water/path/list or recovery adoption. ALL previous originals
    stay held through the exact append. Interrupted preparation is retained HOLD.
    This uninstalled component is NOT qualified source/C6/NEW or send authority.
    """
    from monitor import issue_tracker_unit_catalog as catalog
    budget = catalog._OriginalImageBudget()
    old = catalog._Originals(_image_budget=budget); current = catalog._Originals(_image_budget=budget)
    prepared = None; active_budget = None; failed = False; primary=None; cleanup_problem=None
    project_proofs = {'scope': ExitStack(), 'verify': lambda: None,
                      'delivery_scope':ExitStack(),'delivery_events':[], 'owner_tail':ExitStack()}
    try:
        parent, _legacy, base, keys, ids = _inputs(token, binding, identity, generation_id, publish_id, sheet, requested_keys)
        if token in catalog._IMAGE_BUDGETS:
            raise NvReservationHold()
        active_budget = (ownership._validated_owner(token, binding), binding, budget)
        catalog._IMAGE_BUDGETS[token] = active_budget
        owner, parent, stem, catalog_fd, units, prior, _observations = _pin_catalog_prefix(
            token, binding, identity, old, new_allocation=True, _project_proofs=project_proofs)
        if any(unit.unit_id == base['unit_id'] for unit in units):
            raise NvReservationHold()
        observed = _read_pair(binding, ids, eth_plan, eth_response, ib_plan, ib_response)
        allocation = _catalog_allocation(observed, prior, keys)
        reservations = local._canonical(allocation.requested); prior_raw = local._canonical(prior)
        if len(reservations) > _LIMIT or len(prior_raw) > _LIMIT:
            raise NvReservationHold()
        common = _header(base, eth_plan, ib_plan, observed, reservations)
        name = stem + '.unit-' + base['unit_id'] + '.nv'; started = name + '-started'
        witness = local._canonical({**common, 'state': 'NV-PREPARATION-STARTED-NOT-AUTHORITY',
                                   'prior_sha256': hashlib.sha256(prior_raw).hexdigest()})
        old.sync(); project_proofs['verify'](); ownership._validated_owner(token, binding)
        def verify_witness():
            if ownership._validated_owner(token, binding) is not owner: raise NvReservationHold()
            old.verify(parent_additions={started}); current.verify(); project_proofs['verify']()
        raw, started_identity = _write_catalog_image(parent, started, witness, current, verify_witness)
        if raw != witness:
            raise NvReservationHold()
        # The creator's return is itself a boundary. A prior APPLIED/key/C6
        # rebind immediately after STARTED must stop before the new directory,
        # not merely before its first image. Never refresh the held original.
        verify_witness()
        folder, folder_identity = global_journal._create_folder(parent, name, _return_original=True)
        folder_retained = False
        try:
            # Receive the creator's actual cleanup provenance before the
            # first consumer stat can fail. A recycled foreign FD is HOLD,
            # never ours to close; partial NV and its witness stay retained.
            if journal._identity(os.fstat(folder)) != folder_identity:
                raise NvReservationHold()
            header = {**common, 'prior_sha256': hashlib.sha256(prior_raw).hexdigest(),
                      'started_identity': list(started_identity), 'started_sha256': hashlib.sha256(witness).hexdigest(),
                      'directory_identity': list(folder_identity[:2])}
            completed = set()
            def verify_new_folder(extra=frozenset()):
                if ownership._validated_owner(token, binding) is not owner:
                    raise NvReservationHold()
                old.verify(parent_additions={name, started}); current.verify(); project_proofs['verify']()
                journal._named(parent, name, folder, directory=True)
                if (journal._identity(os.fstat(folder))[:5] != folder_identity[:5]
                        or set(os.listdir(folder)) != completed | extra):
                    raise NvReservationHold()
            originals = {}
            for entry, raw in (('ETH-RAW', eth_response.data), ('IB-RAW', ib_response.data),
                    ('PRIOR', prior_raw), ('HEADER', local._canonical(header)), ('RESERVATIONS', reservations)):
                verify_new_folder()
                originals[entry] = _write_catalog_image(folder, entry, raw, current,
                    lambda entry=entry: verify_new_folder({entry}))
                completed.add(entry); verify_new_folder()
            _write_catalog_image(folder, 'INITIALIZED', None, current, lambda: verify_new_folder({'INITIALIZED'}),
                                 initialization=(header, originals))
            completed.add('INITIALIZED'); verify_new_folder()
            # Every creator file stores this actual parent FD. Keep it alive
            # through replay/append; never rely on a cold open reusing its int.
            final_folder_identity = journal._identity(os.fstat(folder))
            current.directories.append((parent, name, folder, final_folder_identity, tuple(sorted(completed))))
            folder_retained = True
        finally:
            if not folder_retained: catalog._close_original(folder, folder_identity)
        seen = _native_original(parent, name, binding, base, keys, ids, prior, current)
        current.sync()
        record = {'owner': owner, 'token': token, 'binding': binding, 'identity': identity, 'old': old,
                  'current': current, 'catalog': catalog_fd, 'units': units, 'stem': stem, 'parent': parent,
                  'additions': {name, started}, 'appended': None, 'registered': False, 'unit': None, 'indexed': None,
                  'budget': budget, 'origin': None, 'settings':None,'settings_scope':ExitStack(),
                  'failed': False, 'verify_prior_c6': project_proofs['verify'],
                  'prior_delivery_events':project_proofs['delivery_events']}
        prepared = _CatalogNvPreparation(seen); _ACTIVE_CATALOG_PREPARATIONS[prepared] = record
        for prior_delivery in record['prior_delivery_events']:
            if prior_delivery['raw'] is not None:prior_delivery['raw'].bind(record)
        _verify_catalog_preparation(prepared)
        yield prepared
        _verify_catalog_preparation(prepared)
        if not record['registered']:
            raise NvReservationHold()
    except BaseException as exc:
        if isinstance(exc,Exception): failed = True
        else: primary=exc
    finally:
        closes=[]
        if prepared is not None:
            retained = _ACTIVE_CATALOG_PREPARATIONS.pop(prepared, None)
            if retained is not None:
                for prior_delivery in retained['prior_delivery_events']:
                    if prior_delivery['raw'] is not None:
                        try:prior_delivery['raw'].freeze(retained)
                        except BaseException as exc:
                            failed=True
                            if cleanup_problem is None:cleanup_problem=exc
                            if not isinstance(exc,Exception) and primary is None:primary=exc
            if retained is not None:
                closes.append(retained['settings_scope'].close)
            if retained is not None and retained['indexed'] is not None:
                closes.append(retained['indexed'].close)
            if retained is not None and retained['origin'] is not None:
                origin = retained['origin']
                closes.append(origin['held'].close)
                if origin['folder'] is not None:
                    closes.append(lambda:catalog._close_original(origin['folder'],origin['identity']))
        if active_budget is not None and catalog._IMAGE_BUDGETS.get(token) is active_budget:
            catalog._IMAGE_BUDGETS.pop(token)
        # Revoke semantic/preparation authority first. A genuine foreign owner
        # alone retains original exclusion through the raw graph's final check.
        closes.extend((project_proofs['scope'].close,current.close,old.close,
                       project_proofs['delivery_scope'].close,project_proofs['owner_tail'].close))
        # Every owned graph is finalized even when settings' exit verification
        # refuses or interrupts. Revoke registries first; never leak a live
        # preparation/budget because the first finalizer raised.
        for close in closes:
            try:close()
            except BaseException as exc:
                failed=True
                if cleanup_problem is None:cleanup_problem=exc
                if not isinstance(exc,Exception) and primary is None:primary=exc
    if primary is not None:
        if cleanup_problem is not None and cleanup_problem is not primary:raise primary from cleanup_problem
        raise primary
    if failed:
        raise NvReservationHold() from None


def _verify_catalog_preparation(prepared):
    record = _ACTIVE_CATALOG_PREPARATIONS.get(prepared)
    if type(prepared) not in (_CatalogNvPreparation, _CatalogNonallocatingPreparation) or record is None:
        raise NvReservationHold()
    if (type(prepared) is _CatalogNonallocatingPreparation
            and local._owner(record['nonallocating_writer']) is not record['nonallocating_owner']):
        raise NvReservationHold()
    if ownership._validated_owner(record['token'], record['binding']) is not record['owner']:
        raise NvReservationHold()
    if record['failed'] or record['budget'].failed or record['budget'].pending:
        raise NvReservationHold()
    record['old'].verify(parent_additions=record['additions'], appended_to=record['appended'])
    record['verify_prior_c6']()
    for prior_delivery in record['prior_delivery_events']:prior_delivery['verify']()
    record['current'].verify()
    if record['indexed'] is not None:
        record['indexed'].verify()
    origin = record['origin']
    settings=record['settings']
    if settings is not None:
        if local._owner(settings['writer']) is not settings['owner']: raise NvReservationHold()
        settings['verify']()
    if origin is not None:
        if local._owner(origin['writer']) is not origin['owner']:
            raise NvReservationHold()
        if origin['folder'] is not None:
            journal._named(record['parent'], origin['name'], origin['folder'], directory=True)
            actual = journal._identity(os.fstat(origin['folder']))
            if actual[:5] != origin['identity'][:5]: raise NvReservationHold()
            if origin['sealed'] and (actual != origin['identity']
                    or set(os.listdir(origin['folder'])) != {'WITNESS', 'STARTED', 'ORIGIN'}):
                raise NvReservationHold()
        origin['held'].verify()
    return record


def _catalog_nv_append_guard(prepared, token, binding, unit):
    _catalog_nv_compiled_observation(prepared, token, binding, unit)
    record = _verify_catalog_preparation(prepared)
    if record['indexed'] is not None or (record['origin'] is not None and not record['origin']['sealed']):
        raise NvReservationHold()
    if type(prepared) is _CatalogNonallocatingPreparation and record['origin'] is None:
        raise NvReservationHold()
    record['unit'] = unit
    return frozenset(record['additions'])


def _catalog_nv_source_observation(prepared, token, binding, identity, *,
                                   generation_id, publish_id, sheet, requested_keys=None):
    # Receipt labels here come from the genuine compiler's original C6 read.
    # This necessary comparison is not itself C5/C6, freshness or NEW proof.
    record = _verify_catalog_preparation(prepared)
    if (record['token'] is not token or record['binding'] != binding
            or record['identity'] != identity or record['registered']):
        raise NvReservationHold()
    keys = tuple(key for key, _identifier in prepared.observation.reservations)
    actual = keys if requested_keys is None else requested_keys
    _parent, _name, base, checked, _ids = _inputs(token, binding, identity,
        generation_id, publish_id, sheet, actual)
    if checked != keys or base['unit_id'] != prepared.observation.unit_id:
        raise NvReservationHold()
    _verify_catalog_preparation(prepared)
    return prepared.observation


def _catalog_nv_compiled_observation(prepared, token, binding, unit):
    # Preserve actual ACTION/WIRE and all insertion key/ID pairs. No append,
    # namespace mutation or compiler authority is issued by this observation.
    record = _verify_catalog_preparation(prepared)
    nonallocating = type(prepared) is _CatalogNonallocatingPreparation
    unit_id = prepared.unit_id if nonallocating else prepared.observation.unit_id
    reservations = () if nonallocating else prepared.observation.reservations
    if (record['token'] is not token or record['binding'] != binding or record['registered']
            or unit_id != unit.unit_id or _unit_insertions(unit) != reservations):
        raise NvReservationHold()
    enrollment.require_unit_enrollment(token, binding, record['identity'], unit)
    _verify_catalog_preparation(prepared)
    return None if nonallocating else prepared.observation


def _catalog_nv_c6_origin_begin(prepared, writer, token, binding, unit):
    _catalog_nv_compiled_observation(prepared, token, binding, unit)
    record = _verify_catalog_preparation(prepared)
    if type(prepared) is _CatalogNonallocatingPreparation and record['nonallocating_writer'] is not writer:
        raise NvReservationHold()
    if record['origin'] is not None or record['indexed'] is not None: raise NvReservationHold()
    from monitor import issue_tracker_unit_catalog as catalog
    name = record['stem'] + '.unit-' + unit.unit_id + '.project-origin'
    if name in os.listdir(record['parent']): raise NvReservationHold()
    record['unit'] = unit
    record['origin'] = {'writer': writer, 'owner': local._owner(writer), 'name': name,
        'folder': None, 'identity': None, 'held': catalog._Originals(_image_budget=record['budget']), 'sealed': False}


def _catalog_nv_c6_origin_created(prepared, writer, token, binding, unit, folder):
    # Only the actual exclusive creator for the one derived name is admitted.
    # The old namespace is not refreshed and no caller name/list is accepted.
    record = _ACTIVE_CATALOG_PREPARATIONS.get(prepared)
    if record is None or record['failed']: raise NvReservationHold()
    origin = record['origin']
    if (origin is None or origin['writer'] is not writer or record['token'] is not token
            or record['binding'] != binding or record['unit'] is not unit or origin['folder'] is not None):
        raise NvReservationHold()
    journal._named(record['parent'], origin['name'], folder, directory=True)
    identity = journal._identity(os.fstat(folder))
    if os.listdir(folder) or local._owner(writer) is not origin['owner']: raise NvReservationHold()
    origin['folder'] = folder; origin['identity'] = identity
    record['additions'].add(origin['name'])
    _verify_catalog_preparation(prepared)
    return origin['held']


def _catalog_nv_c6_origin_seal(prepared, token, binding, unit):
    record = _verify_catalog_preparation(prepared); origin = record['origin']
    if (origin is None or origin['sealed'] or record['token'] is not token
            or record['binding'] != binding or record['unit'] is not unit
            or set(os.listdir(origin['folder'])) != {'WITNESS', 'STARTED', 'ORIGIN'}):
        raise NvReservationHold()
    images = origin['held'].files
    if {name for parent, name, *_ in images if parent == origin['folder']} != {'WITNESS', 'STARTED', 'ORIGIN'}:
        raise NvReservationHold()
    origin['identity'] = journal._identity(os.fstat(origin['folder']))
    origin['sealed'] = True
    _verify_catalog_preparation(prepared)


def _catalog_nv_c6_origin_anchor(prepared, token, binding, unit):
    record = _verify_catalog_preparation(prepared); origin = record['origin']
    if origin is None: return None
    if (not origin['sealed'] or record['token'] is not token or record['binding'] != binding
            or record['unit'] is not unit or record['registered']): raise NvReservationHold()
    return {'directory_identity': list(origin['identity']), 'originals': {
        name: {'identity': list(identity), 'sha256': hashlib.sha256(raw).hexdigest()}
        for parent, name, _fd, identity, raw in origin['held'].files if parent == origin['folder']}}


def _catalog_nv_c6_origin_registered(prepared, writer, token, binding, unit):
    record = _verify_catalog_preparation(prepared); origin = record['origin']
    if (origin is None or not origin['sealed'] or origin['writer'] is not writer
            or record['token'] is not token or record['binding'] != binding
            or record['unit'] is not unit or record['indexed'] is None or record['registered']):
        raise NvReservationHold()
    record['registered'] = True
    _verify_catalog_preparation(prepared)


def _catalog_nv_c6_origin_failed(prepared):
    try: record = _ACTIVE_CATALOG_PREPARATIONS.get(prepared)
    except TypeError: return
    if record is not None: record['failed'] = True


def _catalog_nv_c6_origin_owns_folder(prepared, folder):
    # Cleanup ownership only, including an exception after actual transfer.
    try: record = _ACTIVE_CATALOG_PREPARATIONS.get(prepared)
    except TypeError: return False
    return (record is not None and record['origin'] is not None
            and record['origin']['folder'] is not None and record['origin']['folder'] == folder)


def _catalog_nv_original_anchor(prepared, token, binding, unit):
    # Called only by the genuine append after its opaque scope/unit guard.
    # Anchor the finished marker in the actual catalog's existing identity
    # chain; no self-stat cycle, caller-provided record or cold re-baselining.
    record = _verify_catalog_preparation(prepared)
    if (record['token'] is not token or record['binding'] != binding
            or record['unit'] is not unit or record['registered']):
        raise NvReservationHold()
    if type(prepared) is _CatalogNonallocatingPreparation:
        if _unit_insertions(unit): raise NvReservationHold()
        return None
    name = record['stem'] + '.unit-' + unit.unit_id + '.nv'
    folders = {fd for parent, entry, fd, _identity, _names in record['current'].directories
               if parent == record['parent'] and entry == name}
    images = [(identity, raw) for parent, entry, _fd, identity, raw in record['current'].files
              if parent in folders and entry == 'INITIALIZED']
    if not images or any(image != images[0] for image in images):
        raise NvReservationHold()
    identity, raw = images[0]
    return {'identity': list(identity), 'sha256': hashlib.sha256(raw).hexdigest()}


def _catalog_nv_appended(prepared, catalog_fd, unit):
    record = _ACTIVE_CATALOG_PREPARATIONS.get(prepared)
    if record is None or record['registered'] or record['unit'] is not unit:
        raise NvReservationHold()
    from monitor import issue_tracker_unit_catalog as catalog
    index = len(record['units']) + 1
    record['additions'].add(record['stem'] + '.units-position-%020d' % index)
    if record['catalog'] is None:
        record['additions'].update((record['stem'] + '.units', record['stem'] + '.units-started'))
    else:
        journal._named(record['parent'], record['stem'] + '.units', catalog_fd, directory=True)
        if journal._identity(os.fstat(catalog_fd))[:2] != journal._identity(os.fstat(record['catalog']))[:2]:
            raise NvReservationHold()
        record['appended'] = (record['catalog'], {unit.unit_id, 'ENTRY-%020d' % index})
    _verify_catalog_preparation(prepared)
    # Hold our exact new catalog originals before acknowledging the handoff.
    indexed = catalog._Originals(_image_budget=record['budget'])
    try:
        _folder, units, _previous = catalog._inspect(record['token'], record['binding'], indexed)
        if units != record['units'] + (unit,):
            raise NvReservationHold()
        indexed.sync(); _verify_catalog_preparation(prepared)
    except Exception:
        indexed.close()
        raise
    record['indexed'] = indexed
    record['registered'] = record['origin'] is None


def register_catalog_nv_unit(prepared, unit):
    """Consume only this live preparation for its exact frozen unit, never GO."""
    failed = False
    try:
        if type(prepared) is not _CatalogNvPreparation: raise NvReservationHold()
        record = _verify_catalog_preparation(prepared)
        from monitor import issue_tracker_unit_catalog as catalog
        catalog.register_pending_unit(record['token'], record['binding'], unit, _nv_preparation=prepared)
        _verify_catalog_preparation(prepared)
    except Exception:
        failed = True
    if failed:
        raise NvReservationHold() from None


def inspect_catalog_nv_reservation(token, binding, identity, unit):
    """Cold replay of ALL original lineage; UNKNOWN IDs retained, never NEW."""
    from monitor import issue_tracker_unit_catalog as catalog
    held = catalog._originals(token, binding); failed = False
    try:
        _owner, _parent, _stem, _folder, _units, _prior, observations = _pin_catalog_prefix(
            token, binding, identity, held, new_allocation=False)
        matches = [seen for original, seen in observations if original == unit]
        if len(matches) != 1:
            raise NvReservationHold()
        held.sync(); result = matches[0]
    except Exception:
        failed = True
    finally:
        held.close()
    if failed:
        raise NvReservationHold() from None
    return result


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
        owner = ownership._validated_owner(token, binding)
        if global_journal._catalog_present(owner):
            result = inspect_catalog_nv_reservation(token, binding, identity, unit)
        else:
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
