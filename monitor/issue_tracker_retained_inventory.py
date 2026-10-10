"""Uninstalled original-image coverage for the existing retained namespace.

Every same-spreadsheet family is covered or refused, never silently filtered.
This fixed legacy namespace currently holds ONE unit. This is not a complete
multi-unit/project/C6/APPLIED inventory, global high-water, G1 or NEW authority.
Future/archive namespaces are HOLD until their original contracts are supported.
No network, repair, cleanup, allocation, completion or mutable caller inventory.
"""
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass, field
import hashlib
import os
import re

from monitor import issue_tracker_local_commit as local
from monitor import issue_tracker_attempt_journal as journal
from monitor import issue_tracker_global_attempt_journal as global_journal
from monitor import issue_tracker_spreadsheet_owner as ownership
from monitor import issue_tracker_enrollment_journal as enrollment
from monitor import issue_tracker_history_preread_journal as history
from monitor import issue_tracker_sheets_read_decode as decode

_FAMILIES = frozenset(('business', 'completion', 'completion-started', 'dispatch', 'enrollment',
                       'history', 'journal', 'journal-started', 'metadata', 'nv'))
_CATALOG_FAMILIES = _FAMILIES | {'project-origin', 'nv-started'}
_FIXED = {
    'enrollment': frozenset(('HEADER', 'INITIALIZED', 'NONCES')),
    'history': frozenset(('HEADER', 'HISTORY-RAW', 'INITIALIZED')),
    'business': frozenset(('BUSINESS-RAW', 'HEADER', 'INITIALIZED', 'MANIFEST')),
    'metadata': frozenset(('HEADER', 'INITIALIZED', 'METADATA-RAW', 'RESERVATION')),
    'nv': frozenset(('ETH-RAW', 'HEADER', 'IB-RAW', 'INITIALIZED', 'RESERVATIONS')),
    'completion': frozenset(('COMPLETE', 'HEADER', 'HEADERS-RAW', 'HISTORY-RAW', 'IDENTITY-RAW', 'METADATA-RAW')),
    'project-origin': frozenset(('STARTED', 'ORIGIN', 'WITNESS')),
}
_TOTAL_LIMIT = 48 * 1024 * 1024


class RetainedInventoryHold(ValueError):
    def __init__(self):
        super().__init__('req7_retained_inventory_unproved')


@dataclass(frozen=True)
class RetainedInventoryObservation:
    unit: object = field(repr=False)
    attempt_count: int
    families: tuple
    originals: tuple


@dataclass(frozen=True)
class CatalogUnitAppliedKeys:
    unit: object = field(repr=False)
    attempt_count: int
    key_watermarks: tuple
    project_identity: tuple


@dataclass(frozen=True)
class CatalogProjectKeyOrder:
    project_identity: tuple
    applied_maxima: tuple
    pending_keys: tuple


@dataclass(frozen=True)
class CatalogFifoFrontier:
    """Borrowed original-derived read only, never fresh admission or a permit."""
    project_identity: tuple
    frontier: tuple
    blocked: tuple
    applied: tuple
    superseded: tuple


@contextmanager
def _hold_all_project_fifo_frontier(token, binding):
    """Shared key order from ALL continuously held original project evidence.

    Catalog order governs overlapping pending keys across projects. Local
    generation sequences and UNSENT witnesses are compared only within the
    exact original project. Every counted unit needs genuine APPLIED inputs;
    any UNKNOWN or interrupted disposition refuses the entire observation.
    This reader does not append dispositions, release NEW, count or send.
    """
    failed = False
    from monitor import issue_tracker_unit_catalog as catalog
    from monitor import issue_tracker_remote_history_match as remote
    intents = catalog._Originals()
    try:
        sheet_owner = ownership._validated_owner(token, binding)
        with ExitStack() as scope:
            rows, verify_inputs = scope.enter_context(_hold_all_project_applied_keys(token, binding))
            owners = {}; namespaces = {}; validators = []; removed = []
            prefixes = ('REMOTE-UNSENT-SUPERSESSION-STARTED-', 'REMOTE-UNSENT-SUPERSESSION-')
            witness_prefix = 'REMOTE-UNSENT-SUPERSESSION-WITNESS-'
            states = ('UNSENT-SUPERSESSION-STARTED', 'SUPERSEDED-NOT-SENT')
            def disposition_names(owner):
                return frozenset(name for name in os.listdir(owner.root_fd)
                                 if name.startswith(prefixes) or name.startswith('.pending-'))
            for project_identity in dict.fromkeys(row.project_identity for row in rows):
                matches = []
                for writer, active in tuple(local._ACTIVE.items()):
                    if (active.pid == os.getpid()
                            and journal._identity(os.fstat(active.project_fd))[:2] == project_identity):
                        matches.append((writer, local._owner(writer)))
                if len(matches) != 1:
                    raise RetainedInventoryHold()
                writer, owner = matches[0]
                owners[project_identity] = (writer, owner)
                project_rows = tuple(row for row in rows if row.project_identity == project_identity)
                pending_rows = tuple(row for row in project_rows if row.attempt_count == 0)
                present = disposition_names(owner); namespaces[project_identity] = present
                allowed = {prefix + row.unit.unit_id for prefix in (*prefixes, witness_prefix) for row in pending_rows}
                if not present <= allowed:
                    raise RetainedInventoryHold()
                for row in pending_rows:
                    names = tuple(prefix + row.unit.unit_id for prefix in prefixes)
                    witness_name = witness_prefix + row.unit.unit_id
                    exists = tuple(name in present for name in (*names, witness_name))
                    if any(exists) and not all(exists):
                        raise RetainedInventoryHold()
                    recorded = None
                    if all(exists):
                        raw, _info = local._read(owner.root_fd, names[1], local._MAX_MANIFEST)
                        recorded = local._json(raw)
                    body, _observed = _unsent_disposition_body(owner, binding, row, project_rows, recorded)
                    if body is None:
                        if any(exists):
                            raise RetainedInventoryHold()
                        continue
                    # A computed later maximum is not a committed disposition.
                    # Missing originals stay HOLD: no adoption or auto-write.
                    if not all(exists):
                        raise RetainedInventoryHold()
                    witness_raw = local._canonical({'schema_version': 1, 'unit_id': row.unit.unit_id,
                        'state': 'UNSENT-SUPERSESSION-WRITE-STARTED-NOT-AUTHORITY',
                        'body_sha256': hashlib.sha256(local._canonical(body)).hexdigest()})
                    raw, identity = intents.file(owner.root_fd, witness_name, 16384)
                    if raw != witness_raw:
                        raise RetainedInventoryHold()
                    body = {**body, 'write_witness': {'identity': list(identity),
                            'sha256': hashlib.sha256(raw).hexdigest()}}
                    validators.append(scope.enter_context(remote._hold_applied_records(owner.root_fd,
                        names, body, states=states)))
                    removed.append(row.unit.unit_id)
            if len(set(removed)) != len(removed):
                raise RetainedInventoryHold()
            removed_ids = set(removed); pending = []; applied = []
            for row in rows:
                if row.attempt_count:
                    applied.append(row.unit.unit_id)
                elif row.unit.unit_id not in removed_ids:
                    action = local._json(row.unit.action_preimage)
                    match = local._GEN.fullmatch(action['identity']['generation_id'])
                    keys = tuple(tuple(item['activity_key']) for item in action['business'])
                    if match is None or int(match.group(1)) < 1 or not keys or len(set(keys)) != len(keys):
                        raise RetainedInventoryHold()
                    pending.append((row.unit.unit_id, row.project_identity, int(match.group(1)), frozenset(keys)))
            frontier = []; blocked = []
            for index, (unit_id, project_identity, sequence, keys) in enumerate(pending):
                barriers = [prior_id for prior_id, _project, _sequence, prior_keys in pending[:index] if keys & prior_keys]
                for row in rows:
                    if (row.attempt_count and row.project_identity == project_identity
                            and any(key in keys and maximum >= sequence for key, maximum in row.key_watermarks)):
                        barriers.append(row.unit.unit_id)
                if barriers:
                    blocked.append((unit_id, tuple(dict.fromkeys(barriers))))
                else:
                    frontier.append(unit_id)
            result = CatalogSharedFifoFrontier(tuple(frontier), tuple(blocked), tuple(applied), tuple(removed),
                tuple((row.unit.unit_id, row.project_identity) for row in rows))
            def verify():
                if ownership._validated_owner(token, binding) is not sheet_owner:
                    raise RetainedInventoryHold()
                verify_inputs(); intents.verify()
                for project_identity, (writer, owner) in owners.items():
                    if (local._owner(writer) is not owner
                            or journal._identity(os.fstat(owner.project_fd))[:2] != project_identity
                            or disposition_names(owner) != namespaces[project_identity]):
                        raise RetainedInventoryHold()
                for validate in validators:
                    validate()
                verify_inputs(); intents.verify()
            verify()
            intents.sync()
            yield result, verify
            verify()
    except Exception:
        failed = True
    finally:
        intents.close()
    if failed:
        raise RetainedInventoryHold() from None


@dataclass(frozen=True)
class CatalogSharedFifoFrontier:
    """ALL borrowed original observations, never a generation or send permit."""
    frontier: tuple
    blocked: tuple
    applied: tuple
    superseded: tuple
    projects: tuple


@contextmanager
def _hold_catalog_fifo_frontier(writer_token, token, binding):
    """Original one-project FIFO partition held through its actual consumer.

    A counted row can leave the pending order only through its genuine
    COMPLETE/APPLIED/key originals. UNSENT additionally requires the immutable
    disposition pair and its write-ahead witness; a computed maximum is not
    settlement. Any unresolved counted row holds the whole read. Pending units
    blocked by earlier overlapping pending units stay in original catalog
    order. A pending key at/below an original APPLIED high-water also stays
    blocked: a partial supersession cannot permit reverse replay of that key.
    No count/reset, mutation, cleanup, first-send or qualified NEW is issued.
    Cross-project roots and sequences are deliberately not inferred here.
    """
    failed = False
    try:
        owner = local._owner(writer_token)
        with ExitStack() as scope:
            rows, verify_rows = scope.enter_context(_hold_catalog_applied_keys(writer_token, token, binding))
            dispositions, verify_dispositions = scope.enter_context(_hold_catalog_unsent_dispositions(writer_token, token, binding))
            project = journal._identity(os.fstat(owner.project_fd))[:2]
            maxima = dict(_project_applied_maxima(rows, project))
            superseded = tuple(unit_id for unit_id, _sequence, _keys in dispositions)
            removed = set(superseded)
            if len(removed) != len(superseded):
                raise RetainedInventoryHold()
            pending = []; applied = []
            for row in rows:
                if row.attempt_count:
                    if row.unit.unit_id in removed:
                        raise RetainedInventoryHold()
                    applied.append(row.unit.unit_id)
                elif row.unit.unit_id not in removed:
                    action = local._json(row.unit.action_preimage)
                    match = local._GEN.fullmatch(action['identity']['generation_id'])
                    if match is None or int(match.group(1)) < 1:
                        raise RetainedInventoryHold()
                    keys = tuple(tuple(item['activity_key']) for item in action['business'])
                    if not keys or len(set(keys)) != len(keys):
                        raise RetainedInventoryHold()
                    pending.append((row.unit.unit_id, int(match.group(1)), frozenset(keys)))
            if not removed <= {row.unit.unit_id for row in rows if row.attempt_count == 0}:
                raise RetainedInventoryHold()
            frontier = []; blocked = []
            for index, (unit_id, sequence, keys) in enumerate(pending):
                barriers = [prior_id for prior_id, _prior_sequence, prior_keys in pending[:index] if keys & prior_keys]
                for row in rows:
                    if row.attempt_count and any(key in keys and maximum >= sequence
                                                 for key, maximum in row.key_watermarks):
                        barriers.append(row.unit.unit_id)
                # Keep the actual blocking witness unit IDs, not caller
                # flags or a detached arithmetic maximum standing as proof.
                if any(maxima.get(key, 0) >= sequence for key in keys) and not barriers:
                    raise RetainedInventoryHold()
                if barriers:
                    blocked.append((unit_id, tuple(dict.fromkeys(barriers))))
                else:
                    frontier.append(unit_id)
            result = CatalogFifoFrontier(project, tuple(frontier), tuple(blocked), tuple(applied), superseded)
            def verify():
                if local._owner(writer_token) is not owner:
                    raise RetainedInventoryHold()
                verify_rows(); verify_dispositions(); verify_rows()
            verify()
            yield result, verify
            verify()
    except Exception:
        failed = True
    if failed:
        raise RetainedInventoryHold() from None


def _project_applied_maxima(rows, project_identity):
    """Pure arithmetic over observations, NOT an original proof or permit.

    Sequences are project-scoped: a foreign project's larger number cannot
    dominate a local key. Only actually APPLIED keys enter this fold. Callers
    must use the held reader below for any original-evidence observation.
    """
    if (type(rows) is not tuple or not rows or type(project_identity) is not tuple
            or len(project_identity) != 2
            or any(type(value) is not int or value < 0 for value in project_identity)):
        raise RetainedInventoryHold()
    maxima = {}
    for row in rows:
        if (type(row) is not CatalogUnitAppliedKeys or row.project_identity != project_identity
                or type(row.attempt_count) is not int or not 0 <= row.attempt_count <= 6
                or type(row.key_watermarks) is not tuple
                or bool(row.key_watermarks) != bool(row.attempt_count)):
            raise RetainedInventoryHold()
        seen = set()
        for pair in row.key_watermarks:
            if type(pair) is not tuple or len(pair) != 2:
                raise RetainedInventoryHold()
            key, sequence = pair
            if (type(key) is not tuple or len(key) != 4
                    or any(type(value) is not str or not value for value in key)
                    or key in seen or type(sequence) is not int or sequence < 1):
                raise RetainedInventoryHold()
            seen.add(key)
            maxima[key] = max(maxima.get(key, 0), sequence)
    return tuple(sorted(maxima.items()))


@contextmanager
def _hold_catalog_key_order(writer_token, token, binding):
    """Fold ALL original APPLIED keys while C6/catalog/COMPLETE remain held.

    This one-project observation lists pending generation/key comparisons;
    it never declares UNKNOWN settled, marks UNSENT superseded, releases FIFO,
    or admits NEW. An incomplete counted unit refuses the entire fold. No
    caller maxima, rows, project path, generation or settlement flag is read.
    """
    failed = False
    try:
        owner = local._owner(writer_token)
        project_identity = journal._identity(os.fstat(owner.project_fd))[:2]
        with _hold_catalog_applied_keys(writer_token, token, binding) as (rows, verify_inputs):
            maxima = _project_applied_maxima(rows, project_identity)
            maximum_by_key = dict(maxima)
            pending = []
            for row in rows:
                if row.attempt_count:
                    continue
                action = local._json(row.unit.action_preimage)
                generation_id = action['identity']['generation_id']
                match = local._GEN.fullmatch(generation_id) if type(generation_id) is str else None
                if match is None or int(match.group(1)) < 1:
                    raise RetainedInventoryHold()
                keys = tuple(sorted(tuple(item['activity_key']) for item in action['business']))
                if not keys or len(set(keys)) != len(keys):
                    raise RetainedInventoryHold()
                pending.append((row.unit.unit_id, int(match.group(1)),
                                tuple((key, maximum_by_key.get(key, 0)) for key in keys)))
            result = CatalogProjectKeyOrder(project_identity, maxima, tuple(pending))
            def verify():
                if (local._owner(writer_token) is not owner
                        or journal._identity(os.fstat(owner.project_fd))[:2] != project_identity):
                    raise RetainedInventoryHold()
                verify_inputs()
            verify()
            yield result, verify
            verify()
    except Exception:
        failed = True
    if failed:
        raise RetainedInventoryHold() from None


def _superseded_unsent_candidates(order):
    """Pure comparison only; no durable disposition or original authority.

    ALL actually sent-candidate keys of an unattempted unit must have a
    strictly later APPLIED key sequence. A later pending/SENT/UNKNOWN unit,
    equal sequence, different key or partial coverage never suffices.
    """
    if (type(order) is not CatalogProjectKeyOrder
            or type(order.applied_maxima) is not tuple
            or type(order.pending_keys) is not tuple):
        raise RetainedInventoryHold()
    maxima = {}
    for pair in order.applied_maxima:
        if type(pair) is not tuple or len(pair) != 2:
            raise RetainedInventoryHold()
        key, sequence = pair
        if (type(key) is not tuple or len(key) != 4 or key in maxima
                or any(type(value) is not str or not value for value in key)
                or type(sequence) is not int or sequence < 1):
            raise RetainedInventoryHold()
        maxima[key] = sequence
    result = []; units = set()
    for pending in order.pending_keys:
        if type(pending) is not tuple or len(pending) != 3:
            raise RetainedInventoryHold()
        unit_id, sequence, keys = pending
        if (type(unit_id) is not str or not unit_id or unit_id in units
                or type(sequence) is not int or sequence < 1
                or type(keys) is not tuple or not keys):
            raise RetainedInventoryHold()
        units.add(unit_id); seen = set()
        for pair in keys:
            if type(pair) is not tuple or len(pair) != 2:
                raise RetainedInventoryHold()
            key, maximum = pair
            if (type(key) is not tuple or len(key) != 4 or key in seen
                    or any(type(value) is not str or not value for value in key)
                    or type(maximum) is not int or maximum != maxima.get(key, 0)):
                raise RetainedInventoryHold()
            seen.add(key)
        if all(maximum > sequence for _key, maximum in keys):
            result.append(pending)
    return tuple(result)


@contextmanager
def _hold_catalog_unsent_supersession_inputs(writer_token, token, binding):
    """Hold original inputs for a future immutable UNSENT disposition.

    No disposition is written or declared committed here. Counted units
    cannot enter pending comparisons; an unresolved counted original holds
    the entire read. This does not change UNKNOWN/count, reclaim originals,
    release FIFO or issue NEW. The pure tuple alone is never authority.
    """
    failed = False
    try:
        owner = local._owner(writer_token)
        with _hold_catalog_key_order(writer_token, token, binding) as (order, verify_inputs):
            candidates = _superseded_unsent_candidates(order)
            def verify():
                if local._owner(writer_token) is not owner:
                    raise RetainedInventoryHold()
                verify_inputs()
            verify()
            yield candidates, verify
            verify()
    except Exception:
        failed = True
    if failed:
        raise RetainedInventoryHold() from None


def _unsent_disposition_body(owner, binding, old, rows, recorded=None):
    """Bind a fixed set of original later APPLIED witnesses, never a live max.

    A newer maximum cannot rewrite an existing immutable disposition. Cold
    readers replay the originally selected units and their key pair inodes.
    This one-project body is NOT a global high-water or NEW/FIFO permit.
    """
    if old.attempt_count != 0:
        raise RetainedInventoryHold()
    action = local._json(old.unit.action_preimage)
    match = local._GEN.fullmatch(action['identity']['generation_id'])
    if match is None or int(match.group(1)) < 1:
        raise RetainedInventoryHold()
    sequence = int(match.group(1))
    keys = tuple(sorted(tuple(item['activity_key']) for item in action['business']))
    if not keys or len(set(keys)) != len(keys):
        raise RetainedInventoryHold()
    applied = {row.unit.unit_id: row for row in rows if row.attempt_count}
    if recorded is None:
        witnesses = []
        for key in keys:
            choices = sorted((later, row.unit.unit_id) for row in applied.values()
                             for candidate, later in row.key_watermarks
                             if candidate == key and later > sequence)
            if not choices:
                return None, None
            later, unit_id = choices[0]
            witnesses.append([list(key), later, unit_id])
    else:
        witnesses = recorded.get('witnesses')
        if type(witnesses) is not list or len(witnesses) != len(keys):
            raise RetainedInventoryHold()
        for key, witness in zip(keys, witnesses):
            if (type(witness) is not list or len(witness) != 3
                    or witness[0] != list(key) or type(witness[1]) is not int
                    or witness[1] <= sequence or type(witness[2]) is not str
                    or witness[2] not in applied
                    or (key, witness[1]) not in applied[witness[2]].key_watermarks):
                raise RetainedInventoryHold()
    references = {}
    for unit_id in sorted({witness[2] for witness in witnesses}):
        for prefix in ('REMOTE-KEY-HIGH-WATER-STARTED-', 'REMOTE-KEY-HIGH-WATER-'):
            name = prefix + unit_id
            raw, info = local._read(owner.root_fd, name, local._MAX_MANIFEST)
            references[name] = {'identity': list(journal._identity(info)),
                                'sha256': hashlib.sha256(raw).hexdigest()}
    body = {'schema_version': 1, 'disposition': 'SUPERSEDED-NOT-SENT',
            'spreadsheet_id': binding.spreadsheet_id,
            'project_identity': list(old.project_identity),
            'unit_id': old.unit.unit_id, 'generation_id': action['identity']['generation_id'],
            'sequence': sequence, 'attempt_count': 0,
            'action_digest': old.unit.action_digest, 'wire_sha256': old.unit.wire_sha256,
            'witnesses': witnesses, 'applied_key_originals': references}
    observed = (old.unit.unit_id, sequence,
                tuple((tuple(key), later) for key, later, _unit_id in witnesses))
    return body, observed


@contextmanager
def _catalog_unsent_dispositions(writer_token, token, binding, *, record):
    """One-project append-only disposition; retain C6/count/APPLIED originals.

    STARTED binds both prepared inodes before the final rename. Partial pairs
    and pending writes survive failure, are never repaired/adopted, and cannot
    authorize sending. UNKNOWN and its counted journal remain unchanged.
    """
    failed = False
    from monitor import issue_tracker_unit_catalog as catalog
    intents = catalog._Originals()
    try:
        owner = local._owner(writer_token)
        from monitor import issue_tracker_remote_history_match as remote
        with ExitStack() as scope:
            rows, verify_inputs = scope.enter_context(_hold_catalog_applied_keys(writer_token, token, binding))
            present = set(os.listdir(owner.root_fd))
            prefixes = ('REMOTE-UNSENT-SUPERSESSION-STARTED-', 'REMOTE-UNSENT-SUPERSESSION-')
            witness_prefix = 'REMOTE-UNSENT-SUPERSESSION-WITNESS-'
            states = ('UNSENT-SUPERSESSION-STARTED', 'SUPERSEDED-NOT-SENT')
            old_rows = tuple(row for row in rows if row.attempt_count == 0)
            allowed = {prefix + row.unit.unit_id for prefix in (*prefixes, witness_prefix) for row in old_rows}
            if (any(name.startswith('.pending-') for name in present)
                    or any(name.startswith(prefixes) and name not in allowed for name in present)):
                raise RetainedInventoryHold()
            results = []; validators = []
            for row in old_rows:
                names = tuple(prefix + row.unit.unit_id for prefix in prefixes)
                witness_name = witness_prefix + row.unit.unit_id
                exists = tuple(name in present for name in (*names, witness_name))
                if any(exists) and not all(exists):
                    raise RetainedInventoryHold()
                recorded = None
                if all(exists):
                    raw, _info = local._read(owner.root_fd, names[1], local._MAX_MANIFEST)
                    recorded = local._json(raw)
                body, observed = _unsent_disposition_body(owner, binding, row, rows, recorded)
                if body is None:
                    continue
                intent_raw = local._canonical({'schema_version': 1, 'unit_id': row.unit.unit_id,
                    'state': 'UNSENT-SUPERSESSION-WRITE-STARTED-NOT-AUTHORITY',
                    'body_sha256': hashlib.sha256(local._canonical(body)).hexdigest()})
                created_identity = None
                if not any(exists):
                    if not record:
                        raise RetainedInventoryHold()
                    verify_inputs()
                    # A fixed STOP witness exists before its first byte. Both
                    # pair names later disappearing never becomes first use.
                    # Short writes/fsync failures retain this witness; no
                    # deletion, repair or adoption of an interrupted creation.
                    created_identity = remote._write_completion_start(owner.root_fd, witness_name, intent_raw)
                raw, identity = intents.file(owner.root_fd, witness_name, 16384)
                if raw != intent_raw or (created_identity is not None and identity != created_identity):
                    raise RetainedInventoryHold()
                intents.sync()
                body = {**body, 'write_witness': {'identity': list(identity),
                        'sha256': hashlib.sha256(raw).hexdigest()}}
                def verify_write_inputs():
                    verify_inputs(); intents.verify()
                if not any(exists):
                    scope.enter_context(remote._write_applied_pair(owner.root_fd, names, body,
                        verify_write_inputs, states=states))
                validators.append(scope.enter_context(remote._hold_applied_records(owner.root_fd,
                    names, body, states=states)))
                results.append(observed)
            def verify():
                if local._owner(writer_token) is not owner:
                    raise RetainedInventoryHold()
                verify_inputs()
                intents.verify()
                for validate in validators:
                    validate()
                verify_inputs()
            verify()
            yield tuple(results), verify
            verify()
    except Exception:
        failed = True
    finally:
        intents.close()
    if failed:
        raise RetainedInventoryHold() from None


@contextmanager
def _hold_catalog_unsent_dispositions(writer_token, token, binding):
    """Cold original-only observation, not FIFO release or NEW admission."""
    with _catalog_unsent_dispositions(writer_token, token, binding, record=False) as result:
        yield result


def _record_catalog_unsent_dispositions(writer_token, token, binding):
    """Append genuine later-APPLIED UNSENT pairs; no override or repair."""
    with _catalog_unsent_dispositions(writer_token, token, binding, record=True) as (result, verify):
        verify()
    return result


def _unique_names(names):
    if (type(names) is not tuple or len(names) > 256 or any(type(name) is not str for name in names)
            or len(set(names)) != len(names)):
        raise RetainedInventoryHold()
    return frozenset(names)


def _namespace_entries(stem, names):
    """Private shape classifier, NOT an owner or original-image certificate."""
    if type(stem) is not str or re.fullmatch(r'[0-9a-f]{64}', stem) is None:
        raise RetainedInventoryHold()
    names = _unique_names(names)
    retained = []
    for name in names:
        if not name.startswith(stem + '.') or name == stem + '.lock':
            continue
        family = name[len(stem) + 1:]
        if family not in _FAMILIES:
            raise RetainedInventoryHold()
        retained.append((name, family))
    if not {stem + '.journal', stem + '.journal-started'} <= names:
        raise RetainedInventoryHold()
    if (stem + '.completion' in names) != (stem + '.completion-started' in names):
        raise RetainedInventoryHold()
    return tuple(sorted(retained))


def _family_entries(family, names):
    names = _unique_names(names)
    if family in _FIXED:
        if names != _FIXED[family]:
            raise RetainedInventoryHold()
    elif family in ('journal', 'dispatch'):
        fixed = {'HEADER', 'INITIALIZED'}
        if family == 'journal':
            fixed.update(('ACTION-PREIMAGE', 'WIRE'))
        count = len(names) - len(fixed)
        prefix = 'ATTEMPT-' if family == 'journal' else 'CLAIM-'
        if not 0 <= count <= 6 or names != fixed | {prefix + str(i) for i in range(1, count + 1)}:
            raise RetainedInventoryHold()
    else:
        raise RetainedInventoryHold()
    return tuple(sorted(names))


def _limit(family, name):
    if name == 'BUSINESS-RAW':
        return 16 * 1024 * 1024
    if name.endswith('-RAW'):
        return 2 * 1024 * 1024
    if name in ('WIRE', 'ACTION-PREIMAGE', 'MANIFEST', 'RESERVATION', 'RESERVATIONS'):
        return 1024 * 1024
    return 65536 if family == 'completion' and name == 'HEADER' else 16384


def _verify_retained_read_links(namespace, files):
    """Check links using ONLY bytes read from the already held originals.

    This is not semantic replay of reservations/business/completion/APPLIED.
    Those families still require their specialized validators. Even for these
    two read families, a coherent link is not remote truth or a NEW permit.
    """
    images = {relative: raw for _directory, _entry, relative, _fd, _identity, raw in files}
    for name, family in namespace:
        if family not in ('enrollment', 'history'):
            continue
        header_raw = images[name + '/HEADER']
        header = local._json(header_raw)
        marker = local._canonical({'schema_version': 1, 'state': 'INITIALIZED',
                                  'header_sha256': hashlib.sha256(header_raw).hexdigest()})
        if images[name + '/INITIALIZED'] != marker:
            raise RetainedInventoryHold()
        field, original = (('nonces_sha256', 'NONCES') if family == 'enrollment'
                           else ('source_sha256', 'HISTORY-RAW'))
        if header.get(field) != hashlib.sha256(images[name + '/' + original]).hexdigest():
            raise RetainedInventoryHold()


def _verify_legacy_read_semantics(stem, namespace, files, directories, unit, binding, parent, *, enrollment_name=None):
    """Replay existing read contracts while all inventory originals stay held.

    Coherent marker/digest links do not bind a foreign nonce or History unit.
    These are local original observations, not remote freshness or admission.
    """
    images = {relative: raw for _directory, _entry, relative, _fd, _identity, raw in files}
    folders = {name: folder for name, folder, _identity, _names in directories}
    action = local._json(unit.action_preimage)
    names = {name for name, _family in namespace}
    enrollment_name = stem + '.enrollment' if enrollment_name is None else enrollment_name
    if enrollment_name in names:
        original = local._json(images[enrollment_name + '/HEADER'])
        if set(original) != {'schema_version', 'spreadsheet_id', 'sheet_ids', 'nonces_sha256'}:
            raise RetainedInventoryHold()
        ids = original['sheet_ids']
        if type(ids) is not list or len(ids) != len(decode._TEMPLATE_SHEETS):
            raise RetainedInventoryHold()
        seen_ids = set()
        for title, row in zip(decode._TEMPLATE_SHEETS, ids):
            if (type(row) is not list or len(row) != 2 or row[0] != title
                    or type(row[1]) is not int or not 0 <= row[1] <= 2147483647
                    or row[1] in seen_ids):
                raise RetainedInventoryHold()
            seen_ids.add(row[1])
        base = {'schema_version': 1, 'spreadsheet_id': binding.spreadsheet_id, 'sheet_ids': ids}
        observed = enrollment._inspect(parent, folders[enrollment_name], enrollment_name, base)
        rows = {title: (sid, nonce) for title, sid, nonce in observed.nonces}
        target = action['identity']
        if (rows.get(target['sheet']) != (target['sheet_id'], action['target_nonce'])
                or rows.get('Update_History') != (action['history_sheet_id'], action['history_nonce'])):
            raise RetainedInventoryHold()
    history_name = stem + '.history'
    if history_name in names:
        base = local._json(images[stem + '.journal/HEADER'])
        history._inspect(parent, history_name, folders[history_name], base, action['history_sheet_id'])


def _close_if_original(fd, identity):
    # Proof verification requires full stat/raw/name equality. Cleanup only
    # closes our original object, including an original whose bytes/ctime have
    # drifted. A recycled integer naming a different object is NOT ours.
    try:
        if identity is None or journal._identity(os.fstat(fd))[:2] != identity[:2]:
            return False
        os.close(fd)
        return True
    except OSError:
        return False


def _verify_legacy_dispatch(stem, namespace, files, directories, unit, state):
    """Bind consumed UNKNOWN claims to the held original prefix, never SENT.

    A complete claim records one-time consumption only. It is not evidence of
    process launch, remote send/settlement, fresh admission or a released FIFO.
    """
    name = stem + '.dispatch'
    if name not in {entry for entry, _family in namespace}:
        return
    originals = {relative: (identity, raw)
                 for _directory, _entry, relative, _fd, identity, raw in files}
    folders = {entry: folder for entry, folder, _identity, _names in directories}
    journal_name = stem + '.journal'
    header = {'schema_version': 1, 'unit_id': unit.unit_id,
              'wire_sha256': unit.wire_sha256, 'action_digest': unit.action_digest,
              'journal_header_sha256': hashlib.sha256(originals[journal_name + '/HEADER'][1]).hexdigest(),
              'wire_identity': originals[journal_name + '/WIRE'][0],
              'action_identity': originals[journal_name + '/ACTION-PREIMAGE'][0]}
    count, _previous = global_journal._inspect_wire_claims(
        folders[name], folders[journal_name], unit, header)
    if count > state.attempt_count:
        raise RetainedInventoryHold()


def _verify_legacy_business_links(stem, namespace, files, unit, *, enrollment_name=None):
    """Necessary original envelope/NOOP coverage, not full cell replay.

    Do not fabricate a remote identity observation from enrolled ids to invoke
    a typed decoder. Full business semantic/source validation is still required
    before this inventory can participate in any admission or APPLIED proof.
    """
    name = stem + '.business'
    names = {entry for entry, _family in namespace}
    if name not in names:
        return
    enrollment_name = stem + '.enrollment' if enrollment_name is None else enrollment_name
    if not {enrollment_name, stem + '.history'} <= names:
        raise RetainedInventoryHold()
    originals = {relative: raw for _directory, _entry, relative, _fd, _identity, raw in files}
    action = local._json(unit.action_preimage)
    manifest = originals[name + '/MANIFEST']
    if hashlib.sha256(manifest).hexdigest() != action['manifest_id']:
        raise RetainedInventoryHold()
    manifest_document = local._json(manifest)
    from monitor.issue_tracker_manifest import _validated_operations, _runtime_operation
    operations = _validated_operations(manifest_document['operations'], 'retained business',
                                       validator=_runtime_operation)
    family = {'ETH&IB Switch': 'switch', 'ETH Cabling': 'eth_cabling', 'IB Cabling': 'ib_cabling'}[
        action['identity']['sheet']]
    selected = [item for item in operations if item['activity_key'][0] == family]
    reads = history._unpack_business(originals[name + '/BUSINESS-RAW'])
    ids = [item['operation_id'] for item in selected]
    if (ids != [item['operation_id'] for item in reads]
            or ids != [item['operation_id'] for item in action['decisions']]):
        raise RetainedInventoryHold()
    raw = originals[name + '/BUSINESS-RAW']
    expected = {**local._json(originals[stem + '.journal/HEADER']),
                'preread_sha256': action['preread_sha256'],
                'source_sha256': hashlib.sha256(raw).hexdigest(),
                'operations_retained': len(ids),
                'noop_operations': sum(item['outcome'] == 'OBSERVED-SATISFIED-AT-READ'
                                       for item in action['decisions'])}
    header = originals[name + '/HEADER']
    if (header != local._canonical(expected)
            or originals[name + '/INITIALIZED'] != global_journal._initialization(expected)):
        raise RetainedInventoryHold()


def _verify_legacy_completion(stem, namespace, token, binding, unit, state, *, enrollment_name=None):
    """Replay the existing retained proof, never trust COMPLETE file shape.

    The remote-history reader reopens and holds original start/header/raw images,
    derives fixed read geometries and replays nonce/fence/all-History semantics.
    No caller identity, MATCHED boolean, read receipt or APPLIED claim is issued.
    The inventory's wider original pins remain held across all those barriers.
    """
    names = {name for name, _family in namespace}
    if stem + '.completion' not in names:
        return
    enrollment_name = stem + '.enrollment' if enrollment_name is None else enrollment_name
    if not {enrollment_name, stem + '.history'} <= names:
        raise RetainedInventoryHold()
    from monitor import issue_tracker_remote_history_match as remote
    result = remote.inspect_completion_evidence(token, binding, unit)
    if (result.state != 'COMPLETE-PRESENT-NOT-APPLIED'
            or result.attempt_count != state.attempt_count or result.unit_id != unit.unit_id):
        raise RetainedInventoryHold()


@contextmanager
def _hold_retained_inventory(token, binding):
    """Pin every entry before interpreting any original journal semantics.

    Names/full stat/raw are checked across semantic replay, every recovery fsync
    and the consumer. A partial/foreign/unsupported namespace is retained HOLD.
    A caller cannot supply paths, files, counts, SHA images or a send permission.
    Enrollment nonces/ids, History decode/capacity and dispatch consumption are
    replayed against this original unit. Other non-journal images remain coverage
    witnesses requiring specialized validators, never APPLIED/remote freshness.
    """
    directories = []; files = []; failed = False
    try:
        with ExitStack() as scope:
            owner = ownership._validated_owner(token, binding)
            parent = owner.directories[-1][0]
            stem = owner.lock_name[:-5]
            parent_identity = journal._identity(os.fstat(parent))
            namespace = _namespace_entries(stem, tuple(os.listdir(parent)))
            total = 0
            for name, family in namespace:
                if family.endswith('-started'):
                    entries = ((parent, name, name, 16384),)
                else:
                    folder = local._directory(parent, name)
                    directories.append((name, folder, journal._identity(os.fstat(folder)), None))
                    journal._named(parent, name, folder, directory=True)
                    identity = journal._identity(os.fstat(folder))
                    names = _family_entries(family, tuple(os.listdir(folder)))
                    directories[-1] = (name, folder, identity, names)
                    entries = tuple((folder, entry, name + '/' + entry, _limit(family, entry)) for entry in names)
                for directory, entry, relative, limit in entries:
                    fd = os.open(entry, local._flags(), dir_fd=directory)
                    files.append((directory, entry, relative, fd, journal._identity(os.fstat(fd)), None))
                    info = local._check(fd, directory=False)
                    journal._named(directory, entry, fd, directory=False)
                    identity = journal._identity(info)
                    raw = os.pread(fd, limit + 1, 0)
                    total += len(raw)
                    if (not raw or len(raw) > limit or len(raw) != info.st_size or total > _TOTAL_LIMIT
                            or journal._identity(os.fstat(fd)) != identity):
                        raise RetainedInventoryHold()
                    files[-1] = (directory, entry, relative, fd, identity, raw)

            def verify():
                if (ownership._validated_owner(token, binding) is not owner
                        or journal._identity(os.fstat(parent)) != parent_identity
                        or _namespace_entries(stem, tuple(os.listdir(parent))) != namespace):
                    raise RetainedInventoryHold()
                for name, folder, identity, names in directories:
                    journal._named(parent, name, folder, directory=True)
                    if (journal._identity(os.fstat(folder)) != identity
                            or tuple(sorted(os.listdir(folder))) != names):
                        raise RetainedInventoryHold()
                for directory, entry, _relative, fd, identity, raw in files:
                    journal._named(directory, entry, fd, directory=False)
                    if journal._identity(os.fstat(fd)) != identity or os.pread(fd, len(raw) + 1, 0) != raw:
                        raise RetainedInventoryHold()

            verify()
            unit, state, verify_global = scope.enter_context(global_journal._hold_original_global_unit(token, binding))
            _verify_retained_read_links(namespace, files)
            _verify_legacy_read_semantics(stem, namespace, files, directories, unit, binding, parent)
            _verify_legacy_dispatch(stem, namespace, files, directories, unit, state)
            _verify_legacy_business_links(stem, namespace, files, unit)
            _verify_legacy_completion(stem, namespace, token, binding, unit, state)
            verify()
            for _directory, _entry, _relative, fd, _identity, _raw in files:
                os.fsync(fd)
            for _name, folder, _identity, _names in directories:
                os.fsync(folder)
            os.fsync(parent); verify_global(); verify()
            seen = RetainedInventoryObservation(unit, state.attempt_count,
                tuple(family for _name, family in namespace),
                tuple((relative, identity, hashlib.sha256(raw).hexdigest())
                      for _directory, _entry, relative, _fd, identity, raw in files))
            def verify_all():
                verify_global(); verify()
            yield seen, verify_all
            verify_all()
    except Exception:
        failed = True
    finally:
        for _directory, _entry, _relative, fd, _identity, _raw in reversed(files):
            if not _close_if_original(fd, _identity):
                failed = True
        for _name, folder, _identity, _names in reversed(directories):
            if not _close_if_original(folder, _identity):
                failed = True
    if failed:
        raise RetainedInventoryHold()


def _verify_catalog_native_nv_originals(binding, observations, native_ids, parent, shared, files, directories, verify):
    """Replay C17 from borrowed actual inventory FDs, never a typed admission.

    Native identities came from the continuously held catalog HEADER chain.
    Enrollment was already replayed against each actual ACTION nonce. No
    synthetic TemplateIdentity, mutable caller inventory or new permit exists.
    """
    if not native_ids: return
    from monitor import issue_tracker_nv_reservation as nv
    images = {(directory, name): (raw, identity)
        for directory, name, _relative, _fd, identity, raw in files}
    folders = {name: folder for name, folder, _identity, _names in directories}
    enrollment_folder = folders[shared]
    enrollment_raw = images[(enrollment_folder, 'HEADER')][0]
    enrollment_header = local._json(enrollment_raw)
    ids = dict(enrollment_header['sheet_ids'])

    class BorrowedOriginals:
        def directory(self, actual_parent, name):
            if actual_parent != parent: raise RetainedInventoryHold()
            return folders[name]

        def file(self, directory, name, limit):
            raw, identity = images[(directory, name)]
            if not 1 <= len(raw) <= limit: raise RetainedInventoryHold()
            return raw, identity

        def verify(self):
            verify()

    borrowed = BorrowedOriginals(); prior = []
    for unit, _state in observations:
        insertions = nv._unit_insertions(unit)
        if not insertions:
            if unit.unit_id in native_ids: raise RetainedInventoryHold()
            continue
        # A later native reservation requires every older reservation's actual
        # original lineage. Never reinterpret an unproved older insertion as 0.
        if unit.unit_id not in native_ids: raise RetainedInventoryHold()
        target = local._json(unit.action_preimage)['identity']
        keys = tuple(key for key, _identifier in insertions)
        base = {'schema_version': 1, 'identity': target, 'unit_id': unit.unit_id,
            'requested_keys': keys, 'sheet_ids': enrollment_header['sheet_ids'],
            'enrollment_sha256': hashlib.sha256(enrollment_raw).hexdigest(),
            'allowlist_sha256': binding.allowlist_sha256, 'policy_sha256': binding.policy_sha256}
        # Native NV has the fixed per-sheet identity, not History/operation
        # fields from the full ACTION envelope.
        base['identity'] = {key: target[key] for key in
            ('schema_version', 'generation_id', 'publish_id', 'spreadsheet_id', 'sheet', 'sheet_id')}
        name = shared[:-len('.enrollment')] + '.unit-' + unit.unit_id + '.nv'
        seen = nv._native_original(parent, name, binding, base, keys, ids, prior, borrowed)
        if seen.unit_id != unit.unit_id or seen.reservations != insertions:
            raise RetainedInventoryHold()
        prior.append({'unit_id': unit.unit_id, 'journal_sha256': seen.journal_sha256,
                      'reservations': seen.reservations})
    verify()


@contextmanager
def _hold_catalog_retained_inventory(token, binding):
    """Pin EVERY original catalog unit/family plus shared enrollment.

    Fixed namespaces only, no caller units/paths/key sets. Pending units without
    their original journal/start pair make this complete diagnostic handoff
    HOLD, not empty/first-use. Replay existing nonce/History/dispatch/business
    links and any COMPLETE semantics while ALL originals remain held. Other
    reservation family images are coverage witnesses, not quota/NEW authority.
    No APPLIED settlement, key maximum, FIFO release or send permit is issued.
    """
    directories = []; files = []; failed = False
    try:
        with ExitStack() as scope:
            observations, verify_counts = scope.enter_context(global_journal._hold_catalog_attempts(token, binding))
            from monitor import issue_tracker_unit_catalog as catalog
            anchored = catalog._Originals(); scope.callback(anchored.close)
            catalog_fd, original_units, _previous = catalog._inspect(token, binding, anchored)
            if original_units != tuple(unit for unit, _state in observations): raise RetainedInventoryHold()
            unit_folders = {name: fd for directory, name, fd, _identity, _entries in anchored.directories
                            if directory == catalog_fd}
            headers = {(directory, name): raw for directory, name, _fd, _identity, raw in anchored.files}
            native_ids = frozenset(unit.unit_id for unit in original_units
                if local._json(headers[(unit_folders[unit.unit_id], 'HEADER')]).get('nv_original') is not None)
            owner = ownership._validated_owner(token, binding)
            parent = owner.directories[-1][0]; stem = owner.lock_name[:-5]
            parent_identity = journal._identity(os.fstat(parent))
            names = set(os.listdir(parent)); shared = stem + '.enrollment'
            namespace = []
            if shared in names:
                namespace.append((shared, 'enrollment'))
            per_unit = []
            for unit, state in observations:
                if state.outcome == 'PENDING_NO_JOURNAL':
                    raise RetainedInventoryHold()
                prefix = stem + '.unit-' + unit.unit_id
                entries = sorted((name, name[len(prefix) + 1:]) for name in names if name.startswith(prefix + '.'))
                unit_names = {name for name, _family in entries}
                if (not {prefix + '.journal', prefix + '.journal-started'} <= unit_names
                        or (prefix + '.completion' in unit_names) != (prefix + '.completion-started' in unit_names)
                        or any(family not in _CATALOG_FAMILIES or family == 'enrollment' for _name, family in entries)
                        or (prefix + '.nv-started' in unit_names and unit.unit_id not in native_ids)
                        or (unit.unit_id in native_ids and not {prefix + '.nv', prefix + '.nv-started'} <= unit_names)):
                    raise RetainedInventoryHold()
                namespace.extend(entries)
                per_unit.append((unit, state, prefix, tuple(sorted(entries + ([(shared, 'enrollment')] if shared in names else [])))))
            namespace = tuple(sorted(namespace)); total = 0
            native_names = {stem + '.unit-' + unit_id + '.nv' for unit_id in native_ids}
            for name, family in namespace:
                if family.endswith('-started'):
                    entries = ((parent, name, name, 16384),)
                else:
                    folder = local._directory(parent, name)
                    directories.append((name, folder, journal._identity(os.fstat(folder)), None))
                    journal._named(parent, name, folder, directory=True)
                    identity = journal._identity(os.fstat(folder))
                    if name in native_names:
                        from monitor import issue_tracker_nv_reservation as nv
                        actual_names = _unique_names(tuple(os.listdir(folder)))
                        if actual_names != nv._CATALOG_NAMES: raise RetainedInventoryHold()
                        child_names = tuple(sorted(actual_names))
                    else:
                        child_names = _family_entries(family, tuple(os.listdir(folder)))
                    directories[-1] = (name, folder, identity, child_names)
                    entries = tuple((folder, child, name + '/' + child,
                        max(_limit(family, child), nv._LIMIT) if name in native_names else _limit(family, child))
                        for child in child_names)
                for directory, entry, relative, limit in entries:
                    fd = os.open(entry, local._flags(), dir_fd=directory)
                    files.append((directory, entry, relative, fd, journal._identity(os.fstat(fd)), None))
                    info = local._check(fd, directory=False); journal._named(directory, entry, fd, directory=False)
                    identity = journal._identity(info); raw = os.pread(fd, limit + 1, 0); total += len(raw)
                    if not raw or len(raw) > limit or len(raw) != info.st_size or total > _TOTAL_LIMIT:
                        raise RetainedInventoryHold()
                    if journal._identity(os.fstat(fd)) != identity:
                        raise RetainedInventoryHold()
                    files[-1] = (directory, entry, relative, fd, identity, raw)

            def verify():
                verify_counts(); anchored.verify()
                if (ownership._validated_owner(token, binding) is not owner
                        or journal._identity(os.fstat(parent)) != parent_identity or set(os.listdir(parent)) != names):
                    raise RetainedInventoryHold()
                for name, folder, identity, child_names in directories:
                    journal._named(parent, name, folder, directory=True)
                    if journal._identity(os.fstat(folder)) != identity or tuple(sorted(os.listdir(folder))) != child_names:
                        raise RetainedInventoryHold()
                for directory, entry, _relative, fd, identity, raw in files:
                    journal._named(directory, entry, fd, directory=False)
                    if journal._identity(os.fstat(fd)) != identity or os.pread(fd, len(raw) + 1, 0) != raw:
                        raise RetainedInventoryHold()
                anchored.verify(); verify_counts()

            verify(); _verify_retained_read_links(namespace, files)
            results = []
            for unit, state, prefix, entries in per_unit:
                _verify_legacy_read_semantics(prefix, entries, files, directories, unit, binding, parent, enrollment_name=shared)
                _verify_legacy_dispatch(prefix, entries, files, directories, unit, state)
                _verify_legacy_business_links(prefix, entries, files, unit, enrollment_name=shared)
                _verify_legacy_completion(prefix, entries, token, binding, unit, state, enrollment_name=shared)
                selected = {name for name, _family in entries}
                results.append(RetainedInventoryObservation(unit, state.attempt_count,
                    tuple(family for _name, family in entries),
                    tuple((relative, identity, hashlib.sha256(raw).hexdigest())
                          for _directory, _entry, relative, _fd, identity, raw in files
                          if relative.split('/')[0] in selected)))
            _verify_catalog_native_nv_originals(binding, observations, native_ids, parent, shared,
                                               files, directories, verify)
            verify()
            for _directory, _entry, _relative, fd, _identity, _raw in files:
                os.fsync(fd)
            for _name, folder, _identity, _child_names in reversed(directories):
                os.fsync(folder)
            os.fsync(parent); verify()
            yield tuple(results), verify
            verify()
    except Exception:
        failed = True
    finally:
        for _directory, _entry, _relative, fd, identity, _raw in reversed(files):
            if not _close_if_original(fd, identity): failed = True
        for _name, folder, identity, _child_names in reversed(directories):
            if not _close_if_original(folder, identity): failed = True
    if failed:
        raise RetainedInventoryHold() from None


@contextmanager
def _hold_all_project_applied_keys(token, binding):
    """Read all original project C6 and counted APPLIED pairs together.

    Only the shared genuine owner selects the immutable catalog. Project
    writers are internal, borrowed from the held original C6 acquisition;
    callers cannot supply paths, writers, counts or settlement. A missing
    counted proof holds the entire read. Local sequence numbers remain scoped
    to their actual project, never a cross-project maximum or NEW permit.
    """
    failed = False
    try:
        sheet_owner = ownership._validated_owner(token, binding)
        from monitor import issue_tracker_unit_catalog as catalog
        from monitor import issue_tracker_remote_history_match as remote
        with ExitStack() as scope:
            projects, verify_c6 = scope.enter_context(catalog.hold_pending_project_c6_units(token, binding))
            observations, verify_inventory = scope.enter_context(_hold_catalog_retained_inventory(token, binding))
            if tuple(row.unit for row in projects) != tuple(row.unit for row in observations):
                raise RetainedInventoryHold()
            validators = []; owners = {}; result = []
            for project, row in zip(projects, observations):
                project_identity = project.project_identity
                if project_identity not in owners:
                    matches = []
                    for writer, active in tuple(local._ACTIVE.items()):
                        if (active.pid == os.getpid()
                                and journal._identity(os.fstat(active.project_fd))[:2] == project_identity):
                            matches.append((writer, local._owner(writer)))
                    if len(matches) != 1:
                        raise RetainedInventoryHold()
                    owners[project_identity] = matches[0]
                writer, owner = owners[project_identity]
                keys = ()
                if row.attempt_count:
                    if 'completion' not in row.families:
                        raise RetainedInventoryHold()
                    facts = local._json(project.c6_facts)
                    generation = local.Generation(facts['generation_id'], facts['sequence'], facts['manifest_id'], writer)
                    held_owner, verify_inputs, body, keys = scope.enter_context(
                        remote._hold_original_applied_key_watermark_inputs(writer, token, binding, row.unit, generation))
                    if held_owner is not owner or tuple(body['project_identity']) != project_identity:
                        raise RetainedInventoryHold()
                    names = ('REMOTE-KEY-HIGH-WATER-STARTED-' + row.unit.unit_id,
                             'REMOTE-KEY-HIGH-WATER-' + row.unit.unit_id)
                    verify_keys = scope.enter_context(remote._hold_applied_records(owner.root_fd, names, body,
                        states=('KEY-HIGH-WATER-STARTED', 'KEY-HIGH-WATER')))
                    validators.extend((verify_inputs, verify_keys))
                elif 'completion' in row.families:
                    raise RetainedInventoryHold()
                result.append(CatalogUnitAppliedKeys(row.unit, row.attempt_count, keys, project_identity))
            def verify():
                if ownership._validated_owner(token, binding) is not sheet_owner:
                    raise RetainedInventoryHold()
                verify_inventory(); verify_c6()
                for project_identity, (writer, owner) in owners.items():
                    if (local._owner(writer) is not owner
                            or journal._identity(os.fstat(owner.project_fd))[:2] != project_identity):
                        raise RetainedInventoryHold()
                for validate in validators:
                    validate()
                verify_inventory(); verify_c6()
            verify()
            yield tuple(result), verify
            verify()
    except Exception:
        failed = True
    if failed:
        raise RetainedInventoryHold() from None


@contextmanager
def _hold_catalog_applied_keys(writer_token, token, binding):
    """Hold every unit's real historical C6 and any COMPLETE/APPLIED/key pair.

    Only this genuine writer's project is supported. Pending unattempted units
    contribute no applied keys. A counted unit without the entire original
    COMPLETE/APPLIED/key pair makes the whole handoff HOLD, not a partial
    maximum. Historical generation names are read selectors, never issued
    mutation handles. No NEW permit, FIFO release or global maximum is issued.
    """
    failed = False
    try:
        owner = local._owner(writer_token)
        from monitor import issue_tracker_unit_catalog as catalog
        from monitor import issue_tracker_remote_history_match as remote
        with ExitStack() as scope:
            units, verify_c6 = scope.enter_context(catalog.hold_pending_c6_units(writer_token, token, binding))
            observations, verify_inventory = scope.enter_context(_hold_catalog_retained_inventory(token, binding))
            if units != tuple(row.unit for row in observations):
                raise RetainedInventoryHold()
            project_identity = journal._identity(os.fstat(owner.project_fd))[:2]
            validators = []; result = []
            for row in observations:
                keys = ()
                if row.attempt_count:
                    if 'completion' not in row.families:
                        raise RetainedInventoryHold()
                    action = local._json(row.unit.action_preimage)
                    generation_id = action['identity']['generation_id']
                    match = local._GEN.fullmatch(generation_id) if type(generation_id) is str else None
                    if match is None or int(match.group(1)) < 1:
                        raise RetainedInventoryHold()
                    generation = local.Generation(generation_id, int(match.group(1)), action['manifest_id'], writer_token)
                    held_owner, verify_inputs, body, keys = scope.enter_context(
                        remote._hold_original_applied_key_watermark_inputs(writer_token, token, binding, row.unit, generation))
                    if held_owner is not owner or tuple(body['project_identity']) != project_identity:
                        raise RetainedInventoryHold()
                    names = ('REMOTE-KEY-HIGH-WATER-STARTED-' + row.unit.unit_id,
                             'REMOTE-KEY-HIGH-WATER-' + row.unit.unit_id)
                    verify_keys = scope.enter_context(remote._hold_applied_records(owner.root_fd, names, body,
                        states=('KEY-HIGH-WATER-STARTED', 'KEY-HIGH-WATER')))
                    validators.extend((verify_inputs, verify_keys))
                elif 'completion' in row.families:
                    raise RetainedInventoryHold()
                result.append(CatalogUnitAppliedKeys(row.unit, row.attempt_count, keys, project_identity))
            def verify():
                if (local._owner(writer_token) is not owner
                        or journal._identity(os.fstat(owner.project_fd))[:2] != project_identity):
                    raise RetainedInventoryHold()
                verify_inventory(); verify_c6()
                for validate in validators:
                    validate()
                verify_inventory(); verify_c6()
            verify()
            yield tuple(result), verify
            verify()
    except Exception:
        failed = True
    if failed:
        raise RetainedInventoryHold() from None


@contextmanager
def _hold_retained_applied_keys(writer_token, token, binding):
    """Join the retained original unit to its actual C6/APPLIED/key pair.

    No caller unit/generation/key set, inventory maximum, FIFO or NEW permit.
    The reconstructed generation is for historical reading only: it is not
    registered as an issued mutation handle in the writer's acquisition.
    Every original remains held through the caller and final checks.
    """
    failed = False
    try:
        owner = local._owner(writer_token)
        with ExitStack() as scope:
            seen, verify_inventory = scope.enter_context(_hold_retained_inventory(token, binding))
            if 'completion' not in seen.families:
                raise RetainedInventoryHold()
            action = local._json(seen.unit.action_preimage)
            generation_id = action['identity']['generation_id']
            match = local._GEN.fullmatch(generation_id) if type(generation_id) is str else None
            if match is None:
                raise RetainedInventoryHold()
            sequence = int(match.group(1))
            if sequence < 1:
                raise RetainedInventoryHold()
            # A name/digest-derived handle is not certification. The held C6
            # reader below replays actual STATE/MANIFEST/INTENT/RECEIPT/XLSX
            # and both recorded APPLIED pairs before any keys are yielded.
            generation = local.Generation(generation_id, sequence, action['manifest_id'], writer_token)
            from monitor import issue_tracker_remote_history_match as remote
            held_owner, verify_inputs, body, keys = scope.enter_context(
                remote._hold_original_applied_key_watermark_inputs(writer_token, token, binding, seen.unit, generation))
            if held_owner is not owner:
                raise RetainedInventoryHold()
            names = ('REMOTE-KEY-HIGH-WATER-STARTED-' + seen.unit.unit_id,
                     'REMOTE-KEY-HIGH-WATER-' + seen.unit.unit_id)
            verify_keys = scope.enter_context(remote._hold_applied_records(owner.root_fd, names, body,
                states=('KEY-HIGH-WATER-STARTED', 'KEY-HIGH-WATER')))
            def verify():
                if local._owner(writer_token) is not owner:
                    raise RetainedInventoryHold()
                verify_inventory(); verify_inputs(); verify_keys()
            verify()
            yield keys, verify
            verify()
    except Exception:
        failed = True
    if failed:
        raise RetainedInventoryHold()
