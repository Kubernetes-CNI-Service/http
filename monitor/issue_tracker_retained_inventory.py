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
_FIXED = {
    'enrollment': frozenset(('HEADER', 'INITIALIZED', 'NONCES')),
    'history': frozenset(('HEADER', 'HISTORY-RAW', 'INITIALIZED')),
    'business': frozenset(('BUSINESS-RAW', 'HEADER', 'INITIALIZED', 'MANIFEST')),
    'metadata': frozenset(('HEADER', 'INITIALIZED', 'METADATA-RAW', 'RESERVATION')),
    'nv': frozenset(('ETH-RAW', 'HEADER', 'IB-RAW', 'INITIALIZED', 'RESERVATIONS')),
    'completion': frozenset(('COMPLETE', 'HEADER', 'HEADERS-RAW', 'HISTORY-RAW', 'IDENTITY-RAW', 'METADATA-RAW')),
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
                        or any(family not in _FAMILIES or family == 'enrollment' for _name, family in entries)):
                    raise RetainedInventoryHold()
                namespace.extend(entries)
                per_unit.append((unit, state, prefix, tuple(sorted(entries + ([(shared, 'enrollment')] if shared in names else [])))))
            namespace = tuple(sorted(namespace)); total = 0
            for name, family in namespace:
                if family.endswith('-started'):
                    entries = ((parent, name, name, 16384),)
                else:
                    folder = local._directory(parent, name)
                    directories.append((name, folder, journal._identity(os.fstat(folder)), None))
                    journal._named(parent, name, folder, directory=True)
                    identity = journal._identity(os.fstat(folder))
                    child_names = _family_entries(family, tuple(os.listdir(folder)))
                    directories[-1] = (name, folder, identity, child_names)
                    entries = tuple((folder, child, name + '/' + child, _limit(family, child)) for child in child_names)
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
                verify_counts()
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
                verify_counts()

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
