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


def _verify_legacy_read_semantics(stem, namespace, files, directories, unit, binding, parent):
    """Replay existing read contracts while all inventory originals stay held.

    Coherent marker/digest links do not bind a foreign nonce or History unit.
    These are local original observations, not remote freshness or admission.
    """
    images = {relative: raw for _directory, _entry, relative, _fd, _identity, raw in files}
    folders = {name: folder for name, folder, _identity, _names in directories}
    action = local._json(unit.action_preimage)
    names = {name for name, _family in namespace}
    enrollment_name = stem + '.enrollment'
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


def _verify_legacy_business_links(stem, namespace, files, unit):
    """Necessary original envelope/NOOP coverage, not full cell replay.

    Do not fabricate a remote identity observation from enrolled ids to invoke
    a typed decoder. Full business semantic/source validation is still required
    before this inventory can participate in any admission or APPLIED proof.
    """
    name = stem + '.business'
    names = {entry for entry, _family in namespace}
    if name not in names:
        return
    if not {stem + '.enrollment', stem + '.history'} <= names:
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


def _verify_legacy_completion(stem, namespace, token, binding, unit, state):
    """Replay the existing retained proof, never trust COMPLETE file shape.

    The remote-history reader reopens and holds original start/header/raw images,
    derives fixed read geometries and replays nonce/fence/all-History semantics.
    No caller identity, MATCHED boolean, read receipt or APPLIED claim is issued.
    The inventory's wider original pins remain held across all those barriers.
    """
    names = {name for name, _family in namespace}
    if stem + '.completion' not in names:
        return
    if not {stem + '.enrollment', stem + '.history'} <= names:
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
