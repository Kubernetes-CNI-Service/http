"""Uninstalled append-only pending ORIGINALS, not admission or send authority.

The real spreadsheet owner alone selects the fixed namespace. This catalog
does not replace legacy evidence, count attempts, prove original C6/APPLIED,
release FIFO or grant NEW. Every indexed pending image remains immutable;
missing, extra or interrupted images are HOLD, never adoption or repair.
"""
from contextlib import contextmanager, ExitStack
import hashlib
import os
import re

from monitor import issue_tracker_spreadsheet_owner as ownership
from monitor import issue_tracker_local_commit as local
from monitor import issue_tracker_attempt_journal as journal
from monitor import issue_tracker_send_intent as compiled
from monitor import issue_tracker_send_unit as composer

_MAX_UNITS = 64
_MAX_IMAGES = 16 * 1024 * 1024
_FILES = frozenset(('HEADER', 'ACTION-PREIMAGE', 'WIRE', 'INITIALIZED'))


class UnitCatalogHold(ValueError):
    def __init__(self):
        super().__init__('req7_pending_original_catalog_unproved')


def _inputs(token, binding):
    owner = ownership._validated_owner(token, binding)
    parent = owner.directories[-1][0]
    stem = owner.lock_name[:-5]
    base = {'schema_version': 1, 'spreadsheet_id': binding.spreadsheet_id,
            'state': 'PENDING_ORIGINALS_NOT_AUTHORITY'}
    return owner, parent, stem + '.units', stem + '.units-started', base


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _close_original(fd, identity):
    # Never close a recycled integer naming another object. This is cleanup,
    # not a certificate of identical open-file description after fd reuse.
    try:
        if journal._identity(os.fstat(fd))[:2] == identity[:2]:
            os.close(fd)
    except OSError:
        pass


class _Originals:
    def __init__(self):
        self.files = []
        self.directories = []
        self.bytes = 0
        self.namespace = None

    def directory(self, parent, name):
        fd = local._directory(parent, name)
        identity = journal._identity(os.fstat(fd))
        self.directories.append((parent, name, fd, identity, tuple(sorted(os.listdir(fd)))))
        journal._named(parent, name, fd, directory=True)
        return fd

    def file(self, parent, name, limit):
        fd = os.open(name, local._flags(), dir_fd=parent)
        identity = journal._identity(os.fstat(fd))
        self.files.append((parent, name, fd, identity, None))
        journal._named(parent, name, fd, directory=False)
        raw = os.pread(fd, limit + 1, 0)
        self.bytes += len(raw)
        if (not 1 <= len(raw) <= limit or len(raw) != identity[6]
                or self.bytes > _MAX_IMAGES):
            raise UnitCatalogHold()
        self.files[-1] = (parent, name, fd, identity, raw)
        return raw, identity

    def verify(self, *, appended_to=None, parent_additions=frozenset()):
        if self.namespace is not None:
            parent, prefix, before = self.namespace
            actual = {item for item in os.listdir(parent) if item.startswith(prefix)}
            if actual != before | parent_additions:
                raise UnitCatalogHold()
        for parent, name, fd, identity, names in self.directories:
            journal._named(parent, name, fd, directory=True)
            current = journal._identity(os.fstat(fd))
            if appended_to is not None and fd == appended_to[0]:
                # Only the writer's catalog gains names. All original child
                # images and directories still require full original stat.
                # APFS st_nlink, size and timestamps change for our two exact
                # new names. Identity/type/owner/mode and EVERY old file stay
                # fixed; any third name, removal or replacement still fails.
                if current[:5] != identity[:5] or set(os.listdir(fd)) != set(names) | appended_to[1]:
                    raise UnitCatalogHold()
            elif current != identity or tuple(sorted(os.listdir(fd))) != names:
                raise UnitCatalogHold()
        for parent, name, fd, identity, raw in self.files:
            journal._named(parent, name, fd, directory=False)
            if (raw is None or journal._identity(os.fstat(fd)) != identity
                    or os.pread(fd, len(raw) + 1, 0) != raw):
                raise UnitCatalogHold()

    def sync(self):
        self.verify()
        for _parent, _name, fd, _identity, _raw in self.files:
            os.fsync(fd)
        for _parent, _name, fd, _identity, _names in reversed(self.directories):
            os.fsync(fd)
        self.verify()

    def close(self):
        for _parent, _name, fd, identity, _raw in reversed(self.files):
            _close_original(fd, identity)
        for _parent, _name, fd, identity, _names in reversed(self.directories):
            _close_original(fd, identity)


def _header(unit):
    return {**compiled._projection(unit), 'state': 'PENDING_NOT_ATTEMPTED'}


def _inspect(token, binding, held):
    owner, parent, name, started, base = _inputs(token, binding)
    prefix = owner.lock_name[:-5] + '.'
    root_names = {item for item in os.listdir(parent) if item.startswith(prefix)}
    if len(root_names) > 256:
        raise UnitCatalogHold()
    held.namespace = (parent, prefix, root_names)
    if held.file(parent, started, 16384)[0] != local._canonical(base):
        raise UnitCatalogHold()
    catalog = held.directory(parent, name)
    header_raw, header_identity = held.file(catalog, 'HEADER', 16384)
    initialized = held.file(catalog, 'INITIALIZED', 16384)[0]
    if (header_raw != local._canonical(base) or initialized != local._canonical({
            'schema_version': 1, 'header_sha256': _digest(header_raw),
            'header_identity': list(header_identity),
            'directory_identity': list(journal._identity(os.fstat(catalog))[:2])})):
        raise UnitCatalogHold()
    names = set(os.listdir(catalog))
    count = (len(names) - 2) // 2
    if not 1 <= count <= _MAX_UNITS:
        raise UnitCatalogHold()
    positions = ['ENTRY-%020d' % index for index in range(1, count + 1)]
    witness_prefix = name + '-position-'
    witnesses = {witness_prefix + '%020d' % index for index in range(1, count + 1)}
    if {item for item in root_names if item.startswith(witness_prefix)} != witnesses:
        raise UnitCatalogHold()
    units = []
    previous = _digest(header_raw)
    unit_ids = set()
    for index, position in enumerate(positions, 1):
        raw, _identity = held.file(catalog, position, 16384)
        entry = local._json(raw, {'schema_version', 'index', 'unit_id',
                                 'initialized_sha256', 'initialized_identity', 'previous_sha256',
                                 'position_sha256', 'position_identity'})
        unit_id = entry['unit_id']
        if (type(unit_id) is not str or re.fullmatch(r'[0-9a-f]{64}', unit_id) is None
                or unit_id in unit_ids or type(entry['index']) is not int
                or entry['index'] != index or entry['schema_version'] != 1
                or entry['previous_sha256'] != previous):
            raise UnitCatalogHold()
        unit_ids.add(unit_id)
        position_raw, position_identity = held.file(parent, witness_prefix + '%020d' % index, 16384)
        if (position_raw != local._canonical({'schema_version': 1, 'index': index,
                'unit_id': unit_id, 'previous_sha256': previous, 'state': 'PENDING_POSITION_NOT_AUTHORITY'})
                or entry['position_sha256'] != _digest(position_raw)
                or entry['position_identity'] != list(position_identity)):
            raise UnitCatalogHold()
        folder = held.directory(catalog, unit_id)
        if set(os.listdir(folder)) != _FILES:
            raise UnitCatalogHold()
        originals = {item: held.file(folder, item, 1024 * 1024) for item in sorted(_FILES)}
        unit = composer._original_unit(originals['ACTION-PREIMAGE'][0], originals['WIRE'][0])
        if (unit.unit_id != unit_id or originals['HEADER'][0] != local._canonical(_header(unit))
                or local._json(unit.action_preimage)['identity']['spreadsheet_id'] != binding.spreadsheet_id):
            raise UnitCatalogHold()
        marker_raw, marker_identity = originals['INITIALIZED']
        expected = {'schema_version': 1, 'state': 'PENDING_ORIGINALS',
                    'directory_identity': list(journal._identity(os.fstat(folder))[:2]),
                    'originals': {item: {'identity': list(originals[item][1]),
                                        'sha256': _digest(originals[item][0])}
                                  for item in sorted(_FILES - {'INITIALIZED'})}}
        if (marker_raw != local._canonical(expected) or entry['initialized_sha256'] != _digest(marker_raw)
                or entry['initialized_identity'] != list(marker_identity)):
            raise UnitCatalogHold()
        # Canonical JSON alone is not strict scalar identity: Python dict
        # equality treats True==1 and an integral float==int. Compare the exact
        # native canonical record, not a coercively equal decoded mapping.
        if raw != local._canonical({'schema_version': 1, 'index': index, 'unit_id': unit_id,
                'initialized_sha256': _digest(marker_raw), 'initialized_identity': list(marker_identity),
                'previous_sha256': previous, 'position_sha256': _digest(position_raw),
                'position_identity': list(position_identity)}):
            raise UnitCatalogHold()
        units.append(unit)
        previous = _digest(raw)
    if names != {'HEADER', 'INITIALIZED', *positions, *unit_ids}:
        raise UnitCatalogHold()
    held.verify()
    if ownership._validated_owner(token, binding) is not owner:
        raise UnitCatalogHold()
    return catalog, tuple(units), previous


@contextmanager
def hold_pending_units(token, binding):
    """All pending originals remain pinned through consumer and context exit."""
    held = _Originals()
    failed = False
    try:
        owner = _inputs(token, binding)[0]
        _catalog, units, _previous = _inspect(token, binding, held)
        held.sync()
        def verify():
            if ownership._validated_owner(token, binding) is not owner:
                raise UnitCatalogHold()
            held.verify()
        verify()
        yield units, verify
        verify()
    except Exception:
        failed = True
    finally:
        held.close()
    if failed:
        raise UnitCatalogHold() from None


@contextmanager
def hold_pending_c6_units(writer_token, token, binding):
    """Join every pending original to real receipts in THIS writer's project.

    Unit/generation/project/key overrides are not accepted. Derivation from
    an action is only a historical read selector: the actual original C6
    reader verifies STATE/MANIFEST/INTENT/RECEIPT/published XLSX, with recovery
    barriers and operation/key correspondence. No generation is added to the
    writer's issued handles. This is not a cross-project inventory, current
    qualified source, COMPLETE/APPLIED, a global maximum or NEW authority.
    Foreign-project or any unresolved unit makes the whole handoff HOLD; never
    yield just the apparently valid prefix or silently reconstruct its source.
    """
    failed = False
    try:
        owner = local._owner(writer_token)
        from monitor import issue_tracker_remote_history_match as remote
        with ExitStack() as scope:
            units, verify_catalog = scope.enter_context(hold_pending_units(token, binding))
            validators = []
            for unit in units:
                action = local._json(unit.action_preimage)
                generation_id = action['identity']['generation_id']
                matched = local._GEN.fullmatch(generation_id) if type(generation_id) is str else None
                if matched is None or int(matched.group(1)) < 1:
                    raise UnitCatalogHold()
                generation = local.Generation(generation_id, int(matched.group(1)), action['manifest_id'], writer_token)
                held_owner, verify_c6, _facts, _operations = scope.enter_context(
                    remote._hold_applied_generation(writer_token, generation, unit))
                if held_owner is not owner:
                    raise UnitCatalogHold()
                validators.append(verify_c6)
            def verify():
                if local._owner(writer_token) is not owner:
                    raise UnitCatalogHold()
                verify_catalog()
                for validate in validators:
                    validate()
                verify_catalog()
            verify()
            yield units, verify
            verify()
    except Exception:
        failed = True
    if failed:
        raise UnitCatalogHold() from None


def register_pending_unit(token, binding, unit):
    """Append one coherent pending image; never repair or issue a capability."""
    held = _Originals()
    catalog = folder = None
    catalog_identity = folder_identity = None
    failed = False
    try:
        owner, parent, name, started, base = _inputs(token, binding)
        header_raw = local._canonical(_header(unit))
        if local._json(unit.action_preimage)['identity']['spreadsheet_id'] != binding.spreadsheet_id:
            raise UnitCatalogHold()
        names = set(os.listdir(parent))
        if name in names or started in names or any(item.startswith(name + '-position-') for item in names):
            catalog, units, previous = _inspect(token, binding, held)
            held.sync()
            if len(units) >= _MAX_UNITS or any(value.unit_id == unit.unit_id for value in units):
                raise UnitCatalogHold()
            index = len(units) + 1
        else:
            # A surviving per-unit family is evidence of a LOST catalog, not
            # first use. Never overwrite/reindex or evade its original UNKNOWN
            # by creating a new catalog after all catalog witnesses disappear.
            # Legacy pending witnesses still remain untouched by this purely
            # diagnostic catalog; GLOBAL refuses any mixed legacy inventory.
            if any(item.startswith(owner.lock_name[:-5] + '.unit-') for item in names):
                raise UnitCatalogHold()
            local._write_new(parent, started, local._canonical(base))
            catalog = local._mkdir(parent, name)
            catalog_identity = journal._identity(os.fstat(catalog))
            local._write_new(catalog, 'HEADER', local._canonical(base))
            raw, identity = local._read(catalog, 'HEADER', 16384)
            local._write_new(catalog, 'INITIALIZED', local._canonical({
                'schema_version': 1, 'header_sha256': _digest(raw),
                'header_identity': list(journal._identity(identity)),
                'directory_identity': list(catalog_identity[:2])}))
            index, previous = 1, _digest(raw)
        # Fixed no-replace dir/file creation. On ANY interruption leave every
        # original and partial name in place; subsequent inspection refuses it.
        if held.bytes + len(header_raw) + len(unit.wire_bytes) + len(unit.action_preimage) + 32768 > _MAX_IMAGES:
            raise UnitCatalogHold()
        held.verify()
        if ownership._validated_owner(token, binding) is not owner:
            raise UnitCatalogHold()
        position_name = name + '-position-%020d' % index
        # Immutable write-ahead position survives a lost whole tail subtree.
        # It is not an attempt, send, first-use or NEW high-water certificate.
        local._write_new(parent, position_name, local._canonical({'schema_version': 1,
            'index': index, 'unit_id': unit.unit_id, 'previous_sha256': previous,
            'state': 'PENDING_POSITION_NOT_AUTHORITY'}))
        position_raw, position_info = local._read(parent, position_name, 16384)
        folder = local._mkdir(catalog, unit.unit_id)
        folder_identity = journal._identity(os.fstat(folder))
        local._write_new(folder, 'HEADER', header_raw)
        local._write_new(folder, 'ACTION-PREIMAGE', unit.action_preimage)
        local._write_new(folder, 'WIRE', unit.wire_bytes)
        originals = {item: local._read(folder, item, 1024 * 1024)
                     for item in sorted(_FILES - {'INITIALIZED'})}
        marker = local._canonical({'schema_version': 1, 'state': 'PENDING_ORIGINALS',
            'directory_identity': list(folder_identity[:2]),
            'originals': {item: {'identity': list(journal._identity(originals[item][1])),
                                'sha256': _digest(originals[item][0])} for item in originals}})
        local._write_new(folder, 'INITIALIZED', marker)
        marker_raw, marker_info = local._read(folder, 'INITIALIZED', 16384)
        local._write_new(catalog, 'ENTRY-%020d' % index, local._canonical({
            'schema_version': 1, 'index': index, 'unit_id': unit.unit_id,
            'initialized_sha256': _digest(marker_raw),
            'initialized_identity': list(journal._identity(marker_info)), 'previous_sha256': previous,
            'position_sha256': _digest(position_raw), 'position_identity': list(journal._identity(position_info))}))
        additions = (catalog, {unit.unit_id, 'ENTRY-%020d' % index})
        held.verify(appended_to=additions, parent_additions={position_name})
        # Original consumer checks, and all durability barriers, also dominate
        # acknowledgement. A read-back alone cannot bless a partial write.
        with hold_pending_units(token, binding) as (recovered, verify):
            if recovered[-1] != unit:
                raise UnitCatalogHold()
            verify()
        held.verify(appended_to=additions, parent_additions={position_name})
        if ownership._validated_owner(token, binding) is not owner:
            raise UnitCatalogHold()
    except Exception:
        failed = True
    finally:
        if folder is not None:
            _close_original(folder, folder_identity)
        if catalog_identity is not None:
            _close_original(catalog, catalog_identity)
        held.close()
    if failed:
        raise UnitCatalogHold() from None
