"""Uninstalled append-only pending ORIGINALS, not admission or send authority.

The real spreadsheet owner alone selects the fixed namespace. This catalog
does not replace legacy evidence, count attempts, prove original C6/APPLIED,
release FIFO or grant NEW. Every indexed pending image remains immutable;
missing, extra or interrupted images are HOLD, never adoption or repair.
"""
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass, field
import hashlib
import os
import re
from pathlib import Path

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


@dataclass(frozen=True)
class CatalogProjectOrigin:
    """Original locator only: no current source, foreign owner or send permit."""
    unit: object = field(repr=False)
    project_path: str
    publication_path: str
    project_identity: tuple
    tracker_identity: tuple
    publication_identity: tuple
    lock_identity: tuple
    c6_facts: bytes = field(repr=False)


@dataclass(frozen=True)
class CatalogProjectC6:
    """Borrowed ALL-project C6 observation, no mutation handle or send permit."""
    unit: object = field(repr=False)
    project_identity: tuple
    c6_facts: bytes = field(repr=False)


def _project_origin_body(owner, binding, unit, facts):
    return {'schema_version': 1, 'unit_id': unit.unit_id,
        'spreadsheet_id': binding.spreadsheet_id, 'allowlist_sha256': binding.allowlist_sha256,
        'policy_sha256': binding.policy_sha256, 'wire_sha256': unit.wire_sha256,
        'action_digest': unit.action_digest, 'project_path': str(owner.project),
        'publication_path': str(owner.publication),
        'project_identity': list(journal._identity(os.fstat(owner.project_fd))[:2]),
        'tracker_identity': list(journal._identity(os.fstat(owner.root_fd))[:2]),
        'publication_identity': list(journal._identity(os.fstat(owner.publication_fd))[:2]),
        'lock_identity': [owner.lock_dev, owner.lock_ino],
        'c6_facts': facts}


def register_pending_c6_unit(writer_token, token, binding, unit, *, _nv_preparation=None, _unit_preparation=None):
    """Register actual C6 plus immutable original project locator, never repair.

    Project/publication paths come only from the live opaque writer, not the
    unit label or caller path vector. A interrupted catalog append or origin
    write stays HOLD. Receipt-absent C6 creates neither catalog nor origin.
    No GLOBAL attempt, APPLIED, cross-project high-water or NEW is issued.
    """
    if _unit_preparation is not None:
        from monitor import issue_tracker_nv_reservation as native
        if _nv_preparation is not None or type(_unit_preparation) is not native._CatalogNonallocatingPreparation:
            raise UnitCatalogHold()
        record = native._verify_catalog_preparation(_unit_preparation)
        if record['nonallocating_writer'] is not writer_token: raise UnitCatalogHold()
        return _register_native_pending_c6_unit(writer_token, token, binding, unit, _unit_preparation)
    if _nv_preparation is not None:
        from monitor import issue_tracker_nv_reservation as native
        if type(_nv_preparation) is not native._CatalogNvPreparation: raise UnitCatalogHold()
        return _register_native_pending_c6_unit(writer_token, token, binding, unit, _nv_preparation)
    held = _originals(token, binding); failed = False; folder = None; folder_identity = None
    try:
        owner = local._owner(writer_token)
        compiled._projection(unit)
        action = local._json(unit.action_preimage)
        match = local._GEN.fullmatch(action['identity']['generation_id'])
        if match is None or int(match.group(1)) < 1:
            raise UnitCatalogHold()
        generation = local.Generation(match.group(0), int(match.group(1)), action['manifest_id'], writer_token)
        from monitor import issue_tracker_remote_history_match as remote
        with ExitStack() as scope:
            original_owner, verify_c6, facts, _operations = scope.enter_context(remote._hold_applied_generation(writer_token, generation, unit))
            if original_owner is not owner:
                raise UnitCatalogHold()
            verify_c6()
            sheet_owner, parent, _name, _started, _base = _inputs(token, binding)
            from monitor import issue_tracker_global_attempt_journal as globals_
            name = sheet_owner.lock_name[:-5] + '.unit-' + unit.unit_id + '.project-origin'
            if name in os.listdir(parent):
                raise UnitCatalogHold()
            if globals_._catalog_present(sheet_owner):
                # Known older loss/partial origin must stop before appending
                # a new position or witness; registration is not a repair.
                with hold_pending_project_origins(token, binding) as (_older, verify_older):
                    verify_older()
            register_pending_unit(token, binding, unit)
            # Establish our exact exclusive first-use name before freezing
            # the catalog reader's namespace. Never refresh an old reader or
            # adopt a pre-existing empty/partial origin directory.
            folder = globals_._create_folder(parent, name)
            folder_identity = journal._identity(os.fstat(folder))
            units, verify_catalog = scope.enter_context(hold_pending_units(token, binding))
            if not units or units[-1] != unit:
                raise UnitCatalogHold()
            if os.listdir(folder):
                raise UnitCatalogHold()
            body = _project_origin_body(owner, binding, unit, facts)
            witness_raw = local._canonical({'schema_version': 1, 'unit_id': unit.unit_id,
                'state': 'PROJECT-ORIGIN-WRITE-STARTED-NOT-AUTHORITY', 'body_sha256': _digest(local._canonical(body))})
            written = remote._write_completion_start(folder, 'WITNESS', witness_raw)
            raw, original = held.file(folder, 'WITNESS', 16384)
            if raw != witness_raw or original != written:
                raise UnitCatalogHold()
            body = {**body, 'write_witness': {'identity': list(original), 'sha256': _digest(raw)}}
            def verify():
                if local._owner(writer_token) is not owner or ownership._validated_owner(token, binding) is not sheet_owner:
                    raise UnitCatalogHold()
                journal._named(parent, name, folder, directory=True)
                verify_c6(); verify_catalog(); held.verify()
            scope.enter_context(remote._write_applied_pair(folder, ('STARTED', 'ORIGIN'), body, verify,
                states=('PROJECT-ORIGIN-STARTED', 'PROJECT-ORIGIN-NOT-AUTHORITY')))
            verify()
            # A complete all-unit reader must succeed before acknowledging
            # this append. Missing older origins never yield a valid prefix.
            with hold_pending_project_origins(token, binding) as (origins, verify_origins):
                if origins[-1].unit != unit:
                    raise UnitCatalogHold()
                verify_origins()
            verify()
    except Exception:
        failed = True
    finally:
        held.close()
        if folder is not None and folder_identity is not None:
            _close_original(folder, folder_identity)
    if failed:
        raise UnitCatalogHold() from None


def _register_native_pending_c6_unit(writer_token, token, binding, unit, prepared):
    """Actual C6 origin first, then one append anchored to those originals.

    The default/legacy writer above stays unchanged. A partial/unindexed origin
    is retained HOLD, not a cold-reader exception, repair or send authority.
    """
    from monitor import issue_tracker_nv_reservation as nv
    from monitor import issue_tracker_remote_history_match as remote
    from monitor import issue_tracker_global_attempt_journal as globals_
    failed = False; folder = None; identity = None
    try:
        owner = local._owner(writer_token); compiled._projection(unit)
        action = local._json(unit.action_preimage)
        match = local._GEN.fullmatch(action['identity']['generation_id'])
        if match is None or int(match.group(1)) < 1: raise UnitCatalogHold()
        generation = local.Generation(match.group(0), int(match.group(1)), action['manifest_id'], writer_token)
        with ExitStack() as scope:
            original_owner, verify_c6, facts, _operations = scope.enter_context(
                remote._hold_applied_generation(writer_token, generation, unit))
            if original_owner is not owner: raise UnitCatalogHold()
            verify_c6()
            sheet_owner, parent, _name, _started, _base = _inputs(token, binding)
            name = sheet_owner.lock_name[:-5] + '.unit-' + unit.unit_id + '.project-origin'
            if name in os.listdir(parent): raise UnitCatalogHold()
            # This live preparation already pinned the genuine pre-append
            # prefix. Its own new NV family is not an older catalog unit.
            if nv._verify_catalog_preparation(prepared)['units']:
                with hold_pending_project_origins(token, binding) as (_older, verify_older): verify_older()
            nv._catalog_nv_c6_origin_begin(prepared, writer_token, token, binding, unit)
            folder, identity = globals_._create_folder(parent, name, _return_original=True)
            if journal._identity(os.fstat(folder)) != identity: raise UnitCatalogHold()
            held = nv._catalog_nv_c6_origin_created(prepared, writer_token, token, binding, unit, folder)
            def verify():
                if local._owner(writer_token) is not owner or ownership._validated_owner(token, binding) is not sheet_owner:
                    raise UnitCatalogHold()
                verify_c6(); nv._verify_catalog_preparation(prepared)
            verify()
            body = _project_origin_body(owner, binding, unit, facts)
            witness = local._canonical({'schema_version': 1, 'unit_id': unit.unit_id,
                'state': 'PROJECT-ORIGIN-WRITE-STARTED-NOT-AUTHORITY', 'body_sha256': _digest(local._canonical(body))})
            written = remote._write_completion_start(folder, 'WITNESS', witness)
            raw, original = held.file(folder, 'WITNESS', 16384)
            if raw != witness or original != written: raise UnitCatalogHold()
            body = {**body, 'write_witness': {'identity': list(original), 'sha256': _digest(raw)}}
            # Reader capture overlaps both real creator FDs; never adopt after
            # the pair writer closes, and finalizers must succeed before append.
            with remote._write_applied_pair(folder, ('STARTED', 'ORIGIN'), body, verify,
                    states=('PROJECT-ORIGIN-STARTED', 'PROJECT-ORIGIN-NOT-AUTHORITY')) as verify_pair:
                verify_pair()
                for entry in ('STARTED', 'ORIGIN'): held.file(folder, entry, local._MAX_MANIFEST)
                with remote._hold_applied_records(folder, ('STARTED', 'ORIGIN'), body,
                        states=('PROJECT-ORIGIN-STARTED', 'PROJECT-ORIGIN-NOT-AUTHORITY')) as verify_records:
                    verify_records(); verify_pair(); held.verify()
                    nv._catalog_nv_c6_origin_seal(prepared, token, binding, unit)
                    verify(); verify_pair(); verify_records()
            verify()
            from monitor import issue_tracker_settings_audit_allocation as settings_allocation
            settings_allocation._prepare_native_catalog_allocation(prepared,writer_token,token,binding,unit)
            register_pending_unit(token, binding, unit, _nv_preparation=prepared)
            with hold_pending_project_c6_units(token, binding) as (rows, verify_projects):
                if not rows or rows[-1].unit != unit: raise UnitCatalogHold()
                verify_projects(); verify()
            verify()
        # Genuine C6 / writer / pair scope finalizers have all succeeded.
        nv._catalog_nv_c6_origin_registered(prepared, writer_token, token, binding, unit)
    except Exception:
        failed = True
        nv._catalog_nv_c6_origin_failed(prepared)
    finally:
        if (folder is not None and identity is not None
                and not nv._catalog_nv_c6_origin_owns_folder(prepared, folder)): _close_original(folder, identity)
    if failed: raise UnitCatalogHold() from None


@contextmanager
def hold_pending_project_origins(token, binding):
    """ALL immutable origin images stay held, not genuine foreign C6 replay.

    Stored paths are historical selectors, not trusted acquisition arguments
    or permission to read a foreign project. The future cross-project C6 join
    must acquire and verify each original project and publication identity;
    this reader alone neither opens those paths nor compares local sequences.
    """
    held = _originals(token, binding); failed = False
    try:
        from monitor import issue_tracker_remote_history_match as remote
        with ExitStack() as scope:
            units, verify_catalog = scope.enter_context(hold_pending_units(token, binding))
            owner, parent, _name, _started, _base = _inputs(token, binding)
            prefix = owner.lock_name[:-5] + '.unit-'
            wanted = {prefix + unit.unit_id + '.project-origin' for unit in units}
            if {name for name in os.listdir(parent) if name.startswith(prefix) and name.endswith('.project-origin')} != wanted:
                raise UnitCatalogHold()
            validators = []; results = []
            for unit in units:
                folder = held.directory(parent, prefix + unit.unit_id + '.project-origin')
                if set(os.listdir(folder)) != {'STARTED', 'ORIGIN', 'WITNESS'}:
                    raise UnitCatalogHold()
                images = {name: held.file(folder, name, local._MAX_MANIFEST) for name in ('STARTED', 'ORIGIN', 'WITNESS')}
                saved = local._json(images['ORIGIN'][0])
                body = {key: value for key, value in saved.items() if key not in ('record_identities', 'state')}
                if set(body) != {'schema_version', 'unit_id', 'spreadsheet_id', 'allowlist_sha256', 'policy_sha256',
                    'wire_sha256', 'action_digest', 'project_path', 'publication_path', 'project_identity',
                    'tracker_identity', 'publication_identity', 'lock_identity', 'c6_facts', 'write_witness'}:
                    raise UnitCatalogHold()
                action = local._json(unit.action_preimage); facts = body['c6_facts']
                if (type(body['schema_version']) is not int or body['schema_version'] != 1
                        or body['unit_id'] != unit.unit_id or body['spreadsheet_id'] != binding.spreadsheet_id
                        or body['allowlist_sha256'] != binding.allowlist_sha256 or body['policy_sha256'] != binding.policy_sha256
                        or body['wire_sha256'] != unit.wire_sha256 or body['action_digest'] != unit.action_digest
                        or type(facts) is not dict or facts.get('generation_id') != action['identity']['generation_id']
                        or facts.get('manifest_id') != action['manifest_id'] or facts.get('published_sha256') != action['identity']['publish_id']):
                    raise UnitCatalogHold()
                for key in ('project_path', 'publication_path'):
                    value = body[key]
                    if type(value) is not str or not Path(value).is_absolute() or str(Path(value)) != value or '..' in Path(value).parts:
                        raise UnitCatalogHold()
                if Path(body['publication_path']).parent != Path(body['project_path']):
                    raise UnitCatalogHold()
                for key in ('project_identity', 'tracker_identity', 'publication_identity', 'lock_identity'):
                    if type(body[key]) is not list or len(body[key]) != 2 or any(type(value) is not int or value < 1 for value in body[key]):
                        raise UnitCatalogHold()
                pre_witness = {key: value for key, value in body.items() if key != 'write_witness'}
                witness = local._canonical({'schema_version': 1, 'unit_id': unit.unit_id,
                    'state': 'PROJECT-ORIGIN-WRITE-STARTED-NOT-AUTHORITY', 'body_sha256': _digest(local._canonical(pre_witness))})
                if images['WITNESS'][0] != witness or body['write_witness'] != {'identity': list(images['WITNESS'][1]), 'sha256': _digest(witness)}:
                    raise UnitCatalogHold()
                validators.append(scope.enter_context(remote._hold_applied_records(folder, ('STARTED', 'ORIGIN'), body,
                    states=('PROJECT-ORIGIN-STARTED', 'PROJECT-ORIGIN-NOT-AUTHORITY'))))
                results.append(CatalogProjectOrigin(unit, body['project_path'], body['publication_path'],
                    tuple(body['project_identity']), tuple(body['tracker_identity']), tuple(body['publication_identity']),
                    tuple(body['lock_identity']), local._canonical(facts)))
            def verify():
                if ownership._validated_owner(token, binding) is not owner:
                    raise UnitCatalogHold()
                verify_catalog(); held.verify()
                for validator in validators:
                    validator()
                verify_catalog(); held.verify()
            verify(); held.sync()
            yield tuple(results), verify
            verify()
    except Exception:
        failed = True
    finally:
        held.close()
    if failed:
        raise UnitCatalogHold() from None


@contextmanager
def _hold_project_c6_from_origins(token, binding, origins, *, _owner_tail=None):
    """Internal join while the caller keeps the original origin images held.

    Separating project originals from catalog namespace checks lets the actual
    native writer append its own exact names without reopening or dropping
    old project locks/C6 files. Rows are locators, never acquisition or send
    authority; every original owner and registered C6 image is replayed here.
    """
    failed = False
    try:
        if _owner_tail is not None and type(_owner_tail) is not ExitStack:
            raise UnitCatalogHold()
        sheet_owner = ownership._validated_owner(token, binding)
        from monitor import issue_tracker_remote_history_match as remote
        with ExitStack() as scope:
            acquired = {}; checks = []; observed = []
            for origin in origins:
                key = (origin.project_path, origin.publication_path)
                if key not in acquired:
                    matches = [writer for writer, owner in tuple(local._ACTIVE.items())
                        if owner.pid == os.getpid() and str(owner.project) == key[0] and str(owner.publication) == key[1]]
                    if len(matches) > 1:
                        raise UnitCatalogHold()
                    # Only newly acquired original owners may outlive semantic
                    # C6 readers. NV's raw finalizer needs their real exclusion
                    # until its last check; no token or generation is reissued.
                    owner_scope = scope if _owner_tail is None else _owner_tail
                    writer = matches[0] if matches else owner_scope.enter_context(local._try_original_writer_owner(*key,
                        (origin.project_identity, origin.tracker_identity, origin.publication_identity, origin.lock_identity)))
                    acquired[key] = (writer, local._owner(writer))
                writer, project_owner = acquired[key]
                def verify_owner(origin=origin, writer=writer, project_owner=project_owner):
                    if local._owner(writer) is not project_owner:
                        raise UnitCatalogHold()
                    if tuple(journal._identity(os.fstat(fd))[:2] for fd in
                        (project_owner.project_fd, project_owner.root_fd, project_owner.publication_fd)) != (
                            origin.project_identity, origin.tracker_identity, origin.publication_identity):
                        raise UnitCatalogHold()
                    if (project_owner.lock_dev, project_owner.lock_ino) != origin.lock_identity:
                        raise UnitCatalogHold()
                verify_owner()
                facts = local._json(origin.c6_facts)
                generation = local.Generation(facts['generation_id'], facts['sequence'], facts['manifest_id'], writer)
                actual_owner, verify_c6, actual_facts, _operations = scope.enter_context(
                    remote._hold_applied_generation(writer, generation, origin.unit))
                if actual_owner is not project_owner or local._canonical(actual_facts) != origin.c6_facts:
                    raise UnitCatalogHold()
                checks.extend((verify_owner, verify_c6))
                observed.append(CatalogProjectC6(origin.unit, origin.project_identity, origin.c6_facts))
            def verify():
                if ownership._validated_owner(token, binding) is not sheet_owner:
                    raise UnitCatalogHold()
                for check in checks:
                    check()
            verify()
            yield tuple(observed), verify
            verify()
    except Exception:
        failed = True
    if failed:
        raise UnitCatalogHold() from None


@contextmanager
def hold_pending_project_c6_units(token, binding):
    """Join ALL historical origin rows to original projects and real C6.

    Actual live writers may be borrowed but never reissued; closed writers
    are acquired once, nonblocking, from held original locators. Named root,
    tracker and publication must still be the original dev/ino. Every actual
    C6 file/stat/byte image must exactly match its original registration.
    A busy/missing/changed project holds the whole read before any prefix.
    Local sequence numbers are never compared between distinct projects.
    Acquired owner tokens and generation selectors never escape the context.
    This is NOT APPLIED/FIFO-release/qualified NEW or online authority.
    """
    failed = False
    try:
        with ExitStack() as scope:
            origins, verify_origins = scope.enter_context(hold_pending_project_origins(token, binding))
            rows, verify_projects = scope.enter_context(_hold_project_c6_from_origins(token, binding, origins))
            def verify():
                verify_origins(); verify_projects(); verify_origins()
            verify()
            yield rows, verify
            verify()
    except Exception:
        failed = True
    if failed:
        raise UnitCatalogHold() from None


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


class _OriginalImageBudget:
    """Fixed unique live-image capacity, never cached original authority."""
    def __init__(self):
        self.bytes = 0
        self.images = {}
        self.pending = {}
        self.failed = False

    def reserve(self, identity):
        key = identity[:2]
        if self.failed:
            raise UnitCatalogHold()
        old = self.images.get(key)
        if old is not None:
            if old[0] != identity or old[1] is None:
                self.failed = True
                raise UnitCatalogHold()
        elif self.bytes + identity[6] > 16 * 1024 * 1024:
            self.failed = True
            raise UnitCatalogHold()
        else:
            self.bytes += identity[6]
            self.images[key] = (identity, None)

    def seal(self, identity, raw):
        saved = self.images[identity[:2]]
        if saved[0] != identity or (saved[1] is not None and saved[1] != raw):
            self.failed = True
            raise UnitCatalogHold()
        self.images[identity[:2]] = (identity, raw)

    def begin_written(self, identity, size):
        # Charge the actual newly opened inode and determined raw length,
        # never synthesize a future stat or admit its unfinished bytes.
        key = identity[:2]
        if (self.failed or key in self.images or type(size) is not int or size < 1
                or self.bytes + size > 16 * 1024 * 1024):
            self.failed = True
            raise UnitCatalogHold()
        self.bytes += size
        self.images[key] = (None, None); self.pending[key] = size

    def seal_written(self, identity, raw):
        key = identity[:2]
        if (self.failed or self.images.get(key) != (None, None)
                or self.pending.get(key) != len(raw) or identity[6] != len(raw)):
            self.failed = True
            raise UnitCatalogHold()
        self.images[key] = (identity, raw); self.pending.pop(key)


# Only a live native preparation installs its actual owner-bound budget.
# Callers cannot provide a limit, budget or original inventory to public APIs.
_IMAGE_BUDGETS = {}


def _originals(token, binding):
    active = _IMAGE_BUDGETS.get(token)
    if active is None:
        return _Originals()
    owner, expected, budget = active
    if expected != binding or ownership._validated_owner(token, binding) is not owner:
        raise UnitCatalogHold()
    return _Originals(_image_budget=budget)


class _Originals:
    def __init__(self, *, _image_budget=None):
        if _image_budget is not None and type(_image_budget) is not _OriginalImageBudget:
            raise UnitCatalogHold()
        self._image_budget = _image_budget
        self.files = []
        self.directories = []
        self.bytes = 0
        self.namespace = None

    def directory(self, parent, name):
        # This named preimage is a cleanup candidate only, never admitted
        # original authority. Successful acquisition still uses actual fstat.
        identity = journal._identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
        fd = local._directory(parent, name)
        try:
            identity = journal._identity(os.fstat(fd))
            names = tuple(sorted(os.listdir(fd)))
        except BaseException:
            # The graph cannot yet see this descriptor. Close only if the
            # current slot still names the candidate/actual acquired inode.
            _close_original(fd, identity)
            raise
        self.directories.append((parent, name, fd, identity, names))
        journal._named(parent, name, fd, directory=True)
        return fd

    def file(self, parent, name, limit):
        identity = journal._identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
        fd = os.open(name, local._flags(), dir_fd=parent)
        try:
            identity = journal._identity(os.fstat(fd))
        except BaseException:
            _close_original(fd, identity)
            raise
        self.files.append((parent, name, fd, identity, None))
        journal._named(parent, name, fd, directory=False)
        if not 1 <= identity[6] <= limit:
            raise UnitCatalogHold()
        if self._image_budget is not None:
            self._image_budget.reserve(identity)
        elif self.bytes + identity[6] > _MAX_IMAGES:
            raise UnitCatalogHold()
        raw = os.pread(fd, limit + 1, 0)
        self.bytes += len(raw)
        if (not 1 <= len(raw) <= limit or len(raw) != identity[6]
                or journal._identity(os.fstat(fd)) != identity):
            raise UnitCatalogHold()
        journal._named(parent, name, fd, directory=False)
        if self._image_budget is not None:
            self._image_budget.seal(identity, raw)
        self.files[-1] = (parent, name, fd, identity, raw)
        return raw, identity

    def _written_file(self,parent,name,written,raw,limit):
        # Private creator overlap, never reopen a pathname to adopt its inode.
        # Register the real writer immediately, before any receiving stat fails.
        fd,identity=written
        self.files.append((parent,name,fd,identity,raw))
        if (type(raw) is not bytes or not 1<=len(raw)<=limit or identity[6]!=len(raw)
                or journal._identity(os.fstat(fd))!=identity): raise UnitCatalogHold()
        journal._named(parent,name,fd,directory=False)
        if os.pread(fd,len(raw)+1,0)!=raw or journal._identity(os.fstat(fd))!=identity:
            raise UnitCatalogHold()
        if self._image_budget is not None:
            self._image_budget.reserve(identity); self._image_budget.seal(identity,raw)
        elif self.bytes+len(raw)>_MAX_IMAGES: raise UnitCatalogHold()
        self.bytes+=len(raw)

    def _written_directory(self,parent,name,folder,first_identity):
        # Own writes legitimately change size/timestamps, not inode/type/owner.
        # The first creator FD remains live while a checked overlapping reader
        # takes its exact completed directory image and all first writer FDs.
        journal._named(parent,name,folder,directory=True)
        current=journal._identity(os.fstat(folder))
        if current[:5]!=first_identity[:5]: raise UnitCatalogHold()
        self.verify()
        captured=self.directory(parent,name)
        if journal._identity(os.fstat(captured))!=current: raise UnitCatalogHold()
        self.files=[(captured if source==folder else source,entry,fd,identity,raw)
            for source,entry,fd,identity,raw in self.files]
        self.verify()
        return captured

    def verify(self, *, appended_to=None, parent_additions=frozenset()):
        if self._image_budget is not None and self._image_budget.failed:
            raise UnitCatalogHold()
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
        problem = None
        primary = None
        for _parent, _name, fd, identity, _raw in reversed(self.files):
            try:
                _close_original(fd, identity)
            except BaseException as exc:
                if problem is None:
                    problem = exc
                if not isinstance(exc, Exception) and primary is None:
                    primary = exc
        for _parent, _name, fd, identity, _names in reversed(self.directories):
            try:
                _close_original(fd, identity)
            except BaseException as exc:
                if problem is None:
                    problem = exc
                if not isinstance(exc, Exception) and primary is None:
                    primary = exc
        # Each slot still closes only its captured original inode. An interrupt
        # in one slot must not bypass the remaining owned originals, nor be
        # replaced by an ordinary cleanup error discovered later.
        if primary is not None:
            if problem is not primary:
                raise primary from problem
            raise primary
        if problem is not None:
            raise problem


def _header(unit, *, nv_original=None, project_origin=None, settings_allocation=None):
    result = {**compiled._projection(unit), 'state': 'PENDING_NOT_ATTEMPTED'}
    if nv_original is not None: result['nv_original'] = nv_original
    if project_origin is not None: result['project_origin'] = project_origin
    if settings_allocation is not None: result['settings_allocation']=settings_allocation
    return result


def _check_native_audit_assignments(seen,unit,origin):
    """ALL-catalog uniqueness uses anchored original project plus event ID.

    This consistency check grants no sending or recovery authority. It runs
    only after the unit's actual allocation/ORIGIN/ENTRY originals validate.
    Different projects may contain the same literal settings event.
    """
    identity=origin.get('project_identity')
    if (origin.get('unit_id')!=unit.unit_id or type(identity) is not list
            or len(identity)!=2 or any(type(value) is not int or value<1 for value in identity)):
        raise UnitCatalogHold()
    audits=local._json(unit.action_preimage)['audits']
    keys={(identity[0],identity[1],row['event_id']) for row in audits}
    if len(keys)!=len(audits) or keys&seen: raise UnitCatalogHold()
    seen.update(keys)


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
    audit_assignments = set()
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
        saved_header = local._json(originals['HEADER'][0])
        nv_original = saved_header.get('nv_original')
        project_origin = saved_header.get('project_origin')
        settings_allocation=saved_header.get('settings_allocation')
        origin_body=None
        if project_origin is not None:
            # Finished real writer identities, anchored by this unit's catalog
            # INITIALIZED->ENTRY chain. Lost-all cannot fall back to a catalog
            # that never required origins; raw/named/full-stat drift also stops.
            origin = held.directory(parent, owner.lock_name[:-5] + '.unit-' + unit_id + '.project-origin')
            if set(os.listdir(origin)) != {'WITNESS', 'STARTED', 'ORIGIN'}: raise UnitCatalogHold()
            images = {item: held.file(origin, item, local._MAX_MANIFEST) for item in ('WITNESS', 'STARTED', 'ORIGIN')}
            expected_origin = {'directory_identity': list(journal._identity(os.fstat(origin))), 'originals': {
                item: {'identity': list(image[1]), 'sha256': _digest(image[0])} for item, image in images.items()}}
            if local._canonical(project_origin) != local._canonical(expected_origin): raise UnitCatalogHold()
            project_origin = expected_origin
            origin_body=local._json(images['ORIGIN'][0])
        nv_name = owner.lock_name[:-5] + '.unit-' + unit_id + '.nv'
        if nv_original is None and {nv_name, nv_name + '-started'} & root_names:
            raise UnitCatalogHold()
        if nv_original is not None:
            # The genuine writer captured this finished marker's full stat
            # and bytes before append. Cold reads compare actual originals;
            # they cannot regenerate the first identity from a changed marker.
            nv_folder = held.directory(parent, nv_name)
            nv_raw, nv_identity = held.file(nv_folder, 'INITIALIZED', 1024 * 1024)
            expected_nv = {'identity': list(nv_identity), 'sha256': _digest(nv_raw)}
            if local._canonical(nv_original) != local._canonical(expected_nv):
                raise UnitCatalogHold()
            nv_original = expected_nv
        audits=local._json(unit.action_preimage)['audits']
        allocation_name=owner.lock_name[:-5]+'.unit-'+unit_id+'.settings-audit'
        if settings_allocation is not None:
            if not audits or origin_body is None: raise UnitCatalogHold()
            if nv_original is None:
                from monitor import issue_tracker_nv_reservation as native
                if native._unit_insertions(unit): raise UnitCatalogHold()
            from monitor import issue_tracker_settings_audit_allocation as allocation
            settings_allocation=allocation._inspect_native_catalog_allocation(parent,allocation_name,unit,binding,
                origin_body,settings_allocation,held)
        elif ((audits and project_origin is not None)
                or {allocation_name,allocation_name+'-started'}&root_names): raise UnitCatalogHold()
        if (unit.unit_id != unit_id or originals['HEADER'][0] != local._canonical(_header(unit, nv_original=nv_original, project_origin=project_origin,settings_allocation=settings_allocation))
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
        if settings_allocation is not None:
            _check_native_audit_assignments(audit_assignments,unit,origin_body)
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
    held = _originals(token, binding)
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


def register_pending_unit(token, binding, unit, *, _nv_preparation=None):
    """Append one coherent pending image; never repair or issue a capability."""
    held = _originals(token, binding)
    catalog = folder = None
    catalog_identity = folder_identity = None
    failed = False
    try:
        owner, parent, name, started, base = _inputs(token, binding)
        nv_additions = frozenset()
        nv_original = None
        project_origin = None
        settings_allocation=None
        if _nv_preparation is not None:
            from monitor import issue_tracker_nv_reservation as nv
            nv_additions = nv._catalog_nv_append_guard(_nv_preparation, token, binding, unit)
            nv_original = nv._catalog_nv_original_anchor(_nv_preparation, token, binding, unit)
            project_origin = nv._catalog_nv_c6_origin_anchor(_nv_preparation, token, binding, unit)
            record=nv._verify_catalog_preparation(_nv_preparation)
            if record['settings'] is not None: settings_allocation=record['settings']['anchor']
            if project_origin is not None and local._json(unit.action_preimage)['audits'] and settings_allocation is None:
                raise UnitCatalogHold()
        header_raw = local._canonical(_header(unit, nv_original=nv_original, project_origin=project_origin,settings_allocation=settings_allocation))
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
            if {item for item in names if item.startswith(owner.lock_name[:-5] + '.unit-')} - nv_additions:
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
        if _nv_preparation is not None:
            nv._catalog_nv_appended(_nv_preparation, catalog, unit)
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
