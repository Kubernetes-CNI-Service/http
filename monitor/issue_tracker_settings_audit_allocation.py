"""Uninstalled C25 original-event allocation under BOTH actual owners.

This conservative first journal retains one unit per project until a future
COMPLETE/DELIVERED verifier exists. It never sends, consumes an outbox event,
repairs a partial journal, authorizes a source, or proves remote delivery.
"""
import hashlib
import json
import os
from contextlib import contextmanager

from monitor import issue_tracker_local_commit as local
from monitor import issue_tracker_attempt_journal as journal
from monitor import issue_tracker_k_chain as chain
from monitor import issue_tracker_k_store as settings
from monitor import issue_tracker_global_attempt_journal as global_journal
from monitor import issue_tracker_spreadsheet_owner as ownership

_FOLDER = 'settings-audit-allocation'
_WITNESS = 'SETTINGS-AUDIT-ALLOCATED'
_LIMIT = 1024 * 1024


class SettingsAuditHold(ValueError):
    def __init__(self): super().__init__('req7_settings_audit_unproved')


@contextmanager
def _hold_settings_originals(writer_token):
    """Keep original FD identities/bytes/names across reads and allocation.

    Same-byte replacement is not an immutable original. Root directory mtime
    is deliberately not frozen: allocation legitimately adds its own witness
    there, but INITIALIZED and the named settings subtree remain pinned.
    """
    owner = local._owner(writer_token)
    held = []
    try:
        def directory(parent,name):
            descriptor=local._directory(parent,name)
            held.append((parent,name,descriptor,True,None,None))
            journal._named(parent,name,descriptor,directory=True)
            identity=journal._identity(os.fstat(descriptor)); names=set(os.listdir(descriptor))
            if journal._identity(os.fstat(descriptor))!=identity: raise SettingsAuditHold()
            held[-1]=(parent,name,descriptor,True,identity,names)
            return descriptor,names
        def file(parent,name):
            descriptor=os.open(name,local._flags(),dir_fd=parent)
            held.append((parent,name,descriptor,False,None,None))
            info=local._check(descriptor,directory=False)
            journal._named(parent,name,descriptor,directory=False)
            identity=journal._identity(info)
            raw=os.pread(descriptor,16385,0)
            if len(raw)>16384 or len(raw)!=info.st_size or journal._identity(os.fstat(descriptor))!=identity:
                raise SettingsAuditHold()
            held[-1]=(parent,name,descriptor,False,identity,raw)
            return raw
        folder,settings_names=directory(owner.root_fd,'settings')
        if settings_names!={'events','outbox','current'}: raise SettingsAuditHold()
        events,names=directory(folder,'events')
        outbox,outbox_names=directory(folder,'outbox')
        if (not names or any(settings._EVENT_NAME.fullmatch(name) is None for name in names)
                or outbox_names != names):
            raise SettingsAuditHold()
        raw_events={int(name[:-5]):file(events,name) for name in sorted(names)}
        raw_outbox={int(name[:-5]):file(outbox,name) for name in sorted(names)}
        current=file(folder,'current'); initialized=file(owner.root_fd,'INITIALIZED')
        def verify():
            if local._owner(writer_token) is not owner: raise SettingsAuditHold()
            for parent,name,descriptor,is_directory,identity,image in held:
                local._check(descriptor,directory=is_directory)
                journal._named(parent,name,descriptor,directory=is_directory)
                if journal._identity(os.fstat(descriptor))!=identity: raise SettingsAuditHold()
                if (set(os.listdir(descriptor)) if is_directory else os.pread(descriptor,16385,0))!=image:
                    raise SettingsAuditHold()
                journal._named(parent,name,descriptor,directory=is_directory)
                if journal._identity(os.fstat(descriptor))!=identity: raise SettingsAuditHold()
            local._owner(writer_token)
        verify()
        yield (raw_events,current,initialized,raw_outbox),verify
        verify()
    finally:
        close_failed=False
        for _parent,_name,descriptor,_directory,_identity,_image in reversed(held):
            try: os.close(descriptor)
            except OSError: close_failed=True
        if close_failed: raise SettingsAuditHold()


def _settings(writer_token):
    """Observe pinned originals, never accept a caller queue/snapshot."""
    with _hold_settings_originals(writer_token) as (images,verify):
        raw_events,current,initialized,raw_outbox=images
        chain.validate_k_chain_snapshot(raw_events, current, initialized)
        result = []
        for revision, raw in sorted(raw_events.items()):
            digest = hashlib.sha256(raw).hexdigest()
            expected = chain._canonical_line({'schema_version': 1, 'revision': revision, 'event_sha256': digest})
            if raw_outbox[revision] != expected: raise SettingsAuditHold()
            event = chain._parse(raw, chain._EVENT_KEYS)
            result.append((revision, digest, {'event_id': f'settings:{revision}:{digest}',
                'recorded_at_utc': event['recorded_at'], 'details': raw.decode('utf-8').rstrip('\n')}))
        verify()
        return tuple(result)


def pending_settings_audits(writer_token):
    """ALL committed events remain pending; allocation is NOT consumption."""
    failed = False
    try: result = tuple(dict(row[2]) for row in _settings(writer_token))
    except Exception: failed = True
    if failed: raise SettingsAuditHold()
    return result


def _originals(writer_token, spreadsheet_token, binding, unit):
    owner = local._owner(writer_token)
    _sheet_owner, _parent, _name, header = global_journal._inputs(spreadsheet_token, binding, unit)
    global_journal.inspect_global_unit(spreadsheet_token, binding, unit)
    audits = json.loads(unit.action_preimage.decode('utf-8'))['audits']
    if not audits: raise SettingsAuditHold()
    actual = {row[2]['event_id']: row for row in _settings(writer_token)}
    selected = []
    for audit in audits:
        revision, digest, original = actual[audit['event_id']]
        if audit != original: raise SettingsAuditHold()
        selected.append({'revision': revision, 'event_sha256': digest, 'audit': original})
    revisions = [row['revision'] for row in selected]
    if revisions != sorted(set(revisions)): raise SettingsAuditHold()
    assignments = local._canonical(selected)
    if not 1 <= len(assignments) <= _LIMIT: raise SettingsAuditHold()
    project, tracker = os.fstat(owner.project_fd), os.fstat(owner.root_fd)
    header = local._canonical({**header, 'project_identity': [project.st_dev, project.st_ino],
        'tracker_identity': [tracker.st_dev, tracker.st_ino]})
    return owner, header, assignments


def _marker(header, assignments):
    return local._canonical({'schema_version': 1, 'state': 'INITIALIZED',
        'header_sha256': hashlib.sha256(header).hexdigest(),
        'assignments_sha256': hashlib.sha256(assignments).hexdigest()})


def _witness(header, assignments):
    # Separate from the deletable unit directory: an attempted allocation is
    # never first use again, even if its final marker/folder disappears.
    return local._canonical({'schema_version': 1, 'state': 'ALLOCATION-STARTED',
        'header_sha256': hashlib.sha256(header).hexdigest(),
        'assignments_sha256': hashlib.sha256(assignments).hexdigest()})


def _inspect(parent, folder, header, assignments):
    if (journal._read(parent, _WITNESS, 16384) != _witness(header, assignments)
            or any(name.startswith('.pending-') for name in os.listdir(parent))
            or set(os.listdir(folder)) != {'HEADER', 'ASSIGNMENTS', 'INITIALIZED'}
            or journal._read(folder, 'HEADER', 16384) != header
            or journal._read(folder, 'ASSIGNMENTS', _LIMIT) != assignments
            or journal._read(folder, 'INITIALIZED', 16384) != _marker(header, assignments)):
        raise SettingsAuditHold()
    journal._named(parent, _FOLDER, folder, directory=True)


def _sync_marker(parent, folder, header, assignments):
    # Confirm the original post-image-barrier marker and its durability; never
    # create a missing one or use a coherent-looking partial image as authority.
    descriptor = os.open('INITIALIZED', local._flags(), dir_fd=folder)
    try:
        info = local._check(descriptor, directory=False)
        journal._named(folder, 'INITIALIZED', descriptor, directory=False)
        raw = os.read(descriptor, 16385)
        if len(raw) != info.st_size or raw != _marker(header, assignments): raise SettingsAuditHold()
        os.fsync(descriptor); os.fsync(folder); os.fsync(parent)
        journal._named(folder, 'INITIALIZED', descriptor, directory=False)
    finally: os.close(descriptor)


def _observe_held(writer_token, spreadsheet_token, binding, unit, *, create, verify_settings):
    folder = None; failed = False
    try:
        owner, header, assignments = _originals(writer_token, spreadsheet_token, binding, unit)
        verify_settings()
        if create:
            # Allocation must precede ANY attempt; UNKNOWN never gains audits.
            if global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count != 0:
                raise SettingsAuditHold()
            names = set(os.listdir(owner.root_fd))
            if (_FOLDER in names or _WITNESS in names
                    or any(name.startswith('.pending-') for name in names)):
                raise SettingsAuditHold()
            # Witness file+parent barriers BEFORE directory creation; a crash
            # leaves the witness or unexplained pending file, never adoption.
            local._write_new(owner.root_fd, _WITNESS, _witness(header, assignments))
            folder = global_journal._create_folder(owner.root_fd, _FOLDER)
            local._write_new(folder, 'HEADER', header)
            local._write_new(folder, 'ASSIGNMENTS', assignments)
            if _originals(writer_token, spreadsheet_token, binding, unit)[1:] != (header, assignments):
                raise SettingsAuditHold()
            if global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count != 0:
                raise SettingsAuditHold()
            journal._named(owner.root_fd, _FOLDER, folder, directory=True)
            verify_settings()
            # ALL eight witness+image barriers precede the unit marker.
            local._write_new(folder, 'INITIALIZED', _marker(header, assignments))
        else:
            folder = local._directory(owner.root_fd, _FOLDER)
        _inspect(owner.root_fd, folder, header, assignments)
        _sync_marker(owner.root_fd, folder, header, assignments)
        if _originals(writer_token, spreadsheet_token, binding, unit)[1:] != (header, assignments):
            raise SettingsAuditHold()
        ownership._validated_owner(spreadsheet_token, binding)
        local._owner(writer_token)
        _inspect(owner.root_fd, folder, header, assignments)
        if create and global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count != 0:
            raise SettingsAuditHold()
        verify_settings()
    except Exception: failed = True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed = True
    if failed: raise SettingsAuditHold()
    return assignments


def _observe(writer_token, spreadsheet_token, binding, unit, *, create):
    failed=False
    try:
        with _hold_settings_originals(writer_token) as (_images,verify):
            result=_observe_held(writer_token,spreadsheet_token,binding,unit,
                                 create=create,verify_settings=verify)
    except Exception: failed=True
    if failed: raise SettingsAuditHold()
    return result


def prepare_settings_audit_allocation(writer_token, spreadsheet_token, binding, unit):
    """Allocate ORIGINAL audit rows to an existing unattempted nonempty unit."""
    return _observe(writer_token, spreadsheet_token, binding, unit, create=True)


def inspect_settings_audit_allocation(writer_token, spreadsheet_token, binding, unit):
    """Read only retained original assignments, including across UNKNOWN retries."""
    return _observe(writer_token, spreadsheet_token, binding, unit, create=False)
