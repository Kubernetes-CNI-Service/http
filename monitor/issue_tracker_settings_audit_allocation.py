"""Uninstalled C25 original-event allocation under BOTH actual owners.

This conservative first journal retains one unit per project. The delivery
bridge requires the actual original C19 COMPLETE proof before its durable
DELIVERED record. A separate paired cleanup archives only those delivered
projections; it never sends, deletes originals, repairs a partial journal,
authorizes a source or releases UNKNOWN/FIFO/admission barriers.
"""
import hashlib
import json
import os
import uuid
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass

from monitor import issue_tracker_local_commit as local
from monitor import issue_tracker_attempt_journal as journal
from monitor import issue_tracker_k_chain as chain
from monitor import issue_tracker_k_store as settings
from monitor import issue_tracker_global_attempt_journal as global_journal
from monitor import issue_tracker_spreadsheet_owner as ownership

_FOLDER = 'settings-audit-allocation'
_WITNESS = 'SETTINGS-AUDIT-ALLOCATED'
_LIMIT = 1024 * 1024
_DELIVERY_FOLDER = 'settings-audit-delivery'
_DELIVERY_STARTED = 'SETTINGS-AUDIT-DELIVERY-STARTED'


class SettingsAuditHold(ValueError):
    def __init__(self): super().__init__('req7_settings_audit_unproved')


@contextmanager
def _hold_settings_originals(writer_token,*,delivered_event_ids=()):
    """Keep original FD identities/bytes/names across reads and allocation.

    Same-byte replacement is not an immutable original. Root directory mtime
    is deliberately not frozen: allocation legitimately adds its own witness
    there, but INITIALIZED and the named settings subtree remain pinned.
    Internal completed-delivery inspection may provisionally read absent
    projections ONLY for exact original unit event IDs. No public observation
    escapes until the paired original COMPLETE and DELIVERED is also validated;
    ordinary readers, allocation and mutation-count paths stay strict.
    """
    owner = local._owner(writer_token)
    held = []; primary=None
    try:
        def directory(parent,name):
            candidate=journal._identity(os.stat(name,dir_fd=parent,follow_symlinks=False))
            descriptor=os.open(name,local._flags(directory=True),dir_fd=parent)
            # The named preimage is only a conditional cleanup candidate.
            # Admission still requires this actual FD's first checked stat.
            held.append((parent,name,descriptor,True,candidate,None))
            info=local._check(descriptor,directory=True)
            if (info.st_dev,info.st_ino)!=candidate[:2]: raise SettingsAuditHold()
            journal._named(parent,name,descriptor,directory=True)
            identity=journal._identity(info); names=set(os.listdir(descriptor))
            if journal._identity(os.fstat(descriptor))!=identity: raise SettingsAuditHold()
            held[-1]=(parent,name,descriptor,True,identity,names)
            return descriptor,names
        def file(parent,name):
            candidate=journal._identity(os.stat(name,dir_fd=parent,follow_symlinks=False))
            descriptor=os.open(name,local._flags(),dir_fd=parent)
            held.append((parent,name,descriptor,False,candidate,None))
            info=local._check(descriptor,directory=False)
            if (info.st_dev,info.st_ino)!=candidate[:2]: raise SettingsAuditHold()
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
                or not outbox_names <= names):
            raise SettingsAuditHold()
        raw_events={int(name[:-5]):file(events,name) for name in sorted(names)}
        missing={f'settings:{revision}:'+hashlib.sha256(raw).hexdigest()
                 for revision,raw in raw_events.items() if f'{revision}.json' not in outbox_names}
        if not missing <= set(delivered_event_ids): raise SettingsAuditHold()
        raw_outbox={int(name[:-5]):file(outbox,name) for name in sorted(outbox_names)}
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
    except BaseException as exc:
        primary=exc
        raise
    finally:
        close_problem=None
        for _parent,_name,descriptor,_directory,identity,_image in reversed(held):
            try: local._close_written_original(descriptor,identity)
            except BaseException as exc:
                if close_problem is None: close_problem=exc
                if primary is None and not isinstance(exc,Exception): primary=exc
        if close_problem is not None:
            refusal=SettingsAuditHold()
            if primary is not None: raise primary from refusal
            raise refusal from close_problem


def _settings(writer_token,*,delivered_event_ids=()):
    """Observe pinned originals, never accept a caller queue/snapshot."""
    with _hold_settings_originals(writer_token,delivered_event_ids=delivered_event_ids) as (images,verify):
        raw_events,current,initialized,raw_outbox=images
        chain.validate_k_chain_snapshot(raw_events, current, initialized)
        result = []
        for revision, raw in sorted(raw_events.items()):
            digest = hashlib.sha256(raw).hexdigest()
            expected = chain._canonical_line({'schema_version': 1, 'revision': revision, 'event_sha256': digest})
            if revision in raw_outbox and raw_outbox[revision] != expected: raise SettingsAuditHold()
            event = chain._parse(raw, chain._EVENT_KEYS)
            result.append((revision, digest, {'event_id': f'settings:{revision}:{digest}',
                'recorded_at_utc': event['recorded_at'], 'details': raw.decode('utf-8').rstrip('\n')}))
        verify()
        return tuple(result)


def pending_settings_audits(writer_token):
    """Read committed pending audits under the actual LIVE settings factory.

    A matching held original COMPLETE/DELIVERED context excludes only its
    exact events. Ordinary writers retain the strict projection contract;
    allocation, caller IDs or a context without its original guard cannot
    consume an event. No cleanup, new allocation or sending is performed.
    """
    failed = False
    try:
        from monitor import issue_tracker_state_owner as state
        owner=local._owner(writer_token)
        context=state._COMPLETED_READ_CONTEXT.get(writer_token)
        guard=state._COMPLETED_ORIGINAL_GUARDS.get(writer_token)
        def verify():
            if (local._owner(writer_token) is not owner
                    or state._COMPLETED_READ_CONTEXT.get(writer_token) is not context
                    or state._COMPLETED_ORIGINAL_GUARDS.get(writer_token) is not guard):
                raise SettingsAuditHold()
            if guard is not None: guard()
            if (local._owner(writer_token) is not owner
                    or state._COMPLETED_READ_CONTEXT.get(writer_token) is not context
                    or state._COMPLETED_ORIGINAL_GUARDS.get(writer_token) is not guard):
                raise SettingsAuditHold()
        verify()
        if context is not None and guard is not None:
            result=pending_settings_audits_after_completed_unit(writer_token,*context)
        else:
            result=tuple(dict(row[2]) for row in _settings(writer_token))
        verify()
    except Exception: failed = True
    if failed: raise SettingsAuditHold()
    return result


def _originals(writer_token, spreadsheet_token, binding, unit,*,delivered_event_ids=()):
    owner = local._owner(writer_token)
    _sheet_owner, _parent, _name, header = global_journal._inputs(spreadsheet_token, binding, unit)
    global_journal.inspect_global_unit(spreadsheet_token, binding, unit)
    audits = json.loads(unit.action_preimage.decode('utf-8'))['audits']
    if not audits: raise SettingsAuditHold()
    actual = {row[2]['event_id']: row for row in _settings(writer_token,delivered_event_ids=delivered_event_ids)}
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


@contextmanager
def _hold_allocation_originals(parent, folder, header, assignments):
    """Pin completed allocation originals through synchronization/rechecks.

    This is a per-observation snapshot, not persistent inode enrollment or
    permission to adopt an incomplete allocation or to send/consume an audit.
    """
    opened=[]
    try:
        journal._named(parent,_FOLDER,folder,directory=True)
        identity=journal._identity(os.fstat(folder))
        names={'HEADER','ASSIGNMENTS','INITIALIZED'}
        if set(os.listdir(folder))!=names: raise SettingsAuditHold()
        for directory,name,expected,limit in (
                (parent,_WITNESS,_witness(header,assignments),16384),
                (folder,'HEADER',header,16384),
                (folder,'ASSIGNMENTS',assignments,_LIMIT),
                (folder,'INITIALIZED',_marker(header,assignments),16384)):
            fd=os.open(name,local._flags(),dir_fd=directory)
            opened.append((directory,name,fd,None,expected,limit))
            info=local._check(fd,directory=False)
            original=journal._identity(info)
            opened[-1]=(directory,name,fd,original,expected,limit)
            journal._named(directory,name,fd,directory=False)
            if (info.st_size!=len(expected) or os.pread(fd,limit+1,0)!=expected
                    or journal._identity(os.fstat(fd))!=original): raise SettingsAuditHold()
        def verify():
            journal._named(parent,_FOLDER,folder,directory=True)
            if (journal._identity(os.fstat(folder))!=identity
                    or set(os.listdir(folder))!=names): raise SettingsAuditHold()
            for directory,name,fd,original,expected,limit in opened:
                journal._named(directory,name,fd,directory=False)
                if (journal._identity(os.fstat(fd))!=original
                        or os.pread(fd,limit+1,0)!=expected): raise SettingsAuditHold()
                journal._named(directory,name,fd,directory=False)
                if journal._identity(os.fstat(fd))!=original: raise SettingsAuditHold()
            journal._named(parent,_FOLDER,folder,directory=True)
            if (journal._identity(os.fstat(folder))!=identity
                    or set(os.listdir(folder))!=names): raise SettingsAuditHold()
        verify()
        yield verify
        verify()
    finally:
        failed=False
        for _directory,_name,fd,original,_expected,_limit in reversed(opened):
            try:
                if original is not None and journal._identity(os.fstat(fd))[:2]!=original[:2]:
                    failed=True  # never close a foreign descriptor reused at this number
                else: os.close(fd)
            except OSError: failed=True
        if failed: raise SettingsAuditHold()


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


@contextmanager
def _hold_counted_audit_originals(writer_token, spreadsheet_token, binding, unit,*,delivered_event_ids=()):
    """Keep the same original settings/allocation through one durable count.

    Read-only necessary scope, not admission, persistent inode enrollment or
    recovery. A post-count failure retains UNKNOWN; never repair or roll back.
    """
    folder=None; failed=False
    try:
        with _hold_settings_originals(writer_token,delivered_event_ids=delivered_event_ids) as (_images,verify_settings):
            owner,header,assignments=_originals(writer_token,spreadsheet_token,binding,unit,delivered_event_ids=delivered_event_ids)
            folder=local._directory(owner.root_fd,_FOLDER)
            with _hold_allocation_originals(owner.root_fd,folder,header,assignments) as verify_allocation:
                _inspect(owner.root_fd,folder,header,assignments)
                def verify():
                    verify_settings()
                    if local._owner(writer_token) is not owner: raise SettingsAuditHold()
                    ownership._validated_owner(spreadsheet_token,binding)
                    verify_allocation()
                verify()
                yield verify
                verify()
    except Exception: failed=True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed=True
    if failed: raise SettingsAuditHold()


def _observe_held(writer_token, spreadsheet_token, binding, unit, *, create, verify_settings):
    folder = None; failed = False; creators=ExitStack(); written=[]
    def verify_written():
        for parent,name,fd,identity,raw in written:
            local._check(fd,directory=False); journal._named(parent,name,fd,directory=False)
            if journal._identity(os.fstat(fd))!=identity or os.pread(fd,len(raw)+1,0)!=raw:
                raise SettingsAuditHold()
            journal._named(parent,name,fd,directory=False)
            if journal._identity(os.fstat(fd))!=identity: raise SettingsAuditHold()
    def write(parent,name,raw):
        fd,identity=local._write_new(parent,name,raw,_return_original=True)
        # Register cleanup BEFORE the first stat/read can fail. Keep the actual
        # creator FD until the completed reader and all finalizers have closed;
        # a same-byte replacement between writer return and capture is not ours.
        creators.callback(local._close_written_original,fd,identity)
        written.append((parent,name,fd,identity,raw)); verify_written()
    try:
        owner, header, assignments = _originals(writer_token, spreadsheet_token, binding, unit)
        verify_settings()
        if create:
            # Allocation must precede ANY attempt; UNKNOWN never gains audits.
            if global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count != 0:
                raise SettingsAuditHold()
            # ALL currently committed pending events belong to the first unit;
            # this check is deliberately NOT repeated for later UNKNOWN retries
            # or delivery, where subsequent K events must not mutate the unit.
            if {row['audit']['event_id'] for row in json.loads(assignments.decode('utf-8'))} != {
                    row[2]['event_id'] for row in _settings(writer_token)}:
                raise SettingsAuditHold()
            names = set(os.listdir(owner.root_fd))
            if (_FOLDER in names or _WITNESS in names
                    or any(name.startswith('.pending-') for name in names)):
                raise SettingsAuditHold()
            # Witness file+parent barriers BEFORE directory creation; a crash
            # leaves the witness or unexplained pending file, never adoption.
            write(owner.root_fd, _WITNESS, _witness(header, assignments))
            folder = global_journal._create_folder(owner.root_fd, _FOLDER)
            write(folder, 'HEADER', header)
            write(folder, 'ASSIGNMENTS', assignments)
            if _originals(writer_token, spreadsheet_token, binding, unit)[1:] != (header, assignments):
                raise SettingsAuditHold()
            if global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count != 0:
                raise SettingsAuditHold()
            journal._named(owner.root_fd, _FOLDER, folder, directory=True)
            verify_settings()
            verify_written()
            # ALL eight witness+image barriers precede the unit marker.
            write(folder, 'INITIALIZED', _marker(header, assignments))
        else:
            folder = local._directory(owner.root_fd, _FOLDER)
        with _hold_allocation_originals(owner.root_fd,folder,header,assignments) as verify_allocation:
            verify_written()
            _inspect(owner.root_fd, folder, header, assignments)
            _sync_marker(owner.root_fd, folder, header, assignments)
            verify_allocation()
            verify_written()
            if _originals(writer_token, spreadsheet_token, binding, unit)[1:] != (header, assignments):
                raise SettingsAuditHold()
            ownership._validated_owner(spreadsheet_token, binding)
            local._owner(writer_token)
            _inspect(owner.root_fd, folder, header, assignments)
            if create and global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count != 0:
                raise SettingsAuditHold()
            verify_settings()
            verify_allocation()
            verify_written()
        verify_written()
    except Exception: failed = True
    finally:
        try:
            try: creators.close()
            except Exception: failed=True
        finally:
            # A creator finalizer interruption cannot bypass the folder close.
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


def _native_assignments(unit):
    """Exact frozen audit images, not caller-supplied event selectors."""
    rows=[]
    for audit in local._json(unit.action_preimage)['audits']:
        raw=(audit['details']+'\n').encode('utf-8'); event=local._json(raw)
        revision=event['revision']; digest=hashlib.sha256(raw).hexdigest()
        if (type(revision) is not int or revision<0
                or audit['event_id']!='settings:%d:%s'%(revision,digest)
                or audit['recorded_at_utc']!=event['recorded_at']): raise SettingsAuditHold()
        rows.append({'revision':revision,'event_sha256':digest,'audit':audit})
    if [row['revision'] for row in rows]!=sorted({row['revision'] for row in rows}): raise SettingsAuditHold()
    return local._canonical(rows)


def _native_header(unit,binding,project_identity,tracker_identity):
    from monitor import issue_tracker_send_intent as compiled
    return local._canonical({**compiled._projection(unit),
        'spreadsheet_id':binding.spreadsheet_id,'allowlist_sha256':binding.allowlist_sha256,
        'policy_sha256':binding.policy_sha256,'project_identity':list(project_identity),
        'tracker_identity':list(tracker_identity),'state':'NATIVE_SETTINGS_ALLOCATION'})


def _native_assigned_event_ids(record,project_identity):
    """Group prior audits by already-held original project, never event alone.

    The preparation has verified these original images and ALL actual C6
    projects. Do not reopen a path or use a current writer/ACTIVE selector to
    reconstruct the older unit's owner. Missing or ambiguous originals stop.
    """
    assigned=set();held=record['old']
    for older in record['units']:
        audits=local._json(older.action_preimage)['audits']
        if not audits: continue
        name=record['stem']+'.unit-'+older.unit_id+'.project-origin'
        folders=[fd for parent,child,fd,_identity,_names in held.directories
                 if parent==record['parent'] and child==name]
        if len(folders)!=1: raise SettingsAuditHold()
        images=[raw for parent,child,_fd,_identity,raw in held.files
                if parent==folders[0] and child=='ORIGIN']
        if len(images)!=1 or images[0] is None: raise SettingsAuditHold()
        origin=local._json(images[0]);identity=origin.get('project_identity')
        if (origin.get('unit_id')!=older.unit_id or type(identity) is not list
                or len(identity)!=2 or any(type(value) is not int or value<1 for value in identity)):
            raise SettingsAuditHold()
        if tuple(identity)==project_identity:
            assigned.update(row['event_id'] for row in audits)
    return assigned


def _prepare_native_catalog_allocation(prepared,writer,token,binding,unit):
    """One genuine live C6 creator, BEFORE its catalog append; never cold NEW.

    No GLOBAL/count0 inference, caller paths or capability flags. The opaque
    preparation owns all original FDs through ENTRY/readback/final verification.
    Prior allocations retain their events, including UNKNOWN. This is not the
    native COMPLETE/DELIVERED bridge or an installed sending authority.
    """
    from monitor import issue_tracker_nv_reservation as nv
    record=nv._verify_catalog_preparation(prepared); origin=record['origin']
    if (origin is None or not origin['sealed'] or origin['writer'] is not writer
            or record['token'] is not token or record['binding']!=binding
            or record['unit'] is not unit or record['registered'] or record['indexed'] is not None
            or record['settings'] is not None): raise SettingsAuditHold()
    audits=local._json(unit.action_preimage)['audits']
    if not audits: return
    owner=local._owner(writer)
    if owner is not origin['owner']: raise SettingsAuditHold()
    _images,verify=record['settings_scope'].enter_context(_hold_settings_originals(writer))
    events=_settings(writer)
    project_identity=journal._identity(os.fstat(owner.project_fd))[:2]
    assigned=_native_assigned_event_ids(record,project_identity)
    nv._verify_catalog_preparation(prepared)
    wanted=tuple(row[2] for row in events if row[2]['event_id'] not in assigned)
    if local._canonical(audits)!=local._canonical(wanted): raise SettingsAuditHold()
    assignments=_native_assignments(unit)
    header=_native_header(unit,binding,project_identity,
                          journal._identity(os.fstat(owner.root_fd))[:2])
    parent=record['parent']; name=record['stem']+'.unit-'+unit.unit_id+'.settings-audit'
    started=name+'-started'
    if {name,started}&set(os.listdir(parent)): raise SettingsAuditHold()
    record['settings']={'writer':writer,'owner':owner,'verify':verify,'anchor':None}
    record['additions'].update((name,started))
    held=record['current']
    def write(directory,entry,raw):
        descriptor,identity=local._write_new(directory,entry,raw,_return_original=True)
        # Own the ACTUAL creator before any subsequent stat can fail.
        held.files.append((directory,entry,descriptor,identity,raw))
        held._image_budget.reserve(identity);held._image_budget.seal(identity,raw)
        held.verify();verify()
        return identity
    witness=_witness(header,assignments)
    witness_identity=write(parent,started,witness)
    folder,created=global_journal._create_folder(parent,name,_return_original=True)
    retained=False
    try:
        if journal._identity(os.fstat(folder))!=created or os.listdir(folder): raise SettingsAuditHold()
        for entry,raw in (('HEADER',header),('ASSIGNMENTS',assignments),('INITIALIZED',_marker(header,assignments))):
            write(folder,entry,raw)
        final=journal._identity(os.fstat(folder))
        held.directories.append((parent,name,folder,final,('ASSIGNMENTS','HEADER','INITIALIZED')));retained=True
        held.verify();verify();held.sync();nv._verify_catalog_preparation(prepared)
        originals={entry:{'identity':list(identity),'sha256':hashlib.sha256(raw).hexdigest()}
            for directory,entry,_fd,identity,raw in held.files if directory==folder}
        record['settings']['anchor']={'directory_identity':list(final),
            'witness':{'identity':list(witness_identity),'sha256':hashlib.sha256(witness).hexdigest()},
            'originals':originals}
        nv._verify_catalog_preparation(prepared)
    finally:
        if not retained: local._close_written_original(folder,created)


def _inspect_native_catalog_allocation(parent,name,unit,binding,origin,anchor,held):
    """Cold read of the catalog's external original anchor, never repair."""
    folder=held.directory(parent,name)
    if set(os.listdir(folder))!={'HEADER','ASSIGNMENTS','INITIALIZED'}: raise SettingsAuditHold()
    images={entry:held.file(folder,entry,_LIMIT) for entry in ('HEADER','ASSIGNMENTS','INITIALIZED')}
    witness,witness_identity=held.file(parent,name+'-started',_LIMIT)
    header=_native_header(unit,binding,origin['project_identity'],origin['tracker_identity'])
    assignments=_native_assignments(unit)
    expected={'directory_identity':list(journal._identity(os.fstat(folder))),
        'witness':{'identity':list(witness_identity),'sha256':hashlib.sha256(witness).hexdigest()},
        'originals':{entry:{'identity':list(info),'sha256':hashlib.sha256(raw).hexdigest()}
            for entry,(raw,info) in images.items()}}
    if (local._canonical(anchor)!=local._canonical(expected)
            or images['HEADER'][0]!=header or images['ASSIGNMENTS'][0]!=assignments
            or images['INITIALIZED'][0]!=_marker(header,assignments)
            or witness!=_witness(header,assignments)): raise SettingsAuditHold()
    held.verify()
    return expected


@dataclass(frozen=True)
class SettingsDeliveryObservation:
    """Original COMPLETE plus durable local record; no send/cleanup permit."""
    state: str
    unit_id: str
    event_ids: tuple


@contextmanager
def _hold_delivery_authority(writer_token,spreadsheet_token,binding,unit,*,inspect_delivered=False):
    """Pin both actual owners, original allocation and the WHOLE C19 proof.

    No caller observation, digest or purported success can stand in for the
    actual complete raw images and their original local journals. New K events
    do not change the already frozen selected audit set.
    """
    from monitor import issue_tracker_remote_history_match as completion
    folder=None
    try:
        with ExitStack() as scope:
            match_verify,_journal_originals=scope.enter_context(completion._hold_match_originals(spreadsheet_token,binding,unit))
            proof_verify=scope.enter_context(completion._hold_completion_originals(spreadsheet_token,binding,unit))
            seen=completion.inspect_completion_evidence(spreadsheet_token,binding,unit)
            if seen.state!='COMPLETE-PRESENT-NOT-APPLIED' or seen.unit_id!=unit.unit_id:
                raise SettingsAuditHold()
            # Internal image readability only, never a sending/cleanup permit.
            # ALL actual proof originals remain held. Public consumers must
            # additionally validate the original durable DELIVERED pair before
            # yielding any pending result; creation/count paths remain strict.
            delivered_ids=tuple(row['event_id'] for row in json.loads(unit.action_preimage.decode('utf-8'))['audits']) if inspect_delivered else ()
            audit_verify=scope.enter_context(_hold_counted_audit_originals(writer_token,spreadsheet_token,binding,unit,
                                                                          delivered_event_ids=delivered_ids))
            owner,header,assignments=_originals(writer_token,spreadsheet_token,binding,unit,delivered_event_ids=delivered_ids)
            _sheet,parent,name,_binding=global_journal._inputs(spreadsheet_token,binding,unit)
            name=name[:-len('.journal')]+'.completion'
            folder=local._directory(parent,name)
            proof_files={file:{'identity':list(journal._identity(os.stat(file,dir_fd=folder,follow_symlinks=False))),
                              'sha256':hashlib.sha256(journal._read(folder,file,2*1024*1024)).hexdigest()}
                         for file in sorted(os.listdir(folder))}
            raw=local._canonical({'schema_version':1,'unit_id':unit.unit_id,
                'allocation_header_sha256':hashlib.sha256(header).hexdigest(),
                'assignments_sha256':hashlib.sha256(assignments).hexdigest(),
                'completion_header_sha256':seen.header_sha256,
                'completion_directory_identity':list(journal._identity(os.fstat(folder))[:2]),
                'completion_originals':proof_files})
            selected=json.loads(assignments.decode('utf-8'))
            with _hold_settings_originals(writer_token,delivered_event_ids=delivered_ids) as (images,settings_verify):
                present=sum(row['revision'] in images[3] for row in selected)
                settings_verify()
            projection_state=('RETAINED' if present==len(selected) else
                              'ABSENT-VALID' if present==0 else 'PARTIAL-VALID')
            result=SettingsDeliveryObservation('DELIVERED-PRESENT-OUTBOX-'+projection_state,unit.unit_id,
                                               tuple(row['audit']['event_id'] for row in selected))
            def verify():
                audit_verify(); match_verify(); proof_verify()
                journal._named(parent,name,folder,directory=True)
                if completion.inspect_completion_evidence(spreadsheet_token,binding,unit)!=seen:
                    raise SettingsAuditHold()
                audit_verify(); match_verify(); proof_verify()
            verify()
            yield owner,raw,result,verify
            verify()
    finally:
        if folder is not None: os.close(folder)


def _delivery_marker(raw,identity):
    return local._canonical({'schema_version':1,'state':'DELIVERED',
        'header_sha256':hashlib.sha256(raw).hexdigest(),'header_identity':list(identity)})


def _delivery_start_raw(raw):
    return local._canonical({'schema_version':1,'state':'DELIVERY-STARTED-NOT-CLEANED',
        'complete_allocation_sha256':hashlib.sha256(raw).hexdigest()})


@contextmanager
def _hold_delivery_start(owner,raw,*,written=None):
    """Retain the original start witness across cold reads and marker writes."""
    fd=None
    try:
        fd=os.open(_DELIVERY_STARTED,local._flags()|os.O_NONBLOCK,dir_fd=owner.root_fd)
        info=local._check(fd,directory=False); identity=journal._identity(info)
        if written is not None and identity!=written: raise SettingsAuditHold()
        expected=_delivery_start_raw(raw)
        def verify():
            journal._named(owner.root_fd,_DELIVERY_STARTED,fd,directory=False)
            if journal._identity(os.fstat(fd))!=identity or os.pread(fd,16385,0)!=expected:
                raise SettingsAuditHold()
            journal._named(owner.root_fd,_DELIVERY_STARTED,fd,directory=False)
            if journal._identity(os.fstat(fd))!=identity: raise SettingsAuditHold()
        verify(); os.fsync(fd); os.fsync(owner.root_fd); verify()
        header=local._canonical({'schema_version':1,'complete_allocation':json.loads(raw.decode('utf-8')),
            'delivery_start_identity':list(identity)})
        yield verify,header
        verify()
    finally:
        if fd is not None: os.close(fd)


def _write_delivery_file(parent,name,raw):
    """Fixed exclusive file; failed writes retain partial evidence, never adopt."""
    if type(raw) is not bytes or not 1<=len(raw)<=16384: raise SettingsAuditHold()
    local._flags()
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
    try:
        local._check(fd,directory=False); journal._named(parent,name,fd,directory=False)
        remaining=memoryview(raw)
        while remaining:
            count=os.write(fd,remaining)
            if count<=0: raise SettingsAuditHold()
            remaining=remaining[count:]
        identity=journal._identity(os.fstat(fd))
        os.fsync(fd); os.fsync(parent)
        journal._named(parent,name,fd,directory=False)
        if journal._identity(os.fstat(fd))!=identity: raise SettingsAuditHold()
        return identity
    finally: os.close(fd)


@contextmanager
def _hold_delivery_header(owner,folder,raw,identity):
    """The first-written HEADER stays original before/through DELIVERED."""
    fd=None
    try:
        fd=os.open('HEADER',local._flags(),dir_fd=folder)
        local._check(fd,directory=False)
        def verify():
            journal._named(owner.root_fd,_DELIVERY_FOLDER,folder,directory=True)
            journal._named(folder,'HEADER',fd,directory=False)
            if journal._identity(os.fstat(fd))!=identity or os.pread(fd,16385,0)!=raw: raise SettingsAuditHold()
            journal._named(folder,'HEADER',fd,directory=False)
            if journal._identity(os.fstat(fd))!=identity: raise SettingsAuditHold()
        verify(); yield verify; verify()
    finally:
        if fd is not None: os.close(fd)


@contextmanager
def _hold_delivery_files(owner,folder,raw,*,written=None):
    held=[]
    try:
        journal._named(owner.root_fd,_DELIVERY_FOLDER,folder,directory=True)
        directory_identity=journal._identity(os.fstat(folder))
        if set(os.listdir(folder))!={'HEADER','DELIVERED'}: raise SettingsAuditHold()
        for name in ('HEADER','DELIVERED'):
            fd=os.open(name,local._flags(),dir_fd=folder); held.append((name,fd,None,None))
            info=local._check(fd,directory=False); identity=journal._identity(info)
            if written is not None and identity!=written[name]: raise SettingsAuditHold()
            journal._named(folder,name,fd,directory=False)
            image=os.pread(fd,16385,0)
            expected=raw if name=='HEADER' else _delivery_marker(raw,held[0][2])
            if len(image)!=info.st_size or image!=expected: raise SettingsAuditHold()
            held[-1]=(name,fd,identity,image)
        def verify():
            journal._named(owner.root_fd,_DELIVERY_FOLDER,folder,directory=True)
            if journal._identity(os.fstat(folder))!=directory_identity or set(os.listdir(folder))!={'HEADER','DELIVERED'}:
                raise SettingsAuditHold()
            for name,fd,identity,image in held:
                journal._named(folder,name,fd,directory=False)
                if journal._identity(os.fstat(fd))!=identity or os.pread(fd,16385,0)!=image: raise SettingsAuditHold()
                journal._named(folder,name,fd,directory=False)
                if journal._identity(os.fstat(fd))!=identity: raise SettingsAuditHold()
            journal._named(owner.root_fd,_DELIVERY_FOLDER,folder,directory=True)
            if journal._identity(os.fstat(folder))!=directory_identity: raise SettingsAuditHold()
        verify()
        for _name,fd,_identity,_image in held: os.fsync(fd)
        os.fsync(folder); os.fsync(owner.root_fd); verify()
        yield verify
        verify()
    finally:
        failed=False
        for _name,fd,_identity,_image in reversed(held):
            try: os.close(fd)
            except OSError: failed=True
        if failed: raise SettingsAuditHold()


def _completed_settings_delivery(writer_token,spreadsheet_token,binding,unit,*,create):
    folder=None; failed=False; scope=ExitStack(); header_verify=None
    try:
        with _hold_delivery_authority(writer_token,spreadsheet_token,binding,unit,inspect_delivered=not create) as (owner,raw,result,verify):
            written=None; started=None
            if create:
                if (_DELIVERY_FOLDER in os.listdir(owner.root_fd) or _DELIVERY_STARTED in os.listdir(owner.root_fd)
                        or any(name.startswith('.pending-') for name in os.listdir(owner.root_fd))):
                    raise SettingsAuditHold()
                # Retain the fixed STOP name even after a first-byte/barrier
                # failure or a subsequently displaced delivery directory.
                started=_write_delivery_file(owner.root_fd,_DELIVERY_STARTED,_delivery_start_raw(raw))
            start_verify,raw=scope.enter_context(_hold_delivery_start(owner,raw,written=started))
            verify(); start_verify()
            if create:
                folder=global_journal._create_folder(owner.root_fd,_DELIVERY_FOLDER)
                header_identity=_write_delivery_file(folder,'HEADER',raw)
                header_verify=scope.enter_context(_hold_delivery_header(owner,folder,raw,header_identity))
                verify(); start_verify(); header_verify()
                # ALL original COMPLETE and allocation barriers precede this
                # exclusive durable DELIVERED. Never clean the outbox here.
                marker_identity=_write_delivery_file(folder,'DELIVERED',_delivery_marker(raw,header_identity))
                written={'HEADER':header_identity,'DELIVERED':marker_identity}
            else: folder=local._directory(owner.root_fd,_DELIVERY_FOLDER)
            with _hold_delivery_files(owner,folder,raw,written=written) as delivery_verify:
                verify(); start_verify(); delivery_verify()
                if header_verify is not None: header_verify()
    except Exception: failed=True
    finally:
        try: scope.close()
        except Exception: failed=True
        if folder is not None:
            try: os.close(folder)
            except OSError: failed=True
    if failed: raise SettingsAuditHold()
    return result


def record_completed_settings_delivery(writer_token,spreadsheet_token,binding,unit):
    """Persist original C25 delivery after validated COMPLETE; no consumption."""
    return _completed_settings_delivery(writer_token,spreadsheet_token,binding,unit,create=True)


def inspect_completed_settings_delivery(writer_token,spreadsheet_token,binding,unit):
    """Revalidate the actual original COMPLETE/DELIVERED pair, never backfill."""
    return _completed_settings_delivery(writer_token,spreadsheet_token,binding,unit,create=False)


def pending_settings_audits_after_completed_unit(writer_token,spreadsheet_token,binding,unit):
    """ALL committed events MINUS this actual original COMPLETE/DELIVERED pair.

    Only the retained one-unit journal is supported. A remaining delivered
    projection is cleanup-only, not a resend source. Only this revalidated pair
    excuses its exact missing projection; subsequent events still require theirs.
    No cleanup, new allocation,
    general historical settlement or UNKNOWN release is performed here. The
    unqualified pending reader alone is not an integrated sending authority.
    """
    folder=None; failed=False
    try:
        with _hold_delivery_authority(writer_token,spreadsheet_token,binding,unit,inspect_delivered=True) as (owner,raw,delivered,verify):
            with _hold_delivery_start(owner,raw) as (start_verify,raw):
                folder=local._directory(owner.root_fd,_DELIVERY_FOLDER)
                with _hold_delivery_files(owner,folder,raw) as delivery_verify:
                    consumed=set(delivered.event_ids)
                    result=tuple(dict(row[2]) for row in _settings(writer_token,delivered_event_ids=delivered.event_ids)
                                 if row[2]['event_id'] not in consumed)
                    verify(); start_verify(); delivery_verify()
    except Exception: failed=True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed=True
    if failed: raise SettingsAuditHold()
    return result


def read_current_k_after_completed_unit(writer_token,spreadsheet_token,binding,unit):
    """Highest original K under the same complete delivery pair; read only.

    No caller-provided consumed IDs, old-K fallback, file repair, cleanup,
    publication or release permission. Ordinary K readers remain strict.
    """
    folder=None; failed=False
    try:
        with _hold_delivery_authority(writer_token,spreadsheet_token,binding,unit,inspect_delivered=True) as (owner,raw,delivered,verify):
            with _hold_delivery_start(owner,raw) as (start_verify,raw):
                folder=local._directory(owner.root_fd,_DELIVERY_FOLDER)
                with _hold_delivery_files(owner,folder,raw) as delivery_verify:
                    with _hold_settings_originals(writer_token,delivered_event_ids=delivered.event_ids) as (images,settings_verify):
                        events,current,initialized,_outbox=images
                        result=chain.validate_k_chain_snapshot(events,current,initialized)
                        verify(); start_verify(); delivery_verify(); settings_verify()
    except Exception: failed=True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed=True
    if failed: raise SettingsAuditHold()
    return result
@contextmanager
def _hold_completed_k_pair(token,sheet,bound,unit):
    from monitor import issue_tracker_remote_history_match as completion
    from monitor import issue_tracker_state_owner as state_owner
    # Capture once. The discovery's own initial pair precedes enrollment, so
    # inner transaction pairs revalidate its held originals without recursion.
    outer=state_owner._COMPLETED_ORIGINAL_GUARDS.get(token)
    with ExitStack() as scope:
        match,_=scope.enter_context(completion._hold_match_originals(sheet,bound,unit))
        proof=scope.enter_context(completion._hold_completion_originals(sheet,bound,unit))
        seen=completion.inspect_completion_evidence(sheet,bound,unit)
        with _hold_delivery_authority(token,sheet,bound,unit,inspect_delivered=True) as (owner,raw,delivered,verify):
            verify()
        start,header=scope.enter_context(_hold_delivery_start(owner,raw))
        folder=local._directory(owner.root_fd,_DELIVERY_FOLDER)
        scope.callback(os.close,folder)
        delivery=scope.enter_context(_hold_delivery_files(owner,folder,header))
        original,allocation_header,assignments=_originals(token,sheet,bound,unit,delivered_event_ids=delivered.event_ids)
        if original is not owner: raise SettingsAuditHold()
        allocated=local._directory(owner.root_fd,_FOLDER); scope.callback(os.close,allocated)
        allocation=scope.enter_context(_hold_allocation_originals(owner.root_fd,allocated,allocation_header,assignments))
        def guard():
            if outer is not None: outer()
            if local._owner(token) is not owner: raise SettingsAuditHold()
            ownership._validated_owner(sheet,bound)
            match(); proof(); start(); delivery(); allocation()
            if completion.inspect_completion_evidence(sheet,bound,unit)!=seen: raise SettingsAuditHold()
            match(); proof(); start(); delivery(); allocation()
            if outer is not None: outer()
        guard(); yield owner,delivered,guard; guard()

@contextmanager
def _hold_discovered_completed_settings(writer):
    """Discover coordinates from held local originals, then prove the whole pair."""
    from monitor.issue_tracker_online_target import OnlineTargetBinding
    from monitor.issue_tracker_send_unit import _original_unit,_pairs,_nonfinite
    owner=local._owner(writer)
    with ExitStack() as scope:
        held=[]
        def directory(parent,name):
            fd=local._directory(parent,name); scope.callback(os.close,fd)
            info=local._check(fd,directory=True); journal._named(parent,name,fd,directory=True)
            held.append((parent,name,fd,True,journal._identity(info),None))
            return fd
        def file(parent,name,limit):
            fd=os.open(name,local._flags(),dir_fd=parent); scope.callback(os.close,fd)
            info=local._check(fd,directory=False); journal._named(parent,name,fd,directory=False)
            raw=os.pread(fd,limit+1,0)
            if not raw or len(raw)!=info.st_size or len(raw)>limit:
                raise SettingsAuditHold()
            held.append((parent,name,fd,False,journal._identity(info),raw))
            return raw
        def verify():
            if local._owner(writer) is not owner: raise SettingsAuditHold()
            for parent,name,fd,is_directory,identity,raw in held:
                local._check(fd,directory=is_directory)
                journal._named(parent,name,fd,directory=is_directory)
                if journal._identity(os.fstat(fd))!=identity: raise SettingsAuditHold()
                if not is_directory and os.pread(fd,len(raw)+1,0)!=raw:
                    raise SettingsAuditHold()
                journal._named(parent,name,fd,directory=is_directory)
                if journal._identity(os.fstat(fd))!=identity: raise SettingsAuditHold()
        markers={_DELIVERY_FOLDER,_DELIVERY_STARTED}
        if not markers.intersection(os.listdir(owner.root_fd)):
            # No durable delivery claim: preserve the ordinary strict K contract.
            def strict_verify():
                if markers.intersection(os.listdir(owner.root_fd)):
                    raise SettingsAuditHold()
                verify()
            yield None,strict_verify
            strict_verify()
            return
        folder=directory(owner.root_fd,_FOLDER)
        raw=file(folder,'HEADER',16384)
        header=json.loads(raw.decode('utf-8','strict'),object_pairs_hook=_pairs,parse_constant=_nonfinite)
        if type(header) is not dict or local._canonical(header)!=raw:
            raise SettingsAuditHold()
        project,tracker=os.fstat(owner.project_fd),os.fstat(owner.root_fd)
        if (header['project_identity']!=[project.st_dev,project.st_ino]
                or header['tracker_identity']!=[tracker.st_dev,tracker.st_ino]):
            raise SettingsAuditHold()
        bound=OnlineTargetBinding(header['spreadsheet_id'],header['allowlist_sha256'],header['policy_sha256'])
        sheet=scope.enter_context(ownership.spreadsheet_owner(bound))
        sheet_owner=ownership._validated_owner(sheet,bound)
        parent=sheet_owner.directories[-1][0]
        catalog_checks=[]
        unit_name=sheet_owner.lock_name[:-5]+'.journal'
        selected=None
        if global_journal._catalog_present(sheet_owner):
            from monitor import issue_tracker_unit_catalog as catalog
            # HEADER is a locator, never authority. Hold ALL original units,
            # attempts and genuine project C6 before selecting the one whose
            # original COMPLETE/DELIVERED pair excuses missing projections.
            states,counts_verify=scope.enter_context(global_journal._hold_catalog_attempts(sheet,bound))
            rows,c6_verify=scope.enter_context(catalog.hold_pending_project_c6_units(sheet,bound))
            if tuple(row.unit for row in rows)!=tuple(unit for unit,_state in states):
                raise SettingsAuditHold()
            matches=[row for row in rows if row.unit.unit_id==header['unit_id']]
            if len(matches)!=1: raise SettingsAuditHold()
            if matches[0].project_identity!=(project.st_dev,project.st_ino):
                raise SettingsAuditHold()
            selected=matches[0].unit
            unit_name=sheet_owner.lock_name[:-5]+'.unit-'+selected.unit_id+'.journal'
            catalog_checks.extend((counts_verify,c6_verify))
            for check in catalog_checks: check()
        unit_folder=directory(parent,unit_name)
        unit=_original_unit(file(unit_folder,'ACTION-PREIMAGE',_LIMIT),
                            file(unit_folder,'WIRE',_LIMIT))
        if selected is not None and unit!=selected: raise SettingsAuditHold()
        _owner,_delivered,pair_verify=scope.enter_context(_hold_completed_k_pair(writer,sheet,bound,unit))
        if _owner is not owner: raise SettingsAuditHold()
        def original_verify():
            verify()
            for check in catalog_checks: check()
            pair_verify()
            for check in catalog_checks: check()
            verify()
        original_verify()
        yield (sheet,bound,unit),original_verify
        original_verify()

class _CompletedSettingsTransition:
    def __init__(self,scope,owner,delivered):
        self.owner=owner; self.delivered=delivered; self.stage=0; self.added=[]
        self.directories=[]; self.files=[]; self.intent=None; self.intent_removed=False
        self.scope=scope; self.archive=None; self.guard_archive=None; self.pointer_archive=None
        self.archive_moved_names=set()
        def directory(parent,name):
            fd=local._directory(parent,name); scope.callback(os.close,fd)
            journal._named(parent,name,fd,directory=True)
            self.directories.append((parent,name,fd,journal._identity(os.fstat(fd))[:5]))
            return fd
        def file(parent,name):
            fd=os.open(name,local._flags(),dir_fd=parent); scope.callback(os.close,fd)
            info=local._check(fd,directory=False); journal._named(parent,name,fd,directory=False)
            raw=os.pread(fd,16385,0)
            if len(raw)!=info.st_size or len(raw)>16384: raise SettingsAuditHold()
            self.files.append((parent,name,fd,journal._identity(info),raw))
            return raw
        self.settings=directory(owner.root_fd,'settings')
        self.events=directory(self.settings,'events'); self.outbox=directory(self.settings,'outbox')
        if set(os.listdir(self.settings))!={'events','outbox','current'}: raise SettingsAuditHold()
        self.event_names=set(os.listdir(self.events)); self.outbox_names=set(os.listdir(self.outbox))
        if (not self.event_names or any(settings._EVENT_NAME.fullmatch(n) is None for n in self.event_names)
                or not self.outbox_names <= self.event_names): raise SettingsAuditHold()
        self.images={int(n[:-5]):file(self.events,n) for n in sorted(self.event_names)}
        self.pointer=file(self.settings,'current'); self.old_pointer=self.files[-1]
        initialized=file(owner.root_fd,'INITIALIZED')
        self.state=chain.validate_k_chain_snapshot(self.images,self.pointer,initialized)
        missing={f'settings:{rev}:'+hashlib.sha256(raw).hexdigest() for rev,raw in self.images.items()
                 if f'{rev}.json' not in self.outbox_names}
        if not missing<=set(delivered.event_ids): raise SettingsAuditHold()
        for name in sorted(self.outbox_names):
            raw=file(self.outbox,name); rev=int(name[:-5])
            if raw!=chain._canonical_line({'schema_version':1,'revision':rev,
                    'event_sha256':hashlib.sha256(self.images[rev]).hexdigest()}): raise SettingsAuditHold()
        self.name=f'{self.state.revision+1}.json'; self.verify()
    def verify(self):
        for parent,name,fd,identity in self.directories:
            local._check(fd,directory=True); journal._named(parent,name,fd,directory=True)
            if journal._identity(os.fstat(fd))[:5]!=identity: raise SettingsAuditHold()
        expected={'events','outbox','current'}
        if self.intent is not None and not self.intent_removed: expected.add(self.intent[1])
        if set(os.listdir(self.settings))!=expected: raise SettingsAuditHold()
        if set(os.listdir(self.events))!=self.event_names|({self.name} if self.stage>=1 else set()): raise SettingsAuditHold()
        if set(os.listdir(self.outbox))!=self.outbox_names|({self.name} if self.stage>=2 else set()): raise SettingsAuditHold()
        for entry in self.files+self.added+([self.intent] if self.intent is not None else []):
            parent,name,fd,identity,raw=entry
            if self.intent_removed and entry is self.intent:
                # The guard was recoverably moved, never deleted by pathname.
                continue
            if self.stage==3 and entry is self.old_pointer:
                # The retained original pointer is now in private quarantine;
                # validate that exact archive below, never unlink its name.
                if self.pointer_archive is None: raise SettingsAuditHold()
                continue
            local._check(fd,directory=False); journal._named(parent,name,fd,directory=False)
            if journal._identity(os.fstat(fd))!=identity or os.pread(fd,16385,0)!=raw: raise SettingsAuditHold()
            journal._named(parent,name,fd,directory=False)
        if self.archive is not None:
            local._check(self.archive,directory=True)
            journal._named(self.owner.root_fd,'quarantine',self.archive,directory=True)
            if (journal._identity(os.fstat(self.archive))[:5]!=self.archive_identity
                    or set(os.listdir(self.archive))!=self.archive_names|self.archive_moved_names):
                raise SettingsAuditHold()
            for name,fd,identity in self.archive_files:
                local._check(fd,directory=False); journal._named(self.archive,name,fd,directory=False)
                if journal._identity(os.fstat(fd))!=identity: raise SettingsAuditHold()
        for archived in (self.guard_archive,self.pointer_archive):
            if archived is None: continue
            parent,name,fd,identity,raw=archived
            local._check(fd,directory=False); journal._named(parent,name,fd,directory=False)
            if journal._identity(os.fstat(fd))!=identity or os.pread(fd,16385,0)!=raw: raise SettingsAuditHold()
    def _open_archive(self):
        if self.archive is not None: return
        self.archive=local._directory(self.owner.root_fd,'quarantine')
        self.scope.callback(os.close,self.archive)
        journal._named(self.owner.root_fd,'quarantine',self.archive,directory=True)
        self.archive_identity=journal._identity(os.fstat(self.archive))[:5]
        if os.fstat(self.archive).st_dev!=os.fstat(self.settings).st_dev: raise SettingsAuditHold()
        self.archive_names=set(os.listdir(self.archive)); self.archive_files=[]
        for name in sorted(self.archive_names):
            fd=os.open(name,local._flags(),dir_fd=self.archive); self.scope.callback(os.close,fd)
            info=local._check(fd,directory=False); journal._named(self.archive,name,fd,directory=False)
            self.archive_files.append((name,fd,journal._identity(info)))
    def begin(self,scope,raw):
        # A persisted guard makes even a coherent-looking failed pointer update
        # unadoptable by existing warm/cold strict settings readers.
        name='.pending-K-change-'+uuid.uuid4().hex
        fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
                   0o600,dir_fd=self.settings)
        scope.callback(os.close,fd)
        remaining=memoryview(raw)
        while remaining:
            wrote=os.write(fd,remaining)
            if wrote<=0: raise SettingsAuditHold()
            remaining=remaining[wrote:]
        os.fsync(fd); os.fsync(self.settings)
        local._check(fd,directory=False); journal._named(self.settings,name,fd,directory=False)
        if os.pread(fd,16385,0)!=raw: raise SettingsAuditHold()
        self.intent=(self.settings,name,fd,journal._identity(os.fstat(fd)),raw)
        self.intent_removed=False; self.verify()
    def finish(self):
        self.verify()
        # These bytes come from retained, rechecked immutable file descriptors.
        images=dict(self.images)
        images[self.state.revision+1]=self.added[0][4]
        initialized=next(entry[4] for entry in self.files if entry[1]=='INITIALIZED')
        chain.validate_k_chain_snapshot(images,self.added[2][4],initialized)
        # A held original check followed by unlink would erase a replacement
        # inserted at the last pathname boundary. Retain the actual object in
        # the existing private same-device quarantine, atomically NOREPLACE.
        self._open_archive()
        self.verify()
        self.archive_name='completed-K-change-guard-'+uuid.uuid4().hex
        parent,name,fd,identity,raw=self.intent
        local._rename_new(parent,name,self.archive_name,destination_parent=self.archive)
        # Even a post-rename identity/barrier failure must retain a fresh STOP
        # guard; never overwrite or remove the object that was actually moved.
        self.intent_removed=True
        self.archive_moved_names.add(self.archive_name)
        journal._named(self.archive,self.archive_name,fd,directory=False)
        info=journal._identity(os.fstat(fd))
        if info[:-1]!=identity[:-1] or os.pread(fd,16385,0)!=raw: raise SettingsAuditHold()
        self.guard_archive=(self.archive,self.archive_name,fd,info,raw)
        os.fsync(self.settings); os.fsync(self.archive)
        self.verify()
    def retain_failed_guard(self,scope):
        if self.intent is None or not self.intent_removed: return
        # Never roll back committed evidence or overwrite a foreign guard. A
        # one-shot cleanup failure is conservatively recorded as unresolved.
        parent,name,fd,identity,raw=self.intent
        journal._named(self.owner.root_fd,'settings',self.settings,directory=True)
        self.begin(scope,raw)
    def install(self,scope,parent,name,raw,*,replace=False):
        temporary='.pending-'+uuid.uuid4().hex
        fd=os.open(temporary,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
        scope.callback(os.close,fd)
        remaining=memoryview(raw)
        while remaining:
            wrote=os.write(fd,remaining)
            if wrote<=0: raise SettingsAuditHold()
            remaining=remaining[wrote:]
        os.fsync(fd); journal._named(parent,temporary,fd,directory=False)
        if os.pread(fd,16385,0)!=raw: raise SettingsAuditHold()
        if replace:
            if parent!=self.settings or name!='current' or self.pointer_archive is not None:
                raise SettingsAuditHold()
            self._open_archive()
            archived='completed-K-change-current-'+uuid.uuid4().hex
            old_parent,old_name,old_fd,identity,old_raw=self.old_pointer
            local._rename_new(old_parent,old_name,archived,destination_parent=self.archive)
            self.archive_moved_names.add(archived)
            journal._named(self.archive,archived,old_fd,directory=False)
            info=journal._identity(os.fstat(old_fd))
            if info[:-1]!=identity[:-1] or os.pread(old_fd,16385,0)!=old_raw: raise SettingsAuditHold()
            self.pointer_archive=(self.archive,archived,old_fd,info,old_raw)
            # Both old-pointer namespaces must be durable before installing the
            # new current. Any collision preserves the actual foreign object.
            os.fsync(parent); os.fsync(self.archive)
            local._rename_new(parent,temporary,name)
            local._check(fd,directory=False); journal._named(parent,name,fd,directory=False)
            os.fsync(parent)
        else:
            # No unlink-by-inode exists for an interveningly replaced temporary
            # pathname. Atomically install without replacing an existing name,
            # then retain/recheck this exact installed FD across both barriers.
            local._rename_new(parent,temporary,name)
            local._check(fd,directory=False); journal._named(parent,name,fd,directory=False)
            os.fsync(parent)
            journal._named(parent,name,fd,directory=False); os.fsync(fd)
        local._check(fd,directory=False); journal._named(parent,name,fd,directory=False)
        if os.pread(fd,16385,0)!=raw: raise SettingsAuditHold()
        self.added.append((parent,name,fd,journal._identity(os.fstat(fd)),raw))

def _apply_completed_k_change(token,sheet,bound,unit,*,new_k,actor,recorded_at,request_id,expected_revision):
    chain._positive_int(new_k); chain._actor(actor); chain._time(recorded_at)
    chain._request_id(request_id); chain._revision(expected_revision)
    if actor=='system:default': raise SettingsAuditHold()
    payload=chain._canonical_line({'new_k':new_k,'actor':actor,
        'expected_revision':expected_revision,'request_id':request_id})
    payload_digest=hashlib.sha256(payload).hexdigest()
    with ExitStack() as scope:
        pair_scope=ExitStack(); scope.callback(pair_scope.close)
        owner,delivered,proof=pair_scope.enter_context(_hold_completed_k_pair(token,sheet,bound,unit))
        before=_CompletedSettingsTransition(scope,owner,delivered)
        for rev,raw in before.images.items():
            row=chain._parse(raw,chain._EVENT_KEYS)
            if row['request_id']==request_id:
                if rev==0 or row['payload_sha256']!=payload_digest: raise settings.KChangeConflict('request payload conflict')
                proof(); before.verify(); pair_scope.close(); before.verify()
                return settings.KStoreReceipt(rev,row['new_k'],hashlib.sha256(raw).hexdigest(),replay=True)
        if expected_revision!=before.state.revision: raise settings.KChangeConflict('stale expected revision')
        revision=before.state.revision+1
        event=chain._canonical_line({'schema_version':1,'revision':revision,'type':'set_k','old_k':before.state.k,
            'new_k':new_k,'actor':actor,'recorded_at':recorded_at,'request_id':request_id,
            'payload_sha256':payload_digest,'predecessor_sha256':before.state.event_sha256})
        digest=hashlib.sha256(event).hexdigest()
        pointer=chain._canonical_line({'schema_version':1,'revision':revision,'event_sha256':digest})
        intent=chain._canonical_line({'schema_version':1,'request_id':request_id,
            'payload_sha256':payload_digest,'expected_revision':expected_revision,
            'event_sha256':digest,'predecessor_sha256':before.state.event_sha256})
        proof(); before.verify(); before.begin(scope,intent); proof()
        try:
            for parent,name,raw,stage,replace in ((before.events,before.name,event,1,False),
                    (before.outbox,before.name,pointer,2,False),(before.settings,'current',pointer,3,True)):
                proof(); before.verify()
                before.install(scope,parent,name,raw,replace=replace); before.stage=stage
                before.verify(); proof()
            before.verify(); proof(); before.finish(); proof()
            with _hold_settings_originals(token,delivered_event_ids=delivered.event_ids) as (images,verify):
                events,current,initialized,_=images
                state=chain.validate_k_chain_snapshot(events,current,initialized)
                if (state.revision,state.k,state.event_sha256)!=(revision,new_k,digest): raise SettingsAuditHold()
                verify(); before.verify(); proof()
                # Recheck/close the paired original proof while the transition
                # FDs are still alive, so a final-scope failure retains STOP too.
                pair_scope.close(); before.verify(); verify()
        except BaseException:
            before.retain_failed_guard(scope)
            raise
        return settings.KStoreReceipt(revision,new_k,digest)


class _CompletedOutboxCleanup(_CompletedSettingsTransition):
    """Recoverably archive only projections bound to the original delivered unit."""
    def __init__(self,scope,owner,delivered):
        # Base construction calls verify before the archive scope exists.
        self.cleanup_archive=None
        self.archived=set()
        super().__init__(scope,owner,delivered)
        self.cleanup_archive=local._directory(owner.root_fd,'quarantine')
        scope.callback(os.close,self.cleanup_archive)
        journal._named(owner.root_fd,'quarantine',self.cleanup_archive,directory=True)
        self.cleanup_archive_identity=journal._identity(os.fstat(self.cleanup_archive))[:5]
        if os.fstat(self.cleanup_archive).st_dev!=os.fstat(self.outbox).st_dev:
            raise SettingsAuditHold()
        self.cleanup_archive_names=set(os.listdir(self.cleanup_archive))
        self.cleanup_archive_files=[]
        for name in sorted(self.cleanup_archive_names):
            fd=os.open(name,local._flags(),dir_fd=self.cleanup_archive)
            scope.callback(os.close,fd)
            info=local._check(fd,directory=False)
            journal._named(self.cleanup_archive,name,fd,directory=False)
            self.cleanup_archive_files.append((name,fd,journal._identity(info)))
        self.verify()

    def verify(self):
        super().verify()
        if self.cleanup_archive is None:
            return
        local._check(self.cleanup_archive,directory=True)
        journal._named(self.owner.root_fd,'quarantine',self.cleanup_archive,directory=True)
        if (journal._identity(os.fstat(self.cleanup_archive))[:5]!=self.cleanup_archive_identity
                or set(os.listdir(self.cleanup_archive))!=self.cleanup_archive_names|self.archived):
            raise SettingsAuditHold()
        for name,fd,identity in self.cleanup_archive_files:
            local._check(fd,directory=False)
            journal._named(self.cleanup_archive,name,fd,directory=False)
            if journal._identity(os.fstat(fd))!=identity:
                raise SettingsAuditHold()

    def move_original(self,entry):
        parent,name,fd,identity,raw=entry
        self.verify()
        destination='completed-settings-'+uuid.uuid4().hex+'-'+name
        # NOREPLACE preserves existing archives. A substituted source may move
        # but is never erased; acknowledgement requires the retained original FD.
        local._rename_new(parent,name,destination,destination_parent=self.cleanup_archive)
        local._check(fd,directory=False)
        journal._named(self.cleanup_archive,destination,fd,directory=False)
        info=journal._identity(os.fstat(fd))
        if info[:-1]!=identity[:-1] or os.pread(fd,16385,0)!=raw:
            raise SettingsAuditHold()
        self.files[self.files.index(entry)]=(self.cleanup_archive,destination,fd,info,raw)
        self.outbox_names.remove(name)
        self.archived.add(destination)
        self.verify()
        os.fsync(parent)
        os.fsync(self.cleanup_archive)
        self.verify()


def cleanup_completed_settings_outbox(token,sheet,bound,unit):
    """Archive actual delivered projections, never resend or release a unit.

    Requires both actual owners and their original COMPLETE/DELIVERED evidence.
    Failure retains moved originals without acknowledgement. Replay only syncs
    existing directories; it cannot manufacture missing evidence or projections.
    """
    try:
        with ExitStack() as scope:
            pair=ExitStack()
            scope.callback(pair.close)
            owner,delivered,proof=pair.enter_context(_hold_completed_k_pair(token,sheet,bound,unit))
            transition=_CompletedOutboxCleanup(scope,owner,delivered)
            selected={f'{rev}.json' for rev,raw in transition.images.items()
                if 'settings:'+str(rev)+':'+hashlib.sha256(raw).hexdigest() in delivered.event_ids}
            entries=[entry for entry in transition.files
                if entry[0]==transition.outbox and entry[1] in selected]
            for entry in entries:
                proof(); transition.verify()
                transition.move_original(entry)
                proof(); transition.verify()
            os.fsync(transition.outbox); os.fsync(transition.cleanup_archive)
            proof(); transition.verify()
            result=inspect_completed_settings_delivery(token,sheet,bound,unit)
            if result.state!='DELIVERED-PRESENT-OUTBOX-ABSENT-VALID':
                raise SettingsAuditHold()
            proof(); transition.verify(); pair.close(); transition.verify()
            return result
    except Exception as exc:
        raise SettingsAuditHold() from exc


def apply_completed_k_change(token,sheet,bound,unit,*,new_k,actor,recorded_at,request_id,expected_revision):
    """Local K mutation under the actual original COMPLETE/DELIVERED pair.

    No consumed-ID override, cleanup, resend, UNKNOWN release or actor trust
    is granted. A failed required write retains a persistent unexplained guard;
    ordinary readers and fresh completed-pair owners must both HOLD on it.
    """
    try:
        return _apply_completed_k_change(token,sheet,bound,unit,new_k=new_k,actor=actor,
            recorded_at=recorded_at,request_id=request_id,expected_revision=expected_revision)
    except settings.KChangeConflict:
        # The established relay completes only proved pre-mutation conflicts;
        # unsafe state/barriers remain claimed UNKNOWN, not completed HOLD.
        raise
    except Exception as exc:
        raise SettingsAuditHold() from exc
