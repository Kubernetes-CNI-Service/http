"""Uninstalled C25 original-event allocation under BOTH actual owners.

The legacy journal retains one unit per project; native allocations bind each
frozen catalog unit. The delivery bridge requires original C19 COMPLETE before
DELIVERED record. A separate paired cleanup archives only those delivered
projections; it never sends, deletes originals, repairs a partial journal,
authorizes a source or releases UNKNOWN/FIFO/admission barriers.
"""
import hashlib
import json
import os
import stat
import threading
import uuid
from contextlib import contextmanager, ExitStack
from contextvars import ContextVar
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace

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
_NATIVE_SETTINGS_CONTEXT = ContextVar('req7_native_settings_original_context',default=None)
_LIVE_NATIVE_SETTINGS_CONTEXTS = {}
_LOCAL_C6_CONTEXT = ContextVar('req7_completed_local_c6_originals', default=None)
_LIVE_LOCAL_C6_CONTEXTS = {}
_DELIVERY_CREATOR_CONTEXT = ContextVar('req7_native_delivery_creator_originals',default=None)
_LIVE_DELIVERY_CREATORS = {}


class _CompletedLocalC6Context:
    """Fixed local C6 read enrollment; never a settings or online allowance."""
    __slots__ = ()


class _NativeCompletedSettingsContext:
    """Opaque LIVE factory identity; no public events or transferable permit."""
    __slots__ = ()


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
            if type(context) is _NativeCompletedSettingsContext:
                _native_settings_packet(writer_token,context)
            elif any(packet['token'] is writer_token for packet in _LIVE_NATIVE_SETTINGS_CONTEXTS.values()):
                raise SettingsAuditHold()
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
        if type(context) is _NativeCompletedSettingsContext:
            result=_pending_native_completed_settings(writer_token,context)
        elif context is not None and guard is not None:
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
    with _hold_native_catalog_audit_originals(writer_token,spreadsheet_token,binding,unit,
                                              delivered_event_ids=delivered_event_ids) as native:
        if native is not None:
            verify=native[3];verify()
            yield verify
            verify()
            return
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
    with _hold_native_catalog_audit_originals(writer_token,spreadsheet_token,binding,unit) as native:
        if native is not None:
            native[3]()
            return native[2]
    return _observe(writer_token, spreadsheet_token, binding, unit, create=False)


@contextmanager
def _hold_native_catalog_audit_originals(writer,token,binding,unit,*,delivered_event_ids=()):
    failed=False
    try:
        with _hold_anchored_native_audit_originals(writer,token,binding,unit,
                delivered_event_ids=delivered_event_ids) as originals:
            yield originals
    except Exception:failed=True
    # Preserve the public safe HOLD contract, not another module's details.
    # Operator interruptions are not converted into successful observations.
    if failed:raise SettingsAuditHold()


@contextmanager
def _hold_anchored_native_audit_originals(writer,token,binding,unit,*,delivered_event_ids=()):
    """COUNT/CLAIM always retains strict mutable settings as well as originals."""
    with _hold_native_catalog_allocation_images(writer,token,binding,unit) as native:
        if native is None:
            yield None
            return
        with _hold_settings_originals(writer,delivered_event_ids=delivered_event_ids) as (_images,settings_verify):
            project,header,assignments,graph_verify=native
            def verify():
                graph_verify();settings_verify();graph_verify()
                events={row[2]['event_id']:row[2] for row in _settings(writer,delivered_event_ids=delivered_event_ids)}
                if any(events.get(row['audit']['event_id'])!=row['audit']
                        for row in json.loads(assignments.decode('utf-8'))):raise SettingsAuditHold()
                settings_verify();graph_verify()
            verify()
            yield project,header,assignments,verify
            verify()


@contextmanager
def _hold_native_catalog_allocation_images(writer,token,binding,unit):
    """Hold immutable native allocation/C6/events, never mutable K or outbox.

    Only an actual catalog HEADER selects this branch. An explicit old legacy
    C6 bridge remains legacy; a broken native anchor never falls back. Mutable
    journal/CLAIM/settings images are guarded by their actual counted holder or
    completed-pair transition. This leaf alone grants no delivery or mutation.
    """
    from monitor import issue_tracker_unit_catalog as catalog
    project=local._owner(writer);sheet=ownership._validated_owner(token,binding)
    if not global_journal._catalog_present(sheet):
        yield None
        return
    with ExitStack() as scope:
        held=catalog._Originals();last_check=None;ancestors=[]
        def close_ancestors(exc_type,exc,tb):
            problem=None
            for _parent,_name,descriptor,info in reversed(ancestors):
                try:local._close_written_original(descriptor,info)
                except BaseException as refused:
                    if problem is None:problem=refused
            if problem is not None and exc is None:raise problem
            return False
        # Ancestors outlive the final C6/immutable graph check, but their
        # cleanup still runs if an earlier graph finalizer refuses/interupts.
        scope.push(close_ancestors)
        def close_originals(exc_type,exc,tb):
            primary=exc;primary_tb=tb
            try:
                # Run after all genuine C6/settings finalizers, while the
                # immutable catalog/origin/allocation FDs remain original.
                # Do not call already-closed subordinate verifiers or mask
                # an operator interruption with an ordinary cleanup refusal.
                if exc_type is None and last_check is not None:last_check()
            except BaseException as refused:
                primary=refused;primary_tb=refused.__traceback__
            try:held.close()
            except BaseException as refused:
                if primary is exc and primary is not None:
                    # Returning False propagates the original object without
                    # raising it inside ExitStack's own context repair (which
                    # can form a cycle with the cleanup's context).
                    primary.__cause__=refused;primary.__suppress_context__=True
                    return False
                if primary is not None:raise primary.with_traceback(primary_tb) from refused
                raise
            if primary is not None and primary is not exc:raise primary.with_traceback(primary_tb)
            return False
        scope.push(close_originals)
        _folder,units,_previous=catalog._inspect(token,binding,held)
        if unit not in units: raise SettingsAuditHold()
        parent=sheet.directories[-1][0];stem=sheet.lock_name[:-5]
        folders=[fd for _parent,name,fd,_identity,_names in held.directories if name==unit.unit_id]
        if len(folders)!=1: raise SettingsAuditHold()
        headers=[raw for p,name,_fd,_identity,raw in held.files if p==folders[0] and name=='HEADER']
        if len(headers)!=1: raise SettingsAuditHold()
        if local._json(headers[0]).get('settings_allocation') is None:
            # Do not carry a strict shared namespace across legacy COUNT.
            scope.close()
            yield None
            return
        global_journal.inspect_global_unit(token,binding,unit);held.verify()
        with catalog.hold_pending_project_origins(token,binding) as (origins,verify_origins):
            if tuple(row.unit for row in origins)!=units: raise SettingsAuditHold()
            captured={name for p,name,_fd,_identity,_names in held.directories if p==parent}
            for older in units:
                name=stem+'.unit-'+older.unit_id+'.project-origin'
                if name not in captured:
                    origin=held.directory(parent,name)
                    for entry in ('WITNESS','STARTED','ORIGIN'):held.file(origin,entry,local._MAX_MANIFEST)
            rows,verify_c6=scope.enter_context(catalog._hold_project_c6_from_origins(token,binding,origins))
            verify_origins();held.verify();verify_c6()
        selected=origins[units.index(unit)]
        if (selected.project_identity!=journal._identity(os.fstat(project.project_fd))[:2]
                or selected.tracker_identity!=journal._identity(os.fstat(project.root_fd))[:2]
                or tuple(row.unit for row in rows)!=units): raise SettingsAuditHold()
        audits=local._json(unit.action_preimage)['audits']
        if not audits:raise SettingsAuditHold()
        name=stem+'.unit-'+unit.unit_id+'.settings-audit'
        allocated=[fd for p,child,fd,_identity,_names in held.directories if p==parent and child==name]
        if len(allocated)!=1:raise SettingsAuditHold()
        images={child:raw for p,child,_fd,_identity,raw in held.files if p==allocated[0]}
        header=images['HEADER'];assignments=images['ASSIGNMENTS']
        if (header!=_native_header(unit,binding,selected.project_identity,selected.tracker_identity)
                or assignments!=_native_assignments(unit)):raise SettingsAuditHold()
        # A completed transaction may append later events and move delivered
        # projections. Pin the selected immutable EVENTs and their actual
        # ancestors, not a snapshot of mutable current/outbox or event names.
        def hold_ancestor(ancestor_parent,ancestor_name):
            # Register a cleanup-only named candidate before the first
            # post-return stat. It is never verification authority: a changed
            # inode is refused and conditional cleanup never closes a foreign FD.
            named=journal._identity(os.stat(ancestor_name,dir_fd=ancestor_parent,follow_symlinks=False))
            descriptor,acquired=local._directory(ancestor_parent,ancestor_name,_return_original=True)
            ancestors.append((ancestor_parent,ancestor_name,descriptor,acquired[:5]))
            info=journal._identity(os.fstat(descriptor))
            if info[:5]!=acquired[:5] or acquired[:5]!=named[:5]:raise SettingsAuditHold()
            ancestors[-1]=(ancestor_parent,ancestor_name,descriptor,info[:5])
            return descriptor
        settings_fd=hold_ancestor(project.root_fd,'settings')
        events_fd=hold_ancestor(settings_fd,'events')
        for row in json.loads(assignments.decode('utf-8')):
            raw,_identity=held.file(events_fd,str(row['revision'])+'.json',16384)
            if (raw!=(row['audit']['details']+'\n').encode('utf-8')
                    or hashlib.sha256(raw).hexdigest()!=row['event_sha256']):raise SettingsAuditHold()
        # The exact selected dispatch may be created by its genuine CLAIM
        # writer. No other new family/unit/position is tolerated by this scope;
        # this allowance itself is not dispatch, count or sending authority.
        dispatch=stem+'.unit-'+unit.unit_id+'.dispatch'
        before=held.namespace[2];alive=True
        def verify_graph():
            if (local._owner(writer) is not project
                    or ownership._validated_owner(token,binding) is not sheet):raise SettingsAuditHold()
            for ancestor_parent,ancestor_name,descriptor,info in ancestors:
                local._check(descriptor,directory=True)
                journal._named(ancestor_parent,ancestor_name,descriptor,directory=True)
                if journal._identity(os.fstat(descriptor))[:5]!=info:raise SettingsAuditHold()
            additions={dispatch} if dispatch not in before and dispatch in os.listdir(parent) else set()
            held.verify(parent_additions=additions)
        def verify():
            if not alive:raise SettingsAuditHold()
            verify_graph();verify_c6();verify_graph()
            additions={dispatch} if dispatch not in before and dispatch in os.listdir(parent) else set()
            held.verify(parent_additions=additions)
        last_check=verify_graph
        held.sync();verify()
        try:
            yield project,header,assignments,verify
            verify()
        finally:alive=False


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
    delivered_events=_native_allocation_prior_events(prepared,writer,token,binding)
    _images,verify=record['settings_scope'].enter_context(
        _hold_settings_originals(writer,delivered_event_ids=delivered_events))
    events=_settings(writer,delivered_event_ids=delivered_events)
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
def _hold_delivery_allocation_originals(writer,sheet,bound,unit,*,delivered_event_ids=()):
    """Select original native bytes, or the explicit original legacy bridge.

    The native holder alone decides whether an anchored native allocation is
    present. A broken native graph is never a reason to reconstruct legacy
    bytes or drop its held verifier. Both branches stay live through consumers.
    """
    with _hold_native_catalog_audit_originals(writer,sheet,bound,unit,
            delivered_event_ids=delivered_event_ids) as native:
        if native is not None:
            native[3]()
            yield native
            native[3]()
            return
    with ExitStack() as scope:
        verify=scope.enter_context(_hold_counted_audit_originals(writer,sheet,bound,unit,
            delivered_event_ids=delivered_event_ids))
        owner,header,assignments=_originals(writer,sheet,bound,unit,
            delivered_event_ids=delivered_event_ids)
        verify()
        yield owner,header,assignments,verify
        verify()


@contextmanager
def _hold_delivery_catalog_replay(sheet,bound,unit):
    """Reuse only the actual live immutable catalog issuer; never a proof/GO.

    Delivery repeatedly interprets the same completion/catalog graph. Keep
    its original images across those reads rather than reparsing/reopening
    them. Every borrow still checks all originals and exact issuer identity;
    mutable counts, COMPLETE/DELIVERED, C6 and K transactions stay independent.
    """
    with ExitStack() as scope:
        if global_journal._HELD_CATALOG_REPLAY.get() is None:
            verify=scope.enter_context(global_journal._hold_native_catalog_replay(sheet,bound,unit))
        else:
            units,verify=scope.enter_context(global_journal._hold_catalog_originals(sheet,bound))
            if unit not in units:raise SettingsAuditHold()
        verify()
        yield verify
        verify()


def _delivery_complete_allocation_body(unit,header,assignments,seen,folder):
    """Encode actual held images; the bytes themselves grant no permission."""
    proof_files={file:{'identity':list(journal._identity(os.stat(file,dir_fd=folder,follow_symlinks=False))),
                      'sha256':hashlib.sha256(journal._read(folder,file,2*1024*1024)).hexdigest()}
                 for file in sorted(os.listdir(folder))}
    body={'schema_version':1,'unit_id':unit.unit_id,
        'allocation_header_sha256':hashlib.sha256(header).hexdigest(),
        'assignments_sha256':hashlib.sha256(assignments).hexdigest(),
        'completion_header_sha256':seen.header_sha256,
        'completion_directory_identity':list(journal._identity(os.fstat(folder))[:2]),
        'completion_originals':proof_files}
    allocation_image=local._json(header)
    if allocation_image.get('state')=='NATIVE_SETTINGS_ALLOCATION':
        if local._canonical(allocation_image)!=header:raise SettingsAuditHold()
        body['native_allocation_header']=allocation_image
        if all(row['revision']!=0 for row in json.loads(assignments.decode('utf-8'))):
            body['native_delivery_unit_id']=unit.unit_id
    return local._canonical(body)


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
            scope.enter_context(_hold_delivery_catalog_replay(spreadsheet_token,binding,unit))
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
            owner,header,assignments,audit_verify=scope.enter_context(
                _hold_delivery_allocation_originals(writer_token,spreadsheet_token,binding,unit,
                    delivered_event_ids=delivered_ids))
            _sheet,parent,name,_binding=global_journal._inputs(spreadsheet_token,binding,unit)
            name=name[:-len('.journal')]+'.completion'
            folder=local._directory(parent,name)
            raw=_delivery_complete_allocation_body(unit,header,assignments,seen,folder)
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


def _delivery_names(raw):
    """Coordinates from actual rederived proof bytes, never caller paths."""
    saved=local._json(raw)
    if type(saved) is not dict or local._canonical(saved)!=raw:raise SettingsAuditHold()
    if 'complete_allocation' in saved:
        if (set(saved)!={'schema_version','complete_allocation','delivery_start_identity'}
                or type(saved['schema_version']) is not int or saved['schema_version']!=1):raise SettingsAuditHold()
        body=saved['complete_allocation']
    else:body=saved
    if (type(body) is not dict or type(body.get('schema_version')) is not int or body['schema_version']!=1
            or set(body)-{'schema_version','unit_id','allocation_header_sha256','assignments_sha256',
                'completion_header_sha256','completion_directory_identity','completion_originals',
                'native_allocation_header','native_delivery_unit_id'}):raise SettingsAuditHold()
    if 'native_allocation_header' in body:
        header=body['native_allocation_header']
        if (type(header) is not dict or header.get('state')!='NATIVE_SETTINGS_ALLOCATION'
                or header.get('unit_id')!=body.get('unit_id')
                or hashlib.sha256(local._canonical(header)).hexdigest()!=body.get('allocation_header_sha256')):
            raise SettingsAuditHold()
    if 'native_delivery_unit_id' not in body:return _DELIVERY_FOLDER,_DELIVERY_STARTED
    unit=body['native_delivery_unit_id'];header=body.get('native_allocation_header')
    if (type(unit) is not str or len(unit)!=64 or any(char not in '0123456789abcdef' for char in unit)
            or type(header) is not dict or header.get('state')!='NATIVE_SETTINGS_ALLOCATION'
            or unit!=body.get('unit_id') or unit!=header.get('unit_id')):raise SettingsAuditHold()
    return _DELIVERY_FOLDER+'-'+unit,_DELIVERY_STARTED+'-'+unit


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
        _folder,started_name=_delivery_names(raw)
        fd=os.open(started_name,local._flags()|os.O_NONBLOCK,dir_fd=owner.root_fd)
        info=local._check(fd,directory=False); identity=journal._identity(info)
        if written is not None and identity!=written: raise SettingsAuditHold()
        expected=_delivery_start_raw(raw)
        def verify():
            journal._named(owner.root_fd,started_name,fd,directory=False)
            if journal._identity(os.fstat(fd))!=identity or os.pread(fd,16385,0)!=expected:
                raise SettingsAuditHold()
            journal._named(owner.root_fd,started_name,fd,directory=False)
            if journal._identity(os.fstat(fd))!=identity: raise SettingsAuditHold()
        verify(); os.fsync(fd); os.fsync(owner.root_fd); verify()
        header=local._canonical({'schema_version':1,'complete_allocation':json.loads(raw.decode('utf-8')),
            'delivery_start_identity':list(identity)})
        yield verify,header
        verify()
    finally:
        if fd is not None: os.close(fd)


def _write_delivery_file(parent,name,raw,*,_creator=None):
    """Fixed exclusive file; failed writes retain partial evidence, never adopt."""
    if type(raw) is not bytes or not 1<=len(raw)<=16384: raise SettingsAuditHold()
    local._flags()
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
    close_identity=None;primary=None
    try:
        if _creator is not None:
            # Named candidate is cleanup provenance only. It must match the
            # actual first checked FD before any write or original enrollment.
            close_identity=journal._identity(os.stat(name,dir_fd=parent,follow_symlinks=False))
        original=journal._identity(local._check(fd,directory=False))
        if _creator is not None:
            if original[:2]!=close_identity[:2]:raise SettingsAuditHold()
            close_identity=original
        journal._named(parent,name,fd,directory=False)
        remaining=memoryview(raw)
        while remaining:
            count=os.write(fd,remaining)
            if count<=0: raise SettingsAuditHold()
            remaining=remaining[count:]
        identity=journal._identity(os.fstat(fd))
        os.fsync(fd); os.fsync(parent)
        journal._named(parent,name,fd,directory=False)
        if journal._identity(os.fstat(fd))!=identity: raise SettingsAuditHold()
        if _creator is not None:
            _creator.capture_written(parent,name,fd,identity,raw)
        return identity
    except BaseException as refused:
        primary=refused;raise
    finally:
        if _creator is None:os.close(fd)
        else:
            try:
                if close_identity is None:raise SettingsAuditHold()
                local._close_written_original(fd,close_identity)
            except BaseException as refused:
                if primary is None:raise
                primary.__cause__=refused;primary.__suppress_context__=True


@contextmanager
def _hold_delivery_header(owner,folder,raw,identity):
    """The first-written HEADER stays original before/through DELIVERED."""
    fd=None
    try:
        folder_name,_started=_delivery_names(raw)
        fd=os.open('HEADER',local._flags(),dir_fd=folder)
        local._check(fd,directory=False)
        def verify():
            journal._named(owner.root_fd,folder_name,folder,directory=True)
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
        folder_name,_started=_delivery_names(raw)
        journal._named(owner.root_fd,folder_name,folder,directory=True)
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
            journal._named(owner.root_fd,folder_name,folder,directory=True)
            if journal._identity(os.fstat(folder))!=directory_identity or set(os.listdir(folder))!={'HEADER','DELIVERED'}:
                raise SettingsAuditHold()
            for name,fd,identity,image in held:
                journal._named(folder,name,fd,directory=False)
                if journal._identity(os.fstat(fd))!=identity or os.pread(fd,16385,0)!=image: raise SettingsAuditHold()
                journal._named(folder,name,fd,directory=False)
                if journal._identity(os.fstat(fd))!=identity: raise SettingsAuditHold()
            journal._named(owner.root_fd,folder_name,folder,directory=True)
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
    folder=None;folder_identity=None;folder_transferred=False;creator=None;primary=None
    failed=False; scope=ExitStack(); header_verify=None
    try:
        with _hold_delivery_entry_authority(writer_token,spreadsheet_token,binding,unit,create=create) as (owner,raw,result,verify,creator):
            if creator is not None:
                # Actual STARTED/HEADER finalizers precede the selected proof
                # and old raw tail. The later finally is an idempotent close.
                creator.tail_scope.push(lambda kind,primary,tb:
                    _close_delivery_scope(scope,kind,primary,tb))
            written=None; started=None
            folder_name,started_name=_delivery_names(raw)
            if create:
                if (folder_name in os.listdir(owner.root_fd) or started_name in os.listdir(owner.root_fd)
                        or any(name.startswith('.pending-') for name in os.listdir(owner.root_fd))):
                    raise SettingsAuditHold()
                # Retain the derived STOP name even after a first-byte/barrier
                # failure or a subsequently displaced delivery directory.
                started=_write_delivery_file(owner.root_fd,started_name,_delivery_start_raw(raw),
                    **({'_creator':creator} if creator is not None else {}))
            start_verify,raw=scope.enter_context(_hold_delivery_start(owner,raw,written=started))
            verify(); start_verify()
            if create:
                if creator is None:folder=global_journal._create_folder(owner.root_fd,folder_name)
                else:
                    # Acquisition transfers its already checked original; never
                    # recapture a possibly recycled source slot after a fault.
                    folder,folder_identity=global_journal._create_folder(owner.root_fd,folder_name,_return_original=True)
                    scope.push(lambda kind,primary,tb,fd=folder,original=folder_identity:
                        _close_delivery_original(fd,original,kind,primary,tb))
                    folder_transferred=True
                    creator.capture_folder(folder)
                header_identity=_write_delivery_file(folder,'HEADER',raw,
                    **({'_creator':creator} if creator is not None else {}))
                header_verify=scope.enter_context(_hold_delivery_header(owner,folder,raw,header_identity))
                verify(); start_verify(); header_verify()
                # ALL original COMPLETE and allocation barriers precede this
                # exclusive durable DELIVERED. Never clean the outbox here.
                marker_identity=_write_delivery_file(folder,'DELIVERED',_delivery_marker(raw,header_identity),
                    **({'_creator':creator} if creator is not None else {}))
                written={'HEADER':header_identity,'DELIVERED':marker_identity}
            else: folder=local._directory(owner.root_fd,folder_name)
            with _hold_delivery_files(owner,folder,raw,written=written) as delivery_verify:
                verify(); start_verify(); delivery_verify()
                if header_verify is not None: header_verify()
    except BaseException as refused:
        primary=refused
        if not isinstance(refused,Exception):raise
        failed=True
    finally:
        try: scope.close()
        except BaseException as refused:
            if primary is not None:primary.__cause__=refused;primary.__suppress_context__=True
            elif not isinstance(refused,Exception):raise
            failed=True
        if folder is not None and not folder_transferred:
            try:
                if creator is None:os.close(folder)
                else:local._close_written_original(folder,folder_identity)
            except BaseException as refused:
                if primary is not None:primary.__cause__=refused;primary.__suppress_context__=True
                elif not isinstance(refused,Exception):raise
                failed=True
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
                folder=local._directory(owner.root_fd,_delivery_names(raw)[0])
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
                folder=local._directory(owner.root_fd,_delivery_names(raw)[0])
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
        scope.enter_context(_hold_delivery_catalog_replay(sheet,bound,unit))
        match,_=scope.enter_context(completion._hold_match_originals(sheet,bound,unit))
        proof=scope.enter_context(completion._hold_completion_originals(sheet,bound,unit))
        seen=completion.inspect_completion_evidence(sheet,bound,unit)
        with _hold_delivery_authority(token,sheet,bound,unit,inspect_delivered=True) as (owner,raw,delivered,verify):
            verify()
        start,header=scope.enter_context(_hold_delivery_start(owner,raw))
        folder=local._directory(owner.root_fd,_delivery_names(raw)[0])
        scope.callback(os.close,folder)
        delivery=scope.enter_context(_hold_delivery_files(owner,folder,header))
        native=scope.enter_context(_hold_native_catalog_allocation_images(token,sheet,bound,unit))
        if native is not None:
            original,allocation_header,assignments,allocation=native
            if original is not owner:raise SettingsAuditHold()
        else:
            original,allocation_header,assignments=_originals(token,sheet,bound,unit,delivered_event_ids=delivered.event_ids)
            if original is not owner:raise SettingsAuditHold()
            allocated=local._directory(owner.root_fd,_FOLDER);scope.callback(os.close,allocated)
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

def _native_delivery_locator(raw):
    """Decode a locator, not authority; actual whole pair must still agree."""
    from monitor.issue_tracker_send_unit import _pairs,_nonfinite
    try:
        saved=json.loads(raw.decode('utf-8','strict'),object_pairs_hook=_pairs,parse_constant=_nonfinite)
        if (type(saved) is not dict or local._canonical(saved)!=raw
                or set(saved)!={'schema_version','complete_allocation','delivery_start_identity'}
                or type(saved['schema_version']) is not int or saved['schema_version']!=1
                or type(saved['complete_allocation']) is not dict):raise SettingsAuditHold()
        body=saved['complete_allocation']
        if 'native_allocation_header' not in body:return None
        header=body['native_allocation_header']
        if (type(header) is not dict or header.get('state')!='NATIVE_SETTINGS_ALLOCATION'
                or header.get('unit_id')!=body.get('unit_id')
                or hashlib.sha256(local._canonical(header)).hexdigest()!=body.get('allocation_header_sha256')):
            raise SettingsAuditHold()
        return header
    except (UnicodeError,ValueError,TypeError,KeyError):raise SettingsAuditHold() from None


@contextmanager
def _hold_native_completed_delivery_originals(writer,sheet,bound,unit,*,_tail_scope=None,
        _c6_handoff=None,_delivery_handoff=None,_allocation_handoff=None):
    """Prove one native immutable pair WITHOUT reading mutable projections.

    This is an internal original join, not a consumed-ID grant, observation,
    K writer, cleanup or dispatch issuer. ALL discovery must separately prove
    every claimed pair before allowing its exact union in a mutable read.
    Legacy public single-unit paths and COUNT/CLAIM remain strict.
    """
    from monitor import issue_tracker_remote_history_match as completion
    from monitor import issue_tracker_unit_catalog as catalog
    if _tail_scope is not None and type(_tail_scope) is not ExitStack:raise SettingsAuditHold()
    if sum(item is not None for item in (_c6_handoff,_delivery_handoff,_allocation_handoff))>1:raise SettingsAuditHold()
    handoff=_c6_handoff if _delivery_handoff is None else _delivery_handoff
    if _allocation_handoff is not None:handoff=_allocation_handoff
    if handoff is not None:
        expected=_NativeAllocationPriorOriginals if _allocation_handoff is not None else (
            _LocalC6Originals if _delivery_handoff is None else _DeliveryCreatorOriginals)
        if type(handoff) is not expected or handoff.writer is not writer:raise SettingsAuditHold()
    owner=local._owner(writer);sheet_owner=ownership._validated_owner(sheet,bound)
    if not global_journal._catalog_present(sheet_owner):raise SettingsAuditHold()
    ancestors=[];project_originals=[];held=(catalog._originals(sheet,bound)
        if _allocation_handoff is not None else catalog._Originals());ready=False
    def verify_raw():
        if local._owner(writer) is not owner or ownership._validated_owner(sheet,bound) is not sheet_owner:
            raise SettingsAuditHold()
        for parent,name,fd,identity in ancestors:
            local._check(fd,directory=True);journal._named(parent,name,fd,directory=True)
            if journal._identity(os.fstat(fd))[:5]!=identity:raise SettingsAuditHold()
        for path,published,descriptors,identities in project_originals:
            project,root,publication,lock=descriptors
            for index,fd in enumerate(descriptors):
                local._check(fd,directory=index<3,private=index in (1,3))
                if journal._identity(os.fstat(fd))[:5]!=identities[index][:5]:raise SettingsAuditHold()
            named=local._open_absolute_directory(path)
            named_identity=identities[0];primary=None
            try:
                opened=journal._identity(os.fstat(named))
                if opened[:5]!=identities[0][:5]:raise SettingsAuditHold()
                named_identity=opened
            except BaseException as refused:
                primary=refused
                raise
            finally:
                try:local._close_written_original(named,named_identity)
                except BaseException as refused:
                    if primary is not None:raise primary from refused
                    raise
            journal._named(project,'.tracker',root,directory=True)
            # Publication is an owner-controlled public projection directory;
            # unlike .tracker, its established contract permits mode 0755.
            named_publication=os.stat(published,dir_fd=project,follow_symlinks=False)
            if journal._identity(named_publication)[:5]!=identities[2][:5]:raise SettingsAuditHold()
            journal._named(root,'LOCK',lock,directory=False)
        held.verify()
    def close_ancestors(exc_type,exc,tb):
        problem=None
        for _parent,_name,fd,identity in reversed(ancestors):
            try:local._close_written_original(fd,identity)
            except BaseException as refused:
                if problem is None:problem=refused
        for _path,_published,descriptors,identities in reversed(project_originals):
            for fd,identity in reversed(tuple(zip(descriptors,identities))):
                try:local._close_written_original(fd,identity)
                except BaseException as refused:
                    if problem is None:problem=refused
        if problem is not None and exc is None:raise problem
        return False
    def finish_originals(exc_type,exc,tb):
        problem=None
        if exc_type is None and ready:
            try:verify_raw()
            except BaseException as refused:problem=refused
        try:held.close()
        except BaseException as refused:
            if exc is not None:
                exc.__cause__=refused;exc.__suppress_context__=True
                return False
            if problem is not None:raise problem from refused
            raise
        if problem is not None:raise problem
        return False
    def ancestor(parent,name):
        fd,identity=local._directory(parent,name,_return_original=True)
        ancestors.append((parent,name,fd,identity[:5]))
        journal._named(parent,name,fd,directory=True)
        if journal._identity(os.fstat(fd))[:5]!=identity[:5]:raise SettingsAuditHold()
        return fd
    def pin_project(actual):
        # Duplicate live acquired originals, never reopen foreign roots after
        # their owner closes. This is a raw-image handoff, not a writer token.
        prior=next((row for row in project_originals if row[0]==actual.project),None)
        if prior is not None:return prior[2]
        sources=(actual.project_fd,actual.root_fd,actual.publication_fd,actual.lock_fd)
        identities=tuple(journal._identity(os.fstat(fd)) for fd in sources)
        descriptors=[]
        project_originals.append((actual.project,actual.publication.name,descriptors,identities))
        for source,identity in zip(sources,identities):
            duplicate=os.dup(source);descriptors.append(duplicate)
            if journal._identity(os.fstat(duplicate))!=identity:raise SettingsAuditHold()
        verify_raw()
        return descriptors
    def original_file(parent,name,limit,expected):
        raw,identity=held.file(parent,name,limit)
        if (list(identity)!=expected['identity']
                or hashlib.sha256(raw).hexdigest()!=expected['sha256']):raise SettingsAuditHold()
        return raw
    try:
        with ExitStack() as scope:
            # ALL discovery owns the tail stack. Its raw graph survives the
            # outer ALL-C6/count/catalog finalizers, but semantic verifiers do
            # not escape their original scopes. Standalone leaf keeps its own
            # lifetime. Entered ExitStack passes through incoming interruptions.
            cleanup=scope if _tail_scope is None else _tail_scope
            cleanup.push(close_ancestors);cleanup.push(finish_originals)
            replay=scope.enter_context(_hold_delivery_catalog_replay(sheet,bound,unit))
            _catalog,units,_previous=catalog._inspect(sheet,bound,held)
            if unit not in units:raise SettingsAuditHold()
            origins,origins_verify=scope.enter_context(catalog.hold_pending_project_origins(sheet,bound))
            if tuple(row.unit for row in origins)!=units:raise SettingsAuditHold()
            c6_rows,c6_verify=scope.enter_context(catalog._hold_project_c6_from_origins(sheet,bound,origins))
            if tuple(row.unit for row in c6_rows)!=units:raise SettingsAuditHold()
            for origin,row in zip(origins,c6_rows):
                origins_verify();c6_verify()
                active=[actual for actual in local._ACTIVE.values() if actual.pid==os.getpid()
                    and actual.project==Path(origin.project_path) and actual.publication==Path(origin.publication_path)]
                if len(active)!=1 or row.c6_facts!=origin.c6_facts:raise SettingsAuditHold()
                _project,root,published,_lock=pin_project(active[0])
                facts=local._json(row.c6_facts)
                generations=held.directory(root,'generations')
                generation=held.directory(generations,facts['generation_id'])
                if list(journal._identity(os.fstat(generation)))!=facts['generation_directory_identity']:
                    raise SettingsAuditHold()
                files=facts['files'];receipt=None
                for entry in ('STATE','MANIFEST','INTENT','RECEIPT'):
                    raw=original_file(generation,entry,1024*1024,files[entry])
                    if entry=='RECEIPT':receipt=local._json(raw)
                published_name=receipt['published']
                if set(files)!={'STATE','MANIFEST','INTENT','RECEIPT',published_name}:raise SettingsAuditHold()
                original_file(published,published_name,local._MAX_XLSX,files[published_name])
                origins_verify();c6_verify();verify_raw()
            native=scope.enter_context(_hold_native_catalog_allocation_images(writer,sheet,bound,unit))
            if native is None:raise SettingsAuditHold()
            actual,header,assignments,allocation_verify=native
            if actual is not owner:raise SettingsAuditHold()
            match,witness=scope.enter_context(completion._hold_match_originals(sheet,bound,unit))
            proof=scope.enter_context(completion._hold_completion_originals(sheet,bound,unit))
            seen=completion.inspect_completion_evidence(sheet,bound,unit)
            if seen.state!='COMPLETE-PRESENT-NOT-APPLIED' or seen.unit_id!=unit.unit_id:raise SettingsAuditHold()
            _sheet,parent,name,_binding=global_journal._inputs(sheet,bound,unit)
            prefix=name[:-len('.journal')]
            match();proof()
            expected_names={prefix+'.journal',prefix+'.history',sheet_owner.lock_name[:-5]+'.enrollment'}
            if set(witness)!=expected_names:raise SettingsAuditHold()
            for folder_name,original in witness.items():
                folder=held.directory(parent,folder_name)
                if (list(journal._identity(os.fstat(folder)))!=original['directory_identity']
                        or set(os.listdir(folder))!=set(original['files'])):raise SettingsAuditHold()
                for entry,expected in original['files'].items():original_file(folder,entry,2*1024*1024,expected)
                match();proof()
            completion_start,completion_start_identity=scope.enter_context(
                completion._hold_completion_start(sheet,bound,unit))
            completion_start();proof()
            _start_raw,start_identity=held.file(parent,prefix+'.completion-started',16384)
            if list(start_identity)!=completion_start_identity:raise SettingsAuditHold()
            completion_start();proof()
            completed=held.directory(parent,name[:-len('.journal')]+'.completion')
            for entry in sorted(os.listdir(completed)):held.file(completed,entry,2*1024*1024)
            proof();match()
            raw=_delivery_complete_allocation_body(unit,header,assignments,seen,completed)
            folder_name,started_name=_delivery_names(raw)
            held.file(owner.root_fd,started_name,16384)
            delivery=held.directory(owner.root_fd,folder_name)
            for entry in ('HEADER','DELIVERED'):held.file(delivery,entry,16384)
            start_verify,wrapped=scope.enter_context(_hold_delivery_start(owner,raw))
            delivery_verify=scope.enter_context(_hold_delivery_files(owner,delivery,wrapped))
            events_fd=ancestor(ancestor(owner.root_fd,'settings'),'events')
            selected=json.loads(assignments.decode('utf-8'))
            for row in selected:
                event,_identity=held.file(events_fd,str(row['revision'])+'.json',16384)
                if event!=(row['audit']['details']+'\n').encode('utf-8'):raise SettingsAuditHold()
            events=tuple(row['audit']['event_id'] for row in selected)
            def verify():
                verify_raw();replay();origins_verify();c6_verify();allocation_verify();match();proof()
                completion_start();start_verify();delivery_verify()
                if completion.inspect_completion_evidence(sheet,bound,unit)!=seen:raise SettingsAuditHold()
                verify_raw()
            ready=True;verify()
            if handoff is not None:
                handoff.retain(held, ancestors, project_originals)
                verify()
            yield owner,events,verify
            verify()
    except Exception as exc:raise SettingsAuditHold() from exc


def _native_settings_packet(token,context):
    from monitor import issue_tracker_state_owner as state
    if type(context) is not _NativeCompletedSettingsContext:raise SettingsAuditHold()
    packet=_LIVE_NATIVE_SETTINGS_CONTEXTS.get(context)
    if (packet is None or _NATIVE_SETTINGS_CONTEXT.get() is not context
            or packet['token'] is not token or packet['pid']!=os.getpid()
            or packet['thread']!=threading.get_ident()
            or state._COMPLETED_READ_CONTEXT.get(token) is not context
            or state._COMPLETED_ORIGINAL_GUARDS.get(token) is not packet['guard']
            or local._owner(token) is not packet['owner']
            or ownership._validated_owner(packet['sheet'],packet['bound']) is not packet['sheet_owner']):
        raise SettingsAuditHold()
    return packet


def _read_native_completed_k(token,context):
    packet=_native_settings_packet(token,context);packet['guard']()
    with _hold_settings_originals(token,delivered_event_ids=packet['events']) as (images,verify):
        events,current,initialized,_outbox=images
        # Validate projection contents too, not just their presence/absence.
        _settings(token,delivered_event_ids=packet['events'])
        result=chain.validate_k_chain_snapshot(events,current,initialized)
        verify();packet['guard']();_native_settings_packet(token,context)
    return result


def _pending_native_completed_settings(token,context):
    packet=_native_settings_packet(token,context);packet['guard']()
    result=tuple(dict(row[2]) for row in _settings(token,delivered_event_ids=packet['events'])
        if row[2]['event_id'] not in packet['events'])
    packet['guard']();_native_settings_packet(token,context)
    return result


class _NativeSettingsAllowance:
    """Internal mutable-reader allowance, never a unit delivery observation."""
    __slots__=('event_ids',)
    def __init__(self,token,context):
        self.event_ids=_native_settings_packet(token,context)['events']


@contextmanager
def _hold_native_settings_transition_pair(token,context):
    packet=_native_settings_packet(token,context)
    guard=packet['guard'];guard()
    yield packet['owner'],_NativeSettingsAllowance(token,context),guard
    guard();_native_settings_packet(token,context)


@contextmanager
def _hold_discovered_native_completed_settings(writer,*,_c6_handoff=None,_delivery_handoff=None,_allocation_handoff=None):
    """ALL claims joined to original native units before any mutable exemption.

    Locators supply coordinates only. Every claimed pair, ALL catalog/counts
    and actual project C6 remain held through finalizers. Only this factory's
    exact LIVE identity can borrow the private union; no caller event IDs.
    """
    from monitor.issue_tracker_online_target import OnlineTargetBinding
    from monitor import issue_tracker_unit_catalog as catalog
    owner=local._owner(writer);held=catalog._Originals();issued=None;reset=None
    if sum(item is not None for item in (_c6_handoff,_delivery_handoff,_allocation_handoff))>1:raise SettingsAuditHold()
    handoff=_c6_handoff if _delivery_handoff is None else _delivery_handoff
    if _allocation_handoff is not None:
        if type(_allocation_handoff) is not _NativeAllocationPriorOriginals or _allocation_handoff.writer is not writer:
            raise SettingsAuditHold()
        handoff=_allocation_handoff
        held=catalog._originals(handoff.sheet,handoff.bound)
    if _delivery_handoff is not None:
        if type(_delivery_handoff) is not _DeliveryCreatorOriginals or _delivery_handoff.writer is not writer:
            raise SettingsAuditHold()
    markers={_DELIVERY_FOLDER,_DELIVERY_STARTED}
    def claimed_names():
        return {name for name in os.listdir(owner.root_fd) if name in markers
            or name.startswith(_DELIVERY_FOLDER+'-') or name.startswith(_DELIVERY_STARTED+'-')}
    claimed=claimed_names()
    def raw_verify():
        if local._owner(writer) is not owner or claimed_names()!=claimed:raise SettingsAuditHold()
        held.verify()
    with ExitStack() as scope:
        scope.callback(held.close)
        locators=[]
        for name in sorted(claimed):
            if name==_DELIVERY_FOLDER or name.startswith(_DELIVERY_FOLDER+'-'):
                folder=held.directory(owner.root_fd,name)
                header=_native_delivery_locator(held.file(folder,'HEADER',16384)[0])
                if header is None:raise SettingsAuditHold()
                locators.append(header)
        if not locators:raise SettingsAuditHold()
        project=journal._identity(os.fstat(owner.project_fd))[:2]
        tracker=journal._identity(os.fstat(owner.root_fd))[:2]
        header=locators[0]
        bound=OnlineTargetBinding(header['spreadsheet_id'],header['allowlist_sha256'],header['policy_sha256'])
        for locator in locators:
            if (locator['project_identity']!=list(project) or locator['tracker_identity']!=list(tracker)
                    or OnlineTargetBinding(locator['spreadsheet_id'],locator['allowlist_sha256'],locator['policy_sha256'])!=bound):
                raise SettingsAuditHold()
        sheet_scope=scope
        if _c6_handoff is not None:
            if type(_c6_handoff) is not _LocalC6Originals or _c6_handoff.writer is not writer:
                raise SettingsAuditHold()
            sheet_scope=_c6_handoff.scope
        if _delivery_handoff is not None or _allocation_handoff is not None:
            borrower=_delivery_handoff if _allocation_handoff is None else _allocation_handoff
            if borrower.bound!=bound:raise SettingsAuditHold()
            sheet=borrower.sheet
        else:sheet=sheet_scope.enter_context(ownership.spreadsheet_owner(bound))
        sheet_owner=ownership._validated_owner(sheet,bound)
        if _c6_handoff is not None:
            _c6_handoff.sheet, _c6_handoff.bound = sheet, bound
            _c6_handoff.retain_sheet_originals(sheet_owner)
            # Settings originals finalize first, then this raw graph check,
            # while the actual spreadsheet issuer still holds the lock.
            sheet_scope.callback(_c6_handoff.verify)
        scope.callback(raw_verify)
        tail=scope.enter_context(ExitStack())
        if not global_journal._catalog_present(sheet_owner):raise SettingsAuditHold()
        _folder,units,_previous=catalog._inspect(sheet,bound,held)
        selected=[unit for unit in units if unit.unit_id==header['unit_id']]
        if len(selected)!=1:raise SettingsAuditHold()
        replay=scope.enter_context(_hold_delivery_catalog_replay(sheet,bound,selected[0]))
        states,counts_verify=scope.enter_context(global_journal._hold_catalog_attempts(sheet,bound))
        rows,c6_verify=scope.enter_context(catalog.hold_pending_project_c6_units(sheet,bound))
        if tuple(unit for unit,_state in states)!=units or tuple(row.unit for row in rows)!=units:
            raise SettingsAuditHold()
        # Retain raw count images past their semantic scope's last finalizer.
        parent=sheet_owner.directories[-1][0];stem=sheet_owner.lock_name[:-5]
        counts_verify()
        for unit,observed in states:
            name=stem+'.unit-'+unit.unit_id+'.journal'
            start=name[:-len('.journal')]+'.journal-started'
            if observed.outcome=='PENDING_NO_JOURNAL':continue
            folder=held.directory(parent,name)
            for entry in sorted(os.listdir(folder)):held.file(folder,entry,2*1024*1024)
            held.file(parent,start,16384)
            counts_verify()
        entries=[];checks=[];expected_claims=set()
        for row in rows:
            if row.project_identity!=project:continue
            unit=row.unit;name=stem+'.unit-'+unit.unit_id+'.settings-audit'
            if name not in os.listdir(parent):continue
            allocation=held.directory(parent,name)
            native_header=held.file(allocation,'HEADER',16384)[0]
            assignments=held.file(allocation,'ASSIGNMENTS',_LIMIT)[0]
            audits=json.loads(assignments.decode('utf-8'))
            if not audits:raise SettingsAuditHold()
            folder_name,started_name=(_DELIVERY_FOLDER,_DELIVERY_STARTED)
            if all(item['revision']!=0 for item in audits):
                folder_name+='-'+unit.unit_id;started_name+='-'+unit.unit_id
            pair_names={folder_name,started_name}
            if not claimed & pair_names:continue
            if not pair_names<=claimed:raise SettingsAuditHold()
            if _native_delivery_locator(held.file(held.directory(owner.root_fd,folder_name),'HEADER',16384)[0])!=json.loads(native_header):
                raise SettingsAuditHold()
            actual,events,check=scope.enter_context(
                _hold_native_completed_delivery_originals(writer,sheet,bound,unit,_tail_scope=tail,
                    _c6_handoff=_c6_handoff,_delivery_handoff=_delivery_handoff,
                    _allocation_handoff=_allocation_handoff))
            if actual is not owner:raise SettingsAuditHold()
            if any(set(events)&set(previous) for _old,previous in entries):raise SettingsAuditHold()
            entries.append((unit,events));checks.append(check);expected_claims.update(pair_names)
        if not entries or expected_claims!=claimed:raise SettingsAuditHold()
        events=tuple(event for _unit,values in entries for event in values)
        def original_verify():
            raw_verify();replay();counts_verify();c6_verify()
            for check in checks:check()
            counts_verify();c6_verify();raw_verify()
        original_verify()
        if handoff is not None:
            # Retain ALL raw families while semantic ALL readers are live.
            # Catalog/NV INITIALIZED alone cannot replace its original files.
            parent=held.namespace[0]
            files={(fd,name) for fd,name,*_rest in held.files}
            directories={(fd,name):child for fd,name,child,*_rest in held.directories}
            for name in sorted(held.namespace[2]):
                if (parent,name) in files or name==sheet_owner.lock_name:
                    continue
                # ALL includes original regular STARTED witnesses as well as
                # folders. Named type selects acquisition, never authority;
                # held.file/directory independently pin the actual original.
                if not stat.S_ISDIR(os.stat(name,dir_fd=parent,follow_symlinks=False).st_mode):
                    held.file(parent,name,16*1024*1024)
                    continue
                folder=directories.get((parent,name))
                if folder is None:
                    folder=held.directory(parent,name)
                for entry in sorted(os.listdir(folder)):
                    if (folder,entry) not in files and (folder,entry) not in directories:
                        held.file(folder,entry,16*1024*1024)
            original_verify()
            handoff.retain(held)
            original_verify()
        issued=_NativeCompletedSettingsContext()
        def guard():
            _native_settings_packet(writer,issued);original_verify();_native_settings_packet(writer,issued)
        packet={'token':writer,'owner':owner,'sheet':sheet,'sheet_owner':sheet_owner,'bound':bound,
            'entries':tuple(entries),'events':events,'guard':guard,'pid':os.getpid(),'thread':threading.get_ident()}
        if _NATIVE_SETTINGS_CONTEXT.get() is not None:raise SettingsAuditHold()
        reset=_NATIVE_SETTINGS_CONTEXT.set(issued);_LIVE_NATIVE_SETTINGS_CONTEXTS[issued]=packet
        try:
            yield issued,guard
            original_verify()
        finally:
            # Permanent issuer revocation precedes ContextVar reset and ALL
            # original graph finalizers, including an interrupted initial read.
            _LIVE_NATIVE_SETTINGS_CONTEXTS.pop(issued,None)
            _NATIVE_SETTINGS_CONTEXT.reset(reset)


class _DeliveryCreatorOriginals:
    """Immutable old ALL graph retained only for a fixed new DELIVERED write.

    No generation additions, K enrollment, COUNT, cleanup or sending grant.
    Every new pair coordinate comes from the selected genuine COMPLETE; its
    actual exclusive writer FD overlaps the retained read FD before closing.
    """
    def __init__(self,writer,sheet,bound):
        self.writer=writer;self.owner=local._owner(writer)
        self.sheet=sheet;self.bound=bound;self.sheet_owner=ownership._validated_owner(sheet,bound)
        self.slots=[];self.duplicates={};self.files=[];self.directories=[]
        self.anchors=[];self.projects=[];self.namespaces=[]
        self.original_claims=self.claims();self.created_claims=set();self.created_files=[]
        self.created_folder=None;self.creation=None;self.tail_scope=None

    def claims(self):
        return {name for name in os.listdir(self.owner.root_fd)
            if name in (_DELIVERY_FOLDER,_DELIVERY_STARTED)
            or name.startswith(_DELIVERY_FOLDER+'-') or name.startswith(_DELIVERY_STARTED+'-')}

    def _dup(self,source,expected=None):
        before=journal._identity(os.fstat(source))
        if expected is not None and before!=expected:raise SettingsAuditHold()
        key=(source,before)
        if key in self.duplicates:
            result=self.duplicates[key]
            if journal._identity(os.fstat(result))!=before:raise SettingsAuditHold()
            return result
        result=os.dup(source);self.slots.append((result,before))
        if journal._identity(os.fstat(result))!=before:raise SettingsAuditHold()
        self.duplicates[key]=result
        return result

    def retain(self,held,ancestors=(),projects=()):
        held.verify()
        for parent,name,fd,identity,names in held.directories:
            self.directories.append((self._dup(parent),name,self._dup(fd,identity),identity,names))
        for parent,name,fd,identity,raw in held.files:
            self.files.append((self._dup(parent),name,self._dup(fd,identity),identity,raw))
        if held.namespace is not None:
            parent,prefix,names=held.namespace
            self.namespaces.append((self._dup(parent),prefix,frozenset(names)))
        for parent,name,fd,identity in ancestors:
            if journal._identity(os.fstat(fd))[:5]!=identity:raise SettingsAuditHold()
            self.anchors.append((self._dup(parent),name,self._dup(fd),identity))
        for path,published,descriptors,identities in projects:
            self.projects.append((path,published,
                tuple(self._dup(fd,identity) for fd,identity in zip(descriptors,identities)),identities))
        held.verify();self.verify()

    def _issued(self):
        packet=_LIVE_DELIVERY_CREATORS.get(self)
        if (_DELIVERY_CREATOR_CONTEXT.get() is not self or packet is None
                or packet['writer'] is not self.writer or packet['owner'] is not self.owner
                or packet['sheet'] is not self.sheet or packet['bound']!=self.bound
                or packet['pid']!=os.getpid() or packet['thread']!=threading.get_ident()
                or self.creation is None):raise SettingsAuditHold()

    def capture_folder(self,source):
        self._issued()
        folder_name,_started=self.creation['names']
        if self.created_folder is not None or len(self.created_files)!=1:raise SettingsAuditHold()
        identity=journal._identity(local._check(source,directory=True))
        journal._named(self.owner.root_fd,folder_name,source,directory=True)
        if os.listdir(source):raise SettingsAuditHold()
        self.created_folder=(self._dup(source,identity),identity)
        self.created_claims.add(folder_name);self.verify()

    def capture_written(self,parent,name,source,identity,raw):
        # The post-write directory now contains this actual new name. Validate
        # enrollment/previous raw graph without treating it as a third claim.
        self._issued()
        folder_name,started_name=self.creation['names'];position=len(self.created_files)
        if position==0:
            expected_parent=self.owner.root_fd;expected_name=started_name
            expected_raw=_delivery_start_raw(self.creation['body'])
        elif position==1 and self.created_folder is not None:
            expected_parent=self.created_folder[0];expected_name='HEADER'
            expected_raw=local._canonical({'schema_version':1,
                'complete_allocation':local._json(self.creation['body']),
                'delivery_start_identity':list(self.created_files[0][3])})
        elif position==2 and self.created_folder is not None:
            expected_parent=self.created_folder[0];expected_name='DELIVERED'
            expected_raw=_delivery_marker(self.created_files[1][4],self.created_files[1][3])
        else:raise SettingsAuditHold()
        if (name!=expected_name or raw!=expected_raw
                or journal._identity(os.fstat(parent))[:2]!=journal._identity(os.fstat(expected_parent))[:2]
                or journal._identity(local._check(source,directory=False))!=identity):raise SettingsAuditHold()
        journal._named(parent,name,source,directory=False)
        self._dup(source,identity)
        # The original write-only OFD is still live while opening and checking
        # this read FD. Replacements cannot be adopted after writer close.
        reader=os.open(name,local._flags(),dir_fd=parent);self.slots.append((reader,identity))
        if journal._identity(local._check(reader,directory=False))!=identity:raise SettingsAuditHold()
        journal._named(parent,name,reader,directory=False)
        if os.pread(reader,len(raw)+1,0)!=raw:raise SettingsAuditHold()
        self.created_files.append((self._dup(parent),name,reader,identity,raw))
        if position==0:self.created_claims.add(started_name)
        self.verify()

    def verify(self):
        try:self._verify_raw_graph()
        except Exception as refused:raise SettingsAuditHold() from refused

    def _verify_raw_graph(self):
        if (local._owner(self.writer) is not self.owner
                or ownership._validated_owner(self.sheet,self.bound) is not self.sheet_owner):raise SettingsAuditHold()
        if self.claims()!=self.original_claims|self.created_claims:raise SettingsAuditHold()
        for parent,prefix,names in self.namespaces:
            if {name for name in os.listdir(parent) if name.startswith(prefix)}!=names:raise SettingsAuditHold()
        for parent,name,fd,identity in self.anchors:
            journal._named(parent,name,fd,directory=True)
            if journal._identity(os.fstat(fd))[:5]!=identity:raise SettingsAuditHold()
        for path,published,descriptors,identities in self.projects:
            project,root,publication,lock=descriptors
            for fd,identity in zip(descriptors,identities):
                if journal._identity(os.fstat(fd))[:5]!=identity[:5]:raise SettingsAuditHold()
            opened=local._open_absolute_directory(path);before=identities[0]
            try:
                before=journal._identity(os.fstat(opened))
                if before[:5]!=identities[0][:5]:raise SettingsAuditHold()
            finally:local._close_written_original(opened,before)
            current=journal._identity(local._check(publication,directory=True,private=False))
            if (current[:5]!=identities[2][:5]
                    or journal._identity(os.stat(published,dir_fd=project,follow_symlinks=False))!=current):raise SettingsAuditHold()
            journal._named(project,'.tracker',root,directory=True)
            journal._named(root,'LOCK',lock,directory=False)
        for parent,name,fd,identity,names in self.directories:
            journal._named(parent,name,fd,directory=True)
            if journal._identity(os.fstat(fd))!=identity or tuple(sorted(os.listdir(fd)))!=names:raise SettingsAuditHold()
        for parent,name,fd,identity,raw in self.files+self.created_files:
            journal._named(parent,name,fd,directory=False)
            if raw is None or journal._identity(os.fstat(fd))!=identity or os.pread(fd,len(raw)+1,0)!=raw:raise SettingsAuditHold()
        if self.created_folder is not None:
            fd,identity=self.created_folder
            journal._named(self.owner.root_fd,self.creation['names'][0],fd,directory=True)
            if (journal._identity(os.fstat(fd))[:5]!=identity[:5]
                    or set(os.listdir(fd))!={name for _p,name,*_rest in self.created_files[1:]}):raise SettingsAuditHold()

    def close(self):
        problem=None
        try:self.verify()
        except BaseException as refused:problem=refused
        for fd,identity in reversed(self.slots):
            try:local._close_written_original(fd,identity)
            except BaseException as refused:
                if problem is None or not isinstance(refused,Exception):problem=refused
        self.slots.clear()
        if problem is not None:raise problem

    def finish(self,kind,primary,tb):
        try:self.close()
        except BaseException as refused:
            if primary is not None:
                primary.__cause__=refused;primary.__suppress_context__=True
                return False
            raise
        return False


class _NativeAllocationPriorOriginals:
    """Raw prior delivery join, never an issuer carried across NV/ENTRY.

    NV already holds the original ALL namespace and appendable catalog before
    this capture. Only those two mutable coordinates stay with that actual NV
    graph; every old file and all other directories remain immutable here.
    No caller additions, event list, settings context or creator grant escapes.
    """
    def __init__(self,writer,sheet,bound,old):
        self.writer=writer;self.owner=local._owner(writer)
        self.sheet=sheet;self.bound=bound;self.old=old
        self.raw=_DeliveryCreatorOriginals(writer,sheet,bound)
        self.catalog_edges=[];self.namespaces=[];self.events=None;self.record=None;self.frozen=None

    def retain(self,held,ancestors=(),projects=()):
        held.verify();self.old.verify()
        actual=ownership._validated_owner(self.sheet,self.bound)
        parent=actual.directories[-1][0];stem=actual.lock_name[:-5]
        directories=[]
        for edge in held.directories:
            p,name,fd,identity,names=edge
            if (name==stem+'.units'
                    and journal._identity(os.fstat(p))[:2]==journal._identity(os.fstat(parent))[:2]):
                original=[row for row in self.old.directories
                    if row[1]==name and journal._identity(os.fstat(row[0]))[:2]==journal._identity(os.fstat(p))[:2]]
                if len(original)!=1 or original[0][3]!=identity or original[0][4]!=names:
                    raise SettingsAuditHold()
                self.catalog_edges.append((self.raw._dup(p),name,self.raw._dup(fd,identity),identity[:5],frozenset(names)))
            else:directories.append(edge)
        if held.namespace is not None:
            p,prefix,names=held.namespace
            original=self.old.namespace
            if (original is None or original[1:]!=(prefix,names)
                    or journal._identity(os.fstat(original[0]))[:2]!=journal._identity(os.fstat(p))[:2]):
                raise SettingsAuditHold()
            self.namespaces.append((self.raw._dup(p),prefix,frozenset(names)))
        captured=SimpleNamespace(directories=directories,files=held.files,namespace=None,verify=held.verify)
        self.raw.retain(captured,ancestors,projects)
        self.old.verify();self.verify()

    def verify(self):
        self.raw.verify()
        additions,appended_identity,appended_names=self._expected_tail()
        for p,prefix,names in self.namespaces:
            if {name for name in os.listdir(p) if name.startswith(prefix)}!=names|additions:raise SettingsAuditHold()
        for p,name,fd,identity,names in self.catalog_edges:
            journal._named(p,name,fd,directory=True)
            if journal._identity(os.fstat(fd))[:5]!=identity:raise SettingsAuditHold()
            expected=names|(appended_names if identity[:2]==appended_identity else frozenset())
            if set(os.listdir(fd))!=expected:raise SettingsAuditHold()
        self.raw.verify()

    def bind(self,record):
        if (self.record is not None or record['old'] is not self.old
                or record['token'] is not self.sheet or record['binding']!=self.bound):raise SettingsAuditHold()
        self.record=record
        self.verify()

    def _expected_tail(self):
        if self.frozen is not None:return self.frozen
        if self.record is None:return frozenset(),None,frozenset()
        record=self.record
        if (record['old'] is not self.old or record['token'] is not self.sheet
                or record['binding']!=self.bound):raise SettingsAuditHold()
        appended=record['appended']
        return (frozenset(record['additions']),
            None if appended is None else journal._identity(os.fstat(appended[0]))[:2],
            frozenset() if appended is None else frozenset(appended[1]))

    def freeze(self,record):
        # The ACTUAL preparation freezes its own write coordinates before
        # issuer/old FD revocation, never from current directory contents.
        if record is not self.record or self.frozen is not None:raise SettingsAuditHold()
        self.frozen=self._expected_tail();self.record=None

    def finish(self,kind,primary,tb):
        try:self.verify()
        except BaseException as refused:
            if primary is None:
                kind,primary,tb=type(refused),refused,refused.__traceback__
                try:self.raw.finish(kind,primary,tb)
                finally:raise primary
            primary.__cause__=refused;primary.__suppress_context__=True
        return self.raw.finish(kind,primary,tb)


@contextmanager
def _hold_native_allocation_prior_deliveries(writer,sheet,bound,old,raw_scope):
    from monitor import issue_tracker_state_owner as state
    owner=local._owner(writer);ownership._validated_owner(sheet,bound);old.verify()
    claims={name for name in os.listdir(owner.root_fd) if name in (_DELIVERY_FOLDER,_DELIVERY_STARTED)
        or name.startswith(_DELIVERY_FOLDER+'-') or name.startswith(_DELIVERY_STARTED+'-')}
    if not claims:
        def strict():
            if local._owner(writer) is not owner or any(name in (_DELIVERY_FOLDER,_DELIVERY_STARTED)
                    or name.startswith(_DELIVERY_FOLDER+'-') or name.startswith(_DELIVERY_STARTED+'-')
                    for name in os.listdir(owner.root_fd)):raise SettingsAuditHold()
        strict();yield (),strict,None;strict();return
    if state._COMPLETED_READ_CONTEXT.get(writer) is not None or state._COMPLETED_ORIGINAL_GUARDS.get(writer) is not None:
        raise SettingsAuditHold()
    raw=_NativeAllocationPriorOriginals(writer,sheet,bound,old);raw_scope.push(raw.finish)
    with _hold_discovered_native_completed_settings(writer,_allocation_handoff=raw) as (native,guard):
        state._COMPLETED_READ_CONTEXT[writer]=native;state._COMPLETED_ORIGINAL_GUARDS[writer]=guard
        try:
            packet=_native_settings_packet(writer,native);guard()
            raw.events=packet['events'];raw.verify();old.verify();guard()
        finally:
            state._COMPLETED_READ_CONTEXT.pop(writer,None);state._COMPLETED_ORIGINAL_GUARDS.pop(writer,None)
    # ALL semantics and issuer now CLOSED. Only immutable raw originals remain.
    if raw.events is None:raise SettingsAuditHold()
    raw.verify();old.verify()
    yield raw.events,raw.verify,raw
    raw.verify()


def _native_allocation_prior_events(prepared,writer,sheet,bound):
    from monitor import issue_tracker_nv_reservation as nv
    record=nv._verify_catalog_preparation(prepared);owner=local._owner(writer)
    if record['token'] is not sheet or record['binding']!=bound:raise SettingsAuditHold()
    matches=[row for row in record['prior_delivery_events'] if row['writer'] is writer and row['owner'] is owner]
    if len(matches)>1:raise SettingsAuditHold()
    if not matches:return ()
    actual=matches[0];actual['verify']();nv._verify_catalog_preparation(prepared)
    return actual['events']


def _close_delivery_scope(scope,kind,primary,tb):
    """Close all owned children without replacing an incoming interruption."""
    try:scope.__exit__(kind,primary,tb)
    except BaseException as refused:
        if primary is not None:
            primary.__cause__=refused;primary.__suppress_context__=True
            return False
        raise
    return False


def _close_delivery_original(fd,identity,kind,primary,tb):
    """Actual source cleanup precedes retained graph's last original check."""
    try:local._close_written_original(fd,identity)
    except BaseException as refused:
        if primary is not None:
            primary.__cause__=refused;primary.__suppress_context__=True
            return False
        raise
    return False


def _finalize_native_completed_settings_delivery(writer,bound):
    """Fixed worker disposition from fresh ALL/C6/native COMPLETE originals.

    The preceding OAuth/read sheet owner must already be closed. Acquire two
    separate genuine sheet lifetimes under the still-live original project
    writer: finish exact pair creation first, then fresh ALL discovery issues
    its private union only for selected original projection archival. Neither
    caller IDs nor reconciliation observations are accepted as permissions.
    No COUNT, sending, NEW admission, K append or partial-evidence repair.
    """
    from monitor import issue_tracker_unit_catalog as catalog,issue_tracker_state_owner as state
    from monitor import issue_tracker_remote_history_match as completion
    owner=local._owner(writer);selected=[]
    if writer in state._COMPLETED_READ_CONTEXT or writer in state._COMPLETED_ORIGINAL_GUARDS:
        raise SettingsAuditHold()
    try:
        with ownership.spreadsheet_owner(bound) as sheet:
            # The actual ALL project/C6 readers finish before local pair writes.
            with catalog.hold_pending_project_c6_units(sheet,bound) as (rows,verify):
                project=journal._identity(os.fstat(owner.project_fd))[:2]
                units=tuple(row.unit for row in rows if row.project_identity==project
                    and local._json(row.unit.action_preimage)['audits'])
                verify()
            for unit in units:
                _sheet,parent,name,_binding=global_journal._inputs(sheet,bound,unit)
                prefix=name[:-len('.journal')]
                actual_names=set(os.listdir(parent))
                completion_names={prefix+'.completion',prefix+'.completion-started'}
                if not actual_names&completion_names:continue
                if not completion_names<=actual_names:raise SettingsAuditHold()
                with ExitStack() as proof_scope:
                    replay=proof_scope.enter_context(_hold_delivery_catalog_replay(sheet,bound,unit))
                    native=proof_scope.enter_context(_hold_native_catalog_allocation_images(writer,sheet,bound,unit))
                    if native is None:raise SettingsAuditHold()
                    actual,header,assignments,audit_verify=native
                    if actual is not owner:raise SettingsAuditHold()
                    match,_=proof_scope.enter_context(completion._hold_match_originals(sheet,bound,unit))
                    proof=proof_scope.enter_context(completion._hold_completion_originals(sheet,bound,unit))
                    seen=completion.inspect_completion_evidence(sheet,bound,unit)
                    if seen.state!='COMPLETE-PRESENT-NOT-APPLIED' or seen.unit_id!=unit.unit_id:
                        raise SettingsAuditHold()
                    folder,identity=local._directory(parent,prefix+'.completion',_return_original=True)
                    proof_scope.push(lambda kind,primary,tb,fd=folder,original=identity:
                        _close_delivery_original(fd,original,kind,primary,tb))
                    raw=_delivery_complete_allocation_body(unit,header,assignments,seen,folder)
                    names=set(_delivery_names(raw));present=set(os.listdir(owner.root_fd))&names
                    if present and present!=names:raise SettingsAuditHold()
                    replay();audit_verify();match();proof()
                if not present:record_completed_settings_delivery(writer,sheet,bound,unit)
                selected.append(unit)
        if not selected:return ()
        # Pair readers are gone. Fresh ALL factory acquires its OWN sheet
        # owner and verifies every claimed original before the first archive.
        with _hold_discovered_native_completed_settings(writer) as (context,guard):
            state._COMPLETED_READ_CONTEXT[writer]=context;state._COMPLETED_ORIGINAL_GUARDS[writer]=guard
            try:
                packet=_native_settings_packet(writer,context)
                if packet['bound']!=bound:raise SettingsAuditHold()
                available=tuple(unit for unit,_events in packet['entries'])
                if any(unit not in available for unit in selected):raise SettingsAuditHold()
                results=[]
                for unit in selected:
                    guard();_native_settings_packet(writer,context)
                    results.append(cleanup_completed_settings_outbox(writer,packet['sheet'],bound,unit))
                    guard();_native_settings_packet(writer,context)
                return tuple(results)
            finally:
                state._COMPLETED_READ_CONTEXT.pop(writer,None);state._COMPLETED_ORIGINAL_GUARDS.pop(writer,None)
    except Exception as refused:raise SettingsAuditHold() from refused


@contextmanager
def _hold_native_delivery_creator_originals(writer,sheet,bound,unit):
    """New native delivery after old archives; fixed actual dual-owner join."""
    from monitor import issue_tracker_state_owner as state, issue_tracker_remote_history_match as completion
    if writer in state._COMPLETED_READ_CONTEXT or writer in state._COMPLETED_ORIGINAL_GUARDS:
        raise SettingsAuditHold()
    with ExitStack() as scope:
        retained=_DeliveryCreatorOriginals(writer,sheet,bound);scope.push(retained.finish)
        with _hold_discovered_native_completed_settings(writer,_delivery_handoff=retained) as (native,guard):
            state._COMPLETED_READ_CONTEXT[writer]=native;state._COMPLETED_ORIGINAL_GUARDS[writer]=guard
            try:
                packet=_native_settings_packet(writer,native)
                if packet['sheet'] is not sheet or packet['bound']!=bound:raise SettingsAuditHold()
                guard();old_events=packet['events']
                images,settings_verify=scope.enter_context(_hold_settings_originals(writer,delivered_event_ids=old_events))
                all_events={row[2]['event_id']:row[2] for row in _settings(writer,delivered_event_ids=old_events)}
                guard();settings_verify();retained.verify()
            finally:
                state._COMPLETED_READ_CONTEXT.pop(writer,None);state._COMPLETED_ORIGINAL_GUARDS.pop(writer,None)
        # ALL old semantic issuers are closed permanently before first write.
        # Retained originals and the actual caller's sheet/project locks stay.
        replay=scope.enter_context(_hold_delivery_catalog_replay(sheet,bound,unit))
        native=scope.enter_context(_hold_native_catalog_allocation_images(writer,sheet,bound,unit))
        if native is None:raise SettingsAuditHold()
        owner,header,assignments,audit_verify=native
        if owner is not retained.owner:raise SettingsAuditHold()
        selected=json.loads(assignments.decode('utf-8'))
        if (not selected or any(row['audit']['event_id'] in old_events
                or row['revision'] not in images[3]
                or all_events.get(row['audit']['event_id'])!=row['audit'] for row in selected)):raise SettingsAuditHold()
        match,_=scope.enter_context(completion._hold_match_originals(sheet,bound,unit))
        proof=scope.enter_context(completion._hold_completion_originals(sheet,bound,unit))
        seen=completion.inspect_completion_evidence(sheet,bound,unit)
        if seen.state!='COMPLETE-PRESENT-NOT-APPLIED' or seen.unit_id!=unit.unit_id:raise SettingsAuditHold()
        _sheet,parent,name,_binding=global_journal._inputs(sheet,bound,unit)
        name=name[:-len('.journal')]+'.completion'
        folder,original=local._directory(parent,name,_return_original=True)
        scope.callback(local._close_written_original,folder,original)
        raw=_delivery_complete_allocation_body(unit,header,assignments,seen,folder)
        names=_delivery_names(raw)
        if set(names)&retained.original_claims:raise SettingsAuditHold()
        retained.creation={'body':raw,'names':names};retained.tail_scope=scope
        def verify():
            retained.verify();settings_verify();replay();audit_verify();match();proof()
            journal._named(parent,name,folder,directory=True)
            if completion.inspect_completion_evidence(sheet,bound,unit)!=seen:raise SettingsAuditHold()
            settings_verify();retained.verify()
        verify()
        if _DELIVERY_CREATOR_CONTEXT.get() is not None:raise SettingsAuditHold()
        reset=_DELIVERY_CREATOR_CONTEXT.set(retained)
        _LIVE_DELIVERY_CREATORS[retained]={'writer':writer,'owner':owner,'sheet':sheet,'bound':bound,
            'pid':os.getpid(),'thread':threading.get_ident()}
        try:
            yield owner,raw,SettingsDeliveryObservation('DELIVERED-PRESENT-OUTBOX-RETAINED',unit.unit_id,
                tuple(row['audit']['event_id'] for row in selected)),verify,retained
            verify()
        finally:
            _LIVE_DELIVERY_CREATORS.pop(retained,None);_DELIVERY_CREATOR_CONTEXT.reset(reset)


@contextmanager
def _hold_delivery_entry_authority(writer,sheet,bound,unit,*,create):
    owner=local._owner(writer)
    claimed={name for name in os.listdir(owner.root_fd) if name in (_DELIVERY_FOLDER,_DELIVERY_STARTED)
        or name.startswith(_DELIVERY_FOLDER+'-') or name.startswith(_DELIVERY_STARTED+'-')}
    if create and claimed:
        with _hold_native_delivery_creator_originals(writer,sheet,bound,unit) as actual:yield actual
    else:
        with _hold_delivery_authority(writer,sheet,bound,unit,inspect_delivered=not create) as actual:
            yield (*actual,None)


class _LocalC6Originals:
    """Overlap raw original FDs, not closed catalog/count semantic guards.

    Only this writer's genuine issued generation handles permit additions to
    its original generations directory. ALL other names/stats/bytes remain
    exact. Parent FDs are duplicated too; no recycled descriptor or reopened
    post-finalizer file is adopted as an original.
    """
    def __init__(self,writer,scope):
        self.writer=writer; self.owner=local._owner(writer); self.scope=scope
        self.sheet=None; self.bound=None; self.sheet_original=None
        self.slots=[]; self.duplicates={}; self.files=[]; self.directories=[]
        self.anchors=[]; self.projects=[]; self.namespaces=[]

    def _dup(self,source,expected=None):
        before=journal._identity(os.fstat(source))
        if expected is not None and before!=expected:raise SettingsAuditHold()
        key=(source,before)
        if key in self.duplicates:
            result=self.duplicates[key]
            if journal._identity(os.fstat(result))!=before:raise SettingsAuditHold()
            return result
        result=os.dup(source)
        # Register conditional cleanup immediately, before checked fstat.
        self.slots.append((result,before))
        if journal._identity(os.fstat(result))!=before:raise SettingsAuditHold()
        self.duplicates[key]=result
        return result

    def retain(self,held,ancestors=(),projects=()):
        held.verify()
        for parent,name,fd,identity,names in held.directories:
            self.directories.append((self._dup(parent),name,self._dup(fd,identity),identity,names))
        for parent,name,fd,identity,raw in held.files:
            self.files.append((self._dup(parent),name,self._dup(fd,identity),identity,raw))
        if held.namespace is not None:
            parent,prefix,names=held.namespace
            self.namespaces.append((self._dup(parent),prefix,frozenset(names)))
        for parent,name,fd,identity in ancestors:
            if journal._identity(os.fstat(fd))[:5]!=identity:raise SettingsAuditHold()
            self.anchors.append((self._dup(parent),name,self._dup(fd),identity))
        for path,published,descriptors,identities in projects:
            copied=tuple(self._dup(fd,identity) for fd,identity in zip(descriptors,identities))
            self.projects.append((path,published,copied,identities))
        held.verify(); self.verify()

    def retain_sheet_originals(self,owner):
        if ownership._validated_owner(self.sheet,self.bound) is not owner:
            raise SettingsAuditHold()
        # Overlap the complete actual sheet ancestor/edge/LOCK graph. This
        # raw FD copy is not an ACTIVE token and cannot grant online authority.
        descriptors={fd:self._dup(fd) for fd in owner.descriptors}
        original=replace(owner,descriptors=tuple(descriptors[fd] for fd in owner.descriptors),
            directories=tuple((descriptors[fd],info,private) for fd,info,private in owner.directories),
            edges=tuple((descriptors[parent],name,info) for parent,name,info in owner.edges),
            lock_fd=descriptors[owner.lock_fd])
        ownership._validate(original)
        self.sheet_original=original
        ownership._validated_owner(self.sheet,self.bound)

    def verify(self):
        if self.sheet is not None:ownership._validated_owner(self.sheet,self.bound)
        self._verify_raw_graph()
        if self.sheet is not None:ownership._validated_owner(self.sheet,self.bound)

    def _verify_raw_graph(self):
        owner=local._owner(self.writer)
        if owner is not self.owner:raise SettingsAuditHold()
        if self.sheet_original is not None:ownership._validate(self.sheet_original)
        for parent,prefix,names in self.namespaces:
            if {name for name in os.listdir(parent) if name.startswith(prefix)}!=names:
                raise SettingsAuditHold()
        for parent,name,fd,identity in self.anchors:
            journal._named(parent,name,fd,directory=True)
            if journal._identity(os.fstat(fd))[:5]!=identity:raise SettingsAuditHold()
        for path,published,descriptors,identities in self.projects:
            project,root,publication,lock=descriptors
            for fd,identity in zip(descriptors,identities):
                if journal._identity(os.fstat(fd))[:5]!=identity[:5]:raise SettingsAuditHold()
            named=local._open_absolute_directory(path)
            before=identities[0]
            try:
                before=journal._identity(os.fstat(named))
                if before[:5]!=identities[0][:5]:raise SettingsAuditHold()
            finally:local._close_written_original(named,before)
            # Publication is public-readable under the existing owner
            # contract, not a private 0700 journal directory. Preserve its
            # original type/owner/mode/inode and actual named/held identity;
            # only directory contents/stat may change during genuine C6.
            current_publication=journal._identity(local._check(publication,directory=True,private=False))
            named_publication=journal._identity(os.stat(published,dir_fd=project,follow_symlinks=False))
            if (current_publication[:5]!=identities[2][:5]
                    or named_publication!=current_publication):raise SettingsAuditHold()
            for parent,name,fd,is_directory in ((project,'.tracker',root,True),(root,'LOCK',lock,False)):
                journal._named(parent,name,fd,directory=is_directory)
        for parent,name,fd,identity,names in self.directories:
            journal._named(parent,name,fd,directory=True)
            current=journal._identity(os.fstat(fd))
            if (name=='generations'
                    and journal._identity(os.fstat(parent))[:2]==journal._identity(os.fstat(owner.root_fd))[:2]):
                additions=set()
                for key,handle in owner.handles.items():
                    if key!=id(handle) or handle.owner_token is not self.writer:raise SettingsAuditHold()
                    original,before=local._generation_fd(owner,handle,token=self.writer,
                        _return_original=True)
                    try:
                        if journal._identity(os.fstat(original))!=before:raise SettingsAuditHold()
                        additions.add(handle.generation_id)
                    finally:local._close_written_original(original,before)
                if current[:5]!=identity[:5] or set(os.listdir(fd))!=set(names)|additions:
                    raise SettingsAuditHold()
            elif current!=identity or tuple(sorted(os.listdir(fd)))!=names:
                raise SettingsAuditHold()
        for parent,name,fd,identity,raw in self.files:
            journal._named(parent,name,fd,directory=False)
            if (raw is None or journal._identity(os.fstat(fd))!=identity
                    or os.pread(fd,len(raw)+1,0)!=raw):raise SettingsAuditHold()

    def close(self):
        problem=None; primary=None
        # The sheet token and all semantic issuers have now been revoked.
        # The overlapped original LOCK OFD remains ours until these slots
        # close; verify raw named/held images once more, never a closed guard.
        try:self._verify_raw_graph()
        except BaseException as exc:
            problem=exc
            if not isinstance(exc,Exception):primary=exc
        for fd,identity in reversed(self.slots):
            try:local._close_written_original(fd,identity)
            except BaseException as exc:
                if problem is None:problem=exc
                if not isinstance(exc,Exception) and primary is None:primary=exc
        self.slots.clear()
        if primary is not None:
            if primary is not problem:raise primary from problem
            raise primary
        if problem is not None:raise problem


@contextmanager
def _hold_completed_local_c6(writer):
    """Finish strict ALL semantics before the fixed actual local C6 writer.

    Actual sheet/project locks and overlapped immutable originals remain held.
    A new opaque read-only enrollment never revives the former settings
    issuer, and grants neither set-K, cleanup, COUNT nor online dispatch.
    """
    from monitor import issue_tracker_state_owner as state
    owner=local._owner(writer)
    def claims():
        return {name for name in os.listdir(owner.root_fd) if name in (_DELIVERY_FOLDER,_DELIVERY_STARTED)
            or name.startswith(_DELIVERY_FOLDER+'-') or name.startswith(_DELIVERY_STARTED+'-')}
    original_claims=claims()
    if not original_claims:
        def strict():
            if local._owner(writer) is not owner or claims():raise SettingsAuditHold()
        strict(); yield None,strict; strict()
        return
    with state._settings_original_scope() as scope:
        raw=_LocalC6Originals(writer,scope); scope.callback(raw.close)
        with _hold_discovered_native_completed_settings(writer,_c6_handoff=raw) as (native,guard):
            state._COMPLETED_READ_CONTEXT[writer]=native
            state._COMPLETED_ORIGINAL_GUARDS[writer]=guard
            try:
                packet=_native_settings_packet(writer,native); guard()
                events=packet['events']
                images,settings_verify=scope.enter_context(_hold_settings_originals(writer,delivered_event_ids=events))
                _settings(writer,delivered_event_ids=events)
                guard(); settings_verify(); raw.verify(); guard()
            finally:
                state._COMPLETED_READ_CONTEXT.pop(writer,None)
                state._COMPLETED_ORIGINAL_GUARDS.pop(writer,None)
        # The former issuer and ALL semantic graph are fully revoked/closed.
        # The actual spreadsheet owner deliberately outlives this handoff.
        def verify():
            if claims()!=original_claims:raise SettingsAuditHold()
            raw.verify(); settings_verify(); raw.verify()
        verify()
        issued=_CompletedLocalC6Context()
        if _LOCAL_C6_CONTEXT.get() is not None:raise SettingsAuditHold()
        packet={'token':writer,'owner':owner,'pid':os.getpid(),'thread':threading.get_ident(),
            'images':images,'verify':verify}
        reset=_LOCAL_C6_CONTEXT.set(issued); _LIVE_LOCAL_C6_CONTEXTS[issued]=packet
        try:
            yield issued,verify
            verify()
        finally:
            _LIVE_LOCAL_C6_CONTEXTS.pop(issued,None)
            _LOCAL_C6_CONTEXT.reset(reset)


def _read_completed_local_c6_k(writer,context):
    from monitor import issue_tracker_state_owner as state
    packet=_LIVE_LOCAL_C6_CONTEXTS.get(context) if type(context) is _CompletedLocalC6Context else None
    if (packet is None or _LOCAL_C6_CONTEXT.get() is not context
            or packet['token'] is not writer or packet['pid']!=os.getpid()
            or packet['thread']!=threading.get_ident() or local._owner(writer) is not packet['owner']
            or state._LOCAL_C6_READ_CONTEXT.get(writer) is not context):raise SettingsAuditHold()
    packet['verify']()
    events,current,initialized,_outbox=packet['images']
    result=chain.validate_k_chain_snapshot(events,current,initialized)
    packet['verify']()
    return result


@contextmanager
def _hold_discovered_completed_settings(writer):
    """Discover coordinates from held local originals, then prove the whole pair."""
    from monitor.issue_tracker_online_target import OnlineTargetBinding
    from monitor.issue_tracker_send_unit import _original_unit,_pairs,_nonfinite
    from monitor import issue_tracker_unit_catalog as catalog
    owner=local._owner(writer)
    with ExitStack() as scope:
        held=catalog._Originals()
        # Original locator descriptors outlive all catalog/C6/pair finalizers.
        # Their existing conditional cleanup never closes a foreign reused FD.
        scope.callback(held.close)
        def directory(parent,name):
            return held.directory(parent,name)
        def file(parent,name,limit):
            return held.file(parent,name,limit)[0]
        def verify():
            if local._owner(writer) is not owner: raise SettingsAuditHold()
            if claimed_names()-markers:raise SettingsAuditHold()
            held.verify()
        markers={_DELIVERY_FOLDER,_DELIVERY_STARTED}
        def claimed_names():
            return {name for name in os.listdir(owner.root_fd) if name in markers
                or name.startswith(_DELIVERY_FOLDER+'-') or name.startswith(_DELIVERY_STARTED+'-')}
        # This first-pair reader cannot silently ignore another durable claim.
        # ALL historical native deliveries need their own complete original
        # join before the default entry may excuse any missing projection.
        if claimed_names()-markers:
            with _hold_discovered_native_completed_settings(writer) as original:
                yield original
            return
        if not claimed_names():
            # No durable delivery claim: preserve the ordinary strict K contract.
            def strict_verify():
                if claimed_names():
                    raise SettingsAuditHold()
                verify()
            yield None,strict_verify
            strict_verify()
            return
        delivery_folder=directory(owner.root_fd,_DELIVERY_FOLDER)
        header=_native_delivery_locator(file(delivery_folder,'HEADER',16384))
        native=header is not None
        if not native:
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
        # Verify locator and journal originals AFTER their subordinate pair/
        # catalog/C6 finalizers, but BEFORE the actual sheet parent owner closes.
        # Closing descriptors is independent and still runs on any refusal.
        scope.callback(verify)
        parent=sheet_owner.directories[-1][0]
        catalog_checks=[]
        unit_name=sheet_owner.lock_name[:-5]+'.journal'
        selected=None
        if native and not global_journal._catalog_present(sheet_owner):raise SettingsAuditHold()
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
            if claimed_names()-markers:raise SettingsAuditHold()
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

def _apply_completed_k_change(token,sheet,bound,unit,*,new_k,actor,recorded_at,request_id,expected_revision,_native_context=None):
    chain._positive_int(new_k); chain._actor(actor); chain._time(recorded_at)
    chain._request_id(request_id); chain._revision(expected_revision)
    if actor=='system:default': raise SettingsAuditHold()
    payload=chain._canonical_line({'new_k':new_k,'actor':actor,
        'expected_revision':expected_revision,'request_id':request_id})
    payload_digest=hashlib.sha256(payload).hexdigest()
    with ExitStack() as scope:
        pair_scope=ExitStack(); scope.callback(pair_scope.close)
        pair=(_hold_completed_k_pair(token,sheet,bound,unit) if _native_context is None
            else _hold_native_settings_transition_pair(token,_native_context))
        owner,delivered,proof=pair_scope.enter_context(pair)
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
        from monitor import issue_tracker_state_owner as state
        context=state._COMPLETED_READ_CONTEXT.get(token)
        native=type(context) is _NativeCompletedSettingsContext
        selected_events=None
        if native:
            packet=_native_settings_packet(token,context)
            matches=[events for original,events in packet['entries'] if original==unit]
            if packet['sheet'] is not sheet or packet['bound']!=bound or len(matches)!=1:
                raise SettingsAuditHold()
            selected_events=matches[0]
        with ExitStack() as scope:
            pair=ExitStack()
            scope.callback(pair.close)
            original_pair=(_hold_native_settings_transition_pair(token,context) if native
                else _hold_completed_k_pair(token,sheet,bound,unit))
            owner,delivered,proof=pair.enter_context(original_pair)
            if selected_events is None:selected_events=delivered.event_ids
            transition=_CompletedOutboxCleanup(scope,owner,delivered)
            selected={f'{rev}.json' for rev,raw in transition.images.items()
                if 'settings:'+str(rev)+':'+hashlib.sha256(raw).hexdigest() in selected_events}
            entries=[entry for entry in transition.files
                if entry[0]==transition.outbox and entry[1] in selected]
            for entry in entries:
                proof(); transition.verify()
                transition.move_original(entry)
                proof(); transition.verify()
            os.fsync(transition.outbox); os.fsync(transition.cleanup_archive)
            proof(); transition.verify()
            if native:
                packet=_native_settings_packet(token,context)
                # The ALL allowance is private. The returned public observation
                # still names only the selected unit and its literal events.
                _settings(token,delivered_event_ids=packet['events'])
                if selected & set(os.listdir(transition.outbox)):raise SettingsAuditHold()
                result=SettingsDeliveryObservation('DELIVERED-PRESENT-OUTBOX-ABSENT-VALID',unit.unit_id,selected_events)
            else:
                result=inspect_completed_settings_delivery(token,sheet,bound,unit)
            if result.state!='DELIVERED-PRESENT-OUTBOX-ABSENT-VALID':
                raise SettingsAuditHold()
            proof(); transition.verify(); pair.close(); transition.verify()
            return result
    except Exception as exc:
        raise SettingsAuditHold() from exc


def _apply_native_completed_k_change(token,context,*,new_k,actor,recorded_at,request_id,expected_revision):
    packet=_native_settings_packet(token,context)
    try:
        return _apply_completed_k_change(token,packet['sheet'],packet['bound'],None,new_k=new_k,actor=actor,
            recorded_at=recorded_at,request_id=request_id,expected_revision=expected_revision,_native_context=context)
    except settings.KChangeConflict:raise
    except Exception as exc:raise SettingsAuditHold() from exc


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
