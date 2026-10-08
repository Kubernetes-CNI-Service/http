"""Uninstalled C25 original-event allocation under BOTH actual owners.

This conservative first journal retains one unit per project. The delivery
bridge requires the actual original C19 COMPLETE proof before its durable
DELIVERED record; it never sends, cleans an outbox event, repairs a partial
journal, authorizes a source or releases UNKNOWN/FIFO/admission barriers.
"""
import hashlib
import json
import os
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
    finally:
        close_failed=False
        for _parent,_name,descriptor,_directory,_identity,_image in reversed(held):
            try: os.close(descriptor)
            except OSError: close_failed=True
        if close_failed: raise SettingsAuditHold()


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
    """ALL committed events remain pending; allocation is NOT consumption."""
    failed = False
    try: result = tuple(dict(row[2]) for row in _settings(writer_token))
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
    folder = None; failed = False
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
        with _hold_allocation_originals(owner.root_fd,folder,header,assignments) as verify_allocation:
            _inspect(owner.root_fd, folder, header, assignments)
            _sync_marker(owner.root_fd, folder, header, assignments)
            verify_allocation()
            if _originals(writer_token, spreadsheet_token, binding, unit)[1:] != (header, assignments):
                raise SettingsAuditHold()
            ownership._validated_owner(spreadsheet_token, binding)
            local._owner(writer_token)
            _inspect(owner.root_fd, folder, header, assignments)
            if create and global_journal.inspect_global_unit(spreadsheet_token, binding, unit).attempt_count != 0:
                raise SettingsAuditHold()
            verify_settings()
            verify_allocation()
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
