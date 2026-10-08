"""Uninstalled journal-bound complete History matching, NOT remote APPLIED.

Only MATCHED_OBSERVATION when an actual counted global unit, original durable
preimage, both original enrollment nonces, exact permanent fence and ALL sent
business/audit rows agree. No send/clear/reset/high-water mutation. Remote read
objects remain necessary inputs, not authenticated source/admission authority;
The owned-read bridge below establishes actual fixed-read provenance, current
dual owners and typed template observations, not durable settlement authority.
"""
from dataclasses import dataclass, asdict
from contextlib import contextmanager, ExitStack
import hashlib
import json
import os
from urllib.parse import urlsplit, urlencode

from monitor import issue_tracker_global_attempt_journal as global_journal
from monitor import issue_tracker_history_preread_journal as before
from monitor import issue_tracker_enrollment_journal as enrollment
from monitor import issue_tracker_sheets_read_decode as decode
from monitor import issue_tracker_metadata_capacity as metadata
from monitor import issue_tracker_spreadsheet_owner as ownership


class RemoteHistoryHold(ValueError):
    def __init__(self): super().__init__('req7_remote_history_unproved')


@dataclass(frozen=True)
class RemoteHistoryObservation:
    state: str
    attempt_count: int
    fence_present: bool
    target_nonce_valid: bool
    history_nonce_valid: bool
    history_rows_expected: int
    history_rows_matched: int
    history_last_row_before_send: int
    history_last_row_after_read: int
    action_digest: str
    wire_sha256: str
    metadata_sha256: str
    history_sha256: str


@dataclass(frozen=True)
class OwnedUnitReadGateObservation:
    """Necessary live read checks, not a mutation permit or globally free quota."""
    identity: object
    whitelist_sha256: str
    enrollment_sha256: str
    capacity_outcome: str


@dataclass(frozen=True)
class CompletionEvidenceObservation:
    """Durable original proof-set observation, NOT APPLIED or a send permit.

    No global barrier, reservation, FIFO/high-water or settings outbox consumer
    accepts this value. Those transitions need their own integrated authority.
    """
    state: str
    attempt_count: int
    history_rows_matched: int
    unit_id: str
    header_sha256: str


def _fence(unit, identity, response):
    """Presence of the exact ID/image, not any z=1 or substituted fence ID."""
    doc = json.loads(response.data.decode('utf-8', 'strict'), object_pairs_hook=metadata._pairs,
                     parse_constant=metadata._nonfinite)
    found = None
    for entry in doc.get('matchedDeveloperMetadata', []):
        mid, pool, size, image = metadata._entry(entry['developerMetadata'], set(dict(identity.sheet_ids).values()))
        if mid == unit.fence_metadata_id:
            if found is not None: raise RemoteHistoryHold()
            found = image
    target = json.loads(unit.action_preimage)['identity']
    expected = ('z', '1', 'DOCUMENT', 'SHEET', target['sheet_id'], None)
    return found is not None, found is not None and found != expected


def _rows(cells, first, last):
    # The typed decoder supplies ordered A:E cells. Group once, including all
    # empty cells/gaps; the 5000-row limit is not permission for O(rows*cells).
    grouped = {row: [] for row in range(first, last + 1)}
    for row, column, entered in cells:
        if row in grouped: grouped[row].append(entered)
    return tuple(tuple(grouped[row]) for row in range(first, last + 1))


@contextmanager
def _hold_match_originals(token,binding,unit):
    """Pin original count, History and nonces across the WHOLE observation.

    Same-byte replacement is not the retained original; an added attempt is
    not the count we matched. Only held private original directories/files,
    never refreshed/adopted images, may survive this context. No writes or
    COMPLETE authority are supplied by this necessary snapshot boundary.
    """
    from monitor import issue_tracker_local_commit as local
    from monitor import issue_tracker_attempt_journal as journal
    held=[]
    try:
        owner,parent,original_name,_header=global_journal._inputs(token,binding,unit)
        prefix=original_name[:-len('.journal')]
        for suffix in ('.journal','.history','.enrollment'):
            name=prefix+suffix
            folder=local._directory(parent,name)
            held.append((name,folder,None,None))
            journal._named(parent,name,folder,directory=True)
            directory_identity=journal._identity(os.fstat(folder))
            names=set(os.listdir(folder))
            if suffix=='.journal':
                count=len(names)-4
                expected={'ACTION-PREIMAGE','WIRE','HEADER','INITIALIZED',
                          *(f'ATTEMPT-{index}' for index in range(1,count+1))}
                if not 1<=count<=6: raise RemoteHistoryHold()
            elif suffix=='.history': expected={'HISTORY-RAW','HEADER','INITIALIZED'}
            else: expected={'NONCES','HEADER','INITIALIZED'}
            if names!=expected: raise RemoteHistoryHold()
            files={}
            for entry in sorted(names):
                identity_before=journal._identity(os.stat(entry,dir_fd=folder,follow_symlinks=False))
                raw=journal._read(folder,entry,2*1024*1024)
                if journal._identity(os.stat(entry,dir_fd=folder,follow_symlinks=False))!=identity_before:
                    raise RemoteHistoryHold()
                files[entry]=(raw,identity_before)
            held[-1]=(name,folder,directory_identity,files)
        def verify():
            if ownership._validated_owner(token,binding) is not owner: raise RemoteHistoryHold()
            for name,folder,directory_identity,files in held:
                journal._named(parent,name,folder,directory=True)
                if (journal._identity(os.fstat(folder))!=directory_identity
                        or set(os.listdir(folder))!=set(files)
                        or any((journal._read(folder,entry,2*1024*1024),
                            journal._identity(os.stat(entry,dir_fd=folder,follow_symlinks=False)))!=saved
                            for entry,saved in files.items())):
                    raise RemoteHistoryHold()
                journal._named(parent,name,folder,directory=True)
                if journal._identity(os.fstat(folder))!=directory_identity: raise RemoteHistoryHold()
            ownership._validated_owner(token,binding)
        verify()
        witness={name:{'directory_identity':list(directory_identity),
                      'files':{entry:{'identity':list(identity),'sha256':hashlib.sha256(raw).hexdigest()}
                               for entry,(raw,identity) in files.items()}}
                 for name,_folder,directory_identity,files in held}
        yield verify,witness
        verify()
    finally:
        close_failed=False
        for _name,folder,_identity,_files in reversed(held):
            try: os.close(folder)
            except OSError: close_failed=True
        if close_failed: raise RemoteHistoryHold()


def observe_remote_history_unit(token, binding, unit, identity, metadata_plan, metadata_response, history_plan, history_response):
    failed=False
    try:
        with _hold_match_originals(token,binding,unit):
            result=_observe_remote_history_unit(token,binding,unit,identity,metadata_plan,
                                                metadata_response,history_plan,history_response)
    except Exception: failed=True
    if failed: raise RemoteHistoryHold()
    return result


def _observe_remote_history_unit(token, binding, unit, identity, metadata_plan, metadata_response, history_plan, history_response):
    """One conservative whole proof-set observation; no durable settlement.

    Fixed full-tail reads only, original prefix unchanged, exact ordered new
    rows including every piggybacked audit. No fabricated History for NOOPs.
    UNKNOWN/CONFLICT remain retained; later rejection never clears this unit.
    """
    failed = False
    try:
        # Preserve the original bounded/coherent unit boundary before parsing
        # any caller unit bytes; the shared matcher rechecks after decoding.
        state = global_journal.inspect_global_unit(token, binding, unit)
        if state.attempt_count < 1: raise RemoteHistoryHold()
        before._read_preread(token, binding, unit)
        enrollment.require_unit_enrollment(token, binding, identity, unit)
        action = json.loads(unit.action_preimage)
        pair = enrollment.observe_enrollment_pair(token, binding, identity, metadata_plan, metadata_response,
                                                  sheet=action['identity']['sheet'])
        if urlsplit(history_plan.path).path != '/v4/spreadsheets/' + binding.spreadsheet_id: raise RemoteHistoryHold()
        post = decode.decode_history_tail(history_plan, history_response, sheet_id=action['history_sheet_id'])
        result = _match_original_decoded_images(token,binding,unit,identity,pair,metadata_response,post)
    except Exception: failed = True
    if failed: raise RemoteHistoryHold()
    return result


def _match_original_decoded_images(token,binding,unit,identity,pair,metadata_response,post):
    """Shared live/cold semantic matcher, never freshness or send authority."""
    failed=False
    try:
        state = global_journal.inspect_global_unit(token, binding, unit)
        if state.attempt_count < 1: raise RemoteHistoryHold()
        preread, original = before._read_preread(token, binding, unit)
        enrollment.require_unit_enrollment(token, binding, identity, unit)
        fence_present, foreign_fence = _fence(unit, identity, metadata_response)
        # Coherence was checked against actual global immutable ACTION/WIRE,
        # including full outcomes and ALL audit rows, before interpreting it.
        requests = json.loads(unit.wire_bytes)['requests']
        expected = tuple(tuple((('stringValue', cell['userEnteredValue']['stringValue']),) for cell in row['values'])
                         for row in requests[-2]['appendCells']['rows'])
        if len(expected) != unit.history_rows_expected: raise RemoteHistoryHold()
        old_tail = preread.history_last_row_before_send
        old = tuple(cell for cell in original.cells if cell[0] <= old_tail)
        still = tuple(cell for cell in post.cells if cell[0] <= old_tail)
        actual = _rows(post.cells, old_tail + 1, post.last_data_row_index)
        matched = sum(1 for first, second in zip(expected, actual) if first == second)
        conflict = (foreign_fence or post.row_count < original.row_count or old != still
                    or actual != expected or post.last_data_row_index != old_tail + len(expected))
        outcome = 'CONFLICT' if conflict else ('MATCHED_OBSERVATION' if fence_present else 'UNKNOWN')
        ownership._validated_owner(token, binding)
        result = RemoteHistoryObservation(outcome, state.attempt_count, fence_present,
            pair.target_nonce_valid, pair.history_nonce_valid, len(expected), matched,
            old_tail, post.last_data_row_index, unit.action_digest, unit.wire_sha256,
            hashlib.sha256(metadata_response.data).hexdigest(), post.source_sha256)
    except Exception: failed = True
    if failed: raise RemoteHistoryHold()
    return result


def observe_owned_remote_history_unit(writer_token, owner_token, binding, unit, *,
                                      identity_response, headers_response, metadata_response, history_response):
    """Keep original proof inputs pinned through the final issued-read gates."""
    failed=False
    try:
        with _hold_match_originals(owner_token,binding,unit):
            result=_observe_owned_remote_history_unit(writer_token,owner_token,binding,unit,
                identity_response=identity_response,headers_response=headers_response,
                metadata_response=metadata_response,history_response=history_response)
    except Exception: failed=True
    if failed: raise RemoteHistoryHold()
    return result


def _observe_owned_remote_history_unit(writer_token, owner_token, binding, unit, *,
                                       identity_response, headers_response, metadata_response, history_response):
    """Actual fixed-read observations → original journal matching, never APPLIED.

    No caller plan/identity/freshness flag is accepted. Each original completion
    must still be issued under these exact actual owner acquisitions, original
    deadline and current fixed target files, before AND after the whole match.
    Four reads are non-atomic observations, not a remote snapshot or CAS; the
    original matcher retains UNKNOWN/CONFLICT and never rewrites the journals.
    Metadata visibility accounting is not upgraded to globally complete here.
    """
    failed = False
    try:
        from monitor.issue_tracker_history_read_launcher import require_current_owned_read
        responses = (('template_identity', identity_response), ('template_headers', headers_response),
                     ('metadata', metadata_response), ('history_tail', history_response))
        plans = tuple(require_current_owned_read(writer_token, owner_token, binding, response, read_kind=kind)
                      for kind, response in responses)
        identity = decode.decode_template_identity(plans[0], identity_response)
        decode.decode_template_headers(plans[1], headers_response, identity)
        result = observe_remote_history_unit(owner_token, binding, unit, identity,
                                             plans[2], metadata_response, plans[3], history_response)
        # A matching response must not escape after local ownership/policy or
        # any original observation deadline becomes invalid during parsing.
        for kind, response in responses:
            require_current_owned_read(writer_token, owner_token, binding, response, read_kind=kind)
    except Exception: failed = True
    if failed: raise RemoteHistoryHold()
    return result


_COMPLETION_READS=(('identity_response','template_identity','IDENTITY-RAW'),
                   ('headers_response','template_headers','HEADERS-RAW'),
                   ('metadata_response','metadata','METADATA-RAW'),
                   ('history_response','history_tail','HISTORY-RAW'))


@dataclass(frozen=True)
class _RetainedReadImage:
    """Historical decoder input only; NEVER an issued/live HTTP response.

    200/complete describe the original writer's required accepted-read contract,
    not a new transport result. No read registry, headers, token or launcher
    accepts this private image; cold replay does not assert current remote state.
    """
    data: bytes
    status: int = 200
    complete: bool = True


def _replay_completion_raw_images(token,binding,unit,header,snapshots):
    """Recompute all proof semantics from original RAW, not stored MATCHED.

    Build only fixed decoder GET geometries, with EMPTY headers/no credentials.
    Verify each actual recorded path digest against its canonical read family.
    Metadata nonce decoding is pure; do not invent authentication to call the
    live HTTP validator. The original journal/WIRE/prefix dominate matching.
    """
    from monitor import issue_tracker_sheets_read_plan as plans
    prefix='/v4/spreadsheets/'+binding.spreadsheet_id
    paths={
        'IDENTITY-RAW':prefix+'?'+urlencode([('includeGridData','false'),('fields',plans._TEMPLATE_ID_FIELDS)]),
        'HEADERS-RAW':prefix+'?'+urlencode([('includeGridData','true'),('fields',plans._FIELDS),
            *(('ranges',value) for value in plans._TEMPLATE_HEADER_RANGES)]),
        'HISTORY-RAW':prefix+'?'+urlencode([('includeGridData','true'),('fields',plans._HISTORY_TAIL_FIELDS),
            ('ranges',"'Update_History'!A3:E5002")]),
        'METADATA-RAW':prefix+'/developerMetadata:search?'+urlencode({'fields':metadata._FIELDS}),
    }
    for file,path in paths.items():
        if header['responses'][file]['request_path_sha256']!=hashlib.sha256(path.encode('utf-8')).hexdigest():
            raise RemoteHistoryHold()
    def plan(file): return plans.PreparedSheetsRead('sheets.googleapis.com',paths[file],'GET',(),b'')
    def image(file): return _RetainedReadImage(snapshots[file][0])
    identity=decode.decode_template_identity(plan('IDENTITY-RAW'),image('IDENTITY-RAW'))
    decode.decode_template_headers(plan('HEADERS-RAW'),image('HEADERS-RAW'),identity)
    action=json.loads(unit.action_preimage)
    pair=enrollment._observe_enrollment_image(token,binding,identity,snapshots['METADATA-RAW'][0],
                                              sheet=action['identity']['sheet'])
    post=decode.decode_history_tail(plan('HISTORY-RAW'),image('HISTORY-RAW'),sheet_id=action['history_sheet_id'])
    return _match_original_decoded_images(token,binding,unit,identity,pair,image('METADATA-RAW'),post)


def _completion_start_raw(unit,base,originals):
    """Retained no-recreation witness, not remote success or APPLIED."""
    from monitor import issue_tracker_local_commit as local
    return local._canonical({'schema_version':1,'unit_id':unit.unit_id,'binding':base,
        'originals_sha256':hashlib.sha256(local._canonical(originals)).hexdigest(),
        'state':'COMPLETION-STARTED-NOT-APPLIED'})


def _write_completion_start(parent,name,raw):
    """Retain the fixed STOP name even BEFORE the first byte/barrier.

    Unlike an ordinary complete image, this witness's partial existence must
    survive a short write or failed file fsync. No pending-name window, replace,
    unlink, adoption or valid-proof claim; partial bytes remain conservative.
    """
    from monitor import issue_tracker_local_commit as local, issue_tracker_attempt_journal as journal
    if type(raw) is not bytes or not 1<=len(raw)<=16384: raise RemoteHistoryHold()
    local._flags()  # Require no-follow/CLOEXEC capability before creating.
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
    try:
        local._check(fd,directory=False); journal._named(parent,name,fd,directory=False)
        remaining=memoryview(raw)
        while remaining:
            written=os.write(fd,remaining)
            if written<=0: raise RemoteHistoryHold()
            remaining=remaining[written:]
        identity=journal._identity(os.fstat(fd))
        os.fsync(fd); journal._named(parent,name,fd,directory=False)
        if journal._identity(os.fstat(fd))!=identity: raise RemoteHistoryHold()
        os.fsync(parent); journal._named(parent,name,fd,directory=False)
        if journal._identity(os.fstat(fd))!=identity: raise RemoteHistoryHold()
    finally: os.close(fd)
    return identity


@contextmanager
def _hold_completion_start(owner_token,binding,unit,*,expected=None,expected_identity=None):
    from monitor import issue_tracker_local_commit as local, issue_tracker_attempt_journal as journal
    fd=None
    try:
        owner,parent,name,_base=global_journal._inputs(owner_token,binding,unit)
        name=name[:-len('.journal')]+'.completion-started'
        fd=os.open(name,local._flags()|os.O_NONBLOCK,dir_fd=parent)
        info=local._check(fd,directory=False); identity=journal._identity(info)
        if expected_identity is not None and identity!=expected_identity: raise RemoteHistoryHold()
        journal._named(parent,name,fd,directory=False)
        raw=os.pread(fd,16385,0)
        if not raw or len(raw)>16384 or len(raw)!=info.st_size or (expected is not None and raw!=expected):
            raise RemoteHistoryHold()
        def verify():
            if ownership._validated_owner(owner_token,binding) is not owner: raise RemoteHistoryHold()
            journal._named(parent,name,fd,directory=False)
            if journal._identity(os.fstat(fd))!=identity or os.pread(fd,len(raw)+1,0)!=raw:
                raise RemoteHistoryHold()
            journal._named(parent,name,fd,directory=False)
            if journal._identity(os.fstat(fd))!=identity: raise RemoteHistoryHold()
        verify()
        # Cold consumers re-establish the original witness barriers too.
        os.fsync(fd); os.fsync(parent); verify()
        yield verify,list(identity)
        verify()
    finally:
        if fd is not None: os.close(fd)


def record_owned_completion_evidence(writer_token,owner_token,binding,unit,*,
                                     identity_response,headers_response,metadata_response,history_response):
    """Persist a complete matched proof set, NEVER clear UNKNOWN or resend.

    Only actual fixed-read objects under the current dual acquisitions may
    enter. No caller observation/plan/path/COMPLETE flag is accepted. A retained
    partial store is HOLD; no recovery, adoption, overwrite or cleanup here.
    COMPLETE is written only AFTER all raw/header barriers and revalidation.
    The downstream APPLIED/high-water/FIFO/outbox transition is not implemented
    by this necessary local evidence API. Online activation remains separate.
    """
    from monitor import issue_tracker_local_commit as local, issue_tracker_attempt_journal as journal
    from monitor.issue_tracker_history_read_launcher import require_current_owned_read
    folder=None; failed=False; scope=ExitStack(); start_verify=None
    try:
        project=local._owner(writer_token)
        responses=dict(identity_response=identity_response,headers_response=headers_response,
                       metadata_response=metadata_response,history_response=history_response)
        with _hold_match_originals(owner_token,binding,unit) as (verify,originals):
            observed=observe_owned_remote_history_unit(writer_token,owner_token,binding,unit,**responses)
            if observed.state!='MATCHED_OBSERVATION': raise RemoteHistoryHold()
            owner,parent,name,base=global_journal._inputs(owner_token,binding,unit)
            key=name[:-len('.journal')]; name=key+'.completion'; start_name=key+'.completion-started'
            def live():
                if local._owner(writer_token) is not project: raise RemoteHistoryHold()
                if ownership._validated_owner(owner_token,binding) is not owner: raise RemoteHistoryHold()
                for key,kind,_file in _COMPLETION_READS:
                    require_current_owned_read(writer_token,owner_token,binding,responses[key],read_kind=kind)
                verify()
                if start_verify is not None: start_verify()
            live()
            if name in os.listdir(parent) or start_name in os.listdir(parent): raise RemoteHistoryHold()
            start_raw=_completion_start_raw(unit,base,originals)
            # File+parent barriers finish before ANY proof directory exists.
            # An interrupted witness remains HOLD; never adopt/recreate it.
            written_start_identity=_write_completion_start(parent,start_name,start_raw)
            start_verify,start_identity=scope.enter_context(
                _hold_completion_start(owner_token,binding,unit,expected=start_raw,expected_identity=written_start_identity))
            live()
            folder=global_journal._create_folder(parent,name)
            files={}
            for key,kind,file in _COMPLETION_READS:
                raw=responses[key].data
                if file in ('METADATA-RAW','HISTORY-RAW'): journal._write_read_image(folder,file,raw)
                else: local._write_new(folder,file,raw)
                files[file]={'identity':list(journal._identity(os.stat(file,dir_fd=folder,follow_symlinks=False))),
                             'sha256':hashlib.sha256(raw).hexdigest(),
                             'request_path_sha256':responses[key].request_path_sha256}
            header={'schema_version':1,'unit_id':unit.unit_id,'binding':base,'originals':originals,
                    'start_witness_identity':start_identity,
                    'folder_identity':list(journal._identity(os.fstat(folder))[:2]),
                    'matched':asdict(observed),'responses':files}
            header_raw=local._canonical(header)
            local._write_new(folder,'HEADER',header_raw)
            header_identity=list(journal._identity(os.stat('HEADER',dir_fd=folder,follow_symlinks=False)))
            # Recheck all files, original journal count/images and issued-read
            # deadlines after their actual durability barriers, before marker.
            journal._named(parent,name,folder,directory=True)
            for key,_kind,file in _COMPLETION_READS:
                if (journal._read(folder,file,2*1024*1024)!=responses[key].data
                        or list(journal._identity(os.stat(file,dir_fd=folder,follow_symlinks=False)))!=files[file]['identity']):
                    raise RemoteHistoryHold()
            if (journal._read(folder,'HEADER',65536)!=header_raw
                    or list(journal._identity(os.stat('HEADER',dir_fd=folder,follow_symlinks=False)))!=header_identity):
                raise RemoteHistoryHold()
            os.fsync(folder); os.fsync(parent)
            live()
            journal._named(parent,name,folder,directory=True)
            marker_raw=local._canonical({'schema_version':1,'unit_id':unit.unit_id,
                'header_sha256':hashlib.sha256(header_raw).hexdigest(),
                'header_identity':header_identity,'state':'COMPLETE-PRESENT-NOT-APPLIED'})
            local._write_new(folder,'COMPLETE',marker_raw)
            live()
            directory_identity=journal._identity(os.fstat(folder))
            originals_saved={file:(responses[key].data,files[file]['identity'])
                             for key,_kind,file in _COMPLETION_READS}
            originals_saved['HEADER']=(header_raw,header_identity)
            originals_saved['COMPLETE']=(marker_raw,list(journal._identity(os.stat('COMPLETE',dir_fd=folder,follow_symlinks=False))))
            result=inspect_completion_evidence(owner_token,binding,unit)
            # The historical reader must not let the writer return after its
            # actual original read deadline or proof namespace is displaced.
            live(); journal._named(parent,name,folder,directory=True)
            if journal._identity(os.fstat(folder))!=directory_identity or set(os.listdir(folder))!=set(originals_saved):
                raise RemoteHistoryHold()
            for file,saved in originals_saved.items():
                if (journal._read(folder,file,2*1024*1024),list(journal._identity(os.stat(file,dir_fd=folder,follow_symlinks=False))))!=saved:
                    raise RemoteHistoryHold()
            live(); journal._named(parent,name,folder,directory=True)
            if journal._identity(os.fstat(folder))!=directory_identity: raise RemoteHistoryHold()
    except Exception: failed=True
    finally:
        try: scope.close()
        except Exception: failed=True
        if folder is not None:
            try: os.close(folder)
            except OSError: failed=True
    if failed: raise RemoteHistoryHold()
    return result


@contextmanager
def _hold_completion_originals(owner_token,binding,unit):
    """Keep the entry proof set pinned through parsing, replay and barriers.

    A later self-consistent HEADER/COMPLETE pair cannot replace the original
    observation, including same-inode rewrites that do not change directory
    mtime. All proof descriptors remain held until the consumer returns. This
    boundary supplies no APPLIED, fresh read, settlement or retry authority.
    """
    from monitor import issue_tracker_local_commit as local, issue_tracker_attempt_journal as journal
    folder=None; held=[]; scope=ExitStack()
    try:
        owner,parent,name,_base=global_journal._inputs(owner_token,binding,unit)
        start_verify,_start_identity=scope.enter_context(_hold_completion_start(owner_token,binding,unit))
        name=name[:-len('.journal')]+'.completion'
        folder=local._directory(parent,name)
        journal._named(parent,name,folder,directory=True)
        directory_identity=journal._identity(os.fstat(folder))
        names={'HEADER','COMPLETE',*(file for _key,_kind,file in _COMPLETION_READS)}
        if set(os.listdir(folder))!=names: raise RemoteHistoryHold()
        for file in sorted(names):
            fd=os.open(file,local._flags()|os.O_NONBLOCK,dir_fd=folder)
            held.append((file,fd,None,None))
            info=local._check(fd,directory=False)
            journal._named(folder,file,fd,directory=False)
            identity=journal._identity(info)
            limit=65536 if file=='HEADER' else (16384 if file=='COMPLETE' else 2*1024*1024)
            raw=os.pread(fd,limit+1,0)
            if (not raw or len(raw)>limit or len(raw)!=info.st_size
                    or journal._identity(os.fstat(fd))!=identity): raise RemoteHistoryHold()
            journal._named(folder,file,fd,directory=False)
            held[-1]=(file,fd,identity,raw)
        def verify():
            start_verify()
            if ownership._validated_owner(owner_token,binding) is not owner: raise RemoteHistoryHold()
            journal._named(parent,name,folder,directory=True)
            if journal._identity(os.fstat(folder))!=directory_identity or set(os.listdir(folder))!=names:
                raise RemoteHistoryHold()
            for file,fd,identity,raw in held:
                journal._named(folder,file,fd,directory=False)
                if (journal._identity(os.fstat(fd))!=identity
                        or os.pread(fd,len(raw)+1,0)!=raw): raise RemoteHistoryHold()
                journal._named(folder,file,fd,directory=False)
                if journal._identity(os.fstat(fd))!=identity: raise RemoteHistoryHold()
            journal._named(parent,name,folder,directory=True)
            if journal._identity(os.fstat(folder))!=directory_identity: raise RemoteHistoryHold()
            ownership._validated_owner(owner_token,binding)
            start_verify()
        verify()
        yield verify
        verify()
    finally:
        close_failed=False
        for _file,fd,_identity,_raw in reversed(held):
            try: os.close(fd)
            except OSError: close_failed=True
        if folder is not None:
            try: os.close(folder)
            except OSError: close_failed=True
        try: scope.close()
        except Exception: close_failed=True
        if close_failed: raise RemoteHistoryHold()


def inspect_completion_evidence(owner_token,binding,unit):
    """Hold the entry originals through the entire historical proof replay."""
    failed=False
    try:
        with _hold_completion_originals(owner_token,binding,unit) as verify:
            result=_inspect_completion_evidence(owner_token,binding,unit)
            verify()
    except Exception: failed=True
    if failed: raise RemoteHistoryHold()
    return result


def _inspect_completion_evidence(owner_token,binding,unit):
    """Validate retained originals and complete proof images, no settlement.

    Missing/partial evidence never gets backfilled or promoted. Synchronize
    the original complete store under the owner; mere marker existence does
    not prove its barriers completed. No fresh remote state is asserted by
    this historical observation, and the UNKNOWN journal remains immutable.
    """
    from monitor import issue_tracker_local_commit as local, issue_tracker_attempt_journal as journal
    folder=None; failed=False
    try:
        with _hold_match_originals(owner_token,binding,unit) as (verify,originals):
            owner,parent,name,base=global_journal._inputs(owner_token,binding,unit)
            key=name[:-len('.journal')]; name=key+'.completion'; start_name=key+'.completion-started'
            folder=local._directory(parent,name)
            journal._named(parent,name,folder,directory=True)
            if set(os.listdir(folder))!={'HEADER','COMPLETE',*(file for _key,_kind,file in _COMPLETION_READS)}:
                raise RemoteHistoryHold()
            identity=journal._identity(os.fstat(folder))
            raw=journal._read(folder,'HEADER',65536)
            header=json.loads(raw.decode('utf-8'),object_pairs_hook=metadata._pairs,parse_constant=metadata._nonfinite)
            if (set(header)!={'schema_version','unit_id','binding','originals','folder_identity','matched','responses','start_witness_identity'}
                    or local._canonical(header)!=raw or type(header['schema_version']) is not int
                    or header['schema_version']!=1 or header['unit_id']!=unit.unit_id
                    or local._canonical(header['binding'])!=local._canonical(base)
                    or local._canonical(header['originals'])!=local._canonical(originals)
                    or local._canonical(header['folder_identity'])!=local._canonical(list(identity[:2]))
                    or journal._read(parent,start_name,16384)!=_completion_start_raw(unit,base,originals)
                    or local._canonical(header['start_witness_identity'])!=local._canonical(
                        list(journal._identity(os.stat(start_name,dir_fd=parent,follow_symlinks=False))))):
                raise RemoteHistoryHold()
            matched=header['matched']
            state=global_journal.inspect_global_unit(owner_token,binding,unit)
            preread,_original=before._read_preread(owner_token,binding,unit)
            if (set(matched)!=set(RemoteHistoryObservation.__dataclass_fields__)
                    or matched['state']!='MATCHED_OBSERVATION' or matched['fence_present'] is not True
                    or matched['target_nonce_valid'] is not True or matched['history_nonce_valid'] is not True
                    or type(matched['attempt_count']) is not int or matched['attempt_count']!=state.attempt_count
                    or type(matched['history_rows_expected']) is not int or matched['history_rows_expected']!=unit.history_rows_expected
                    or type(matched['history_rows_matched']) is not int or matched['history_rows_matched']!=unit.history_rows_expected
                    or type(matched['history_last_row_before_send']) is not int
                    or matched['history_last_row_before_send']!=preread.history_last_row_before_send
                    or type(matched['history_last_row_after_read']) is not int
                    or matched['history_last_row_after_read']!=preread.history_last_row_before_send+unit.history_rows_expected
                    or matched['action_digest']!=unit.action_digest or matched['wire_sha256']!=unit.wire_sha256):
                raise RemoteHistoryHold()
            expected_files={file for _key,_kind,file in _COMPLETION_READS}
            if type(header['responses']) is not dict or set(header['responses'])!=expected_files: raise RemoteHistoryHold()
            snapshots={}
            for file in sorted(expected_files|{'HEADER','COMPLETE'}):
                image=journal._read(folder,file,2*1024*1024)
                file_identity=list(journal._identity(os.stat(file,dir_fd=folder,follow_symlinks=False)))
                if file in expected_files:
                    facts=header['responses'][file]
                    if (type(facts) is not dict or set(facts)!={'identity','sha256','request_path_sha256'}
                            or local._canonical(facts['identity'])!=local._canonical(file_identity)
                            or facts['sha256']!=hashlib.sha256(image).hexdigest()
                            or type(facts['request_path_sha256']) is not str
                            or len(facts['request_path_sha256'])!=64
                            or any(letter not in '0123456789abcdef' for letter in facts['request_path_sha256'])):
                        raise RemoteHistoryHold()
                snapshots[file]=(image,file_identity)
            digest=hashlib.sha256(raw).hexdigest()
            if snapshots['COMPLETE'][0]!=local._canonical({'schema_version':1,'unit_id':unit.unit_id,
                    'header_sha256':digest,'header_identity':snapshots['HEADER'][1],
                    'state':'COMPLETE-PRESENT-NOT-APPLIED'}): raise RemoteHistoryHold()
            if (matched['metadata_sha256']!=header['responses']['METADATA-RAW']['sha256']
                    or matched['history_sha256']!=header['responses']['HISTORY-RAW']['sha256']): raise RemoteHistoryHold()
            replayed=_replay_completion_raw_images(owner_token,binding,unit,header,snapshots)
            if (replayed.state!='MATCHED_OBSERVATION'
                    or local._canonical(asdict(replayed))!=local._canonical(matched)):
                raise RemoteHistoryHold()
            for file in sorted(snapshots):
                fd=os.open(file,local._flags()|os.O_NONBLOCK,dir_fd=folder)
                try:
                    journal._named(folder,file,fd,directory=False)
                    if list(journal._identity(os.fstat(fd)))!=snapshots[file][1]: raise RemoteHistoryHold()
                    os.fsync(fd)
                finally: os.close(fd)
            os.fsync(folder); os.fsync(parent)
            verify(); journal._named(parent,name,folder,directory=True)
            if journal._identity(os.fstat(folder))!=identity or set(os.listdir(folder))!=set(snapshots): raise RemoteHistoryHold()
            for file,saved in snapshots.items():
                if (journal._read(folder,file,2*1024*1024),list(journal._identity(os.stat(file,dir_fd=folder,follow_symlinks=False))))!=saved:
                    raise RemoteHistoryHold()
            verify(); journal._named(parent,name,folder,directory=True)
            if journal._identity(os.fstat(folder))!=identity: raise RemoteHistoryHold()
            result=CompletionEvidenceObservation('COMPLETE-PRESENT-NOT-APPLIED',state.attempt_count,
                matched['history_rows_matched'],unit.unit_id,digest)
    except Exception: failed=True
    finally:
        if folder is not None:
            try: os.close(folder)
            except OSError: failed=True
    if failed: raise RemoteHistoryHold()
    return result


def observe_owned_unit_read_gates(writer_token, owner_token, binding, unit, *,
                                  whitelist_snapshot, identity_response, headers_response,
                                  whitelist_response, metadata_response):
    """Fresh original W1/template/nonces under actual dual owners, not GO.

    Read-only metadata inventory still cannot see other PROJECT scopes. Reject
    visible overflow, and any already-present unit fence must be reconciled,
    never turned into a new counted send here. Full row/History continuity,
    original C5/C6/cadence/reservations and the fixed mutation permit are separate.
    """
    failed=False
    try:
        from monitor.issue_tracker_history_read_launcher import require_current_owned_read
        from monitor.issue_tracker_online_whitelist_read import compare_online_whitelist_read
        responses=(('template_identity',identity_response),('template_headers',headers_response),
                   ('whitelist',whitelist_response),('metadata',metadata_response))
        plans=tuple(require_current_owned_read(writer_token,owner_token,binding,response,read_kind=kind)
                    for kind,response in responses)
        identity=decode.decode_template_identity(plans[0],identity_response)
        decode.decode_template_headers(plans[1],headers_response,identity)
        whitelist=compare_online_whitelist_read(plans[2],whitelist_response,whitelist_snapshot)
        if whitelist.sheet_id != dict(identity.sheet_ids)['Whitelist']: raise RemoteHistoryHold()
        global_journal.inspect_global_unit(owner_token,binding,unit)
        enrollment.require_unit_enrollment(owner_token,binding,identity,unit)
        action=json.loads(unit.action_preimage)
        pair=enrollment.observe_enrollment_pair(owner_token,binding,identity,plans[3],metadata_response,
                                                sheet=action['identity']['sheet'])
        capacity=metadata.observe_metadata_capacity(plans[3],metadata_response,identity,reservations=())
        if capacity.outcome=='STOP_CAPACITY' or _fence(unit,identity,metadata_response)[0]: raise RemoteHistoryHold()
        for kind,response in responses:
            require_current_owned_read(writer_token,owner_token,binding,response,read_kind=kind)
        result=OwnedUnitReadGateObservation(identity,whitelist.rules_sha256,pair.journal_sha256,capacity.outcome)
    except Exception: failed=True
    if failed: raise RemoteHistoryHold()
    return result
